"""
cmd_catalog — bundle catalog + instantiation: catalog, init, duplicate.

A *bundle* is a shipped directory `/usr/share/workloadctl/workloads/<bundle>/`
co-locating a template declaration (`workload.toml`) with its control files.
`init` stamps a catalog bundle into `/etc/workloads.d/<name>/workload.toml`; `duplicate`
copies a live workload. Neither touches `/var` or the boot path — they only
write the authoritative `/etc` declaration. Control files are *not* copied:
the new TOML's resolved `bundle` falls through to the shared `/usr` tree until
the operator overrides something.
"""

import difflib
import json
from pathlib import Path
import re
import shutil
import sys
import tomllib

from cli_log import emit_result
from workload_lib import iter_workloads, workload_config_dir, workload_config_path, WORKLOAD_BUNDLES_DIR
from validation import validate_workload_name
from secrets_template import auto_detect_credentials
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    require_root,
    toml_string,
)
from cmd_validate import validate_single

BUNDLES_DIR = WORKLOAD_BUNDLES_DIR

# Edit a single field inside the [workload] section only (mirrors
# cmd_lifecycle._set_enabled): scoping keeps the regex from touching a
# same-named field in some other section.
_WORKLOAD_SECTION_RE = re.compile(
    r'(?ms)(?P<header>^\[workload\][^\n]*\n)(?P<body>.*?)(?=^\[|\Z)'
)


def _write_new(path: Path, text: str) -> bool:
    """Exclusively create `path` with `text`. Returns False if it already exists
    (closing the check→write TOCTOU; the caller's earlier exists() check is for
    the friendly message, this is the race-safe guarantee)."""
    try:
        with open(path, "x") as f:
            f.write(text)
        return True
    except FileExistsError:
        return False



def _config_images(cfg: WorkloadConfig) -> set[str]:
    """Container images a workload references, shape-safe across single/pod/
    bridge. VMs have no container image, so return empty. Used by the duplicate
    lint to spot a mutable tag shared with another workload without assuming a
    top-level [container] (which pod/bridge workloads don't have)."""
    if cfg.is_vm:
        return set()
    try:
        return {img for _, img in cfg.container_images()}
    except Exception:
        return set()


def _referenced_secrets(cfg: WorkloadConfig) -> list[str]:
    """Secret names a config pulls in — [secrets].files credentials (top-level and
    per-container) and unescaped ${SECRET:name} refs across every container's
    environment (single/pod/bridge). Delegates to auto_detect_credentials so this
    report matches exactly what the boot path loads: an escaped `$${SECRET:name}`
    is a literal, not a reference, and nested/per-container secrets are included."""
    return sorted(auto_detect_credentials(cfg.config))


def _set_workload_field(content: str, field: str, value: str) -> str:
    """Set `field = value` in [workload] (value is a TOML literal). Replaces an
    existing line in place or prepends one to the section body."""
    m = _WORKLOAD_SECTION_RE.search(content)
    if not m:
        sep = "" if content.endswith("\n") else "\n"
        return content + f"{sep}[workload]\n{field} = {value}\n"
    body = m.group("body")
    # Tolerate an indented key (TOML allows leading whitespace); the comment
    # `#field` won't match because `^[ \t]*field` requires the key at a line's
    # logical start, not after a `#`.
    pat = rf'^[ \t]*{re.escape(field)}\s*=[^\n]*'
    if re.search(pat, body, re.MULTILINE):
        new_body = re.sub(pat, f'{field} = {value}', body, count=1, flags=re.MULTILINE)
    else:
        new_body = f'{field} = {value}\n' + body
    return content[:m.start("body")] + new_body + content[m.end("body"):]


# ---------------------------------------------------------------------------
# Bundle discovery
# ---------------------------------------------------------------------------

def list_bundles() -> list[str]:
    """Sorted names of shippable bundles (a dir with a workload.toml)."""
    if not BUNDLES_DIR.is_dir():
        return []
    return [name for name, _ in iter_workloads(BUNDLES_DIR)]


def _bundle_kind(bundle: str) -> str:
    """'vm' or 'container' (best-effort; '?' if the template won't parse)."""
    try:
        data = tomllib.loads((BUNDLES_DIR / bundle / "workload.toml").read_text())
    except (OSError, tomllib.TOMLDecodeError):
        return "?"
    return "vm" if "vm" in data else "container"


def _suggest_bundle(bundle: str) -> None:
    """Print a did-you-mean hint + the available bundle list to stderr."""
    avail = list_bundles()
    if not avail:
        return
    close = difflib.get_close_matches(bundle, avail, n=1)
    if close:
        print(f"  did you mean '{close[0]}'?", file=sys.stderr)
    print("  available bundles: " + ", ".join(avail), file=sys.stderr)


# ---------------------------------------------------------------------------
# catalog
# ---------------------------------------------------------------------------

def cmd_catalog(args, manager: WorkloadManager):
    """List shippable bundles under the workloads share dir."""
    bundles = list_bundles()
    if getattr(args, "json", False):
        print(json.dumps(
            [{"bundle": b, "kind": _bundle_kind(b)} for b in bundles], indent=2))
        return
    if not bundles:
        print(f"No bundles found under {BUNDLES_DIR}")
        return
    print("Available bundles (workloadctl init <bundle> [--as <name>]):")
    for b in bundles:
        print(f"  {b:<32} {_bundle_kind(b)}")


# ---------------------------------------------------------------------------
# init — instantiate a catalog bundle into /etc
# ---------------------------------------------------------------------------

_SCRATCH_VM_CLOUD_IMAGE_URL = (
    "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/"
    "Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2"
)
_SCRATCH_VM_CLOUD_IMAGE_CHECKSUM = (
    "sha256:28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f"
)

# Raw, and with the leading newline trimmed rather than backslash-continued:
# the seed contains a `printf '%s\n'`, and in a non-raw literal that backslash
# would be read here instead of by the guest's shell. Byte-identical to
# workloads/vm-base/cloud-init/user-data, which tests/test_catalog.py asserts.
_SCRATCH_VM_USER_DATA = r"""
#cloud-config
# Starter cloud-init for a workloadctl VM. Substitution happens at seed-build
# time (see docs/workloads.md "Bootstrapping a VM with cloud-init"):
#   $${WORKLOADCTL_SSH_KEY}        the workload's auto-generated pubkey
#   $${WORKLOADCTL_WORKLOAD_NAME}  this workload's name
#   $${WORKLOADCTL_VM_USER}        [vm].user — the account the CLI logs in as
#   $${WORKLOADCTL_VM_HOST_KEY_B64} the workload's SSH *host* key (base64 PEM)
#   $${WORKLOADCTL_VM_HOST_PUBKEY}  matching host public key
#   $${VAR}                        from [vm.cloud_init.template_vars] or env
#   SECRET:name / SECRET?name   systemd-creds (?=optional, ""), $$ = literal $
hostname: ${WORKLOADCTL_WORKLOAD_NAME}

users:
  - default
  - name: ${WORKLOADCTL_VM_USER}
    groups: [wheel]
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - ${WORKLOADCTL_SSH_KEY}

ssh_pwauth: false

# Install the workload's SSH host key so the CLI can verify the guest — the CLI
# pins it (StrictHostKeyChecking=yes), so a custom seed MUST install it or
# provisioning fails. base64 (encoding: b64) keeps the multi-line PEM on one
# line; sshd picks it up on first boot before it starts.
#
# ssh_deletekeys: false is required, not optional. cc_ssh defaults it to true,
# which wipes /etc/ssh/ssh_host_* and regenerates — and it runs *after*
# write_files, so the pinned key would be installed and then discarded.
ssh_deletekeys: false

write_files:
  - path: /etc/ssh/ssh_host_ed25519_key
    permissions: '0600'
    owner: root:root
    encoding: b64
    content: ${WORKLOADCTL_VM_HOST_KEY_B64}
  - path: /etc/ssh/ssh_host_ed25519_key.pub
    permissions: '0644'
    owner: root:root
    content: ${WORKLOADCTL_VM_HOST_PUBKEY}
  - path: /etc/modules-load.d/ptp-kvm.conf
    permissions: '0644'
    content: |
      ptp_kvm
  - path: /etc/udev/rules.d/70-ptp-kvm.rules
    permissions: '0644'
    content: |
      SUBSYSTEM=="ptp", ATTR{clock_name}=="KVM virtual PTP", SYMLINK+="ptp_kvm"

# --- One thing this file must carry that the built-in seed would have -------
#
# Setting user_data_file replaces workloadctl's generated cloud-config outright.
# That config is where the guest environment and the virtiofs mounts come from,
# so once this file is in play they are yours to write. The block below is
# commented out because the shipped defaults (no volumes) do not need it;
# provisioning refuses to build a seed that needs it and lacks it, and names
# what is missing, so you will be told rather than left to find out.

# THERE IS NO PROXY BLOCK HERE ANY MORE, AND ITS ABSENCE IS THE POINT.
#
# Through rung 1 this file carried an export block for
# http_proxy/https_proxy/no_proxy at an advertised endpoint, plus recipes for
# /etc/systemd/system.conf.d and /etc/dnf/dnf.conf, and a seed that omitted them
# on a workload with `hosts` was refused. All of it is gone. Egress filtering is
# now a uid-keyed redirect the guest is neither told about nor able to opt out
# of: it dials names normally and its own inspector reads the Host header or the
# SNI. A guest that still exports the old variables dials a host address where
# nothing listens.
#
# If you are copying an older seed forward, DELETE those exports rather than
# leaving them. They do not degrade gracefully -- a client that honours them
# fails outright, while every client that ignores them works, so the guest ends
# up half broken in a way that looks like a flaky network.
#
# One consequence worth keeping: an allowlist of `*.fedoraproject.org` still
# does not cover Fedora's mirrors (they live on mm.fcix.net, osuosl.org, ...).
# Either pin the repos to a baseurl under dl.fedoraproject.org, or provision
# with egress = "open" and switch to filtered once the guest is built.

# Volume mounts — required once [vm] sets `volumes`.
#    Each volume is attached as a virtiofs device tagged after its guest path
#    (see virtiofs_tags in lib/workload_lib.py: sanitized, truncated to 36
#    chars, index-suffixed on collision). The device is present and virtiofsd
#    is running, but nothing mounts it guest-side unless you say so. Skipping
#    this is silent: the guest path stays an ordinary directory on the system
#    disk, so writes look fine, never reach the host, and are discarded by the
#    next disk rebuild. For volumes = ["./home:/home/fedora"] the tag is
#    `home-fedora`:
#
# write_files (append to the list above):
#   - path: /etc/fstab
#     append: true
#     content: |
#       home-fedora /home/fedora virtiofs defaults,nofail 0 0
#
# runcmd (add these as items to the `runcmd:` list AT THE END OF THIS FILE --
# a second `runcmd:` key here would not merge with it, it would replace it, and
# the paravirtual clock below would silently stop being wired):
#    Seed the skeleton dotfiles into the share before mounting over them, or
#    the first login lands in a home with no .bashrc. cp -n never clobbers the
#    authorized_keys workloadctl already seeded into a home-mounted share.
#   - mkdir -p /mnt/.seed
#   - mount -t virtiofs home-fedora /mnt/.seed
#   - cp -a -n /home/${WORKLOADCTL_VM_USER}/. /mnt/.seed/ || true
#   - umount /mnt/.seed && rmdir /mnt/.seed
#   - systemctl daemon-reload
#   - mount /home/${WORKLOADCTL_VM_USER}
#
#    If the guest image already handles one of these — a mount baked into its
#    own /etc/fstab, say — declare it instead of duplicating it:
#      [vm.cloud_init]
#      seed_provides = ["mounts"]   # and/or "ca"

# --- The egress CA — required once [vm.network] sets egress = "filtered" -----
#
# A filtered workload's HTTPS is terminated by its own inspector, which presents
# a leaf signed by a CA minted for this workload alone. The guest has to trust
# that CA or every HTTPS request fails as a bad certificate rather than as a
# policy decision — and provisioning refuses to build a filtered seed that never
# installs it, so you are told rather than left to find out.
#
# The built-in cloud-config does this and a custom seed replaces it, so the
# pieces below are yours to write. They are commented out because this
# bundle is `egress = "open"`: with no CA to install, ${WORKLOADCTL_VM_EGRESS_CA_B64}
# substitutes to an empty string and the entries would write an empty anchor.
# Uncomment them at the same moment you set egress = "filtered".
#
# TWO ROUTES, BOTH NEEDED. The guest's system trust store covers almost
# everything; the copy at the fixed path is what the five environment variables
# name, for the runtimes that carry their own root list and never consult the
# system store. Either alone leaves a measured population of clients failing.
#
# BOTH ROUTES USE THE B64 FORM, AND THAT IS NOT A STYLE CHOICE. Substitution is
# a plain textual replace, so a multi-line value keeps the placeholder's
# indentation on its FIRST line only: splice the raw ${WORKLOADCTL_VM_EGRESS_CA} form
# into an indented YAML block scalar and every line after the first lands at
# column 0. That does not fail as a missing anchor -- cloud-init cannot parse
# the document at all, and the guest loses the host key, the mounts and
# everything else in this file. The raw variable is safe only where column 0 is
# where the PEM belongs; encoded, the value is one line and cannot break the
# seed whatever it is nested inside.
#
# The first entry is what a cloud-init `ca_certs: trusted:` block would do,
# written as a file instead so the b64 form is available: on Fedora that module
# writes this very directory and then runs update-ca-trust, which is the runcmd
# below.
#
# write_files (append to the list above):
#   - path: /etc/pki/ca-trust/source/anchors/workloadctl-egress.crt
#     permissions: '0644'
#     owner: root:root
#     encoding: b64
#     content: ${WORKLOADCTL_VM_EGRESS_CA_B64}
#   - path: /usr/local/share/ca-certificates/workloadctl-egress.crt
#     permissions: '0644'
#     owner: root:root
#     encoding: b64
#     content: ${WORKLOADCTL_VM_EGRESS_CA_B64}
#   - path: /etc/environment
#     append: true
#     content: |
#       SSL_CERT_FILE=/usr/local/share/ca-certificates/workloadctl-egress.crt
#       NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/workloadctl-egress.crt
#       REQUESTS_CA_BUNDLE=/usr/local/share/ca-certificates/workloadctl-egress.crt
#       GIT_SSL_CAINFO=/usr/local/share/ca-certificates/workloadctl-egress.crt
#       PIP_CERT=/usr/local/share/ca-certificates/workloadctl-egress.crt
#
# runcmd (add as an item to the `runcmd:` list AT THE END OF THIS FILE, never as
# a second `runcmd:` key -- see below):
#   - update-ca-trust extract
#
# `tls = "splice"` on the workload (with the `tls_reason` it requires) is the
# answer for a guest that cannot be given the anchor — a weaker property, not a
# deprecated one, and it needs none of this. The CA is still minted and still seeded either way, so
# switching between the two never rotates the instance-id.

# An example of your own, for the `runcmd:` list at the end of this file. Add
# it as an item there rather than opening a second `runcmd:` key, which YAML
# resolves by keeping one of the two -- and the one it keeps is not the one
# that wires the clock:
#   - echo "first boot" > /etc/motd

# --- The paravirtual clock, which a custom seed does NOT get for free --------
#
# A vCPU pause -- `backup --consistency crash`, a host suspend, `incant stop` --
# is lost by the guest exactly and permanently, and NTP will not put it back: a
# stock chrony steps only during its first three updates and slews forever
# after, at a rate that needs months to walk off a two-hour jump. In a filtered
# guest NTP is dead anyway, since this design closed the UDP path it needs.
#
# ptp_kvm costs nothing and needs no network: the guest reads the host's clock
# over a KVM hypercall. Nothing is required on the host side. The three pieces
# below are the module, a stable name for the device (/dev/ptpN is allocation-
# ordered, so select on the driver's clock_name), and `makestep 1 -1` -- the
# line that actually fixes the bug, by letting chrony step at any time rather
# than only at startup.
#
# The host repairs a skewed guest too, on the egress inspector's mint path, but
# only if the guest runs qemu-guest-agent and only when a certificate is minted.
# Keep both: they cover each other's blind spot.
runcmd:
  - |
    udevadm control --reload-rules || true
    if modprobe ptp_kvm 2>/dev/null; then
      for _ in 1 2 3 4 5; do [ -e /dev/ptp_kvm ] && break; sleep 1; done
    fi
    if [ -e /dev/ptp_kvm ] && [ -f /etc/chrony.conf ] && ! grep -qF '# workloadctl: paravirtual clock' /etc/chrony.conf; then
      printf '%s\n' '# workloadctl: paravirtual clock' 'refclock PHC /dev/ptp_kvm poll 2 dpoll -2 offset 0' 'makestep 1 -1' >> /etc/chrony.conf
      systemctl restart chronyd || true
    fi
"""[1:]


def _scratch_vm(name: str, manager: WorkloadManager) -> None:
    """Stamp a self-contained VM stub under /etc/workloads.d/<name>/."""
    try:
        validate_workload_name(name)
    except ValueError as e:
        print(f"Error: invalid workload name {name!r}: {e}", file=sys.stderr)
        sys.exit(1)

    dst = workload_config_path(name)
    if dst.parent.exists():
        print(f"Error: workload '{name}' already exists: {dst}", file=sys.stderr)
        sys.exit(1)
    dst.parent.mkdir()

    stub = (
        f'[workload]\n'
        f'name = "{name}"\n'
        f'\n'
        f'[vm]\n'
        f'# Fedora 44 Cloud-Base (bump with fedora-versions.yml `stable:`).\n'
        f'cloud_image_url = "{_SCRATCH_VM_CLOUD_IMAGE_URL}"\n'
        f'cloud_image_checksum = "{_SCRATCH_VM_CLOUD_IMAGE_CHECKSUM}"\n'
        f'# --- or copy/reflink a local qcow2 instead: ---\n'
        f'# local_image = "/path/to/image.qcow2"\n'
        f'# --- or build from a bootc image ref (needs bootc-image-builder + /dev/kvm): ---\n'
        f'# image = "ghcr.io/you/custom-bootc:latest"\n'
        f'vcpus = 2\n'
        f'memory = "2G"\n'
        f'system_disk_size = "20G"\n'
        f'# data_disk_size = "20G"   # uncomment for a persistent /dev/vdb data disk\n'
        f'user = "fedora"\n'
        f'\n'
        f'[vm.cloud_init]\n'
        f'user_data_file = "cloud-init/user-data"\n'
        f'\n'
        f'# [vm.cloud_init.template_vars]\n'
        f'# MY_VAR = "value"   # referenced as ${{MY_VAR}} in cloud-init/user-data\n'
    )

    if not _write_new(dst, stub):
        print(f"Error: workload '{name}' already exists: {dst}", file=sys.stderr)
        sys.exit(1)

    cloud_init_dir = dst.parent / "cloud-init"
    cloud_init_dir.mkdir()
    (cloud_init_dir / "user-data").write_text(_SCRATCH_VM_USER_DATA)

    print(f"✓ Created VM stub workload '{name}'")
    print(f"  {dst}")
    _post_write_report(name, manager, "created", source="vm-stub")


def cmd_init(args, manager: WorkloadManager):
    """Stamp a catalog bundle into /etc/workloads.d/<name>/workload.toml."""
    require_root()

    scratch = getattr(args, "scratch", None)
    scratch_vm = getattr(args, "scratch_vm", None)
    bundle = getattr(args, "bundle", None)

    if sum(bool(x) for x in (scratch, scratch_vm, bundle)) > 1:
        print("Error: --scratch, --scratch-vm, and a bundle positional are mutually exclusive", file=sys.stderr)
        sys.exit(1)

    if scratch_vm:
        _scratch_vm(scratch_vm, manager)
        return

    if scratch:
        name = scratch
        try:
            validate_workload_name(name)
        except ValueError as e:
            print(f"Error: invalid workload name {name!r}: {e}", file=sys.stderr)
            sys.exit(1)
        stub = (
            f'[workload]\n'
            f'name = "{name}"\n'
            f'\n'
            f'[container]\n'
            f'image = "CHANGE_ME"\n'
            f'pull = "missing"\n'
        )
        dst = workload_config_path(name)
        if dst.parent.exists():
            print(f"Error: workload '{name}' already exists: {dst}", file=sys.stderr)
            sys.exit(1)
        dst.parent.mkdir()
        if not _write_new(dst, stub):
            print(f"Error: workload '{name}' already exists: {dst}", file=sys.stderr)
            sys.exit(1)
        print(f"✓ Created scratch workload '{name}'")
        print(f"  {dst}")
        _post_write_report(name, manager, "created", source="scratch")
        return

    if not bundle:
        print("Error: no bundle specified (pass a bundle name, --scratch, or --scratch-vm)",
              file=sys.stderr)
        sys.exit(1)

    name = args.as_name or bundle

    # Validate the bundle before it's pathed (it's a directory name); the
    # existence check below would also catch a traversal, but an up-front
    # name error is clearer and consistent with how `name` is handled.
    try:
        validate_workload_name(bundle)
    except ValueError as e:
        print(f"Error: invalid bundle name {bundle!r}: {e}", file=sys.stderr)
        _suggest_bundle(bundle)
        sys.exit(1)

    try:
        validate_workload_name(name)
    except ValueError as e:
        print(f"Error: invalid workload name {name!r}: {e}", file=sys.stderr)
        sys.exit(1)

    src = BUNDLES_DIR / bundle / "workload.toml"
    if not src.exists():
        print(f"Error: no bundle '{bundle}' under {BUNDLES_DIR}", file=sys.stderr)
        _suggest_bundle(bundle)
        sys.exit(1)

    dst = workload_config_path(name)
    if dst.parent.exists():
        print(f"Error: workload '{name}' already exists: {dst}", file=sys.stderr)
        print("  choose another name with --as, or edit the existing one", file=sys.stderr)
        sys.exit(1)

    dst.parent.mkdir()
    text = src.read_text()
    text = _set_workload_field(text, "name", toml_string(name))
    # Only pin `bundle` when the instance name diverges from the bundle, so
    # the copy's control files still resolve to the source bundle's tree.
    # When name == bundle, `bundle` defaults to name and the field is noise.
    if name != bundle:
        text = _set_workload_field(text, "bundle", toml_string(bundle))
    if not _write_new(dst, text):
        print(f"Error: workload '{name}' already exists: {dst}", file=sys.stderr)
        sys.exit(1)

    print(f"✓ Instantiated bundle '{bundle}' as '{name}'")
    print(f"  {dst}")
    _post_write_report(name, manager, "created", source="bundle", bundle=bundle)


# ---------------------------------------------------------------------------
# duplicate — copy a live workload
# ---------------------------------------------------------------------------

def cmd_duplicate(args, manager: WorkloadManager):
    """Copy a live workload's declaration under a new name (alias: clone)."""
    require_root()
    src_name = args.source
    new_name = args.new

    # Validate BOTH names before either becomes a path. src_name flows into
    # `workload_config_dir() / src_name / "workload.toml"` and is read_text()'d as root
    # (directly and in the tomllib fallback below), so a `../`-laden source would
    # read an arbitrary workload.toml from outside the workloads dir — hold it to
    # the same bar as new_name even though it's only ever read.
    try:
        validate_workload_name(src_name)
    except ValueError as e:
        print(f"Error: invalid source workload name {src_name!r}: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        validate_workload_name(new_name)
    except ValueError as e:
        print(f"Error: invalid workload name {new_name!r}: {e}", file=sys.stderr)
        sys.exit(1)

    src_path = workload_config_path(src_name)
    if not src_path.exists():
        print(f"Error: no workload '{src_name}' in {workload_config_dir()}", file=sys.stderr)
        sys.exit(1)

    dst_path = workload_config_path(new_name)
    if dst_path.parent.exists():
        print(f"Error: workload '{new_name}' already exists: {dst_path}", file=sys.stderr)
        sys.exit(1)

    # Resolve the source's bundle: a duplicate of a duplicate must point at the
    # original /usr bundle (src.bundle or src.name), never at the source's own
    # name (which has no /usr bundle dir).
    try:
        resolved_bundle = WorkloadConfig(src_name).bundle
    except Exception:
        data = tomllib.loads(src_path.read_text())
        resolved_bundle = data.get("workload", {}).get("bundle") or src_name

    text = src_path.read_text()
    text = _set_workload_field(text, "name", toml_string(new_name))
    text = _set_workload_field(text, "bundle", toml_string(resolved_bundle))
    dst_path.parent.mkdir()
    if not _write_new(dst_path, text):
        print(f"Error: workload '{new_name}' already exists: {dst_path}", file=sys.stderr)
        sys.exit(1)

    print(f"✓ Duplicated '{src_name}' → '{new_name}' (bundle '{resolved_bundle}')")
    print(f"  {dst_path}")
    _lint_duplicate(new_name, manager)
    _post_write_report(new_name, manager, "duplicated", source_workload=src_name,
                       bundle=resolved_bundle)


def _lint_duplicate(name: str, manager: WorkloadManager) -> None:
    """Warn (never block) on host-global settings a verbatim copy inherits that
    two enabled instances can't both hold: published host ports, absolute volume
    paths (silent data sharing), and a mutable image tag shared with another
    enabled workload. Enforcement is at enable/bind time, not here."""
    try:
        cfg = WorkloadConfig(name)
    except Exception:
        return

    warnings = []

    ports = cfg.config.get("network", {}).get("ports", [])
    if ports:
        warnings.append(
            f"publishes host port(s) {', '.join(str(p) for p in ports)} — two "
            f"instances can't bind the same port; remap before enabling both")

    for vol in cfg.get_volumes():
        host_path = str(vol).split(":", 1)[0]
        if host_path.startswith("/"):
            warnings.append(
                f"absolute volume path '{host_path}' — both instances would "
                f"share it silently (no bind error); point the copy elsewhere")

    # Shared mutable image tag across enabled workloads (a legitimate choice for
    # :latest, but worth surfacing). Shape-safe: a pod/bridge workload has no
    # top-level [container] — `cfg.image` would KeyError — so enumerate every
    # container's image via container_images() for both this copy and each peer.
    others = [c for c in manager.get_all_configs() if c.name != name]
    for img in sorted(_config_images(cfg)):
        sharers = [c.name for c in others if img in _config_images(c)]
        if sharers:
            warnings.append(
                f"image '{img}' is also used by {', '.join(sharers)} — they "
                f"share a mutable tag (fine for :latest, intentional otherwise)")

    # Secrets are name-keyed in a global credstore, so a verbatim copy decrypts
    # fine — but it now reads the *same* credential as the source. Surface it:
    # the copy may want its own secret (rotate one without touching the other).
    secrets = _referenced_secrets(cfg)
    if secrets:
        warnings.append(
            f"references secret(s) {', '.join(secrets)} — the copy reads the same "
            f"credential as its source; give it its own if they should differ "
            f"(workloadctl secret create …)")

    if warnings:
        print()
        print("  Lint (warnings — nothing blocked):")
        for w in warnings:
            print(f"    ⚠ {w}")


def _post_write_report(name: str, manager: WorkloadManager, result: str,
                       **detail) -> None:
    """Validate the freshly written config (non-fatal — a fresh copy commonly
    needs volume dirs created on first enable), record the operation, and print
    next steps.

    Every verb in this module ends here on success, which is why the operations
    log is written here rather than at each of the five call sites: a new way to
    author a workload gets recorded by construction. `result` says which one it
    was ("created" / "duplicated" / "installed") and `detail` carries whatever
    that verb can add — the bundle it came from, the workload it was copied off.
    """
    emit_result([{"workload": name, "result": result, **detail}])
    print()
    try:
        cfg = WorkloadConfig(name)
        validate_single(cfg, manager, json_mode=False)
    except Exception as e:
        print(f"  (could not validate yet: {e})")
    print()
    print("Next steps:")
    print(f"  Edit:    workloadctl edit {name}")
    print(f"  Enable:  workloadctl enable {name}")


# ---------------------------------------------------------------------------
# install — promote a local workload directory into /etc/workloads.d/
# ---------------------------------------------------------------------------

def cmd_install(args, manager: WorkloadManager):
    """Copy a workload directory into /etc/workloads.d/<name>/ (from workload.toml name)."""
    require_root()
    src = Path(args.src).resolve()

    toml_path = src / "workload.toml"
    if not toml_path.exists():
        print(f"Error: no workload.toml found in {src}", file=sys.stderr)
        sys.exit(1)

    try:
        data = tomllib.loads(toml_path.read_text())
    except tomllib.TOMLDecodeError as e:
        print(f"Error: workload.toml parse error: {e}", file=sys.stderr)
        sys.exit(1)

    name = data.get("workload", {}).get("name", "")
    if not name:
        print("Error: workload.toml has no [workload] name field", file=sys.stderr)
        sys.exit(1)

    try:
        validate_workload_name(name)
    except ValueError as e:
        print(f"Error: invalid workload name {name!r}: {e}", file=sys.stderr)
        sys.exit(1)

    dst_dir = workload_config_path(name).parent
    if dst_dir.exists():
        print(f"Error: workload '{name}' already exists: {dst_dir}", file=sys.stderr)
        sys.exit(1)

    # Never carry the source's enable marker into a fresh instance — a newly
    # installed/cloned workload always starts disabled.
    shutil.copytree(src, dst_dir,
                    ignore=shutil.ignore_patterns(".git", "__pycache__", ".enabled"))

    dst = workload_config_path(name)
    print(f"✓ Installed '{name}' from {src}")
    print(f"  {dst}")
    _post_write_report(name, manager, "installed", source=str(src))
