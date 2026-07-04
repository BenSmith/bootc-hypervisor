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

from workload_lib import iter_workloads, SECRET_PATTERN, validate_workload_name, workload_config_dir, workload_config_path, WORKLOAD_BUNDLES_DIR
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    require_root,
    toml_string,
)
from cmd_admin import validate_single

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
    """Secret names a config pulls in — via [secrets].files credentials and
    ${SECRET:name} refs in any container's environment (single/pod/bridge)."""
    found: set[str] = set()
    for spec in cfg.config.get("secrets", {}).get("files", []):
        cred = spec.get("credential")
        if cred:
            found.add(cred)
    container_envs = []
    single = cfg.config.get("container", {})
    if single:
        container_envs.append(single.get("environment", {}))
    for c in cfg.config.get("containers", []):
        container_envs.append(c.get("environment", {}))
    for env in container_envs:
        for val in env.values():
            for m in SECRET_PATTERN.finditer(str(val)):
                found.add(m.group(1))
    return sorted(found)


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

_SCRATCH_VM_USER_DATA = """\
#cloud-config
# Starter cloud-init for a workloadctl VM. Substitution happens at seed-build
# time (see docs/workloads.md "Bootstrapping a VM with cloud-init"):
#   $${WORKLOADCTL_SSH_KEY}        the workload's auto-generated pubkey
#   $${WORKLOADCTL_WORKLOAD_NAME}  this workload's name
#   $${VAR}                        from [vm.cloud_init.template_vars] or env
#   SECRET:name / SECRET?name   systemd-creds (?=optional, ""), $$ = literal $
hostname: ${WORKLOADCTL_WORKLOAD_NAME}

users:
  - default
  - name: fedora
    groups: [wheel]
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - ${WORKLOADCTL_SSH_KEY}

ssh_pwauth: false

# runcmd:
#   - echo "first boot" > /etc/motd
"""


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
    _post_write_report(name, manager)


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
            f'pull = "newer"\n'
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
        _post_write_report(name, manager)
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
    _post_write_report(name, manager)


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
    _post_write_report(new_name, manager)


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


def _post_write_report(name: str, manager: WorkloadManager) -> None:
    """Validate the freshly written config (non-fatal — a fresh copy commonly
    needs volume dirs created on first enable) and print next steps."""
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
    _post_write_report(name, manager)
