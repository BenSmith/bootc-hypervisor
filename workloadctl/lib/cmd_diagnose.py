"""
cmd_diagnose — explain why a workload isn't healthy.

collect_diagnose_checks() is pure collection: no root check, no printing, no
exit, so `doctor` can run the same battery fleet-wide and render it its own way.
Where validate asks "is this config fit to enable", diagnose asks "this is
enabled and unhappy — what is wrong with it right now".
"""
import base64
import bz2
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from workload_lib import (
    derived_subid_range,
    expand_volume_path,
    HOST_USERNS_OPT_IN,
    login_defs_subid_window,
    read_subid_entry,
    selinux_module_name,
    selinux_type_name,
    subgid_file,
    subid_files_with_entries,
    subuid_file,
    units_outdated,
    units_from_other_build,
    workload_data_dir,
    workload_root_dir,
    WORKLOADCTL_VERSION,
    WORKLOADS_BASE,
)
from provisioning import (
    vm_fcontext_pattern,
    HOST_ARTIFACT_KINDS,
    HOST_SETUP_ARTIFACTS_ACTION,
    host_setup_artifacts,
)
from validation import uses_host_userns
from vm import (
    NFT_BIN, NFT_SET_ALLOW4, NFT_SET_ALLOW6, NFT_SET_FILTERED, NFT_TABLE,
    VM_EGRESS_DEFAULT, VM_MGMT_SSH_PORT, VM_QEMU_TYPE, VM_RUNCON_BIN,
    VM_SOCKET_DIR, VM_SOCKET_FCONTEXT_PATTERN, VM_SOCKET_SELINUX_TYPE,
    VM_SOCKET_SELINUX_TYPE_REAL, VM_SELINUX_CIL, VM_SELINUX_MODULE,
    nft_drop_counter,
    nft_set_elements, selinux_enabled, vm_management_address, vm_nflog_group,
    vm_owned_elements,
    NFT_PROXY_MAP, NFT_PROXY_TABLE, VM_PROXY_ADDR, VM_PROXY_IFACE,
    VM_PROXY_PORT, vm_proxy_hosts, vm_uses_proxy,
)
from podman import PodmanError
from workloadctl_core import WorkloadManager, require_root
from substrate import service_active
from cmd_validate import load_config_or_exit
from pcap import PCAP_CHAINS, pcap_unit_name


def _gpu_vendors(config) -> set[str]:
    """GPU vendors declared by any container's ``[devices] gpu``.

    Reads the raw TOML in both shapes — top-level ``[devices]`` for single
    mode, per-entry for ``[[containers]]`` — and returns the vendor half of
    ``vendor[:spec]``. "none" and absent are omitted, so an empty set means
    the workload asked for no GPU.
    """
    cfg = config.config
    sections = [cfg, *(cfg.get("containers") or [])]
    vendors = set()
    for section in sections:
        gpu = (section.get("devices") or {}).get("gpu", "none")
        if gpu and gpu != "none":
            vendors.add(gpu.partition(":")[0])
    return vendors


def _getsebool(name: str) -> bool | None:
    """State of an SELinux boolean, or None when it can't be determined.

    None covers three cases the caller must not treat as "off": no
    getsebool binary, SELinux disabled, and a boolean this policy version
    doesn't define.
    """
    if not shutil.which("getsebool"):
        return None
    result = subprocess.run(
        ["getsebool", name], capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return result.stdout.strip().endswith("on")


def _fcontext_rule_present(pattern: str | None = None) -> bool | None:
    """Is the persistent fcontext rule for `pattern` registered?

    Defaults to the blanket /var/lib/workloads rule that container workloads
    rely on. A VM workload passes its own per-workload pattern instead, since
    that is the rule which actually decides its tree's label — the blanket rule
    being present says nothing about whether the VM override was registered.

    None when it can't be determined — no semanage binary, SELinux disabled,
    or the read lock is contended right now. None must never read as "missing".
    """
    if pattern is None:
        pattern = f"{WORKLOADS_BASE}(/.*)?"
    if not shutil.which("semanage"):
        return None
    result = subprocess.run(
        ["semanage", "fcontext", "-l"], capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return pattern in result.stdout


# --- CA trust store ---
#
# Anchors an operator or the image installed, and the bundle that actually
# grants trust. Kept relative to a root so the probe can be pointed at a
# fixture tree, and so the /usr/etc comparison can reuse the same tail.
CA_ANCHOR_DIR = "pki/ca-trust/source/anchors"
CA_TLS_BUNDLE = "pki/ca-trust/extracted/pem/tls-ca-bundle.pem"


def _cert_fingerprints(data: bytes) -> set[str]:
    """SHA-256 over every certificate body in `data`, PEM or DER.

    Hashing the decoded body rather than the file means the two encodings of
    one certificate give one fingerprint, which is what lets an anchor be
    matched against a bundle that re-encoded it.

    Anything that is not a certificate yields the empty set: an operator's
    README in the anchor dir must not read as an untrusted anchor, and a
    truncated PEM must not raise. Discriminated on content, not extension —
    a DER certificate opens with the SEQUENCE tag 0x30, which no text file
    written by hand does.
    """
    marker = b"-----BEGIN CERTIFICATE-----"
    if marker not in data:
        return {hashlib.sha256(data).hexdigest()} if data[:1] == b"\x30" else set()
    out = set()
    for chunk in data.split(marker)[1:]:
        body, _, _ = chunk.partition(b"-----END CERTIFICATE-----")
        try:
            der = base64.b64decode(body, validate=False)
        except ValueError:
            continue
        if der:
            out.add(hashlib.sha256(der).hexdigest())
    return out


def _ca_trust_facts(root: Path = Path("/")):
    """Facts for ca_trust_anchor_check, or None when they can't be read.

    Returns (unbundled, local_anchors):

    - `unbundled` — anchor files whose certificates are absent from the
      extracted TLS bundle. This is the property that actually matters and it
      is mechanism-independent: it asks whether the trust the host was
      configured to have is in effect, not how it got out of step.
    - `local_anchors` — anchor files that differ from, or are absent from, the
      booted deployment's /usr/etc copy. None when there is no /usr/etc, i.e.
      no ostree /etc merge, so nothing can distinguish a locally added anchor
      from a shipped one. Only ever used to pick the fix, never the verdict.
    """
    anchor_dir = root / "etc" / CA_ANCHOR_DIR
    try:
        bundle_fps = _cert_fingerprints((root / "etc" / CA_TLS_BUNDLE).read_bytes())
        anchors = sorted(p for p in anchor_dir.iterdir() if p.is_file())
    except OSError:
        return None

    unbundled = []
    for path in anchors:
        try:
            fps = _cert_fingerprints(path.read_bytes())
        except OSError:
            continue
        if fps and not fps <= bundle_fps:
            unbundled.append(path.name)

    shipped_dir = root / "usr/etc" / CA_ANCHOR_DIR
    if not shipped_dir.is_dir():
        return unbundled, None
    local = []
    for path in anchors:
        shipped = shipped_dir / path.name
        try:
            if not shipped.is_file() or shipped.read_bytes() != path.read_bytes():
                local.append(path.name)
        except OSError:
            local.append(path.name)
    return unbundled, local


def ca_trust_anchor_check(
    unbundled: list[str],
    local_anchors: list[str] | None,
) -> tuple[bool, str, str | None]:
    """Verdict: is every configured trust anchor actually in the TLS bundle?

    The gap this closes is that installing an anchor and trusting it are two
    steps, and only the first one is visible. `update-ca-trust` extracts
    source/anchors into extracted/, but on a bootc host extracted/ is under
    /etc — so a host that ever ran `update-ca-trust` by hand has that path
    marked locally modified, ostree's 3-way merge keeps the host copy forever,
    and the image's extraction is discarded. A *new* anchor file still lands;
    nothing extracts it.

    Measured on a storage host 2026-07-30: a homelab root dated that morning
    sat in source/anchors beside a bundle dated 2026-05-21 that did not contain
    it, and every registry.local pull failed `unable to get local issuer
    certificate` while the anchor was plainly present. The symptom points away
    from the cause — the trust store looks correct — which is why this is a
    check and not a note.

    Asks the direct question rather than the mechanical one. "Does extracted/
    differ from /usr/etc" would also fire on a host with a deliberate local
    anchor, which is a permanent and correct divergence, and would report
    nothing on a non-ostree host. "Is this anchor in the bundle" is true or
    false everywhere, and `local_anchors` only chooses which repair to name.
    """
    if not unbundled:
        return (True, "Trust anchors are all in the extracted TLS bundle", None)

    named = ", ".join(unbundled)
    message = (f"Trust anchor not in the extracted bundle: {named} — the "
               f"anchor is installed but grants no trust, so TLS to anything "
               f"it signs fails with 'unable to get local issuer certificate'")

    if local_anchors is None:
        # No /usr/etc: no merge to converge back to, so regeneration is the
        # only repair and carries none of the divergence cost it does below.
        return (False, message, "sudo update-ca-trust")

    if local_anchors:
        # Restoring would silently drop these from the bundle — revoking trust
        # the operator added by hand is a worse failure than the one being
        # fixed, so it is not offered.
        return (False, message,
                f"sudo update-ca-trust  (this host carries locally added "
                f"anchors — {', '.join(local_anchors)} — so extracted/ cannot "
                f"be restored from the image without revoking them; it stays "
                f"locally modified and every later anchor rotation needs this "
                f"command again)")

    # Every anchor is the image's, so the bundle can be restored from the
    # booted deployment. That brings `ostree admin config-diff` clean, which
    # is the point: the merge tracks the image again and later anchor
    # rotations apply by themselves, instead of needing a repair each time.
    return (False, message,
            "sudo cp -a /usr/etc/pki/ca-trust/extracted/. "
            "/etc/pki/ca-trust/extracted/ && "
            "sudo restorecon -R /etc/pki/ca-trust/extracted  "
            "(restores the merge, so later anchor rotations self-apply; "
            "`sudo update-ca-trust` also restores trust but leaves this host "
            "diverged from the image forever)")


def _selinux_type(path: Path) -> str | None:
    """Type field of a path's SELinux label, or None if it has none.

    Read straight off the xattr rather than shelling out to ls -Z: no
    parsing of locale-dependent output, and a missing xattr (SELinux
    disabled, or a filesystem without labels) raises OSError and reads as
    unknown.
    """
    try:
        raw = os.getxattr(str(path), "security.selinux")
    except OSError:
        return None
    parts = raw.decode(errors="replace").rstrip("\x00").split(":")
    return parts[2] if len(parts) > 2 else None


def selinux_label_check(rule_present: bool | None, label: str | None,
                        name: str, is_vm: bool = False) -> tuple[bool, str, str | None]:
    """Verdict for the workload tree's SELinux labeling: (passed, message, fix).

    Two independent facts, because they fail independently and one of them
    fails silently. The fcontext rule has to be registered AND the tree has to
    carry the label it implies; a tree labelled correctly today with no rule
    behind it reverts on the next relabel.

    **The expected type differs by substrate.** Container workloads need
    container_file_t, which rootless podman requires. VM workloads need
    svirt_image_t: `virt_domain` has no read, write, getattr or append on
    container_file_t, so a confined QEMU cannot use a disk image labelled with
    it. The VM rule is registered per workload at enable time and wins its own
    subtree against the blanket rule by specificity.

    Historically this check hardcoded container_file_t, which would report
    every correctly-labelled VM workload as broken.
    """
    expected = "svirt_image_t" if is_vm else "container_file_t"
    scope = f"{WORKLOADS_BASE}/{name}" if is_vm else str(WORKLOADS_BASE)
    consumer = ("a confined QEMU will be denied access to its own disks"
                if is_vm else "rootless podman will be denied access to it")

    if rule_present is None and label is None:
        return (True, "SELinux labeling state unknown "
                      "(semanage unavailable or SELinux disabled)", None)
    # `restorecon -RF`, not `-R`: both container_file_t and svirt_image_t are
    # in contexts/customizable_types, and plain restorecon skips any file whose
    # *current* type is customizable — printing "not reset as customized by
    # admin" only under -v, and exiting 0. Without -F the remediation below
    # would appear to succeed and change nothing.
    fix = (f"sudo semanage fcontext -a -t {expected} '{scope}(/.*)?' "
           f"&& sudo restorecon -RF {scope}")

    if label is not None and label != expected:
        return (False, f"Workload tree is labeled {label}, not {expected} "
                       f"— {consumer}"
                       + ("" if rule_present else " (and no fcontext rule is "
                          "registered for it, so a relabel will not fix it)"),
                fix)
    if rule_present is False:
        return (False, f"No fcontext rule registered for {scope} — the tree is "
                       f"labeled correctly now but a full relabel or "
                       f"`restorecon -F` will reset it to the default type",
                fix)
    return (True, f"SELinux labeling correct ({expected}, "
                  f"fcontext rule registered)", None)


def vm_socket_dir_selinux_check(rule_present: bool | None, label: str | None,
                                path: str | None = None
                                ) -> tuple[bool, str, str | None]:
    """Verdict for /run/workload-vm's SELinux labeling: (passed, message, fix).

    The sibling of selinux_label_check for the *runtime* half. Same two
    independent facts — the fcontext rule is registered, and the directory
    carries the type it implies — but they fail differently here, and worse:

      * /run is a tmpfs, so the directory is recreated every boot and
        `workload-ensure-user` restorecons it at each one. That relabel is a
        silent no-op when no rule is registered, so a lost rule is not noticed
        at the moment it is lost but at the next boot.
      * the unit sets RuntimeDirectoryPreserve=yes, so a directory that came up
        mislabelled survives every `systemctl restart`. Restarting the workload
        cannot fix it and neither can re-running ensure-user's relabel once
        anything has been created inside; the fix has to name the directory.

    The reported symptom is whichever confined domain reaches the directory
    first, which is not the same for every workload — verified by breaking a
    real host both ways. QEMU (svirt_t) times out on the QMP socket; virtiofsd
    (wlvfsd_t) fails earlier still on its pid file, so a VM with volumes never
    reaches QEMU at all and shows a plain "Permission denied" instead. Naming
    only one of them sends half the readers looking in the wrong place.

    Host-global, unlike the per-workload tree rule, so a single missing rule
    takes out every VM workload at once. Reported per workload anyway, because
    that is where the operator is looking when the guest will not boot.

    `label` is None when the directory does not exist — the ordinary state for
    a stopped workload, and not a finding: nothing is mislabelled yet, and the
    rule is what decides how it comes up. `path` names whichever directory the
    caller actually inspected (the shared parent, or one workload's preserved
    subdirectory under it), so the message points at the thing to relabel.
    """
    path = path or str(VM_SOCKET_DIR)
    if rule_present is None and label is None:
        return (True, "VM socket dir SELinux state unknown "
                      "(semanage unavailable or SELinux disabled)", None)

    # Plain restorecon, no -F: neither var_run_t nor qemu_var_run_t is a
    # customizable type, so nothing is skipped. Rooted at the parent because
    # that is what the rule names and a wrong label there is inherited by every
    # workload's subdirectory.
    fix = (f"sudo semanage fcontext -a -t {VM_SOCKET_SELINUX_TYPE} "
           f"'{VM_SOCKET_FCONTEXT_PATTERN}' "
           f"&& sudo systemctl stop workload-<name> "
           f"&& sudo restorecon -R {VM_SOCKET_DIR}")

    if label is not None and label not in (VM_SOCKET_SELINUX_TYPE,
                                           VM_SOCKET_SELINUX_TYPE_REAL):
        return (False, f"{path} is labeled {label}, not "
                       f"{VM_SOCKET_SELINUX_TYPE_REAL} — nothing confined can "
                       f"write there, so the guest will not start: QEMU cannot "
                       f"create its QMP socket (a bare 60s timeout), and on a "
                       f"VM with volumes virtiofsd fails one layer earlier "
                       f"creating its pid file (a plain 'Permission denied')"
                       + ("" if rule_present else
                          " (and no fcontext rule is registered, so the "
                          "relabel at boot is a no-op)")
                       + ". RuntimeDirectoryPreserve=yes keeps the "
                         "mislabelled directory across restarts, so a restart "
                         "will not clear this",
                fix)
    if rule_present is False:
        return (False, f"No fcontext rule registered for "
                       f"{VM_SOCKET_FCONTEXT_PATTERN} — the next boot recreates "
                       f"{VM_SOCKET_DIR} on tmpfs as var_run_t and every VM "
                       f"workload on this host stops starting",
                fix)
    return (True, f"VM socket dir labeled correctly "
                  f"({VM_SOCKET_SELINUX_TYPE_REAL}, fcontext rule registered)",
            None)


def gpu_selinux_check(xserver: bool | None, blanket: bool | None,
                      module: str | None) -> tuple[bool, str, str | None]:
    """Verdict for NVIDIA device access under SELinux: (passed, message, fix).

    Split out from the collector so the outcomes are testable without
    standing up a workload. `module` is the workload's own SELinux module
    name, or None if it ships no policy.cil. See the caller for why only the
    no-path-at-all case fails.

    `module` is decided first, and deliberately: a workload with its own type
    runs as `wl_<name>.process`, and `container_use_xserver_devices` is
    written against `container_t` alone, so the boolean grants that workload
    nothing. Reporting the boolean for a module-bearing workload names a path
    that does not apply to it, and would read as "allowed" on a host where
    the boolean is on but the bundle's own grant is missing — the exact
    regression ShippedBundleGrantsTest exists to catch. Observed on a GPU hypervisor host
    2026-07-29: vnc-sway (wl_vnc_sway.process) was reported as covered by the
    boolean while its access in fact came from its own module.
    """
    if module:
        return (True, f"NVIDIA device access granted by the workload's own "
                      f"policy module {module} (host booleans are written "
                      f"against container_t and do not cover its type)", None)
    if xserver is None and blanket is None:
        return (True, "NVIDIA GPU requested; SELinux boolean state unknown "
                      "(getsebool unavailable or SELinux disabled)", None)
    if xserver:
        return (True, "NVIDIA device access allowed "
                      "(container_use_xserver_devices on)", None)
    if blanket:
        return (True, "NVIDIA device access allowed via the legacy blanket "
                      "container_use_devices — narrow it: setsebool -P "
                      "container_use_xserver_devices on, then setsebool -P "
                      "container_use_devices off", None)
    return (False, "NVIDIA GPU requested but nothing grants access to "
                   "/dev/nvidia* (xserver_misc_device_t) — expect permission "
                   "denied from the CUDA runtime",
            "sudo setsebool -P container_use_xserver_devices on")


def _unit_props(unit: str) -> dict | None:
    """systemd properties for a host-global unit, or None if it has no unit file.

    `systemctl show` invents a stub for a nonexistent unit (LoadState=not-found)
    rather than failing, so absence is read off LoadState, not the exit code.
    """
    result = subprocess.run(
        ["systemctl", "show", unit,
         "-p", "LoadState,ActiveState,SubState,Result,NRestarts"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return None
    props = dict(
        line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
    )
    if props.get("LoadState") in ("not-found", "masked", "bad-setting", "error"):
        return None
    return props


def host_artifact_check(artifact, state, name: str) -> tuple[bool, str, str | None]:
    """Verdict for one declared host artifact.

    `state` is whatever the probe for this kind produced: the `systemctl show`
    property dict for a unit (None when the unit file is absent), a bool for a
    file. Pure, so the verdicts are testable without a host — same split as
    selinux_label_check().

    NRestarts > 0 is a failure in its own right and is the reason this check
    exists: `<name>-udev-relay.service` restart-looped 2012 times over seven
    days on a deployed host while `systemctl list-units --failed` stayed clean, because
    a unit that keeps being restarted never settles into `failed`.
    """
    fix = f"sudo workloadctl enable {name}  (re-runs the workload's setup.sh)"
    if artifact.kind == "unit":
        if state is None:
            return (False,
                    f"Declared host unit is not installed: {artifact.ref}", fix)
        active = state.get("ActiveState", "unknown")
        try:
            n_restarts = int(state.get("NRestarts") or 0)
        except ValueError:
            n_restarts = 0
        if n_restarts > 0:
            return (False,
                    f"Declared host unit is restart-looping: {artifact.ref} "
                    f"(NRestarts={n_restarts}, currently {active}) — it never "
                    f"reaches 'failed', so --failed will not show it",
                    f"journalctl -u {artifact.ref} -n 50")
        if active in ("failed", "activating"):
            result = state.get("Result", "")
            detail = f"{active}" + (f", Result={result}" if result else "")
            return (False,
                    f"Declared host unit is not running: {artifact.ref} ({detail})",
                    f"journalctl -u {artifact.ref} -n 50")
        return (True,
                f"Host unit active: {artifact.ref} "
                f"({active}/{state.get('SubState', '')})", None)

    if state:
        return (True, f"Host file present: {artifact.ref}", None)
    return (False, f"Declared host file is missing: {artifact.ref}", fix)


def collect_host_artifact_checks(config, _check) -> None:
    """Check the host-global artifacts a workload's setup.sh declares.

    Fills the gap `workload_run_files()` names in its own docstring — it covers
    generator output only, so a `setup.sh` sidecar is invisible to every verb
    built on it. The set is read from the script rather than inferred, because
    the script is the only thing that knows: half of these are installed
    conditionally (sunshine mints a TLS leaf only where the homelab CA is
    readable, publishes mDNS only where avahi's service dir exists), and a
    declaration made anywhere else would report those correct absences as
    faults.

    Gated on `enabled`: disable() removes these, so a disabled workload is
    *supposed* to be missing them.
    """
    if not config.enabled:
        return
    declared = host_setup_artifacts(config)
    if declared is None:
        return  # no [host] setup, or the script is gone (enable reports that)

    if declared.error:
        _check("host_artifacts", False,
               f"Could not read host artifact declaration: {declared.error}")
        return

    if not declared.supported:
        # Unknown, not empty. Reported as a pass because an un-updated bundle is
        # not a fault of the host being diagnosed — but reported at all, so the
        # operator knows this workload's sidecars are outside the check.
        _check("host_artifacts", True,
               f"Host artifacts undeclared — setup.sh does not implement "
               f"'{HOST_SETUP_ARTIFACTS_ACTION}', so any sidecars it installs "
               f"are not checked here")
        return

    for line in declared.unparsed:
        _check("host_artifacts", False,
               f"setup.sh {HOST_SETUP_ARTIFACTS_ACTION} printed a line that is "
               f"not a declaration: {line!r}",
               fix=f"expected '<{'|'.join(HOST_ARTIFACT_KINDS)}> <ref>' per line, "
                   f"nothing else on stdout")

    if not declared.artifacts:
        _check("host_artifacts", True,
               "setup.sh declares no host-global artifacts")
        return

    for artifact in declared.artifacts:
        state = (_unit_props(artifact.ref) if artifact.kind == "unit"
                 else Path(artifact.ref).exists())
        passed, message, fix = host_artifact_check(artifact, state, config.name)
        _check(f"host_artifact[{artifact.ref}]", passed, message, fix=fix)


def vm_network_check(config) -> tuple[str, bool, str]:
    """Report a VM's network topology and its uid-derived values.

    Returns a (check_name, passed, message) triple ready for `_check`.

    This exists because ADR 006 made two facts invisible from the TOML. The
    management address and nflog group are derived from the workload's uid, so
    nothing in the config says where to ssh or what to capture; and a VM that
    names a bridge is unfiltered, which the config states only by implication.
    """
    bridge = config.vm_bridge
    if bridge is not None:
        return ("vm_network", True,
                f"VM is on operator-provided bridge {bridge} — it has a real "
                f"LAN identity and host egress policy does not reach it. This "
                f"is a supported configuration; passt is the filterable one.")

    try:
        uid = config.uid
    except Exception:
        # The user does not exist yet, which check 1 already reports. Say what
        # is true rather than claiming the network is fine or that it is broken.
        return ("vm_network", True,
                "VM uses passt; management address and nflog group are derived "
                "from the workload uid, which does not exist yet")

    return ("vm_network", True,
            f"VM uses passt (uid {uid} is its network identity) — "
            f"ssh {vm_management_address(uid)}:{VM_MGMT_SSH_PORT}, "
            f"capture with 'tcpdump -i nflog:{vm_nflog_group(uid)}'")


def _nft_json(*args):
    """Run `nft -j <args>` and return the parsed document, or None."""
    try:
        result = subprocess.run([NFT_BIN, "-j", *args],
                                capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except ValueError:
        return None


# Sentinel for "measure this yourself", distinct from None, which several of
# these observations use to mean a real state (not running / could not ask).
PROBE = object()


def _selinux_module_loaded(module: str) -> bool | None:
    """Whether `semodule -l` lists `module`. None if it could not be asked."""
    try:
        result = subprocess.run(["semodule", "-l"],
                                capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return module in result.stdout.split()


# Host-global SELinux modules whose source the RPM installs, so a loaded module
# can be compared against what the image ships. Deliberately just these two.
#
# The image's own modules (pasta_sandbox, container_input_devices,
# seatd_container, extra_varrun) are compiled into the policy store at build
# time and ship no .cil to the host -- there is nothing on the machine to
# compare them against, so they cannot be checked here however much they have
# the same drift problem. The udica templates belong to the udica RPM, and the
# per-workload bundle modules are templated (`__WL_MODULE__` is substituted at
# enable), so a byte comparison against workloads/<name>/policy.cil would report
# every one of them as stale.
HOST_SELINUX_MODULES = (
    (VM_SELINUX_MODULE, VM_SELINUX_CIL),
    ("workload-proxy", "/usr/share/workloadctl/workload-proxy.cil"),
)

# Where semodule keeps the policy store. Fedora's default is /var/lib/selinux,
# but semanage.conf can move it with `store-root=` -- and the hypervisor image
# sets `store-root=/etc/selinux`, which is precisely what puts the store inside
# the tree ostree 3-way-merges and creates the drift this check reports. Both
# layouts are live on real hosts (measured: a bootc host in /etc, a package host
# in /var/lib), so neither can be assumed.
SEMANAGE_CONF = Path("/etc/selinux/semanage.conf")
SELINUX_STORE_ROOTS = (Path("/var/lib/selinux"), Path("/etc/selinux"))


def _selinux_store_roots() -> list[Path]:
    """Candidate policy-store roots, the configured one first."""
    roots = []
    try:
        for line in SEMANAGE_CONF.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("store-root") and "=" in stripped:
                roots.append(Path(stripped.split("=", 1)[1].strip()))
                break
    except OSError:
        pass
    for root in SELINUX_STORE_ROOTS:
        if root not in roots:
            roots.append(root)
    return roots


def _loaded_module_source(module: str) -> bytes | None:
    """The CIL source semodule stored for `module`, or None if unreadable.

    semodule keeps the module it was handed verbatim under
    /etc/selinux/<type>/active/modules/<priority>/<module>/cil, bzip2-compressed
    when semanage.conf enables compression (the Fedora default) and plain
    otherwise. Verified byte-identical to the installed .cil on a live host, so
    an equality test against the shipped file is exact rather than heuristic.

    Globbed over store root, policy type and priority instead of hardcoding
    one path: the priority is a semodule argument, a host may carry more than
    one policy type, and the store root itself moves (see SELINUX_STORE_ROOTS).
    None on any failure -- the store is 0600, so an unprivileged caller lands
    here and must be reported as "cannot tell", never as a difference.
    """
    matches = []
    for root in _selinux_store_roots():
        matches += sorted(root.glob(f"*/active/modules/*/{module}/cil"))
    if not matches:
        return None
    try:
        raw = matches[-1].read_bytes()
    except OSError:
        return None
    if raw.startswith(b"BZh"):
        try:
            return bz2.decompress(raw)
        except (OSError, ValueError):
            return None
    return raw


SELINUXFS = Path("/sys/fs/selinux")

# (allow SRC TGT (CLASS (perm perm ...))) -- the only CIL form this asks about.
# Anything else in the module (typetransition, typeattributeset, filecon) either
# is not an access decision or cannot be queried through the AV interface.
_CIL_ALLOW = re.compile(
    r"\(allow\s+([\w.]+)\s+([\w.]+)\s+\(([\w.]+)\s+\(([^()]*)\)\)\)")
_CIL_COMMENT = re.compile(r";[^\n]*")


def _cil_allow_rules(text: str, block_type: str | None = None):
    """Yield (src, tgt, class, perms) for every allow rule in CIL `text`.

    Comments are stripped BEFORE whitespace is collapsed, and collapsing is what
    lets a rule wrapped across lines match at all (the shipped per-workload
    policies wrap their longer ones). Collapsing first would let a `;` comment
    swallow the rule on the following line.

    `block_type` resolves the block-local names a per-workload policy uses: its
    rules are written inside `(block wl_<name> …)` against a bare `process`,
    which is really `wl_<name>.process`. `self` means the source type, so it is
    resolved rather than skipped -- `(allow process self (process (…)))` is one
    of the commonest rules in these bundles, and dropping it would leave the
    check blind to most of a policy.
    """
    text = _CIL_COMMENT.sub("", text)
    text = re.sub(r"\s+", " ", text)
    for src, tgt, cls, perms in _CIL_ALLOW.findall(text):
        if block_type is not None:
            src = block_type if src == "process" else src
            tgt = block_type if tgt == "process" else tgt
        if src == "self":
            continue
        if tgt == "self":
            tgt = src
        yield src, tgt, cls, perms.split()


def _policy_grants(src: str, tgt: str, cls: str, perms) -> bool | None:
    """Ask the KERNEL whether the loaded policy grants src->tgt:cls {perms}.

    /sys/fs/selinux/access is the access-vector interface libselinux's
    security_compute_av() uses: write "scontext tcontext classindex request",
    read back "allowed decided auditallow auditdeny seqno flags". It answers
    from the policy actually in force, in ~0.4ms, with no setools dependency --
    where `sesearch` costs ~1.75s per call, needs setools-console installed, and
    reads rules rather than decisions.

    NOTE the perms file holds a bit POSITION, not a mask: getattr on filesystem
    reads "4" and the mask is 1 << 3. Using the value directly asks about the
    wrong permission and quietly reports a granted rule as missing.

    None when the question cannot be put (SELinux disabled, class absent from
    this policy, context rejected). Never guesses.
    """
    try:
        index = (SELINUXFS / "class" / cls / "index").read_text().strip()
        request = 0
        for perm in perms:
            bit = int((SELINUXFS / "class" / cls / "perms" / perm)
                      .read_text().strip())
            request |= 1 << (bit - 1)
    except (OSError, ValueError):
        return None
    if not request:
        return None

    # A type used as an object may be an object type (object_r) or another
    # domain (system_r, e.g. svirt_t -> wlvfsd_t:unix_stream_socket connectto),
    # and the right role is not derivable from the rule alone. So ask under
    # both and take the permissive answer.
    #
    # Both, rather than the first the kernel accepts: an object_r context over a
    # domain type is ACCEPTED but then fails the RBAC constraint on
    # process:transition, so `init_t -> wlvfsd_t:process transition` came back
    # denied on a host that plainly grants it. Type enforcement is what is being
    # measured here; a constraint failing under a role this rule never uses is
    # noise, and treating it as a missing rule reports every host as stale.
    answers = []
    for role in ("system_r", "object_r"):
        scon = f"system_u:system_r:{src}:s0"
        tcon = f"system_u:{role}:{tgt}:s0"
        try:
            with open(SELINUXFS / "access", "r+") as fh:
                fh.write(f"{scon} {tcon} {index} {request}")
                fh.seek(0)
                allowed = int(fh.read().split()[0], 16)
        except (OSError, ValueError, IndexError):
            continue
        answers.append((allowed & request) == request)
    if not answers:
        return None
    return any(answers)


def _selinux_module_enforced(cil_path: str) -> bool | None:
    """Whether every allow rule in the shipped CIL is granted by live policy.

    This is the question that matters and the byte comparison only approximates:
    "are the rules this build needs actually in force?". It catches the case the
    file comparison cannot -- ostree adopting a new module SOURCE while keeping
    the locally-modified COMPILED policy, so the store looks current and the
    kernel still enforces the old rule set. Nothing rebuilds policy at boot.

    Deliberately not the converse test: a policy granting MORE than the shipped
    module asks for is not stale, it is a superset (a host mid-upgrade, or one
    carrying an extra local module), and failing it would cry wolf.

    None if no rule could be evaluated at all.
    """
    try:
        text = Path(cil_path).read_text()
    except OSError:
        return None
    return _rules_enforced(text)


def _rules_enforced(text: str, block_type: str | None = None) -> bool | None:
    """Whether every queryable allow rule in `text` is granted by live policy."""
    asked = False
    for src, tgt, cls, perms in _cil_allow_rules(text, block_type):
        granted = _policy_grants(src, tgt, cls, perms)
        if granted is None:
            continue
        asked = True
        if not granted:
            return False
    return True if asked else None


def _workload_module_enforced(config) -> bool | None:
    """Whether the workload's own policy module is in force, as this build
    defines it.

    The per-workload modules drift harder than the host-global ones, and in a
    way nothing recovers from on its own: `semodule -i` at enable makes them
    locally ADDED files in the deployment's /etc, and ostree never updates an
    added file. So a bundle's policy.cil edit that ships in a new image is not
    applied to an existing instance, ever, until someone re-enables it -- where
    workload-vm at least merges when its file is pristine.

    Resolved through the same chain enable uses, so a `workloadctl edit`
    override is compared rather than the shipped default, and an instance whose
    `selinux_policy` names another bundle is compared against that bundle.
    """
    if not getattr(config, "selinux_policy", None):
        return None
    try:
        text = config.resolve_control_file("policy.cil").read_text()
    except (OSError, ValueError):
        return None
    module = selinux_module_name(config.name)
    return _rules_enforced(text.replace("__WL_MODULE__", module),
                           block_type=f"{module}.process")


def _selinux_module_current(module: str, cil_path: str) -> bool | None:
    """Whether the loaded `module` matches the CIL the RPM ships.

    None when it cannot be determined. The check exists because a `bootc
    upgrade` does NOT deliver a changed module to a host whose policy store has
    local modifications -- and every host that has enabled a workload has them,
    since `semanage fcontext -a` rewrites the store. /usr is replaced wholesale
    so the shipped .cil is always current; the loaded module is what drifts, and
    `semodule -l` reports it as present eitherway.
    """
    try:
        shipped = Path(cil_path).read_bytes()
    except OSError:
        return None
    loaded = _loaded_module_source(module)
    if loaded is None:
        return None
    return loaded == shipped


def _vm_qemu_context(name: str) -> str | None:
    """SELinux context of the running QEMU for `name`, or None if not found.

    Found by its QMP socket path in /proc/<pid>/cmdline rather than by walking
    down from the unit's MainPID, because MainPID is workload-vm-notify: runcon
    execs QEMU in its own process, so QEMU is the wrapper's child, not the
    service's main process.

    The comm test is not belt-and-braces, it is the whole correctness of this
    function. workload-vm-notify is invoked WITH the full QEMU command line as
    its arguments, so the wrapper's own cmdline contains the socket path too —
    matching on the path alone finds the wrapper (unconfined_service_t, since
    it is a Python script) and reports every confined VM as unconfined. Observed
    on a live host where `ps -eo label` showed svirt_t at the same moment.
    """
    needle = f"{VM_SOCKET_DIR}/{name}/qmp.sock".encode()
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            with open(f"/proc/{entry.name}/comm") as fh:
                if not fh.read().startswith("qemu"):
                    continue
            with open(f"/proc/{entry.name}/cmdline", "rb") as fh:
                if needle not in fh.read():
                    continue
            with open(f"/proc/{entry.name}/attr/current") as fh:
                return fh.read().strip("\x00\n")
        except OSError:
            continue        # the process exited mid-scan, or we may not look
    return None


def vm_confinement_check(config, *, enabled=PROBE, module_loaded=PROBE,
                         qemu_context=PROBE) -> tuple[str, bool, str] | None:
    """Report whether a running VM is actually confined as svirt_t.

    The observations are injectable so the verdict logic is testable without a
    live host; each defaults to the PROBE sentinel and is measured here. The
    sentinel is not None, because None is a meaningful *observation* for two of
    the three — "the VM is not running" and "semodule could not be asked" — and
    conflating those with "go and look" would make them untestable.

    Two failures this exists for, both of which leave every other signal green.
    A VM whose QEMU never entered `svirt_t` (runcon absent, the transition
    refused, an old unit still live after an upgrade) runs
    `unconfined_service_t` while the disks are labelled and the module is
    loaded — it looks confined from every direction except the one that counts.
    And a host missing `wlvfsd` breaks virtiofs volumes for a confined VM, which
    surfaces as a guest that boots without its shares rather than as anything
    naming SELinux.

    That second one is specifically a bootc hazard: the policy store lives in
    /etc, which ostree 3-way-merges, so `bootc upgrade` does not deliver the
    module to a host that has ever loaded a per-workload policy locally.
    """
    if not config.is_vm:
        return None

    if enabled is PROBE:
        enabled = selinux_enabled()
    if not enabled:
        # Not a lapse to scold: SELinux disabled is the host's posture, and the
        # VM runs exactly as it did before confinement shipped. Say so plainly.
        return ("vm_confinement", True,
                "SELinux is disabled on this host; the VM runs unconfined "
                "(nftables egress policy is unaffected — it keys on the uid)")

    if module_loaded is PROBE:
        module_loaded = _selinux_module_loaded(VM_SELINUX_MODULE)
    if qemu_context is PROBE:
        qemu_context = _vm_qemu_context(config.name)

    has_volumes = bool(config.config.get("vm", {}).get("volumes"))

    if qemu_context is not None:
        qemu_type = qemu_context.split(":")[2] if qemu_context.count(":") >= 2 \
            else qemu_context
        if qemu_type != VM_QEMU_TYPE:
            return ("vm_confinement", False,
                    f"QEMU is running as {qemu_type}, not {VM_QEMU_TYPE} — this "
                    f"VM is NOT confined. Check that {VM_RUNCON_BIN} exists and "
                    f"restart it: systemctl restart "
                    f"workload-{config.name}.service")

    if has_volumes and module_loaded is False:
        return ("vm_confinement", False,
                f"the {VM_SELINUX_MODULE} SELinux module is not loaded, so a "
                f"confined QEMU cannot connect to this VM's virtiofsd sockets "
                f"and its volumes will not mount. Load it: "
                f"semodule -i {VM_SELINUX_CIL}")

    if qemu_context is None:
        state = {True: "loaded", False: "NOT loaded", None: "unknown"}[module_loaded]
        return ("vm_confinement", True,
                f"VM is not running; {VM_SELINUX_MODULE} module {state}")

    tail = "" if not has_volumes else \
        f", {VM_SELINUX_MODULE} module " + \
        {True: "loaded", False: "NOT loaded", None: "state unknown"}[module_loaded]
    return ("vm_confinement", True, f"QEMU confined as {VM_QEMU_TYPE}{tail}")


def vm_egress_check(config) -> tuple[str, bool, str] | None:
    """Report whether a VM's declared egress posture is actually in force.

    Returns None for workloads the check does not apply to, so the caller can
    skip emitting a line at all.

    The failure this exists for: a config that says `egress = "filtered"` while
    the uid is absent from `wl_filtered`. That VM is wide open and every other
    signal — the unit is active, the guest has network, `status` is green —
    looks correct. Nothing else in `diagnose` would notice.
    """
    if config.vm_bridge is not None:
        return None                      # unfiltered by design; see vm_network
    egress = (config.vm_network or {}).get("egress", VM_EGRESS_DEFAULT)
    try:
        uid = config.uid
    except Exception:
        return None                      # no user yet; check 1 reports it

    table = NFT_TABLE.split()
    filtered = _nft_json("list", "set", *table, NFT_SET_FILTERED)
    if filtered is None:
        if egress != "filtered":
            return ("vm_egress", True,
                    f"egress is {egress!r}; no filter table present, which is "
                    f"consistent")
        return ("vm_egress", False,
                f"egress is 'filtered' but the {NFT_TABLE} table is absent, so "
                f"this VM is NOT filtered. It is rebuilt on the next start: "
                f"systemctl restart workload-{config.name}.service")

    armed = str(uid) in vm_owned_elements(uid, nft_set_elements(filtered))
    if egress != "filtered":
        if armed:
            return ("vm_egress", False,
                    f"egress is {egress!r} but uid {uid} is still in "
                    f"{NFT_SET_FILTERED} — a stale element from an earlier "
                    f"config is filtering this VM")
        return ("vm_egress", True, f"egress is {egress!r}; VM is not filtered")

    if not armed:
        return ("vm_egress", False,
                f"egress is 'filtered' but uid {uid} is absent from "
                f"{NFT_SET_FILTERED} — this VM is running UNFILTERED while its "
                f"config says otherwise. Restart it to re-arm: "
                f"systemctl restart workload-{config.name}.service")

    allowed = []
    for set_name in (NFT_SET_ALLOW4, NFT_SET_ALLOW6):
        payload = _nft_json("list", "set", *table, set_name)
        if payload:
            allowed += vm_owned_elements(uid, nft_set_elements(payload))

    # The drop counter is shared: one rule guarded on set membership serves
    # every filtered workload, so this is a host-wide total and saying
    # otherwise would misattribute a sibling's dropped traffic.
    dropped = nft_drop_counter(_nft_json("list", "chain", *table, "output"))
    tail = ""
    if dropped is not None:
        tail = (f"; {dropped[0]} packets dropped across all filtered VMs "
                f"(the counter is shared, not per-workload)")
    return ("vm_egress", True,
            f"egress filtered on uid {uid} with {len(allowed)} allow "
            f"entr{'y' if len(allowed) == 1 else 'ies'}{tail}")


def capture_check(config, *, unit_active=PROBE, log_rules=PROBE
                  ) -> tuple[str, bool, str] | None:
    """Report a running capture, so its extra rule is explained rather than found.

    `pcap` is the one read-flavoured command that writes into the
    security-critical `inet workload_filter` table. The rule it adds is
    non-terminating and cannot change accept/drop semantics, but an operator
    who finds an unexplained rule there is right to be alarmed — so diagnose
    names it, names the unit that owns it, and says how it goes away.

    Both outcomes are passes. A capture is a deliberate act, not a fault. The
    line is omitted entirely when nothing is capturing, so this costs a
    healthy workload nothing.
    """
    if unit_active is PROBE:
        # Unpack: service_active returns (active, state), and a bare tuple is
        # always truthy — which reported a running capture for every workload,
        # capture or not. The injected-argument tests never caught it because
        # they pass a bool and skip this line.
        unit_active, _ = service_active(pcap_unit_name(config.name))
    if log_rules is PROBE:
        log_rules = _log_rule_count()

    if not unit_active and not log_rules:
        return None

    unit = pcap_unit_name(config.name)
    if unit_active:
        return ("capture", True,
                f"a packet capture is running ({unit}). It adds a "
                f"non-terminating `log` rule to {NFT_TABLE}, which cannot "
                f"change accept/drop semantics and is removed when the "
                f"capture stops: workloadctl pcap --stop {config.name}")

    # Rules with no unit: a stale artefact rather than an active capture, and
    # the one state worth flagging — the unit's ExecStopPost should have taken
    # them, so something removed the unit without running it.
    return ("capture", False,
            f"{log_rules} `log` rule(s) remain in {NFT_TABLE} with no capture "
            f"unit running. They are non-terminating and change no policy, but "
            f"nothing owns them now. Clear them: nft delete table "
            f"{NFT_TABLE}  (the skeleton is rebuilt on the next VM start)")


def _log_rule_count() -> int:
    """How many `log` rules the filter table currently carries."""
    total = 0
    for chain in PCAP_CHAINS:
        total += _count_log_rules(
            _nft_json("list", "chain", *NFT_TABLE.split(), chain))
    return total


def _count_log_rules(payload) -> int:
    count = 0
    for item in (payload or {}).get("nftables", []):
        rule = item.get("rule")
        if not rule:
            continue
        if any("log" in expr for expr in rule.get("expr", [])
               if isinstance(expr, dict)):
            count += 1
    return count


def vm_proxy_check(config, *, elements=PROBE, address_present=PROBE
                   ) -> tuple[str, bool, str] | None:
    """Report whether a VM's hostname policy is actually reachable.

    Returns None for workloads with no `hosts` list — the check does not apply,
    so no line is emitted.

    Three things have to hold together and each fails silently on its own. The
    proxy can be listening while its uid is absent from the redirect map, in
    which case the guest's connection to the advertised address goes to a host
    where nothing listens. The redirect can be installed while the dummy
    interface is missing, in which case the destination is unroutable. And
    either can be true while the unit is active, the guest boots, and `status`
    is green — a filtered VM whose only route out is a proxy it cannot reach
    looks exactly like a VM with a network problem.

    Observations are injectable (PROBE sentinel) so the verdict logic is
    testable without a live host.
    """
    if not vm_uses_proxy(config.config):
        return None
    try:
        uid = config.uid
    except Exception:
        return None                      # no user yet; check 1 reports it

    hosts = vm_proxy_hosts(config.vm_network or {})

    if elements is PROBE:
        payload = _nft_json("list", "map", *NFT_PROXY_TABLE.split(),
                            NFT_PROXY_MAP)
        elements = None if payload is None else nft_set_elements(payload)

    if address_present is PROBE:
        address_present = _proxy_address_present()

    restart = f"systemctl restart workload-{config.name}-proxy.service"

    if elements is None:
        return ("vm_proxy", False,
                f"{len(hosts)} host pattern(s) configured but the "
                f"{NFT_PROXY_TABLE} table is absent, so nothing redirects this "
                f"guest to its proxy. Rebuilt on the next start: {restart}")

    # The map is keyed on uid; the element renders as "uid : addr . port".
    armed = any(key.split(":")[0].strip() == str(uid)
                for key in _proxy_map_keys(elements))
    if not armed:
        return ("vm_proxy", False,
                f"{len(hosts)} host pattern(s) configured but uid {uid} has no "
                f"element in {NFT_PROXY_MAP}, so this guest's traffic to "
                f"{VM_PROXY_ADDR}:{VM_PROXY_PORT} is not redirected anywhere. "
                f"Re-arm it: {restart}")

    if not address_present:
        return ("vm_proxy", False,
                f"uid {uid} is redirected, but {VM_PROXY_ADDR} is not present "
                f"on {VM_PROXY_IFACE}, so the guest cannot route to it. "
                f"Re-create it: {restart}")

    return ("vm_proxy", True,
            f"hostname policy on {len(hosts)} pattern(s), reached at "
            f"{VM_PROXY_ADDR}:{VM_PROXY_PORT} and redirected to this "
            f"workload's own proxy")


def _proxy_map_keys(elements) -> list:
    """Flatten nft's map JSON to one entry per element.

    nft 1.1.6 renders a map element as a two-item list [key, value] — NOT the
    {"elem": {"key": …}} shape a set's counted element uses. Reading only the
    dict shape reports a working redirect as missing, which is how this was
    found. Hand-built fixtures may also use the flat "k : v" string. All three
    are normalized to something whose leading field is the uid.
    """
    out = []
    for elem in elements or []:
        if isinstance(elem, list) and elem:
            out.append(str(elem[0]))
        elif isinstance(elem, dict) and "elem" in elem:
            inner = elem["elem"]
            key = inner.get("key", inner) if isinstance(inner, dict) else inner
            out.append(str(key[0] if isinstance(key, list) else key))
        else:
            out.append(str(elem))
    return out


def _proxy_address_present() -> bool:
    """Whether the advertised address is configured on the dummy interface."""
    try:
        result = subprocess.run(
            ["/usr/sbin/ip", "-o", "addr", "show", "dev", VM_PROXY_IFACE],
            capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and VM_PROXY_ADDR in result.stdout


def subid_derived_check(
    entries: list[tuple[str, tuple[int, int] | None]],
    expected: tuple[int, int],
    uid: int,
) -> tuple[bool, str, str | None]:
    """Verdict: does each subid file's main range equal the derived one?

    `entries` is [(file, (start, count) | None), …]; a None (no entry at all) is
    Check 2's business, not this one.

    Why this can't self-heal: `configure_subuid_subgid` grandfathers any
    existing entry — deliberately, because shifting a UID mapping under a
    running container corrupts its namespace. Correct behaviour, but it makes
    drift permanent *and* invisible: every later enable leaves the old range
    alone and reports success. Nothing else in the tree compares the two, which
    is why three of six workload users on a lab host sat on pre-derivation
    ranges for months.

    This is the load-bearing half of the pair, for a reason worth stating
    because it is not the one originally filed. `useradd` refuses to allocate
    over an entry it can see in /etc/subuid (measured — see
    subid_overlap_check), but `append_subid_entries` has no such courtesy: it
    writes the derived range without consulting anything. Collision safety
    therefore comes entirely from the derivation putting workload ranges above
    the territory `useradd` allocates in. A range off the formula is a range
    that has left the only guarantee there is.

    It also predicts (per claim_uid) a re-created workload adopting the old UID
    and grandfathering the wrong range straight back in.
    """
    off = [(f, e) for f, e in entries if e is not None and e != expected]
    if not off:
        return (True,
                f"Subid ranges match the derived range "
                f"({expected[0]}:{expected[1]})", None)
    detail = ", ".join(f"{f} has {s}:{c}" for f, (s, c) in off)
    return (False,
            f"Subid range is not the derived range for UID {uid}: expected "
            f"{expected[0]}:{expected[1]}, {detail}",
            "Remapping is manual and must be done with the workload stopped: "
            "rewrite the entry in /etc/subuid and /etc/subgid, then chown "
            "state/ from the old range to the new one. Scope the chown to "
            "state/ — every file in data/ is owned by the workload UID itself, "
            "so only the reconstructible graphroot needs remapping")


def subid_overlap_check(
    entries: list[tuple[str, tuple[int, int] | None]],
    window: tuple[int, int],
) -> tuple[bool, str, str | None]:
    """Verdict: does any main range sit inside `useradd`'s allocation window?

    **`useradd` is not the naive allocator this was originally filed against.**
    Measured on Fedora 44: park `_wl-caddy:589824:65536` in /etc/subuid where
    the next allocation would land, and successive `useradd`s take 524288 and
    then *655360* — they skip the parked range rather than overlapping it. Fill
    the window so the only candidate would straddle an existing entry and
    `useradd` refuses outright ("Can't get unique subordinate UID range"). So a
    range inside the window is not, on its own, the two-namespaces-in-one
    hazard this check was first justified by; that framing was wrong and this
    docstring is the correction.

    What it still catches is an **ordering** hazard, because the protection is
    one-directional. `useradd` defends itself against entries it can see in
    /etc/subuid. Nothing defends *us*: `append_subid_entries` writes the derived
    range without consulting existing entries, so a workload provisioned after
    a colliding human range would write straight over it. Living above the
    window is what makes that unreachable — which is why subid_derived is the
    load-bearing one and this check is its corroboration, not the reverse.

    And `useradd` can only skip what it can see. /etc is per-deployment on a
    bootc host while /etc/subuid entries accrue at runtime, so a rollback can
    boot a deployment whose /etc/subuid never listed a workload enabled later,
    while /var still holds files owned out of that range. A `useradd` there
    allocates it legitimately. Same /etc-vs-/var asymmetry as claim_uid.

    Scope is ranges starting strictly below SUB_UID_MAX. A range starting *at*
    SUB_UID_MAX — which on stock Fedora is also SUBID_BASE, since the two
    windows abut — cannot be taken while the entry is listed, per the refusal
    measured above, so it is not reported.
    """
    sub_uid_min, sub_uid_max = window
    inside = [(f, e) for f, e in entries if e is not None and e[0] < sub_uid_max]
    if not inside:
        return (True,
                f"Subid ranges are clear of useradd's window "
                f"({sub_uid_min}-{sub_uid_max})", None)
    detail = ", ".join(f"{f} at {s}:{c}" for f, (s, c) in inside)
    return (False,
            f"Subid range sits inside the window useradd allocates from "
            f"({sub_uid_min}-{sub_uid_max}): {detail} — useradd skips ranges "
            f"it can see in /etc/subuid, but nothing protects this range if it "
            f"is provisioned after a colliding one, or if a rollback boots an "
            f"/etc/subuid that never listed it",
            "Remap onto the derived range (see subid_derived's fix). Not "
            "urgent on its own — check `/etc/subuid` for a human user's range "
            "that already overlaps this one, which is the case that has "
            "already gone wrong rather than one that might")


# An MCS category set on a file under data/ is a fault signature, not a
# configuration. Ordinary container writes into a bind-mounted volume land at
# plain `s0` — verified by creating files inside running containers in every
# volume of two workloads, one with a per-workload SELinux type and one without.
# So categories there mean something stamped those files with one specific
# container's level, and MCS grants access only when the file's category set is
# a SUBSET of the reading process's. Podman draws a fresh random pair per
# container, so the next start is denied — while mode and owner still read as
# correct, which is what makes this expensive to diagnose. `ls -l` shows nothing;
# only `ls -Z` does.
#
# state/ is deliberately out of scope. It holds the rootless podman graphroot,
# where per-container MCS labelling is exactly right and is rewritten as
# containers come and go; scanning it would fire on every healthy workload.
#
# The glob is anchored on the level field on purpose: the obvious `*:c*` also
# matches the *type* in `...:container_file_t:s0` and reports every file as bad.
MCS_SCAN_TIMEOUT = 60
MCS_SAMPLE_PATHS = 3


def _check_mcs_labels(config, _check) -> None:
    """Flag files under data/ carrying SELinux MCS categories.

    Stays silent when the scan cannot run at all (SELinux disabled, findutils
    built without -context, timeout on a very large tree): an untestable
    condition must not be recorded as a pass.
    """
    data_dir = workload_data_dir(config.name)
    if not data_dir.is_dir():
        return
    try:
        found = subprocess.run(
            ["find", str(data_dir), "-context", "*:s0:c*", "-print"],
            capture_output=True, text=True, timeout=MCS_SCAN_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired):
        return
    if found.returncode != 0:
        return

    paths = [p for p in found.stdout.splitlines() if p]
    if not paths:
        _check("mcs_labels", True,
               f"No MCS-categorised files under {data_dir}")
        return

    sample = ", ".join(paths[:MCS_SAMPLE_PATHS])
    if len(paths) > MCS_SAMPLE_PATHS:
        sample += f", ... (+{len(paths) - MCS_SAMPLE_PATHS} more)"
    _check("mcs_labels", False,
           f"{len(paths)} file(s) under {data_dir} carry SELinux MCS "
           f"categories and may be unreadable to the container despite correct "
           f"mode and owner: {sample}",
           fix=f"sudo find {data_dir} -context '*:s0:c*' "
               f"-exec chcon -l s0 {{}} +")


# The runtime state `disable` tears down: linger, the runtime dir it implies,
# the per-workload SELinux module, the generated units and the service state.
# Every one of these is *supposed* to be absent on a disabled workload, so each
# reports its absence as a failure and a disabled workload came out of the
# battery carrying eight findings that were all the same fact — with fixes
# (`enable-linger`, `daemon-reload`, `workloadctl enable`) that an operator who
# stopped the workload on purpose must not follow.
#
# Deliberately NOT in this list: `selinux_labels`, `subid_*`, `home_dir`,
# `volume_paths`. Those describe on-disk state that must stay correct while the
# workload is off — it is what the next enable builds on — so their failures are
# real findings, not consequences. `user_session` is absent rather than
# excluded: Check 3b only runs when linger is on, which for a disabled workload
# it is not.
DISABLED_CONSEQUENCE_CHECKS = (
    "linger_enabled",
    "runtime_dir",
    "selinux_module",
    "podman_session",
    "service_file",
    "service_enabled",
    "service_active",
)


def collapse_disabled_consequences(checks: list[dict], name: str) -> list[dict]:
    """Fold a disabled workload's expected absences into one check.

    Only ever called for a workload whose enable marker is gone. Returns a new
    list with the folded entries replaced, in place, by a single passing
    `workload_disabled` check — passing because a workload that is off is a
    state, not a fault, and the eight failures it used to print made the one
    finding that *was* real (a drifted subid range, say) the ninth item in a
    list of eight non-problems.

    Only absences fold. An entry in the list that *passed* is residue — linger
    still on, a unit still loaded after disable — which is a genuine anomaly and
    stays visible. `podman_session` inverts that: it is the skip line emitted
    when the workload's rootless podman cannot answer, so for a disabled
    workload its passing form IS the absence. It cannot be here in its failing
    form, which _podman_read only emits when the workload is enabled.
    """
    folded = [
        c for c in checks
        if c["check"] in DISABLED_CONSEQUENCE_CHECKS
        and (not c["passed"] or c["check"] == "podman_session")
    ]
    if not folded:
        return checks

    folded_ids = {id(c) for c in folded}
    kept = [c for c in checks if id(c) not in folded_ids]
    names = ", ".join(c["check"] for c in folded)
    summary = {
        "check": "workload_disabled",
        "passed": True,
        "message": (
            f"Workload is disabled, so its runtime state is absent as "
            f"expected — {len(folded)} checks folded into this one: {names}. "
            f"Run it with: sudo workloadctl enable {name}"
        ),
    }
    kept.insert(checks.index(folded[0]), summary)
    return kept


def collect_diagnose_checks(config, manager: WorkloadManager):
    """Run the diagnose check battery and return (checks, passed).

    checks is the ordered list of {check, passed, message[, fix]} dicts;
    passed is True iff every check passed. Pure collection — no root
    check, no printing, no exit — shared by cmd_diagnose and doctor.
    """
    checks = []
    linger_enabled = False  # set by Check 3; referenced by the session/runtime checks

    # The rootless-podman session checks below (subuid/subgid ranges, linger, the
    # user@<uid> manager and its /run/user/<uid>) describe how a *container*
    # workload runs. A VM has none of it: QEMU uses no user namespaces, and the
    # VM service is a system unit with User=<workload user> and its own
    # RuntimeDirectory=workload-vm/<name>, so it never needs a user manager to be
    # up. workload-ensure-user says as much and deliberately skips both steps for
    # kind == "vm" — which made these checks unfixable as well as wrong: they
    # failed, and the fix they printed (`workload-ensure-user <name>`) was the
    # very code path that had decided not to do the thing.
    session_scoped = not config.is_vm

    def _check(name, passed, message, fix=None):
        entry = {"check": name, "passed": passed, "message": message}
        if fix:
            entry["fix"] = fix
        checks.append(entry)

    # The podman-backed checks below (image inventory, container liveness) run
    # under the workload's *own* rootless podman, which needs its user manager
    # and /run/user/<uid> up. A disabled workload has neither — disable() drops
    # linger, and logind GCs the runtime dir — so podman exits before it can
    # answer anything and every such read raises. Unwrapped, that aborted the
    # whole battery at Check 6 with a traceback, discarding the dozen checks
    # after it including the ones that would have said *why* (Checks 8/9: the
    # workload is off). Diagnose is the first thing an operator reaches for on a
    # workload that is not running, so that is exactly the case it must survive.
    #
    # podman.py's own self-heal does not cover this and should not: it is gated
    # on linger already being enabled, because a read path must never be what
    # turns linger on. For a disabled workload it correctly declines, so the
    # error arrives here.
    #
    # A failed read *omits* its check rather than passing it — asserting an image
    # is present in a store we could not open is the same guess ca_trust_anchors
    # refuses to make. The omission is announced once, because a check that
    # silently vanishes is indistinguishable from one that passed. Whether that
    # announcement is a fault depends on enabled-ness: for a disabled workload an
    # unreachable podman is the expected consequence of it being off; for an
    # enabled one it is a real failure worth a fix.
    podman_reported = False

    def _podman_read(fn, *args):
        """Run a podman read that must not abort the battery: (ok, value)."""
        nonlocal podman_reported
        try:
            return True, fn(*args)
        except PodmanError as e:
            if not podman_reported:
                podman_reported = True
                # Last line, not str(e): the exception text carries the whole
                # argv, and the operator needs the reason, not the command.
                lines = e.stderr.strip().splitlines()
                detail = lines[-1].strip() if lines else f"exited {e.returncode}"
                if config.enabled:
                    _check("podman_session", False,
                           f"Rootless podman is not answering for "
                           f"{config.username}: {detail}",
                           fix=(f"Check the user manager: systemctl status "
                                f"user@{config.uid}.service, then "
                                f"sudo workloadctl restart {config.name}"))
                else:
                    # Emitted, then folded away by
                    # collapse_disabled_consequences — which is why this text is
                    # not what an operator sees for a disabled workload; the
                    # fold names the check instead. The two layers stay
                    # independent on purpose: this one knows only that podman
                    # could not answer, and says so whoever is reading.
                    _check("podman_session", True,
                           f"Image and container checks skipped: "
                           f"{config.username} has no rootless podman session "
                           f"(workload disabled)")
            return False, None

    # Check 1: User exists
    user_exists = manager.user_exists(config)
    if user_exists:
        _check("user_exists", True, f"User exists: {config.username} (UID {config.uid})")
    else:
        _check("user_exists", False, f"User does not exist: {config.username}",
               fix="sudo workloadctl enable " + config.name)

    # Check 2: Subuid/subgid configured
    if user_exists and session_scoped:
        with_entries = subid_files_with_entries(config.username)
        subuid_exists = subuid_file() in with_entries
        subgid_exists = subgid_file() in with_entries

        if subuid_exists and subgid_exists:
            _check("subid_configured", True, "Subuid/subgid configured")
        else:
            _check("subid_configured", False, "Subuid/subgid not configured",
                   fix=f"sudo /usr/libexec/workloadctl/workload-ensure-user {config.name}")

        # Checks 2b/2c: is the configured range the *right* range? Presence
        # (above) is not enough — the grandfather in configure_subuid_subgid
        # never corrects an existing entry, so a range predating the derivation
        # survives every enable and every upgrade, silently.
        entries = [
            (str(path), read_subid_entry(config.username, path))
            for path in (subuid_file(), subgid_file())
        ]
        # No window means login.defs was unreadable or silent on the keys — omit
        # the check rather than pass it, so "clear of the window" is never
        # claimed on a guess about where the window is.
        window = login_defs_subid_window()
        if any(e is not None for _, e in entries):
            try:
                expected = derived_subid_range(config.uid)
            except ValueError:
                expected = None  # UID out of range: user_exists/enable's problem
            if expected:
                _check("subid_derived",
                       *subid_derived_check(entries, expected, config.uid))
            if window:
                _check("subid_overlap", *subid_overlap_check(entries, window))

    # Check 3: Linger enabled
    if user_exists and session_scoped:
        linger_result = subprocess.run(
            ["loginctl", "show-user", str(config.uid), "--property=Linger", "--value"],
            capture_output=True, text=True
        )
        linger_enabled = linger_result.returncode == 0 and linger_result.stdout.strip() == "yes"
        if linger_enabled:
            _check("linger_enabled", True, "Linger enabled")
        else:
            _check("linger_enabled", False, "Linger not enabled",
                   fix=f"sudo loginctl enable-linger {config.uid}")

    # Check 3b: User manager session live. Rootless workloads need user@<uid> up
    # (linger keeps it alive) for the user D-Bus that crun's cgroup manager talks
    # to. If linger is on but the session is dead, the safe fix is to RESTART the
    # user manager — never `loginctl terminate-user`, which also tears down
    # /run/user/<uid> and leaves workloads failing with 226/NAMESPACE.
    if user_exists and linger_enabled:
        session_active = subprocess.run(
            ["systemctl", "is-active", f"user@{config.uid}.service"],
            capture_output=True, text=True,
        ).returncode == 0
        if session_active:
            _check("user_session", True, f"User manager session active: user@{config.uid}.service")
        else:
            _check("user_session", False,
                   f"User manager session not active despite linger: user@{config.uid}.service",
                   fix=f"sudo systemctl restart user@{config.uid}.service  "
                       f"(do NOT use 'loginctl terminate-user' — it removes /run/user/{config.uid} "
                       f"→ 226/NAMESPACE)")

    # Check: per-workload SELinux module loaded (only if the workload ships one)
    if config.selinux_policy:
        module = selinux_module_name(config.name)
        if not shutil.which("semodule"):
            _check("selinux_module", False,
                   "SELinux tooling (semodule) not found",
                   fix="sudo dnf install policycoreutils")
        else:
            loaded = subprocess.run(["semodule", "-l"], capture_output=True, text=True)
            if module in loaded.stdout.split():
                _check("selinux_module", True,
                       f"SELinux module loaded: {module} "
                       f"(type {selinux_type_name(config.name)})")
                # Loaded says nothing about WHICH version is loaded, and these
                # modules are locally-added files that no upgrade ever replaces.
                if _workload_module_enforced(config) is False:
                    _check("workload_selinux_module_current", False,
                           f"{module} is loaded but does not grant everything "
                           f"this build's policy.cil asks for, so the module "
                           f"predates the bundle (an image upgrade never "
                           f"replaces it -- enable installed it, so /etc owns "
                           f"it)",
                           fix=f"sudo workloadctl enable {config.name}")
            else:
                _check("selinux_module", False,
                       f"SELinux module not loaded: {module}",
                       fix=f"sudo workloadctl enable {config.name}")

    # Check: the host-global SELinux modules match what the image ships.
    #
    # `semodule -l` only answers "present", and a module that is present but
    # OLD is the expected state after a `bootc upgrade`, not an exotic one: the
    # policy store lives in /etc, ostree 3-way-merges /etc, and every host that
    # has enabled a workload has a locally-modified store because `semanage
    # fcontext -a` rewrites it. So the image's new module is silently not
    # applied while every existing check still passes. Measured on a live host:
    # 493 of ~639 diverged /etc paths were the policy store, the module
    # directory itself among them.
    #
    # /usr is replaced wholesale, so the shipped .cil is authoritative and the
    # loaded module is the thing that drifts.
    # Two questions, and the order matters. "Does the live policy grant what
    # this build's module asks for?" is the real one, answered against the
    # kernel. The file comparison is only the fallback for when that cannot be
    # asked, because it can be fooled in both directions: ostree may adopt a new
    # module SOURCE while keeping the old COMPILED policy (looks current, is
    # not), and a host whose loaded policy is a superset reads as differing
    # while working perfectly.
    stale = []
    determinable = False
    for module, cil_path in HOST_SELINUX_MODULES:
        state = _selinux_module_enforced(cil_path)
        how = "rules are not in force"
        if state is None:
            state = _selinux_module_current(module, cil_path)
            how = "stored module differs from the shipped .cil"
        if state is None:
            continue
        determinable = True
        if not state:
            stale.append((module, cil_path, how))
    if determinable and stale:
        detail = "; ".join(f"{m} ({h})" for m, _, h in stale)
        _check("selinux_module_current", False,
               f"host SELinux policy is behind the version this build ships: "
               f"{detail}. A `bootc upgrade` does not replace a "
               f"locally-modified policy store, and nothing recompiles policy "
               f"at boot, so the image's rules can be present on disk and still "
               f"not enforced",
               fix="; ".join(f"sudo semodule -i {c}" for _, c, _ in stale))
    elif determinable:
        _check("selinux_module_current", True,
               "Host SELinux modules match the shipped policy")

    # Check: NVIDIA device nodes reachable under SELinux.
    #
    # /dev/nvidia*, nvidiactl, nvidia-uvm* and nvidia-caps/* are all
    # xserver_misc_device_t, and unlike DRI (dri_device_t, covered by the
    # default-on container_use_dri_devices) and ROCm (hsa_device_t,
    # unconditional) nothing grants it by default. The base image deliberately
    # grants no device access host-wide, so an NVIDIA workload reaches those
    # nodes one of three ways: container_use_xserver_devices, which the
    # hypervisor-nvidia-* variants set and which covers container_t; its own
    # policy.cil, which is how a workload with a udica-derived type must do it
    # (the boolean is written against container_t, not container_domain); or
    # the legacy blanket container_use_devices, which works but hands every
    # container every device_node type and should be migrated off.
    #
    # Only the no-path-at-all case fails. A host still carrying the blanket
    # boolean is working, not broken, so it passes with the migration in the
    # message — image-side SELinux changes don't reach existing hosts on
    # `bootc upgrade` (the policy store is in /etc and semodule -i has made it
    # locally modified), so that state is expected on any machine that predates
    # the scoped policy and shouldn't read as a fault.
    vendors = _gpu_vendors(config)
    wants_nvidia = "nvidia" in vendors or (
        "auto" in vendors and Path("/dev/nvidia0").exists()
    )
    if wants_nvidia:
        passed, message, fix = gpu_selinux_check(
            _getsebool("container_use_xserver_devices"),
            _getsebool("container_use_devices"),
            selinux_module_name(config.name) if config.selinux_policy else None,
        )
        _check("gpu_selinux", passed, message, fix=fix)

    # Check 4: Runtime directory exists
    if user_exists and session_scoped:
        runtime_dir = Path(f"/run/user/{config.uid}")
        if runtime_dir.exists():
            _check("runtime_dir", True, f"Runtime directory exists: {runtime_dir}")
        elif linger_enabled:
            # Linger is on but the dir is gone — the classic `terminate-user`
            # aftermath. Restarting the user manager recreates it.
            _check("runtime_dir", False, f"Runtime directory missing: {runtime_dir}",
                   fix=f"sudo systemctl restart user@{config.uid}.service "
                       f"(linger is on; do NOT 'loginctl terminate-user')")
        else:
            _check("runtime_dir", False, f"Runtime directory missing: {runtime_dir}",
                   fix=f"sudo loginctl enable-linger {config.uid} (creates the runtime directory)")

    # Check 5: Home directory exists
    if user_exists:
        home_dir = config.home_dir
        if home_dir.exists():
            _check("home_dir", True, f"Home directory exists: {home_dir}")
        else:
            _check("home_dir", False, f"Home directory missing: {home_dir}",
                   fix=f"sudo /usr/libexec/workloadctl/workload-ensure-user {config.name}")

    # Check 5b: the workload tree carries the label its substrate needs, and the
    # rule that keeps it across relabels is registered. The expected type and
    # the rule that governs it both differ between containers (container_file_t,
    # blanket rule) and VMs (svirt_image_t, per-workload rule) — see
    # selinux_label_check.
    root_dir = workload_root_dir(config.name)
    if root_dir.exists():
        pattern = (vm_fcontext_pattern(config.name) if config.is_vm else None)
        passed, message, fix = selinux_label_check(
            _fcontext_rule_present(pattern), _selinux_type(root_dir),
            config.name, is_vm=config.is_vm)
        _check("selinux_labels", passed, message, fix=fix)

    # Check 5c: the VM runtime socket dir. Host-global, and checked separately
    # from 5b because the two rules are registered by different things at
    # different times — the tree rule per workload at enable, this one once by
    # the RPM's %post — so one being right says nothing about the other. A host
    # rebuild that drops this one takes out every VM workload with a timeout
    # that names nothing SELinux; see vm_socket_dir_selinux_check.
    if config.is_vm:
        # Both halves, parent first. The parent is what the rule names and what
        # a fresh boot inherits from, but RuntimeDirectoryPreserve=yes means a
        # workload's own subdirectory can stay mislabelled under a parent that
        # was since put right — the exact shape of a host where the rule was
        # added by hand and only the running service restarted. Report the
        # first one that is wrong, so the fix names a directory that is
        # actually wrong rather than the one further up.
        rule_present = _fcontext_rule_present(VM_SOCKET_FCONTEXT_PATTERN)
        inspected = str(VM_SOCKET_DIR)
        label = _selinux_type(VM_SOCKET_DIR) if VM_SOCKET_DIR.exists() else None
        if label in (VM_SOCKET_SELINUX_TYPE, VM_SOCKET_SELINUX_TYPE_REAL):
            sock_dir = VM_SOCKET_DIR / config.name
            if sock_dir.exists():
                inspected, label = str(sock_dir), _selinux_type(sock_dir)
        passed, message, fix = vm_socket_dir_selinux_check(
            rule_present, label, inspected)
        _check("vm_socket_dir_selinux", passed, message, fix=fix)

    # Check 6: Image(s) exist locally
    if user_exists:
        if config.is_vm:
            # VM workloads have no container image to inventory — the disk is
            # provisioned by the substrate, not pulled. `config.image` is the
            # sentinel "(vm)" and get_image_id() would pointlessly shell out to
            # `podman image inspect "(vm)"`, so skip the container-image check.
            pass
        elif config.is_multi:
            for cname, img in config.container_images():
                ok, iid = _podman_read(manager.podman(config).image_id, img)
                if not ok:
                    continue
                if iid:
                    _check(f"image_available[{cname}]", True,
                           f"Image available for {cname}: {img} ({iid[:12]})")
                else:
                    _check(f"image_available[{cname}]", False,
                           f"Image not available for {cname}: {img}",
                           fix="Image will be pulled on first start")
        else:
            ok, image_id = _podman_read(manager.get_image_id, config)
            if not ok:
                pass  # announced by _podman_read; nothing here to assert
            elif image_id:
                _check("image_available", True, f"Image available: {config.image} ({image_id[:12]})")
            else:
                pull_policy = config.config.get("container", {}).get("pull", "missing")
                if pull_policy == "never":
                    try:
                        build_script = config.resolve_control_file("build.sh")
                        fix = (f"Build it: {build_script}" if build_script.exists()
                               else f"Build or provide: {config.image}")
                    except ValueError as e:
                        # Malformed [workload] bundle: report it as the fix-text
                        # rather than letting it crash the whole diagnose run.
                        fix = f"Fix [workload] bundle: {e}"
                else:
                    fix = "Image will be pulled on first start"
                _check("image_available", False, f"Image not available: {config.image}", fix=fix)

    # Check 7: Service file(s) exist
    service_file = Path(f"/run/systemd/system/{config.service_name}")
    if service_file.exists():
        _check("service_file", True, f"Service file exists: {service_file}")
    else:
        _check("service_file", False, f"Service file missing: {service_file}",
               fix="sudo systemctl daemon-reload")

    if config.is_multi:
        for unit in config.sub_service_names():
            sub_file = Path(f"/run/systemd/system/{unit}")
            if sub_file.exists():
                _check(f"service_file[{unit}]", True, f"Sub-service file exists: {unit}")
            else:
                _check(f"service_file[{unit}]", False, f"Sub-service file missing: {unit}",
                       fix="sudo systemctl daemon-reload")

    # Check 7b: Config not edited since the units were last generated. Editing
    # the workload.toml + `daemon-reload` does NOT regenerate per-workload units
    # (only `enable` runs the unit-writer), a common foot-gun.
    if service_file.exists():
        if units_outdated(config.name):
            _check("config_current", False,
                   "Config edited since last enable — generated units are stale",
                   fix=f"sudo workloadctl enable {config.name}  "
                       f"(daemon-reload does not regenerate units; see `drift` for the diff)")
        else:
            _check("config_current", True, "Generated units match current config (by mtime)")

    # Check 7c: Units generated by the workloadctl that is running. Units live in
    # /run and are only rewritten at boot or by `enable`, so `dnf upgrade
    # workloadctl` on a package host leaves running workloads on the previous
    # generator's output. Check 7b cannot see it — neither file's mtime moved.
    if service_file.exists():
        other_build = units_from_other_build(config.name)
        if other_build:
            _check("units_current", False,
                   f"Units were generated by {other_build}, not the running "
                   f"{WORKLOADCTL_VERSION}",
                   fix=f"sudo workloadctl enable {config.name}  "
                       f"(a reboot also regenerates them; `drift` normalizes the "
                       f"stamp away, so it will not show this)")
        else:
            _check("units_current", True,
                   f"Units generated by the running build ({WORKLOADCTL_VERSION})")

    # Check 7d: Host-global artifacts the workload's setup.sh installed. Not in
    # workload_run_files(), so nothing above this line can see them.
    collect_host_artifact_checks(config, _check)

    # Check 7e: the VM's network posture. There is no shared bridge unit to
    # check any more (ADR 006), but there is something the TOML does not show:
    # under passt the management address and nflog group are *derived from the
    # uid*, so an operator reading the config cannot work out where to ssh or
    # which nflog group to capture. Report the derived values.
    #
    # Both outcomes are passes. A VM on an operator-provided bridge takes a
    # real LAN identity and is unfiltered — that is a supported configuration,
    # not a lapse, and saying so plainly is what honesty requires here.
    # Scolding an operator for a deliberate choice would be the wrong reading.
    if config.is_vm:
        _check(*vm_network_check(config))
        egress_result = vm_egress_check(config)
        if egress_result:
            _check(*egress_result)
        confinement_result = vm_confinement_check(config)
        if confinement_result:
            _check(*confinement_result)
        proxy_result = vm_proxy_check(config)
        if proxy_result:
            _check(*proxy_result)

    # Not gated on is_vm: the host-side vantage works on every substrate,
    # because `meta skuid` does not care what produced the socket.
    capture_result = capture_check(config)
    if capture_result:
        _check(*capture_result)

    # Check 7f: host trust anchors, for workloads that pull an image. Host-wide
    # state rather than this workload's, reported here for the same reason
    # gpu_selinux is: it is invisible from the workload's own files, and the
    # failure it produces (a pull that cannot verify the registry) is read as
    # the workload's problem. Skipped for VMs, which pull nothing through
    # podman, and omitted rather than passed when the store can't be read —
    # claiming trust is intact on a store we could not open asserts a guess.
    if not config.is_vm:
        facts = _ca_trust_facts()
        if facts is not None:
            _check("ca_trust_anchors", *ca_trust_anchor_check(*facts))

    # Check 8: Service enabled
    result = subprocess.run(
        ["systemctl", "is-enabled", config.service_name],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        _check("service_enabled", True, "Service enabled")
    else:
        _check("service_enabled", False, "Service not enabled",
               fix="Service should be auto-enabled via generator")

    # Check 9: Service active
    svc_active, service_state = service_active(config.service_name)
    if svc_active:
        _check("service_active", True, f"Service active: {service_state}")
    else:
        # No disabled-workload branch here any more: when this fails on a
        # disabled workload the check is folded into `workload_disabled`, so a
        # fix reading "Workload is disabled in config" could never be printed.
        _check("service_active", False, f"Service not active: {service_state}",
               fix=f"Check logs: sudo journalctl -u {config.service_name} -n 50")

    # Check 10: Container(s) running. A VM workload has no container to inspect —
    # its liveness is the QEMU service's own state, already covered by Check 9,
    # and `podman container inspect workload-<name>` under the VM's user would
    # simply never find anything.
    if user_exists and not config.is_vm:
        if config.is_multi:
            for cname in config.container_names():
                pn = config.podman_container_name(cname)
                ok, cs = _podman_read(
                    manager.podman(config).container_status, pn)
                if not ok:
                    continue
                if cs:
                    _check(f"container_running[{cname}]", True,
                           f"Container running: {pn} ({cs})")
                else:
                    _check(f"container_running[{cname}]", False,
                           f"Container not running: {pn}",
                           fix=f"Check logs: sudo journalctl -u workload-{config.name}-{cname}.service -n 50")
        else:
            ok, container_status = _podman_read(
                manager.podman(config).container_status, config.container_name)
            if not ok:
                pass  # announced by _podman_read; nothing here to assert
            elif container_status:
                _check("container_running", True, f"Container running: {container_status}")
            else:
                _check("container_running", False, "Container not running",
                       fix=f"Check logs: sudo journalctl -u {config.service_name} -n 50")

    # Check 11: Volume paths exist
    volumes = config.get_volumes()
    if volumes:
        missing_volumes = []
        for vol_spec in volumes:
            expanded_spec = expand_volume_path(vol_spec, str(config.home_dir))
            host_path = expanded_spec.split(':')[0]
            if not Path(host_path).exists():
                missing_volumes.append(host_path)

        if not missing_volumes:
            _check("volume_paths", True, f"All volume paths exist ({len(volumes)} volumes)")
        else:
            _check("volume_paths", False,
                   f"Missing volume paths: {', '.join(missing_volumes)}",
                   fix="sudo mkdir -p " + " ".join(missing_volumes))

    _check_mcs_labels(config, _check)

    # Check 12: UID mapping (for userns=host)
    userns_mode = config.config.get("security", {}).get("userns", "keep-id")
    if userns_mode == "host" and user_exists:
        try:
            entry = read_subid_entry(config.username, subuid_file())
            if entry is not None:
                subuid_start, subuid_count = entry
                subuid_end = subuid_start + subuid_count - 1
                _check("uid_mapping", True,
                       f"UID mapping configured: container UIDs 1-{subuid_count} → host UIDs {subuid_start}-{subuid_end}")
            elif subuid_file() in subid_files_with_entries(config.username):
                # A line for this user exists but doesn't parse as
                # user:start:count. Distinct from absence: the fix is to repair
                # the entry, not to re-run enable.
                _check("uid_mapping", False,
                       f"Error reading subuid: malformed {subuid_file()} entry for {config.username}",
                       fix=f"Repair the {config.username} line in {subuid_file()}")
            else:
                _check("uid_mapping", False, "Cannot calculate UID mapping (subuid not found)",
                       fix=f"Check {subuid_file()} configuration")
        except Exception as e:
            _check("uid_mapping", False, f"Error reading subuid: {e}")

    # Trust posture: host userns dissolves the per-workload isolation boundary.
    # When it's in effect (only reachable if opted in — an un-acknowledged
    # host-userns workload fails validation and never generates/enables),
    # surface the elevated trust so it isn't invisible. Passes: it's an
    # acknowledged, intended state, not a fault.
    if uses_host_userns(config.config):
        _check("host_userns", True,
               'Elevated trust: security.userns="host" in effect '
               f'(acknowledged via {HOST_USERNS_OPT_IN}=true) — the '
               'per-workload isolation boundary is dissolved.')

    if not config.enabled:
        checks = collapse_disabled_consequences(checks, config.name)

    return checks, all(c["passed"] for c in checks)


def cmd_diagnose(args, manager: WorkloadManager):
    """Diagnose workload runtime setup (user, subids, linger, SELinux)"""
    require_root()
    config = load_config_or_exit(args.workload, json_mode=args.json)

    checks, passed = collect_diagnose_checks(config, manager)
    checks_passed = sum(1 for c in checks if c["passed"])
    checks_total = len(checks)

    if args.json:
        print(json.dumps({
            "workload": config.name,
            "passed": passed,
            "checks_passed": checks_passed,
            "checks_total": checks_total,
            "checks": checks
        }, indent=2))
        sys.exit(0 if passed else 1)

    print(f"Diagnosing workload: {config.name}")
    print()
    for c in checks:
        symbol = "✓" if c["passed"] else "✗"
        print(f"{symbol} {c['message']}")
        if "fix" in c and not c["passed"]:
            print(f"  Fix: {c['fix']}")

    print()
    print(f"Checks: {checks_passed}/{checks_total} passed")
    print()

    if not passed:
        print("Issues found:")
        for i, c in enumerate((c for c in checks if not c["passed"]), 1):
            print(f"  {i}. {c['message']}")
            if "fix" in c:
                print(f"     {c['fix']}")
        print()
        sys.exit(1)
    else:
        # "healthy" alone would read as "running" on a workload that is off —
        # the same confusion the folded check exists to remove.
        state = "" if config.enabled else " (disabled — nothing is running)"
        print(f"✓ All checks passed - workload is healthy{state}")
        sys.exit(0)

