"""
The SELinux half of diagnose: is the policy the workload runs under the one
the image ships, and is the tree labelled the way that policy expects.

Labels on the workload tree and the VM socket dir, the per-workload and
host-global modules (loaded, current, and actually enforced), the NVIDIA
device nodes, QEMU's confinement, and the MCS categories that mark a data/
tree one container has stamped as its own.
"""
import bz2
import os
from pathlib import Path
import re
import shutil
import subprocess

from config_parser import SOCKET_DIR, WORKLOADS_BASE
from diagnose_probe import PROBE
from egress_selinux import (
    INSPECT_SELINUX_CIL, INSPECT_SELINUX_MODULE, VM_QEMU_TYPE,
    VM_CLOCK_SELINUX_CIL, VM_CLOCK_SELINUX_MODULE,
    VM_RESOLVE_SELINUX_CIL, VM_RESOLVE_SELINUX_MODULE, VM_RUNCON_BIN,
    VM_SELINUX_CIL, VM_SELINUX_MODULE, VM_SOCKET_FCONTEXT_PATTERN,
    VM_SOCKET_SELINUX_TYPE, VM_SOCKET_SELINUX_TYPE_REAL, selinux_enabled,
)
from workload_lib import selinux_module_name, workload_data_dir


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
    path = path or str(SOCKET_DIR)
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
           f"&& sudo restorecon -R {SOCKET_DIR}")

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
                       f"{SOCKET_DIR} on tmpfs as var_run_t and every VM "
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
    regression ShippedBundleGrantsTest exists to catch: a workload gets reported
    as covered by the boolean while its access in fact comes from its own
    module.
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
# can be compared against what the image ships. Deliberately just these three:
# the VM domain, and the two the retired proxy's module was replaced by. A
# module the RPM installs and this tuple omits is a domain that drifts silently
# -- which is what happened when workload-proxy left and this list did not
# follow it.
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
    (INSPECT_SELINUX_MODULE, INSPECT_SELINUX_CIL),
    (VM_RESOLVE_SELINUX_MODULE, VM_RESOLVE_SELINUX_CIL),
    (VM_CLOCK_SELINUX_MODULE, VM_CLOCK_SELINUX_CIL),
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
    needle = f"{SOCKET_DIR}/{name}/qmp.sock".encode()
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
