"""
diagnose_battery — the checks `diagnose` runs, in the order an operator reads.

collect_diagnose_checks() is pure collection: no root check, no printing, no
exit, so `doctor` can run the same battery fleet-wide and render it its own way.
Where validate asks "is this config fit to enable", diagnose asks "this is
enabled and unhappy — what is wrong with it right now".

The battery is the order and the gating; each check's reading lives in the
function it calls, here for the checks with no family and in
lib/diagnose_selinux.py (labels, modules, confinement), lib/diagnose_inspect.py
(the inspector and the resolver), lib/diagnose_egress.py (the nft plane),
lib/diagnose_subid.py, lib/diagnose_ca_trust.py and lib/diagnose_provisioning.py
(host artifacts, cloud-init marker). The fold that hides a disabled workload's
consequences is here too, because the battery is its only caller.
"""
from pathlib import Path
import shutil
import subprocess

from diagnose_ca_trust import _ca_trust_facts, ca_trust_anchor_check
from config_parser import SOCKET_DIR, workload_root_dir
from diagnose_egress import (
    allow_drift_check, capture_check, container_resolver_check,
    vm_egress_check, vm_network_check,
)
from diagnose_inspect import inspect_check, vm_resolve_check
from diagnose_provisioning import collect_host_artifact_checks, vm_provisioning_check
from diagnose_selinux import (
    HOST_SELINUX_MODULES, _check_mcs_labels, _fcontext_rule_present,
    _getsebool, _gpu_vendors, _selinux_module_current,
    _selinux_module_enforced, _selinux_type, _workload_module_enforced,
    gpu_selinux_check, selinux_label_check, vm_confinement_check,
    vm_socket_dir_selinux_check,
)
from diagnose_subid import subid_derived_check, subid_overlap_check
from egress_selinux import (
    VM_SOCKET_FCONTEXT_PATTERN, VM_SOCKET_SELINUX_TYPE,
    VM_SOCKET_SELINUX_TYPE_REAL,
)
from podman import PodmanError
from workload_selinux import fcontext_pattern
from run_files import units_outdated, units_from_other_build
from substrate import service_active
from validation import uses_host_userns
from vm_provision import (
    PROVISION_DONE, PROVISION_FAILED,
    read_provision_marker, record_guest_provision_result,
)
from workload_lib import (
    expand_volume_path, HOST_USERNS_OPT_IN, selinux_module_name,
    selinux_type_name, WORKLOADCTL_VERSION,
)
from workload_uid import (
    derived_subid_range, login_defs_subid_window, read_subid_entry,
    subgid_file, subid_files_with_entries, subuid_file,
)
from workloadctl_core import WorkloadManager


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
# excluded: it only runs when linger is on, which for a disabled workload it is
# not.
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


class _PodmanReads:
    """Podman reads that must not abort the battery.

    The podman-backed checks (image inventory, container liveness) run
    under the workload's *own* rootless podman, which needs its user manager
    and /run/user/<uid> up. A disabled workload has neither — disable() drops
    linger, and logind GCs the runtime dir — so podman exits before it can
    answer anything and every such read raises. Unwrapped, that aborted the
    whole battery at the image check with a traceback, discarding the dozen
    checks after it including the ones that would have said *why* (the
    service checks: the workload is off). Diagnose is the first thing an
    operator reaches for on a workload that is not running, so that is
    exactly the case it must survive.

    podman.py's own self-heal does not cover this and should not: it is gated
    on linger already being enabled, because a read path must never be what
    turns linger on. For a disabled workload it correctly declines, so the
    error arrives here.

    A failed read *omits* its check rather than passing it — asserting an image
    is present in a store we could not open is the same guess ca_trust_anchors
    refuses to make. The omission is announced once, because a check that
    silently vanishes is indistinguishable from one that passed. Whether that
    announcement is a fault depends on enabled-ness: for a disabled workload an
    unreachable podman is the expected consequence of it being off; for an
    enabled one it is a real failure worth a fix.
    """

    def __init__(self, config, check):
        self.config = config
        self.check = check
        self.reported = False

    def __call__(self, fn, *args):
        """Run one podman read: (ok, value)."""
        try:
            return True, fn(*args)
        except PodmanError as e:
            if not self.reported:
                self.reported = True
                self._announce(e)
            return False, None

    def _announce(self, e):
        config = self.config
        # Last line, not str(e): the exception text carries the whole
        # argv, and the operator needs the reason, not the command.
        lines = e.stderr.strip().splitlines()
        detail = lines[-1].strip() if lines else f"exited {e.returncode}"
        if config.enabled:
            self.check("podman_session", False,
                       f"Rootless podman is not answering for "
                       f"{config.username}: {detail}",
                       fix=(f"Check the user manager: systemctl status "
                            f"user@{config.uid}.service, then "
                            f"sudo workloadctl restart {config.name}"))
        else:
            # Emitted, then folded away by collapse_disabled_consequences —
            # which is why this text is not what an operator sees for a
            # disabled workload; the fold names the check instead. The two
            # layers stay independent on purpose: this one knows only that
            # podman could not answer, and says so whoever is reading.
            self.check("podman_session", True,
                       f"Image and container checks skipped: "
                       f"{config.username} has no rootless podman session "
                       f"(workload disabled)")


def _user_exists_check(config, manager, _check) -> bool:
    user_exists = manager.user_exists(config)
    if user_exists:
        _check("user_exists", True, f"User exists: {config.username} (UID {config.uid})")
    else:
        _check("user_exists", False, f"User does not exist: {config.username}",
               fix="sudo workloadctl enable " + config.name)
    return user_exists


def _subid_checks(config, _check):
    """Subuid/subgid configured, derived from the uid, and clear of login.defs."""
    with_entries = subid_files_with_entries(config.username)
    subuid_exists = subuid_file() in with_entries
    subgid_exists = subgid_file() in with_entries

    if subuid_exists and subgid_exists:
        _check("subid_configured", True, "Subuid/subgid configured")
    else:
        _check("subid_configured", False, "Subuid/subgid not configured",
               fix=f"sudo /usr/libexec/workloadctl/workload-ensure-user {config.name}")

    # Is the configured range the *right* range? Presence (above) is not
    # enough — the grandfather in configure_subuid_subgid never corrects an
    # existing entry, so a range predating the derivation survives every
    # enable and every upgrade, silently.
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


def _linger_check(config, _check) -> bool:
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
    return linger_enabled


def _user_session_check(config, _check):
    """User manager session live.

    Rootless workloads need user@<uid> up (linger keeps it alive) for the
    user D-Bus that crun's cgroup manager talks to. If linger is on but the
    session is dead, the safe fix is to RESTART the user manager — never
    `loginctl terminate-user`, which also tears down /run/user/<uid> and
    leaves workloads failing with 226/NAMESPACE.
    """
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


def _workload_selinux_module_checks(config, _check):
    """The per-workload SELinux module is loaded, and is this build's."""
    module = selinux_module_name(config.name)
    if not shutil.which("semodule"):
        _check("selinux_module", False,
               "SELinux tooling (semodule) not found",
               fix="sudo dnf install policycoreutils")
        return
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


def _host_selinux_modules_check(_check):
    """The host-global SELinux modules match what the image ships.

    `semodule -l` only answers "present", and a module that is present but
    OLD is the expected state after a `bootc upgrade`, not an exotic one: the
    policy store lives in /etc, ostree 3-way-merges /etc, and every host that
    has enabled a workload has a locally-modified store because `semanage
    fcontext -a` rewrites it. So the image's new module is silently not
    applied while every existing check still passes. Measured on a live host:
    493 of ~639 diverged /etc paths were the policy store, the module
    directory itself among them.

    /usr is replaced wholesale, so the shipped .cil is authoritative and the
    loaded module is the thing that drifts.

    Two questions, and the order matters. "Does the live policy grant what
    this build's module asks for?" is the real one, answered against the
    kernel. The file comparison is only the fallback for when that cannot be
    asked, because it can be fooled in both directions: ostree may adopt a new
    module SOURCE while keeping the old COMPILED policy (looks current, is
    not), and a host whose loaded policy is a superset reads as differing
    while working perfectly.
    """
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


def _gpu_selinux_checks(config, _check):
    """NVIDIA device nodes reachable under SELinux.

    /dev/nvidia*, nvidiactl, nvidia-uvm* and nvidia-caps/* are all
    xserver_misc_device_t, and unlike DRI (dri_device_t, covered by the
    default-on container_use_dri_devices) and ROCm (hsa_device_t,
    unconditional) nothing grants it by default. The base image deliberately
    grants no device access host-wide, so an NVIDIA workload reaches those
    nodes one of three ways: container_use_xserver_devices, which the
    hypervisor-nvidia-* variants set and which covers container_t; its own
    policy.cil, which is how a workload with a udica-derived type must do it
    (the boolean is written against container_t, not container_domain); or
    the legacy blanket container_use_devices, which works but hands every
    container every device_node type and should be migrated off.

    Only the no-path-at-all case fails. A host still carrying the blanket
    boolean is working, not broken, so it passes with the migration in the
    message — image-side SELinux changes don't reach existing hosts on
    `bootc upgrade` (the policy store is in /etc and semodule -i has made it
    locally modified), so that state is expected on any machine that predates
    the scoped policy and shouldn't read as a fault.
    """
    vendors = _gpu_vendors(config)
    wants_nvidia = "nvidia" in vendors or (
        "auto" in vendors and Path("/dev/nvidia0").exists()
    )
    if not wants_nvidia:
        return
    passed, message, fix = gpu_selinux_check(
        _getsebool("container_use_xserver_devices"),
        _getsebool("container_use_devices"),
        selinux_module_name(config.name) if config.selinux_policy else None,
    )
    _check("gpu_selinux", passed, message, fix=fix)


def _runtime_dir_check(config, linger_enabled, _check):
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


def _home_dir_check(config, _check):
    home_dir = config.home_dir
    if home_dir.exists():
        _check("home_dir", True, f"Home directory exists: {home_dir}")
    else:
        _check("home_dir", False, f"Home directory missing: {home_dir}",
               fix=f"sudo /usr/libexec/workloadctl/workload-ensure-user {config.name}")


def _tree_label_check(config, _check):
    """The workload tree carries the label its substrate needs, and the rule
    that keeps it across relabels is registered.

    The expected type and the rule that governs it both differ between
    containers (container_file_t, blanket rule) and VMs (svirt_image_t,
    per-workload rule) — see selinux_label_check.
    """
    root_dir = workload_root_dir(config.name)
    if not root_dir.exists():
        return
    pattern = (fcontext_pattern(config.name) if config.is_vm else None)
    passed, message, fix = selinux_label_check(
        _fcontext_rule_present(pattern), _selinux_type(root_dir),
        config.name, is_vm=config.is_vm)
    _check("selinux_labels", passed, message, fix=fix)


def _vm_socket_dir_check(config, _check):
    """The VM runtime socket dir.

    Host-global, and checked separately from the tree label because the two
    rules are registered by different things at different times — the tree
    rule per workload at enable, this one once by the RPM's %post — so one
    being right says nothing about the other. A host rebuild that drops this
    one takes out every VM workload with a timeout that names nothing
    SELinux; see vm_socket_dir_selinux_check.
    """
    # Both halves, parent first. The parent is what the rule names and what
    # a fresh boot inherits from, but RuntimeDirectoryPreserve=yes means a
    # workload's own subdirectory can stay mislabelled under a parent that
    # was since put right — the exact shape of a host where the rule was
    # added by hand and only the running service restarted. Report the
    # first one that is wrong, so the fix names a directory that is
    # actually wrong rather than the one further up.
    rule_present = _fcontext_rule_present(VM_SOCKET_FCONTEXT_PATTERN)
    inspected = str(SOCKET_DIR)
    label = _selinux_type(SOCKET_DIR) if SOCKET_DIR.exists() else None
    if label in (VM_SOCKET_SELINUX_TYPE, VM_SOCKET_SELINUX_TYPE_REAL):
        sock_dir = SOCKET_DIR / config.name
        if sock_dir.exists():
            inspected, label = str(sock_dir), _selinux_type(sock_dir)
    passed, message, fix = vm_socket_dir_selinux_check(
        rule_present, label, inspected)
    _check("vm_socket_dir_selinux", passed, message, fix=fix)


def _vm_provisioning_checks(config, _check):
    """The guest's cloud-init actually finished.

    Nothing else in this battery can see inside the guest, so a VM whose
    first boot was interrupted passes everything else while being
    permanently half-provisioned.
    """
    state_dir = config.home_dir
    try:
        instance_id = (state_dir / ".cloud-init-instance-id").read_text().strip()
    except OSError:
        instance_id = None
    marker = read_provision_marker(state_dir)
    # Ask the guest directly when we have no outcome for the instance in
    # play and the VM is up: the marker is normally written by the running
    # service's watch, but a VM that has been up since before this check
    # existed has none, and a diagnose that answers "unknown" for a guest
    # sitting right there is the sort of gap that hides the bug it was
    # written for. Cheap and bounded — one local socket round trip, and it
    # records what it learns so later runs need not ask.
    have_outcome = ((marker or {}).get("instance_id") == instance_id
                    and (marker or {}).get("status") in (PROVISION_DONE,
                                                         PROVISION_FAILED))
    if not have_outcome and instance_id and service_active(config.service_name)[0]:
        try:
            record_guest_provision_result(state_dir, instance_id,
                                          config.name)
            marker = read_provision_marker(state_dir)
        except OSError:
            pass  # unreadable/unwritable state dir: report what we have
    passed, message, fix = vm_provisioning_check(marker, instance_id,
                                                 config.name)
    _check("vm_provisioning", passed, message, fix=fix)


def _image_checks(config, manager, _check, podman_read):
    """Image(s) exist locally."""
    if config.is_multi:
        for cname, img in config.container_images():
            ok, iid = podman_read(manager.podman(config).image_id, img)
            if not ok:
                continue
            if iid:
                _check(f"image_available[{cname}]", True,
                       f"Image available for {cname}: {img} ({iid[:12]})")
            else:
                _check(f"image_available[{cname}]", False,
                       f"Image not available for {cname}: {img}",
                       fix="Image will be pulled on first start")
        return
    ok, image_id = podman_read(manager.get_image_id, config)
    if not ok:
        return  # announced by podman_read; nothing here to assert
    if image_id:
        _check("image_available", True, f"Image available: {config.image} ({image_id[:12]})")
        return
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


def _service_file_checks(config, _check) -> bool:
    """Service file(s) exist; returns whether the main unit does."""
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
    return service_file.exists()


def _units_current_checks(config, _check):
    """The generated units are from this config and from this build."""
    # Config not edited since the units were last generated. Editing the
    # workload.toml + `daemon-reload` does NOT regenerate per-workload units
    # (only `enable` runs the unit-writer), a common foot-gun.
    if units_outdated(config.name):
        _check("config_current", False,
               "Config edited since last enable — generated units are stale",
               fix=f"sudo workloadctl enable {config.name}  "
                   f"(daemon-reload does not regenerate units; see `drift` for the diff)")
    else:
        _check("config_current", True, "Generated units match current config (by mtime)")

    # Units generated by the workloadctl that is running. Units live in /run
    # and are only rewritten at boot or by `enable`, so `dnf upgrade
    # workloadctl` on a package host leaves running workloads on the previous
    # generator's output. The mtime check above cannot see it — neither
    # file's mtime moved.
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


def _egress_plane_checks(config, _check):
    """The network plane, in the order the guest meets it: network, egress,
    confinement, inspector, resolver, allow-list drift, capture.

    Reading the resolver's verdict before the inspector's sends someone after
    a DNS answer when what failed was the redirect that answer points into,
    so the order here is load-bearing and the VM-only lines are interleaved
    with the shared ones rather than grouped.
    """
    # The VM's network posture. There is no shared bridge unit to check any
    # more (ADR 006), but there is something the TOML does not show: under
    # passt the management address and nflog group are *derived from the
    # uid*, so an operator reading the config cannot work out where to ssh
    # or which nflog group to capture. Report the derived values.
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

    # NOT gated on is_vm, and this hoist is the whole of the routing -- the
    # substrate-aware wording inside inspect_check() is inert without it.
    # The check's own `if not _uses_inspect(config)` early return is the
    # only gate it needs: a container gets the same
    # workload-<name>-inspect.socket from the same generate_inspect_socket()
    # and the same two uid-keyed nft maps.
    inspect_result = inspect_check(config)
    if inspect_result:
        _check(*inspect_result)

    if config.is_vm:
        # After the inspector's line, because that is the order the guest
        # meets them in: it resolves a name, then dials what it was told.
        #
        # VM-only, and stays that way: containers get no per-workload DNS
        # responder, so there is no synthesising resolver here for this to
        # report on.
        resolve_result = vm_resolve_check(config)
        if resolve_result:
            _check(*resolve_result)

    # The container's half of the resolver question, in the slot a VM's
    # vm_resolve_check occupies just above and for the same ordering reason:
    # the workload resolves a name before it dials anything, so a reader who
    # meets the dial's verdict first is sent after the wrong thing. The check
    # returns None for a VM, which has a responder of its own.
    resolver_result = container_resolver_check(config)
    if resolver_result:
        _check(*resolver_result)

    # Not gated on is_vm either, and for the same reason the inspector's line
    # is not: the pinning it reports is a property of the nft element, which
    # both substrates arm identically. Placed after the resolver's line
    # because on a VM the two are read together -- the resolver keeps an
    # INSPECTED name current, and this is the path that has no such thing.
    drift_result = allow_drift_check(config)
    if drift_result:
        _check(*drift_result)

    # Not gated on is_vm: the host-side vantage works on every substrate,
    # because `meta skuid` does not care what produced the socket.
    capture_result = capture_check(config)
    if capture_result:
        _check(*capture_result)


def _ca_trust_check(_check):
    """Host trust anchors, for workloads that pull an image.

    Host-wide state rather than this workload's, reported here for the same
    reason gpu_selinux is: it is invisible from the workload's own files, and
    the failure it produces (a pull that cannot verify the registry) is read
    as the workload's problem. Omitted rather than passed when the store
    can't be read — claiming trust is intact on a store we could not open
    asserts a guess.
    """
    facts = _ca_trust_facts()
    if facts is not None:
        _check("ca_trust_anchors", *ca_trust_anchor_check(*facts))


def _service_state_checks(config, _check):
    """Service enabled, service active."""
    result = subprocess.run(
        ["systemctl", "is-enabled", config.service_name],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        _check("service_enabled", True, "Service enabled")
    else:
        _check("service_enabled", False, "Service not enabled",
               fix="Service should be auto-enabled via generator")

    svc_active, service_state = service_active(config.service_name)
    if svc_active:
        _check("service_active", True, f"Service active: {service_state}")
    else:
        # No disabled-workload branch here: when this fails on a disabled
        # workload the check is folded into `workload_disabled`, so a fix
        # reading "Workload is disabled in config" could never be printed.
        _check("service_active", False, f"Service not active: {service_state}",
               fix=f"Check logs: sudo journalctl -u {config.service_name} -n 50")


def _container_running_checks(config, manager, _check, podman_read):
    """Container(s) running."""
    if config.is_multi:
        for cname in config.container_names():
            pn = config.podman_container_name(cname)
            ok, cs = podman_read(
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
        return
    ok, container_status = podman_read(
        manager.podman(config).container_status, config.container_name)
    if not ok:
        return  # announced by podman_read; nothing here to assert
    if container_status:
        _check("container_running", True, f"Container running: {container_status}")
    else:
        _check("container_running", False, "Container not running",
               fix=f"Check logs: sudo journalctl -u {config.service_name} -n 50")


def _volume_paths_check(config, _check):
    volumes = config.get_volumes()
    if not volumes:
        return
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


def _uid_mapping_check(config, _check):
    """UID mapping, for userns=host."""
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


def _host_userns_check(_check):
    """Trust posture: host userns dissolves the per-workload isolation
    boundary. Only reachable if opted in — an un-acknowledged host-userns
    workload fails validation and never generates/enables — so surface the
    elevated trust rather than let it be invisible. Passes: it's an
    acknowledged, intended state, not a fault.
    """
    _check("host_userns", True,
           'Elevated trust: security.userns="host" in effect '
           f'(acknowledged via {HOST_USERNS_OPT_IN}=true) — the '
           'per-workload isolation boundary is dissolved.')


def collect_diagnose_checks(config, manager: WorkloadManager):
    """Run the diagnose check battery and return (checks, passed).

    checks is the ordered list of {check, passed, message[, fix]} dicts;
    passed is True iff every check passed. Pure collection — no root
    check, no printing, no exit — shared by cmd_diagnose and doctor.

    This function is the order and the gating; each check's reading lives in
    the function it calls. The order is what an operator reads, so a line is
    placed where its verdict is useful, not where its subject is grouped.
    """
    checks = []

    def _check(name, passed, message, fix=None):
        entry = {"check": name, "passed": passed, "message": message}
        if fix:
            entry["fix"] = fix
        checks.append(entry)

    # The rootless-podman session checks (subuid/subgid ranges, linger, the
    # user@<uid> manager and its /run/user/<uid>) describe how a *container*
    # workload runs. A VM has none of it: QEMU uses no user namespaces, and the
    # VM service is a system unit with User=<workload user> and its own
    # RuntimeDirectory=workload-vm/<name>, so it never needs a user manager to be
    # up. workload-ensure-user says as much and deliberately skips both steps for
    # kind == "vm" — which made these checks unfixable as well as wrong: they
    # failed, and the fix they printed (`workload-ensure-user <name>`) was the
    # very code path that had decided not to do the thing.
    session_scoped = not config.is_vm
    podman_read = _PodmanReads(config, _check)

    user_exists = _user_exists_check(config, manager, _check)
    linger_enabled = False
    if user_exists and session_scoped:
        _subid_checks(config, _check)
        linger_enabled = _linger_check(config, _check)
    if user_exists and linger_enabled:
        _user_session_check(config, _check)

    if config.selinux_policy:
        _workload_selinux_module_checks(config, _check)
    _host_selinux_modules_check(_check)
    _gpu_selinux_checks(config, _check)

    if user_exists and session_scoped:
        _runtime_dir_check(config, linger_enabled, _check)
    if user_exists:
        _home_dir_check(config, _check)
    _tree_label_check(config, _check)
    if config.is_vm:
        _vm_socket_dir_check(config, _check)
        _vm_provisioning_checks(config, _check)

    # A VM has no container image to inventory — the disk is provisioned by
    # the substrate, not pulled, and `config.image` is the sentinel "(vm)".
    if user_exists and not config.is_vm:
        _image_checks(config, manager, _check, podman_read)

    if _service_file_checks(config, _check):
        _units_current_checks(config, _check)
    # Host-global artifacts the workload's setup.sh installed. Not in
    # workload_run_files(), so nothing above this line can see them.
    collect_host_artifact_checks(config, _check)

    _egress_plane_checks(config, _check)

    # VMs pull nothing through podman, so the host trust store is not theirs.
    if not config.is_vm:
        _ca_trust_check(_check)

    _service_state_checks(config, _check)

    # A VM's liveness is the QEMU service's own state, already reported, and
    # `podman container inspect workload-<name>` under the VM's user would
    # simply never find anything.
    if user_exists and not config.is_vm:
        _container_running_checks(config, manager, _check, podman_read)

    _volume_paths_check(config, _check)
    _check_mcs_labels(config, _check)

    userns_mode = config.config.get("security", {}).get("userns", "keep-id")
    if userns_mode == "host" and user_exists:
        _uid_mapping_check(config, _check)
    if uses_host_userns(config.config):
        _host_userns_check(_check)

    if not config.enabled:
        checks = collapse_disabled_consequences(checks, config.name)

    return checks, all(c["passed"] for c in checks)
