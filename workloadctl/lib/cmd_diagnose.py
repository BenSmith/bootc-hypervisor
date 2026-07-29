"""
cmd_diagnose — explain why a workload isn't healthy.

collect_diagnose_checks() is pure collection: no root check, no printing, no
exit, so `doctor` can run the same battery fleet-wide and render it its own way.
Where validate asks "is this config fit to enable", diagnose asks "this is
enabled and unhappy — what is wrong with it right now".
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from workload_lib import (
    expand_volume_path,
    HOST_USERNS_OPT_IN,
    read_subid_entry,
    selinux_module_name,
    selinux_type_name,
    subgid_file,
    subid_files_with_entries,
    subuid_file,
    units_outdated,
    units_from_other_build,
    workload_root_dir,
    WORKLOADCTL_VERSION,
    WORKLOADS_BASE,
)
from provisioning import (
    HOST_ARTIFACT_KINDS,
    HOST_SETUP_ARTIFACTS_ACTION,
    host_setup_artifacts,
)
from validation import uses_host_userns
from vm import VM_BRIDGE_NAME
from workloadctl_core import WorkloadManager, require_root
from substrate import service_active
from cmd_validate import load_config_or_exit


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


def _fcontext_rule_present() -> bool | None:
    """Is the persistent fcontext rule for /var/lib/workloads registered?

    None when it can't be determined — no semanage binary, SELinux disabled,
    or the read lock is contended right now (the same contention this check
    exists to detect the aftermath of). None must never read as "missing".
    """
    if not shutil.which("semanage"):
        return None
    result = subprocess.run(
        ["semanage", "fcontext", "-l"], capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return f"{WORKLOADS_BASE}(/.*)?" in result.stdout


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
                        name: str) -> tuple[bool, str, str | None]:
    """Verdict for the workload tree's SELinux labeling: (passed, message, fix).

    Two independent facts, because they fail independently and one of them
    fails silently. `workload-ensure-user` registers the fcontext rule for
    /var/lib/workloads and then restorecons the workload's tree — but the
    semanage read lock is contended when several workloads enable at once or
    at boot, and the registration is best-effort: it logs

        WARNING: semanage fcontext -l failed: Could not get direct read lock
        at /var/lib/selinux/targeted/semanage.read.LOCK

    once, returns, and never retries. The restorecon then runs against a
    policy with no rule for this path and applies the *default* label
    (var_lib_t), so the container is denied writes to its own home. The
    warning has long since scrolled out of the journal by the time anyone
    connects it to the denial — which is the whole reason this is a check
    and not just a log line. Gap 3 of Q6, 2026-07-28.

    A tree that is correctly labeled today but has no registered rule still
    fails: it is one `restorecon -R /var` or policy relabel away from the
    same denial, and the fix is one command either way.
    """
    if rule_present is None and label is None:
        return (True, "SELinux labeling state unknown "
                      "(semanage unavailable or SELinux disabled)", None)
    if label is not None and label != "container_file_t":
        return (False, f"Workload tree is labeled {label}, not container_file_t "
                       f"— rootless podman will be denied access to it"
                       + ("" if rule_present else " (and no fcontext rule is "
                          "registered for it, so a relabel will not fix it)"),
                f"sudo /usr/libexec/workloadctl/workload-ensure-user {name}")
    if rule_present is False:
        return (False, f"No fcontext rule registered for {WORKLOADS_BASE} — the "
                       f"tree is labeled correctly now but a relabel will reset "
                       f"it to the default type (semanage lock contention at "
                       f"enable time skips this registration silently)",
                f"sudo semanage fcontext -a -t container_file_t "
                f"'{WORKLOADS_BASE}(/.*)?' && sudo restorecon -R {WORKLOADS_BASE}")
    return (True, "SELinux labeling correct (container_file_t, "
                  "fcontext rule registered)", None)


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
    regression ShippedBundleGrantsTest exists to catch. Observed on onepiece
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
    days on onepiece while `systemctl list-units --failed` stayed clean, because
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


def shared_bridge_check(state, name: str) -> tuple[bool, str, str | None]:
    """Verdict for the shared VM bridge unit. `state` as in _unit_props().

    The other half of the same blind spot: `workload_run_files()` excludes
    shared infra by design ("never includes ... workload-bridge.service"), and
    for a VM on the managed bridge that unit is the entire network path — it
    creates `_workload-br` and runs the dnsmasq the guest gets its lease from.
    tp had it fail five times with nothing in any verb saying so.

    Not part of the setup.sh declaration mechanism: no script installs this,
    it is one fixed unit, and it is shared, so it is checked by name here
    rather than declared by a workload that does not own it.
    """
    unit = "workload-bridge.service"
    if state is None:
        return (False,
                f"Shared VM bridge unit is not installed: {unit} — this VM is on "
                f"the managed bridge {VM_BRIDGE_NAME} and has no network without it",
                f"sudo workloadctl enable {name}  (the generator emits it)")
    active = state.get("ActiveState", "unknown")
    if active == "active":
        return (True, f"Shared VM bridge active: {unit} ({VM_BRIDGE_NAME})", None)
    result = state.get("Result", "")
    detail = active + (f", Result={result}" if result else "")
    return (False,
            f"Shared VM bridge is not running: {unit} ({detail}) — "
            f"{VM_BRIDGE_NAME} and its dnsmasq are this VM's whole network path",
            f"sudo systemctl status {unit}; journalctl -u {unit} -n 50")


def collect_diagnose_checks(config, manager: WorkloadManager):
    """Run the diagnose check battery and return (checks, passed).

    checks is the ordered list of {check, passed, message[, fix]} dicts;
    passed is True iff every check passed. Pure collection — no root
    check, no printing, no exit — shared by cmd_diagnose and doctor.
    """
    checks = []
    linger_enabled = False  # set by Check 3; referenced by the session/runtime checks

    def _check(name, passed, message, fix=None):
        entry = {"check": name, "passed": passed, "message": message}
        if fix:
            entry["fix"] = fix
        checks.append(entry)

    # Check 1: User exists
    user_exists = manager.user_exists(config)
    if user_exists:
        _check("user_exists", True, f"User exists: {config.username} (UID {config.uid})")
    else:
        _check("user_exists", False, f"User does not exist: {config.username}",
               fix="sudo workloadctl enable " + config.name)

    # Check 2: Subuid/subgid configured
    if user_exists:
        with_entries = subid_files_with_entries(config.username)
        subuid_exists = subuid_file() in with_entries
        subgid_exists = subgid_file() in with_entries

        if subuid_exists and subgid_exists:
            _check("subid_configured", True, "Subuid/subgid configured")
        else:
            _check("subid_configured", False, "Subuid/subgid not configured",
                   fix=f"sudo /usr/libexec/workloadctl/workload-ensure-user {config.name}")

    # Check 3: Linger enabled
    if user_exists:
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
            else:
                _check("selinux_module", False,
                       f"SELinux module not loaded: {module}",
                       fix=f"sudo workloadctl enable {config.name}")

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
    if user_exists:
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

    # Check 5b: the workload tree carries the label rootless podman needs, and
    # the rule that keeps it across relabels is registered. See
    # selinux_label_check for why a silent skip at enable time surfaces as an
    # unexplained permission denial much later.
    root_dir = workload_root_dir(config.name)
    if root_dir.exists():
        passed, message, fix = selinux_label_check(
            _fcontext_rule_present(), _selinux_type(root_dir), config.name)
        _check("selinux_labels", passed, message, fix=fix)

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
                iid = manager.podman(config).image_id(img)
                if iid:
                    _check(f"image_available[{cname}]", True,
                           f"Image available for {cname}: {img} ({iid[:12]})")
                else:
                    _check(f"image_available[{cname}]", False,
                           f"Image not available for {cname}: {img}",
                           fix="Image will be pulled on first start")
        else:
            image_id = manager.get_image_id(config)
            if image_id:
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

    # Check 7e: the shared VM bridge, for VMs that use it. Also outside
    # workload_run_files() — and unlike 7d, nobody declares it: it is one fixed
    # unit shared by every managed-bridge VM. Skipped for a VM bridged onto a
    # user-provided interface (br0 onto the LAN), which the generator
    # deliberately does not emit it for.
    if config.is_vm and config.enabled:
        bridge = config.config.get("vm", {}).get("network", {}).get(
            "bridge", VM_BRIDGE_NAME)
        if bridge == VM_BRIDGE_NAME:
            passed, message, fix = shared_bridge_check(
                _unit_props("workload-bridge.service"), config.name)
            _check("shared_bridge", passed, message, fix=fix)

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
        fix = (f"Check logs: sudo journalctl -u {config.service_name} -n 50"
               if config.enabled else "Workload is disabled in config")
        _check("service_active", False, f"Service not active: {service_state}", fix=fix)

    # Check 10: Container(s) running
    if user_exists:
        if config.is_multi:
            for cname in config.container_names():
                pn = config.podman_container_name(cname)
                cs = manager.podman(config).container_status(pn)
                if cs:
                    _check(f"container_running[{cname}]", True,
                           f"Container running: {pn} ({cs})")
                else:
                    _check(f"container_running[{cname}]", False,
                           f"Container not running: {pn}",
                           fix=f"Check logs: sudo journalctl -u workload-{config.name}-{cname}.service -n 50")
        else:
            container_status = manager.podman(config).container_status(config.container_name)
            if container_status:
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
        print("✓ All checks passed - workload is healthy")
        sys.exit(0)

