"""
cmd_lifecycle — workload lifecycle commands:
enable, disable, start, stop, recreate, reboot, cleanup.
"""

import difflib
import fcntl
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib

from workload_lib import (
    iter_workloads,
    selinux_module_name,
    selinux_type_name,
    USERNAME_PREFIX,
    WORKLOADS_BASE,
    WORKLOAD_BUNDLES_DIR,
    VM_SOCKET_DIR,
    get_next_uid,
    NAME_PATTERN,
    workload_config_path,
    workload_enabled_marker,
    workload_username,
    workload_root_dir,
    RUN_SYSTEMD_SYSTEM,
    workload_run_files,
    render_sysusers_config,
    SUBID_LOCK,
)
import imagebuild
from podman import Podman
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    WorkloadUserNotFound,
    require_root,
    VM_BRIDGE_NAME,
)
from cmd_backup import BACKUP_DIR
from substrate import get_substrate, service_active, LifecycleError


REQUIRED_EXECUTABLES = ["podman", "systemctl", "loginctl", "systemd-sysusers", "restorecon", "semodule"]
RECOMMENDED_EXECUTABLES = ["semanage", "udica"]


class SelinuxPolicyError(Exception):
    """Raised by _apply_selinux_policy() when loading/removing a workload's
    SELinux type fails.

    Same contract as substrate.ProvisionFailed: the diagnostic has already
    been printed, so the caller exits 1 without printing again (the enable
    path) or lets it fold into the disable path's best-effort failure list.
    """

UDICA_TEMPLATE_DIR = Path("/usr/share/udica/templates")
_BUNDLES_DIR = WORKLOAD_BUNDLES_DIR

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _gating_units(config):
    """Units that must succeed before the main service can start."""
    return get_substrate(config, None).gating_units()


def _effective_state(config):
    """Return (state, failed_unit) for display. If the main service isn't
    active but a gating unit has failed, report 'failed' and name the culprit
    so the cause isn't buried behind a bland 'inactive'."""
    _, main = service_active(config.service_name)
    if main == "active":
        return main, None
    for unit in _gating_units(config):
        _, st = service_active(unit)
        if st == "failed":
            return "failed", unit
    return main, None


def _preflight_checks(config: WorkloadConfig) -> bool:
    """Run pre-flight checks for a workload. Returns True if all checks pass."""
    print()
    print("Running pre-flight checks...")
    failed = False

    # Check required executables are available
    missing_required = [exe for exe in REQUIRED_EXECUTABLES if not shutil.which(exe)]
    if missing_required:
        print("  ✗ Missing required executables:")
        for exe in missing_required:
            print(f"    - {exe}")
        failed = True

    missing_recommended = [exe for exe in RECOMMENDED_EXECUTABLES if not shutil.which(exe)]
    if missing_recommended:
        print("  ! Missing recommended executables (SELinux policy management):")
        for exe in missing_recommended:
            print(f"    - {exe}")
        print("    Install: dnf install policycoreutils-python-utils checkpolicy")

    if config.is_vm:
        # VM-specific preflight: qemu, OVMF firmware, /dev/kvm, socat (for
        # `workloadctl shell` which execs into socat to reach the serial
        # console). Surface socat here so the first console attempt doesn't
        # exec-fail with a generic ENOENT.
        vm_required = ["qemu-system-x86_64", "qemu-img", "socat"]
        missing_vm = [exe for exe in vm_required if not shutil.which(exe)]
        if missing_vm:
            print("  ✗ Missing required VM executables:")
            for exe in missing_vm:
                print(f"    - {exe}")
            print("    Install: dnf install qemu-kvm socat")
            failed = True

        if not Path("/dev/kvm").exists():
            print("  ✗ /dev/kvm not found — KVM acceleration unavailable")
            print("    Enable nested KVM or run on bare metal")
            failed = True

        from workload_lib import find_ovmf_code
        if not find_ovmf_code():
            print("  ✗ OVMF firmware (edk2-ovmf) not found")
            print("    Install: dnf install edk2-ovmf")
            failed = True

        bridge_conf = Path("/etc/qemu/bridge.conf")
        bridge = config.vm_bridge
        if not bridge_conf.exists() or f"allow {bridge}" not in bridge_conf.read_text(errors="replace"):
            print(f"  ! /etc/qemu/bridge.conf missing 'allow {bridge}'")
            print("    Will be configured automatically on first enable via workload-ensure-user")

        return not failed

    from workload_lib import expand_volume_path
    # Check pull=never images exist locally (once per container)
    for _cname, image, pull in config.container_specs():
        if pull == "never" and not Podman.for_root().image_id(image):
            print(f"  ✗ Image '{image}' not found locally and pull=never")
            build_script = config.resolve_control_file("build.sh")
            if build_script.exists():
                print("    Build the image first:")
                print(f"      sudo {build_script}")
            else:
                print("    Build or pull the image first, or change pull policy")
            failed = True

    # Check required files exist (declared in [setup].required_files)
    required_files = config.get_required_files()
    required_file_paths = {entry["path"] for entry in required_files}
    missing_required_files = [e for e in required_files if not Path(e["path"]).exists()]

    if missing_required_files:
        # Auto-copy is gated on the destination being inside the workload's own
        # tree. Anchor on the workload ROOT, not home_dir: home_dir is the
        # state/ subdir, but `./`-anchored required_files resolve to the data/
        # sibling — checking against home_dir (state/) would reject every
        # data/ destination and silently skip the copy.
        root_resolved = workload_root_dir(config.name).resolve()
        still_missing = []
        for entry in missing_required_files:
            dest = Path(entry["path"])
            hint = entry.get("hint")
            if hint and Path(hint).exists() and dest.resolve().is_relative_to(root_resolved):
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(hint, dest)
                print(f"  ✓ Copied config template: {dest}")
            else:
                still_missing.append(entry)

        if still_missing:
            print("  ✗ Missing required files:")
            for entry in still_missing:
                print(f"    - {entry['path']}")
            print()
            print("  Create these files before enabling:")
            for entry in still_missing:
                if entry["hint"]:
                    print(f"    sudo cp {entry['hint']} \\")
                    print(f"             {entry['path']}")
                else:
                    print(f"    # Create {entry['path']}")
            failed = True

    # Check volume paths exist
    # Paths in required_files are files the user must provide
    # All other volume paths are directories to auto-create
    volumes = config.all_volumes()
    missing_dirs = []
    missing_files = []

    for vol_spec in volumes:
        expanded_spec = expand_volume_path(vol_spec, str(config.home_dir))
        host_path = expanded_spec.split(':')[0]

        if Path(host_path).exists():
            continue

        if host_path in required_file_paths:
            missing_files.append(host_path)
        else:
            missing_dirs.append(host_path)

    if missing_dirs:
        # Same root-vs-home distinction as the required_files copy above: a `./`
        # volume dir resolves under data/ (sibling of state/), so anchor the
        # "auto-create vs operator-must-provision" split on the workload ROOT.
        # Genuinely external bind sources (absolute host paths) stay must-create.
        root_resolved = workload_root_dir(config.name).resolve()
        auto_create = [p for p in missing_dirs
                       if Path(p).resolve().is_relative_to(root_resolved)]
        must_create = [p for p in missing_dirs
                       if not Path(p).resolve().is_relative_to(root_resolved)]

        for path in auto_create:
            Path(path).mkdir(parents=True, exist_ok=True)
            print(f"  ✓ Created volume directory: {path}")

        if must_create:
            print("  ✗ Missing volume directories (outside workload home):")
            for path in must_create:
                print(f"    - {path}")
            print()
            print("  Create these directories before enabling:")
            for path in must_create:
                print(f"    sudo mkdir -p {path}")
            failed = True

    if missing_files:
        print("  ✗ Missing volume files:")
        for path in missing_files:
            print(f"    - {path}")
        print()
        print("  Create these files before enabling (see workload documentation).")
        failed = True

    # Check extra groups exist
    import grp as _grp
    missing_groups = []
    for group in config.get_extra_groups():
        try:
            _grp.getgrnam(group)
        except KeyError:
            missing_groups.append(group)

    if missing_groups:
        print("  ✗ Missing groups:")
        for group in missing_groups:
            print(f"    - {group}")
        print()
        print("  These groups must exist on the system.")
        failed = True

    # Check ip_unprivileged_port_start for host-mode workloads
    if config.get_network_mode() == "host":
        try:
            sysctl_path = Path("/proc/sys/net/ipv4/ip_unprivileged_port_start")
            unpriv_start = int(sysctl_path.read_text().strip())
            if unpriv_start > 0:
                print(f"  ! host-mode workload: ip_unprivileged_port_start={unpriv_start}")
                print(f"    Binding ports below {unpriv_start} will fail with 'permission denied'.")
                print("    Fix: echo 'net.ipv4.ip_unprivileged_port_start = 0' | "
                      "sudo tee /etc/sysctl.d/50-privileged-ports.conf && sudo sysctl --system")
        except Exception:
            pass

    if not failed:
        print("  ✓ Pre-flight checks passed")

    return not failed


def _provision_user(config: WorkloadConfig):
    """Create workload user and configure subuid/subgid, home dir, linger."""
    print("  Running systemd-sysusers...")

    user_name = config.username
    home_dir = str(config.home_dir)
    extra_groups = config.config.get("security", {}).get("extra_groups", [])

    # Look up existing UID or allocate the next free one in the workload range.
    # Flock matches /run/lock/workload-subid.lock in workload-ensure-user so
    # concurrent enables don't race on the same UID slot. The lock MUST span
    # allocation *through* systemd-sysusers: get_next_uid() dedupes against
    # /etc/passwd (plus a per-process set), so the picked UID isn't visible to a
    # concurrent enable until sysusers has created the user. Releasing after
    # allocation (as before) let two enables pick the same free UID.
    _subid_lock = SUBID_LOCK
    _subid_lock.parent.mkdir(parents=True, exist_ok=True)
    with open(_subid_lock, "w") as _lock_fd:
        fcntl.flock(_lock_fd.fileno(), fcntl.LOCK_EX)
        try:
            uid = pwd.getpwnam(user_name).pw_uid
        except KeyError:
            try:
                uid = get_next_uid()
            except RuntimeError as e:
                # UID-range exhaustion is an operator-fixable environment
                # condition, not a bug — surface it as the CLI's clean
                # one-line error rather than a traceback.
                raise LifecycleError(str(e)) from e

        # Write a temporary sysusers config (the generator creates the
        # persistent copy at boot in /run/systemd/system/, but enable runs
        # before boot). Rendered by the shared helper so the enable-time .conf
        # is byte-identical to the generator's boot-time output.
        sysusers_content = render_sysusers_config(
            name=config.name,
            user_name=user_name,
            uid=uid,
            home_dir=home_dir,
            extra_groups=extra_groups,
            is_vm=config.is_vm,
        )

        sysusers_dir = Path("/run/sysusers.d")
        sysusers_dir.mkdir(parents=True, exist_ok=True)
        sysusers_file = sysusers_dir / f"workload-{config.name}.conf"
        sysusers_file.write_text(sysusers_content)

        subprocess.run(["systemd-sysusers", str(sysusers_file)], check=True)

    print("  Configuring workload user...")
    subprocess.run(["/usr/libexec/workloadctl/workload-ensure-user", config.name], check=True)


def _transfer_image(config: WorkloadConfig, manager: WorkloadManager):
    """Transfer pull=never images from the root store to the workload user store.

    Runs once per container; containers with any other pull policy are skipped.
    """
    for _cname, image, pull in config.container_specs():
        if pull == "never":
            _transfer_one_image(config, manager, image)


def _transfer_one_image(config: WorkloadConfig, manager: WorkloadManager, image: str):
    """Transfer a single pull=never image into the workload user store.

    Compares image IDs between root and user stores; transfers if the user
    store is missing the image or has a stale copy after a rebuild.
    Exits the process on failure.

    Boundary note (B13): the `podman load` step below hand-builds its own
    sudo invocation instead of going through `Podman.run()`. It needs a
    `TMPDIR=config.home_dir` override the wrapper's `_build_cmd()` doesn't
    expose (podman load's staging files must land somewhere the target user
    can write — the wrapper only carries XDG_RUNTIME_DIR/HOME) and a `cwd`
    set to the same dir for consistency. Documented here rather than growing
    the wrapper's env handling for this one call site (see `Podman.run()`).
    """
    user_image_id = manager.podman(config).image_id(image)
    root_image_id = Podman.for_root().image_id(image)

    need_transfer = root_image_id and root_image_id != user_image_id

    if need_transfer:
        if user_image_id:
            print(f"  Root store has an updated '{image}' (rebuild detected), re-transferring...")
        else:
            print(f"  Transferring '{image}' from root store to workload user store...")

        # Use a temp file rather than a pipe.  podman save via pipe creates a
        # pipeDir in /var/tmp as root (mode 700); the target user can't access
        # it, causing the load to fail with ENOENT on large images.  Writing to
        # a file owned by the target user in their home dir sidesteps this.
        fd, tmp_path = tempfile.mkstemp(suffix=".tar", dir=config.home_dir)
        os.close(fd)
        try:
            os.chown(tmp_path, config.uid, config.gid)

            save_result = subprocess.run(
                ["podman", "save", "--format", "docker-archive", "-o", tmp_path, image],
                capture_output=True,
            )
            if save_result.returncode != 0:
                print(
                    f"Error: Failed to save image '{image}': "
                    f"{save_result.stderr.decode(errors='replace')}",
                    file=sys.stderr,
                )
                sys.exit(1)

            # TMPDIR=config.home_dir: Podman.run()/_build_cmd() has no env
            # override hook, so this bypasses the wrapper (see the class
            # docstring note on Podman.run()).
            load_result = subprocess.run(
                ["sudo", "-n", "-u", config.username,
                 "-E", f"XDG_RUNTIME_DIR=/run/user/{config.uid}",
                 "-E", f"HOME={config.home_dir}",
                 "-E", f"TMPDIR={config.home_dir}",
                 "podman", "load", "-i", tmp_path],
                capture_output=True,
                cwd=config.home_dir,
            )
            if load_result.returncode != 0:
                print(
                    f"Error: Failed to transfer image '{image}': "
                    f"{load_result.stderr.decode(errors='replace')}",
                    file=sys.stderr,
                )
                sys.exit(1)
        finally:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
        print(f"  Image '{image}' transferred successfully")
        if user_image_id:
            active = subprocess.run(
                ["systemctl", "is-active", "--quiet", config.service_name],
                check=False
            )
            if active.returncode == 0:
                print("  Note: container is still running the old image.")
                print(f"  Run 'sudo workloadctl recreate {config.name}' to restart with the new image.")
    elif not user_image_id:
        print()
        print(f"Error: Image '{image}' not found locally and pull=never", file=sys.stderr)
        build_script = config.resolve_control_file("build.sh")
        if build_script.exists():
            print("Build the image first:", file=sys.stderr)
            print(f"  sudo {build_script}", file=sys.stderr)
        else:
            print(f"Build or pull the image '{image}' first.", file=sys.stderr)
        sys.exit(1)


def _activate_service(config: WorkloadConfig):
    """Re-run the workload-generate script and refresh systemd unit state."""
    # Architecture: the real systemd generator (`workload-generator`, shell)
    # only emits a single oneshot service (`workload-generate.service`) that
    # runs the Python `workload-generate` script at early boot. daemon-reload
    # re-runs generators, so it re-emits workload-generate.service — but it
    # does not re-run that service, so the per-workload unit files aren't
    # regenerated. For post-boot config changes we invoke the Python script
    # directly here, then daemon-reload so systemd picks up the new units.
    print("  Generating service files...")
    subprocess.run(
        ["/usr/libexec/workloadctl/workload-generate", "/run/systemd/system"],
        check=True,
    )
    subprocess.run(["systemctl", "daemon-reload"], check=True)

    print(f"  Starting {config.service_name}...")
    print("  (Image pull may take a few minutes on first start)")
    # A re-enabled unit name can still carry a `start-limit-hit` lockout from a
    # prior incarnation (StartLimitBurst survives userdel/purge), which would
    # refuse this fresh start. Clear it first; idempotent on a clean unit. The
    # start stays `--no-block` so enable returns before a slow first image pull.
    subprocess.run(["systemctl", "reset-failed", config.service_name],
                   check=False, capture_output=True)
    subprocess.run(["systemctl", "start", "--no-block", config.service_name], check=True)


def _run_host_setup(config: WorkloadConfig, action: str):
    """Run host setup script if configured in [host] section.

    The setup script receives 'enable' or 'disable' as its first argument.
    It is expected to be idempotent in both directions.
    """
    setup_script = config.config.get("host", {}).get("setup", "")
    if not setup_script:
        return

    # Relative names resolve through the override chain (/etc override wins over
    # the shipped bundle); an absolute path is taken verbatim.
    script_path = config.resolve_control_file(setup_script)

    if not script_path.exists():
        print(f"  WARNING: Host setup script not found: {script_path}", file=sys.stderr)
        return

    print(f"  Running host setup script ({action})...")
    result = subprocess.run(
        [str(script_path), action],
        capture_output=False,
    )
    if result.returncode != 0:
        print(f"  Error: Host setup script exited with code {result.returncode}",
              file=sys.stderr)
        if action == "enable":
            sys.exit(1)


def _selinux_available() -> bool:
    """True if the host can load CIL policy modules (semodule + udica bases)."""
    return bool(shutil.which("semodule")) and UDICA_TEMPLATE_DIR.is_dir()


def _selinux_enforcing() -> bool:
    """True if SELinux is currently in enforcing mode."""
    try:
        result = subprocess.run(["getenforce"], capture_output=True, text=True)
        return result.returncode == 0 and result.stdout.strip() == "Enforcing"
    except FileNotFoundError:
        return False


def _available_bundles() -> list[str]:
    """Bundle names shipping a CIL policy under the workloads share dir.

    A bundle is a subdir <name>/ that contains policy.cil (the template
    _apply_selinux_policy loads). Returned sorted for stable output.
    """
    if not _BUNDLES_DIR.is_dir():
        return []
    return sorted(
        d.name for d in _BUNDLES_DIR.iterdir()
        if d.is_dir() and (d / "policy.cil").exists()
    )


def _print_available_bundles(bundle: str):
    """Hint at valid selinux_policy bundles after a missing-template error."""
    available = _available_bundles()
    if not available:
        return
    match = difflib.get_close_matches(bundle, available, n=1)
    if match:
        print(f"         did you mean {match[0]!r}?", file=sys.stderr)
    print("         available bundles: " + ", ".join(available), file=sys.stderr)


def _apply_selinux_policy(config: WorkloadConfig, action: str):
    """Load (enable) or remove (disable) a workload's per-workload SELinux type.

    The bundle ships its policy as a CIL template (`policy.cil`) using the
    __WL_MODULE__ placeholder. On enable we substitute the name-keyed block name
    (wl_<name>) and load it alongside udica's base templates (which the
    workload's `(blockinherit ...)` resolves against); on disable we remove the
    wl_<name> module, leaving the shared base templates loaded.

    No-op for workloads without `[security].selinux_policy = true`.
    """
    if not config.selinux_policy:
        return

    module = selinux_module_name(config.name)

    if not _selinux_available():
        # Hard-fail only on enable: the container would fail to start under
        # enforcing mode without its type loaded. disable is best-effort
        # teardown — without tooling there's nothing we could remove anyway, so
        # never block it.
        if action != "disable" and _selinux_enforcing():
            print(f"  ERROR: selinux_policy is set for '{config.name}' but SELinux tooling "
                  f"(semodule + container-selinux templates) is missing. The container "
                  f"would fail to start under enforcing mode. Install container-selinux "
                  f"and policycoreutils, then re-run enable.",
                  file=sys.stderr)
            raise SelinuxPolicyError(f"selinux tooling missing for '{config.name}'")
        print(f"  WARNING: SELinux tooling (semodule + udica templates) not "
              f"found; skipping policy {action} for '{config.name}'",
              file=sys.stderr)
        return

    if action == "disable":
        loaded = subprocess.run(["semodule", "-l"], capture_output=True, text=True)
        if module in loaded.stdout.split():
            print(f"  Removing SELinux module {module}...")
            subprocess.run(["semodule", "-r", module], check=False)
        return

    # enable: substitute the block name and load the workload CIL alongside the
    # udica base templates (so any `(blockinherit ...)` resolves). semodule -i
    # upgrades in place, so re-enabling is idempotent. The CIL is sourced from
    # the bundle dir (defaults to the workload name; a `selinux_policy` string
    # names it explicitly so a renamed workload keeps its original policy).
    bundle = config.selinux_bundle
    if bundle is None:
        # Reached only if a workload without selinux_policy is routed here.
        print(f"  ERROR: no SELinux bundle resolved for '{config.name}' "
              f"(selinux_policy not set)", file=sys.stderr)
        raise SelinuxPolicyError(f"no SELinux bundle resolved for '{config.name}'")
    if not NAME_PATTERN.match(bundle):
        # bundle goes straight into a filesystem path; reject anything that
        # isn't a plain workload-style name (blocks traversal / odd values).
        print(f"  ERROR: invalid [workload] bundle {bundle!r} "
              f"(must match {NAME_PATTERN.pattern})", file=sys.stderr)
        # Common footgun: users copy the SELinux *type* name (wl_foo_bar,
        # underscores) into `bundle`, but the bundle is a directory name
        # and dirs are hyphenated. Suggest the hyphenated form.
        if "_" in bundle:
            print(f"         did you mean {bundle.replace('_', '-')!r}? "
                  f"(the bundle is a directory name and uses hyphens, not the "
                  f"underscores of the SELinux type name)", file=sys.stderr)
        raise SelinuxPolicyError(f"invalid bundle {bundle!r} for '{config.name}'")
    template = config.resolve_control_file("policy.cil")
    if not template.exists():
        print(f"  ERROR: SELinux policy template not found: {template}",
              file=sys.stderr)
        _print_available_bundles(bundle)
        raise SelinuxPolicyError(f"policy template not found for '{config.name}'")

    bases = sorted(str(p) for p in UDICA_TEMPLATE_DIR.glob("*.cil"))
    src = template.read_text().replace("__WL_MODULE__", module)

    print(f"  Installing SELinux module {module} (type {selinux_type_name(config.name)})...")
    with tempfile.TemporaryDirectory() as work:
        cil = Path(work) / f"{module}.cil"
        cil.write_text(src)
        try:
            subprocess.run(["semodule", "-i", str(cil), *bases], check=True)
        except subprocess.CalledProcessError as e:
            print(f"  Error: SELinux policy install failed (exit {e.returncode})",
                  file=sys.stderr)
            raise SelinuxPolicyError(f"semodule -i failed for '{config.name}'")


def _remove_runtime_env_files(config: WorkloadConfig) -> list[str]:
    """Delete a workload's /run/workload-env files on purge. Returns names removed.

    These are tmpfs + root-owned, written by workload-write-env (decrypted
    ${SECRET:…} values → .secrets) and workload-ensure-user
    (XDG_RUNTIME_DIR/HOST_IP → .env). Nothing rewrites them once the workload is
    gone, so without this a purge leaves decrypted secrets readable in /run
    until the next reboot. The env-tree entries of workload_run_files() name
    them by exact basename (not a glob), so purging 'git' never touches
    'github's files, and honor WORKLOAD_ENV_DIR for tests.
    """
    removed = []
    for rf in workload_run_files(config):
        if rf.kind != "env-file":
            continue
        if rf.path.exists():
            rf.path.unlink()
            removed.append(rf.path.name)
    return removed


def _stop_user_manager(username: str) -> bool:
    """Tear down a workload user's lingering systemd manager on disable.

    Terminates the user's session/manager and removes the linger marker so a
    *disabled* workload doesn't keep a live user@<uid>.service with a pinned
    /run/user/<uid>. Idempotent and safe: the user, home, and subuid ranges are
    left intact, and workload-ensure-user re-enables linger on the next start.
    Returns True if the user existed (and we acted), False otherwise.
    """
    try:
        uid = pwd.getpwnam(username).pw_uid
    except KeyError:
        return False
    subprocess.run(["loginctl", "terminate-user", str(uid)],
                   check=False, capture_output=True)
    subprocess.run(["loginctl", "disable-linger", str(uid)],
                   check=False, capture_output=True)
    return True


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_enable(args, manager: WorkloadManager):
    """Enable and start a workload"""
    require_root()

    config_path = workload_config_path(args.workload)
    if not config_path.exists():
        print(f"Error: Workload config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Enabling workload: {args.workload}")

    # Mark enabled before the daemon-reload below: the boot/CLI generator only
    # emits this workload's units when the marker is present.
    workload_enabled_marker(args.workload).touch()

    print("  Reloading systemd...")
    subprocess.run(["systemctl", "daemon-reload"], check=True)

    config = WorkloadConfig(args.workload)

    # Create workload home dir early so pre-flight copy instructions work verbatim
    config.home_dir.mkdir(parents=True, exist_ok=True)

    if not _preflight_checks(config):
        print()
        print("Pre-flight checks failed. Fix the issues above, then re-run enable.")
        print(f"  Directories have been set up at {config.home_dir} — copy any required files there.")
        print(f"  Workload left disabled; re-run 'sudo workloadctl enable {args.workload}' when ready.")
        # Nothing was started, so revert to disabled by removing the marker.
        workload_enabled_marker(args.workload).unlink(missing_ok=True)
        subprocess.run(["systemctl", "daemon-reload"], check=False)
        sys.exit(1)

    # Run host setup script if configured
    _run_host_setup(config, "enable")

    # Load the per-workload SELinux type (before the service starts, so the
    # container's label resolves). The error is already printed by
    # _apply_selinux_policy(); exit without printing again.
    try:
        _apply_selinux_policy(config, "enable")
    except SelinuxPolicyError:
        sys.exit(1)

    print()
    _provision_user(config)
    if not config.is_vm:
        _transfer_image(config, manager)
    _activate_service(config)

    already_running = subprocess.run(
        ["systemctl", "is-active", "--quiet", config.service_name], check=False
    ).returncode == 0

    if already_running:
        print(f"✓ Workload '{args.workload}' setup complete (already running)")
        print(f"  To apply config changes to the live container: sudo workloadctl recreate {args.workload}")
    else:
        print(f"✓ Workload '{args.workload}' enabled and starting")
        print(f"  Check status: workloadctl status {args.workload}")
        print(f"  Watch logs: sudo journalctl -fu {config.service_name}")


def _stop_bridge_if_last_vm(config: WorkloadConfig, manager: WorkloadManager):
    """Stop the shared VM bridge service when no managed-bridge VMs remain enabled.

    Called at the end of cmd_disable (purge and non-purge alike).  If the
    disabled workload was not itself a managed-bridge VM, returns immediately
    without consulting the workload list.  When it *was* the last such workload,
    stops workload-bridge.service so the _workload-br interface, dnsmasq, and
    nftables NAT table are torn down without waiting for a reboot.
    """
    if not (config.is_vm and config.vm_bridge == VM_BRIDGE_NAME):
        return

    still_needed = any(
        c.is_vm and c.vm_bridge == VM_BRIDGE_NAME and c.name != config.name
        for c in manager.get_all_configs(enabled_only=True)
    )
    if still_needed:
        return

    subprocess.run(
        ["systemctl", "stop", "workload-bridge.service"],
        check=False,
        capture_output=True,
    )
    print("  Stopped shared VM bridge (no managed-bridge VMs remain)")


def cmd_disable(args, manager: WorkloadManager):
    """Disable and stop a workload"""
    require_root()

    config = WorkloadConfig(args.workload)
    purge = args.purge

    if purge:
        print(f"Disabling and purging workload: {args.workload}")
    else:
        print(f"Disabling workload: {args.workload}")

    # Every teardown/removal step below is attempted independently and
    # best-effort: a failure in one never skips the rest, so a half-provisioned
    # or partly-wedged workload still gets torn down as far as possible. Failures
    # are collected and reported together with a non-zero exit at the end.
    failures: list[str] = []

    def attempt(label, fn):
        try:
            fn()
        except Exception as e:
            failures.append(f"{label}: {e}")

    print(f"  Stopping {config.service_name}...")
    attempt(f"stop {config.service_name}",
            lambda: subprocess.run(["systemctl", "stop", config.service_name], check=False))

    # Stop and reset the workload's RemainAfterExit=yes oneshot helpers so they
    # re-run on the next enable. They stay "active (exited)" after the umbrella
    # service stops (Requires= does not propagate stop), so a same-name re-enable
    # within one boot finds the Requires=d helper already satisfied and systemd
    # SILENTLY SKIPS re-running it. For the setup service that means
    # workload-ensure-user (linger, subuid/subgid, volume dirs, EnvironmentFile)
    # never re-runs: the workload comes up with no lingering user manager, so
    # /run/user/<uid> only exists for the lifetime of each transient
    # `sudo -u … podman` session and is GC'd in between — making every CLI podman
    # call (health/images/status/logs/exec/cp) intermittently fail with
    # "lstat /run/user/<uid>: no such file or directory".
    # Every service unit the workload owns except the umbrella (stopped above):
    # the setup/build oneshots, BOTH the pod and net helpers, per-container
    # sub-services, and a VM's virtiofs mounts. They share the RemainAfterExit
    # staleness, so all must be stopped + reset for a same-name re-enable to
    # re-run them; stopping an absent unit is a harmless no-op.
    #
    # Sourced from the run-file SUPERSET (workload_run_files), NOT the emitted
    # subset — this MUST match _remove_run_files below, which unlinks both the
    # -pod and -net fragments regardless of the current mode. If the TOML's mode
    # is changed (e.g. pod -> bridge) between enable and disable, the old mode's
    # still-active helper would otherwise have its fragment removed but never be
    # stopped, stranding a loaded unit (and its pod) until the next reboot.
    helper_services = [
        rf.path.name
        for rf in workload_run_files(config)
        if rf.kind == "unit" and rf.path.name != config.service_name
    ]
    for svc in helper_services:
        attempt(f"stop {svc}",
                lambda svc=svc: subprocess.run(["systemctl", "stop", svc], check=False, capture_output=True))
        attempt(f"reset-failed {svc}",
                lambda svc=svc: subprocess.run(["systemctl", "reset-failed", svc], check=False, capture_output=True))

    # Run host setup teardown if configured
    attempt("host setup teardown", lambda: _run_host_setup(config, "disable"))

    # Remove the per-workload SELinux module (1:1 with the workload, so this is
    # an unambiguous teardown — nothing else depends on wl_<name>).
    attempt("remove SELinux module", lambda: _apply_selinux_policy(config, "disable"))

    # Mark disabled so a future generation (next enable of anything, or boot)
    # won't re-emit this workload.
    attempt("mark disabled (unlink marker)",
            lambda: workload_enabled_marker(args.workload).unlink(missing_ok=True))

    # Remove this workload's generated unit files from /run/systemd/system. The
    # generator only ever writes (idempotent emit from the enabled set), so unless
    # we delete them here they linger as dead units — including the user@<uid>
    # drop-in that pins the user manager into workloads.slice — until the next
    # reboot wipes the tmpfs. Each unlink is independent (one failure never skips
    # the rest), then daemon-reload drops them from systemd's view.
    def _remove_run_files():
        # Removable (superset) view: every systemd-side file the workload owns,
        # -pod and -net listed for the whole topology so missing_ok covers the
        # mode we didn't emit. The env-tree files are removed separately, on
        # --purge only, by _remove_runtime_env_files.
        for rf in workload_run_files(config):
            if rf.kind == "env-file":
                continue
            try:
                rf.path.unlink(missing_ok=True)
            except OSError as e:
                failures.append(f"remove {rf.path}: {e}")
        if not config.is_vm:
            # Prune the now-empty user@<uid>.service.d drop-in dir. The UID lookup
            # raises once the user is gone; nothing to prune in that case.
            try:
                (RUN_SYSTEMD_SYSTEM / f"user@{config.uid}.service.d").rmdir()
            except (OSError, WorkloadUserNotFound):
                pass
    attempt("remove /run unit files", _remove_run_files)
    attempt("reload systemd",
            lambda: subprocess.run(["systemctl", "daemon-reload"], check=False))

    if purge:
        # Look up the user up front (may be absent if the workload was enabled
        # but never fully provisioned — /var setup is deferred to first start).
        # An absent user is "already clean", not an error.
        uid = None
        try:
            uid = pwd.getpwnam(config.username).pw_uid
        except KeyError:
            print(f"  User {config.username} not present (nothing to remove)")

        if uid is not None:
            try:
                print(f"  Terminating user sessions for {config.username}...")
                _stop_user_manager(config.username)
                time.sleep(1)
                # Kill any straggler processes (rootless podman, conmon, etc.)
                # so userdel doesn't print "user is currently used by process N".
                subprocess.run(["pkill", "-KILL", "-u", str(uid)],
                               check=False, capture_output=True)
                time.sleep(0.5)
            except Exception as e:
                failures.append(f"terminate user sessions: {e}")

        # Remove per-workload runtime files in /run/workload-env (decrypted
        # secrets + the env file) so a purge doesn't leave them readable in
        # /run until the next reboot.
        try:
            _remove_runtime_env_files(config)
        except Exception as e:
            failures.append(f"remove runtime env files: {e}")

        if config.is_vm:
            try:
                # Clean up the runtime socket directory
                vm_sock_dir = VM_SOCKET_DIR / config.name
                if vm_sock_dir.exists():
                    shutil.rmtree(vm_sock_dir, ignore_errors=True)
            except Exception as e:
                failures.append(f"remove VM socket dir: {e}")
        else:
            try:
                print("  Removing subuid/subgid entries...")
                subid_lock = SUBID_LOCK
                subid_lock.parent.mkdir(parents=True, exist_ok=True)
                with open(subid_lock, "w") as lock_fd:
                    fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
                    for file in ["/etc/subuid", "/etc/subgid"]:
                        p = Path(file)
                        if p.exists():
                            lines = [line for line in p.read_text().splitlines()
                                     if not line.startswith(f"{config.username}:")]
                            p.write_text("\n".join(lines) + ("\n" if lines else ""))
            except Exception as e:
                failures.append(f"remove subuid/subgid entries: {e}")

        if uid is not None:
            try:
                print(f"  Removing user {config.username}...")
                userdel = subprocess.run(["userdel", "-f", config.username],
                                         check=False, capture_output=True, text=True)
                # userdel -f exits 0 even when it prints a warning about a
                # process still using the account — check whether the user
                # actually got removed rather than trusting the exit code.
                try:
                    pwd.getpwnam(config.username)
                    msg = f"userdel: user {config.username} still exists"
                    if userdel.stderr.strip():
                        msg += f" ({userdel.stderr.strip()})"
                    msg += " — fix the underlying issue (e.g. 'sudo grpck') then re-run disable --purge"
                    failures.append(msg)
                except KeyError:
                    pass
            except Exception as e:
                failures.append(f"remove user {config.username}: {e}")

        # Remove the data dir regardless of whether the user still existed — an
        # orphaned /var/lib/workloads/<name> should still be swept.
        workload_dir = workload_root_dir(config.name)
        if workload_dir.exists():
            try:
                print(f"  Removing workload directory {workload_dir}...")
                shutil.rmtree(workload_dir)
            except OSError as e:
                failures.append(f"remove {workload_dir}: {e} "
                                "(data may still be present — remove manually before re-enabling)")

        if uid is None:
            success_msg = (f"✓ Workload '{args.workload}' disabled and purged "
                           "(user was not provisioned)")
        else:
            success_msg = f"✓ Workload '{args.workload}' disabled and purged"
    else:
        # A disabled (non-purged) workload keeps its user, home, and subuid
        # ranges, but should not keep a live lingering user manager. Stop it so
        # /run/user/<uid> and user@<uid>.service don't idle on; re-enable
        # re-establishes linger via workload-ensure-user.
        def _stop_lingering_user_manager():
            if _stop_user_manager(config.username):
                print(f"  Stopped lingering user manager for {config.username}")
        attempt("stop lingering user manager", _stop_lingering_user_manager)
        success_msg = f"✓ Workload '{args.workload}' disabled and stopped (use --purge to fully remove)"

    attempt("stop shared VM bridge", lambda: _stop_bridge_if_last_vm(config, manager))

    if failures:
        sys.stderr.write(f"  ! Disable of '{args.workload}' completed with errors:\n")
        for f in failures:
            sys.stderr.write(f"    - {f}\n")
        sys.exit(1)

    print(success_msg)


def cmd_start(args, manager: WorkloadManager):
    """Start a workload service (does not change enabled state)"""
    require_root()

    config_path = workload_config_path(args.workload)
    if not config_path.exists():
        print(f"Error: Workload config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    config = WorkloadConfig(args.workload)
    print(f"Starting {config.service_name}...")
    substrate = get_substrate(config, manager)
    substrate.lifecycle("start")
    print(f"✓ Workload '{args.workload}' started")


def cmd_stop(args, manager: WorkloadManager):
    """Stop a workload service (does not change enabled state)"""
    require_root()

    config_path = workload_config_path(args.workload)
    if not config_path.exists():
        print(f"Error: Workload config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    config = WorkloadConfig(args.workload)
    print(f"Stopping {config.service_name}...")
    result = subprocess.run(["systemctl", "stop", config.service_name])
    if result.returncode != 0:
        sys.exit(result.returncode)
    print(f"✓ Workload '{args.workload}' stopped")


def cmd_recreate(args, manager: WorkloadManager):
    """Recreate a workload from its image/config (containers: destroy overlay;
    VMs: rebuild the cloud-init seed and reboot QEMU onto it)."""
    require_root()
    config = WorkloadConfig(args.workload)

    print(f"Recreating workload: {args.workload}")
    print("  Regenerating service files...")
    subprocess.run(
        ["/usr/libexec/workloadctl/workload-generate", "/run/systemd/system"],
        check=True,
    )
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    # Clear any failed/start-limit state before restarting. A VM that was
    # stopped and started several times in quick succession (e.g. during
    # debug cycles or immediately after a fresh enable) can hit
    # StartLimitBurst and refuse a restart even though the underlying QEMU
    # binary is healthy. `recreate` explicitly means "restart fresh from
    # config", so it should never be blocked by accumulated start-limit
    # state. reset-failed is idempotent and harmless on a clean unit.
    subprocess.run(
        ["systemctl", "reset-failed", config.service_name],
        check=False, capture_output=True,
    )
    if not config.is_vm:
        _transfer_image(config, manager)
    substrate = get_substrate(config, manager)
    substrate.reprovision(recreate=True)
    print(f"✓ Workload '{args.workload}' recreated")
    print(f"  Watch logs: sudo journalctl -fu {config.service_name}")


def _run_build(config: WorkloadConfig) -> int:
    """Dispatch a build, returning its exit code. Run as root, building into
    root's podman store — `enable`/`recreate` then transfer the resulting
    pull=never image to the user store.

    Two modes (override-correct in both, via the merged build context):
      - `[build].script` set → escape hatch, run it (imagebuild.run_build_script).
      - else, a Containerfile resolves → built-in podman builder.
    Both operate on the merged /usr+/etc context, so overriding the Containerfile
    (or a COPY-ed asset) takes effect — unlike the old self-locating build.sh.
    """
    if config.build_script:
        return imagebuild.run_build_script(config)
    if config.has_build_context():
        return imagebuild.build_image(config)
    print(f"Error: nothing to build for '{config.name}'", file=sys.stderr)
    print("  No pull=never image with a resolvable Containerfile, and no "
          "[build].script — this workload pulls a published image.",
          file=sys.stderr)
    return 1


def cmd_build(args, manager: WorkloadManager):
    """Build a workload's container image from its bundle build context."""
    require_root()
    config = WorkloadConfig(args.workload)
    if config.is_vm:
        print(f"Error: 'build' applies to container workloads; '{config.name}' "
              f"is a VM (provision via 'update'/'recreate').", file=sys.stderr)
        sys.exit(1)

    rc = _run_build(config)
    if rc != 0:
        print(f"✗ Build failed (exit {rc})", file=sys.stderr)
        sys.exit(rc)

    print()
    print(f"✓ Built image for '{config.name}'")
    if config.enabled:
        print(f"  Apply to the running workload: sudo workloadctl recreate {config.name}")
    else:
        print(f"  Enable when ready: sudo workloadctl enable {config.name}")


def cmd_reboot(args, manager: WorkloadManager):
    """Soft-reboot a workload (re-exec systemd, restart all services, keep disk).

    Containers: `systemctl soft-reboot` in the container. VMs: the same
    soft-reboot inside the guest over SSH (a container `podman exec` is
    meaningless for a VM, which has no container)."""
    config = WorkloadConfig(args.workload)

    if not manager.user_exists(config):
        print(f"Error: Workload user '{config.username}' does not exist", file=sys.stderr)
        print("Is the workload enabled and running?", file=sys.stderr)
        sys.exit(1)

    print(f"Soft-rebooting workload: {args.workload}")
    substrate = get_substrate(config, manager)
    substrate.lifecycle("reboot")


def cmd_cleanup(args, manager: WorkloadManager):
    """Find and remove orphaned workload users and directories"""
    require_root()

    apply = args.apply

    # Collect names of ALL configured workloads (enabled or not)
    # A user with a config (even disabled) is not orphaned
    configured_names = set()
    # Per-workload SELinux modules a config still expects (selinux_policy = true).
    # Keyed on declaration, not enabled state — same as users above.
    expected_modules = set()
    for _name, config_file in iter_workloads():
        try:
            with open(config_file, "rb") as f:
                cfg = tomllib.load(f)
            name = cfg.get("workload", {}).get("name")
            if name:
                configured_names.add(name)
                if cfg.get("security", {}).get("selinux_policy"):
                    expected_modules.add(selinux_module_name(name))
        except Exception:
            pass

    # Orphaned per-workload SELinux modules: loaded wl_* modules that no config
    # still declares. semodule loads are persistent (a reboot reloads the same
    # policy), so a hand-deleted TOML or a dropped selinux_policy leaves the
    # module loaded with nothing behind it. The wl_ prefix scopes this to
    # per-workload modules — udica base templates and seatd_container are untouched.
    orphaned_modules = []
    if shutil.which("semodule"):
        r = subprocess.run(["semodule", "-l"], capture_output=True, text=True)
        if r.returncode == 0:
            loaded = {ln.strip() for ln in r.stdout.splitlines()
                      if ln.strip().startswith("wl_")}
            orphaned_modules = sorted(loaded - expected_modules)

    # Find all _wl-* system users
    all_users = pwd.getpwall()
    orphaned_users = []
    for entry in all_users:
        if not entry.pw_name.startswith(USERNAME_PREFIX):
            continue
        name = entry.pw_name[len(USERNAME_PREFIX):]
        if name not in configured_names:
            orphaned_users.append(entry)

    # Find workload dirs with no corresponding system user
    workloads_base = WORKLOADS_BASE
    orphaned_dirs = []
    if workloads_base.exists():
        existing_users = {e.pw_name for e in all_users}
        for d in workloads_base.iterdir():
            if not d.is_dir() or d.name.startswith("."):
                continue
            # The shared backup output dir has no _wl- user; it is not an
            # orphaned workload dir (`workloadctl backup` writes here).
            if d == workloads_base / BACKUP_DIR.name:
                continue
            # A dir with a live config but no user yet is NOT an orphan: the
            # documented recovery flow (pre-flight failed -> stage required
            # files in the dir -> re-run enable) leaves exactly that state, and
            # rmtree'ing it would destroy operator-staged data. Mirror the
            # configured_names guard used for orphan users above.
            expected_user = workload_username(d.name)
            if expected_user not in existing_users and d.name not in configured_names:
                orphaned_dirs.append(d)

    if args.json and not apply:
        print(json.dumps({
            "dry_run": True,
            "orphan_users": [e.pw_name for e in orphaned_users],
            "orphan_dirs": [str(d) for d in orphaned_dirs],
            "orphan_modules": orphaned_modules,
            "removed_users": [],
            "removed_dirs": [],
            "removed_modules": []
        }, indent=2))
        return

    if not orphaned_users and not orphaned_dirs and not orphaned_modules:
        if args.json:
            print(json.dumps({
                "dry_run": not apply,
                "orphan_users": [],
                "orphan_dirs": [],
                "orphan_modules": [],
                "removed_users": [],
                "removed_dirs": [],
                "removed_modules": []
            }, indent=2))
        else:
            print("Nothing to clean up.")
        return

    if not args.json:
        # Report what was found
        if orphaned_users:
            print(f"Orphaned users ({len(orphaned_users)}):")
            for entry in orphaned_users:
                has_subid_entries = False
                for subid_file in ["/etc/subuid", "/etc/subgid"]:
                    if Path(subid_file).exists() and any(
                        line.startswith(f"{entry.pw_name}:")
                        for line in Path(subid_file).read_text().splitlines()
                    ):
                        has_subid_entries = True
                        break
                extras = []
                if Path(entry.pw_dir).exists():
                    extras.append("has home dir")
                if has_subid_entries:
                    extras.append("has subuid/subgid")
                extra_str = f"  ({', '.join(extras)})" if extras else ""
                print(f"  {entry.pw_name} (UID {entry.pw_uid}){extra_str}")

        if orphaned_dirs:
            print(f"\nOrphaned directories ({len(orphaned_dirs)}):")
            for d in orphaned_dirs:
                print(f"  {d}")

        if orphaned_modules:
            print(f"\nOrphaned SELinux modules ({len(orphaned_modules)}):")
            for m in orphaned_modules:
                print(f"  {m}  (no workload declares selinux_policy)")

        if not apply:
            print("\nRun with --apply to remove the above.")
            return

    removed_users = []
    removed_dirs = []

    # Remove orphaned users
    if not args.json:
        print()
    for entry in orphaned_users:
        username = entry.pw_name
        uid = entry.pw_uid
        if not args.json:
            print(f"Removing {username}...")

        subprocess.run(["loginctl", "terminate-user", str(uid)], check=False,
                       capture_output=True)
        subprocess.run(["loginctl", "disable-linger", str(uid)], check=False,
                       capture_output=True)

        for subid_file in ["/etc/subuid", "/etc/subgid"]:
            p = Path(subid_file)
            if p.exists():
                lines = [line for line in p.read_text().splitlines()
                         if not line.startswith(f"{username}:")]
                p.write_text("\n".join(lines) + ("\n" if lines else ""))

        subprocess.run(["userdel", "-r", username], check=False, capture_output=True)
        removed_users.append(username)
        if not args.json:
            print(f"  ✓ Removed {username}")

    # Remove orphaned directories
    for d in orphaned_dirs:
        if not args.json:
            print(f"Removing directory {d}...")
        shutil.rmtree(d, ignore_errors=True)
        removed_dirs.append(str(d))
        if not args.json:
            print(f"  ✓ Removed {d}")

    # Remove orphaned SELinux modules
    removed_modules = []
    for m in orphaned_modules:
        if not args.json:
            print(f"Removing SELinux module {m}...")
        rc = subprocess.run(["semodule", "-r", m], check=False,
                            capture_output=True, text=True)
        if rc.returncode == 0:
            removed_modules.append(m)
            if not args.json:
                print(f"  ✓ Removed {m}")
        elif not args.json:
            print(f"  ✗ Failed to remove {m}: {rc.stderr.strip()}", file=sys.stderr)

    if args.json:
        print(json.dumps({
            "dry_run": False,
            "orphan_users": [e.pw_name for e in orphaned_users],
            "orphan_dirs": [str(d) for d in orphaned_dirs],
            "orphan_modules": orphaned_modules,
            "removed_users": removed_users,
            "removed_dirs": removed_dirs,
            "removed_modules": removed_modules
        }, indent=2))
    else:
        print("\nCleanup complete.")
