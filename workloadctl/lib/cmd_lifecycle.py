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
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib

from workload_lib import (
    selinux_module_name,
    selinux_type_name,
    USERNAME_PREFIX,
    WORKLOADS_BASE,
    VM_SOCKET_DIR,
    get_next_uid,
    NAME_PATTERN,
    workload_username,
)
from podman import Podman
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    require_root,
    WORKLOAD_DIR,
)
from cmd_admin import validate_single
from cmd_backup import BACKUP_DIR


REQUIRED_EXECUTABLES = ["podman", "systemctl", "loginctl", "systemd-sysusers", "restorecon", "semodule"]
RECOMMENDED_EXECUTABLES = ["semanage", "udica"]

UDICA_TEMPLATE_DIR = Path("/usr/share/udica/templates")
_CONTAINERS_DIR = Path("/usr/share/workloadctl/containers")

_WORKLOAD_SECTION_RE = re.compile(
    r'(?ms)(?P<header>^\[workload\][^\n]*\n)(?P<body>.*?)(?=^\[|\Z)'
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _gating_units(config):
    """Units that must succeed before the main service can start. VMs split
    user/cloud-init setup and the system-disk build into their own units; a
    failure there leaves the main service merely 'inactive' (dependency not
    met), hiding the real cause. Container workloads run their setup as an
    ExecStartPre of the main unit, so a failure already surfaces there."""
    if config.is_vm:
        return [f"workload-{config.name}-setup.service",
                f"workload-{config.name}-build.service"]
    return []


def _effective_state(config):
    """Return (state, failed_unit) for display. If the main service isn't
    active but a gating unit has failed, report 'failed' and name the culprit
    so the cause isn't buried behind a bland 'inactive'."""
    main = subprocess.run(
        ["systemctl", "is-active", config.service_name],
        capture_output=True, text=True,
    ).stdout.strip()
    if main == "active":
        return main, None
    for unit in _gating_units(config):
        st = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True, text=True,
        ).stdout.strip()
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
            # TODO: remove hardcoded path
            build_script = Path(f"/usr/share/workloadctl/containers/{config.name}/build.sh")
            if build_script.exists():
                print(f"    Build the image first:")
                print(f"      sudo {build_script}")
            else:
                print(f"    Build or pull the image first, or change pull policy")
            failed = True

    # Check required files exist (declared in [setup].required_files)
    required_files = config.get_required_files()
    required_file_paths = {entry["path"] for entry in required_files}
    missing_required_files = [e for e in required_files if not Path(e["path"]).exists()]

    if missing_required_files:
        home_resolved = Path(config.home_dir).resolve()
        still_missing = []
        for entry in missing_required_files:
            dest = Path(entry["path"])
            hint = entry.get("hint")
            if hint and Path(hint).exists() and dest.resolve().is_relative_to(home_resolved):
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
        home_resolved = Path(config.home_dir).resolve()
        auto_create = [p for p in missing_dirs
                       if Path(p).resolve().is_relative_to(home_resolved)]
        must_create = [p for p in missing_dirs
                       if not Path(p).resolve().is_relative_to(home_resolved)]

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
        print(f"  ✗ Missing groups:")
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
                print(f"    Fix: echo 'net.ipv4.ip_unprivileged_port_start = 0' | "
                      f"sudo tee /etc/sysctl.d/50-privileged-ports.conf && sudo sysctl --system")
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
    # concurrent enables don't race on the same UID slot.
    _subid_lock = Path("/run/lock/workload-subid.lock")
    _subid_lock.parent.mkdir(parents=True, exist_ok=True)
    with open(_subid_lock, "w") as _lock_fd:
        fcntl.flock(_lock_fd.fileno(), fcntl.LOCK_EX)
        try:
            uid = pwd.getpwnam(user_name).pw_uid
        except KeyError:
            uid = get_next_uid()

    # Write a temporary sysusers config (the generator creates the persistent
    # copy at boot in /run/systemd/system/, but enable runs before boot)
    sysusers_lines = [
        f"# Workload user for {config.name}",
        f'u {user_name} {uid} "{config.name} workload" {home_dir}',
    ]
    if config.is_vm:
        sysusers_lines.append(f"m {user_name} kvm")
    for group in extra_groups:
        sysusers_lines.append(f"m {user_name} {group}")

    sysusers_dir = Path("/run/sysusers.d")
    sysusers_dir.mkdir(parents=True, exist_ok=True)
    sysusers_file = sysusers_dir / f"workload-{config.name}.conf"
    sysusers_file.write_text("\n".join(sysusers_lines) + "\n")

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
                print(f"  Note: container is still running the old image.")
                print(f"  Run 'sudo workloadctl recreate {config.name}' to restart with the new image.")
    elif not user_image_id:
        print()
        print(f"Error: Image '{image}' not found locally and pull=never", file=sys.stderr)
        build_script = Path(f"/usr/share/workloadctl/containers/{config.name}/build.sh")
        if build_script.exists():
            print(f"Build the image first:", file=sys.stderr)
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
    subprocess.run(["systemctl", "start", "--no-block", config.service_name], check=True)


def _run_host_setup(config: WorkloadConfig, action: str):
    """Run host setup script if configured in [host] section.

    The setup script receives 'enable' or 'disable' as its first argument.
    It is expected to be idempotent in both directions.
    """
    setup_script = config.config.get("host", {}).get("setup", "")
    if not setup_script:
        return

    if setup_script.startswith("/"):
        script_path = Path(setup_script)
    else:
        container_dir = Path(f"/usr/share/workloadctl/containers/{config.name}")
        script_path = container_dir / setup_script

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
    """Bundle names shipping a CIL policy under the containers share dir.

    A bundle is a subdir <name>/ that contains <name>.cil (the template
    _apply_selinux_policy loads). Returned sorted for stable output.
    """
    if not _CONTAINERS_DIR.is_dir():
        return []
    return sorted(
        d.name for d in _CONTAINERS_DIR.iterdir()
        if d.is_dir() and (d / f"{d.name}.cil").exists()
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

    The bundle ships its policy as a CIL template (`<name>.cil`) using the
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
            sys.exit(1)
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
    if not NAME_PATTERN.match(bundle):
        # bundle goes straight into a filesystem path; reject anything that
        # isn't a plain workload-style name (blocks traversal / odd values).
        print(f"  ERROR: invalid selinux_policy bundle {bundle!r} "
              f"(must match {NAME_PATTERN.pattern})", file=sys.stderr)
        # Common footgun: users copy the SELinux *type* name (wl_foo_bar,
        # underscores) into selinux_policy, but the bundle is a directory name
        # and dirs are hyphenated. Suggest the hyphenated form.
        if "_" in bundle:
            print(f"         did you mean {bundle.replace('_', '-')!r}? "
                  f"(the bundle is a directory name and uses hyphens, not the "
                  f"underscores of the SELinux type name)", file=sys.stderr)
        sys.exit(1)
    template = Path(f"/usr/share/workloadctl/containers/{bundle}/{bundle}.cil")
    if not template.exists():
        print(f"  ERROR: SELinux policy template not found: {template}",
              file=sys.stderr)
        _print_available_bundles(bundle)
        sys.exit(1)

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
            sys.exit(1)


def _replace_workload_enabled(content: str, value: str | None) -> tuple[str, bool]:
    """Set, change, or remove `enabled` in the [workload] section only.

    Scoping the edit to [workload] keeps the regex from accidentally flipping
    an unrelated `enabled = ...` in some other section (today there's none,
    but the schema is open to extension and the wider regex would silently
    catch a future `[[containers]] enabled = ...` field).

    value: "true" or "false" to set; None to remove the line.
    Returns (new_content, had_field_before).
    """
    m = _WORKLOAD_SECTION_RE.search(content)
    if not m:
        if value is None:
            return content, False
        sep = "" if content.endswith("\n") else "\n"
        return content + f"{sep}[workload]\nenabled = {value}\n", False
    body = m.group("body")
    had_field = bool(re.search(r'^enabled\s*=', body, re.MULTILINE))
    if had_field and value is None:
        new_body = re.sub(r'^enabled\s*=[^\n]*\n?', '', body, count=1,
                          flags=re.MULTILINE)
    elif had_field:
        new_body = re.sub(r'^enabled\s*=[^\n]*', f'enabled = {value}',
                          body, count=1, flags=re.MULTILINE)
    elif value is None:
        new_body = body
    else:
        new_body = f'enabled = {value}\n' + body
    return content[:m.start("body")] + new_body + content[m.end("body"):], had_field


def _remove_user_dropin(config: WorkloadConfig):
    """Remove the user@<uid>.service.d/50-workload.conf drop-in for a workload."""
    dropin_dir = Path("/run/systemd/system") / f"user@{config.uid}.service.d"
    dropin_conf = dropin_dir / "50-workload.conf"
    if dropin_conf.exists():
        dropin_conf.unlink()
    try:
        dropin_dir.rmdir()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_enable(args, manager: WorkloadManager):
    """Enable and start a workload"""
    require_root()

    config_path = WORKLOAD_DIR / f"{args.workload}.toml"
    if not config_path.exists():
        print(f"Error: Workload config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Enabling workload: {args.workload}")

    content = config_path.read_text()
    content, had_enabled_field = _replace_workload_enabled(content, "true")
    config_path.write_text(content)

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
        # Revert enabled = true since we haven't actually started anything.
        # If the original file didn't have an enabled field, remove the one we
        # added; otherwise flip it back to false to preserve user formatting.
        content = config_path.read_text()
        content, _ = _replace_workload_enabled(
            content, "false" if had_enabled_field else None
        )
        config_path.write_text(content)
        subprocess.run(["systemctl", "daemon-reload"], check=False)
        sys.exit(1)

    # Run host setup script if configured
    _run_host_setup(config, "enable")

    # Load the per-workload SELinux type (before the service starts, so the
    # container's label resolves).
    _apply_selinux_policy(config, "enable")

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


def cmd_disable(args, manager: WorkloadManager):
    """Disable and stop a workload"""
    require_root()

    config = WorkloadConfig(args.workload)
    purge = args.purge

    if purge:
        print(f"Disabling and purging workload: {args.workload}")
    else:
        print(f"Disabling workload: {args.workload}")

    print(f"  Stopping {config.service_name}...")
    subprocess.run(["systemctl", "stop", config.service_name], check=False)

    if config.is_vm:
        # Stop and reset the build/setup oneshot services so they re-run on
        # the next enable. Without this, --purge deletes the disk but the
        # build service stays in "active exited" and systemd skips it.
        for suffix in ("build", "setup"):
            svc = f"workload-{config.name}-{suffix}.service"
            subprocess.run(["systemctl", "stop", svc], check=False, capture_output=True)
            subprocess.run(["systemctl", "reset-failed", svc], check=False, capture_output=True)

    # Run host setup teardown if configured
    _run_host_setup(config, "disable")

    # Remove the per-workload SELinux module (1:1 with the workload, so this is
    # an unambiguous teardown — nothing else depends on wl_<name>).
    _apply_selinux_policy(config, "disable")

    config_path = WORKLOAD_DIR / f"{args.workload}.toml"
    content = config_path.read_text()
    if re.search(r'^enabled\s*=', content, re.MULTILINE):
        content = re.sub(r'^enabled\s*=\s*true', 'enabled = false', content, flags=re.MULTILINE)
    else:
        content = re.sub(r'^(\[workload\])', r'\1\nenabled = false', content, flags=re.MULTILINE)
    config_path.write_text(content)

    # Remove the user@ drop-in so systemd stops constraining user@<uid>
    # to workloads.slice once the workload is disabled.  Lives in /run so
    # it would vanish on reboot anyway, but clean it up eagerly.
    _remove_user_dropin(config)

    subprocess.run(["systemctl", "daemon-reload"], check=False)

    if purge:
        # Get user info before deletion
        try:
            pw = pwd.getpwnam(config.username)
            uid = pw.pw_uid
            home_dir = pw.pw_dir

            print(f"  Terminating user sessions for {config.username}...")
            subprocess.run(["loginctl", "terminate-user", str(uid)], check=False)
            subprocess.run(["loginctl", "disable-linger", str(uid)], check=False)
            time.sleep(1)
            # Kill any straggler processes (rootless podman, conmon, etc.)
            # so userdel doesn't print "user is currently used by process N".
            subprocess.run(["pkill", "-KILL", "-u", str(uid)],
                           check=False, capture_output=True)
            time.sleep(0.5)

            if config.is_vm:
                # Clean up the runtime socket directory
                vm_sock_dir = VM_SOCKET_DIR / config.name
                if vm_sock_dir.exists():
                    shutil.rmtree(vm_sock_dir, ignore_errors=True)
            else:
                print("  Removing subuid/subgid entries...")
                subid_lock = Path("/run/lock/workload-subid.lock")
                subid_lock.parent.mkdir(parents=True, exist_ok=True)
                with open(subid_lock, "w") as lock_fd:
                    fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
                    for file in ["/etc/subuid", "/etc/subgid"]:
                        p = Path(file)
                        if p.exists():
                            lines = [l for l in p.read_text().splitlines()
                                     if not l.startswith(f"{config.username}:")]
                            p.write_text("\n".join(lines) + ("\n" if lines else ""))

            print(f"  Removing user {config.username}...")
            userdel = subprocess.run(["userdel", "-f", config.username],
                                     check=False, capture_output=True, text=True)
            # userdel -f exits 0 even when it prints a warning about a process
            # still using the account — check whether the user actually got
            # removed rather than trusting the exit code.
            user_still_exists = False
            try:
                pwd.getpwnam(config.username)
                user_still_exists = True
            except KeyError:
                pass

            if user_still_exists:
                sys.stderr.write(f"  ! userdel failed — user {config.username} still exists.\n")
                if userdel.stderr.strip():
                    sys.stderr.write(f"    {userdel.stderr.strip()}\n")
                sys.stderr.write(f"    Fix the underlying issue (e.g. 'sudo grpck') then re-run disable --purge.\n")
                sys.exit(1)

            home_path = Path(home_dir)
            if home_path.exists():
                print(f"  Removing home directory {home_dir}...")
                try:
                    shutil.rmtree(home_dir)
                except OSError as e:
                    sys.stderr.write(f"  ! Failed to fully remove {home_dir}: {e}\n")
                    sys.stderr.write(f"  ! Workload data may still be present — remove manually before re-enabling.\n")
                    sys.exit(1)

            print(f"✓ Workload '{args.workload}' disabled and purged")
        except KeyError:
            print(f"✓ Workload '{args.workload}' disabled (user not found)")
    else:
        print(f"✓ Workload '{args.workload}' disabled and stopped (use --purge to fully remove)")


def cmd_start(args, manager: WorkloadManager):
    """Start a workload service (does not change enabled state)"""
    require_root()

    config_path = WORKLOAD_DIR / f"{args.workload}.toml"
    if not config_path.exists():
        print(f"Error: Workload config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    config = WorkloadConfig(args.workload)
    print(f"Starting {config.service_name}...")
    result = subprocess.run(["systemctl", "start", config.service_name])
    if result.returncode != 0:
        sys.exit(result.returncode)
    print(f"✓ Workload '{args.workload}' started")


def cmd_stop(args, manager: WorkloadManager):
    """Stop a workload service (does not change enabled state)"""
    require_root()

    config_path = WORKLOAD_DIR / f"{args.workload}.toml"
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
    if config.is_vm:
        # The cloud-init ISO and nvram are built by the setup oneshot
        # (RemainAfterExit=yes), which a plain main-service restart does NOT
        # re-run. Restart it first so config edits (template_vars, volumes, …)
        # are re-rendered into a fresh seed before QEMU boots onto it.
        subprocess.run(
            ["systemctl", "restart", f"workload-{config.name}-setup.service"],
            check=True,
        )
    subprocess.run(["systemctl", "restart", config.service_name], check=True)
    print(f"✓ Workload '{args.workload}' recreated")
    print(f"  Watch logs: sudo journalctl -fu {config.service_name}")


def cmd_reboot(args, manager: WorkloadManager):
    """Soft-reboot a workload (re-exec systemd, restart all services, keep disk).

    Containers: `systemctl soft-reboot` in the container. VMs: the same
    soft-reboot inside the guest over SSH (a container `podman exec` is
    meaningless for a VM, which has no container)."""
    from cmd_interact import _vm_guest_ip, _vm_ssh_command
    config = WorkloadConfig(args.workload)

    if not manager.user_exists(config):
        print(f"Error: Workload user '{config.username}' does not exist", file=sys.stderr)
        print("Is the workload enabled and running?", file=sys.stderr)
        sys.exit(1)

    print(f"Soft-rebooting workload: {args.workload}")

    if config.is_vm:
        guest_ip = _vm_guest_ip(config.name, config.vm_bridge)
        if not guest_ip:
            from workload_lib import VM_DHCP_LEASE_FILE
            print(f"Error: could not determine IP for VM '{args.workload}'", file=sys.stderr)
            print(f"  Check {VM_DHCP_LEASE_FILE} or use 'workloadctl shell {args.workload}' (console).",
                  file=sys.stderr)
            sys.exit(1)
        # Fire the soft-reboot detached via systemd-run --no-block: a direct
        # `systemctl soft-reboot` tears down sshd mid-command, so the SSH
        # connection drops and ssh exits nonzero *even on success*. Running it
        # in a transient unit lets the SSH command return cleanly (0) before
        # teardown; --collect reaps the unit. (`sudo` failures are still caught
        # here; an unsupported soft-reboot on systemd <254 fails async.)
        ssh_cmd = _vm_ssh_command(
            config, guest_ip,
            exec_args=["sudo", "systemd-run", "--collect", "--no-block",
                       "systemctl", "soft-reboot"],
            connect_timeout=5,
        )
        result = subprocess.run(ssh_cmd)
        if result.returncode != 0:
            print("Error: could not initiate guest soft-reboot.", file=sys.stderr)
            print("  Needs passwordless sudo and systemd 254+ in the guest. To "
                  "power-cycle the VM regardless of its init system (disk "
                  "preserved), run:", file=sys.stderr)
            print(f"    sudo systemctl restart {config.service_name}", file=sys.stderr)
            sys.exit(1)
        print(f"✓ VM '{args.workload}' soft-reboot initiated (disk preserved)")
        return

    result = manager.run_podman_exec(config,
                                     [config.container_name, "systemctl", "soft-reboot"])
    if result.returncode != 0:
        print("Error: soft-reboot failed. Is this a systemd container?", file=sys.stderr)
        sys.exit(1)
    print(f"✓ Workload '{args.workload}' soft-rebooted (overlay preserved)")


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
    for config_file in manager.workload_dir.glob("*.toml"):
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
            if d.name == BACKUP_DIR.name:
                continue
            expected_user = workload_username(d.name)
            if expected_user not in existing_users:
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
                for f in ["/etc/subuid", "/etc/subgid"]:
                    if Path(f).exists() and any(
                        line.startswith(f"{entry.pw_name}:")
                        for line in Path(f).read_text().splitlines()
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

        for f in ["/etc/subuid", "/etc/subgid"]:
            p = Path(f)
            if p.exists():
                lines = [l for l in p.read_text().splitlines()
                         if not l.startswith(f"{username}:")]
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
