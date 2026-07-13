"""
cmd_enable — enable and start a workload.

The order is load-bearing: mark enabled, pre-flight, host hook, SELinux type,
*then* generate (the single producer of the sysusers .conf, UID and units) and
provision the user from what the generator wrote. Every step that can fail
before anything is started reverts the enabled marker, so a workload that
didn't come up is left honestly disabled.
"""

import subprocess
import sys

from workload_lib import workload_config_path, workload_enabled_marker
from workloadctl_core import WorkloadConfig, WorkloadManager, require_root
from substrate import LifecycleError
from cmd_provision import (
    apply_selinux_policy,
    generate_units,
    preflight_checks,
    provision_user,
    run_host_setup,
    SelinuxPolicyError,
    start_service,
    transfer_image,
)


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

    if not preflight_checks(config):
        print()
        print("Pre-flight checks failed. Fix the issues above, then re-run enable.")
        print(f"  Directories have been set up at {config.home_dir} — copy any required files there.")
        print(f"  Workload left disabled; re-run 'sudo workloadctl enable {args.workload}' when ready.")
        # Nothing was started, so revert to disabled by removing the marker.
        workload_enabled_marker(args.workload).unlink(missing_ok=True)
        subprocess.run(["systemctl", "daemon-reload"], check=False)
        sys.exit(1)

    # Run host setup script if configured
    run_host_setup(config, "enable")

    # Load the per-workload SELinux type (before the service starts, so the
    # container's label resolves). The error is already printed by
    # apply_selinux_policy(); exit without printing again.
    try:
        apply_selinux_policy(config, "enable")
    except SelinuxPolicyError:
        sys.exit(1)

    print()
    # Generate first: the generator is the single producer of the sysusers
    # .conf + UID + units, and provision_user consumes what it writes. If it
    # can't produce this workload's units (UID exhaustion), revert to disabled
    # so the "left disabled" message is true and the next boot doesn't retry.
    try:
        generate_units(config)
    except LifecycleError:
        workload_enabled_marker(args.workload).unlink(missing_ok=True)
        subprocess.run(["systemctl", "daemon-reload"], check=False)
        raise
    provision_user(config)
    if not config.is_vm:
        transfer_image(config, manager)
    start_service(config)

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

