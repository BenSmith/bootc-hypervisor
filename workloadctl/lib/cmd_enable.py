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

from cli_log import emit_result, error, info
from workload_lib import (
    workload_config_path,
    workload_enabled_marker,
    workload_root_dir,
)
from workloadctl_core import WorkloadConfig, WorkloadManager, require_root
from substrate import LifecycleError
from provisioning import (
    apply_selinux_policy,
    apply_vm_fcontext,
    generate_units,
    ImageTransferError,
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
        error(f"Error: Workload config not found: {config_path}")
        sys.exit(1)

    info(f"Enabling workload: {args.workload}")

    # Mark enabled before the daemon-reload below: the boot/CLI generator only
    # emits this workload's units when the marker is present.
    workload_enabled_marker(args.workload).touch()

    info("  Reloading systemd...")
    subprocess.run(["systemctl", "daemon-reload"], check=True)

    config = WorkloadConfig(args.workload)

    # Create workload home dir early so pre-flight copy instructions work verbatim
    config.home_dir.mkdir(parents=True, exist_ok=True)

    if not preflight_checks(config):
        info()
        info("Pre-flight checks failed. Fix the issues above, then re-run enable.")
        info(f"  Directories have been set up under {workload_root_dir(config.name)}; "
             "use the full paths listed above.")
        info(f"  Workload left disabled; re-run 'sudo workloadctl enable {args.workload}' when ready.")
        # Nothing was started, so revert to disabled by removing the marker.
        workload_enabled_marker(args.workload).unlink(missing_ok=True)
        subprocess.run(["systemctl", "daemon-reload"], check=False)
        emit_result([{"workload": args.workload, "result": "failed",
                      "reason": "pre-flight checks failed"}], ok=False)
        sys.exit(1)

    # Run host setup script if configured
    run_host_setup(config, "enable")

    # Load the per-workload SELinux type (before the service starts, so the
    # container's label resolves). The error is already printed by
    # apply_selinux_policy(); exit without printing again.
    try:
        apply_selinux_policy(config, "enable")
    except SelinuxPolicyError as e:
        emit_result([{"workload": args.workload, "result": "failed",
                      "reason": str(e)}], ok=False)
        sys.exit(1)

    # Register the VM tree's fcontext rule (svirt_image_t rather than the
    # blanket container_file_t). Enable is the right place for it and a
    # workload's ExecStartPre is not: at boot N workloads would race the same
    # semanage read lock, whereas an enable is one-time and operator-initiated.
    apply_vm_fcontext(config, "enable")

    info()
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
        # Same shape as the SELinux step: the diagnostic is the raiser's, the
        # machine-readable result is this layer's.
        try:
            transfer_image(config, manager)
        except ImageTransferError as e:
            error(str(e))
            emit_result([{"workload": args.workload, "result": "failed",
                          "reason": str(e)}], ok=False)
            sys.exit(1)
    start_service(config)

    already_running = subprocess.run(
        ["systemctl", "is-active", "--quiet", config.service_name], check=False
    ).returncode == 0

    if already_running:
        info(f"✓ Workload '{args.workload}' setup complete (already running)")
        info(f"  To apply config changes to the live container: sudo workloadctl recreate {args.workload}")
    else:
        info(f"✓ Workload '{args.workload}' enabled and starting")
        info(f"  Check status: workloadctl status {args.workload}")
        info(f"  Watch logs: sudo journalctl -fu {config.service_name}")

    emit_result([{
        "workload": args.workload,
        "result": "already-running" if already_running else "enabled",
        "service": config.service_name,
    }])

