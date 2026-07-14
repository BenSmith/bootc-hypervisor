"""
cmd_lifecycle — the runtime verbs: start, stop, restart, recreate, reboot, build.

These act on a workload that is already provisioned; none of them change its
enabled state (see cmd_enable / cmd_disable for that). start/stop/restart/reboot
go through the substrate's lifecycle() primitive so a VM and a container are
driven the same way; recreate re-runs the generator for this workload and hands
off to reprovision(recreate=True), which owns the semantics that make recreate
different from a bounce.
"""

import subprocess
import sys

import imagebuild
from cli_log import emit_result, error, info
from workload_lib import workload_config_path
from workloadctl_core import WorkloadConfig, WorkloadManager, require_root
from substrate import get_substrate, service_active
from cmd_provision import transfer_image


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


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_start(args, manager: WorkloadManager):
    """Start a workload service (does not change enabled state)"""
    require_root()

    config_path = workload_config_path(args.workload)
    if not config_path.exists():
        error(f"Error: Workload config not found: {config_path}")
        sys.exit(1)

    config = WorkloadConfig(args.workload)
    info(f"Starting {config.service_name}...")
    substrate = get_substrate(config, manager)
    substrate.lifecycle("start")
    info(f"✓ Workload '{args.workload}' started")
    emit_result([{"workload": args.workload, "result": "started",
                  "service": config.service_name}])


def cmd_stop(args, manager: WorkloadManager):
    """Stop a workload service (does not change enabled state)"""
    require_root()

    config_path = workload_config_path(args.workload)
    if not config_path.exists():
        error(f"Error: Workload config not found: {config_path}")
        sys.exit(1)

    config = WorkloadConfig(args.workload)
    info(f"Stopping {config.service_name}...")
    substrate = get_substrate(config, manager)
    substrate.lifecycle("stop")
    info(f"✓ Workload '{args.workload}' stopped")
    emit_result([{"workload": args.workload, "result": "stopped",
                  "service": config.service_name}])


def cmd_restart(args, manager: WorkloadManager):
    """Restart a workload service (does not change enabled state)"""
    require_root()

    config_path = workload_config_path(args.workload)
    if not config_path.exists():
        error(f"Error: Workload config not found: {config_path}")
        sys.exit(1)

    config = WorkloadConfig(args.workload)
    info(f"Restarting {config.service_name}...")
    substrate = get_substrate(config, manager)
    substrate.lifecycle("restart")
    info(f"✓ Workload '{args.workload}' restarted")
    emit_result([{"workload": args.workload, "result": "restarted",
                  "service": config.service_name}])


def cmd_recreate(args, manager: WorkloadManager):
    """Recreate a workload from its image/config (containers: destroy overlay;
    VMs: rebuild the cloud-init seed and reboot QEMU onto it)."""
    require_root()
    config = WorkloadConfig(args.workload)

    info(f"Recreating workload: {args.workload}")
    info("  Regenerating service files...")
    subprocess.run(
        ["/usr/libexec/workloadctl/workload-generate", "/run/systemd/system",
         "--workload", config.name],
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
        transfer_image(config, manager)
    substrate = get_substrate(config, manager)
    substrate.reprovision(recreate=True)
    info(f"✓ Workload '{args.workload}' recreated")
    info(f"  Watch logs: sudo journalctl -fu {config.service_name}")
    emit_result([{"workload": args.workload, "result": "recreated",
                  "service": config.service_name}])


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
    error(f"Error: nothing to build for '{config.name}'")
    error("  No pull=never image with a resolvable Containerfile, and no "
          "[build].script — this workload pulls a published image.")
    return 1


def cmd_build(args, manager: WorkloadManager):
    """Build a workload's container image from its bundle build context."""
    require_root()
    config = WorkloadConfig(args.workload)
    if config.is_vm:
        error(f"Error: 'build' applies to container workloads; '{config.name}' "
              f"is a VM (provision via 'update'/'recreate').")
        sys.exit(1)

    rc = _run_build(config)
    if rc != 0:
        error(f"✗ Build failed (exit {rc})")
        sys.exit(rc)

    info()
    info(f"✓ Built image for '{config.name}'")
    if config.enabled:
        info(f"  Apply to the running workload: sudo workloadctl recreate {config.name}")
    else:
        info(f"  Enable when ready: sudo workloadctl enable {config.name}")
    emit_result([{"workload": config.name, "result": "built"}])


def cmd_reboot(args, manager: WorkloadManager):
    """Soft-reboot a workload (re-exec systemd, restart all services, keep disk).

    Containers: `systemctl soft-reboot` in the container. VMs: the same
    soft-reboot inside the guest over SSH (a container `podman exec` is
    meaningless for a VM, which has no container)."""
    config = WorkloadConfig(args.workload)

    if not manager.user_exists(config):
        error(f"Error: Workload user '{config.username}' does not exist")
        error("Is the workload enabled and running?")
        sys.exit(1)

    info(f"Soft-rebooting workload: {args.workload}")
    substrate = get_substrate(config, manager)
    substrate.lifecycle("reboot")
    emit_result([{"workload": args.workload, "result": "rebooted",
                  "service": config.service_name}])
