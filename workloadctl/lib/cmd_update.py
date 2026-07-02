"""
cmd_update — update and rollback commands.
"""

import subprocess
import sys
import time

from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    require_root,
)
from service_runtime import restart_workload_service
from substrate import (
    get_substrate,
    VMSubstrate,
    ProvisionFailed,
    NotApplicable,
    rollback_tag,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_duration(s: str) -> int:
    """Parse a duration string like '30s', '5m', '1h' to seconds."""
    s = s.strip()
    if s.endswith("s"):
        return int(s[:-1])
    if s.endswith("m"):
        return int(s[:-1]) * 60
    if s.endswith("h"):
        return int(s[:-1]) * 3600
    return int(s)


def _health_wait_seconds(config: WorkloadConfig) -> int:
    """Return how long to wait for a workload's health checks (0 if none).

    Multi-container workloads have one health block per container; take the
    max so we don't return prematurely on the slowest-starting container.
    """
    waits = []
    for _local, _podman_name, health in config.container_health_blocks():
        start_period = _parse_duration(health.get("start_period", "0s"))
        interval = _parse_duration(health.get("interval", "30s"))
        waits.append(start_period + interval)
    return max(waits) if waits else 0


def _do_rollback(config: WorkloadConfig, manager: WorkloadManager, old_ids: dict):
    """Roll back every container to its previous image and restart."""
    pod = manager.podman(config)
    for cname, image in config.container_images():
        tag = rollback_tag(config.name, cname if config.is_multi else None)
        if pod.image_id(tag):
            pod.tag(tag, image)
    restart_workload_service(config.uid, config.service_name)
    print(f"  ✗ {config.name}: rolled back to previous image(s)")



def _verify_all(updated: list, manager: WorkloadManager) -> int:
    """Verify all updated workloads after restart. Returns number of rollbacks."""
    # Wait time: max health check wait, minimum 5s for crash detection
    max_wait = 5
    for config, _ in updated:
        wait = _health_wait_seconds(config)
        if wait > max_wait:
            max_wait = wait

    hc_names = [c.name for c, _ in updated if c.has_health_check()]
    nhc_names = [c.name for c, _ in updated if not c.has_health_check()]
    parts = []
    if hc_names:
        parts.append(f"health checks: {', '.join(hc_names)}")
    if nhc_names:
        parts.append(f"service liveness: {', '.join(nhc_names)}")
    print(f"Verifying updates ({'; '.join(parts)})...")
    print(f"  Waiting {max_wait}s...", end="", flush=True)
    time.sleep(max_wait)
    print(" checking")

    rolled_back = 0
    for config, old_ids in updated:
        have_old = any(old_ids.values())
        if config.has_health_check():
            # Multi-container workloads have one health block per container;
            # each container has its own podman container, so we check them
            # individually and aggregate. A workload is healthy only when
            # every checked container is.
            hc_blocks = config.container_health_blocks()
            pod = manager.podman(config)
            statuses = {local: pod.container_health(pname) or ""
                        for local, pname, _h in hc_blocks}

            if all(s == "healthy" for s in statuses.values()):
                print(f"  ✓ {config.name}: healthy")
            elif any(s == "starting" for s in statuses.values()) and have_old:
                # One container is still starting — give it the longest
                # remaining interval before declaring failure.
                interval = max(
                    _parse_duration(h.get("interval", "30s"))
                    for local, _pname, h in hc_blocks
                    if statuses[local] == "starting"
                )
                still = ", ".join(local for local, s in statuses.items() if s == "starting")
                print(f"  ⏳ {config.name}: still starting ({still}), waiting {interval}s more...",
                      end="", flush=True)
                time.sleep(interval)
                statuses = {local: pod.container_health(pname) or ""
                            for local, pname, _h in hc_blocks}
                if all(s == "healthy" for s in statuses.values()):
                    print(" healthy")
                else:
                    detail = ", ".join(f"{local_name}={s or 'unknown'}" for local_name, s in statuses.items()
                                       if s != "healthy")
                    print(f" {detail}")
                    _do_rollback(config, manager, old_ids)
                    rolled_back += 1
            elif have_old:
                detail = ", ".join(f"{local_name}={s or 'unknown'}" for local_name, s in statuses.items()
                                   if s != "healthy")
                print(f"  ✗ {config.name}: {detail}")
                _do_rollback(config, manager, old_ids)
                rolled_back += 1
            else:
                detail = ", ".join(f"{local_name}={s or 'unknown'}" for local_name, s in statuses.items()
                                   if s != "healthy")
                print(f"  ⚠ {config.name}: {detail} (no previous image to roll back)")
        else:
            # No health check — verify the service(s) survived. For
            # multi-container the umbrella is a oneshot (always "active"), so
            # check each container sub-service instead.
            units = config.sub_service_names() if config.is_multi else [config.service_name]
            failed = [u for u in units
                      if subprocess.run(["systemctl", "is-active", "--quiet", u]).returncode != 0]
            if not failed:
                print(f"  ✓ {config.name}: active")
            elif have_old:
                print(f"  ✗ {config.name}: service crashed ({', '.join(failed)})")
                _do_rollback(config, manager, old_ids)
                rolled_back += 1
            else:
                print(f"  ⚠ {config.name}: service crashed (no previous image to roll back)")

    return rolled_back


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_update(args, manager: WorkloadManager):
    """Update workload image and restart"""
    require_root()

    if args.all:
        configs = manager.get_all_configs(enabled_only=True)
        if not configs:
            print("No enabled workloads found")
            return

        # Phase 1: Reprovision all workloads
        updated = []  # (config, old_ids) tuples — containers only, for verification
        skipped = 0
        container_failed = 0
        vm_total = 0
        vm_failed = 0
        for config in configs:
            substrate = get_substrate(config, manager)
            is_vm = isinstance(substrate, VMSubstrate)
            if is_vm:
                vm_total += 1
            try:
                result = substrate.reprovision(force=args.force)
                if result is not None:
                    updated.append(result)
            except NotApplicable:
                skipped += 1
            except ProvisionFailed:
                if is_vm:
                    vm_failed += 1
                else:
                    container_failed += 1
            print()

        # Phase 2: Verify + rollback containers only
        rolled_back = 0
        if updated:
            rolled_back = _verify_all(updated, manager)

        done = f"Done: {len(updated) - rolled_back} updated, {rolled_back} rolled back, {skipped} skipped (pull=never)"
        if container_failed:
            done += f", {container_failed} failed"
        print(done)
        if vm_total:
            # "updated" rather than "rebuilt": a pet VM is restarted in place
            # (system.qcow2 is never rotated), so "rebuilt" would misdescribe it.
            print(f"VMs: {vm_total - vm_failed} updated, {vm_failed} failed")
        # A failed update (VM rebuild, or a container pull/restart) must not be
        # silently reported as success — exit nonzero for scripted callers. VMs
        # additionally have no auto-rollback safety net.
        if vm_failed or container_failed:
            sys.exit(1)
    else:
        if not args.workload:
            print("Error: Workload name required (or use --all)", file=sys.stderr)
            sys.exit(1)
        config = WorkloadConfig(args.workload)
        substrate = get_substrate(config, manager)
        try:
            result = substrate.reprovision(force=args.force)
        except NotApplicable as e:
            print(f"Error: {e.reason}", file=sys.stderr)
            sys.exit(1)
        except ProvisionFailed:
            sys.exit(1)
        if result is not None:
            _verify_all([result], manager)


def cmd_rollback(args, manager: WorkloadManager):
    """Roll back to the previous image (or list available rollback targets)"""
    require_root()
    config = WorkloadConfig(args.workload)

    if not manager.user_exists(config):
        print(f"Error: user {config.username} does not exist (workload not enabled?)", file=sys.stderr)
        sys.exit(1)

    substrate = get_substrate(config, manager)

    if getattr(args, "list", False):
        targets = substrate.rollback_targets()
        if not targets:
            print(f"No rollback targets available for '{config.name}'.")
            return
        print(f"Rollback targets for '{config.name}':")
        for t in targets:
            print(f"  {t['label']}")
        return

    substrate.rollback()
