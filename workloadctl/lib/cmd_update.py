"""
cmd_update — update and rollback commands.
"""

import subprocess
import sys
import time

from podman import PodmanError
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    ensure_runtime_dir,
    require_root,
    restart_workload_service,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def rollback_tag(name: str, container: str | None = None) -> str:
    """Return the rollback image tag for a workload (or one of its containers)."""
    suffix = f"-{container}" if container else ""
    return f"localhost/workload-rollback/{name}{suffix}:latest"


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


def _pull_and_restart(config: WorkloadConfig, manager: WorkloadManager, force: bool):
    """Pull image(s) and restart if any changed. Returns (config, old_ids) or None.

    old_ids maps each container name to its previous image id (for rollback).
    """
    specs = config.container_specs()

    if all(pull == "never" for _, _, pull in specs):
        print(f"Error: {config.name} uses pull=never (local image). Build it manually.", file=sys.stderr)
        return None

    print(f"Updating {config.name}...")

    if not manager.user_exists(config):
        print(f"  Skipping: user {config.username} does not exist (workload not enabled?)")
        return None

    pod = manager.podman(config)
    old_ids: dict[str, str] = {}
    changed = False

    for cname, image, pull in specs:
        old_id = pod.image_id(image)
        if not old_id:
            # A just-(re)started rootless store can transiently report an empty
            # `inspect` (mid `podman system migrate`, or while a recycled UID's
            # runtime dir is being re-pinned) even though the image is present
            # — losing the rollback point. Re-pin and retry briefly before
            # giving up; a genuinely-absent image just falls through with "".
            ensure_runtime_dir(config.uid)
            for _ in range(10):
                time.sleep(0.5)
                old_id = pod.image_id(image)
                if old_id:
                    break
        old_ids[cname] = old_id
        if pull == "never":
            continue
        try:
            pod.pull(image)
        except PodmanError as e:
            print(f"  ✗ Failed to pull {image}: {e.stderr}", file=sys.stderr)
            return None
        new_id = pod.image_id(image)
        if old_id != new_id:
            changed = True
            label = f"{config.name}/{cname}" if config.is_multi else config.name
            print(f"  {label}: {(old_id or 'none')[:12]} → {(new_id or 'unknown')[:12]}")

    if not changed and not force:
        print(f"  ✓ Already up to date")
        return None

    # Tag old images for rollback before restarting
    for cname, image, pull in specs:
        old_id = old_ids.get(cname)
        if old_id:
            pod.tag(old_id, rollback_tag(config.name, cname if config.is_multi else None))

    restart_workload_service(config.uid, config.service_name)
    print(f"  ✓ {config.name}: restarted")

    return (config, old_ids)


def _vm_rebuild_and_restart(config: WorkloadConfig):
    """Rebuild a VM's system disk (--update) and restart its service.

    Returns True on success, False if the disk rebuild or the restart failed.
    Never raises, so a single VM failure doesn't abort an `update --all` run.
    """
    print(f"Updating VM workload {config.name}...")
    result = subprocess.run(
        ["/usr/libexec/workloadctl/workload-vm-build-disk", config.name, "--update"],
        check=False,
    )
    if result.returncode != 0:
        print(f"  ✗ Disk rebuild failed for {config.name}", file=sys.stderr)
        return False
    restart = subprocess.run(["systemctl", "restart", config.service_name], check=False)
    if restart.returncode != 0:
        print(f"  ✗ Restart failed for {config.name}", file=sys.stderr)
        return False
    print(f"  ✓ {config.name}: rebuilt and restarted")
    return True


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
                    detail = ", ".join(f"{l}={s or 'unknown'}" for l, s in statuses.items()
                                       if s != "healthy")
                    print(f" {detail}")
                    _do_rollback(config, manager, old_ids)
                    rolled_back += 1
            elif have_old:
                detail = ", ".join(f"{l}={s or 'unknown'}" for l, s in statuses.items()
                                   if s != "healthy")
                print(f"  ✗ {config.name}: {detail}")
                _do_rollback(config, manager, old_ids)
                rolled_back += 1
            else:
                detail = ", ".join(f"{l}={s or 'unknown'}" for l, s in statuses.items()
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

        # Phase 1: Pull/rebuild and restart all
        updated = []  # (config, old_id) tuples
        skipped = 0
        vm_total = 0
        vm_failed = 0
        for config in configs:
            if config.is_vm:
                vm_total += 1
                if not _vm_rebuild_and_restart(config):
                    vm_failed += 1
                print()
                continue
            if all(pull == "never" for _, _, pull in config.container_specs()):
                skipped += 1
                continue
            result = _pull_and_restart(config, manager, args.force)
            if result:
                updated.append(result)
            print()

        # Phase 2: One wait, verify all (containers only)
        rolled_back = 0
        if updated:
            rolled_back = _verify_all(updated, manager)

        print(f"Done: {len(updated) - rolled_back} updated, {rolled_back} rolled back, {skipped} skipped (pull=never)")
        if vm_total:
            print(f"VMs: {vm_total - vm_failed} rebuilt, {vm_failed} failed")
        # VMs have no auto-rollback safety net, so a failed VM update must not
        # be silently reported as success — exit nonzero for scripted callers.
        if vm_failed:
            sys.exit(1)
    else:
        if not args.workload:
            print("Error: Workload name required (or use --all)", file=sys.stderr)
            sys.exit(1)
        config = WorkloadConfig(args.workload)
        if config.is_vm:
            if not _vm_rebuild_and_restart(config):
                sys.exit(1)
            return
        if all(pull == "never" for _, _, pull in config.container_specs()):
            print(f"Error: {config.name} uses pull=never (local image). Build it manually.", file=sys.stderr)
            sys.exit(1)
        result = _pull_and_restart(config, manager, args.force)
        if result:
            _verify_all([result], manager)


def cmd_rollback(args, manager: WorkloadManager):
    """Roll back to the previous image"""
    require_root()
    config = WorkloadConfig(args.workload)

    if not manager.user_exists(config):
        print(f"Error: user {config.username} does not exist (workload not enabled?)", file=sys.stderr)
        sys.exit(1)

    if config.is_vm:
        home_dir = config.home_dir
        system_disk = home_dir / "system.qcow2"
        gens = sorted(
            int(p.suffix[5:])
            for p in home_dir.glob("system.qcow2.gen-*")
            if p.suffix[5:].isdigit()
        )
        if not gens:
            print(f"Error: No rollback generation found for VM '{config.name}'", file=sys.stderr)
            print(f"  (generations are created automatically by 'workloadctl update')", file=sys.stderr)
            sys.exit(1)
        latest_gen = max(gens)
        gen_path = home_dir / f"system.qcow2.gen-{latest_gen}"
        print(f"Rolling back VM '{config.name}':")
        print(f"  system.qcow2.gen-{latest_gen} → system.qcow2")
        # Stop the VM before swapping disks: QEMU holds the active qcow2
        # open, and renaming a file out from under it leaves the running
        # guest writing to an unlinked inode while the new disk is mounted
        # by the next start. Path.replace is atomic so the rename either
        # succeeds entirely or leaves system_disk gone (and we surface that).
        subprocess.run(["systemctl", "stop", config.service_name], check=False)
        gen_path.replace(system_disk)
        subprocess.run(["systemctl", "start", config.service_name], check=True)
        print(f"✓ Rolled back {config.name} to generation {latest_gen}")
        return

    pod = manager.podman(config)

    # Build the rollback plan: one entry per container that has a rollback
    # image differing from what it currently runs.
    plan = []          # (label, image, tag, current_id, rollback_id)
    have_any_tag = False
    for cname, image in config.container_images():
        tag = rollback_tag(config.name, cname if config.is_multi else None)
        rollback_id = pod.image_id(tag)
        if not rollback_id:
            continue
        have_any_tag = True
        current_id = pod.image_id(image)
        if current_id == rollback_id:
            continue
        label = f"{config.name}/{cname}" if config.is_multi else config.name
        plan.append((label, image, tag, current_id, rollback_id))

    if not have_any_tag:
        print(f"Error: No rollback image found for {config.name}", file=sys.stderr)
        print(f"  (rollback images are created automatically by 'workloadctl update')", file=sys.stderr)
        sys.exit(1)

    if not plan:
        print(f"Already running the rollback image(s) for {config.name}")
        return

    # Retag each rollback image as the container's working image
    for label, image, tag, current_id, rollback_id in plan:
        try:
            pod.tag(tag, image)
        except PodmanError as e:
            print(f"Error: Failed to retag rollback image for {label}: {e.stderr}", file=sys.stderr)
            sys.exit(1)
        print(f"  {label}: {current_id[:12] if current_id else 'unknown'} → {rollback_id[:12]}")

    restart_workload_service(config.uid, config.service_name)
    print(f"✓ Rolled back {config.name}")
