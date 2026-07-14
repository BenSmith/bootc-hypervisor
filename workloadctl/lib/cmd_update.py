"""
cmd_update — update and rollback commands.
"""

import subprocess
import sys
import time

from cli_log import emit_result, error, info, json_enabled, partial, warn
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    require_root,
)
from service_runtime import restart_workload_service
from substrate import (
    get_substrate,
    ProvisionFailed,
    NotApplicable,
    rollback_tag,
)
from substrate_vm import VMSubstrate


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


def _do_rollback(config: WorkloadConfig, manager: WorkloadManager):
    """Roll back every container to its previous image and restart."""
    pod = manager.podman(config)
    for cname, image in config.container_images():
        tag = rollback_tag(config.name, cname if config.is_multi else None)
        if pod.image_id(tag):
            pod.tag(tag, image)
    restart_workload_service(config.uid, config.service_name)
    info(f"  ✗ {config.name}: rolled back to previous image(s)")



def _verify_all(updated: list, manager: WorkloadManager,
                results: dict | None = None) -> int:
    """Verify all updated workloads after restart. Returns number of rollbacks.

    When `results` is given, each workload's verdict is recorded into it as
    `{name: {"verify": <health|active|…>, "rolled_back": bool}}` — the detail
    the --json result object reports per workload, which the rollback count
    alone can't carry.
    """
    def verdict(config, state: str, rolled_back: bool = False) -> None:
        if results is not None:
            results[config.name] = {"verify": state, "rolled_back": rolled_back}

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
    info(f"Verifying updates ({'; '.join(parts)})...")
    partial(f"  Waiting {max_wait}s...")
    time.sleep(max_wait)
    info(" checking")

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
                info(f"  ✓ {config.name}: healthy")
                verdict(config, "healthy")
            elif any(s == "starting" for s in statuses.values()) and have_old:
                # One container is still starting — give it the longest
                # remaining interval before declaring failure.
                interval = max(
                    _parse_duration(h.get("interval", "30s"))
                    for local, _pname, h in hc_blocks
                    if statuses[local] == "starting"
                )
                still = ", ".join(local for local, s in statuses.items() if s == "starting")
                partial(f"  ⏳ {config.name}: still starting ({still}), "
                        f"waiting {interval}s more...")
                time.sleep(interval)
                statuses = {local: pod.container_health(pname) or ""
                            for local, pname, _h in hc_blocks}
                if all(s == "healthy" for s in statuses.values()):
                    info(" healthy")
                    verdict(config, "healthy")
                else:
                    detail = ", ".join(f"{local_name}={s or 'unknown'}" for local_name, s in statuses.items()
                                       if s != "healthy")
                    info(f" {detail}")
                    _do_rollback(config, manager)
                    verdict(config, "unhealthy", rolled_back=True)
                    rolled_back += 1
            elif have_old:
                detail = ", ".join(f"{local_name}={s or 'unknown'}" for local_name, s in statuses.items()
                                   if s != "healthy")
                info(f"  ✗ {config.name}: {detail}")
                _do_rollback(config, manager)
                verdict(config, "unhealthy", rolled_back=True)
                rolled_back += 1
            else:
                detail = ", ".join(f"{local_name}={s or 'unknown'}" for local_name, s in statuses.items()
                                   if s != "healthy")
                warn(f"  ⚠ {config.name}: {detail} (no previous image to roll back)")
                verdict(config, "unhealthy")
        else:
            # No health check — verify the service(s) survived. For
            # multi-container the umbrella is a oneshot (always "active"), so
            # check each container sub-service instead.
            units = config.sub_service_names() if config.is_multi else [config.service_name]
            failed = [u for u in units
                      if subprocess.run(["systemctl", "is-active", "--quiet", u]).returncode != 0]
            if not failed:
                info(f"  ✓ {config.name}: active")
                verdict(config, "active")
            elif have_old:
                info(f"  ✗ {config.name}: service crashed ({', '.join(failed)})")
                _do_rollback(config, manager)
                verdict(config, "crashed", rolled_back=True)
                rolled_back += 1
            else:
                warn(f"  ⚠ {config.name}: service crashed (no previous image to roll back)")
                verdict(config, "crashed")

    return rolled_back


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _update_plan(config: WorkloadConfig, manager: WorkloadManager) -> list[str]:
    """The work `update` would do for one workload, as printable lines.

    Reports the plan, not its outcome: whether a pull actually produces a new
    image is only knowable by doing it, so this names the images it would pull
    and the image ID each would roll back to, and stops short of predicting the
    result. Read-only — no pull, no restart.
    """
    lines = []

    if config.is_vm:
        if config.lifecycle == "pet":
            lines.append("rebuild the system disk in place (pet: no generation rotation)")
        else:
            lines.append("rebuild the system disk as a new generation (previous kept for rollback)")
        lines.append(f"restart {config.service_name} (VM power-cycle; no auto-rollback on failure)")
        return lines

    specs = config.container_specs()
    pullable = [(c, image, pull) for c, image, pull in specs if pull != "never"]
    if not pullable:
        lines.append("nothing to pull (every image is pull=never) — update would skip this workload")
        return lines

    user_present = manager.user_exists(config)
    pod = manager.podman(config) if user_present else None
    for cname, image, pull in specs:
        if pull == "never":
            lines.append(f"skip {image} (pull=never, built locally)")
            continue
        current = pod.image_id(image) if pod else None
        current_str = f"current {current[:19]}" if current else "not present locally"
        lines.append(f"pull {image} (pull={pull}, {current_str})")

    if config.lifecycle == "pet":
        lines.append(f"snapshot the container overlay before recreating "
                     f"(pet, keeping {config.snapshot_keep})")
    lines.append(f"restart {config.service_name} if any image changed")
    if user_present:
        lines.append("verify health after restart, and roll back to the current image on failure")
    return lines


def _image_transitions(config: WorkloadConfig, old_ids: dict,
                       manager: WorkloadManager) -> dict:
    """Per-container old→new image IDs, for the --json result row."""
    pod = manager.podman(config)
    return {
        cname: {
            "image": image,
            "old": old_ids.get(cname),
            "new": pod.image_id(image),
        }
        for cname, image in config.container_images()
    }


def _reprovision_one(config: WorkloadConfig, manager: WorkloadManager, *,
                     force: bool) -> tuple[dict, tuple | None]:
    """Update one workload. Returns its --json result row plus the
    (config, old_ids) tuple the verification phase consumes — None when there
    is nothing to verify (a VM, a no-op update, a skip, a failure).

    A failure becomes a row rather than an escaping exception: `update --all`
    has to keep going and tally it, and the single-workload path wants the same
    row to report before it exits nonzero.
    """
    substrate = get_substrate(config, manager)
    is_vm = isinstance(substrate, VMSubstrate)
    row = {
        "workload": config.name,
        "kind": "vm" if is_vm else "container",
        "result": "unchanged",
    }
    try:
        result = substrate.reprovision(force=force)
    except NotApplicable as e:
        row["result"] = "skipped"
        row["reason"] = e.reason
        return row, None
    except ProvisionFailed as e:
        row["result"] = "failed"
        row["reason"] = str(e)
        return row, None

    if is_vm:
        # VMs have no verification phase: reprovision either rebuilt and
        # restarted the VM, or raised.
        row["result"] = "updated"
        return row, None
    if result is None:
        return row, None

    row["result"] = "updated"
    if json_enabled():
        row["images"] = _image_transitions(config, result[1], manager)
    return row, result


def _apply_verdicts(rows: list[dict], verified: dict) -> None:
    """Fold the verification phase's verdict into the result rows: a workload
    that failed its post-restart check and was put back on its previous image
    is 'rolled-back', not 'updated'."""
    for row in rows:
        v = verified.get(row["workload"])
        if not v:
            continue
        row["verify"] = v["verify"]
        if v["rolled_back"]:
            row["result"] = "rolled-back"


def _tally(rows: list[dict]) -> dict:
    """Count rows by result — the JSON summary, and the source of the prose
    counts, so the two can't disagree."""
    return {
        outcome: sum(1 for r in rows if r["result"] == outcome)
        for outcome in ("updated", "rolled-back", "skipped", "failed", "unchanged")
    }


def cmd_update(args, manager: WorkloadManager):
    """Update workload image and restart"""
    require_root()

    if getattr(args, "dry_run", False):
        if args.all:
            configs = manager.get_all_configs(enabled_only=True)
        elif args.workload:
            configs = [WorkloadConfig(args.workload)]
        else:
            error("Error: Workload name required (or use --all)")
            sys.exit(1)

        if not configs:
            if json_enabled():
                emit_result([])
            else:
                print("No enabled workloads found")
            return

        if json_enabled():
            emit_result([
                {"workload": c.name, "result": "dry-run",
                 "plan": _update_plan(c, manager)}
                for c in configs
            ])
            return

        print("Dry run — would update:")
        for config in configs:
            print(f"  {config.name}:")
            for line in _update_plan(config, manager):
                print(f"    {line}")
        print("\nNothing was changed. Re-run without --dry-run to apply.")
        return

    if args.all:
        configs = manager.get_all_configs(enabled_only=True)
        if not configs:
            info("No enabled workloads found")
            emit_result([])
            return

        # Phase 1: reprovision every workload, tallying rather than aborting —
        # one workload's failed pull must not strand the other seven.
        rows = []
        updated = []  # (config, old_ids) — containers only, for verification
        for config in configs:
            row, verify_input = _reprovision_one(config, manager, force=args.force)
            rows.append(row)
            if verify_input is not None:
                updated.append(verify_input)
            info()

        # Phase 2: verify + roll back containers only
        verified: dict = {}
        rolled_back = 0
        if updated:
            rolled_back = _verify_all(updated, manager, verified)
        _apply_verdicts(rows, verified)

        counts = _tally(rows)
        containers = [r for r in rows if r["kind"] == "container"]
        vms = [r for r in rows if r["kind"] == "vm"]
        container_failed = sum(1 for r in containers if r["result"] == "failed")
        vm_failed = sum(1 for r in vms if r["result"] == "failed")
        container_updated = sum(1 for r in containers if r["result"] == "updated")

        done = (f"Done: {container_updated} updated, {rolled_back} rolled back, "
                f"{counts['skipped']} skipped (pull=never)")
        if container_failed:
            done += f", {container_failed} failed"
        info(done)
        if vms:
            # "updated" rather than "rebuilt": a pet VM is restarted in place
            # (system.qcow2 is never rotated), so "rebuilt" would misdescribe it.
            info(f"VMs: {len(vms) - vm_failed} updated, {vm_failed} failed")

        failed = container_failed + vm_failed
        emit_result(rows, ok=not failed, summary=counts)
        # A failed update (VM rebuild, or a container pull/restart) must not be
        # silently reported as success — exit nonzero for scripted callers. VMs
        # additionally have no auto-rollback safety net.
        if failed:
            sys.exit(1)
    else:
        if not args.workload:
            error("Error: Workload name required (or use --all)")
            sys.exit(1)
        config = WorkloadConfig(args.workload)
        row, verify_input = _reprovision_one(config, manager, force=args.force)

        if row["result"] == "skipped":
            error(f"Error: {row['reason']}")
        if row["result"] in ("skipped", "failed"):
            # The ProvisionFailed diagnostic is already on stderr; don't repeat it.
            emit_result([row], ok=False)
            sys.exit(1)

        if verify_input is not None:
            verified: dict = {}
            _verify_all([verify_input], manager, verified)
            _apply_verdicts([row], verified)
        emit_result([row])


def cmd_rollback(args, manager: WorkloadManager):
    """Roll back to the previous image (or list available rollback targets)"""
    require_root()
    config = WorkloadConfig(args.workload)

    if not manager.user_exists(config):
        error(f"Error: user {config.username} does not exist (workload not enabled?)")
        sys.exit(1)

    substrate = get_substrate(config, manager)

    if getattr(args, "list", False):
        targets = substrate.rollback_targets()
        if json_enabled():
            emit_result([{"workload": config.name, "result": "listed",
                          "targets": targets}])
            return
        if not targets:
            print(f"No rollback targets available for '{config.name}'.")
            return
        print(f"Rollback targets for '{config.name}':")
        for t in targets:
            print(f"  {t['label']}")
        return

    substrate.rollback()
    emit_result([{"workload": config.name, "result": "rolled-back"}])
