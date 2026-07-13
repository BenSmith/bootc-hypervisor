"""
cmd_stats — resource usage, for one workload or the whole enabled fleet.
The numbers come from the substrate (podman stats for containers, QMP for
VMs); this module only picks the targets and renders.
"""

import json
import sys

from substrate import NotApplicable, get_substrate
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
)


# ---------------------------------------------------------------------------
# cmd_stats
# ---------------------------------------------------------------------------

def cmd_stats(args, manager: WorkloadManager):
    """Show resource usage statistics"""
    if args.json and args.follow:
        print("Error: --json is incompatible with --follow", file=sys.stderr)
        sys.exit(1)

    if args.workload:
        config = WorkloadConfig(args.workload)
        substrate = get_substrate(config, manager)

        if not manager.user_exists(config):
            print("Error: Workload user not found. Is workload enabled?", file=sys.stderr)
            sys.exit(1)

        target_names = config.podman_targets()

        try:
            rows = substrate.resource_usage(
                target_names, json_out=args.json, follow=args.follow,
            )
        except NotApplicable as e:
            print(f"stats: not applicable for {config.name} — {e.reason}")
            sys.exit(0)

        if args.json:
            print(json.dumps({"stats": rows or []}, indent=2))
    else:
        configs = manager.get_all_configs(enabled_only=True)

        def _targets(c):
            """The stats targets for one workload, or None to skip it.

            A VM has no podman targets — its substrate sources the row from QMP
            and ignores the list — so an enabled VM is included with an empty
            one. A container is only worth asking about if it actually exists.
            """
            if not manager.user_exists(c):
                return None
            if c.is_vm:
                return []
            names = [n for n in c.podman_targets() if manager.podman(c).container_exists(n)]
            return names or None

        running = [(c, t) for c in configs for t in [_targets(c)] if t is not None]

        if args.json:
            stats_list = []
            for config, target_names in running:
                substrate = get_substrate(config, manager)
                try:
                    rows = substrate.resource_usage(target_names, json_out=True)
                except NotApplicable:
                    continue
                stats_list.extend(rows or [])
            print(json.dumps({"stats": stats_list}, indent=2))
            return

        if not running:
            print("No running workloads found")
            return

        for config, target_names in running:
            substrate = get_substrate(config, manager)
            try:
                if args.follow:
                    print(f"Note: --follow with multiple workloads shows only {config.name}")
                    substrate.resource_usage(target_names, follow=True)
                    return
                substrate.resource_usage(target_names)
            except NotApplicable:
                continue
            print()
