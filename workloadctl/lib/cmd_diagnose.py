"""
cmd_diagnose — explain why a workload isn't healthy.

The command: root check, config load, one run of the battery in
lib/diagnose_battery.py, and the rendering — a symbol per check, the fixes for
what failed, and the exit status. `doctor` runs the same battery.
"""
import json
import sys

from cmd_validate import load_config_or_exit
from diagnose_battery import collect_diagnose_checks
from workloadctl_core import WorkloadManager, require_root


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
        # "healthy" alone would read as "running" on a workload that is off —
        # the same confusion the folded check exists to remove.
        state = "" if config.enabled else " (disabled — nothing is running)"
        print(f"✓ All checks passed - workload is healthy{state}")
        sys.exit(0)
