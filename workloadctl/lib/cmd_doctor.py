"""
cmd_doctor — one-shot aggregate diagnosis for a workload.

Collapses the manual failure-diagnosis loop (generator journal → unit states
→ setup checks → drift → health) into a single skimmable report. Read-only:
doctor never mutates state. Leaf module: it imports collectors and substrate
primitives only, never other cmd_* entry points, which keeps it out of the
cmd_lifecycle → cmd_admin import cycle.
"""

import json
import subprocess
import sys

from cmd_admin import collect_diagnose_checks
from cmd_drift import collect_drift
from substrate import get_substrate
from workload_lib import units_outdated, workload_config_path, workload_run_files
from workloadctl_core import WorkloadConfig, WorkloadMasked, require_root

JOURNAL_TAIL_LINES = 15
GENERATOR_LINES_CAP = 20

# Report order mirrors the generator's prereq chain: setup → build →
# virtiofs → net/pod → per-container → main.
_ROLE_ORDER = {
    "setup": 0, "build": 1, "virtiofs": 2, "net": 3, "pod": 3,
    "container": 4, "main": 5,
}


def _generator_lines(name: str) -> list[str]:
    """This boot's generate-step journal lines that mention <name> or look
    like errors, capped at GENERATOR_LINES_CAP.

    Greps MESSAGE, not SYSLOG_IDENTIFIER: the generator's early lines carry
    the tag ``workload-generate[EARLY]``, which journald won't parse as
    ``ident[pid]``. Kernel transport (-k, the /dev/kmsg lines) and the
    oneshot's own unit are both consulted.
    """
    lines: list[str] = []
    for cmd in (
        ["journalctl", "-b", "-k", "-g", "workload-generate",
         "-o", "cat", "--no-pager"],
        ["journalctl", "-b", "-u", "workload-generate.service",
         "-o", "cat", "--no-pager"],
    ):
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            lines.extend(result.stdout.splitlines())

    seen = set()
    kept = []
    for line in lines:
        if not line.strip() or line.startswith("--") or line in seen:
            continue
        if name in line or "error" in line.lower():
            seen.add(line)
            kept.append(line)
    return kept[-GENERATOR_LINES_CAP:]


def _journal_tail(unit: str, n: int = JOURNAL_TAIL_LINES) -> list[str]:
    result = subprocess.run(
        ["journalctl", "-u", unit, "-n", str(n), "-o", "cat", "--no-pager"],
        capture_output=True, text=True,
    )
    return result.stdout.splitlines() if result.returncode == 0 else []


def _unit_rows(config) -> list[dict]:
    """One row per emitted unit: systemd state props + a problem verdict.

    Unit names come from workload_run_files() — never a hand-written
    ``workload-<name>`` enumeration. An absent unit file counts as a problem
    only when the workload is enabled; absent-and-disabled is a finding
    ("not enabled"), not an error — doctor exists for the won't-come-up case.
    A journal tail is attached only to problem rows (skimmability rule).
    """
    unit_files = [
        f for f in workload_run_files(config)
        if f.kind == "unit" and f.emitted
    ]
    unit_files.sort(key=lambda f: _ROLE_ORDER.get(f.role, 9))

    rows = []
    for f in unit_files:
        unit = f.path.name
        row = {"unit": unit, "role": f.role, "present": f.path.exists()}
        if not row["present"]:
            row.update(active_state="absent", sub_state="", result="",
                       n_restarts=0, problem=config.enabled)
            rows.append(row)
            continue

        result = subprocess.run(
            ["systemctl", "show", unit,
             "-p", "ActiveState,SubState,Result,ExecMainStatus,NRestarts"],
            capture_output=True, text=True,
        )
        props = dict(
            line.split("=", 1)
            for line in result.stdout.splitlines() if "=" in line
        )
        active = props.get("ActiveState", "unknown")
        unit_result = props.get("Result", "")
        try:
            n_restarts = int(props.get("NRestarts") or 0)
        except ValueError:
            n_restarts = 0

        # NRestarts > 0 catches the silent-restart-loop class (pasta
        # stale-pause) that is-active alone hides; "activating" is a unit
        # stuck mid-start or flapping.
        problem = (
            active in ("failed", "activating")
            or n_restarts > 0
            or unit_result not in ("", "success")
        )
        row.update(active_state=active, sub_state=props.get("SubState", ""),
                   result=unit_result, n_restarts=n_restarts, problem=problem)
        if problem:
            row["journal_tail"] = _journal_tail(unit)
        rows.append(row)
    return rows


def cmd_doctor(args, manager):
    """Aggregate report: generator journal + unit states + setup checks +
    drift + health for one workload. Read-only. Exit 0 healthy, 1 problems
    found; unknown-workload/bad-args surface through the CLI's usual
    exception→exit-code ladder (matching health/diagnose)."""
    require_root()
    try:
        config = WorkloadConfig(args.workload)
    except WorkloadMasked as e:
        # Masked is a deliberate operator state, not a fault.
        print(f"Workload masked: {e}")
        sys.exit(0)
    name = config.name

    gen_lines = _generator_lines(name)
    unit_rows = _unit_rows(config)
    stale = units_outdated(name)
    checks, checks_ok = collect_diagnose_checks(config, manager)

    drift_error = None
    drifted: list[str] = []
    try:
        drifted = [fname for fname, _, _ in collect_drift(name)]
    except RuntimeError as e:
        drift_error = str(e)

    liveness = get_substrate(config, manager).liveness()

    gen_errors = [line for line in gen_lines if "error" in line.lower()]
    unit_problems = [r for r in unit_rows if r["problem"]]
    failing_checks = [c for c in checks if not c["passed"]]
    problems = (
        len(gen_errors)
        + len(unit_problems)
        + len(failing_checks)
        + (1 if (drifted or drift_error) else 0)
        + (0 if liveness["healthy"] else 1)
        + (1 if stale else 0)
    )
    healthy = problems == 0

    if getattr(args, "json", False):
        print(json.dumps({
            "workload": name,
            "kind": config.kind,
            "mode": config.mode,
            "lifecycle": config.lifecycle,
            "enabled": config.enabled,
            "config_stale": stale,
            "generator": gen_lines,
            "units": unit_rows,
            "checks": checks,
            "drift": {"error": drift_error, "drifted_units": drifted},
            "health": liveness,
            "overall": {"healthy": healthy, "problems": problems},
        }, indent=2))
        sys.exit(0 if healthy else 1)

    print(f"Workload: {name}  ({config.kind}, {config.mode}, "
          f"{config.lifecycle}, "
          f"{'enabled' if config.enabled else 'disabled'})")
    stale_note = "  [stale — edited since last enable]" if stale else ""
    print(f"Config:   {workload_config_path(name)}{stale_note}")
    print()

    print("Generator (this boot)")
    if gen_errors:
        for line in gen_lines:
            print(f"  ✗ {line}" if "error" in line.lower() else f"    {line}")
    elif gen_lines:
        print(f"  ✓ {len(gen_lines)} lines, no errors")
    else:
        print("  ✓ no messages for this workload")

    print("Units")
    for row in unit_rows:
        symbol = "✗" if row["problem"] else "✓"
        if not row["present"]:
            note = "absent" if config.enabled else "absent (not enabled)"
            print(f"  {symbol} {row['unit']:<44} {note}")
            continue
        detail = f"{row['active_state']} ({row['sub_state']})"
        if row["result"]:
            detail += f"  Result={row['result']}"
        if row["n_restarts"]:
            detail += f"  NRestarts={row['n_restarts']}"
        print(f"  {symbol} {row['unit']:<44} {detail}")
        for line in row.get("journal_tail", []):
            print(f"      │ {line}")

    print("Setup checks")
    if checks_ok:
        print(f"  ✓ {len(checks)} checks passed")
    else:
        for c in failing_checks:
            print(f"  ✗ {c['message']}")
            if "fix" in c:
                print(f"    Fix: {c['fix']}")
        print(f"  ({len(checks) - len(failing_checks)}/{len(checks)} passed)")

    print("Drift")
    if drift_error:
        print(f"  ✗ drift check failed: {drift_error.splitlines()[0]}")
    elif drifted:
        print(f"  ✗ {len(drifted)} file(s) drifted: {', '.join(drifted)}"
              f" — run `workloadctl drift {name}`")
    else:
        print("  ✓ running units match generated output")

    print("Health")
    if liveness["healthy"]:
        print(f"  ✓ healthy ({liveness['service_state']})")
    else:
        detail = liveness["service_state"]
        if liveness.get("container_running") is False:
            detail += ", container not running"
        print(f"  ✗ UNHEALTHY: {detail}")

    print()
    if healthy:
        print("Overall: HEALTHY")
        sys.exit(0)
    print(f"Overall: UNHEALTHY ({problems} "
          f"problem{'s' if problems != 1 else ''})")
    sys.exit(1)
