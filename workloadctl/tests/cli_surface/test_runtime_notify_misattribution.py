"""
test_runtime_notify_misattribution.py — C1 GAP check: Type=notify stays broken by
design under the rootless+linger architecture, proven on a real kernel.

This is a settled *negative* invariant. `--sdnotify=conmon` (and `=healthy`) emit
READY=1 from a process that lives in `user@<uid>.service`'s cgroup, never
`workload-<name>.service`'s; systemd credits the sender's cgroup owner, so the
workload unit never receives READY and never goes active. No `NotifyAccess` tweak
fixes it (the generator sets `NotifyAccess=all` and it still fails). Type=exec is
the supported default; this test guards against a future change silently
"re-enabling" notify — if it ever started working, this test would flip red and
force the design question back open.

Drives a `service_type = "notify"` workload (rt-notify) with a short
`timeout_start_sec` so the doomed start attempt is bounded, and asserts the unit
**never reaches active** while confirming it is genuinely a Type=notify unit that
systemd did try to start.

Marked `runtime`: only runs under `--target=vm:<mode>` (i.e. `just test-runtime`).
"""

import time

import pytest

from fixtures import _install_toml, _purge_workload

pytestmark = pytest.mark.runtime

WORKLOAD = "rt-notify"
SERVICE = "workload-rt-notify.service"

# States that show systemd actually attempted the start (as opposed to never
# touching the unit) — any of these, but NEVER "active".
ATTEMPTED_STATES = {"activating", "failed", "deactivating", "auto-restart", "reloading"}


def _dump_journal(target, name):
    r = target.run(
        ["journalctl", "--no-pager", "-n", "100", "-u", f"workload-{name}.service"],
        sudo=True, check=False,
    )
    print(f"\n----- journalctl -u workload-{name}.service (tail) -----\n"
          f"{r.stdout}\n{r.stderr}\n--------------------------------------------------------")


def _active_state(target):
    return target.run(
        ["systemctl", "is-active", SERVICE], sudo=False, check=False
    ).stdout.strip()


def test_notify_never_reaches_active(target):
    """A Type=notify workload never goes active — READY=1 is misattributed to the
    user manager, exactly as designed."""
    _install_toml(target, "rt-notify.toml")
    try:
        # Enable WITHOUT the readiness wait: this start is expected to fail. With
        # Type=notify, `systemctl start` blocks until TimeoutStartSec (20s) and
        # then fails, so give the CLI room to return before we inspect.
        target.wl(f"enable {WORKLOAD}", check=False, timeout=90)

        # Confirm we actually built a Type=notify unit (else the invariant is
        # untested — a regression to exec would sail past a "never active" check).
        unit_type = target.run(
            ["systemctl", "show", SERVICE, "-p", "Type", "--value"],
            sudo=True, check=False,
        ).stdout.strip()
        assert unit_type == "notify", (
            f"{SERVICE} is Type={unit_type!r}, expected notify — the notify path "
            f"was not exercised"
        )

        # Observe for a window: the unit must never report active, and must show
        # at least one start-attempt state (proving systemd tried, and this isn't
        # a silently-unstarted false pass).
        seen = []
        attempted = False
        for _ in range(9):  # ~18s of polling on top of the enable's own attempt
            state = _active_state(target)
            seen.append(state)
            if state in ATTEMPTED_STATES:
                attempted = True
            assert state != "active", (
                f"{SERVICE} reached ACTIVE with Type=notify — the notify "
                f"misattribution invariant has changed (states seen: {seen})"
            )
            time.sleep(2)

        print(f"\n----- {SERVICE} is-active states over window -----\n{seen}\n"
              f"-------------------------------------------------")
        if not attempted:
            _dump_journal(target, WORKLOAD)
        assert attempted, (
            f"{SERVICE} never entered a start-attempt state {ATTEMPTED_STATES} "
            f"(states seen: {seen}) — enable did not start the unit, so the "
            f"invariant was not actually exercised"
        )
    finally:
        _purge_workload(target, WORKLOAD)
