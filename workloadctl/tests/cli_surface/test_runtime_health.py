"""
test_runtime_health.py — B2 runtime check: a container workload reaches
active + healthy on a real kernel, then purges cleanly.

Proves the whole enable→run→health→purge lifecycle end to end against a booted
VM (the thing unit-file text tests can never show): the `rt-basic` pasta
workload's payload actually starts, podman's healthcheck settles to "healthy",
and `disable --purge` removes both the dedicated user and the /run unit.

Marked `runtime`: only runs under `--target=vm:<mode>` (i.e. `just test-runtime`).
"""

import time

import pytest

from fixtures import _enable_workload, _install_toml, _purge_workload, dump_journal

pytestmark = pytest.mark.runtime

WORKLOAD = "rt-basic"
USER = "_wl-rt-basic"
RUN_UNIT = "/run/systemd/system/workload-rt-basic.service"


def test_health_lifecycle(target):
    """Enable rt-basic, watch it reach active + healthy, then purge and verify
    the user and /run unit are gone."""
    _install_toml(target, "rt-basic.toml")
    try:
        # Enable + wait for active and a running container.
        try:
            _enable_workload(target, WORKLOAD, timeout=180)
        except Exception:
            dump_journal(target, WORKLOAD)
            raise

        # Step 3: unit is active.
        r = target.run(
            ["systemctl", "is-active", f"workload-{WORKLOAD}.service"],
            sudo=False, check=False,
        )
        assert r.stdout.strip() == "active", (
            f"workload-{WORKLOAD}.service is {r.stdout.strip()!r}, expected active"
        )

        # Step 4: `workloadctl health` reaches ok (rc 0). The `true` healthcheck
        # needs one 5s interval to flip from "starting" to "healthy", so poll.
        deadline = time.monotonic() + 60
        h = None
        while time.monotonic() < deadline:
            h = target.wl(f"health {WORKLOAD}", sudo=True, check=False)
            if h.rc == 0:
                break
            time.sleep(3)
        assert h is not None and h.rc == 0, (
            f"`workloadctl health {WORKLOAD}` never reached ok within 60s "
            f"(last rc={None if h is None else h.rc}):\n"
            f"{'' if h is None else h.stdout}"
        )

    finally:
        # Step 5: purge. Do it inside the test (not just teardown) so the
        # post-purge assertions below are the point of the check.
        _purge_workload(target, WORKLOAD)

    # User is gone.
    r = target.run(["id", USER], sudo=False, check=False)
    assert r.rc != 0, f"user {USER} still exists after purge:\n{r.stdout}"

    # /run unit is gone (generator output removed by disable, per purge-completeness).
    r = target.run(["test", "-e", RUN_UNIT], sudo=False, check=False)
    assert r.rc != 0, f"{RUN_UNIT} still present after purge"
