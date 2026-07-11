"""
test_runtime_pod_reenable.py — a multi-container pod workload comes up healthy,
including a same-boot re-enable after a plain (non-purge) disable.

Regression for the pod-cgroup collision: rootless podman under the systemd
cgroup manager makes *every* container start (the infra container included)
unconditionally create the pod's shared `libpod_pod_<id>.slice` transient unit.
systemd lets only the first caller win; every later member dies with exit 126
("slice already loaded or has a fragment file"), so a pod never gets more than
one container up. The generator's `--share-parent=false` gives each container
its own cgroup under the user manager, sidestepping the shared-slice race.

The failure is timing-sensitive (which member loses the race varies) and only
reproduces on a real kernel with a real per-user systemd manager, so it lives in
the runtime rung. The enable/disable/re-enable cycle also covers the teardown
path: a plain disable keeps the user + config, so nothing masks a residual.

Marked `runtime`: only runs under `--target=vm:<mode>` (i.e. `just test-runtime`).
"""

import pytest

from fixtures import _enable_workload, _install_toml, _purge_workload

pytestmark = pytest.mark.runtime

WORKLOAD = "rt-pod"


def _dump_journal(target, name):
    """Print the umbrella + pod + member unit journals — the diagnosis on failure."""
    for unit in (
        f"workload-{name}.service",
        f"workload-{name}-pod.service",
        f"workload-{name}-app.service",
        f"workload-{name}-proxy.service",
    ):
        r = target.run(
            ["journalctl", "--no-pager", "-n", "30", "-u", unit],
            sudo=True, check=False,
        )
        print(f"\n----- journalctl -u {unit} (tail) -----\n{r.stdout}\n{r.stderr}")


def test_pod_same_boot_reenable(target):
    """A two-container pod comes up healthy (both members running), survives a
    plain disable, and comes back healthy on a same-boot re-enable — no member
    lost to a shared-pod-cgroup collision."""
    _install_toml(target, "rt-pod.toml")
    try:
        # First enable: both members must come up (this alone catches the
        # collision — pre-fix, one member wins and the other exits 126).
        try:
            _enable_workload(target, WORKLOAD, timeout=180)
        except Exception:
            _dump_journal(target, WORKLOAD)
            raise

        # Plain disable — keeps the user + config, so any residual pod/cgroup
        # state (which a reboot would otherwise wipe) is left in place.
        target.wl(f"disable {WORKLOAD}", sudo=True, check=True, timeout=120)

        # Re-enable in the SAME boot. retries=0 is essential: _enable_workload's
        # default retry does `disable --purge`, which deletes the user (and any
        # residual state) before retrying — masking a same-boot teardown gap.
        try:
            _enable_workload(target, WORKLOAD, timeout=180, retries=0)
        except Exception:
            _dump_journal(target, WORKLOAD)
            raise
    finally:
        _purge_workload(target, WORKLOAD)
