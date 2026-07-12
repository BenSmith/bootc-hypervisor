"""
test_runtime_smoke.py — the runtime rung's canary.

Proves the harness can boot a VM (dev or gate), that the workloadctl RPM is
present and runnable, and that the target answers basic CLI verbs. Everything
downstream (health, cgroup, pasta, secret) depends on this coming up green.

Marked `runtime`: only runs under `--target=vm:<mode>` (i.e. `just test-runtime`).
"""

import pytest

pytestmark = pytest.mark.runtime


def test_rpm_installed(target):
    assert target.capabilities["has_workloadctl"], (
        "workloadctl not on PATH in the guest — deploy/rpm-install did not land"
    )


def test_list_works(target):
    r = target.wl("list", check=False)
    assert r.rc == 0, f"`workloadctl list` failed (rc={r.rc}):\n{r.stderr}"


def test_version(target):
    # --version is a recent addition (review item E3); only assert its output
    # when the flag is recognized so the smoke test works against older builds.
    r = target.run(["workloadctl", "--version"], sudo=False, check=False)
    if r.rc == 0:
        assert r.stdout.strip(), "`workloadctl --version` produced no output"
