"""
test_runtime_config_drift.py — C1 GAP check: the `config_current` staleness hint
tracks real config edits end-to-end on a live system.

Editing `workload.toml` and running `daemon-reload` does NOT regenerate the
per-workload units — only `enable` re-runs the unit writer. That foot-gun is
guarded by a cheap mtime heuristic (`units_outdated`: config mtime > unit mtime),
surfaced as the `config_current` check in `diagnose` (and the `config_stale` flag
in `status`/`doctor`). This test drives that hint end-to-end against a running
workload: fresh after enable → touch the config → the hint flips and `diagnose`
fails → restore the unit mtime → the hint clears.

Pure CLI + `touch`; no new guest tooling. Non-destructive: touching the config
neither restarts the workload nor regenerates units.

Marked `runtime`: only runs under `--target=vm:<mode>` (i.e. `just test-runtime`).
"""

import json
import time

import pytest

from fixtures import _enable_workload, _install_toml, _purge_workload, dump_journal

pytestmark = pytest.mark.runtime

WORKLOAD = "rt-basic"
CONFIG_PATH = f"/etc/workloads.d/{WORKLOAD}/workload.toml"
UNIT_PATH = f"/run/systemd/system/workload-{WORKLOAD}.service"


def _diagnose(target, name):
    """Run `diagnose --json` and return (config_current_passed, overall_rc).

    config_current_passed is None if the check is absent (e.g. units missing).
    """
    r = target.wl(f"diagnose --json {name}", sudo=True, check=False)
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        print(f"non-JSON diagnose output (rc={r.rc}):\n{r.stdout}\n{r.stderr}")
        return None, r.rc
    current = None
    for c in data.get("checks", []):
        if c.get("check") == "config_current":
            current = c.get("passed")
    return current, r.rc


def test_config_stale_hint_tracks_edits(target):
    """`config_current` is true after enable, flips false when the config is
    edited (and `diagnose` then fails), and clears when the unit mtime is
    restored ahead of the config again."""
    _install_toml(target, "rt-basic.toml")
    try:
        try:
            _enable_workload(target, WORKLOAD, timeout=180)
        except Exception:
            dump_journal(target, WORKLOAD)
            raise

        # 1) Fresh after enable: units match the config.
        current, _ = _diagnose(target, WORKLOAD)
        assert current is True, (
            f"config_current should be true right after enable, got {current!r}"
        )

        # 2) Edit the config (bump its mtime past the generated unit). Sleep past
        # the 1s slack `units_outdated` allows before touching.
        time.sleep(2)
        target.run(["touch", CONFIG_PATH], sudo=True, check=True)

        current, rc = _diagnose(target, WORKLOAD)
        assert current is False, (
            f"config_current should be false after editing the config, got {current!r}"
        )
        # config_current failing makes the whole diagnose battery fail (exit 1).
        assert rc != 0, (
            f"diagnose should exit non-zero while the config is stale, got rc={rc}"
        )

        # 3) Restore: bump the unit mtime ahead of the config again → hint clears.
        # (Mirrors what a re-`enable` would do to the mtimes, without regenerating.)
        target.run(["touch", UNIT_PATH], sudo=True, check=True)

        current, _ = _diagnose(target, WORKLOAD)
        assert current is True, (
            f"config_current should clear once the unit is newer than the config, "
            f"got {current!r}"
        )
    finally:
        _purge_workload(target, WORKLOAD)
