"""
test_cleanup.py — cleanup verb.

Covers: cleanup (dry-run, --apply, --json).

Side effects: an orphaned user + home planted by the test is reaped by
`cleanup --apply`. dry-run reports but does not remove.
"""

import json
import time

import pytest

from target import Target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _plant_orphan_user(target: Target, username: str, uid: int):
    """Create a _wl-* system user with no corresponding workload TOML."""
    # Use useradd to create the orphan user
    target.run(
        ["useradd", "--no-create-home", "--system",
         "--uid", str(uid), "--shell", "/usr/sbin/nologin", username],
        sudo=True, check=False,  # may fail if UID taken; ok for test
    )
    # Create a home directory
    home = f"/var/lib/workloads/{username[len('_wl-'):]}"
    target.run(["mkdir", "-p", home], sudo=True, check=False)


def _remove_orphan_user(target: Target, username: str):
    """Clean up: remove the test orphan user."""
    name_part = username[len("_wl-"):]
    home = f"/var/lib/workloads/{name_part}"
    target.run(["userdel", "-f", username], sudo=True, check=False)
    target.run(["rm", "-rf", home], sudo=True, check=False)


# ---------------------------------------------------------------------------
# cleanup dry-run
# ---------------------------------------------------------------------------

class TestCleanupDryRun:
    def test_cleanup_no_orphans(self, target, clitest_single, record_property):
        """cleanup with no orphans: exits 0, reports nothing to clean."""
        record_property("cell", "cleanup/dry_run")
        r = target.wl("cleanup", check=True)
        assert r.rc == 0
        assert "Traceback" not in r.stderr

    def test_cleanup_json_no_orphans(self, target, clitest_single, record_property):
        """cleanup --json: parseable output with empty lists."""
        record_property("cell", "cleanup/dry_run")
        r = target.wl("cleanup --json", check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert "orphan_users" in data
        assert "orphan_dirs" in data
        # clitest_single has a proper TOML so its user is not orphaned
        assert "clitest-single" not in str(data.get("orphan_users", []))

    @pytest.mark.mutating
    def test_cleanup_dry_run_reports_orphan(self, target, record_property):
        """cleanup (dry-run) reports an orphaned user without removing it."""
        record_property("cell", "cleanup/dry_run")
        orphan_user = "_wl-clitest-orphan-dr"
        # Top of the workload UID range (10000+); unlikely to collide with a
        # real workload unless the target has ~10000 of them.
        orphan_uid = 19998

        try:
            _plant_orphan_user(target, orphan_user, orphan_uid)
            time.sleep(0.5)

            r = target.wl("cleanup --json", check=True)
            data = json.loads(r.stdout)

            # Dry-run should not remove the orphan
            assert orphan_user in data.get("orphan_users", []), (
                f"Expected {orphan_user!r} in orphan_users: {data}"
            )
            assert orphan_user not in data.get("removed_users", []), (
                "Dry-run should not remove orphan"
            )
            # User still exists
            r2 = target.run(["id", orphan_user], sudo=False, check=False)
            assert r2.rc == 0, f"Orphan user {orphan_user!r} was removed by dry-run"

        finally:
            _remove_orphan_user(target, orphan_user)


# ---------------------------------------------------------------------------
# cleanup --apply
# ---------------------------------------------------------------------------

class TestCleanupApply:
    @pytest.mark.mutating
    @pytest.mark.destructive
    def test_cleanup_apply_removes_orphan(self, target, record_property):
        """cleanup --apply removes an orphaned user and its home directory."""
        record_property("cell", "cleanup/apply")
        orphan_user = "_wl-clitest-orphan-ap"
        orphan_uid = 19999

        try:
            _plant_orphan_user(target, orphan_user, orphan_uid)
            time.sleep(0.5)

            r = target.wl("cleanup --apply --json", check=True, timeout=60)
            data = json.loads(r.stdout)

            assert orphan_user in data.get("removed_users", []), (
                f"Expected {orphan_user!r} in removed_users: {data}"
            )

            # User should be gone
            r2 = target.run(["id", orphan_user], sudo=False, check=False)
            assert r2.rc != 0, f"Orphan user {orphan_user!r} still exists after cleanup --apply"

        finally:
            _remove_orphan_user(target, orphan_user)

    def test_cleanup_apply_no_orphans(self, target, clitest_single, record_property):
        """cleanup --apply with no orphans: exits 0 cleanly."""
        record_property("cell", "cleanup/apply")
        r = target.wl("cleanup --apply --json", check=True, timeout=60)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert "removed_users" in data
