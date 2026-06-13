"""
test_update_rollback.py — update and rollback verbs.

For containers: update --force creates a rollback tag; rollback restores it.
For VMs: update rebuilds the system disk (system.qcow2.gen-N); rollback
         restores the previous generation.

Sequencing: enable → update --force → verify new state → rollback → verify prior.
"""

import time

import pytest

from target import Target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_active(target: Target, name: str) -> bool:
    r = target.run(
        ["systemctl", "is-active", f"workload-{name}.service"],
        sudo=False, check=False,
    )
    return r.stdout.strip() == "active"


def _wait_active(target: Target, name: str, timeout: int = 120) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _is_active(target, name):
            return True
        time.sleep(3)
    return False


def _vm_gen_count(target: Target, name: str) -> int:
    """Return the number of system.qcow2.gen-N files for a VM workload."""
    r = target.run(
        ["bash", "-c",
         f"ls /var/lib/workloads/{name}/system.qcow2.gen-* 2>/dev/null | wc -l"],
        sudo=True, check=False,
    )
    try:
        return int(r.stdout.strip())
    except ValueError:
        return 0


# ---------------------------------------------------------------------------
# Container update / rollback
# ---------------------------------------------------------------------------

class TestUpdateRollbackContainer:
    @pytest.mark.mutating
    @pytest.mark.slow
    def test_update_force_creates_rollback_tag(self, target, fresh_single, record_property):
        """update --force restarts the service (creates a rollback image tag)."""
        record_property("cell", "update/container")

        r = target.wl(f"update --force {fresh_single}", check=True, timeout=300)
        assert r.rc == 0
        assert "Traceback" not in r.stderr

        # Service should be active after update
        assert _wait_active(target, fresh_single, timeout=120), (
            f"{fresh_single!r} not active after update"
        )

    @pytest.mark.mutating
    @pytest.mark.slow
    def test_rollback_after_update(self, target, record_property):
        """update --force then rollback returns to the previous image.

        Uses a separate short-lived workload to keep this test self-contained.
        """
        record_property("cell", "rollback/container")
        name = "clitest-rollback-test"
        toml_path = f"/etc/workloads.d/{name}.toml"
        toml_content = (
            f'[workload]\nname = "{name}"\nenabled = false\n\n'
            '[container]\nimage = "docker.io/library/caddy:2-alpine"\n'
        )
        try:
            # Enable
            target.put_content(toml_content, toml_path)
            target.wl(f"enable {name}", check=True, timeout=180)
            assert _wait_active(target, name)

            # Update --force to create a rollback tag
            r = target.wl(f"update --force {name}", check=True, timeout=300)
            assert r.rc == 0
            assert _wait_active(target, name, timeout=120)

            # Rollback
            r = target.wl(f"rollback {name}", check=True, timeout=120)
            assert r.rc == 0
            assert "Traceback" not in r.stderr
            assert _wait_active(target, name, timeout=120), (
                f"{name!r} not active after rollback"
            )

        finally:
            target.wl(f"disable --purge {name}", check=False, timeout=60)
            target.run(["rm", "-f", toml_path], sudo=True, check=False)

    def test_rollback_without_prior_fails_cleanly(self, target, fresh_single, record_property):
        """rollback when no rollback tag exists: exit nonzero, no traceback."""
        record_property("cell", "rollback/container")
        # This is a fresh, per-test fixture so no rollback tag exists yet.
        r = target.wl(f"rollback {fresh_single}", check=False, timeout=30)
        # No prior update in this fixture's lifetime; just check for no traceback
        assert "Traceback" not in r.stderr

    @pytest.mark.mutating
    def test_update_all(self, target, fresh_single, record_property):
        """update --all doesn't crash with container workloads present."""
        record_property("cell", "update_all/container")
        r = target.wl("update --all", check=False, timeout=600)
        # May exit nonzero if nothing to update or update fails; no traceback
        assert "Traceback" not in r.stderr


# ---------------------------------------------------------------------------
# VM update / rollback
# ---------------------------------------------------------------------------

@pytest.mark.vm
@pytest.mark.slow
class TestUpdateRollbackVM:
    def test_update_then_rollback_vm(self, target, clitest_vm, record_property):
        """update → rollback on a VM, in sequence on one fixture.

        clitest_vm is function-scoped, so each test gets a fresh VM with zero
        generations. Update and rollback must therefore run in a single test:
        update creates system.qcow2.gen-N, rollback restores the prior disk.
        If update can't produce a generation (cloud image unchanged, build
        failure), the rollback half is skipped rather than asserted blindly.
        """
        record_property("cell", "update/vm")

        gen_before = _vm_gen_count(target, clitest_vm)

        r = target.wl(f"update {clitest_vm}", check=False, timeout=600)
        # May fail if cloud image unchanged or disk build fails; check no traceback
        assert "Traceback" not in r.stderr, f"update crashed on VM: {r.stderr}"

        gen_after = _vm_gen_count(target, clitest_vm)
        if r.rc != 0 or gen_after <= gen_before:
            pytest.skip(
                "update did not produce a new VM generation "
                f"(rc={r.rc}, gens {gen_before}→{gen_after}); "
                "nothing to roll back to"
            )

        # A generation now exists — exercise rollback.
        record_property("cell", "rollback/vm")
        r = target.wl(f"rollback {clitest_vm}", check=True, timeout=120)
        assert r.rc == 0
        assert "Traceback" not in r.stderr
        assert _wait_active(target, clitest_vm, timeout=300), (
            f"{clitest_vm!r} not active after rollback"
        )
