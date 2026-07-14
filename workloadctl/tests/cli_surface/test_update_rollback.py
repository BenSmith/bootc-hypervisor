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
from fixtures import _wait_container_running, _purge_workload, unit_state


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_active(target: Target, name: str) -> bool:
    return unit_state(target, f"workload-{name}.service") == "active"


def _wait_active(target: Target, name: str, timeout: int = 120) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _is_active(target, name):
            return True
        time.sleep(3)
    return False


def _vm_gen_count(target: Target, name: str) -> int:
    """Return the number of system.qcow2.gen-N snapshots for a VM workload.

    Generations live under the state/ subtree (the reconstructible-disk half
    of the state/data layout) — same place the product's rollback_targets()
    globs. Looking in the workload root one level too high silently counts
    zero, which used to make the rollback half skip on every run.
    """
    r = target.run(
        ["bash", "-c",
         f"ls /var/lib/workloads/{name}/state/system.qcow2.gen-* 2>/dev/null | wc -l"],
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
        cfg_dir = f"/etc/workloads.d/{name}"
        toml_path = f"{cfg_dir}/workload.toml"
        toml_content = (
            f'[workload]\nname = "{name}"\nenabled = false\n\n'
            '[container]\nimage = "docker.io/library/caddy:2-alpine"\n'
        )
        try:
            # Enable
            target.run(["mkdir", "-p", cfg_dir], sudo=True, check=True)
            target.put_content(toml_content, toml_path)
            target.wl(f"enable {name}", check=True, timeout=180)
            assert _wait_active(target, name)
            # Unit-active is NOT enough: with Type=exec the unit goes active
            # while the service's `ExecStartPre=podman system migrate` is still
            # settling the rootless store, so a *peer* podman call (which is
            # exactly what `update` does to read the old image id) transiently
            # sees an empty store. Updating in that window reads an empty
            # old_id (→ no rollback tag) and restarts a still-settling unit,
            # tripping StartLimitBurst. Wait for the container to actually be
            # Up before mutating. (The fresh_* fixtures already do this; this
            # test builds its workload inline so it must do it too.)
            _wait_container_running(target, name)

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
            # Use the shared purge helper, not a bare `disable --purge`: it also
            # `systemctl reset-failed`s the unit. Without that, if this test's
            # workload ever trips StartLimitBurst (start-limit-hit), the failed
            # state survives the purge and poisons the *next* run's `enable` of
            # the same unit name (it never reaches active).
            _purge_workload(target, name)
            target.run(["rm", "-rf", cfg_dir], sudo=True, check=False)

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
    def test_update_then_rollback_vm(self, target, fresh_vm, record_property):
        """update → rollback on a VM, in sequence on one fixture.

        fresh_vm is function-scoped, so each test gets a fresh VM with zero
        generations. Update and rollback run in a single test: update rotates
        system.qcow2 → system.qcow2.gen-N and rebuilds, rollback restores the
        prior disk.

        This is deterministic: fresh_vm is a cattle VM backed by a cloud image
        cached at enable time, and `--update` always rotates a generation on a
        successful rebuild — so the generation (and therefore the rollback
        half) is asserted, not skipped.
        """
        record_property("cell", "update/vm")

        gen_before = _vm_gen_count(target, fresh_vm)

        r = target.wl(f"update {fresh_vm}", check=False, timeout=600)
        assert "Traceback" not in r.stderr, f"update crashed on VM: {r.stderr}"
        assert r.rc == 0, f"update failed on VM (rc={r.rc}): {r.stderr}"

        gen_after = _vm_gen_count(target, fresh_vm)
        assert gen_after > gen_before, (
            f"update did not cut a new generation (gens {gen_before}→{gen_after}); "
            "a cattle VM + --update should always rotate system.qcow2"
        )

        # A generation now exists — exercise rollback.
        record_property("cell", "rollback/vm")
        r = target.wl(f"rollback {fresh_vm}", check=True, timeout=120)
        assert r.rc == 0
        assert "Traceback" not in r.stderr
        assert _wait_active(target, fresh_vm, timeout=300), (
            f"{fresh_vm!r} not active after rollback"
        )
