"""
test_lifecycle.py — lifecycle verb tests.

Covers: create, enable, start, stop, disable (--purge), edit, reboot, recreate.

Most tests use a fresh workload per test (function-scoped fixtures).
Side effects are verified, not just exit codes.
"""

import json
import time

import pytest

from target import Target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_active(target: Target, name: str) -> bool:
    """Return True if the workload service is active."""
    r = target.run(
        ["systemctl", "is-active", f"workload-{name}.service"],
        sudo=False, check=False,
    )
    return r.stdout.strip() == "active"


def _user_exists(target: Target, name: str) -> bool:
    """Return True if the workload system user (_wl-<name>) exists."""
    r = target.run(["id", f"_wl-{name}"], sudo=False, check=False)
    return r.rc == 0


def _home_exists(target: Target, name: str) -> bool:
    """Return True if /var/lib/workloads/<name> exists."""
    r = target.run(
        ["test", "-d", f"/var/lib/workloads/{name}"],
        sudo=False, check=False,
    )
    return r.rc == 0


def _wait_active(target: Target, name: str, timeout: int = 120) -> bool:
    """Wait until workload is active. Returns True on success."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _is_active(target, name):
            return True
        time.sleep(2)
    return False


def _wait_inactive(target: Target, name: str, timeout: int = 30) -> bool:
    """Wait until workload is not active. Returns True on success."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _is_active(target, name):
            return True
        time.sleep(1)
    return False


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------

class TestCreate:
    @pytest.mark.mutating
    def test_create_produces_toml(self, target, record_property):
        """create writes a TOML file to /etc/workloads.d/."""
        record_property("cell", "create/container")
        name = "clitest-created"
        toml_path = f"/etc/workloads.d/{name}.toml"
        try:
            r = target.wl(
                f"create --image docker.io/library/caddy:2-alpine {name}",
                check=True,
            )
            assert r.rc == 0
            # TOML file exists
            exists = target.remote_path_exists(toml_path)
            assert exists, f"create did not produce {toml_path}"
            # validate passes on the new TOML
            v = target.wl(f"validate {name}", check=True)
            assert v.rc == 0
        finally:
            target.run(["rm", "-f", toml_path], sudo=True, check=False)

    @pytest.mark.mutating
    def test_create_with_ports(self, target, record_property):
        """create --ports writes port mapping into the TOML."""
        record_property("cell", "create/container")
        name = "clitest-created-ports"
        toml_path = f"/etc/workloads.d/{name}.toml"
        try:
            target.wl(
                f"create --image docker.io/library/caddy:2-alpine --ports 19099:80 {name}",
                check=True,
            )
            r = target.wl(f"ports --json {name}", check=True)
            data = json.loads(r.stdout)
            ports = data.get("ports", [])
            assert any("19099" in p for p in ports), f"Port not found in: {ports}"
        finally:
            target.run(["rm", "-f", toml_path], sudo=True, check=False)


# ---------------------------------------------------------------------------
# enable / disable
# ---------------------------------------------------------------------------

class TestEnableDisable:
    @pytest.mark.mutating
    def test_enable_starts_service(self, target, clitest_single, record_property):
        """The clitest_single fixture already enabled the workload; verify it's active."""
        record_property("cell", "enable/container")
        assert _is_active(target, clitest_single), (
            f"Workload {clitest_single!r} should be active after enable"
        )

    @pytest.mark.mutating
    def test_enable_creates_user(self, target, clitest_single, record_property):
        record_property("cell", "enable/container")
        assert _user_exists(target, clitest_single), (
            f"User _wl-{clitest_single} should exist after enable"
        )

    @pytest.mark.mutating
    def test_enable_creates_home(self, target, clitest_single, record_property):
        record_property("cell", "enable/container")
        assert _home_exists(target, clitest_single), (
            f"/var/lib/workloads/{clitest_single} should exist after enable"
        )

    @pytest.mark.mutating
    @pytest.mark.destructive
    def test_disable_stops_service(self, target, record_property):
        """enable then disable (without --purge) stops the service."""
        record_property("cell", "disable/container")
        name = "clitest-dis-test"
        toml_path = f"/etc/workloads.d/{name}.toml"
        # Write minimal TOML
        toml_content = (
            f'[workload]\nname = "{name}"\nenabled = false\n\n'
            '[container]\nimage = "docker.io/library/caddy:2-alpine"\n'
        )
        try:
            target.put_content(toml_content, toml_path)
            target.wl(f"enable {name}", check=True, timeout=180)
            assert _wait_active(target, name), f"{name} did not become active"

            target.wl(f"disable {name}", check=True)
            assert _wait_inactive(target, name), f"{name} did not stop after disable"

            # User still exists (no --purge)
            assert _user_exists(target, name), "User removed unexpectedly (no --purge)"
        finally:
            target.wl(f"disable --purge {name}", check=False, timeout=60)
            target.run(["rm", "-f", toml_path], sudo=True, check=False)

    @pytest.mark.mutating
    @pytest.mark.destructive
    def test_disable_purge_removes_user_and_home(self, target, record_property):
        """disable --purge removes the user and home directory."""
        record_property("cell", "disable_purge/container")
        name = "clitest-purge-test"
        toml_path = f"/etc/workloads.d/{name}.toml"
        toml_content = (
            f'[workload]\nname = "{name}"\nenabled = false\n\n'
            '[container]\nimage = "docker.io/library/caddy:2-alpine"\n'
        )
        try:
            target.put_content(toml_content, toml_path)
            target.wl(f"enable {name}", check=True, timeout=180)
            assert _wait_active(target, name)

            target.wl(f"disable --purge {name}", check=True, timeout=60)

            # User gone
            assert not _user_exists(target, name), f"User _wl-{name} still exists after purge"
            # Home gone
            assert not _home_exists(target, name), f"Home /var/lib/workloads/{name} still exists"
        finally:
            target.wl(f"disable --purge {name}", check=False, timeout=60)
            target.run(["rm", "-f", toml_path], sudo=True, check=False)


# ---------------------------------------------------------------------------
# start / stop
# ---------------------------------------------------------------------------

class TestStartStop:
    @pytest.mark.mutating
    def test_stop_stops_service(self, target, clitest_single, record_property):
        record_property("cell", "stop/container")
        assert _is_active(target, clitest_single)
        target.wl(f"stop {clitest_single}", check=True)
        assert _wait_inactive(target, clitest_single), (
            f"Workload {clitest_single!r} did not stop"
        )

    @pytest.mark.mutating
    def test_start_starts_service(self, target, clitest_single, record_property):
        record_property("cell", "start/container")
        # First stop it
        target.wl(f"stop {clitest_single}", check=False)
        _wait_inactive(target, clitest_single, timeout=15)
        # Now start
        target.wl(f"start {clitest_single}", check=True)
        assert _wait_active(target, clitest_single), (
            f"Workload {clitest_single!r} did not start"
        )

    @pytest.mark.mutating
    @pytest.mark.vm
    @pytest.mark.slow
    def test_stop_vm(self, target, clitest_vm, record_property):
        record_property("cell", "stop/vm")
        assert _is_active(target, clitest_vm)
        target.wl(f"stop {clitest_vm}", check=True, timeout=30)
        assert _wait_inactive(target, clitest_vm, timeout=30)

    @pytest.mark.mutating
    @pytest.mark.vm
    @pytest.mark.slow
    def test_start_vm(self, target, clitest_vm, record_property):
        record_property("cell", "start/vm")
        target.wl(f"stop {clitest_vm}", check=False, timeout=30)
        _wait_inactive(target, clitest_vm, timeout=30)
        target.wl(f"start {clitest_vm}", check=True, timeout=30)
        assert _wait_active(target, clitest_vm, timeout=60)


# ---------------------------------------------------------------------------
# recreate
# ---------------------------------------------------------------------------

class TestRecreate:
    @pytest.mark.mutating
    def test_recreate_container(self, target, clitest_single, record_property):
        """recreate restarts the container without destroying data."""
        record_property("cell", "recreate/container")
        r = target.wl(f"recreate {clitest_single}", check=True, timeout=120)
        assert r.rc == 0
        # Should be active after recreate
        assert _wait_active(target, clitest_single, timeout=90), (
            f"{clitest_single!r} not active after recreate"
        )

    @pytest.mark.mutating
    @pytest.mark.vm
    @pytest.mark.slow
    def test_recreate_vm(self, target, clitest_vm, record_property):
        """recreate on a VM rebuilds the cloud-init seed and reboots QEMU."""
        record_property("cell", "recreate/vm")
        r = target.wl(f"recreate {clitest_vm}", check=True, timeout=120)
        assert r.rc == 0
        # VM should come back up
        assert _wait_active(target, clitest_vm, timeout=300), (
            f"{clitest_vm!r} not active after recreate"
        )


# ---------------------------------------------------------------------------
# reboot
# ---------------------------------------------------------------------------

class TestReboot:
    @pytest.mark.mutating
    @pytest.mark.slow
    def test_reboot_container(self, target, clitest_single, record_property):
        """reboot on a container: systemctl soft-reboot inside the container.

        Note: caddy is not a systemd container so this may fail with a
        non-0 exit. The test verifies it doesn't crash with a traceback,
        and re-checks that the workload service is still active.
        """
        record_property("cell", "reboot/container")
        r = target.wl(f"reboot {clitest_single}", check=False, timeout=30)
        # soft-reboot may fail in a non-systemd container; don't require rc==0
        # but must not produce a Python traceback
        assert "Traceback" not in r.stderr, (
            f"reboot produced a traceback: {r.stderr}"
        )
        # The workload service must survive the reboot attempt: a non-systemd
        # container may restart, but the unit must not end up failed.
        time.sleep(5)
        state = target.run(
            ["systemctl", "is-active", f"workload-{clitest_single}.service"],
            sudo=False, check=False,
        ).stdout.strip()
        assert state in ("active", "activating"), (
            f"workload service in unexpected state after reboot: {state!r}"
        )

    @pytest.mark.mutating
    @pytest.mark.vm
    @pytest.mark.slow
    def test_reboot_vm(self, target, clitest_vm, record_property):
        """reboot on a VM: sends soft-reboot to the guest over SSH."""
        record_property("cell", "reboot/vm")
        r = target.wl(f"reboot {clitest_vm}", check=False, timeout=30)
        assert "Traceback" not in r.stderr, f"reboot traceback: {r.stderr}"
        # rc==0 expected when SSH succeeds
        # Give the VM time to reboot and come back
        time.sleep(60)
        assert _wait_active(target, clitest_vm, timeout=180), (
            f"{clitest_vm!r} not active after reboot"
        )


# ---------------------------------------------------------------------------
# edit
# ---------------------------------------------------------------------------

class TestEdit:
    @pytest.mark.mutating
    def test_edit_applies_change(self, target, clitest_single, record_property):
        """edit with a non-interactive EDITOR changes the TOML."""
        record_property("cell", "edit/container")

        # Write a minimal editor script: append a comment line
        editor_script = (
            "#!/bin/bash\n"
            "echo '# edited-by-clitest' >> \"$1\"\n"
        )
        # Upload the editor script to a temp location on the target
        remote_editor = "/tmp/clitest-editor.sh"
        target.put_content(editor_script, remote_editor)
        target.run(["chmod", "+x", remote_editor], sudo=False, check=True)

        # Run edit with EDITOR set to our script.  sudo scrubs the environment
        # by default, so pass EDITOR through with `env` inside the sudo context
        # rather than exporting it in the outer shell (where it would be lost).
        r = target.run(
            ["sudo", "-n", "env", f"EDITOR={remote_editor}",
             "workloadctl", "edit", clitest_single],
            sudo=False, check=True,
        )
        assert r.rc == 0

        # Verify the change is in the TOML
        content = target.read(f"/etc/workloads.d/{clitest_single}.toml")
        assert "edited-by-clitest" in content, (
            f"edit did not persist the change: {content[:500]}"
        )

        # Cleanup editor script
        target.run(["rm", "-f", remote_editor], sudo=False, check=False)


# ---------------------------------------------------------------------------
# Topology parametrize: enable/disable across all container topologies
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fixture_name", [
    "clitest_single",
    "clitest_pod",
    "clitest_bridge",
    "clitest_host",
])
def test_topology_is_active(request, fixture_name, target, record_property):
    """Each container topology must become active after enable."""
    wl = request.getfixturevalue(fixture_name)
    record_property("cell", f"enable/{fixture_name.replace('clitest_', '')}")
    assert _is_active(target, wl), (
        f"Topology {fixture_name!r} not active after enable"
    )
