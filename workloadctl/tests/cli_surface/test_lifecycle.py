"""
test_lifecycle.py — lifecycle verb tests.

Covers: create, enable, start, stop, disable (--purge), edit, reboot, recreate.

Most tests use a fresh workload per test (function-scoped fixtures).
Side effects are verified, not just exit codes.

VM lifecycle tests (stop/start/recreate/reboot) share ONE module-scoped
clitest_vm_lifecycle fixture so the VM is booted once for the group rather
than four times.  Each test calls _vm_lifecycle_baseline() at entry to:
  - clear any accumulated StartLimitBurst state (reset-failed), and
  - restore the VM to active/running before exercising the verb under test.
This is harness-level hygiene, not a product fix: the product's StartLimitBurst
settings are tight by design, so the harness must not allow limit state to
bleed across tests that share one unit.
"""

import json
import time

import pytest

from fixtures import poll_vm_reachable, unit_state
from target import Target

# The shared VM bridge and the unit that owns it. Mirrors VM_BRIDGE_NAME in
# lib/workload_lib.py — spelled out here rather than imported because the
# harness talks to the target only through the CLI and the host's own files.
MANAGED_BRIDGE = "_workload-br"
BRIDGE_UNIT = "workload-bridge.service"
# Substring of the teardown-plan line VMSubstrate.teardown_plan emits when the
# workload being disabled is the last one holding the bridge up.
BRIDGE_STOP_PLAN = "stop shared VM bridge"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_active(target: Target, name: str) -> bool:
    """Return True if the workload service is active."""
    return unit_state(target, f"workload-{name}.service") == "active"


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


def _managed_bridge_vms(target: Target, *, exclude: tuple[str, ...] = ()) -> list[str]:
    """Enabled VM workloads attached to the shared bridge, read from host config.

    Deliberately derived from `list --json` plus the TOMLs on disk, never from
    workloadctl's own teardown plan: that plan *is* the predicate under test
    (`VMSubstrate._last_managed_bridge_vm`), so computing the expectation from it
    would assert only that the predicate agrees with itself.

    The bridge defaults to MANAGED_BRIDGE when `[vm.network] bridge` is absent,
    matching WorkloadConfig.vm_bridge. A flat scan for a `bridge =` key is safe
    for VM TOMLs, where that key exists in one section only.
    """
    data = json.loads(target.wl("list --json", check=True).stdout)
    names = []
    for w in data["workloads"]:
        if w["kind"] != "vm" or not w["enabled"] or w["name"] in exclude:
            continue
        bridge = MANAGED_BRIDGE
        toml = target.read(f"/etc/workloads.d/{w['name']}/workload.toml")
        for line in toml.splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip() == "bridge":
                bridge = value.strip().strip("\"'")
        if bridge == MANAGED_BRIDGE:
            names.append(w["name"])
    return names


def _purge_plan(target: Target, name: str) -> list[str]:
    """The lines `disable --purge` says it would perform, without performing them."""
    r = target.wl(f"disable --purge --dry-run --json {name}", check=True, timeout=60)
    return json.loads(r.stdout)["workloads"][0]["plan"]


def _wait_unit_state(target: Target, unit: str, want: str, timeout: int = 30) -> str:
    """Poll until `unit` reaches state `want`; return whatever state it ended in."""
    deadline = time.monotonic() + timeout
    state = unit_state(target, unit)
    while state != want and time.monotonic() < deadline:
        time.sleep(1)
        state = unit_state(target, unit)
    return state


def _vm_lifecycle_baseline(target: Target, name: str, timeout: int = 120):
    """Bring clitest_vm_lifecycle to a known-good baseline before each test.

    Shared lifecycle tests mutate the VM (stop it, reboot it, etc.).  Without
    explicit baseline restoration a test that finds the VM already stopped (left
    by the previous test) would either skip the interesting verb or produce a
    confusing failure.  This helper:

      1. Clears any accumulated StartLimitBurst/failed state on the systemd
         unit — necessary because StartLimitBurst=3/300s is tight and the
         lifecycle tests trigger several start/stop cycles on the same unit.
         reset-failed is idempotent and harmless when the unit is clean.

      2. If the VM is not already active, starts it and waits until it is.
         This ensures every test begins with a running VM regardless of what
         the previous test did to it.

    Call at the very top of each VM lifecycle test body (after record_property).
    """
    svc = f"workload-{name}.service"
    # Step 1: clear start-limit state unconditionally.
    target.run(["systemctl", "reset-failed", svc], sudo=True, check=False)
    # Step 2: ensure the VM is running.
    if not _is_active(target, name):
        target.wl(f"start {name}", check=True, timeout=30)
        assert _wait_active(target, name, timeout=timeout), (
            f"clitest_vm_lifecycle did not become active within {timeout}s "
            "during per-test baseline restore"
        )


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------

class TestCreate:
    @pytest.mark.mutating
    def test_create_produces_toml(self, target, record_property):
        """create writes a TOML file to /etc/workloads.d/."""
        record_property("cell", "create/container")
        name = "clitest-created"
        cfg_dir = f"/etc/workloads.d/{name}"
        toml_path = f"{cfg_dir}/workload.toml"
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
            target.run(["rm", "-rf", cfg_dir], sudo=True, check=False)

    @pytest.mark.mutating
    def test_create_with_ports(self, target, record_property):
        """create --ports writes port mapping into the TOML."""
        record_property("cell", "create/container")
        name = "clitest-created-ports"
        cfg_dir = f"/etc/workloads.d/{name}"
        try:
            target.wl(
                f"create --image docker.io/library/caddy:2-alpine --ports 19099:80 {name}",
                check=True,
            )
            r = target.wl(f"info --json {name}", check=True)
            data = json.loads(r.stdout)
            ports = data["network"]["ports"]
            assert any("19099" in p for p in ports), f"Port not found in: {ports}"
        finally:
            target.run(["rm", "-rf", cfg_dir], sudo=True, check=False)


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
        cfg_dir = f"/etc/workloads.d/{name}"
        toml_path = f"{cfg_dir}/workload.toml"
        # Write minimal TOML
        toml_content = (
            f'[workload]\nname = "{name}"\nenabled = false\n\n'
            '[container]\nimage = "docker.io/library/caddy:2-alpine"\n'
        )
        try:
            target.run(["mkdir", "-p", cfg_dir], sudo=True, check=True)
            target.put_content(toml_content, toml_path)
            target.wl(f"enable {name}", check=True, timeout=180)
            assert _wait_active(target, name), f"{name} did not become active"

            target.wl(f"disable {name}", check=True)
            assert _wait_inactive(target, name), f"{name} did not stop after disable"

            # User still exists (no --purge)
            assert _user_exists(target, name), "User removed unexpectedly (no --purge)"
        finally:
            target.wl(f"disable --purge {name}", check=False, timeout=60)
            target.run(["rm", "-rf", cfg_dir], sudo=True, check=False)

    @pytest.mark.mutating
    @pytest.mark.destructive
    def test_disable_purge_removes_user_and_home(self, target, record_property):
        """disable --purge removes the user and home directory."""
        record_property("cell", "disable_purge/container")
        name = "clitest-purge-test"
        cfg_dir = f"/etc/workloads.d/{name}"
        toml_path = f"{cfg_dir}/workload.toml"
        toml_content = (
            f'[workload]\nname = "{name}"\nenabled = false\n\n'
            '[container]\nimage = "docker.io/library/caddy:2-alpine"\n'
        )
        try:
            target.run(["mkdir", "-p", cfg_dir], sudo=True, check=True)
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
            target.run(["rm", "-rf", cfg_dir], sudo=True, check=False)

    @pytest.mark.vm
    @pytest.mark.mutating
    @pytest.mark.destructive
    @pytest.mark.slow
    def test_disable_purge_removes_vm_state(self, target, fresh_vm, record_property):
        """disable --purge takes a VM's substrate state with it, and says so.

        Every VM fixture already tears down through `disable --purge`, but as
        best-effort with errors ignored (`fixtures.py:_purge_workload`) — so that
        path runs constantly while asserting nothing, and could fail in every test
        without turning the suite red. This is the assertion: purge *succeeds*, and
        the state `VMSubstrate.teardown` owns is actually gone afterwards.

        The socket dir is the VM-specific half (QMP + serial sockets under
        /run/workload-vm/<name>, meaningless once the guest is gone); the user and
        home are the shared half, checked here too because a VM purge takes a
        different route to them than a container purge does.
        """
        record_property("cell", "disable_purge/vm")
        name = fresh_vm
        sock_dir = f"/run/workload-vm/{name}"

        # Precondition: the sockets exist while the guest runs, otherwise their
        # absence afterwards would prove nothing.
        pre = target.run(["test", "-d", sock_dir], sudo=True, check=False)
        assert pre.rc == 0, (
            f"{sock_dir} absent while the VM is running — this test cannot tell a "
            f"successful teardown from a path that was never created"
        )

        # check=True is the whole point: the fixture teardown passes check=False.
        target.wl(f"disable --purge {name}", check=True, timeout=180)

        post = target.run(["test", "-d", sock_dir], sudo=True, check=False)
        assert post.rc != 0, f"VM socket dir survived purge: {sock_dir}"
        assert not _user_exists(target, name), f"User _wl-{name} survived purge"
        assert not _home_exists(target, name), (
            f"Home /var/lib/workloads/{name} survived purge"
        )

        # The subuid/subgid ranges outlive the user if teardown misses them, and
        # would then be handed to whoever next claims the UID.
        for db in ("/etc/subuid", "/etc/subgid"):
            r = target.run(["grep", "-c", f"^_wl-{name}:", db], sudo=True, check=False)
            assert r.rc != 0, f"_wl-{name} still has entries in {db} after purge"


# ---------------------------------------------------------------------------
# shared VM bridge
# ---------------------------------------------------------------------------

class TestSharedVMBridge:
    """The shared bridge must outlive a purge that isn't the last VM's.

    `VMSubstrate.teardown` stops workload-bridge.service only when no other
    enabled VM on MANAGED_BRIDGE remains. Getting that wrong pulls the network
    out from under a *running* guest, which is why this is worth two VM boots:
    the unit tests in tests/test_disable_bridge.py drive the predicate with
    mocked configs, so they pin the logic but cannot show that
    `get_all_configs(enabled_only=True)` reflects the host.

    Both directions live in one test on purpose: "the bridge stayed up" is also
    what a teardown that never stops the bridge would produce, so the second
    half is what gives the first one meaning — and running them as one sequence
    costs two VM boots instead of three, with no ordering assumption between
    them.
    """

    @pytest.mark.vm
    @pytest.mark.mutating
    @pytest.mark.destructive
    @pytest.mark.slow
    def test_purge_keeps_bridge_while_another_vm_uses_it(
        self, target, vm_bridge_peer, fresh_vm, record_property,
    ):
        """Purge one of two bridged VMs: bridge stays and the survivor still
        answers. Then purge the survivor: the bridge goes down with it."""
        record_property("cell", "disable_purge/vm")
        peer, doomed = vm_bridge_peer, fresh_vm

        assert unit_state(target, BRIDGE_UNIT) == "active", (
            f"{BRIDGE_UNIT} is not active with two VMs up — the rest of this "
            f"test would be measuring nothing"
        )

        # Plan first: it is the one assertion that holds no matter what else is
        # enabled on this host, since `peer` alone already disqualifies `doomed`
        # from being last.
        plan = _purge_plan(target, doomed)
        assert not any(BRIDGE_STOP_PLAN in line for line in plan), (
            f"purge of {doomed!r} plans to stop the bridge while {peer!r} still "
            f"uses it; plan was {plan}"
        )

        target.wl(f"disable --purge {doomed}", check=True, timeout=180)

        assert unit_state(target, BRIDGE_UNIT) == "active", (
            f"{BRIDGE_UNIT} went down when {doomed!r} was purged, with {peer!r} "
            f"still on it"
        )
        # Unit state is not connectivity: assert the survivor still answers over
        # its own network path, which is the failure this test exists to catch.
        r = poll_vm_reachable(target, peer, timeout=120)
        assert r is not None and r.rc == 0, (
            f"{peer!r} unreachable after {doomed!r} was purged: "
            f"rc={None if r is None else r.rc} "
            f"{'' if r is None else r.stdout + r.stderr}"
        )

        # --- complementary half: purge the survivor too -------------------
        # Order-dependent by nature: another VM fixture alive in this session
        # legitimately keeps the bridge up. So the expectation is computed from
        # the host's own config rather than assumed, and when the peer is not
        # genuinely last the *other* branch is asserted instead of skipping —
        # both directions of the predicate are real behavior.
        others = _managed_bridge_vms(target, exclude=(peer,))

        plan = _purge_plan(target, peer)
        plans_stop = any(BRIDGE_STOP_PLAN in line for line in plan)
        assert plans_stop == (not others), (
            f"purge plan for {peer!r} {'includes' if plans_stop else 'omits'} the "
            f"bridge stop, but other bridged VMs are {others or 'absent'}; "
            f"plan was {plan}"
        )

        target.wl(f"disable --purge {peer}", check=True, timeout=180)

        want = "inactive" if not others else "active"
        got = _wait_unit_state(target, BRIDGE_UNIT, want, timeout=30)
        assert got == want, (
            f"{BRIDGE_UNIT} is {got!r} after purging {peer!r} "
            f"(other bridged VMs: {others or 'none'}); expected {want!r}"
        )


# ---------------------------------------------------------------------------
# start / stop
# ---------------------------------------------------------------------------

class TestStartStop:
    @pytest.mark.mutating
    def test_stop_stops_service(self, target, fresh_single, record_property):
        record_property("cell", "stop/container")
        assert _is_active(target, fresh_single)
        target.wl(f"stop {fresh_single}", check=True)
        assert _wait_inactive(target, fresh_single), (
            f"Workload {fresh_single!r} did not stop"
        )

    @pytest.mark.mutating
    def test_start_starts_service(self, target, fresh_single, record_property):
        record_property("cell", "start/container")
        # First stop it
        target.wl(f"stop {fresh_single}", check=False)
        _wait_inactive(target, fresh_single, timeout=15)
        # Now start
        target.wl(f"start {fresh_single}", check=True)
        assert _wait_active(target, fresh_single), (
            f"Workload {fresh_single!r} did not start"
        )

    @pytest.mark.mutating
    @pytest.mark.vm
    @pytest.mark.slow
    def test_stop_vm(self, target, clitest_vm_lifecycle, record_property):
        record_property("cell", "stop/vm")
        _vm_lifecycle_baseline(target, clitest_vm_lifecycle)
        assert _is_active(target, clitest_vm_lifecycle)
        target.wl(f"stop {clitest_vm_lifecycle}", check=True, timeout=30)
        assert _wait_inactive(target, clitest_vm_lifecycle, timeout=30)

    @pytest.mark.mutating
    @pytest.mark.vm
    @pytest.mark.slow
    def test_start_vm(self, target, clitest_vm_lifecycle, record_property):
        record_property("cell", "start/vm")
        # Baseline: reset-failed + ensure inactive so we can start from cold.
        svc = f"workload-{clitest_vm_lifecycle}.service"
        target.run(["systemctl", "reset-failed", svc], sudo=True, check=False)
        if _is_active(target, clitest_vm_lifecycle):
            target.wl(f"stop {clitest_vm_lifecycle}", check=False, timeout=30)
            _wait_inactive(target, clitest_vm_lifecycle, timeout=30)
        # Now exercise start
        target.wl(f"start {clitest_vm_lifecycle}", check=True, timeout=30)
        assert _wait_active(target, clitest_vm_lifecycle, timeout=60)


# ---------------------------------------------------------------------------
# recreate
# ---------------------------------------------------------------------------

class TestRecreate:
    @pytest.mark.mutating
    def test_recreate_container(self, target, fresh_single, record_property):
        """recreate restarts the container without destroying data."""
        record_property("cell", "recreate/container")
        r = target.wl(f"recreate {fresh_single}", check=True, timeout=120)
        assert r.rc == 0
        # Should be active after recreate
        assert _wait_active(target, fresh_single, timeout=90), (
            f"{fresh_single!r} not active after recreate"
        )

    @pytest.mark.mutating
    @pytest.mark.vm
    @pytest.mark.slow
    def test_recreate_vm(self, target, clitest_vm_lifecycle, record_property):
        """recreate on a VM rebuilds the cloud-init seed and reboots QEMU."""
        record_property("cell", "recreate/vm")
        _vm_lifecycle_baseline(target, clitest_vm_lifecycle)
        r = target.wl(f"recreate {clitest_vm_lifecycle}", check=True, timeout=120)
        assert r.rc == 0
        # VM should come back up
        assert _wait_active(target, clitest_vm_lifecycle, timeout=300), (
            f"{clitest_vm_lifecycle!r} not active after recreate"
        )


# ---------------------------------------------------------------------------
# reboot
# ---------------------------------------------------------------------------

class TestReboot:
    @pytest.mark.mutating
    @pytest.mark.slow
    def test_reboot_container(self, target, fresh_single, record_property):
        """reboot on a container: systemctl soft-reboot inside the container.

        Note: caddy is not a systemd container so this may fail with a
        non-0 exit. The test verifies it doesn't crash with a traceback,
        and re-checks that the workload service is still active.
        """
        record_property("cell", "reboot/container")
        r = target.wl(f"reboot {fresh_single}", check=False, timeout=30)
        # soft-reboot may fail in a non-systemd container; don't require rc==0
        # but must not produce a Python traceback
        assert "Traceback" not in r.stderr, (
            f"reboot produced a traceback: {r.stderr}"
        )
        # The workload service must survive the reboot attempt: a non-systemd
        # container may restart, but the unit must not end up failed.
        time.sleep(5)
        state = target.run(
            ["systemctl", "is-active", f"workload-{fresh_single}.service"],
            sudo=False, check=False,
        ).stdout.strip()
        assert state in ("active", "activating"), (
            f"workload service in unexpected state after reboot: {state!r}"
        )

    @pytest.mark.mutating
    @pytest.mark.vm
    @pytest.mark.slow
    def test_reboot_vm(self, target, clitest_vm_lifecycle, record_property):
        """reboot on a VM: sends soft-reboot to the guest over SSH."""
        record_property("cell", "reboot/vm")
        _vm_lifecycle_baseline(target, clitest_vm_lifecycle)
        r = target.wl(f"reboot {clitest_vm_lifecycle}", check=False, timeout=30)
        assert "Traceback" not in r.stderr, f"reboot traceback: {r.stderr}"
        # rc==0 expected when SSH succeeds
        # Give the VM time to reboot and come back
        time.sleep(60)
        assert _wait_active(target, clitest_vm_lifecycle, timeout=180), (
            f"{clitest_vm_lifecycle!r} not active after reboot"
        )


# ---------------------------------------------------------------------------
# edit
# ---------------------------------------------------------------------------

class TestEdit:
    @pytest.mark.mutating
    def test_edit_applies_change(self, target, fresh_single, record_property):
        """edit with a non-interactive EDITOR changes the TOML."""
        record_property("cell", "edit/container")

        # Write a minimal editor script: append a comment line
        editor_script = (
            "#!/bin/bash\n"
            "echo '# edited-by-clitest' >> \"$1\"\n"
        )
        # Upload the editor script to a temp location on the target
        remote_editor = "/tmp/clitest-editor.sh"
        # put_content writes via `sudo tee`, so the file is root-owned; the
        # chmod must therefore run as root too (a non-sudo chmod hits EPERM).
        target.put_content(editor_script, remote_editor)
        target.run(["chmod", "+x", remote_editor], sudo=True, check=True)

        # Run edit with EDITOR set to our script.  sudo scrubs the environment
        # by default, so pass EDITOR through with `env` inside the sudo context
        # rather than exporting it in the outer shell (where it would be lost).
        # --yes confirms the post-validation "Apply and restart?" prompt
        # non-interactively (the harness has no tty to answer it on).
        r = target.run(
            ["sudo", "-n", "env", f"EDITOR={remote_editor}",
             "workloadctl", "edit", "--yes", fresh_single],
            sudo=False, check=True,
        )
        assert r.rc == 0

        # Verify the change is in the TOML
        content = target.read(f"/etc/workloads.d/{fresh_single}/workload.toml")
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
