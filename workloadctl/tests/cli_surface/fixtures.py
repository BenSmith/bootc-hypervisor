"""
fixtures.py — pytest fixtures that provision and tear down clitest-* workloads.

Two flavours of workload fixture exist, because provisioning a workload
(enable → wait active → wait container up → purge on teardown) is by far the
dominant cost in this suite:

  - **Session-scoped "shared" topologies** (clitest_single / clitest_pod /
    clitest_bridge / clitest_host). Provisioned ONCE per session and reused by
    every *read-only* test (introspection, exec, logs, cleanup-no-orphan, …).
    These tests never mutate the workload, so sharing one instance is safe and
    turns dozens of enable/purge cycles into one.

  - **Function-scoped "fresh" instances** (fresh_single / fresh_bridge).
    A brand-new, isolated workload per test, for *mutating* tests
    (stop/start/recreate/edit, backup, update/rollback, network create). They
    use distinct workload names + host ports (clitest-fresh-*) so a fresh
    instance can run alongside the long-lived shared one without colliding on
    the name or the published port.

All workload fixtures are:
  - Lazy: only created when a test requests them
  - Idempotent: safe to call on a target that already has the workload
  - Self-cleaning: a finalizer disables --purge the workload on teardown

Fixture names match the workload names (clitest-single, clitest-pod, etc.)
and the TOML files in workloads/.
"""

import json
import time
from pathlib import Path

import pytest

from target import Target

# Directory containing the fixture TOML files (relative to this file)
WORKLOADS_DIR = Path(__file__).parent / "workloads"


# ---------------------------------------------------------------------------
# Capability-gate skip helpers (used by fixtures + tests).
#
# These live here (not in conftest) so fixtures.py stays self-contained and can
# be star-imported by conftest without a circular import. conftest re-exports
# them, so `from conftest import skip_if_no_kvm` continues to work.
# ---------------------------------------------------------------------------

def skip_if_no_kvm(target: Target):
    if not target.capabilities["has_kvm"]:
        pytest.skip("requires /dev/kvm (KVM acceleration)")


def skip_if_no_br0(target: Target):
    if not target.capabilities["has_br0"]:
        pytest.skip("requires br0 bridge interface")


# ---------------------------------------------------------------------------
# Low-level provision/teardown helpers
# ---------------------------------------------------------------------------

def _install_toml(target: Target, toml_name: str) -> str:
    """Copy a fixture TOML to /etc/workloads.d/ on the target.

    Returns the workload name (derived from the TOML filename, stripping .toml).
    """
    toml_path = WORKLOADS_DIR / toml_name
    assert toml_path.exists(), f"Fixture TOML not found: {toml_path}"
    remote_path = f"/etc/workloads.d/{toml_name}"
    target.put_content(toml_path.read_text(), remote_path)
    return toml_name.replace(".toml", "")


def _enable_workload(target: Target, name: str, timeout: int = 120,
                     expect_container: bool = True):
    """Enable a workload and wait until it is genuinely ready.

    For container workloads, unit-active is NOT sufficient: with Type=exec the
    systemd unit goes active the moment the `podman` binary execs, before the
    container is actually up and listable. So after the unit is active we also
    wait for the container to appear running. VM workloads have no container,
    so callers pass expect_container=False for them.
    """
    target.wl(f"enable {name}", check=True, timeout=timeout)
    _wait_active(target, name, timeout=timeout)
    if expect_container:
        _wait_container_running(target, name, timeout=timeout)


def _wait_active(target: Target, name: str, timeout: int = 120):
    """Poll until the workload service is active or timeout."""
    service = f"workload-{name}.service"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = target.run(
            ["systemctl", "is-active", service],
            sudo=False, check=False,
        )
        if r.stdout.strip() == "active":
            return
        time.sleep(2)
    # Last check with output for diagnosis
    r = target.run(["systemctl", "status", "--no-pager", service], sudo=False, check=False)
    raise TimeoutError(
        f"Workload '{name}' did not become active within {timeout}s:\n{r.stdout}\n{r.stderr}"
    )


def _wait_container_running(target: Target, name: str, timeout: int = 120):
    """Poll until at least one of the workload's containers is Up.

    Closes the Type=exec readiness gap: the unit can be `active` while the
    container is still coming up. A workload's podman container names all
    contain the workload name (workload-<name>[-<container>]).
    """
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        r = target.wl("ps --json", sudo=True, check=False)
        if r.rc == 0 and r.stdout.strip():
            try:
                containers = json.loads(r.stdout).get("containers", [])
            except json.JSONDecodeError:
                containers = []
            last = ", ".join(
                f"{c.get('name', '')}:{c.get('status', '')}" for c in containers
            )
            for c in containers:
                if name in c.get("name", "") and c.get("status", "").startswith("Up"):
                    return
        time.sleep(2)
    raise TimeoutError(
        f"No running container for workload {name!r} within {timeout}s; "
        f"last ps saw: [{last}]"
    )


def _purge_workload(target: Target, name: str):
    """Disable --purge a workload. Best-effort: ignores all errors."""
    target.wl(f"disable --purge {name}", check=False, timeout=60)
    time.sleep(1)
    target.run(
        ["rm", "-f", f"/etc/workloads.d/{name}.toml"],
        sudo=True, check=False,
    )


# ---------------------------------------------------------------------------
# Shared (session-scoped) container topologies — for READ-ONLY tests.
#
# Provisioned once per session and reused across every test that only inspects
# the workload (it must not be mutated, or other tests sharing it would see the
# change). Mutating tests must use the fresh_* fixtures below instead.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def clitest_single(target: Target):
    """Shared single-container workload (pasta networking, port mapped)."""
    name = _install_toml(target, "clitest-single.toml")
    try:
        _enable_workload(target, name, timeout=180)
    except Exception:
        _purge_workload(target, name)
        raise
    yield name
    _purge_workload(target, name)


@pytest.fixture(scope="session")
def clitest_pod(target: Target):
    """Shared pod-mode multi-container workload (shared netns)."""
    name = _install_toml(target, "clitest-pod.toml")
    try:
        _enable_workload(target, name, timeout=180)
    except Exception:
        _purge_workload(target, name)
        raise
    yield name
    _purge_workload(target, name)


@pytest.fixture(scope="session")
def clitest_bridge(target: Target):
    """Shared bridge-mode multi-container workload (per-container netns)."""
    name = _install_toml(target, "clitest-bridge.toml")
    try:
        _enable_workload(target, name, timeout=180)
    except Exception:
        _purge_workload(target, name)
        raise
    yield name
    _purge_workload(target, name)


@pytest.fixture(scope="session")
def clitest_host(target: Target):
    """Shared single container with host networking."""
    name = _install_toml(target, "clitest-host.toml")
    try:
        _enable_workload(target, name, timeout=180)
    except Exception:
        _purge_workload(target, name)
        raise
    yield name
    _purge_workload(target, name)


# ---------------------------------------------------------------------------
# Fresh (function-scoped) container instances — for MUTATING tests.
#
# A brand-new isolated workload per test. Distinct name + host port from the
# shared topologies above so the two can coexist within one session.
# ---------------------------------------------------------------------------

@pytest.fixture()
def fresh_single(target: Target):
    """Fresh, isolated single-container workload (clitest-fresh-single)."""
    name = _install_toml(target, "clitest-fresh-single.toml")
    try:
        _enable_workload(target, name, timeout=180)
    except Exception:
        _purge_workload(target, name)
        raise
    yield name
    _purge_workload(target, name)


@pytest.fixture()
def fresh_bridge(target: Target):
    """Fresh, isolated bridge-mode workload (clitest-fresh-bridge)."""
    name = _install_toml(target, "clitest-fresh-bridge.toml")
    try:
        _enable_workload(target, name, timeout=180)
    except Exception:
        _purge_workload(target, name)
        raise
    yield name
    _purge_workload(target, name)


@pytest.fixture()
def clitest_secret(target: Target, key_type: str):
    """Single container referencing ${SECRET:clitest_token}.

    The clitest_token credential must exist before the workload can start,
    so create it here (and tear it down after the workload is purged).
    """
    cred_name = "clitest_token"
    target.wl(
        f"secret create --key-type {key_type} --force {cred_name}",
        input="clitest-secret-value-12345",
        check=True,
        timeout=30,
    )
    name = _install_toml(target, "clitest-secret.toml")
    try:
        _enable_workload(target, name, timeout=180)
    except Exception:
        _purge_workload(target, name)
        target.wl(f"secret delete --force {cred_name}", check=False, timeout=15)
        raise
    yield name
    _purge_workload(target, name)
    target.wl(f"secret delete --force {cred_name}", check=False, timeout=15)


@pytest.fixture()
def clitest_broken(target: Target):
    """Invalid TOML — only installed (not enabled), for negative-case tests."""
    name = _install_toml(target, "clitest-broken.toml")
    yield name
    target.run(
        ["rm", "-f", f"/etc/workloads.d/{name}.toml"],
        sudo=True, check=False,
    )


# ---------------------------------------------------------------------------
# VM workload fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def clitest_vm(target: Target):
    """VM workload on the managed NAT bridge (_workload-br).

    Tests that use this fixture carry their own @pytest.mark.vm/slow markers;
    markers on a fixture function do not propagate to its consumers.
    """
    skip_if_no_kvm(target)
    name = _install_toml(target, "clitest-vm.toml")
    try:
        # VM boot can take a while: first enable builds the disk. VMs have no
        # container, so don't wait for one.
        _enable_workload(target, name, timeout=600, expect_container=False)
        # Wait a bit extra for cloud-init to complete
        time.sleep(30)
    except Exception:
        _purge_workload(target, name)
        raise
    yield name
    _purge_workload(target, name)


@pytest.fixture()
def clitest_vm_bridged(target: Target):
    """VM workload on br0 (real LAN bridge).

    Consumers carry their own @pytest.mark.vm/slow markers (see clitest_vm).
    """
    skip_if_no_kvm(target)
    skip_if_no_br0(target)
    name = _install_toml(target, "clitest-vm-bridged.toml")
    try:
        _enable_workload(target, name, timeout=600, expect_container=False)
        time.sleep(30)
    except Exception:
        _purge_workload(target, name)
        raise
    yield name
    _purge_workload(target, name)
