"""
fixtures.py — pytest fixtures that provision and tear down clitest-* workloads.

Two flavours of workload fixture exist, because provisioning a workload
(enable → wait active → wait container up → purge on teardown) is by far the
dominant cost in this suite:

  - **Session-scoped "shared" topologies** (clitest_single / clitest_pod /
    clitest_bridge / clitest_host / clitest_vm). Provisioned ONCE per session
    and reused by every *read-only* test (introspection, exec, logs,
    cleanup-no-orphan, …). These tests never mutate the workload, so sharing
    one instance is safe and turns dozens of enable/purge cycles into one.
    clitest_vm follows the same pattern for VM workloads (one boot per session).

  - **Function-scoped "fresh" instances** (fresh_single / fresh_bridge /
    fresh_vm). A brand-new, isolated workload per test, for *mutating* tests
    (stop/start/recreate/edit, backup, update/rollback, network create). They
    use distinct workload names + host ports (clitest-fresh-*) so a fresh
    instance can run alongside the long-lived shared one without colliding on
    the name or the published port. fresh_vm provides the same isolation for
    mutating VM tests (backup, update/rollback).

All workload fixtures are:
  - Lazy: only created when a test requests them
  - Idempotent: safe to call on a target that already has the workload
  - Self-cleaning: a finalizer disables --purge the workload on teardown

Fixture names match the workload names (clitest-single, clitest-pod, etc.)
and the TOML files in workloads/.
"""

import json
import os
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


# OVMF firmware search order, mirroring workload_lib.OVMF_CODE_CANDIDATES — the
# VM path's own pre-flight (lib/cmd_lifecycle.py) requires one of these plus the
# qemu binaries + socat. The bootc hypervisor image bakes the whole toolchain;
# the bare dev cloud image has none of it.
_OVMF_CODE_CANDIDATES = (
    "/usr/share/edk2/ovmf/OVMF_CODE.fd",
    "/usr/share/OVMF/OVMF_CODE.fd",
    "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd",
    "/usr/share/ovmf/OVMF.fd",
)


def skip_if_no_vm_toolchain(target: Target):
    """Skip unless the VM enable pre-flight would pass: qemu-system-x86_64,
    qemu-img, socat, and OVMF firmware present. This lives on the hypervisor
    image, not in the workloadctl RPM — so a `[vm]` runtime check runs under
    gate mode and skips cleanly under the bare dev cloud image."""
    for tool in ("qemu-system-x86_64", "qemu-img", "socat"):
        if target.run(["command", "-v", tool], sudo=False, check=False).rc != 0:
            pytest.skip(f"requires VM toolchain ({tool} missing) — present on the "
                        "bootc hypervisor image; run in gate mode")
    ovmf = " ".join(_OVMF_CODE_CANDIDATES)
    if target.run(["sh", "-c", f"for f in {ovmf}; do [ -e \"$f\" ] && exit 0; done; exit 1"],
                  sudo=False, check=False).rc != 0:
        pytest.skip("requires OVMF firmware (edk2-ovmf) — present on the bootc "
                    "hypervisor image; run in gate mode")


def poll_vm_reachable(target: Target, name: str, *, token: str = "vm-reachable",
                      timeout: int = 300, interval: int = 10):
    """Poll `workloadctl exec <name> echo <token>` until it succeeds, or timeout.

    `workloadctl exec` reaches a VM workload over SSH with the pinned host key
    (StrictHostKeyChecking=yes), so a success here is also positive proof that
    the guest presented the host key the harness injected. Returns the last
    RunResult (rc 0 + token on stdout on success); the caller asserts on it.
    """
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = target.wl_exec(name, f"echo {token}", sudo=True, check=False, timeout=60)
        if last.rc == 0 and token in last.stdout:
            return last
        time.sleep(interval)
    return last


def guest_boot_id(target: Target, name: str) -> str:
    """Read the guest's current boot_id over `workloadctl exec` (changes on reboot)."""
    r = target.wl_exec(name, "cat /proc/sys/kernel/random/boot_id",
                       sudo=True, check=True, timeout=60)
    return r.stdout.strip()


# ---------------------------------------------------------------------------
# Low-level provision/teardown helpers
# ---------------------------------------------------------------------------

def _install_toml(target: Target, toml_name: str) -> str:
    """Copy a fixture TOML into its Step-2 subdir on the target.

    Writes /etc/workloads.d/<name>/workload.toml (name = filename minus .toml,
    matching the subdir layout the generator/resolver expect) and returns the
    workload name.
    """
    toml_path = WORKLOADS_DIR / toml_name
    assert toml_path.exists(), f"Fixture TOML not found: {toml_path}"
    name = toml_name.replace(".toml", "")
    target.run(["mkdir", "-p", f"/etc/workloads.d/{name}"], sudo=True, check=True)
    remote_path = f"/etc/workloads.d/{name}/workload.toml"
    target.put_content(toml_path.read_text(), remote_path)
    return name


def _enable_workload(target: Target, name: str, timeout: int = 120,
                     expect_container: bool = True, retries: int = 1):
    """Enable a workload and wait until it is genuinely ready.

    For container workloads, unit-active is NOT sufficient: with Type=exec the
    systemd unit goes active the moment the `podman` binary execs, before the
    container is actually up and listable. So after the unit is active we also
    wait for the container to appear running. VM workloads have no container,
    so callers pass expect_container=False for them.

    A *first* enable can lose a rootless cold-start race that a retry clears:
    the workload's `/run/user/<uid>` (XDG_RUNTIME_DIR) or user session bus may
    not be up yet when an auxiliary unit (e.g. the bridge-mode `-net` service,
    or aardvark-dns) runs, so the workload never reaches ready. This is genuine
    workloadctl first-enable flakiness, not something this CLI-surface suite is
    meant to assert on — so reset cleanly and retry once before giving up.
    """
    attempt = 0
    while True:
        target.wl(f"enable {name}", check=True, timeout=timeout)
        try:
            _wait_active(target, name, timeout=timeout)
            if expect_container:
                _wait_container_running(target, name, timeout=timeout)
            return
        except TimeoutError:
            if attempt >= retries:
                raise
            attempt += 1
            # Tear down to a clean slate (disable --purge keeps the config dir
            # /etc/workloads.d/<name>/, so the retry's enable still finds it) and clear
            # any failed/start-limit state before re-enabling.
            target.wl(f"disable --purge {name}", check=False, timeout=120)
            target.run(
                ["systemctl", "reset-failed", f"workload-{name}.service"],
                sudo=True, check=False,
            )
            time.sleep(5)


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
    container is still coming up.

    We use `health --json`, which reports the real podman container state (it
    queries `podman container_status` under the hood): a single-container
    workload exposes a `container_running` entry in `checks[]`, while pod/bridge
    workloads expose a per-container `running` flag in `containers[]`. We key off
    that container-running signal only, NOT overall health — other health checks
    (port reachability, a configured healthcheck) can lag behind the container
    actually being up, and we just want "is it running yet". `health` exits 1
    when unhealthy, so accept any rc and inspect the JSON.
    """
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        r = target.wl(f"health --json {name}", sudo=True, check=False)
        if r.stdout.strip():
            try:
                data = json.loads(r.stdout)
            except json.JSONDecodeError:
                data = {}
            last = json.dumps(data.get("checks") or data.get("containers") or data)
            if _health_reports_container_running(data):
                return
        time.sleep(2)
    raise TimeoutError(
        f"No running container for workload {name!r} within {timeout}s; "
        f"last health saw: [{last}]"
    )


def _health_reports_container_running(health_data: dict) -> bool:
    """True if `health --json` shows at least one container actually running.

    Single-container health is a flat `checks[]` list carrying a
    `container_running` check; pod/bridge health is a `containers[]` list with a
    per-container `running` flag. Handle both shapes.
    """
    for c in health_data.get("containers", []):
        if c.get("running"):
            return True
    for chk in health_data.get("checks", []):
        if chk.get("check") == "container_running" and chk.get("healthy"):
            return True
    return False


def _purge_workload(target: Target, name: str):
    """Disable --purge a workload. Best-effort: ignores all errors.

    Also clears any lingering systemd failed/start-limit state. A mutating test
    (e.g. backup, which does an internal stop→start) can leave the unit mid-
    restart when `disable --purge` arrives; that races `Restart=on-failure` and
    trips StartLimitBurst, leaving the unit stuck in "start request repeated too
    quickly". Without a reset-failed that lockout survives the purge and poisons
    the *next* fresh fixture's `enable` (it never reaches active). reset-failed
    is idempotent and harmless when the unit is already clean.

    Timeout is 120s because VM workloads run ExecStop (workload-vm-shutdown)
    which sends ACPI power-off and blocks up to 80s waiting for the guest.
    The VM may have just restarted (e.g. after rollback), so a generous timeout
    avoids a spurious teardown ERROR when the stop is simply slow.
    """
    # WLRT_KEEP_VM: leave the workload in place so a failed run can be inspected
    # live. Safe because reset_vm reverts the guest to `base` at the next test's
    # setup anyway, so skipping this cleanup never leaks state into another test.
    if os.environ.get("WLRT_KEEP_VM"):
        print(f"[WLRT_KEEP_VM] skipping purge of {name} — left in place for inspection")
        return
    target.wl(f"disable --purge {name}", check=False, timeout=120)
    time.sleep(1)
    target.run(
        ["systemctl", "reset-failed", f"workload-{name}.service"],
        sudo=True, check=False,
    )
    target.run(
        ["rm", "-rf", f"/etc/workloads.d/{name}"],
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
        ["rm", "-rf", f"/etc/workloads.d/{name}"],
        sudo=True, check=False,
    )


# ---------------------------------------------------------------------------
# VM workload fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def clitest_vm(target: Target):
    """Shared VM workload on the managed NAT bridge (_workload-br).

    Provisioned ONCE per session and reused by every *read-only* VM test
    (introspection, exec, logs, stats, images, …). Mirrors the wording and
    intent of the session-scoped container fixtures above. Mutating VM tests
    (backup, update/rollback) must use the fresh_vm fixture below instead.

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
def fresh_vm(target: Target):
    """Fresh, isolated VM per test, for mutating VM tests (backup, update/rollback).

    A brand-new VM workload instance backed by clitest-vm-fresh.toml
    (workload name clitest-vm-fresh). Uses the same managed NAT bridge
    (_workload-br) as clitest_vm but with a distinct name, so both can
    coexist within one session without colliding.
    """
    skip_if_no_kvm(target)
    name = _install_toml(target, "clitest-vm-fresh.toml")
    try:
        _enable_workload(target, name, timeout=600, expect_container=False)
        time.sleep(30)
    except Exception:
        _purge_workload(target, name)
        raise
    yield name
    _purge_workload(target, name)


@pytest.fixture(scope="module")
def clitest_vm_lifecycle(target: Target):
    """Shared module-scoped VM for the four mutating lifecycle tests in test_lifecycle.py.

    Booted ONCE per module (stop/start/recreate/reboot tests all share it),
    saving ~3 VM boots vs. per-test fresh_vm.  Backed by
    clitest-vm-lifecycle.toml (distinct name → distinct DHCP/MAC so it can
    coexist on _workload-br with clitest_vm and clitest-vm-fresh).

    Module scope means this fixture is provisioned the first time any lifecycle
    VM test runs and torn down after the last one in that module finishes —
    isolated from the session-scoped read-only clitest_vm and from fresh_vm.
    """
    skip_if_no_kvm(target)
    name = _install_toml(target, "clitest-vm-lifecycle.toml")
    try:
        _enable_workload(target, name, timeout=600, expect_container=False)
        # Extra settle time: cloud-init still running after systemd sees active
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
