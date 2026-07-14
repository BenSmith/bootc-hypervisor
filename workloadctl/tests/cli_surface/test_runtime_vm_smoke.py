"""
test_runtime_vm_smoke.py — B6 runtime check: a `[vm]` workload boots and is
reachable on a real (nested) kernel.

The VM substrate has plenty of unit-file / CLI-surface coverage (clitest_vm
fixture, test_exec_vm, the VM lifecycle cases), but none of it proves the raw
QEMU/KVM path end-to-end on a booted host: disk build → OVMF/UEFI boot →
cloud-init (sshd + workload user + per-workload key) → the VM actually reachable
over SSH. That needs a real kernel with KVM — and here it's *nested*: this VM
runs inside the runtime harness guest.

Two gates, both default-safe skips:
  - nested `/dev/kvm` — false inside a non-nested guest (most laptops, the
    Forgejo container runner), so this skips cleanly and passes.
  - the VM toolchain (qemu/OVMF/socat) — baked into the *hypervisor image*, not
    the workloadctl RPM. So this really runs under **gate mode** (the booted
    bootc image, e.g. on tp); under the bare dev cloud image it skips.

Marked `runtime` + `slow`: only under `--target=vm:<mode>` (`just test-runtime`),
and it's the heaviest single check (nested boot + first-run cloud-image fetch).
"""

import time

import pytest

from fixtures import (
    dump_journal,
    _enable_workload, _install_toml, _purge_workload,
    skip_if_no_kvm, skip_if_no_vm_toolchain,
)

pytestmark = [pytest.mark.runtime, pytest.mark.slow]

WORKLOAD = "rt-vm"
SERVICE = f"workload-{WORKLOAD}.service"


def test_vm_workload_boots_and_is_reachable(target):
    """Enable a tiny [vm] workload, wait for its service to go active, then prove
    the guest is genuinely up by exec'ing a command over SSH."""
    # Nested KVM only: /dev/kvm must exist *inside* the harness guest. Absent on
    # non-nested hosts → clean skip (the mandatory default-safe path for B6).
    skip_if_no_kvm(target)
    # The VM toolchain (qemu/OVMF/socat) ships in the hypervisor image, not the
    # RPM — so this runs under gate mode and skips under the bare dev cloud image.
    skip_if_no_vm_toolchain(target)

    _install_toml(target, "rt-vm.toml")
    try:
        # First enable builds the system disk and fetches the cloud image, then
        # boots + runs cloud-init; VMs have no container to wait on. Generous
        # timeout: nested boot + a possible cold image download.
        try:
            _enable_workload(target, WORKLOAD, timeout=900, expect_container=False)
        except Exception:
            dump_journal(target, WORKLOAD)
            raise

        # The VM service is active.
        r = target.run(["systemctl", "is-active", SERVICE], sudo=False, check=False)
        if r.stdout.strip() != "active":
            dump_journal(target, WORKLOAD)
        assert r.stdout.strip() == "active", (
            f"{SERVICE} is {r.stdout.strip()!r}, expected active"
        )

        # Reachability: `workloadctl exec` goes over SSH to the guest. cloud-init
        # (sshd start + key injection) can lag the service going active, so poll
        # exec until it succeeds or we give up.
        deadline = time.monotonic() + 300
        last = None
        while time.monotonic() < deadline:
            last = target.wl_exec(WORKLOAD, "echo rt-vm-reachable",
                                  sudo=True, check=False, timeout=60)
            if last.rc == 0 and "rt-vm-reachable" in last.stdout:
                break
            time.sleep(10)
        if not (last and last.rc == 0 and "rt-vm-reachable" in last.stdout):
            dump_journal(target, WORKLOAD)
        assert last is not None and last.rc == 0 and "rt-vm-reachable" in last.stdout, (
            f"`workloadctl exec {WORKLOAD}` never reached the guest over SSH "
            f"within 300s (last rc={None if last is None else last.rc}):\n"
            f"{'' if last is None else last.stdout}\n{'' if last is None else last.stderr}"
        )
    finally:
        _purge_workload(target, WORKLOAD)

    # Purge removed the VM service.
    r = target.run(["test", "-e", f"/run/systemd/system/{SERVICE}"], sudo=False, check=False)
    assert r.rc != 0, f"/run/systemd/system/{SERVICE} still present after purge"
