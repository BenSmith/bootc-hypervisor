"""
test_runtime_vm_restart.py — O6 runtime proof: `[vm].restart = "on-reboot"`
distinguishes a guest reboot from a guest poweroff on a real boot.

QEMU runs `-no-reboot`, so both a guest reboot and a guest poweroff make the
process exit — the two are only distinguishable by the QMP `SHUTDOWN` event
`reason` (`guest-reset` vs `guest-shutdown`). The notify wrapper watches that on
a dedicated `qmp-notify.sock` and exits `VM_REBOOT_EXIT_CODE` (133) on a reboot
vs 0 on a poweroff; the unit uses `Restart=on-failure`, so a reboot relaunches
while a poweroff stays down.

Unit tests prove the generator wires the socket + env + Restart directive in
on-reboot mode. What they can't prove is that real QEMU actually emits the two
distinct SHUTDOWN reasons and that the wrapper's exit-code translation produces
the intended systemd behavior end-to-end. That's this proof:

  1. Guest reboot → the workload service stays up and the guest comes back with a
     *different* boot_id (it genuinely cycled, not just kept running).
  2. Guest poweroff → the workload service goes inactive and *stays* down.

Same gates + nested-KVM shape as test_runtime_vm_smoke.py: default-safe skips
without nested /dev/kvm or the VM toolchain (runs under gate mode).
"""

import time

import pytest

from fixtures import (
    dump_journal, unit_state,
    _install_toml, _purge_workload, _enable_workload,
    guest_boot_id, poll_vm_reachable, skip_if_no_kvm, skip_if_no_vm_toolchain,
)

pytestmark = [pytest.mark.runtime, pytest.mark.slow]

WORKLOAD = "rt-vm-reboot"
SERVICE = f"workload-{WORKLOAD}.service"


def _trigger_guest(target, name, verb):
    """Issue `systemctl reboot`/`poweroff` inside the guest, detached.

    systemd-run detaches from this SSH session so tearing the guest down doesn't
    make the exec itself report failure (and, for reboot, so the QEMU process can
    exit cleanly under -no-reboot without the session hanging).
    """
    target.wl_exec(
        name, ["sudo", "systemd-run", "--collect", f"--unit={name}-{verb}",
               "systemctl", verb],
        sudo=True, check=True, timeout=60,
    )


def test_vm_restart_on_reboot_cycles_but_poweroff_stays_down(target):
    skip_if_no_kvm(target)
    skip_if_no_vm_toolchain(target)

    _install_toml(target, "rt-vm-reboot.toml")
    try:
        try:
            _enable_workload(target, WORKLOAD, timeout=900, expect_container=False)
        except Exception:
            dump_journal(target, WORKLOAD)
            raise

        # Deploy-time guard: before exercising the runtime behavior, confirm the
        # *deployed* unit actually carries on-reboot's shape. This localizes a
        # failure — if the generator or the enable path didn't apply
        # restart=on-reboot, the live unit is the default Restart=always and the
        # reboot/poweroff dance below would be meaningless. Read the unit off the
        # guest and assert on-failure + the reboot-exit env are present.
        unit_path = f"/run/systemd/system/{SERVICE}"
        deployed_unit = target.read(unit_path)
        assert "Restart=on-failure" in deployed_unit and "Restart=always" not in deployed_unit, (
            f"deployed {SERVICE} has the wrong Restart directive — restart=on-reboot "
            f"was not applied at enable time (this is the O6 generation/enable path, "
            f"not the wrapper). Unit:\n{deployed_unit}"
        )
        assert "WORKLOADCTL_VM_REBOOT_EXIT=133" in deployed_unit, (
            f"deployed {SERVICE} is missing the reboot-exit env that arms the "
            f"wrapper's reason detection — restart=on-reboot not fully applied. "
            f"Unit:\n{deployed_unit}"
        )

        # Reachable + capture the pre-reboot boot_id.
        first = poll_vm_reachable(target, WORKLOAD, token="rt-reboot-up", timeout=300)
        if not (first and first.rc == 0 and "rt-reboot-up" in first.stdout):
            dump_journal(target, WORKLOAD)
        assert first is not None and first.rc == 0 and "rt-reboot-up" in first.stdout, (
            f"VM never became reachable before reboot (last rc="
            f"{None if first is None else first.rc})"
        )
        boot_id_before = guest_boot_id(target, WORKLOAD)

        # (1) Guest reboot: -no-reboot exits QEMU, QMP reason=guest-reset →
        # wrapper exits 133 → Restart=on-failure relaunches. Prove it by the
        # service coming back reachable with a *different* boot_id.
        _trigger_guest(target, WORKLOAD, "reboot")

        deadline = time.monotonic() + 420
        boot_id_after = None
        while time.monotonic() < deadline:
            # check=False: the guest is unreachable while it cycles, which is
            # the expected state here, not a failure.
            current = guest_boot_id(target, WORKLOAD, check=False)
            if current and current != boot_id_before:
                boot_id_after = current
                break
            time.sleep(10)

        if boot_id_after is None:
            dump_journal(target, WORKLOAD)
        assert boot_id_after is not None, (
            "VM never came back with a new boot_id after a guest reboot — "
            "on-reboot did not relaunch the VM (boot_id stayed "
            f"{boot_id_before!r})"
        )
        assert unit_state(target, SERVICE) == "active", (
            f"{SERVICE} is not active after the guest reboot cycle"
        )

        # (2) Guest poweroff: QMP reason=guest-shutdown → wrapper exits 0 →
        # Restart=on-failure does NOT relaunch. Prove the service goes down and
        # stays down.
        _trigger_guest(target, WORKLOAD, "poweroff")

        deadline = time.monotonic() + 180
        went_down = False
        while time.monotonic() < deadline:
            if unit_state(target, SERVICE) != "active":
                went_down = True
                break
            time.sleep(5)

        if not went_down:
            dump_journal(target, WORKLOAD)
        assert went_down, (
            f"{SERVICE} stayed active after a guest poweroff — on-reboot wrongly "
            "relaunched a powered-off VM"
        )

        # And it must *stay* down (no delayed relaunch).
        time.sleep(30)
        state = unit_state(target, SERVICE)
        if state == "active":
            dump_journal(target, WORKLOAD)
        assert state != "active", (
            f"{SERVICE} relaunched after a guest poweroff (state={state!r}) — "
            "poweroff must stay down under restart=on-reboot"
        )
    finally:
        _purge_workload(target, WORKLOAD)
