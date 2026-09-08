#!/usr/bin/env python3
"""The guest-side paravirtual clock seed (ptp_kvm).

Split out of vm.py, where it sat between the transparent redirect's nftables
elements and the per-workload egress CA and shared nothing with either: this
block reaches the guest as cloud-init text and never touches a socket, a
packet or a file on the host. It is data with a long explanation attached,
which is exactly the shape that gets skipped when it is buried mid-file.

Nothing here imports vm; vm imports this and re-exports every public name, so
no caller changed. lib/vm_clock.py is the host-side half of the same remedy --
see the comment below for why neither replaces the other -- and it is NOT this
module's home, because it imports vm and taking these names there would make
the cycle.

Installed to /usr/libexec/workloadctl/vm_ptp.py.
"""

# The guest-side half of the remedy whose host-side half is lib/vm_clock. Both
# exist for the same failure -- a vCPU pause is lost by the guest exactly and
# permanently, and NTP cannot repair it -- and they fail in opposite directions,
# which is why neither replaces the other. The host's check repairs a guest that
# has no idea anything happened, but only on a mint cache miss and only if the
# guest runs qemu-guest-agent. This repairs the guest on its own four-second
# poll with no agent and no host involvement, but only if the guest was seeded
# with it. A guest that has both is repaired before anything asks it to be.
#
# NOTHING IS NEEDED ON THE HOST. ptp_kvm is not a QEMU device and takes no
# argument: on x86_64 the guest driver issues a KVM hypercall (KVM_HC_CLOCK_
# PAIRING) that pairs its TSC with the host's realtime clock, and on aarch64 an
# equivalent SMCCC call. Everything it needs is already implied by the
# `-machine q35,accel=kvm -cpu host` the generator emits. That is the whole
# reason to prefer it over a host NTP server the guests dial: it is the only
# correction path that survives the egress filter, because it sends no packets.
#
# What IS required of the host is a condition rather than a setting, and it is
# the one that catches people: the host's own clocksource must be the TSC. KVM
# answers the clock-pairing hypercall EOPNOTSUPP otherwise, so on a host running
# hpet or acpi_pm the module refuses to load in every guest, however correct
# the seed below is: the device simply never appears. Such a guest keeps its stock time configuration and is covered by
# lib/vm_clock's host-side check alone.
#
# THREE PIECES, AND THE LEAST OBVIOUS ONE IS LOAD-BEARING
#
#   - the module, which no cloud image loads on its own;
#   - a stable name for the device. /dev/ptpN is allocation-ordered, so a guest
#     with a PTP-capable NIC or a passed-through device can put the KVM clock on
#     ptp1. The rule below selects on the driver's own clock_name, which is the
#     only selector that cannot be reordered;
#   - `makestep 1 -1`, which is the piece that actually fixes the bug. Fedora's
#     stock chrony.conf says `makestep 1.0 3`: step for the first three updates,
#     slew forever after. Slewing is capped near 83 us/s, so a two-hour rewind
#     would take months to walk off -- the
#     guest would spend all of it inside the window where new leaves fail to
#     validate. `-1` means "step whenever the offset exceeds a second, always",
#     which is right here and would be wrong on a public NTP client, where an
#     unconditional step is a thing an attacker can aim.
#
# The chrony half is written by runcmd rather than write_files BECAUSE IT IS
# CONDITIONAL. chronyd treats a refclock it cannot open as fatal, so a seed that
# unconditionally appends the refclock line would leave a guest on a host
# without ptp_kvm with no time service at all -- trading a clock that is wrong
# after a pause for a clock that is unmanaged always.
VM_PTP_KVM_MODULE = "ptp_kvm"
VM_PTP_KVM_CLOCK_NAME = "KVM virtual PTP"
VM_PTP_KVM_DEVICE = "/dev/ptp_kvm"
VM_PTP_KVM_MODULES_LOAD_PATH = "/etc/modules-load.d/ptp-kvm.conf"
VM_PTP_KVM_UDEV_RULE_PATH = "/etc/udev/rules.d/70-ptp-kvm.rules"
VM_PTP_KVM_CHRONY_PATH = "/etc/chrony.conf"

# The marker the runcmd block greps for before appending. Idempotence matters
# even though cloud-init runs runcmd once per instance id, because the id
# rotates whenever the seed's text changes -- so any later edit to the seed
# replays this block on a guest that already has the lines.
VM_PTP_KVM_CHRONY_MARKER = "# workloadctl: paravirtual clock"


def vm_ptp_kvm_seed_files() -> list[tuple[str, str, str]]:
    """(path, permissions, content) for the seed's write_files entries."""
    return [
        (VM_PTP_KVM_MODULES_LOAD_PATH, "0644", f"{VM_PTP_KVM_MODULE}\n"),
        (VM_PTP_KVM_UDEV_RULE_PATH, "0644",
         f'SUBSYSTEM=="ptp", ATTR{{clock_name}}=="{VM_PTP_KVM_CLOCK_NAME}", '
         f'SYMLINK+="{VM_PTP_KVM_DEVICE.removeprefix("/dev/")}"\n'),
    ]


def vm_ptp_kvm_runcmd_lines() -> list[str]:
    """The shell that loads the module and points chrony at it, if it is there.

    Returned as lines rather than spelled into the renderer so the built-in
    seed, the shipped reference seeds and the tests assert against one text.
    """
    return [
        "udevadm control --reload-rules || true",
        # The wait is bounded and only happens when the module actually loaded.
        # `udevadm settle` was here and is not enough on its own: it can return
        # before a just-queued uevent is visible, and the symptom of losing that
        # race is indistinguishable from the host not supporting ptp_kvm at all.
        # Gating on modprobe's exit status is also what keeps the wait off the
        # boot of a guest on a host that cannot offer the clock, where the
        # module fails immediately and no amount of waiting would help.
        f"if modprobe {VM_PTP_KVM_MODULE} 2>/dev/null; then",
        f"  for _ in 1 2 3 4 5; do [ -e {VM_PTP_KVM_DEVICE} ] && break;"
        f" sleep 1; done",
        "fi",
        # `-f` before the grep, and it is not belt-and-braces: grep on a
        # missing file exits 2, which `!` turns into true, so without it a
        # guest whose image ships no chrony at all gets a /etc/chrony.conf
        # CREATED here holding a refclock and nothing else -- a config file
        # for a service that is not installed, which reads to the next person
        # as a chrony that is configured and broken rather than absent.
        f"if [ -e {VM_PTP_KVM_DEVICE} ] && [ -f {VM_PTP_KVM_CHRONY_PATH} ] &&"
        f" ! grep -qF '{VM_PTP_KVM_CHRONY_MARKER}' {VM_PTP_KVM_CHRONY_PATH}; then",
        f"  printf '%s\\n' '{VM_PTP_KVM_CHRONY_MARKER}'"
        f" 'refclock PHC {VM_PTP_KVM_DEVICE} poll 2 dpoll -2 offset 0'"
        f" 'makestep 1 -1' >> {VM_PTP_KVM_CHRONY_PATH}",
        "  systemctl restart chronyd || true",
        "fi",
    ]
