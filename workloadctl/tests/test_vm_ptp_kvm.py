"""The guest's paravirtual clock: what the seed must carry, and why each piece.

A vCPU pause is lost by the guest exactly and permanently (lib/vm_clock.py has
the measurements). The host repairs that on the egress inspector's mint path;
this is the other half, which repairs the guest from inside, on its own poll,
with no agent and no packets. Neither covers the other's blind spot, so both
ship.

Every assertion here guards a failure that is silent by construction. A guest
whose clock quietly stops being corrected boots, logs in, passes every health
check and reaches every host it has already visited -- it fails only on names
whose leaves are not yet cached, and only after something paused it. Nothing in
the test suite or the runtime rung would notice, which is why the wiring is
pinned here rather than left to the seeds.
"""

import re
import unittest
from pathlib import Path

from tests import REPO_ROOT, load_script
from vm import (
    VM_PTP_KVM_CHRONY_MARKER, VM_PTP_KVM_CHRONY_PATH, VM_PTP_KVM_CLOCK_NAME,
    VM_PTP_KVM_DEVICE, VM_PTP_KVM_MODULE, VM_PTP_KVM_MODULES_LOAD_PATH,
    VM_PTP_KVM_UDEV_RULE_PATH, vm_ptp_kvm_runcmd_lines, vm_ptp_kvm_seed_files,
)

BUNDLES = REPO_ROOT / "workloads"


def _uncommented(text):
    """`text` with its comment lines removed.

    THE SAME BLINDNESS THE SEED CONTRACTS HAD. A shipped seed is what an
    operator copies, and vm-base carries one recipe LIVE (this one) beside
    another COMMENTED OUT (the egress CA, which must not install an empty
    anchor in an `egress = "open"` bundle) -- so the two are one editing
    mistake apart, and a substring assertion over the raw text cannot tell
    them apart. libexec/workload-ensure-user strips comments for exactly this
    reason before its own substring pins; a gate written to catch drift in
    those seeds has to see them the way cloud-init does.
    """
    return "\n".join(line for line in text.splitlines()
                      if not line.lstrip().startswith("#"))


def _seeds():
    """Every shipped bundle seed, as (bundle name, LIVE text)."""
    return [(p.parent.parent.name, _uncommented(p.read_text()))
            for p in sorted(BUNDLES.glob("*/cloud-init/user-data"))]


def _built_in_seed(**kwargs):
    mod = load_script("libexec/workload-ensure-user")
    args = dict(name="myvm", guest_user="fedora", pubkey="ssh-ed25519 AAAA",
                mounts=[], has_data_disk=False)
    args.update(kwargs)
    return mod._render_default_user_data(**args)


class TestTheDeviceIsSelectedByName(unittest.TestCase):
    """/dev/ptpN is allocation-ordered; the driver's clock_name is not.

    A guest with a PTP-capable NIC, or one passed through, can land the KVM
    clock on ptp1 -- and a seed pinned to ptp0 then points chrony at a clock
    belonging to something else, which is worse than pointing it at nothing.
    """

    def test_the_udev_rule_matches_on_clock_name(self):
        rule = dict((p, c) for p, _perm, c in vm_ptp_kvm_seed_files())[
            VM_PTP_KVM_UDEV_RULE_PATH]
        self.assertIn(f'ATTR{{clock_name}}=="{VM_PTP_KVM_CLOCK_NAME}"', rule)
        self.assertIn('SUBSYSTEM=="ptp"', rule)

    def test_no_numbered_ptp_device_is_named_anywhere(self):
        blob = "\n".join(
            [c for _p, _perm, c in vm_ptp_kvm_seed_files()]
            + vm_ptp_kvm_runcmd_lines()
            + [text for _name, text in _seeds()]
        )
        self.assertIsNone(re.search(r"/dev/ptp\d", blob),
                          "a numbered PTP device is pinned somewhere")

    def test_the_symlink_the_rule_creates_is_the_one_chrony_is_given(self):
        """The two halves are a pair; a drift makes chronyd fail to start."""
        rule = dict((p, c) for p, _perm, c in vm_ptp_kvm_seed_files())[
            VM_PTP_KVM_UDEV_RULE_PATH]
        self.assertIn(f'SYMLINK+="{VM_PTP_KVM_DEVICE.removeprefix("/dev/")}"',
                      rule)
        self.assertIn(VM_PTP_KVM_DEVICE, "\n".join(vm_ptp_kvm_runcmd_lines()))


class TestTheModuleIsLoaded(unittest.TestCase):
    """No cloud image loads ptp_kvm on its own."""

    def test_modules_load_carries_it(self):
        content = dict((p, c) for p, _perm, c in vm_ptp_kvm_seed_files())[
            VM_PTP_KVM_MODULES_LOAD_PATH]
        self.assertEqual(content.strip(), VM_PTP_KVM_MODULE)

    def test_first_boot_does_not_wait_for_a_reboot(self):
        """modules-load.d covers every boot AFTER this one.

        Without the modprobe, a freshly provisioned guest has no clock source
        until something restarts it -- and the window it spends unprotected is
        exactly the window in which an operator is most likely to snapshot it.
        """
        self.assertIn(f"modprobe {VM_PTP_KVM_MODULE}",
                      "\n".join(vm_ptp_kvm_runcmd_lines()))


class TestSteppingIsUnconditional(unittest.TestCase):
    """`makestep 1 -1` is the line that fixes the bug, not the refclock."""

    def test_the_seed_overrides_the_stock_three_update_limit(self):
        script = "\n".join(vm_ptp_kvm_runcmd_lines())
        self.assertIn("makestep 1 -1", script)

    def test_a_refclock_alone_would_not_be_enough(self):
        """Fedora ships `makestep 1.0 3`: step three times, then slew forever.

        Slewing is capped near 83 us/s, so the two-hour rewind clock_rig
        measures would take months to walk off. A seed that adds the refclock
        and leaves the stock makestep in place looks completely correct and
        repairs nothing on the timescale that matters.
        """
        script = "\n".join(vm_ptp_kvm_runcmd_lines())
        self.assertIn(f"refclock PHC {VM_PTP_KVM_DEVICE}", script)
        self.assertNotIn("makestep 1.0 3", script)


class TestTheChronyEditIsConditional(unittest.TestCase):
    """chronyd treats a refclock it cannot open as fatal.

    So an unconditional append trades "the clock is wrong after a pause" for
    "there is no time service at all" on any host without ptp_kvm -- a strictly
    worse failure, and one that would only ever show up somewhere else.
    """

    def test_the_append_is_guarded_on_the_device_existing(self):
        script = "\n".join(vm_ptp_kvm_runcmd_lines())
        self.assertIn(f"[ -e {VM_PTP_KVM_DEVICE} ]", script)
        self.assertLess(script.index(f"[ -e {VM_PTP_KVM_DEVICE} ]"),
                        script.index("refclock PHC"))

    def test_it_never_creates_a_chrony_conf_that_was_not_there(self):
        """`grep` on a missing file exits 2, which `!` reads as "not present".

        Without a `-f` test in front of it, a guest image that ships no chrony
        at all gets /etc/chrony.conf CREATED here holding a refclock and a
        makestep and nothing else -- a config file for a daemon that is not
        installed, which the next person reads as a chrony that is configured
        and broken rather than one that is absent.
        """
        script = "\n".join(vm_ptp_kvm_runcmd_lines())
        self.assertIn(f"[ -f {VM_PTP_KVM_CHRONY_PATH} ]", script)
        self.assertLess(script.index(f"[ -f {VM_PTP_KVM_CHRONY_PATH} ]"),
                        script.index(f">> {VM_PTP_KVM_CHRONY_PATH}"))

    def test_the_append_is_idempotent(self):
        """runcmd replays whenever the seed's text changes the instance id.

        Any later edit to the seed -- a new volume, a rotated CA -- rotates it,
        so a block that appends unguarded accumulates a refclock line per edit.
        """
        script = "\n".join(vm_ptp_kvm_runcmd_lines())
        self.assertIn(f"grep -qF '{VM_PTP_KVM_CHRONY_MARKER}' "
                      f"{VM_PTP_KVM_CHRONY_PATH}", script)

    def test_chrony_is_restarted_so_the_edit_takes_effect_now(self):
        script = "\n".join(vm_ptp_kvm_runcmd_lines())
        self.assertIn("systemctl restart chronyd", script)
        self.assertLess(script.index("refclock PHC"),
                        script.index("systemctl restart chronyd"))

    def test_nothing_in_the_block_is_allowed_to_fail_the_boot(self):
        """cloud-init aborts the remaining runcmd blocks on a non-zero exit.

        Every command that can fail is either suffixed `|| true` or is the
        condition of an `if`, which swallows its status by definition.
        """
        script = vm_ptp_kvm_runcmd_lines()
        for line in script:
            stripped = line.strip()
            if not stripped.startswith(("udevadm", "modprobe", "systemctl")):
                continue
            self.assertTrue(
                stripped.endswith("|| true") or stripped.startswith("if "),
                stripped)

    def test_the_device_is_waited_for_rather_than_settled_for(self):
        """`udevadm settle` can return before a just-queued uevent is visible.

        Losing that race looks exactly like the host not supporting ptp_kvm,
        which is the one failure here with a legitimate silent branch -- so the
        two must not be confusable. The wait is bounded and gated on the module
        having loaded, so a host that genuinely cannot offer the clock pays
        nothing for it.
        """
        script = "\n".join(vm_ptp_kvm_runcmd_lines())
        self.assertIn(f"if modprobe {VM_PTP_KVM_MODULE}", script)
        self.assertIn(f"[ -e {VM_PTP_KVM_DEVICE} ] && break", script)
        self.assertNotIn("udevadm settle", script)


class TestTheBuiltInSeedCarriesIt(unittest.TestCase):

    def test_every_piece_is_rendered(self):
        out = _built_in_seed()
        for path, _perm, content in vm_ptp_kvm_seed_files():
            self.assertIn(f"- path: {path}", out)
            for line in content.splitlines():
                self.assertIn(line, out)
        for line in vm_ptp_kvm_runcmd_lines():
            self.assertIn(line, out)

    def test_it_is_there_with_no_volumes_no_data_disk_and_no_ca(self):
        """The minimal VM is the one most likely to be snapshotted casually."""
        out = _built_in_seed()
        self.assertIn("runcmd:", out)
        self.assertIn(VM_PTP_KVM_MODULE, out)

    def test_the_clock_block_is_its_own_runcmd_fragment(self):
        """Separate `- |` entries, so the data disk's failure is not its own."""
        out = _built_in_seed(has_data_disk=True)
        runcmd = out[out.index("runcmd:"):]
        self.assertEqual(runcmd.count("  - |"), 2)
        self.assertLess(runcmd.index(VM_PTP_KVM_MODULE), runcmd.index("mkfs"))

    def test_the_data_disk_block_still_works(self):
        out = _built_in_seed(has_data_disk=True)
        self.assertIn("blkid /dev/vdb | grep -q TYPE || mkfs.ext4", out)
        self.assertIn("mountpoint -q /data || mount /data", out)


class TestTheShippedSeedsCarryIt(unittest.TestCase):
    """A custom user_data_file replaces the built-in seed outright.

    Nothing refuses a seed that omits the clock -- unlike the CA and the volume
    mounts, a guest without it is degraded rather than broken, and the host's
    mint-path check still repairs it. But the seeds we ship are what operators
    copy, so an omission here propagates.
    """

    def test_there_is_at_least_one_shipped_seed(self):
        self.assertTrue(_seeds(), "the glob found nothing; check the path")

    def test_each_shipped_seed_wires_the_clock(self):
        for name, text in _seeds():
            with self.subTest(bundle=name):
                self.assertIn(VM_PTP_KVM_MODULES_LOAD_PATH, text)
                self.assertIn(VM_PTP_KVM_UDEV_RULE_PATH, text)
                self.assertIn(f"refclock PHC {VM_PTP_KVM_DEVICE}", text)
                self.assertIn("makestep 1 -1", text)
                self.assertIn(f"[ -e {VM_PTP_KVM_DEVICE} ]", text)

    def test_each_shipped_seed_carries_THE_block_and_not_a_variant(self):
        """Line-for-line against vm_ptp_kvm_runcmd_lines(), not substrings.

        The assertions above establish that a seed mentions each piece; they
        do not establish that it runs the same shell. A guard added to the
        generated block -- the `-f /etc/chrony.conf` that stops a chrony-less
        guest getting a config file for a daemon it does not have -- reaches
        the built-in seed for free and reaches these copies only if somebody
        remembers. That is drift with no failing test, in files whose whole
        purpose is to be copied.
        """
        wanted = [line.strip() for line in vm_ptp_kvm_runcmd_lines()]
        for name, text in _seeds():
            with self.subTest(bundle=name):
                present = {line.strip() for line in text.splitlines()}
                missing = [line for line in wanted if line not in present]
                self.assertEqual(
                    missing, [],
                    f"{name}'s copy of the clock block has drifted from "
                    f"vm.vm_ptp_kvm_runcmd_lines()")


class TestTheHostSidePremise(unittest.TestCase):
    """ptp_kvm is a hypercall, not a device -- but it is not free of the host.

    It needs KVM acceleration and a CPU model that exposes the paravirtual
    clock. Both come from the QEMU argv the generator writes, so a change there
    silently removes every guest's ability to correct itself, with no error on
    either side.
    """

    def test_the_qemu_argv_still_enables_kvm(self):
        source = (REPO_ROOT / "generators" / "workload-generate").read_text()
        self.assertIn('"-machine q35,accel=kvm"', source)
        self.assertIn('"-cpu host"', source)

    def test_nothing_adds_a_ptp_device_to_the_argv(self):
        """If someone ever adds `-device ptp...`, this premise changed."""
        source = (REPO_ROOT / "generators" / "workload-generate").read_text()
        self.assertNotIn("ptp", source)


if __name__ == "__main__":
    unittest.main()
