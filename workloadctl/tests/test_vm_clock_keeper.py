#!/usr/bin/env python3
"""The clock keeper: workload-<name>-clock.timer, its service, and the tick.

The keeper is the half of the guest-clock remedy that owes nothing to the
egress inspector. vm_clock.py's header says why there are two halves; this
file holds what the keeper's half must be:

  * every VM gets one, behind no predicate -- a bridged VM with open egress
    has the same rewound clock after a pause and no inspector to repair it;
  * it stops with the VM and never holds the VM up: PartOf=/After= from the
    timer, Wants= from the VM, Requires= from neither;
  * it ticks on a monotonic period, so a host resumed from suspend is
    repaired within one period of coming back;
  * one tick says something only when it did something, and exits 1 only
    when it reached the agent and could not set the clock.

test_vm_clock.py owns the check itself (offset, threshold, the two protocol
facts). This file owns what wraps it.
"""

import io
import unittest
from unittest import mock

from tests import load_script
import gen_vm
import vm_clock
from config_parser import SOCKET_DIR
from nft_constants import SIDECAR_SLICE

CONFIG = {"workload": {"name": "web"}, "vm": {"network": {}}}
_MOD = None


def _keeper():
    global _MOD
    if _MOD is None:
        _MOD = load_script("libexec/workload-vm-clock")
    return _MOD


class TestTheTimer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.lines = gen_vm.generate_vm_clock_timer(CONFIG).splitlines()

    def test_it_ticks_on_the_keeper_period_and_not_a_calendar(self):
        """OnUnitActiveSec= counts on CLOCK_MONOTONIC, which stands still
        through a host suspend -- so a resumed host ticks within one period.
        A calendar timer would fire every VM's keeper at :00 together."""
        period = f"{vm_clock.CLOCK_KEEPER_PERIOD_SECONDS}s"
        self.assertIn(f"OnUnitActiveSec={period}", self.lines)
        self.assertIn(f"OnActiveSec={period}", self.lines)
        self.assertFalse([l for l in self.lines if l.startswith("OnCalendar")])

    def test_the_accuracy_is_tighter_than_the_period(self):
        """The default AccuracySec= is a minute. On a one-minute period that
        is a tick anywhere from one to two minutes after the last, which
        is not the window the period promises."""
        self.assertIn("AccuracySec=5s", self.lines)

    def test_it_stops_with_the_vm_and_starts_after_it(self):
        self.assertIn("PartOf=workload-web.service", self.lines)
        self.assertIn("After=workload-web.service", self.lines)

    def test_it_is_not_installed_on_its_own(self):
        """No [Install] and no WantedBy=timers.target: the VM pulls it in,
        so a VM that is disabled leaves no timer ticking at a socket that
        will never exist."""
        self.assertNotIn("[Install]", self.lines)
        self.assertFalse([l for l in self.lines if l.startswith("WantedBy")])


class TestTheService(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.text = gen_vm.generate_vm_clock_service(CONFIG, "_wl-web")
        cls.lines = cls.text.splitlines()

    def test_it_is_a_oneshot_running_the_keeper_as_the_workload_user(self):
        self.assertIn("Type=oneshot", self.lines)
        self.assertIn("User=_wl-web", self.lines)
        self.assertIn("Group=_wl-web", self.lines)
        self.assertIn(f'ExecStart={vm_clock.VM_CLOCK_KEEPER_BIN} "web"',
                      self.lines)

    def test_a_missing_agent_socket_skips_the_tick_rather_than_failing_it(self):
        """A tick that lands while the VM is between stops has no socket to
        dial. That is not a keeper fault, and a Condition is the difference
        between a skipped unit and a failed one in `systemctl --failed`."""
        self.assertIn(f"ConditionPathExists={SOCKET_DIR}/web/ga.sock",
                      self.lines)

    def test_it_runs_in_the_sidecar_sandbox_with_only_af_unix(self):
        """The agent channel is a unix socket and nothing else is opened. A
        keeper that could open an inet socket is one that could be made to;
        the responder keeps AF_INET because it has listeners, this has none."""
        self.assertIn("RestrictAddressFamilies=AF_UNIX", self.lines)
        self.assertIn("ProtectSystem=strict", self.lines)
        self.assertIn("CapabilityBoundingSet=", self.lines)
        self.assertIn(f"Slice={SIDECAR_SLICE}", self.lines)

    def test_the_socket_directory_is_writable_because_connect_needs_it(self):
        """connect() on a unix socket is a write on its node, and under
        ProtectSystem=strict /run is read-only until named back."""
        self.assertIn(f'ReadWritePaths="{SOCKET_DIR}/web"', self.lines)

    def test_it_stops_with_the_vm(self):
        self.assertIn("PartOf=workload-web.service", self.lines)
        self.assertIn("After=workload-web.service", self.lines)

    def test_no_new_privileges_is_absent(self):
        """The domain transition from init_t is refused under NNP with a bare
        203/EXEC. harden_sidecar's docstring carries the measurement; this
        asserts a later hardening pass does not add it back here."""
        self.assertNotIn("NoNewPrivileges", self.text)
        self.assertNotIn("DynamicUser", self.text)


class TestTheVmPullsItIn(unittest.TestCase):

    def test_the_vm_wants_the_timer_and_does_not_require_it(self):
        """Wants=, so a keeper that cannot start is a keeper that is not
        running and not a VM that will not boot. The keeper repairs a
        condition the VM can live with for an hour; the VM being down is
        not that."""
        text = gen_vm.generate_vm_service(CONFIG, "_wl-web", 10000)
        lines = text.splitlines()
        self.assertIn("Wants=workload-web-clock.timer", lines)
        requires = [l for l in lines if l.startswith("Requires=")]
        self.assertTrue(requires)
        self.assertNotIn("clock", " ".join(requires))

    def test_a_bridged_vm_has_one_too(self):
        """No predicate. The inspector's remedy is gated on inspection; the
        keeper exists precisely for the VMs that gate excludes."""
        bridged = {"workload": {"name": "web"},
                   "vm": {"network": {"bridge": "br0"}}}
        lines = gen_vm.generate_vm_service(bridged, "_wl-web", 10000).splitlines()
        self.assertIn("Wants=workload-web-clock.timer", lines)


class TestOneTick(unittest.TestCase):
    """The helper's main(), against keep_guest_clock patched at the seam."""

    def _tick(self, outcome, offset):
        keeper = _keeper()
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(keeper, "keep_guest_clock",
                               return_value=(outcome, offset)), \
                mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
            code = keeper.main(["workload-vm-clock", "web"])
        return code, out.getvalue(), err.getvalue()

    def test_a_healthy_clock_says_nothing(self):
        """Every tick but one in a year. A line per tick is a journal that
        says nothing by saying the same thing forever."""
        self.assertEqual(self._tick(vm_clock.CLOCK_OK, 0.02), (0, "", ""))

    def test_a_guest_with_no_agent_says_nothing_and_does_not_fail(self):
        """A supported configuration, reported once by the inspector's
        `remedy_unavailable` rather than once a minute here."""
        self.assertEqual(self._tick(vm_clock.CLOCK_UNAVAILABLE, None),
                         (0, "", ""))

    def test_a_resync_is_one_line_carrying_the_offset(self):
        code, out, err = self._tick(vm_clock.CLOCK_RESYNCED, -7199.98)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.count("\n"), 1)
        self.assertIn("-7200.0s", out)
        self.assertIn("'web'", out)

    def test_a_failed_resync_is_the_only_failing_exit(self):
        code, out, err = self._tick(vm_clock.CLOCK_FAILED, 400.0)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("+400.0s", err)
        self.assertIn("guest-set-time failed", err)

    def test_usage(self):
        keeper = _keeper()
        with mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(keeper.main(["workload-vm-clock"]), 2)

    def test_the_tick_uses_the_keeper_threshold_and_not_backups(self):
        """The default, which is CLOCK_SKEW_THRESHOLD_SECONDS. backup's
        one-second threshold is for a pause it knows the length of; a
        periodic tick knows nothing and must not chase ordinary drift."""
        keeper = _keeper()
        with mock.patch.object(keeper, "keep_guest_clock",
                               return_value=(vm_clock.CLOCK_OK, 0.0)) as keep, \
                mock.patch("sys.stdout", io.StringIO()):
            keeper.main(["workload-vm-clock", "web"])
        self.assertEqual(keep.call_args.kwargs, {})


class TestKeepGuestClock(unittest.TestCase):
    """The number comes out with the word, and the word alone still does."""

    def test_the_offset_is_reported_with_every_outcome_that_measured_one(self):
        with mock.patch.object(vm_clock, "guest_clock_offset",
                               return_value=-7200.0), \
                mock.patch.object(vm_clock, "set_guest_time",
                                  return_value=True):
            self.assertEqual(vm_clock.keep_guest_clock("wl"),
                             (vm_clock.CLOCK_RESYNCED, -7200.0))
        with mock.patch.object(vm_clock, "guest_clock_offset",
                               return_value=1.5):
            self.assertEqual(vm_clock.keep_guest_clock("wl"),
                             (vm_clock.CLOCK_OK, 1.5))
        with mock.patch.object(vm_clock, "guest_clock_offset",
                               return_value=None):
            self.assertEqual(vm_clock.keep_guest_clock("wl"),
                             (vm_clock.CLOCK_UNAVAILABLE, None))

    def test_resync_guest_clock_if_skewed_is_the_word_alone(self):
        with mock.patch.object(vm_clock, "keep_guest_clock",
                               return_value=(vm_clock.CLOCK_RESYNCED, -9.0)) as keep:
            self.assertEqual(
                vm_clock.resync_guest_clock_if_skewed("wl", threshold=1.0),
                vm_clock.CLOCK_RESYNCED)
        self.assertEqual(keep.call_args.kwargs, {"threshold": 1.0})


if __name__ == "__main__":
    unittest.main()
