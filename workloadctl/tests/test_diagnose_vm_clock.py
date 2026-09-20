"""diagnose's guest-clock line: the one place a guest the keeper cannot
reach is reported.

The keeper is silent about an unreachable guest by design (once a minute,
forever, is not a report), and the inspector no longer counts it (the mint
path stopped asking about the guest's clock when the keeper arrived). So
`diagnose` asks once, when an operator does, and this is what the answer
must say.
"""
import unittest
from unittest import mock

import diagnose_battery
import vm_clock
from diagnose_vm_clock import vm_guest_clock_check


class TestTheVerdict(unittest.TestCase):

    def test_no_answer_fails_and_names_the_guest_side_fix(self):
        """The guest's problem, so the fix is in the guest: an operator sent
        to the timer would find it ticking and skipping, correctly."""
        passed, message, fix = vm_guest_clock_check(None, "web")
        self.assertFalse(passed)
        self.assertIn("guest agent does not answer", message)
        self.assertIn("qemu-guest-agent", fix)
        self.assertNotIn("clock.timer", fix)

    def test_a_healthy_clock_passes_with_the_number(self):
        passed, message, fix = vm_guest_clock_check(-0.37, "web")
        self.assertTrue(passed)
        self.assertIn("0.4s", message)
        self.assertIsNone(fix)

    def test_skew_past_the_keepers_threshold_fails_and_names_the_timer(self):
        """The host's problem: the keeper should have acted. Same threshold
        as the keeper's, so the line is red exactly where a tick would set
        the clock, and green wherever a tick would leave it."""
        passed, message, fix = vm_guest_clock_check(-7200.0, "web")
        self.assertFalse(passed)
        self.assertIn("-7200.0s", message)
        self.assertIn("workload-web-clock.timer", fix)

    def test_the_threshold_is_the_keepers(self):
        edge = vm_clock.CLOCK_SKEW_THRESHOLD_SECONDS
        self.assertTrue(vm_guest_clock_check(edge, "web")[0])
        self.assertTrue(vm_guest_clock_check(-edge, "web")[0])
        self.assertFalse(vm_guest_clock_check(edge + 0.5, "web")[0])
        self.assertFalse(vm_guest_clock_check(-edge - 0.5, "web")[0])


class TestTheBatteryAsksOnce(unittest.TestCase):

    def _run(self, active, offset):
        checks = []

        def _check(name, passed, message, fix=None):
            checks.append((name, passed, message, fix))

        config = mock.Mock(name_="web", service_name="workload-web.service")
        config.name = "web"
        with mock.patch.object(diagnose_battery, "service_active",
                               return_value=(active, "active" if active
                                             else "inactive")), \
                mock.patch.object(diagnose_battery, "guest_clock_offset",
                                  return_value=offset) as ask:
            diagnose_battery._vm_clock_check(config, _check)
        return checks, ask

    def test_a_running_vm_gets_one_round_trip_and_one_line(self):
        checks, ask = self._run(True, 1.5)
        self.assertEqual(ask.call_count, 1)
        self.assertEqual([c[0] for c in checks], ["vm_guest_clock"])
        self.assertTrue(checks[0][1])

    def test_a_stopped_vm_is_not_asked_and_gets_no_line(self):
        """No agent to ask and no clock to be wrong. An absent line, not a
        verdict about nothing."""
        checks, ask = self._run(False, None)
        self.assertEqual(ask.call_count, 0)
        self.assertEqual(checks, [])

    def test_it_reads_and_never_sets(self):
        """The keeper repairs; diagnose reports. A diagnose that set the
        clock would be a second writer of the thing it checks."""
        with mock.patch.object(vm_clock, "set_guest_time") as setter:
            self._run(True, -7200.0)
        self.assertEqual(setter.call_count, 0)


if __name__ == "__main__":
    unittest.main()
