"""The guest clock: reading it, repairing it, and where the repair is hooked.

WHAT THESE TESTS CAN AND CANNOT PROVE. The behaviour this unit exists for -- a
vCPU pause being lost by the guest exactly and permanently -- was established by
measurement, twice on different hardware, and lives in tests/manual/clock_rig.py
because it needs a real VM. What is unit-testable is the half that decides
whether the measured remedy is actually reached: that the offset is read from
the agent and not inferred, that only the explicit-nanoseconds form is ever
sent, that an absent agent is a non-event rather than an error, and that
`backup` resyncs after `cont` without being able to fail the backup.
"""

import inspect
import time
import unittest
from unittest import mock

import backup as backup_mod
import vm_clock


class _FakeAgent:
    """Stands in for QMPClient against the guest-agent channel."""

    def __init__(self, replies=None, *, fail_on_connect=False):
        self.replies = dict(replies or {})
        self.sent = []
        self.closed = False
        self._fail_on_connect = fail_on_connect
        self._sync_token = None

    def connect(self, path, timeout=None, recv_timeout=None):
        if self._fail_on_connect:
            raise TimeoutError("no agent")

    def execute(self, command, arguments=None, max_events=20):
        self.sent.append((command, arguments))
        if command == "guest-sync":
            return {"return": arguments["id"]}
        if command in self.replies:
            return self.replies[command]
        return {"error": {"desc": f"unsupported: {command}"}}

    def next_message(self):
        return None

    def close(self):
        self.closed = True


def _patched(agent, *, socket_exists=True):
    """Patch vm_clock's two seams: the socket's existence and the client."""
    return (
        mock.patch.object(vm_clock, "QMPClient", lambda: agent),
        mock.patch.object(vm_clock, "vm_guest_agent_socket",
                          lambda name: mock.Mock(
                              exists=lambda: socket_exists)),
    )


class _ClockCase(unittest.TestCase):

    def use(self, agent, *, socket_exists=True):
        for patcher in _patched(agent, socket_exists=socket_exists):
            patcher.start()
            self.addCleanup(patcher.stop)
        return agent


class TestReadingTheOffset(_ClockCase):

    def test_it_reports_how_far_ahead_the_guest_is(self):
        ahead = time.time() + 42
        agent = self.use(_FakeAgent(
            {"guest-get-time": {"return": int(ahead * 1_000_000_000)}}))
        self.assertAlmostEqual(vm_clock.vm_guest_clock_offset("wl"), 42,
                               delta=1)
        self.assertTrue(agent.closed)

    def test_it_reports_a_rewound_guest_as_negative(self):
        behind = time.time() - 3600
        self.use(_FakeAgent(
            {"guest-get-time": {"return": int(behind * 1_000_000_000)}}))
        self.assertAlmostEqual(vm_clock.vm_guest_clock_offset("wl"), -3600,
                               delta=1)

    def test_it_syncs_the_nonce_before_asking(self):
        # The channel outlives its clients: a previous lookup that timed out
        # after sending but before reading leaves its reply queued, and a naive
        # read would take it as the answer to a question it never asked.
        agent = self.use(_FakeAgent(
            {"guest-get-time": {"return": int(time.time() * 1e9)}}))
        vm_clock.vm_guest_clock_offset("wl")
        self.assertEqual(agent.sent[0][0], "guest-sync")

    def test_no_socket_is_not_an_error(self):
        self.use(_FakeAgent(), socket_exists=False)
        self.assertIsNone(vm_clock.vm_guest_clock_offset("wl"))

    def test_an_agent_that_never_answers_is_not_an_error(self):
        # A guest whose image lacks qemu-guest-agent is a supported
        # configuration -- QEMU accepts our connection either way, so this is
        # indistinguishable from a slow guest and must not raise.
        self.use(_FakeAgent(fail_on_connect=True))
        self.assertIsNone(vm_clock.vm_guest_clock_offset("wl"))

    def test_a_nonsense_reply_is_not_an_error(self):
        self.use(_FakeAgent({"guest-get-time": {"return": "soon"}}))
        self.assertIsNone(vm_clock.vm_guest_clock_offset("wl"))


class TestSettingTheTime(_ClockCase):

    def test_it_sends_the_explicit_nanoseconds_form(self):
        """MEASURED: the no-argument form does not work on these guests.

        It reads the guest's RTC and that read fails with `hwclock: select() to
        /dev/rtc0 to wait for clock tick timed out`. It presents as a timeout at
        the caller, which invites a retry with a longer budget that will never
        succeed. This asserts the form, because the difference is invisible in
        every other symptom.
        """
        agent = self.use(_FakeAgent({"guest-set-time": {"return": {}}}))
        self.assertTrue(vm_clock.vm_set_guest_time("wl", now=1_000.5))
        command, arguments = agent.sent[-1]
        self.assertEqual(command, "guest-set-time")
        self.assertEqual(arguments, {"time": 1_000_500_000_000})

    def test_an_error_reply_is_a_failure_not_an_exception(self):
        self.use(_FakeAgent({"guest-set-time": {"error": {"desc": "no"}}}))
        self.assertFalse(vm_clock.vm_set_guest_time("wl"))

    def test_no_agent_is_a_failure_not_an_exception(self):
        self.use(_FakeAgent(), socket_exists=False)
        self.assertFalse(vm_clock.vm_set_guest_time("wl"))


class TestTheSkewCheck(_ClockCase):
    """What the mint path calls. Three outcomes, not two -- see CLOCK_*."""

    def test_a_healthy_clock_costs_one_round_trip_and_no_repair(self):
        agent = self.use(_FakeAgent(
            {"guest-get-time": {"return": int(time.time() * 1e9)},
             "guest-set-time": {"return": {}}}))
        self.assertEqual(vm_clock.vm_resync_guest_clock_if_skewed("wl"),
                         vm_clock.CLOCK_OK)
        self.assertNotIn("guest-set-time", [c for c, _ in agent.sent])

    def test_ordinary_drift_stays_under_the_threshold(self):
        # ~10 ppm measured, so about five minutes a YEAR. The threshold is five
        # minutes precisely so drift never reaches it and a pause always does.
        self.use(_FakeAgent(
            {"guest-get-time": {"return": int((time.time() + 30) * 1e9)}}))
        self.assertEqual(vm_clock.vm_resync_guest_clock_if_skewed("wl"),
                         vm_clock.CLOCK_OK)

    def test_a_paused_guest_is_repaired(self):
        agent = self.use(_FakeAgent(
            {"guest-get-time": {"return": int((time.time() - 7200) * 1e9)},
             "guest-set-time": {"return": {}}}))
        self.assertEqual(vm_clock.vm_resync_guest_clock_if_skewed("wl"),
                         vm_clock.CLOCK_RESYNCED)
        self.assertIn("guest-set-time", [c for c, _ in agent.sent])

    def test_a_guest_with_no_agent_reports_unavailable_rather_than_ok(self):
        """The residual this rung cannot fix in code, and must not hide.

        A guest whose image lacks qemu-guest-agent silently keeps the old
        behaviour: the pause lands, nothing resyncs, and past an hour every
        minted leaf has a notBefore in the guest's future while every host-side
        figure reads healthy. Collapsing this into CLOCK_OK would erase the one
        signal `diagnose` has to report it from.
        """
        self.use(_FakeAgent(), socket_exists=False)
        self.assertEqual(vm_clock.vm_resync_guest_clock_if_skewed("wl"),
                         vm_clock.CLOCK_UNAVAILABLE)

    def test_a_repair_that_fails_is_distinguishable_from_one_not_attempted(self):
        self.use(_FakeAgent(
            {"guest-get-time": {"return": int((time.time() - 7200) * 1e9)},
             "guest-set-time": {"error": {"desc": "no"}}}))
        self.assertEqual(vm_clock.vm_resync_guest_clock_if_skewed("wl"),
                         vm_clock.CLOCK_FAILED)

    def test_the_threshold_is_inside_the_backdate(self):
        # If it were not, the guard could pass on a guest whose next leaf is
        # already invalid -- the whole failure this unit removes.
        import vm
        self.assertLess(vm_clock.VM_CLOCK_SKEW_THRESHOLD_SECONDS,
                        vm.VM_CA_BACKDATE_SECONDS)


class TestBackupResyncsAfterResuming(unittest.TestCase):
    """The one path in the tree that pauses on its own initiative.

    NOT THE REMEDY, and the tests say so: a host that suspends rewinds the same
    guest with no hook available. This narrows the window on the path we own
    from "until the next mint" to "one guest-agent round trip", which is worth
    doing at the source and worth nothing on its own.
    """

    def test_the_helper_resyncs(self):
        with mock.patch.object(backup_mod, "vm_resync_guest_clock_if_skewed",
                               return_value=vm_clock.CLOCK_RESYNCED) as resync:
            backup_mod._resync_after_pause(mock.Mock(name_="x"), quiet=True)
        self.assertEqual(resync.call_count, 1)

    def test_it_uses_its_own_threshold_and_not_the_mint_paths(self):
        """The mint path's five minutes would skip the pause this exists for.

        VM_CLOCK_SKEW_THRESHOLD_SECONDS answers a different question -- is an
        arbitrary guest far enough out to be worth a round trip on a
        connection someone is waiting for. Here the pause is ours and its
        length is whatever the copy took, which for an ordinary disk is well
        under five minutes. Left on the default, this call did nothing on the
        overwhelming majority of the backups it was written for, while its
        comment claimed the window had been narrowed to a round trip.
        """
        with mock.patch.object(backup_mod, "vm_resync_guest_clock_if_skewed",
                               return_value=vm_clock.CLOCK_OK) as resync:
            backup_mod._resync_after_pause(mock.Mock(name_="x"), quiet=True)
        threshold = resync.call_args.kwargs["threshold"]
        self.assertLess(threshold, vm_clock.VM_CLOCK_SKEW_THRESHOLD_SECONDS)
        self.assertEqual(threshold,
                         backup_mod.BACKUP_RESYNC_THRESHOLD_SECONDS)

    def test_a_two_minute_pause_is_repaired_rather_than_tolerated(self):
        """The end-to-end shape of the number above, through the real check."""
        with mock.patch.object(vm_clock, "vm_guest_clock_offset",
                               return_value=-120.0), \
             mock.patch.object(vm_clock, "vm_set_guest_time",
                               return_value=True) as setter:
            outcome = vm_clock.vm_resync_guest_clock_if_skewed(
                "wl", threshold=backup_mod.BACKUP_RESYNC_THRESHOLD_SECONDS)
        self.assertEqual(outcome, vm_clock.CLOCK_RESYNCED)
        self.assertEqual(setter.call_count, 1)

    def test_it_runs_after_cont_and_not_before(self):
        # Ordering is the whole point: resyncing a still-paused guest sets a
        # clock that the resume then leaves exactly as wrong as it was.
        source = inspect.getsource(backup_mod.backup_vm_crash)
        self.assertLess(source.index('qmp.execute("cont")'),
                        source.index("_resync_after_pause"))

    def test_it_is_inside_the_finally_so_a_failed_copy_still_resyncs(self):
        source = inspect.getsource(backup_mod.backup_vm_crash)
        self.assertIn("finally:", source[:source.index("_resync_after_pause")])

    def test_a_resync_that_raises_cannot_fail_a_completed_backup(self):
        """The archive is already written by the time this runs.

        A backup that reports failure over a clock is a worse outcome than a
        slow clock. Asserted against the SOURCE rather than by driving
        backup_vm_crash, and the limitation is stated rather than hidden:
        reaching the call site for real needs a live QMP monitor and a real
        copy, so what is checked here is that the call is inside an
        `except Exception`, not that the exception was survived.
        """
        source = inspect.getsource(backup_mod.backup_vm_crash)
        guarded = source[source.index("_resync_after_pause"):]
        self.assertIn("except Exception", guarded)


if __name__ == "__main__":
    unittest.main()
