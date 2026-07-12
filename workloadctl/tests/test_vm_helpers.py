#!/usr/bin/env python3
"""Unit tests for the VM libexec helpers: workload-vm-notify,
workload-vm-qmp, workload-vm-shutdown.

These three gate VM readiness (sd_notify), the QMP escape hatch, and graceful
power-off — and had no tests at all. They're argv scripts (no .py), so we load
each via SourceFileLoader and drive its pure functions with a fake QMPClient;
the real socket/QEMU/systemd I/O is out of scope for a unit test.
"""

import importlib.machinery
import importlib.util
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from typing import Any
from unittest import mock

LIBEXEC = Path(__file__).resolve().parent.parent / "libexec"
LIB = str(Path(__file__).resolve().parent.parent / "lib")
if LIB not in sys.path:
    sys.path.insert(0, LIB)


def _load(script: str, modname: str):
    loader = importlib.machinery.SourceFileLoader(modname, str(LIBEXEC / script))
    spec = importlib.util.spec_from_loader(modname, loader)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


notify = _load("workload-vm-notify", "wl_vm_notify")
qmp = _load("workload-vm-qmp", "wl_vm_qmp")
shutdown = _load("workload-vm-shutdown", "wl_vm_shutdown")


class FakeQMP:
    """Configurable stand-in for qmp.QMPClient."""

    def __init__(self, *, connect_raises=None, handler=None, messages=None):
        self.connect_raises = connect_raises
        self.handler: Any = handler or (lambda cmd, args=None: {"return": {}})
        self.sent = []
        self.closed = False
        # Queue for next_message(): dicts are returned in order; a None entry
        # simulates a read timeout; exhausting the queue raises ConnectionError
        # (the monitor closed / QEMU exited).
        self.messages = list(messages) if messages else []

    def connect(self, path, timeout=10.0, recv_timeout=5.0):
        if self.connect_raises is not None:
            raise self.connect_raises

    def negotiate(self):
        pass

    def execute(self, command, arguments=None, **kw):
        self.sent.append((command, arguments))
        return self.handler(command, arguments)

    def next_message(self):
        if not self.messages:
            raise ConnectionError("monitor closed")
        return self.messages.pop(0)

    def close(self):
        self.closed = True


# ---------------------------------------------------------------------------
# workload-vm-notify
# ---------------------------------------------------------------------------

class NotifyTest(unittest.TestCase):
    def test_wait_running_returns_when_running(self):
        fake = FakeQMP(handler=lambda c, a=None: {"return": {"running": True}})
        notify.wait_running(fake, timeout=5.0)  # should not raise

    def test_wait_running_sleeps_between_polls(self):
        # running False on the first poll, True on the second: the loop must
        # sleep once (covers the poll-interval sleep) then return on the retry.
        seq = iter([False, True])
        fake = FakeQMP(handler=lambda c, a=None: {"return": {"running": next(seq)}})
        with mock.patch.object(notify.time, "sleep") as sl:
            notify.wait_running(fake, timeout=5.0)  # should not raise
        sl.assert_called_once_with(0.5)
        self.assertEqual([c for c, _ in fake.sent], ["query-status", "query-status"])

    def test_wait_running_times_out(self):
        fake = FakeQMP(handler=lambda c, a=None: {"return": {"running": False}})
        # timeout=0 => deadline already passed => immediate TimeoutError, no sleep.
        with self.assertRaises(TimeoutError):
            notify.wait_running(fake, timeout=0)

    def test_sd_notify_no_socket_is_noop(self):
        # NOTIFY_SOCKET unset: must return quietly, not raise.
        with mock.patch.dict(os.environ, {}, clear=True):
            notify.sd_notify("READY=1")

    def test_sd_notify_sends_to_socket(self):
        fake_sock = mock.MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        with mock.patch.dict(os.environ, {"NOTIFY_SOCKET": "/run/n.sock"}), \
             mock.patch.object(notify.socket, "socket", return_value=fake_sock):
            notify.sd_notify("READY=1")
        fake_sock.connect.assert_called_once_with("/run/n.sock")
        fake_sock.sendall.assert_called_once_with(b"READY=1")

    def test_sd_notify_abstract_socket_translated(self):
        fake_sock = mock.MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        with mock.patch.dict(os.environ, {"NOTIFY_SOCKET": "@abstract"}), \
             mock.patch.object(notify.socket, "socket", return_value=fake_sock):
            notify.sd_notify("READY=1")
        # leading @ becomes a NUL for the abstract namespace
        fake_sock.connect.assert_called_once_with("\0abstract")

    def test_sd_notify_oserror_swallowed(self):
        fake_sock = mock.MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.connect.side_effect = OSError("no such socket")
        with mock.patch.dict(os.environ, {"NOTIFY_SOCKET": "/run/n.sock"}), \
             mock.patch.object(notify.socket, "socket", return_value=fake_sock):
            notify.sd_notify("READY=1")  # must not raise

    def test_main_usage_error_exits_1(self):
        with mock.patch.object(notify.sys, "argv", ["notify", "onlyname"]), \
             redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                notify.main()
        self.assertEqual(cm.exception.code, 1)

    # --- on-reboot shutdown-reason monitoring (O6) -----------------------

    def test_monitor_returns_shutdown_reason(self):
        proc = mock.Mock(); proc.poll.return_value = None
        fake = FakeQMP(messages=[
            {"event": "NIC_RX"},  # unrelated event, skipped
            {"event": "SHUTDOWN", "data": {"reason": "guest-reset"}},
        ])
        with mock.patch.object(notify, "QMPClient", return_value=fake):
            self.assertEqual(
                notify.monitor_shutdown_reason("vm1", proc), "guest-reset")
        self.assertTrue(fake.closed)

    def test_monitor_none_when_monitor_closes_first(self):
        proc = mock.Mock(); proc.poll.return_value = None
        fake = FakeQMP(messages=[])  # next_message raises ConnectionError
        with mock.patch.object(notify, "QMPClient", return_value=fake):
            self.assertIsNone(notify.monitor_shutdown_reason("vm1", proc))

    def test_monitor_none_on_timeout_after_qemu_exit(self):
        # A read timeout (None) with QEMU already gone ends the wait.
        proc = mock.Mock(); proc.poll.return_value = 0
        fake = FakeQMP(messages=[None])
        with mock.patch.object(notify, "QMPClient", return_value=fake):
            self.assertIsNone(notify.monitor_shutdown_reason("vm1", proc))

    def _run_main_reboot_mode(self, reason, wait_rc=0):
        fake = FakeQMP(handler=lambda c, a=None: {"return": {"running": True}})
        proc = mock.Mock(); proc.wait.return_value = wait_rc
        with mock.patch.dict(os.environ, {"WORKLOADCTL_VM_REBOOT_EXIT": "133"}), \
             mock.patch.object(notify.sys, "argv",
                               ["notify", "vm1", "qemu", "-nographic"]), \
             mock.patch.object(notify.subprocess, "Popen", return_value=proc), \
             mock.patch.object(notify, "QMPClient", return_value=fake), \
             mock.patch.object(notify.signal, "signal"), \
             mock.patch.object(notify, "monitor_shutdown_reason",
                               return_value=reason), \
             mock.patch.object(notify, "sd_notify"), \
             redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                notify.main()
        return cm.exception.code

    def test_main_on_reboot_reboot_exits_reboot_code(self):
        self.assertEqual(self._run_main_reboot_mode("guest-reset"), 133)

    def test_main_on_reboot_poweroff_exits_zero(self):
        self.assertEqual(
            self._run_main_reboot_mode("guest-shutdown", wait_rc=0), 0)

    def test_main_on_reboot_other_reason_propagates_qemu_rc(self):
        # host-signal / crash / unknown → fall through to QEMU's own exit code.
        self.assertEqual(self._run_main_reboot_mode(None, wait_rc=5), 5)

    def _run_main(self, fake_qmp, wait_rc=0):
        proc = mock.Mock()
        proc.wait.return_value = wait_rc
        with mock.patch.object(notify.sys, "argv",
                               ["notify", "vm1", "qemu", "-nographic"]), \
             mock.patch.object(notify.subprocess, "Popen", return_value=proc), \
             mock.patch.object(notify, "QMPClient", return_value=fake_qmp), \
             mock.patch.object(notify.signal, "signal"), \
             mock.patch.object(notify, "sd_notify") as sd, \
             redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                notify.main()
        return cm.exception.code, sd, fake_qmp

    def test_main_happy_path_sends_ready_and_propagates_rc(self):
        fake = FakeQMP(handler=lambda c, a=None: {"return": {"running": True}})
        code, sd, fake = self._run_main(fake, wait_rc=0)
        self.assertEqual(code, 0)
        sd.assert_any_call("READY=1")
        self.assertTrue(fake.closed)

    def test_main_qmp_connect_error_still_readies(self):
        fake = FakeQMP(connect_raises=RuntimeError("no qmp"))
        code, sd, fake = self._run_main(fake, wait_rc=7)
        self.assertEqual(code, 7)  # QEMU's exit code propagates
        sd.assert_any_call("READY=1")  # degraded path still readies the unit

    def test_main_wait_timeout_does_not_ready_and_propagates_rc(self):
        # QMP connects/negotiates fine but the guest never enters "running":
        # wait_running raises TimeoutError. The unit must NOT be marked READY
        # (that path deliberately defers to systemd's TimeoutStartSec) but must
        # still surface a STATUS= and propagate QEMU's exit code.
        fake = FakeQMP(handler=lambda c, a=None: {"return": {"running": False}})
        proc = mock.Mock()
        proc.wait.return_value = 4
        with mock.patch.object(notify.sys, "argv",
                               ["notify", "vm1", "qemu", "-nographic"]), \
             mock.patch.object(notify.subprocess, "Popen", return_value=proc), \
             mock.patch.object(notify, "QMPClient", return_value=fake), \
             mock.patch.object(notify.signal, "signal"), \
             mock.patch.object(notify, "wait_running",
                               side_effect=TimeoutError("no run")), \
             mock.patch.object(notify, "sd_notify") as sd, \
             redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                notify.main()
        self.assertEqual(cm.exception.code, 4)
        self.assertNotIn(mock.call("READY=1"), sd.call_args_list)
        self.assertTrue(any("STATUS=Timeout" in c.args[0]
                            for c in sd.call_args_list))
        self.assertTrue(fake.closed)

    def test_main_installs_signal_forwarder(self):
        # main() registers a SIGTERM/SIGINT forwarder closure. Capture it and
        # drive both branches: a live QEMU (send_signal) and an already-dead one
        # (ProcessLookupError must be swallowed).
        proc = mock.Mock()
        proc.wait.return_value = 0
        handlers: dict = {}
        fake = FakeQMP(handler=lambda c, a=None: {"return": {"running": True}})
        with mock.patch.object(notify.sys, "argv",
                               ["notify", "vm1", "qemu", "-nographic"]), \
             mock.patch.object(notify.subprocess, "Popen", return_value=proc), \
             mock.patch.object(notify, "QMPClient", return_value=fake), \
             mock.patch.object(notify.signal, "signal",
                               lambda sig, h: handlers.__setitem__(sig, h)), \
             mock.patch.object(notify, "sd_notify"), \
             redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                notify.main()
        fwd = handlers[notify.signal.SIGTERM]
        self.assertIs(fwd, handlers[notify.signal.SIGINT])
        fwd(notify.signal.SIGTERM, None)
        proc.send_signal.assert_called_once_with(notify.signal.SIGTERM)
        # QEMU already reaped: forwarder must not propagate ProcessLookupError.
        proc.send_signal.side_effect = ProcessLookupError()
        fwd(notify.signal.SIGTERM, None)  # must not raise


# ---------------------------------------------------------------------------
# workload-vm-qmp
# ---------------------------------------------------------------------------

class QmpTest(unittest.TestCase):
    def test_send_cmd_prints_result(self):
        fake = FakeQMP(handler=lambda c, a=None: {"return": {"status": "running"}})
        with mock.patch.object(qmp, "QMPClient", lambda: fake):
            out = io.StringIO()
            with redirect_stdout(out):
                qmp.qmp_send_cmd("/sock", "query-status")
        self.assertEqual(json.loads(out.getvalue())["return"]["status"], "running")
        self.assertTrue(fake.closed)  # socket always closed

    def test_send_cmd_connect_timeout_exits(self):
        fake = FakeQMP(connect_raises=TimeoutError())
        with mock.patch.object(qmp, "QMPClient", lambda: fake):
            err = io.StringIO()
            with self.assertRaises(SystemExit) as cm, redirect_stderr(err):
                qmp.qmp_send_cmd("/sock", "query-status")
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("not available", err.getvalue())

    def test_main_parses_key_value_args(self):
        seen = {}

        def _capture(sock_path, command, arguments, **kw):
            seen["command"] = command
            seen["arguments"] = arguments

        with mock.patch.object(qmp, "qmp_send_cmd", _capture), \
             mock.patch.object(qmp, "VM_SOCKET_DIR", Path("/sockroot")), \
             mock.patch.object(qmp.Path, "exists", lambda self: True), \
             mock.patch.object(sys, "argv",
                               ["prog", "myvm", "block_resize",
                                "device=foo", "size=123", "noequals"]):
            qmp.main()
        # key=value tokens become the args dict; bare tokens are ignored.
        self.assertEqual(seen["command"], "block_resize")
        self.assertEqual(seen["arguments"], {"device": "foo", "size": "123"})

    def test_main_usage_error_exits_1(self):
        # Fewer than <name> <command> => usage message on stderr, exit 1.
        with mock.patch.object(sys, "argv", ["prog", "onlyname"]), \
             mock.patch.object(qmp, "qmp_send_cmd") as send:
            err = io.StringIO()
            with self.assertRaises(SystemExit) as cm, redirect_stderr(err):
                qmp.main()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("Usage:", err.getvalue())
        send.assert_not_called()

    def test_main_missing_socket_exits_1(self):
        # Valid argv but the QMP socket file doesn't exist => exit 1 before
        # any connection attempt, with a "not running?" hint.
        with mock.patch.object(qmp, "qmp_send_cmd") as send, \
             mock.patch.object(qmp, "VM_SOCKET_DIR", Path("/sockroot")), \
             mock.patch.object(qmp.Path, "exists", lambda self: False), \
             mock.patch.object(sys, "argv", ["prog", "myvm", "query-status"]):
            err = io.StringIO()
            with self.assertRaises(SystemExit) as cm, redirect_stderr(err):
                qmp.main()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("socket not found", err.getvalue())
        send.assert_not_called()


# ---------------------------------------------------------------------------
# workload-vm-shutdown
# ---------------------------------------------------------------------------

class ShutdownTest(unittest.TestCase):
    def test_powerdown_then_monitor_drops_means_success(self):
        # First execute (system_powerdown) ok; query-status then raises
        # ConnectionError => QEMU exited => guest powered off.
        calls = {"n": 0}

        def handler(cmd, args=None):
            if cmd == "system_powerdown":
                return {"return": {}}
            calls["n"] += 1
            raise ConnectionError("monitor closed")

        fake = FakeQMP(handler=handler)
        with mock.patch.object(shutdown, "QMPClient", lambda: fake):
            self.assertTrue(shutdown.shutdown_and_wait("/sock", timeout=5.0))
        self.assertTrue(fake.closed)

    def test_explicit_shutdown_status_means_success(self):
        def handler(cmd, args=None):
            if cmd == "system_powerdown":
                return {"return": {}}
            return {"return": {"status": "shutdown"}}

        fake = FakeQMP(handler=handler)
        with mock.patch.object(shutdown, "QMPClient", lambda: fake):
            self.assertTrue(shutdown.shutdown_and_wait("/sock", timeout=5.0))

    def test_unreachable_monitor_returns_false(self):
        fake = FakeQMP(connect_raises=OSError("no socket"))
        with mock.patch.object(shutdown, "QMPClient", lambda: fake):
            err = io.StringIO()
            with redirect_stderr(err):
                self.assertFalse(shutdown.shutdown_and_wait("/sock", timeout=5.0))
        self.assertIn("QMP unavailable", err.getvalue())

    def test_timeout_returns_false(self):
        # Guest stays "running"; timeout=0 => loop body never runs => False.
        def handler(cmd, args=None):
            if cmd == "system_powerdown":
                return {"return": {}}
            return {"return": {"status": "running"}}

        fake = FakeQMP(handler=handler)
        with mock.patch.object(shutdown, "QMPClient", lambda: fake):
            self.assertFalse(shutdown.shutdown_and_wait("/sock", timeout=0))

    def test_running_status_polls_then_succeeds(self):
        # First query-status is "running" (guest still up) => sleep and poll
        # again; second poll sees the monitor drop => success. Exercises the
        # time.sleep(0.5) poll-loop body.
        replies = iter(["running", "gone"])

        def handler(cmd, args=None):
            if cmd == "system_powerdown":
                return {"return": {}}
            if next(replies) == "gone":
                raise ConnectionError("monitor closed")
            return {"return": {"status": "running"}}

        fake = FakeQMP(handler=handler)
        slept = []
        with mock.patch.object(shutdown, "QMPClient", lambda: fake), \
             mock.patch.object(shutdown.time, "sleep", slept.append), \
             mock.patch.object(shutdown.time, "monotonic",
                               side_effect=[0.0, 0.0, 1.0]):
            self.assertTrue(shutdown.shutdown_and_wait("/sock", timeout=5.0))
        self.assertEqual(slept, [0.5])  # slept once between the two polls
        self.assertTrue(fake.closed)


# ---------------------------------------------------------------------------
# workload-vm-shutdown: main() argv handling
# ---------------------------------------------------------------------------

class ShutdownMainTest(unittest.TestCase):
    def _run_main(self, argv, sock_exists, wait_result=True):
        sock = mock.MagicMock()
        sock.exists.return_value = sock_exists
        sock.__str__.return_value = "/fake/qmp.sock"
        sock_dir = mock.MagicMock()
        sock_dir.__truediv__ = lambda self, other: sock_dir
        # VM_SOCKET_DIR / name / "qmp.sock" => sock
        chain = mock.MagicMock()
        chain.__truediv__ = mock.MagicMock(return_value=sock)
        vm_socket_dir = mock.MagicMock()
        vm_socket_dir.__truediv__ = mock.MagicMock(return_value=chain)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(shutdown, "VM_SOCKET_DIR", vm_socket_dir), \
             mock.patch.object(shutdown, "shutdown_and_wait",
                               return_value=wait_result) as waited, \
             mock.patch.object(sys, "argv", argv), \
             redirect_stdout(out), redirect_stderr(err):
            shutdown.main()
        return out.getvalue(), err.getvalue(), waited

    def test_no_args_exits_1(self):
        with mock.patch.object(sys, "argv", ["workload-vm-shutdown"]), \
             redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(SystemExit) as cm:
                shutdown.main()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("Usage:", err.getvalue())

    def test_missing_socket_is_noop(self):
        out, err, waited = self._run_main(
            ["workload-vm-shutdown", "vm1"], sock_exists=False)
        waited.assert_not_called()
        self.assertEqual(out, "")

    def test_clean_poweroff_prints_success(self):
        out, err, waited = self._run_main(
            ["workload-vm-shutdown", "vm1"], sock_exists=True, wait_result=True)
        # default timeout used when no arg given
        self.assertEqual(waited.call_args[0][1], shutdown.DEFAULT_TIMEOUT)
        self.assertIn("powered off cleanly", out)

    def test_timeout_defers_to_systemd_kill(self):
        out, err, waited = self._run_main(
            ["workload-vm-shutdown", "vm1", "30"], sock_exists=True,
            wait_result=False)
        self.assertEqual(waited.call_args[0][1], 30.0)  # arg parsed as float
        self.assertIn("deferring to systemd kill", err)


if __name__ == "__main__":
    unittest.main()
