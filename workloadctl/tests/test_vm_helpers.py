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
    """Configurable stand-in for workload_lib.QMPClient."""

    def __init__(self, *, connect_raises=None, handler=None):
        self.connect_raises = connect_raises
        self.handler: Any = handler or (lambda cmd, args=None: {"return": {}})
        self.sent = []
        self.closed = False

    def connect(self, path, timeout=10.0, recv_timeout=5.0):
        if self.connect_raises is not None:
            raise self.connect_raises

    def negotiate(self):
        pass

    def execute(self, command, arguments=None, **kw):
        self.sent.append((command, arguments))
        return self.handler(command, arguments)

    def close(self):
        self.closed = True


# ---------------------------------------------------------------------------
# workload-vm-notify
# ---------------------------------------------------------------------------

class NotifyTest(unittest.TestCase):
    def test_wait_running_returns_when_running(self):
        fake = FakeQMP(handler=lambda c, a=None: {"return": {"running": True}})
        notify.wait_running(fake, timeout=5.0)  # should not raise

    def test_wait_running_times_out(self):
        fake = FakeQMP(handler=lambda c, a=None: {"return": {"running": False}})
        # timeout=0 => deadline already passed => immediate TimeoutError, no sleep.
        with self.assertRaises(TimeoutError):
            notify.wait_running(fake, timeout=0)

    def test_sd_notify_no_socket_is_noop(self):
        # NOTIFY_SOCKET unset: must return quietly, not raise.
        with mock.patch.dict(os.environ, {}, clear=True):
            notify.sd_notify("READY=1")


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


if __name__ == "__main__":
    unittest.main()
