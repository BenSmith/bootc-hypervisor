#!/usr/bin/env python3
"""Unit tests for cmd_logs and cmd_exec dispatch.

cmd_cp is covered separately (test_cmd_cp.py). These pin the two remaining
interact dispatchers that carry real logic rather than a single passthrough:

  * cmd_logs — the journalctl unit-list it builds for single / multi / a
    container target (and the not-in-workload guard). The substrate.logs()
    call is stubbed; what's asserted is the argv handed to it.
  * cmd_exec — the argparse.REMAINDER `--` stripping and the empty-command
    exit(2). The substrate.exec() return code is propagated via sys.exit.
"""

import argparse
import io
import types
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock


import cmd_interact  # noqa: E402


class _FakeSingle:
    is_multi = False
    is_vm = False
    mode = "single"
    username = "_wl-web"
    service_name = "workload-web.service"

    def container_names(self):
        return ["web"]

    def sub_service_names(self):
        return ["workload-web.service"]

    def podman_targets(self):
        return ["workload-web"]

    def podman_container_name(self, name):
        return "workload-web"


class _FakePod:
    is_multi = True
    is_vm = False
    mode = "pod"
    username = "_wl-app"
    service_name = "workload-app.service"

    def container_names(self):
        return ["api", "db"]

    def sub_service_names(self):
        return ["workload-app-api.service", "workload-app-db.service"]

    def podman_targets(self):
        return ["workload-app-api", "workload-app-db"]

    def podman_container_name(self, name):
        return f"workload-app-{name}"


class _LogsBase(unittest.TestCase):
    def setUp(self):
        self.captured: dict = {}

        class _Sub:
            def logs(_self, cmd):
                self.captured["cmd"] = cmd

        self.enterContext(mock.patch.object(
            cmd_interact, "get_substrate", lambda c, m: _Sub()))
        self.manager = mock.Mock()

    def _run(self, config, workload, *, follow=False, lines=None,
             since=None, extra_args=None):
        self.enterContext(mock.patch.object(
            cmd_interact, "WorkloadConfig", lambda n: config))
        args = argparse.Namespace(
            workload=workload, follow=follow, lines=lines,
            since=since, extra_args=extra_args or [])
        out, err = io.StringIO(), io.StringIO()
        code = None
        try:
            with redirect_stdout(out), redirect_stderr(err):
                cmd_interact.cmd_logs(args, self.manager)
        except SystemExit as e:
            code = e.code
        self._err = err.getvalue()
        return code


class LogsUnitListTest(_LogsBase):
    def test_single_uses_one_unit_and_default_lines(self):
        self.assertIsNone(self._run(_FakeSingle(), "web"))
        # single -> the umbrella unit ORed with its passthrough identifier,
        # defaulted to -n 50. Full selection shape is pinned in
        # test_cmd_interact.JournalSelectionTest; here just the integration.
        self.assertEqual(
            self.captured["cmd"][:6],
            ["journalctl", "_SYSTEMD_UNIT=workload-web.service", "+",
             "UNIT=workload-web.service", "+", "SYSLOG_IDENTIFIER=workload-web"])
        self.assertEqual(self.captured["cmd"][-2:], ["-n", "50"])

    def test_multi_threads_service_units_into_journalctl(self):
        # The multi unit list is workload_service_units(config), in order.
        # Its per-mode contents (pod vs net, containers) are pinned in
        # test_workload_run_files; here we assert cmd_logs threads that list
        # verbatim into the _SYSTEMD_UNIT= match terms.
        service_units = [
            "workload-app-setup.service",
            "workload-app.service",
            "workload-app-pod.service",
            "workload-app-api.service",
            "workload-app-db.service",
        ]
        with mock.patch.object(cmd_interact, "workload_service_units",
                               return_value=service_units) as m:
            self.assertIsNone(self._run(_FakePod(), "app"))
        m.assert_called_once()
        cmd = self.captured["cmd"]
        units = [t.split("=", 1)[1] for t in cmd
                 if t.startswith("_SYSTEMD_UNIT=")]
        self.assertEqual(units, service_units)
        # Every container's passthrough identifier is ORed in too.
        idents = [t.split("=", 1)[1] for t in cmd
                  if t.startswith("SYSLOG_IDENTIFIER=")]
        self.assertEqual(idents, ["workload-app-api", "workload-app-db"])

    def test_container_target_single_unit(self):
        self.assertIsNone(self._run(_FakePod(), "app/api"))
        # A container target narrows to just that container's unit + identifier.
        self.assertEqual(
            self.captured["cmd"][:6],
            ["journalctl", "_SYSTEMD_UNIT=workload-app-api.service", "+",
             "UNIT=workload-app-api.service", "+",
             "SYSLOG_IDENTIFIER=workload-app-api"])
        self.assertEqual(self.captured["cmd"][-2:], ["-n", "50"])

    def test_unknown_container_target_errors(self):
        code = self._run(_FakePod(), "app/nope")
        self.assertEqual(code, 2)
        self.assertIn("not in workload", self._err)
        self.assertIn("api, db", self._err)             # lists the real ones
        self.assertNotIn("cmd", self.captured)          # logs() never called

    def test_follow_and_lines_options(self):
        self.assertIsNone(self._run(_FakeSingle(), "web", follow=True, lines=10))
        cmd = self.captured["cmd"]
        self.assertIn("-f", cmd)
        self.assertIn("-n", cmd)
        self.assertEqual(cmd[cmd.index("-n") + 1], "10")

    def test_since_suppresses_default_lines(self):
        self.assertIsNone(self._run(_FakeSingle(), "web", since="-1h"))
        cmd = self.captured["cmd"]
        self.assertIn("--since", cmd)
        self.assertNotIn("-n", cmd)                     # default 50 not added


class ExecTest(unittest.TestCase):
    def setUp(self):
        self.manager = mock.Mock()
        self.manager.user_exists.return_value = True
        self.calls: dict = {}

        class _Sub:
            def exec(_self, exec_args, container=None):
                self.calls["exec_args"] = exec_args
                self.calls["container"] = container
                return 7

        self.enterContext(mock.patch.object(
            cmd_interact, "WorkloadConfig",
            lambda n: types.SimpleNamespace(username="_wl-web")))
        self.enterContext(mock.patch.object(
            cmd_interact, "get_substrate", lambda c, m: _Sub()))

    def _run(self, workload, exec_args):
        args = argparse.Namespace(workload=workload, exec_args=exec_args)
        out, err = io.StringIO(), io.StringIO()
        code = None
        try:
            with redirect_stdout(out), redirect_stderr(err):
                cmd_interact.cmd_exec(args, self.manager)
        except SystemExit as e:
            code = e.code
        self._err = err.getvalue()
        return code

    def test_propagates_substrate_exit_code(self):
        code = self._run("web", ["ls", "/"])
        self.assertEqual(code, 7)                        # substrate.exec() return
        self.assertEqual(self.calls["exec_args"], ["ls", "/"])

    def test_strips_leading_double_dash(self):
        self._run("web", ["--", "ps", "aux"])
        self.assertEqual(self.calls["exec_args"], ["ps", "aux"])

    def test_only_first_double_dash_stripped(self):
        self._run("web", ["--", "sh", "-c", "echo --"])
        self.assertEqual(self.calls["exec_args"], ["sh", "-c", "echo --"])

    def test_empty_command_exits_2(self):
        code = self._run("web", [])
        self.assertEqual(code, 2)
        self.assertIn("no command", self._err)

    def test_bare_double_dash_is_empty_command(self):
        code = self._run("web", ["--"])
        self.assertEqual(code, 2)
        self.assertIn("no command", self._err)

    def test_missing_user_exits_1(self):
        self.manager.user_exists.return_value = False
        code = self._run("web", ["ls"])
        self.assertEqual(code, 1)
        self.assertIn("does not exist", self._err)

    def test_container_target_forwarded(self):
        self._run("app/api", ["env"])
        self.assertEqual(self.calls["container"], "api")


if __name__ == "__main__":
    unittest.main()
