#!/usr/bin/env python3
"""Unit tests for cmd_doctor (aggregate diagnosis report).

Doctor is orchestration over collectors that are each tested in their own
suites (collect_diagnose_checks via test_cmd_admin, collect_drift via
test_cmd_drift, substrate liveness via test_substrate). Pinned here:

- CLI wiring: `workloadctl doctor <name>` dispatches to cmd_doctor.
- The healthy path collapses to a green summary and exits 0.
- A failing unit (the broken-ExecStartPre shape: Result=exit-code on the
  main service) surfaces the unit, its journal tail, and exits 1 — the
  won't-come-up case doctor exists for.
"""

import argparse
import importlib.machinery
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

LIB = os.path.join(os.path.dirname(__file__), "..", "lib")
if LIB not in sys.path:
    sys.path.insert(0, LIB)

import cmd_doctor  # noqa: E402


def _load_cli():
    """Load the extensionless bin/workloadctl as a module (no __main__ side
    effects; same technique as test_cli_exit_codes)."""
    path = Path(__file__).parent.parent / "bin" / "workloadctl"
    loader = importlib.machinery.SourceFileLoader("workloadctl_bin", str(path))
    spec = importlib.util.spec_from_loader("workloadctl_bin", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class WiringTest(unittest.TestCase):
    def test_doctor_dispatches_to_cmd_doctor(self):
        cli = _load_cli()
        fake = mock.Mock(name="cmd_doctor")
        with mock.patch.object(cli, "cmd_doctor", fake), \
                mock.patch.object(cli, "WorkloadManager"), \
                mock.patch.object(sys, "argv", ["workloadctl", "doctor", "app"]):
            cli.main()
        args = fake.call_args.args[0]
        self.assertEqual(args.workload, "app")
        self.assertFalse(args.json)


def _fake_config(enabled=True):
    return SimpleNamespace(
        name="app", kind="container", mode="single", lifecycle="cattle",
        enabled=enabled,
    )


class DoctorReportTest(unittest.TestCase):
    """cmd_doctor with the collectors stubbed at their seams."""

    HEALTHY_CHECKS = ([{"check": "user_exists", "passed": True,
                        "message": "User exists"}], True)
    HEALTHY_LIVENESS = {"service_active": True, "service_state": "active",
                        "container_running": True, "container_status": "Up",
                        "healthy": True}

    def setUp(self):
        self.enterContext(mock.patch.object(cmd_doctor, "require_root", lambda: None))
        self.enterContext(mock.patch.object(
            cmd_doctor, "WorkloadConfig", lambda name: _fake_config()))
        self.enterContext(mock.patch.object(
            cmd_doctor, "units_outdated", lambda name: False))
        self.enterContext(mock.patch.object(
            cmd_doctor, "workload_config_path",
            lambda name: f"/etc/workloads.d/{name}/workload.toml"))
        self.enterContext(mock.patch.object(
            cmd_doctor, "_generator_lines", lambda name: []))
        self.enterContext(mock.patch.object(
            cmd_doctor, "collect_diagnose_checks",
            lambda config, manager: self.HEALTHY_CHECKS))
        self.enterContext(mock.patch.object(
            cmd_doctor, "collect_drift", lambda name: []))
        substrate = mock.Mock()
        substrate.liveness.return_value = dict(self.HEALTHY_LIVENESS)
        self.enterContext(mock.patch.object(
            cmd_doctor, "get_substrate", lambda config, manager: substrate))
        self.substrate = substrate

    def _run(self, json_mode=False):
        out = io.StringIO()
        ns = argparse.Namespace(workload="app", json=json_mode)
        code = None
        try:
            with redirect_stdout(out):
                cmd_doctor.cmd_doctor(ns, mock.Mock())
        except SystemExit as e:
            code = e.code
        return code, out.getvalue()

    def test_healthy_green_summary_exit_0(self):
        with mock.patch.object(cmd_doctor, "_unit_rows", lambda config: [
            {"unit": "workload-app.service", "role": "main", "present": True,
             "active_state": "active", "sub_state": "running", "result": "",
             "n_restarts": 0, "problem": False},
        ]):
            code, out = self._run()
        self.assertEqual(code, 0)
        self.assertIn("Overall: HEALTHY", out)
        self.assertIn("✓ workload-app.service", out)
        self.assertIn("✓ 1 checks passed", out)
        self.assertNotIn("journal", out.lower())

    def test_failed_unit_surfaces_tail_and_exits_1(self):
        # The broken-ExecStartPre shape: workload-ensure-user failed, so the
        # main unit shows failed/Result=exit-code and its journal carries the
        # provisioning ERROR line.
        with mock.patch.object(cmd_doctor, "_unit_rows", lambda config: [
            {"unit": "workload-app.service", "role": "main", "present": True,
             "active_state": "failed", "sub_state": "failed",
             "result": "exit-code", "n_restarts": 0, "problem": True,
             "journal_tail": ["ERROR: Failed to enable linger for _wl-app"]},
        ]):
            code, out = self._run()
        self.assertEqual(code, 1)
        self.assertIn("✗ workload-app.service", out)
        self.assertIn("Result=exit-code", out)
        self.assertIn("ERROR: Failed to enable linger", out)
        self.assertIn("Overall: UNHEALTHY", out)

    def test_json_shape(self):
        with mock.patch.object(cmd_doctor, "_unit_rows", lambda config: []):
            code, out = self._run(json_mode=True)
        self.assertEqual(code, 0)
        import json as _json
        data = _json.loads(out)
        self.assertEqual(data["workload"], "app")
        for key in ("generator", "units", "checks", "drift", "health", "overall"):
            self.assertIn(key, data)
        self.assertTrue(data["overall"]["healthy"])


class UnitRowsTest(unittest.TestCase):
    """_unit_rows against fake run-files and a mocked systemctl."""

    def _run_file(self, path, role, emitted=True):
        return SimpleNamespace(path=path, kind="unit", role=role, emitted=emitted)

    def test_absent_unit_not_problem_when_disabled(self):
        missing = Path("/nonexistent/workload-app.service")
        with mock.patch.object(
                cmd_doctor, "workload_run_files",
                lambda config: [self._run_file(missing, "main")]):
            rows = cmd_doctor._unit_rows(_fake_config(enabled=False))
        self.assertEqual(rows[0]["active_state"], "absent")
        self.assertFalse(rows[0]["problem"])

    def test_restart_looping_unit_is_problem(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        unit = Path(tmp) / "workload-app.service"
        unit.write_text("[Service]\n")
        show = mock.Mock(returncode=0, stdout=(
            "ActiveState=active\nSubState=running\nResult=success\n"
            "ExecMainStatus=0\nNRestarts=4\n"))
        tail = mock.Mock(returncode=0, stdout="pasta: pivot_root ENOENT\n")
        with mock.patch.object(cmd_doctor, "workload_run_files",
                               lambda config: [self._run_file(unit, "main")]), \
                mock.patch.object(cmd_doctor.subprocess, "run",
                                  side_effect=[show, tail]):
            rows = cmd_doctor._unit_rows(_fake_config())
        self.assertTrue(rows[0]["problem"])
        self.assertEqual(rows[0]["n_restarts"], 4)
        self.assertEqual(rows[0]["journal_tail"], ["pasta: pivot_root ENOENT"])


if __name__ == "__main__":
    unittest.main()
