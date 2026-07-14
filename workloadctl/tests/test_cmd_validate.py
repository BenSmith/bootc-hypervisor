#!/usr/bin/env python3
"""Unit tests for cmd_validate dispatch (the --all aggregation wrapper).

validate_single's per-check logic is covered in test_cmd_admin.py /
test_json_output.py. This pins the dispatcher around it: the --all rollup
(all_passed reflects the worst single result), the json-vs-text branch, the
exit codes, and the single-workload "name required" guard. validate_single
itself is stubbed so each test controls pass/fail directly.
"""

import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock


import cmd_validate  # noqa: E402
import workload_lib  # noqa: E402
from workloadctl_core import WorkloadConfig, WorkloadManager  # noqa: E402


def _ns(**kw):
    base = dict(all=False, json=False, workload=None)
    base.update(kw)
    return argparse.Namespace(**base)


class ValidateDispatchTest(unittest.TestCase):
    def setUp(self):
        self.manager = mock.Mock()
        # Map config name -> passed bool; validate_single stub honors it.
        self.verdicts: dict = {}

        def fake_validate(config, manager, json_mode=False):
            name = getattr(config, "name", config)
            passed = self.verdicts.get(name, True)
            return {"workload": name, "passed": passed, "checks": []}

        self.enterContext(mock.patch.object(cmd_validate, "validate_single", fake_validate))
        self.enterContext(mock.patch.object(
            cmd_validate, "WorkloadConfig",
            lambda n: argparse.Namespace(name=n)))

    def _run(self, **kw):
        out, err = io.StringIO(), io.StringIO()
        code = None
        try:
            with redirect_stdout(out), redirect_stderr(err):
                cmd_validate.cmd_validate(_ns(**kw), self.manager)
        except SystemExit as e:
            code = e.code
        self._out, self._err = out.getvalue(), err.getvalue()
        return code

    def _set_configs(self, *names):
        self.manager.get_all_configs.return_value = [
            argparse.Namespace(name=n) for n in names]

    # --- --all rollup ------------------------------------------------------

    def test_all_pass_exits_0(self):
        self._set_configs("a", "b")
        self.assertEqual(self._run(all=True), 0)

    def test_all_one_failure_exits_1(self):
        self._set_configs("a", "b", "c")
        self.verdicts["b"] = False
        self.assertEqual(self._run(all=True), 1)

    def test_all_empty_exits_0(self):
        self._set_configs()
        self.assertEqual(self._run(all=True), 0)

    def test_all_json_reports_each_and_rollup(self):
        self._set_configs("a", "b")
        self.verdicts["a"] = False
        code = self._run(all=True, json=True)
        self.assertEqual(code, 1)
        doc = json.loads(self._out)
        self.assertEqual([r["workload"] for r in doc["validation_results"]], ["a", "b"])
        self.assertFalse(doc["all_passed"])

    # --- single workload ---------------------------------------------------

    def test_single_requires_name(self):
        code = self._run(all=False, workload=None)
        self.assertEqual(code, 1)
        self.assertIn("required", self._err)

    def test_single_pass_exits_0(self):
        code = self._run(workload="web")
        self.assertEqual(code, 0)

    def test_single_fail_exits_1(self):
        self.verdicts["web"] = False
        code = self._run(workload="web")
        self.assertEqual(code, 1)

    def test_single_json_emits_one_result(self):
        code = self._run(workload="web", json=True)
        self.assertEqual(code, 0)
        doc = json.loads(self._out)
        self.assertEqual(doc["workload"], "web")
        self.assertTrue(doc["passed"])


class ValidateSingleCredentialsTest(unittest.TestCase):
    """validate_single cross-checks ${SECRET:name} references against the
    credstore so a missing secret is a named, config-time error instead of a
    cryptic namespace/ExecStart failure at service-start time."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        self.credstore = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(cmd_validate, "CREDSTORE_DIR", self.credstore))

    def _validate(self, name, toml):
        (self.tmp / name).mkdir()
        (self.tmp / name / "workload.toml").write_text(toml)
        config = WorkloadConfig(name)
        manager = mock.Mock(spec=WorkloadManager)
        manager.user_exists.return_value = False
        manager.get_all_configs.return_value = []
        return cmd_validate.validate_single(config, manager, json_mode=True)

    def test_no_secret_refs_ok(self):
        result = self._validate(
            "clitest-nosecret",
            '[workload]\nname = "clitest-nosecret"\n\n'
            '[container]\nimage = "x:latest"\n',
        )
        creds = [c for c in result["checks"] if c["check"] == "credentials"]
        self.assertEqual(len(creds), 1)
        self.assertTrue(creds[0]["passed"])
        self.assertEqual(creds[0]["message"], "No credential references")

    def test_all_refs_present_ok(self):
        (self.credstore / "dbpass").write_text("secret")
        result = self._validate(
            "clitest-present",
            '[workload]\nname = "clitest-present"\n\n'
            '[container]\nimage = "x:latest"\n'
            '[container.environment]\nDB_PASS = "${SECRET:dbpass}"\n',
        )
        creds = [c for c in result["checks"] if c["check"] == "credentials"]
        self.assertEqual(len(creds), 1)
        self.assertTrue(creds[0]["passed"])
        self.assertIn("dbpass", creds[0]["message"])
        self.assertTrue(result["passed"])
        self.assertEqual(result["errors"], 0)

    def test_missing_ref_errors(self):
        result = self._validate(
            "clitest-missing",
            '[workload]\nname = "clitest-missing"\n\n'
            '[container]\nimage = "x:latest"\n'
            '[container.environment]\nDB_PASS = "${SECRET:dbpass}"\n',
        )
        creds = [c for c in result["checks"] if c["check"] == "credentials"]
        self.assertTrue(creds and not creds[0]["passed"])
        self.assertIn("dbpass", creds[0]["message"])
        self.assertFalse(result["passed"])
        self.assertGreaterEqual(result["errors"], 1)

    def test_permission_error_warns_not_errors(self):
        class _NoPermDir:
            """Stands in for a 0700 credstore this process can't read into."""
            def __truediv__(self, other):
                raise PermissionError(13, "Permission denied")

        with mock.patch.object(cmd_validate, "CREDSTORE_DIR", _NoPermDir()):
            result = self._validate(
                "clitest-noperm",
                '[workload]\nname = "clitest-noperm"\n\n'
                '[container]\nimage = "x:latest"\n'
                '[container.environment]\nDB_PASS = "${SECRET:dbpass}"\n',
            )
        creds = [c for c in result["checks"] if c["check"] == "credentials"]
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]["severity"], "warning")
        self.assertTrue(creds[0]["passed"])
        self.assertTrue(result["passed"])
        self.assertEqual(result["errors"], 0)
        self.assertGreaterEqual(result["warnings"], 1)


if __name__ == "__main__":
    unittest.main()
