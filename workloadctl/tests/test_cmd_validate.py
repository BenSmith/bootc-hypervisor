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
import os
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

LIB = os.path.join(os.path.dirname(__file__), "..", "lib")
if LIB not in sys.path:
    sys.path.insert(0, LIB)

import cmd_admin  # noqa: E402


def _ns(**kw):
    base = dict(all=False, json=False, workload=None)
    base.update(kw)
    return argparse.Namespace(**base)


class ValidateDispatchTest(unittest.TestCase):
    def setUp(self):
        self.manager = mock.Mock()
        # Map config name -> passed bool; validate_single stub honors it.
        self.verdicts = {}

        def fake_validate(config, manager, json_mode=False):
            name = getattr(config, "name", config)
            passed = self.verdicts.get(name, True)
            return {"workload": name, "passed": passed, "checks": []}

        self.enterContext(mock.patch.object(cmd_admin, "validate_single", fake_validate))
        self.enterContext(mock.patch.object(
            cmd_admin, "WorkloadConfig",
            lambda n: argparse.Namespace(name=n)))

    def _run(self, **kw):
        out, err = io.StringIO(), io.StringIO()
        code = None
        try:
            with redirect_stdout(out), redirect_stderr(err):
                cmd_admin.cmd_validate(_ns(**kw), self.manager)
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


if __name__ == "__main__":
    unittest.main()
