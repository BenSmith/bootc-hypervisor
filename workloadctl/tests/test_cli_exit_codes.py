#!/usr/bin/env python3
"""Unit tests for the CLI's exception→exit-code contract (cli_main.run).

cli_main.run catches library exceptions at the top level and maps each to a
specific process exit code (a contract scripts and CI depend on). It returns
the code rather than exiting, so the mapping is testable here directly rather
than only through end-to-end subprocess runs that can't easily provoke every
exception type. bin/workloadctl is tested only for handing argv to it.
"""

import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import argparse
import importlib.util

import cli_log
import cli_main
import cli_parser
from substrate import LifecycleError
from workloadctl_core import UsageError, WorkloadMasked, WorkloadUserNotFound
from tests import REPO_ROOT, load_script


cli_script = load_script("bin/workloadctl", "workloadctl_bin")


class HandlerReturnCodeTest(unittest.TestCase):
    """A handler that RETURNS a code exits with it.

    The exception ladder run() tests below is not the only way a command
    reports failure. `egress` and `pcap` return an int instead, and main()'s
    dispatch dropped it -- so both printed a correct diagnostic to stderr and
    exited 0. Found on a KVM host 2026-08-31 by a rig that asserted the exit
    status rather than the message, which is the only thing that separates
    "refused" from "reported nothing".

    Driven through main() with a stub handler rather than through a real
    subcommand, so this pins the DISPATCH and does not move if either of those
    two commands changes which codes it returns.
    """

    def _dispatch(self, returned):
        argv = ["workloadctl", "list"]
        handler = mock.Mock(return_value=returned)
        parser = mock.Mock(spec=argparse.ArgumentParser)
        parser.parse_args.return_value = mock.Mock(
            func=handler, command="list", json=False, quiet=False)
        buf, out = io.StringIO(), io.StringIO()
        with mock.patch.object(cli_main, "WorkloadManager", mock.Mock()), \
                mock.patch.object(cli_main, "build_parser", return_value=parser), \
                redirect_stderr(buf), redirect_stdout(out):
            return cli_main.main(argv)

    def test_a_nonzero_return_becomes_the_exit_code(self):
        self.assertEqual(self._dispatch(2), 2)

    def test_a_one_return_becomes_the_exit_code(self):
        self.assertEqual(self._dispatch(1), 1)

    def test_none_is_success(self):
        """The shape nearly every handler has."""
        self.assertEqual(self._dispatch(None), 0)

    def test_zero_is_success(self):
        self.assertEqual(self._dispatch(0), 0)

    def test_a_non_integer_return_is_not_an_exit_code(self):
        """A handler that returns something that is not a number is not asking
        for an exit status, and treating it as one would exit with a value the
        shell cannot represent. Named here because it is also what a test that
        stands a handler up as a bare Mock produces."""
        self.assertEqual(self._dispatch(mock.Mock()), 0)


class RunCliExitCodeTest(unittest.TestCase):
    """Each exception main() can surface maps to the documented exit code."""

    def _run_with_main(self, side_effect):
        """Patch main() to raise/return `side_effect`, return (code, stderr)."""
        if isinstance(side_effect, BaseException) or (
                isinstance(side_effect, type) and issubclass(side_effect, BaseException)):
            fake_main = mock.Mock(side_effect=side_effect)
        else:
            fake_main = mock.Mock(return_value=side_effect)
        buf = io.StringIO()
        with mock.patch.object(cli_main, 'main', fake_main), redirect_stderr(buf):
            code = cli_main.run(["workloadctl"])
        return code, buf.getvalue()

    def test_success_returns_0(self):
        code, _ = self._run_with_main(0)
        self.assertEqual(code, 0)

    def test_a_handler_status_is_returned(self):
        code, _ = self._run_with_main(3)
        self.assertEqual(code, 3)

    def test_usage_error_returns_2_without_reprinting(self):
        # UsageError's message is printed by the raiser; the ladder must not
        # print a second line, and must exit 2 (not the catch-all 1).
        code, err = self._run_with_main(UsageError("bad args"))
        self.assertEqual(code, 2)
        self.assertEqual(err, "")

    def test_lifecycle_error_passes_through_returncode(self):
        # LifecycleError reproduces the exact returncode of the failed
        # systemctl/podman call — not a flattened 1.
        for rc in (3, 5, 137):
            code, _ = self._run_with_main(LifecycleError(rc))
            self.assertEqual(code, rc)

    def test_workload_masked_returns_1_and_prints(self):
        code, err = self._run_with_main(WorkloadMasked("svc is masked"))
        self.assertEqual(code, 1)
        self.assertIn("masked", err)

    def test_workload_user_not_found_returns_1(self):
        code, err = self._run_with_main(WorkloadUserNotFound("_wl-x"))
        self.assertEqual(code, 1)
        self.assertIn("Error:", err)

    def test_file_not_found_returns_1(self):
        code, err = self._run_with_main(FileNotFoundError("no such file"))
        self.assertEqual(code, 1)
        self.assertIn("Error:", err)

    def test_generic_exception_prints_traceback_and_returns_1(self):
        # Unexpected exceptions (not one of the typed errors above) are a
        # likely workloadctl bug, so the full traceback must reach stderr
        # rather than being flattened to a one-line message.
        code, err = self._run_with_main(ValueError("boom"))
        self.assertEqual(code, 1)
        self.assertIn("Traceback (most recent call last)", err)
        self.assertIn("ValueError: boom", err)
        self.assertIn("workloadctl bug", err)

    def test_keyboard_interrupt_returns_130(self):
        code, err = self._run_with_main(KeyboardInterrupt())
        self.assertEqual(code, 130)
        self.assertIn("Interrupted", err)

    def test_systemexit_from_a_handler_keeps_its_code(self):
        # Handlers that call sys.exit() directly raise SystemExit; the ladder
        # returns its code as the interpreter would have used it.
        code, err = self._run_with_main(SystemExit(7))
        self.assertEqual(code, 7)
        self.assertEqual(err, "")

    def test_systemexit_with_no_code_is_0(self):
        code, _ = self._run_with_main(SystemExit())
        self.assertEqual(code, 0)

    def test_systemexit_with_a_message_prints_it_and_is_1(self):
        code, err = self._run_with_main(SystemExit("no such thing"))
        self.assertEqual(code, 1)
        self.assertEqual(err, "no such thing\n")

    def test_a_nonzero_systemexit_emits_the_json_failure(self):
        cli_log.configure(quiet=True, json_mode=True, command="start")
        self.addCleanup(cli_log.reset)
        out = io.StringIO()
        with mock.patch.object(cli_main, 'main', mock.Mock(side_effect=SystemExit(4))), \
                redirect_stdout(out), redirect_stderr(io.StringIO()):
            self.assertEqual(cli_main.run(["workloadctl"]), 4)
        self.assertIn("exit 4", json.loads(out.getvalue())["error"])


class JsonModeWiringTest(unittest.TestCase):
    """--json means two different things, and main() must tell them apart.

    On a mutating verb it hands stdout to cli_log, which writes the result
    object. On a read verb it means the *verb* prints a JSON report and cli_log
    must not write to stdout at all — because the exit ladder's emit_failure()
    fires on any non-zero exit, and a `diagnose --json` that legitimately exits 1
    would otherwise carry a second JSON document tacked onto its report, which
    nothing downstream can parse.
    """

    def setUp(self):
        self.addCleanup(cli_log.reset)

    def _configure_for(self, argv):
        """Run main() far enough to configure cli_log, then stop."""
        with mock.patch.object(cli_main, 'WorkloadManager', mock.Mock()), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            cli_main.main(['workloadctl', *argv])

    def test_mutating_json_hands_stdout_to_cli_log(self):
        with mock.patch.object(cli_parser, 'cmd_start'):
            self._configure_for(['start', '--json', 'web'])
        self.assertTrue(cli_log.json_enabled())

    def test_read_verb_json_does_not_hand_stdout_to_cli_log(self):
        with mock.patch.object(cli_parser, 'cmd_diagnose'):
            self._configure_for(['diagnose', '--json', 'web'])
        self.assertFalse(cli_log.json_enabled())
        # ...but prose is still kept off the report's stream.
        self.assertTrue(cli_log.is_quiet())

    def test_read_verb_json_emits_no_failure_object(self):
        # The regression itself: a read verb's own JSON report, followed by a
        # non-zero exit, must leave stdout holding exactly one document.
        def failing_diagnose(args, manager):
            print(json.dumps({"workload": "web", "passed": False}))
            sys.exit(1)

        buf = io.StringIO()
        with mock.patch.object(cli_parser, 'cmd_diagnose', failing_diagnose), \
                mock.patch.object(cli_main, 'WorkloadManager', mock.Mock()), \
                redirect_stdout(buf), redirect_stderr(io.StringIO()):
            code = cli_main.run(['workloadctl', 'diagnose', '--json', 'web'])
        self.assertEqual(code, 1)
        # json.loads() is the assertion: it raises on a second document.
        self.assertEqual(json.loads(buf.getvalue()),
                         {"workload": "web", "passed": False})


class VersionFlagTest(unittest.TestCase):
    """`workloadctl --version` prints the baked version and exits 0."""

    def _run_version(self):
        """Drive main()'s argparse --version action; return (exit_code, stdout)."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_main.run(['workloadctl', '--version'])
        return code, buf.getvalue()

    def test_version_exits_0_and_prints_single_line(self):
        code, out = self._run_version()
        self.assertEqual(code, 0)
        lines = out.splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0], f"workloadctl {cli_parser.__version__}")

    def test_source_checkout_reports_dev_fallback(self):
        # A real source checkout has no _version.py, so workload_lib falls back
        # to the sentinel rather than crashing on the missing import. Block the
        # _version module and load a fresh copy of workload_lib so this asserts
        # the fallback branch itself -- not the module-level import, which would
        # pick up a _version.py that an in-place build or a system-installed
        # package left importable on sys.path (as on a host with the RPM
        # installed).
        spec = importlib.util.spec_from_file_location(
            "workload_lib_fresh", REPO_ROOT / "lib" / "workload_lib.py")
        fresh = importlib.util.module_from_spec(spec)
        with mock.patch.dict(sys.modules, {'_version': None}):
            spec.loader.exec_module(fresh)
        self.assertEqual(fresh.WORKLOADCTL_VERSION, "0-dev")


class ShimTest(unittest.TestCase):
    """bin/workloadctl: argv to cli_main.run, its status back."""

    def test_hands_argv_to_run(self):
        with mock.patch.object(cli_script, "run", return_value=0) as run:
            rc = cli_script.main(["workloadctl", "list", "--json"])
        self.assertEqual(rc, 0)
        run.assert_called_once_with(["workloadctl", "list", "--json"])

    def test_the_run_status_is_the_exit_status(self):
        with mock.patch.object(cli_script, "run", return_value=130):
            self.assertEqual(cli_script.main(["workloadctl", "list"]), 130)


if __name__ == '__main__':
    unittest.main()
