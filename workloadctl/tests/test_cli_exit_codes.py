#!/usr/bin/env python3
"""Unit tests for bin/workloadctl's exception→exit-code contract (_run_cli).

The CLI entrypoint catches library exceptions at the top level and maps each to
a specific process exit code (a contract scripts and CI depend on). _run_cli is
split out of the __main__ guard so that mapping is testable here directly,
rather than only through end-to-end subprocess runs that can't easily provoke
every exception type.
"""

import importlib.machinery
import importlib.util
import io
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

LIB_DIR = os.path.join(os.path.dirname(__file__), '..', 'lib')
sys.path.insert(0, LIB_DIR)

# Load the extensionless bin/workloadctl script as a module. The __main__ guard
# does not fire (module name != "__main__"), so importing it is side-effect free
# beyond its top-level imports.
_WCTL = Path(__file__).parent.parent / 'bin' / 'workloadctl'
_loader = importlib.machinery.SourceFileLoader('workloadctl_bin', str(_WCTL))
_spec = importlib.util.spec_from_loader('workloadctl_bin', _loader)
cli = importlib.util.module_from_spec(_spec)
_loader.exec_module(cli)


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
        with mock.patch.object(cli, 'main', fake_main), redirect_stderr(buf):
            code = cli._run_cli()
        return code, buf.getvalue()

    def test_success_returns_0(self):
        code, _ = self._run_with_main(None)
        self.assertEqual(code, 0)

    def test_usage_error_returns_2_without_reprinting(self):
        # UsageError's message is printed by the raiser; the ladder must not
        # print a second line, and must exit 2 (not the catch-all 1).
        code, err = self._run_with_main(cli.UsageError("bad args"))
        self.assertEqual(code, 2)
        self.assertEqual(err, "")

    def test_lifecycle_error_passes_through_returncode(self):
        # LifecycleError reproduces the exact returncode of the failed
        # systemctl/podman call — not a flattened 1.
        for rc in (3, 5, 137):
            code, _ = self._run_with_main(cli.LifecycleError(rc))
            self.assertEqual(code, rc)

    def test_workload_masked_returns_1_and_prints(self):
        code, err = self._run_with_main(cli.WorkloadMasked("svc is masked"))
        self.assertEqual(code, 1)
        self.assertIn("masked", err)

    def test_workload_user_not_found_returns_1(self):
        code, err = self._run_with_main(cli.WorkloadUserNotFound("_wl-x"))
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

    def test_systemexit_from_main_propagates_unchanged(self):
        # Handlers that call sys.exit() directly raise SystemExit; the ladder
        # must not swallow it into a return value (its own exit code stands).
        with mock.patch.object(cli, 'main', mock.Mock(side_effect=SystemExit(7))):
            with self.assertRaises(SystemExit) as cm:
                cli._run_cli()
        self.assertEqual(cm.exception.code, 7)


class VersionFlagTest(unittest.TestCase):
    """`workloadctl --version` prints the baked version and exits 0."""

    def _run_version(self):
        """Drive main()'s argparse --version action; return (exit_code, stdout)."""
        buf = io.StringIO()
        with mock.patch.object(cli.sys, 'argv', ['workloadctl', '--version']), \
                redirect_stdout(buf):
            with self.assertRaises(SystemExit) as cm:
                cli.main()
        return cm.exception.code, buf.getvalue()

    def test_version_exits_0_and_prints_single_line(self):
        code, out = self._run_version()
        self.assertEqual(code, 0)
        lines = out.splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0], f"workloadctl {cli.__version__}")

    def test_source_checkout_reports_dev_fallback(self):
        # A real source checkout has no _version.py, so the CLI falls back to
        # the sentinel rather than crashing on the missing import. Block the
        # _version module and reload the CLI so this asserts the fallback branch
        # itself — not the module-level import, which would pick up a _version.py
        # that an in-place build or a system-installed package left importable on
        # sys.path (as on a host with the RPM installed).
        with mock.patch.dict(sys.modules, {'_version': None}):
            reloaded = importlib.util.module_from_spec(_spec)
            _loader.exec_module(reloaded)
            self.assertEqual(reloaded.__version__, "0-dev")


if __name__ == '__main__':
    unittest.main()
