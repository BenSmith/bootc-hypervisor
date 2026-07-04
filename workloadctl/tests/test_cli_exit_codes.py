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
from contextlib import redirect_stderr
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

    def test_generic_exception_returns_1(self):
        code, err = self._run_with_main(ValueError("boom"))
        self.assertEqual(code, 1)
        self.assertIn("Error:", err)

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


if __name__ == '__main__':
    unittest.main()
