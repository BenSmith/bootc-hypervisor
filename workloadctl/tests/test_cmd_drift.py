#!/usr/bin/env python3
"""Unit tests for cmd_drift's orphan detection.

cmd_drift runs the real generator into a scratch dir and diffs its output
against /run/systemd/system. The content-diff side (edited-but-not-re-enabled
units) is exercised on live hosts by tests/cli_surface. What is pinned here is
the *orphan* side — live run-files a removed workload left behind — across every
kind the generator writes into that tree: the .service units, the sysusers
.conf, and the multi-user.target.wants enablement symlink. A gap there makes
"No drift detected" a false all-clear, so each kind gets a case.

The generator is replaced by a tiny fake that writes a known "still generated"
set for one workload (`keep`); LIVE_UNITS_DIR is staged with that same set plus
a removed workload's (`gone`) leftovers.
"""

import argparse
import io
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

LIB = os.path.join(os.path.dirname(__file__), "..", "lib")
if LIB not in sys.path:
    sys.path.insert(0, LIB)

import cmd_drift  # noqa: E402


# A stand-in for generators/workload-generate: given argv[1]=services dir, emit
# the full run-file set for one still-configured workload named `keep`.
_FAKE_GENERATOR = """#!/usr/bin/env python3
import os, sys
from pathlib import Path
out = Path(sys.argv[1])
(out / "multi-user.target.wants").mkdir(parents=True, exist_ok=True)
(out / "workload-keep.service").write_text("KEEP\\n")
(out / "workload-keep.conf").write_text("u keep 10000\\n")
os.symlink("../workload-keep.service",
           out / "multi-user.target.wants" / "workload-keep.service")
"""


class OrphanDetectionTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="drift-test-")
        root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

        gen = root / "fake-generate"
        gen.write_text(_FAKE_GENERATOR)
        gen.chmod(gen.stat().st_mode | stat.S_IEXEC | stat.S_IRUSR)

        self.live = root / "live"
        (self.live / "multi-user.target.wants").mkdir(parents=True)

        self.enterContext(mock.patch.object(
            cmd_drift, "_find_generator", lambda: gen))
        self.enterContext(mock.patch.object(
            cmd_drift, "LIVE_UNITS_DIR", self.live))
        self.enterContext(mock.patch.object(
            cmd_drift, "workload_config_dir", lambda: root / "cfg"))

    def _stage_keep(self):
        """Live copy that matches what the fake generator emits (no drift)."""
        (self.live / "workload-keep.service").write_text("KEEP\n")
        (self.live / "workload-keep.conf").write_text("u keep 10000\n")
        os.symlink("../workload-keep.service",
                   self.live / "multi-user.target.wants" / "workload-keep.service")

    def _stage_gone(self):
        """Leftovers of a workload removed from config (no generated match)."""
        (self.live / "workload-gone.service").write_text("GONE\n")
        (self.live / "workload-gone.conf").write_text("u gone 10001\n")
        os.symlink("../workload-gone.service",
                   self.live / "multi-user.target.wants" / "workload-gone.service")

    def _run(self, workload=None):
        args = argparse.Namespace(workload=workload, json=False)
        out = io.StringIO()
        code = None
        try:
            with redirect_stdout(out):
                cmd_drift.cmd_drift(args, manager=None)
        except SystemExit as e:
            code = e.code
        return code, out.getvalue()

    def test_no_orphans_reports_in_sync(self):
        self._stage_keep()
        code, out = self._run()
        self.assertEqual(code, 0)
        self.assertIn("No drift", out)

    def test_orphan_service_reported(self):
        self._stage_keep()
        self._stage_gone()
        code, out = self._run()
        self.assertEqual(code, 1)
        self.assertIn("workload-gone.service", out)
        self.assertNotIn("workload-keep.service", out)   # still generated

    def test_orphan_sysusers_conf_reported(self):
        # The .conf is the kind the old glob-only scan missed entirely.
        self._stage_keep()
        (self.live / "workload-gone.conf").write_text("u gone 10001\n")
        code, out = self._run()
        self.assertEqual(code, 1)
        self.assertIn("workload-gone.conf", out)

    def test_orphan_wants_symlink_reported(self):
        self._stage_keep()
        os.symlink("../workload-gone.service",
                   self.live / "multi-user.target.wants" / "workload-gone.service")
        code, out = self._run()
        self.assertEqual(code, 1)
        self.assertIn("multi-user.target.wants/workload-gone.service", out)

    def test_missing_wants_symlink_reported(self):
        # Generator wants the enablement symlink but the live tree lacks it —
        # the workload would not auto-start on boot (owned-but-missing).
        (self.live / "workload-keep.service").write_text("KEEP\n")
        (self.live / "workload-keep.conf").write_text("u keep 10000\n")
        # deliberately omit multi-user.target.wants/workload-keep.service
        code, out = self._run()
        self.assertEqual(code, 1)
        self.assertIn("multi-user.target.wants/workload-keep.service", out)

    def test_dangling_enablement_symlink_not_reported_missing(self):
        # Regression: a present-but-dangling enablement symlink (its target
        # moved/removed) must NOT be reported as a missing symlink. The link
        # file exists, so enablement is present even though exists() follows the
        # link to a nonexistent target and returns False.
        (self.live / "workload-keep.service").write_text("KEEP\n")
        (self.live / "workload-keep.conf").write_text("u keep 10000\n")
        os.symlink("../does-not-exist.service",
                   self.live / "multi-user.target.wants" / "workload-keep.service")
        code, out = self._run()
        self.assertEqual(code, 0)
        self.assertNotIn("missing enablement symlink", out)

    def test_missing_sysusers_conf_reported(self):
        self._stage_keep()
        (self.live / "workload-keep.conf").unlink()
        code, out = self._run()
        self.assertEqual(code, 1)
        self.assertIn("workload-keep.conf", out)

    def test_workload_filter_scopes_orphans(self):
        # Filtering to the still-present workload hides an unrelated orphan.
        self._stage_keep()
        self._stage_gone()
        code, out = self._run(workload="keep")
        self.assertEqual(code, 0)
        self.assertNotIn("gone", out)


if __name__ == "__main__":
    unittest.main()
