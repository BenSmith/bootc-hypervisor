#!/usr/bin/env python3
"""The stale-run sweep reports what it actually removed.

`reap_stale_runs()` exists to stop leaked run dirs from starving a long-lived CI
runner's disk, and it removes them with `shutil.rmtree(..., ignore_errors=True)`.
For a long time it appended every candidate to its reaped list regardless of
whether the removal worked — so a gate run's dir, whose root-owned `bib/` content
(BIB runs under `sudo podman run --privileged`; only `/output` gets `--chown`)
defeats an unprivileged rmtree, was reported as reaped and left on disk. Observed
on the dev host: two dirs that `just reap-stale-runs` claimed for days without removing.

A sweep that prints success while doing nothing is worse than one that fails,
because the starvation it exists to prevent then arrives with no warning. These
tests pin the honest-reporting contract, and the `sudo rm -rf` guard that the
escalation path depends on.

vmlaunch is harness code under tests/runtime/ rather than a lib/ module, so it is
loaded by path.
"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from tests import load_script

vmlaunch = load_script("tests/runtime/vmlaunch.py", "vmlaunch")


class TestIsRunDir(unittest.TestCase):
    """The whole-of-it guard on privileged removal, so it is tested first."""

    def test_accepts_a_real_run_dir(self):
        for root in (vmlaunch.RUN_ROOT, Path("/tmp")):
            with self.subTest(root=root):
                self.assertTrue(
                    vmlaunch._is_run_dir(root / f"{vmlaunch.RUN_PREFIX}abc123"))

    def test_rejects_anything_else(self):
        cases = [
            Path("/tmp/not-a-run-dir"),                     # wrong prefix
            Path("/home/someone/wlrt-run.abc"),             # wrong parent
            Path(f"/tmp/nested/{vmlaunch.RUN_PREFIX}abc"),   # not directly under
            Path("/"),
            Path("/var"),
        ]
        for p in cases:
            with self.subTest(path=p):
                self.assertFalse(vmlaunch._is_run_dir(p))

    def test_a_symlink_cannot_aim_the_removal_elsewhere(self):
        """Checked against the resolved path: a run-dir-named symlink pointing at
        something precious must not qualify. This is the case that makes the
        difference between a guard and the appearance of one."""
        with TemporaryDirectory() as tmp:
            link = Path(tmp) / f"{vmlaunch.RUN_PREFIX}evil"
            link.symlink_to("/etc")
            self.assertFalse(vmlaunch._is_run_dir(link))


class TestReapReportsOnlyWhatItRemoved(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        # Point both swept roots at the sandbox: reap_stale_runs unions RUN_ROOT
        # with /tmp, and a test must never glob the real /tmp.
        self.enterContext(mock.patch.object(vmlaunch, "RUN_ROOT", self.root))
        self.enterContext(mock.patch.object(vmlaunch, "Path", _PathAt(self.root)))

    def _run_dir(self, suffix):
        d = self.root / f"{vmlaunch.RUN_PREFIX}{suffix}"
        d.mkdir()
        return d

    def test_a_removed_dir_is_reaped(self):
        d = self._run_dir("gone")
        reaped, stuck = vmlaunch.reap_stale_runs()
        self.assertEqual((reaped, stuck), ([d], []))
        self.assertFalse(d.exists())

    def test_a_surviving_dir_is_reported_stuck_not_reaped(self):
        """The actual bug. rmtree(ignore_errors=True) leaves the dir and says
        nothing; the escalation also fails (no passwordless sudo in the test, and
        stubbed out here regardless). It must land in `stuck`."""
        d = self._run_dir("stubborn")
        with mock.patch.object(vmlaunch.shutil, "rmtree"), \
             mock.patch.object(vmlaunch.subprocess, "run") as sudo_run:
            reaped, stuck = vmlaunch.reap_stale_runs()
        self.assertEqual((reaped, stuck), ([], [d]))
        self.assertTrue(d.exists(), "sanity: the dir was meant to survive")
        # And it did try to escalate before giving up.
        argv = sudo_run.call_args.args[0]
        self.assertEqual(argv[:4], ["sudo", "-n", "rm", "-rf"])
        self.assertEqual(argv[-1], str(d))

    def test_escalation_is_skipped_for_a_path_that_is_not_a_run_dir(self):
        """No `sudo rm -rf` may be issued for anything _is_run_dir rejects, even
        when the unprivileged removal failed."""
        d = self._run_dir("outside")
        with mock.patch.object(vmlaunch.shutil, "rmtree"), \
             mock.patch.object(vmlaunch, "_is_run_dir", return_value=False), \
             mock.patch.object(vmlaunch.subprocess, "run") as sudo_run:
            reaped, stuck = vmlaunch.reap_stale_runs()
        self.assertEqual((reaped, stuck), ([], [d]))
        sudo_run.assert_not_called()

    def test_mixed_sweep_splits_the_two_lists(self):
        ok = self._run_dir("a-ok")
        bad = self._run_dir("b-bad")
        real_rmtree = vmlaunch.shutil.rmtree

        def picky_rmtree(path, **kw):
            if Path(path) == bad:
                return
            real_rmtree(path, **kw)

        with mock.patch.object(vmlaunch.shutil, "rmtree", picky_rmtree), \
             mock.patch.object(vmlaunch.subprocess, "run"):
            reaped, stuck = vmlaunch.reap_stale_runs()
        self.assertEqual((reaped, stuck), ([ok], [bad]))

    def test_nothing_stale_is_not_an_error(self):
        self.assertEqual(vmlaunch.reap_stale_runs(), ([], []))


class _PathAt:
    """`Path` stand-in that redirects the hardcoded `/tmp` sweep into a sandbox.

    reap_stale_runs globs `{RUN_ROOT, Path("/tmp")}`. RUN_ROOT is patchable but
    the literal is not, and a test that globbed the real /tmp would reap a
    developer's live run dir. Only that one literal is rewritten; every other path
    is constructed normally.
    """

    def __init__(self, sandbox: Path):
        self._sandbox = sandbox

    def __call__(self, *args):
        if args == ("/tmp",):
            return self._sandbox
        return Path(*args)

    def __getattr__(self, name):
        return getattr(Path, name)


if __name__ == "__main__":
    unittest.main()
