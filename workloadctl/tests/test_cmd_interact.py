#!/usr/bin/env python3
"""Unit tests for cmd_interact covering the gaps left by
test_cmd_interact_dispatch.py (cmd_exec/cmd_logs dispatch) and test_cmd_cp.py
(cmd_cp parsing + docker-cp semantics):

  * cmd_shell — user-exists guard and substrate.open_shell() dispatch
    (container target + console flag).
  * cmd_incant — user-exists guard, `--` stripping, empty-argv exit(2),
    substrate.control() exit-code propagation.
  * cmd_logs extra_args passthrough (appended verbatim to the journalctl argv).
  * cmd_cp end-to-end success message + the pod.run() failure branches and
    "nothing was copied" branch of _cp_to_container / _cp_from_container that
    test_cmd_cp.py doesn't reach.
  * _cp_staging and _chown_tree helpers directly.
"""

import argparse
import io
import os
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

LIB = os.path.join(os.path.dirname(__file__), "..", "lib")
if LIB not in sys.path:
    sys.path.insert(0, LIB)

import cmd_interact  # noqa: E402


class _FakeConfig:
    username = "_wl-web"
    uid = 10001
    gid = 10001

    def __init__(self, home=None):
        self._home = home

    @property
    def home_dir(self):
        return self._home


def _run(fn, *args, **kwargs):
    out, err = io.StringIO(), io.StringIO()
    code = None
    try:
        with redirect_stdout(out), redirect_stderr(err):
            fn(*args, **kwargs)
    except SystemExit as e:
        code = e.code
    return code, out.getvalue(), err.getvalue()


class ShellTest(unittest.TestCase):
    def setUp(self):
        self.manager = mock.Mock()
        self.manager.user_exists.return_value = True
        self.enterContext(mock.patch.object(
            cmd_interact, "WorkloadConfig", lambda n: _FakeConfig()))
        self.calls = {}

        class _Sub:
            def open_shell(_self, container=None, console=False):
                self.calls["container"] = container
                self.calls["console"] = console

        self.enterContext(mock.patch.object(
            cmd_interact, "get_substrate", lambda c, m: _Sub()))

    def test_missing_user_exits_1(self):
        self.manager.user_exists.return_value = False
        code, _out, err = _run(
            cmd_interact.cmd_shell, argparse.Namespace(workload="web"), self.manager)
        self.assertEqual(code, 1)
        self.assertIn("does not exist", err)
        self.assertEqual(self.calls, {})

    def test_opens_shell_no_console_by_default(self):
        code, _out, _err = _run(
            cmd_interact.cmd_shell, argparse.Namespace(workload="web"), self.manager)
        self.assertIsNone(code)
        self.assertIsNone(self.calls["container"])
        self.assertFalse(self.calls["console"])

    def test_container_target_and_console_flag_forwarded(self):
        code, _out, _err = _run(
            cmd_interact.cmd_shell,
            argparse.Namespace(workload="app/api", console=True), self.manager)
        self.assertIsNone(code)
        self.assertEqual(self.calls["container"], "api")
        self.assertTrue(self.calls["console"])


class IncantTest(unittest.TestCase):
    def setUp(self):
        self.manager = mock.Mock()
        self.manager.user_exists.return_value = True
        self.enterContext(mock.patch.object(
            cmd_interact, "WorkloadConfig", lambda n: _FakeConfig()))
        self.calls = {}

        class _Sub:
            def control(_self, argv):
                self.calls["argv"] = argv
                return 3

        self.enterContext(mock.patch.object(
            cmd_interact, "get_substrate", lambda c, m: _Sub()))

    def _run(self, workload, argv):
        return _run(cmd_interact.cmd_incant,
                     argparse.Namespace(workload=workload, argv=argv), self.manager)

    def test_missing_user_exits_1(self):
        self.manager.user_exists.return_value = False
        code, _out, err = self._run("web", ["network", "ls"])
        self.assertEqual(code, 1)
        self.assertIn("does not exist", err)

    def test_strips_leading_double_dash(self):
        self._run("web", ["--", "volume", "ls"])
        self.assertEqual(self.calls["argv"], ["volume", "ls"])

    def test_empty_argv_exits_2(self):
        code, _out, err = self._run("web", [])
        self.assertEqual(code, 2)
        self.assertIn("no command", err)

    def test_bare_double_dash_is_empty(self):
        code, _out, err = self._run("web", ["--"])
        self.assertEqual(code, 2)
        self.assertIn("no command", err)

    def test_propagates_substrate_exit_code(self):
        code, _out, _err = self._run("git", ["query-status"])
        self.assertEqual(code, 3)
        self.assertEqual(self.calls["argv"], ["query-status"])


class LogsExtraArgsTest(unittest.TestCase):
    def test_extra_args_appended_verbatim(self):
        captured = {}

        class _Single:
            is_multi = False
            mode = "single"
            service_name = "workload-web.service"

            def container_names(self):
                return ["web"]

        class _Sub:
            def logs(_self, cmd):
                captured["cmd"] = cmd

        with mock.patch.object(cmd_interact, "WorkloadConfig", lambda n: _Single()), \
             mock.patch.object(cmd_interact, "get_substrate", lambda c, m: _Sub()):
            args = argparse.Namespace(
                workload="web", follow=False, lines=None, since=None,
                extra_args=["-o", "json"])
            code, _out, _err = _run(cmd_interact.cmd_logs, args, mock.Mock())
        self.assertIsNone(code)
        cmd = captured["cmd"]
        self.assertEqual(cmd[-2:], ["-o", "json"])
        # extra_args present -> default "-n 50" is suppressed.
        self.assertNotIn("-n", cmd)


class CpSuccessMessageTest(unittest.TestCase):
    """cmd_cp end-to-end: successful direction dispatch prints the checkmark."""

    def test_prints_success_message(self):
        manager = mock.Mock()
        manager.user_exists.return_value = True
        with mock.patch.object(cmd_interact, "WorkloadConfig", lambda n: _FakeConfig()), \
             mock.patch.object(cmd_interact, "resolve_container_target",
                                lambda c, ct, w: "container-web"), \
             mock.patch.object(cmd_interact, "_cp_to_container") as to_mock:
            args = argparse.Namespace(source="./a", destination="web:/b")
            code, out, _err = _run(cmd_interact.cmd_cp, args, manager)
        self.assertIsNone(code)
        to_mock.assert_called_once()
        self.assertIn("Copied successfully", out)


class CpPodFailureTest(unittest.TestCase):
    """pod.run() nonzero returncode branches, not reached by test_cmd_cp.py."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.stage = self.tmp / "stage"
        self.stage.mkdir()

        import contextlib

        @contextlib.contextmanager
        def _fake_staging(config):
            yield self.stage

        self.enterContext(mock.patch.object(cmd_interact, "_cp_staging", _fake_staging))
        self.enterContext(mock.patch.object(cmd_interact, "_chown_tree", lambda *a, **k: None))
        self.pod = mock.Mock()

    def test_to_container_pod_run_failure_exits_1(self):
        src = self.tmp / "file.txt"
        src.write_text("hi")
        self.pod.run.return_value = types.SimpleNamespace(
            returncode=1, stdout=b"", stderr="boom")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            with self.assertRaises(SystemExit) as cm:
                cmd_interact._cp_to_container(
                    self.pod, _FakeConfig(), "container-web", "/dst", str(src))
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("copy into container failed", err.getvalue())
        self.assertIn("boom", err.getvalue())

    def test_from_container_pod_run_failure_exits_1(self):
        dest = self.tmp / "out.txt"
        self.pod.run.return_value = types.SimpleNamespace(
            returncode=1, stdout=b"", stderr="nope")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            with self.assertRaises(SystemExit) as cm:
                cmd_interact._cp_from_container(
                    self.pod, _FakeConfig(), "container-web", "/src", str(dest))
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("copy from container failed", err.getvalue())
        self.assertIn("nope", err.getvalue())

    def test_from_container_nothing_copied_exits_1(self):
        dest = self.tmp / "out.txt"
        # pod.run "succeeds" but drops nothing into the staging dir.
        self.pod.run.return_value = types.SimpleNamespace(
            returncode=0, stdout=b"", stderr=b"")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            with self.assertRaises(SystemExit) as cm:
                cmd_interact._cp_from_container(
                    self.pod, _FakeConfig(), "container-web", "/src", str(dest))
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("nothing was copied", err.getvalue())


class CpStagingAndChownTreeTest(unittest.TestCase):
    """Exercise _cp_staging and _chown_tree directly (os.chown/os.chmod
    stubbed since the test doesn't run as root)."""

    def test_staging_missing_home_exits_1(self):
        cfg = _FakeConfig(home=Path("/nonexistent/definitely-not-here"))
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            with self.assertRaises(SystemExit) as cm:
                with cmd_interact._cp_staging(cfg):
                    pass  # pragma: no cover - never reached
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("does not exist", err.getvalue())

    def test_staging_creates_and_cleans_up_dir(self):
        with tempfile.TemporaryDirectory() as home:
            cfg = _FakeConfig(home=Path(home))
            with mock.patch.object(cmd_interact.os, "chown") as chown_mock, \
                 mock.patch.object(cmd_interact.os, "chmod") as chmod_mock:
                with cmd_interact._cp_staging(cfg) as d:
                    self.assertTrue(d.is_dir())
                    self.assertTrue(str(d).startswith(home))
                    created = d
                chown_mock.assert_called_once_with(
                    created, cfg.uid, cfg.gid, follow_symlinks=False)
                chmod_mock.assert_called_once_with(created, 0o700)
            # Removed on exit even though chown/chmod were mocked out.
            self.assertFalse(created.exists())

    def test_chown_tree_recurses_and_swallows_oserror(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            (base / "sub").mkdir()
            (base / "sub" / "f.txt").write_text("x")
            calls = []

            def _fake_chown(path, uid, gid, follow_symlinks=True):
                calls.append(os.path.basename(path))
                if os.path.basename(path) == "f.txt":
                    raise OSError("nope")

            with mock.patch.object(cmd_interact.os, "chown", _fake_chown):
                cmd_interact._chown_tree(base, 0, 0)
            # top-level dir + the "sub" subdir + the file all attempted;
            # the OSError on the file is swallowed rather than propagating.
            self.assertIn(os.path.basename(str(base)), calls)
            self.assertIn("sub", calls)
            self.assertIn("f.txt", calls)


if __name__ == "__main__":
    unittest.main()
