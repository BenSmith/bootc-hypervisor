#!/usr/bin/env python3
"""Unit tests for cmd_cp: workload:path parsing/direction detection, the
user-exists guard, and the docker-cp destination semantics in
_cp_from_container / _cp_to_container.

The chown-to-root and rootless-podman bits need a live host, so those seams
(_cp_staging, _chown_tree, the podman wrapper) are stubbed; what's exercised is
the host-side path logic that previously only ran behind a live SSH target.
"""

import argparse
import contextlib
import io
import tempfile
import types
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock


import cmd_interact  # noqa: E402


class _FakeConfig:
    username = "_wl-web"
    uid = 10001
    gid = 10001


def _ns(source, destination):
    return argparse.Namespace(source=source, destination=destination)


class CpParseTest(unittest.TestCase):
    """Direction detection + guards, with the heavy copy helpers stubbed."""

    def setUp(self):
        self.manager = mock.Mock()
        self.manager.user_exists.return_value = True
        self.enterContext(mock.patch.object(
            cmd_interact, "WorkloadConfig", lambda n: _FakeConfig()))
        self.enterContext(mock.patch.object(
            cmd_interact, "resolve_container_target", lambda c, ct, w: "container-web"))
        self.to = self.enterContext(mock.patch.object(cmd_interact, "_cp_to_container"))
        self.frm = self.enterContext(mock.patch.object(cmd_interact, "_cp_from_container"))

    def _run(self, source, destination):
        out, err = io.StringIO(), io.StringIO()
        code = None
        try:
            with redirect_stdout(out), redirect_stderr(err):
                cmd_interact.cmd_cp(_ns(source, destination), self.manager)
        except SystemExit as e:
            code = e.code
        self._err = err.getvalue()
        return code

    def test_to_container_direction(self):
        self.assertIsNone(self._run("./local.txt", "web:/data/local.txt"))
        self.frm.assert_not_called()
        self.to.assert_called_once()
        # _cp_to_container(pod, config, target, container_path, host_path)
        _pod, _cfg, _target, container_path, host_path = self.to.call_args.args
        self.assertEqual(container_path, "/data/local.txt")
        self.assertEqual(host_path, "./local.txt")

    def test_from_container_direction(self):
        self.assertIsNone(self._run("web:/etc/conf", "./conf"))
        self.to.assert_not_called()
        self.frm.assert_called_once()
        _pod, _cfg, _target, container_path, host_path = self.frm.call_args.args
        self.assertEqual(container_path, "/etc/conf")
        self.assertEqual(host_path, "./conf")

    def test_both_sides_colon_is_error(self):
        code = self._run("a:/x", "b:/y")
        self.assertEqual(code, 1)
        self.assertIn("workload:path format", self._err)
        self.to.assert_not_called()
        self.frm.assert_not_called()

    def test_neither_side_colon_is_error(self):
        code = self._run("./a", "./b")
        self.assertEqual(code, 1)
        self.assertIn("workload:path format", self._err)

    def test_user_missing_is_error(self):
        self.manager.user_exists.return_value = False
        code = self._run("./a", "web:/b")
        self.assertEqual(code, 1)
        self.assertIn("does not exist", self._err)
        self.to.assert_not_called()


class CpSemanticsTest(unittest.TestCase):
    """_cp_to/_from path guards and docker-cp destination placement, with the
    staging dir handed in directly and chown stubbed out."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.stage = self.tmp / "stage"
        self.stage.mkdir()
        # _cp_staging yields a workload-owned temp dir; hand it our real one.
        @contextlib.contextmanager
        def _fake_staging(config):
            yield self.stage
        self.enterContext(mock.patch.object(cmd_interact, "_cp_staging", _fake_staging))
        # chown-to-root / chown-to-workload need privilege; make them no-ops.
        self.enterContext(mock.patch.object(cmd_interact, "_chown_tree", lambda *a, **k: None))
        self.pod = mock.Mock()

    def _err_exit(self, fn, *args):
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            with self.assertRaises(SystemExit) as cm:
                fn(*args)
        return cm.exception.code, err.getvalue()

    # --- to-container guard ---

    def test_to_missing_source_exits(self):
        code, err = self._err_exit(
            cmd_interact._cp_to_container, self.pod, _FakeConfig(),
            "container-web", "/dst", str(self.tmp / "nope"))
        self.assertEqual(code, 1)
        self.assertIn("does not exist", err)
        self.pod.run.assert_not_called()

    # --- from-container guard ---

    def test_from_missing_dest_parent_exits(self):
        code, err = self._err_exit(
            cmd_interact._cp_from_container, self.pod, _FakeConfig(),
            "container-web", "/src", str(self.tmp / "ghost-dir" / "f"))
        self.assertEqual(code, 1)
        self.assertIn("does not exist", err)
        self.pod.run.assert_not_called()

    # --- from-container docker-cp destination semantics ---

    def _pod_produces(self, filename, content=b"hi"):
        """Make pod.run drop `filename` into the staging dir (as podman cp would)."""
        def _run(*args, **kwargs):
            (self.stage / filename).write_bytes(content)
            return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        self.pod.run.side_effect = _run

    def test_from_into_existing_dir_uses_basename(self):
        dest_dir = self.tmp / "out"
        dest_dir.mkdir()
        self._pod_produces("conf")
        with redirect_stdout(io.StringIO()):
            cmd_interact._cp_from_container(
                self.pod, _FakeConfig(), "container-web", "/etc/conf", str(dest_dir))
        # Existing dir => result lands under the produced basename inside it.
        self.assertTrue((dest_dir / "conf").is_file())

    def test_from_to_named_path_overwrites(self):
        dest = self.tmp / "renamed.conf"
        dest.write_bytes(b"old")
        self._pod_produces("conf", content=b"new")
        with redirect_stdout(io.StringIO()):
            cmd_interact._cp_from_container(
                self.pod, _FakeConfig(), "container-web", "/etc/conf", str(dest))
        # Non-dir destination names the result; existing file is overwritten.
        self.assertTrue(dest.is_file())
        self.assertEqual(dest.read_bytes(), b"new")
        self.assertFalse((dest / "conf").exists() if dest.is_dir() else False)


if __name__ == "__main__":
    unittest.main()
