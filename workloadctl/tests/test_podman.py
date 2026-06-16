"""Unit tests for lib/podman.py."""

import json
import os
import sys
import unittest
from subprocess import CompletedProcess
from unittest.mock import call, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from podman import Podman, PodmanError


def _ok(stdout="", stderr=""):
    return CompletedProcess(args=[], returncode=0, stdout=stdout, stderr=stderr)


def _fail(stderr, code=125):
    return CompletedProcess(args=[], returncode=code, stdout="", stderr=stderr)


class PodmanWrapperTests(unittest.TestCase):
    def setUp(self):
        self.p = Podman.for_user("_wl-test", 5001, "/var/lib/workloads/test")

    @patch("subprocess.run")
    def test_image_id_present(self, mock_run):
        mock_run.return_value = _ok(stdout=json.dumps([{"Id": "sha256:abcd"}]))
        self.assertEqual(self.p.image_id("ref"), "sha256:abcd")

    @patch("subprocess.run")
    def test_image_id_missing(self, mock_run):
        mock_run.return_value = _fail("Error: image not known")
        self.assertEqual(self.p.image_id("ref"), "")

    @patch("subprocess.run")
    def test_image_id_unexpected_failure_raises(self, mock_run):
        mock_run.return_value = _fail("sudo: a password is required", code=1)
        with self.assertRaises(PodmanError):
            self.p.image_id("ref")

    @patch("subprocess.run")
    def test_container_health_healthy(self, mock_run):
        mock_run.return_value = _ok(stdout=json.dumps(
            [{"State": {"Health": {"Status": "healthy"}}}]
        ))
        self.assertEqual(self.p.container_health("c"), "healthy")

    @patch("subprocess.run")
    def test_container_health_no_healthcheck(self, mock_run):
        mock_run.return_value = _ok(stdout=json.dumps([{"State": {}}]))
        self.assertIsNone(self.p.container_health("c"))

    @patch("subprocess.run")
    def test_container_health_missing(self, mock_run):
        mock_run.return_value = _fail("Error: no such container c")
        self.assertIsNone(self.p.container_health("c"))

    @patch("subprocess.run")
    def test_list_containers_empty_null(self, mock_run):
        mock_run.return_value = _ok(stdout="null\n")
        self.assertEqual(self.p.list_containers(), [])

    @patch("subprocess.run")
    def test_list_containers_populated(self, mock_run):
        mock_run.return_value = _ok(stdout=json.dumps(
            [{"Names": ["c1"], "Status": "Up 2 hours"}]
        ))
        rows = self.p.list_containers()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["Status"], "Up 2 hours")

    @patch("subprocess.run")
    def test_tag_success(self, mock_run):
        mock_run.return_value = _ok()
        self.p.tag("a", "b")  # should not raise

    @patch("subprocess.run")
    def test_tag_failure_raises(self, mock_run):
        mock_run.return_value = _fail("Error: image not known", code=125)
        with self.assertRaises(PodmanError) as cm:
            self.p.tag("a", "b")
        self.assertEqual(cm.exception.returncode, 125)
        self.assertIn("image not known", cm.exception.stderr)

    @patch("subprocess.run")
    def test_for_root_no_sudo_prefix(self, mock_run):
        mock_run.return_value = _ok(stdout=json.dumps([{"Id": "x"}]))
        Podman.for_root().image_id("ref")
        cmd = mock_run.call_args.args[0]
        self.assertEqual(cmd[0], "podman")
        self.assertNotIn("sudo", cmd)

    @patch("subprocess.run")
    def test_for_user_has_sudo_prefix(self, mock_run):
        mock_run.return_value = _ok(stdout=json.dumps([{"Id": "x"}]))
        self.p.image_id("ref")
        cmd = mock_run.call_args.args[0]
        self.assertEqual(cmd[0], "sudo")
        self.assertIn("_wl-test", cmd)

    @patch("subprocess.run")
    def test_log_level_error_passed(self, mock_run):
        mock_run.return_value = _ok(stdout="null")
        self.p.list_containers()
        cmd = mock_run.call_args.args[0]
        self.assertIn("--log-level=error", cmd)


class RuntimeDirRetryTests(unittest.TestCase):
    """Tests for the self-healing retry on /run/user/<uid> missing."""

    def setUp(self):
        # UID 5001 matches the XDG_RUNTIME_DIR in _build_cmd
        self.p = Podman.for_user("_wl-test", 5001, "/var/lib/workloads/test")

    def _runtime_dir_error(self, uid=5001):
        return _fail(
            f"Failed to obtain podman configuration: "
            f"lstat /run/user/{uid}: no such file or directory",
            code=1,
        )

    @patch("podman.Podman._ensure_runtime_dir")
    @patch("subprocess.run")
    def test_retry_on_runtime_dir_missing(self, mock_run, mock_ensure):
        """First call fails with runtime-dir error; retry succeeds."""
        ok = _ok(stdout=json.dumps([{"Id": "sha256:abcd"}]))
        mock_run.side_effect = [self._runtime_dir_error(), ok]
        result = self.p.image_id("ref")
        self.assertEqual(result, "sha256:abcd")
        mock_ensure.assert_called_once()
        self.assertEqual(mock_run.call_count, 2)

    @patch("podman.Podman._ensure_runtime_dir")
    @patch("subprocess.run")
    def test_retry_still_fails_raises_podman_error(self, mock_run, mock_ensure):
        """Both calls fail with runtime-dir error — raises PodmanError."""
        err = self._runtime_dir_error()
        mock_run.side_effect = [err, err]
        with self.assertRaises(PodmanError):
            self.p.image_id("ref")
        mock_ensure.assert_called_once()
        self.assertEqual(mock_run.call_count, 2)

    @patch("podman.Podman._ensure_runtime_dir")
    @patch("subprocess.run")
    def test_no_retry_for_root_podman(self, mock_run, mock_ensure):
        """Root podman (username=None) does not trigger the retry path."""
        p_root = Podman.for_root()
        mock_run.return_value = self._runtime_dir_error()
        with self.assertRaises(PodmanError):
            p_root.image_id("ref")
        mock_ensure.assert_not_called()
        self.assertEqual(mock_run.call_count, 1)

    @patch("podman.Podman._ensure_runtime_dir")
    @patch("subprocess.run")
    def test_no_retry_for_different_uid(self, mock_run, mock_ensure):
        """Runtime-dir error for a different UID does not trigger retry."""
        mock_run.return_value = self._runtime_dir_error(uid=9999)
        with self.assertRaises(PodmanError):
            self.p.image_id("ref")
        mock_ensure.assert_not_called()
        self.assertEqual(mock_run.call_count, 1)

    @patch("podman.Podman._ensure_runtime_dir")
    @patch("subprocess.run")
    def test_no_retry_for_unrelated_error(self, mock_run, mock_ensure):
        """Unrelated podman failure is raised immediately, no retry."""
        mock_run.return_value = _fail("sudo: a password is required", code=1)
        with self.assertRaises(PodmanError):
            self.p.image_id("ref")
        mock_ensure.assert_not_called()
        self.assertEqual(mock_run.call_count, 1)

    @patch("podman.Podman._ensure_runtime_dir")
    @patch("subprocess.run")
    def test_allow_missing_not_affected_by_retry(self, mock_run, mock_ensure):
        """allow_missing=True still returns empty-string for not-found errors (no retry)."""
        mock_run.return_value = _fail("Error: image not known")
        result = self.p.image_id("ref")
        self.assertEqual(result, "")
        mock_ensure.assert_not_called()


if __name__ == "__main__":
    unittest.main()
