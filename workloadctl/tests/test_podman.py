"""Unit tests for lib/podman.py."""

import json
import os
import sys
import unittest
from subprocess import CompletedProcess
from unittest.mock import patch

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


if __name__ == "__main__":
    unittest.main()
