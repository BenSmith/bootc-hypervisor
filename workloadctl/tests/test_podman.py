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

    def test_podman_error_preserves_cmd_args(self):
        # BaseException.__init__ overwrites .args, so PodmanError must expose
        # the argv under a different attribute (.cmd_args) that survives
        # construction.
        exc = PodmanError(125, "boom", ["image", "inspect", "x"])
        self.assertEqual(exc.cmd_args, ("image", "inspect", "x"))

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
    def test_for_user_passes_session_bus_for_cgroup_placement(self, mock_run):
        # Without DBUS_SESSION_BUS_ADDRESS pointing at the workload user's own
        # bus, rootless crun writes the container cgroup.procs directly and
        # `podman exec` from a foreign session cgroup fails with EPERM. The
        # value must match the user's runtime-dir bus for the migration to be
        # routed through user@<uid>.service.
        mock_run.return_value = _ok(stdout=json.dumps([{"Id": "x"}]))
        self.p.image_id("ref")
        cmd = mock_run.call_args.args[0]
        self.assertIn(
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/5001/bus", cmd
        )

    @patch("subprocess.run")
    def test_for_root_omits_session_bus(self, mock_run):
        # Root talks to the system store directly; no per-user bus applies.
        mock_run.return_value = _ok(stdout=json.dumps([{"Id": "x"}]))
        Podman.for_root().image_id("ref")
        cmd = mock_run.call_args.args[0]
        self.assertFalse(any("DBUS_SESSION_BUS_ADDRESS" in a for a in cmd))

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


class PodmanUncoveredMethodTests(unittest.TestCase):
    """Cover the structured-read/mutator methods not yet exercised above."""

    def setUp(self):
        self.p = Podman.for_user("_wl-test", 5001, "/var/lib/workloads/test")
        self.root = Podman.for_root()

    @patch("subprocess.run")
    def test_image_info_present(self, mock_run):
        mock_run.return_value = _ok(stdout=json.dumps(
            [{"Id": "sha256:abcd", "RepoTags": ["x:latest"]}]
        ))
        info = self.p.image_info("ref")
        self.assertEqual(info["Id"], "sha256:abcd")

    @patch("subprocess.run")
    def test_image_info_missing_returns_none(self, mock_run):
        mock_run.return_value = _fail("Error: image not known")
        self.assertIsNone(self.p.image_info("ref"))

    @patch("subprocess.run")
    def test_container_status_matches_by_name(self, mock_run):
        mock_run.return_value = _ok(stdout=json.dumps(
            [{"Names": ["c1"], "Status": "Up 2 hours"},
             {"Names": ["c2"], "Status": "Exited"}]
        ))
        self.assertEqual(self.p.container_status("c1"), "Up 2 hours")

    @patch("subprocess.run")
    def test_container_status_no_match_returns_none(self, mock_run):
        mock_run.return_value = _ok(stdout=json.dumps(
            [{"Names": ["other"], "Status": "Up"}]
        ))
        self.assertIsNone(self.p.container_status("c1"))

    @patch("subprocess.run")
    def test_container_status_empty_list(self, mock_run):
        mock_run.return_value = _ok(stdout="null")
        self.assertIsNone(self.p.container_status("c1"))

    @patch("subprocess.run")
    def test_container_exists_true(self, mock_run):
        mock_run.return_value = _ok(stdout=json.dumps([{"Id": "abc"}]))
        self.assertTrue(self.p.container_exists("c1"))

    @patch("subprocess.run")
    def test_container_exists_false(self, mock_run):
        mock_run.return_value = _fail("Error: no such container c1")
        self.assertFalse(self.p.container_exists("c1"))

    @patch("subprocess.run")
    def test_list_containers_with_filters_passes_filter_args(self, mock_run):
        mock_run.return_value = _ok(stdout="null")
        self.p.list_containers(filters={"name": "c1", "status": "running"})
        cmd = mock_run.call_args.args[0]
        self.assertIn("--filter", cmd)
        self.assertIn("name=c1", cmd)
        self.assertIn("status=running", cmd)

    @patch("subprocess.run")
    def test_list_containers_all_false_omits_all_flag(self, mock_run):
        mock_run.return_value = _ok(stdout="null")
        self.p.list_containers(all=False)
        cmd = mock_run.call_args.args[0]
        self.assertNotIn("--all", cmd)

    @patch("subprocess.run")
    def test_network_exists_true(self, mock_run):
        mock_run.return_value = _ok()
        self.assertTrue(self.p.network_exists("net1"))

    @patch("subprocess.run")
    def test_network_exists_false(self, mock_run):
        mock_run.return_value = _fail("Error: network not found", code=1)
        self.assertFalse(self.p.network_exists("net1"))

    @patch("subprocess.run")
    def test_network_exists_does_not_raise_on_failure(self, mock_run):
        # network exists uses check=False, so a nonzero return must not raise.
        mock_run.return_value = _fail("boom", code=125)
        try:
            self.p.network_exists("net1")
        except PodmanError:
            self.fail("network_exists must not raise on nonzero returncode")

    @patch("subprocess.run")
    def test_commit_success(self, mock_run):
        mock_run.return_value = _ok()
        self.p.commit("container1", "myimage:snap")  # no raise
        cmd = mock_run.call_args.args[0]
        self.assertIn("commit", cmd)
        self.assertIn("container1", cmd)
        self.assertIn("myimage:snap", cmd)

    @patch("subprocess.run")
    def test_commit_failure_raises(self, mock_run):
        mock_run.return_value = _fail("Error: no such container", code=125)
        with self.assertRaises(PodmanError):
            self.p.commit("container1", "myimage:snap")

    @patch("subprocess.run")
    def test_pull_success(self, mock_run):
        mock_run.return_value = _ok()
        self.p.pull("docker.io/library/alpine")  # no raise
        cmd = mock_run.call_args.args[0]
        self.assertIn("pull", cmd)

    @patch("subprocess.run")
    def test_pull_failure_raises(self, mock_run):
        mock_run.return_value = _fail("Error: unable to find image", code=125)
        with self.assertRaises(PodmanError):
            self.p.pull("nope:latest")

    @patch("subprocess.run")
    def test_network_create_success(self, mock_run):
        mock_run.return_value = _ok()
        self.p.network_create("mynet")  # no raise
        cmd = mock_run.call_args.args[0]
        self.assertIn("network", cmd)
        self.assertIn("create", cmd)
        self.assertIn("mynet", cmd)

    @patch("subprocess.run")
    def test_run_escape_hatch_passes_through(self, mock_run):
        mock_run.return_value = CompletedProcess(
            args=[], returncode=0, stdout="hello\n", stderr="")
        proc = self.p.run("exec", "c1", "echo", "hi", capture_output=True)
        self.assertEqual(proc.stdout, "hello\n")
        cmd = mock_run.call_args.args[0]
        self.assertIn("exec", cmd)
        # escape hatch does not raise-on-failure by default (check=False)
        self.assertEqual(mock_run.call_args.kwargs.get("check"), False)

    @patch("subprocess.run")
    def test_run_escape_hatch_check_true_raises_on_failure(self, mock_run):
        import subprocess as sp
        mock_run.side_effect = sp.CalledProcessError(1, ["podman"])
        with self.assertRaises(sp.CalledProcessError):
            self.p.run("exec", "c1", "false", check=True)

    @patch("subprocess.run")
    def test_check_false_returns_failed_proc_without_raising(self, mock_run):
        # Exercises the `if check: raise ...` else `return proc` branch (line 145)
        # via network_exists, the only public method that passes check=False.
        mock_run.return_value = _fail("some transient error", code=2)
        proc = self.p.network_exists("net1")
        self.assertFalse(proc)


if __name__ == "__main__":
    unittest.main()
