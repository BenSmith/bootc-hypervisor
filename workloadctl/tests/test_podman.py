"""Unit tests for lib/podman.py."""

import json
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

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

    # These two pin the sudo path specifically, so they fix the caller's euid
    # rather than inheriting the test runner's (as root the wrapper setuids
    # instead — RootDropsPrivsWithoutSudoTests).
    @patch("podman.os.geteuid", return_value=1000)
    @patch("subprocess.run")
    def test_for_user_has_sudo_prefix(self, mock_run, _euid):
        mock_run.return_value = _ok(stdout=json.dumps([{"Id": "x"}]))
        self.p.image_id("ref")
        cmd = mock_run.call_args.args[0]
        self.assertEqual(cmd[0], "sudo")
        self.assertIn("_wl-test", cmd)

    @patch("podman.os.geteuid", return_value=1000)
    @patch("subprocess.run")
    def test_for_user_passes_session_bus_for_cgroup_placement(
            self, mock_run, _euid):
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


class EnsureRuntimeDirGateTests(unittest.TestCase):
    """The read-path self-heal only fires for an already-lingering user; it
    must never enable-linger for a disabled workload (which would trigger a
    set-user-linger polkit prompt / silently re-linger under sudo)."""

    def setUp(self):
        self.p = Podman.for_user("_wl-test", 5001, "/var/lib/workloads/test")

    @patch("podman.ensure_runtime_dir")
    def test_skips_when_linger_off(self, mock_ensure):
        """No linger marker → runtime dir is legitimately absent; don't heal."""
        with tempfile.TemporaryDirectory() as d:
            with patch("podman._LINGER_DIR", Path(d)):
                self.p._ensure_runtime_dir()
        mock_ensure.assert_not_called()

    @patch("podman.ensure_runtime_dir")
    def test_heals_when_linger_on(self, mock_ensure):
        """Linger marker present → an enabled workload's dir was GC'd; heal it."""
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "_wl-test").touch()
            with patch("podman._LINGER_DIR", Path(d)):
                self.p._ensure_runtime_dir()
        mock_ensure.assert_called_once_with(5001, timeout=5.0)


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


class _FakePw:
    def __init__(self, uid=5001, gid=5001, name="_wl-test"):
        self.pw_uid, self.pw_gid, self.pw_name = uid, gid, name
        self.pw_dir = "/var/lib/workloads/test"


def _as_root(euid=0):
    """Patch the two lookups `_compute_drop_privs` consults."""
    return (
        patch("podman.os.geteuid", return_value=euid),
        patch("podman.pwd.getpwnam", return_value=_FakePw()),
        patch("podman.os.getgrouplist", return_value=[5001, 39]),
    )


class RootDropsPrivsWithoutSudoTests(unittest.TestCase):
    """A root caller becomes the workload user by setuid, not by sudo (Q6-X).

    sudo emits ~6 audit records per invocation and `workload-exporter` makes
    one call per health-checked workload every 30s, which is what buried real
    failures under ~21,500 records per workload in a host's journal. The
    identity the child ends up with must be unchanged — same uid, same env —
    so these assert the *equivalence*, not just the absence of sudo.
    """

    def setUp(self):
        self.p = Podman.for_user("_wl-test", 5001, "/var/lib/workloads/test")
        self.patches = _as_root()
        for p in self.patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self.patches])

    @patch("subprocess.run")
    def test_no_sudo_in_argv(self, mock_run):
        mock_run.return_value = _ok(stdout=json.dumps([{"Id": "x"}]))
        self.p.image_id("ref")
        cmd = mock_run.call_args.args[0]
        self.assertEqual(cmd[0], "podman")
        self.assertNotIn("sudo", cmd)

    @patch("subprocess.run")
    def test_child_setuids_to_the_workload_user_with_its_groups(self, mock_run):
        mock_run.return_value = _ok(stdout=json.dumps([{"Id": "x"}]))
        self.p.image_id("ref")
        kw = mock_run.call_args.kwargs
        self.assertEqual(kw["user"], 5001)
        # group/extra_groups must be set explicitly: `user=` alone leaves the
        # child holding root's gid and supplementary groups.
        self.assertEqual(kw["group"], 5001)
        self.assertEqual(kw["extra_groups"], [5001, 39])

    @patch("subprocess.run")
    def test_env_matches_what_sudo_would_have_set(self, mock_run):
        mock_run.return_value = _ok(stdout=json.dumps([{"Id": "x"}]))
        self.p.image_id("ref")
        env = mock_run.call_args.kwargs["env"]
        self.assertEqual(env["XDG_RUNTIME_DIR"], "/run/user/5001")
        self.assertEqual(env["HOME"], "/var/lib/workloads/test")
        self.assertEqual(
            env["DBUS_SESSION_BUS_ADDRESS"], "unix:path=/run/user/5001/bus")
        self.assertEqual(env["USER"], "_wl-test")
        self.assertEqual(env["LOGNAME"], "_wl-test")

    @patch("subprocess.run")
    def test_identity_env_is_the_same_on_both_paths(self, mock_run):
        """The sudo `-E VAR=value` args and the setuid env carry one source."""
        mock_run.return_value = _ok(stdout=json.dumps([{"Id": "x"}]))
        self.p.image_id("ref")
        env = mock_run.call_args.kwargs["env"]

        with patch("podman.os.geteuid", return_value=1000):
            sudo = Podman.for_user(
                "_wl-test", 5001, "/var/lib/workloads/test")._build_cmd("info")
        for key in ("XDG_RUNTIME_DIR", "HOME", "DBUS_SESSION_BUS_ADDRESS"):
            self.assertIn(f"{key}={env[key]}", sudo)

    @patch("subprocess.run")
    def test_root_podman_never_setuids(self, mock_run):
        """for_root() has no user to become — no user= kwarg at all."""
        mock_run.return_value = _ok(stdout=json.dumps([{"Id": "x"}]))
        Podman.for_root().image_id("ref")
        self.assertNotIn("user", mock_run.call_args.kwargs)

    @patch("subprocess.run")
    def test_unknown_user_falls_back_to_sudo(self, mock_run):
        """No passwd entry: let sudo produce the error, don't invent a uid."""
        mock_run.return_value = _ok(stdout=json.dumps([{"Id": "x"}]))
        with patch("podman.pwd.getpwnam", side_effect=KeyError("_wl-test")):
            Podman.for_user(
                "_wl-test", 5001, "/var/lib/workloads/test").image_id("ref")
        self.assertEqual(mock_run.call_args.args[0][0], "sudo")
        self.assertNotIn("user", mock_run.call_args.kwargs)

    @patch("subprocess.run")
    def test_setuid_refused_falls_back_to_sudo_and_sticks(self, mock_run):
        """Root without CAP_SETUID (a narrowed CapabilityBoundingSet) still works.

        subprocess reports the child's failed setuid as a PermissionError in
        the parent; one failed spawn per instance, then sudo from then on.
        """
        ok = _ok(stdout=json.dumps([{"Id": "x"}]))
        mock_run.side_effect = [PermissionError(1, "Operation not permitted"),
                                ok, ok]
        p = Podman.for_user("_wl-test", 5001, "/var/lib/workloads/test")
        self.assertEqual(p.image_id("ref"), "x")
        self.assertEqual(mock_run.call_args.args[0][0], "sudo")

        p.image_id("ref")  # second call must not re-attempt the setuid spawn
        self.assertEqual(mock_run.call_count, 3)
        self.assertEqual(mock_run.call_args.args[0][0], "sudo")


class NonRootStillUsesSudoTests(unittest.TestCase):
    """Becoming another user from an unprivileged caller is an escalation —
    only sudo can grant it, so the audit records there are the point."""

    @patch("subprocess.run")
    def test_unprivileged_caller_keeps_sudo(self, mock_run):
        mock_run.return_value = _ok(stdout=json.dumps([{"Id": "x"}]))
        with patch("podman.os.geteuid", return_value=1000):
            Podman.for_user(
                "_wl-test", 5001, "/var/lib/workloads/test").image_id("ref")
        cmd = mock_run.call_args.args[0]
        self.assertEqual(cmd[0], "sudo")
        self.assertIn("_wl-test", cmd)
        self.assertNotIn("user", mock_run.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
