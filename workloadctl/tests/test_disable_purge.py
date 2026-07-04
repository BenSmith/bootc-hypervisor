#!/usr/bin/env python3
"""Unit tests for purge-time cleanup of /run/workload-env files.

Covers cmd_lifecycle._remove_runtime_env_files — the helper cmd_disable --purge
calls to delete a workload's decrypted .secrets and .env from /run so they don't
linger root-readable until the next reboot.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

LIB_DIR = os.path.join(os.path.dirname(__file__), '..', 'lib')
sys.path.insert(0, LIB_DIR)

import workload_lib
import cmd_lifecycle
import workloadctl_core
from workloadctl_core import WorkloadConfig


SINGLE_TOML = """\
[workload]
name = "{name}"

[container]
image = "example.com/test:latest"
"""

MULTI_TOML = """\
[workload]
name = "{name}"
mode = "pod"

[[containers]]
name = "web"
[containers.container]
image = "example.com/web:latest"

[[containers]]
name = "db"
[containers.container]
image = "example.com/db:latest"
"""


BRIDGE_TOML = """\
[workload]
name = "{name}"
mode = "bridge"

[[containers]]
name = "web"
[containers.container]
image = "example.com/web:latest"
"""


VM_TOML = """\
[workload]
name = "{name}"

[vm]
cloud_image_url = "https://example.com/img.qcow2"
memory = "2G"
system_disk_size = "10G"
"""


class _Env:
    """Temp WORKLOAD_DIR (with one TOML) + temp WORKLOAD_ENV_DIR.

    Yields (config, env_dir). env_dir is exported via WORKLOAD_ENV_DIR so the
    helper writes/reads there instead of /run/workload-env.
    """

    def __init__(self, toml, name):
        self._toml = toml.format(name=name)
        self._name = name

    def __enter__(self):
        self._wl_tmp = tempfile.mkdtemp()
        self._env_tmp = tempfile.mkdtemp()
        wl_path = Path(self._wl_tmp)
        (wl_path / self._name).mkdir()
        (wl_path / self._name / 'workload.toml').write_text(self._toml)
        self._wl_patch = patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', wl_path)
        self._wl_patch.start()
        self._env_patch = patch.dict(
            os.environ, {'WORKLOAD_ENV_DIR': self._env_tmp}
        )
        self._env_patch.start()
        config = WorkloadConfig(self._name)
        return config, Path(self._env_tmp)

    def __exit__(self, *_):
        self._env_patch.stop()
        self._wl_patch.stop()
        import shutil
        shutil.rmtree(self._wl_tmp, ignore_errors=True)
        shutil.rmtree(self._env_tmp, ignore_errors=True)


def _touch(env_dir, *names):
    for n in names:
        (env_dir / n).write_text("secret\n")


def _names(env_dir):
    return sorted(p.name for p in env_dir.iterdir())


class TestRemoveRuntimeEnvFilesSingle(unittest.TestCase):

    def test_removes_env_and_secrets(self):
        with _Env(SINGLE_TOML, 'test-wl') as (config, env_dir):
            _touch(env_dir,
                   'workload-test-wl.env',
                   'workload-test-wl.secrets')
            removed = cmd_lifecycle._remove_runtime_env_files(config)
            self.assertEqual(
                sorted(removed),
                ['workload-test-wl.env', 'workload-test-wl.secrets'])
            self.assertEqual(_names(env_dir), [])

    def test_missing_files_is_noop(self):
        with _Env(SINGLE_TOML, 'test-wl') as (config, env_dir):
            removed = cmd_lifecycle._remove_runtime_env_files(config)
            self.assertEqual(removed, [])

    def test_does_not_touch_prefix_collisions(self):
        # Purging 'git' must not delete 'github's files (glob would).
        with _Env(SINGLE_TOML, 'git') as (config, env_dir):
            _touch(env_dir,
                   'workload-git.env',
                   'workload-git.secrets',
                   'workload-github.env',          # different workload
                   'workload-github.secrets',
                   'workload-git-extra.secrets')   # not a container of 'git'
            removed = cmd_lifecycle._remove_runtime_env_files(config)
            self.assertEqual(
                sorted(removed),
                ['workload-git.env', 'workload-git.secrets'])
            self.assertEqual(
                _names(env_dir),
                ['workload-git-extra.secrets',
                 'workload-github.env',
                 'workload-github.secrets'],
            )


class TestRemoveRuntimeEnvFilesMulti(unittest.TestCase):

    def test_removes_per_container_secrets(self):
        with _Env(MULTI_TOML, 'stack') as (config, env_dir):
            self.assertTrue(config.is_multi)
            _touch(env_dir,
                   'workload-stack.env',
                   'workload-stack-web.secrets',
                   'workload-stack-db.secrets')
            removed = cmd_lifecycle._remove_runtime_env_files(config)
            self.assertEqual(
                sorted(removed),
                ['workload-stack-db.secrets',
                 'workload-stack-web.secrets',
                 'workload-stack.env'],
            )
            self.assertEqual(_names(env_dir), [])

    def test_leaves_unrelated_container_secrets(self):
        with _Env(MULTI_TOML, 'stack') as (config, env_dir):
            _touch(env_dir,
                   'workload-stack-web.secrets',
                   'workload-stack-cache.secrets')  # 'cache' not a container
            removed = cmd_lifecycle._remove_runtime_env_files(config)
            self.assertEqual(removed, ['workload-stack-web.secrets'])
            self.assertEqual(_names(env_dir), ['workload-stack-cache.secrets'])


class TestStopUserManager(unittest.TestCase):
    """cmd_disable's non-purge path tears down the lingering user manager."""

    def test_existing_user_terminates_and_disables_linger(self):
        with patch.object(cmd_lifecycle.pwd, 'getpwnam',
                          return_value=SimpleNamespace(pw_uid=10005)), \
             patch.object(cmd_lifecycle.subprocess, 'run',
                          MagicMock()) as run:
            acted = cmd_lifecycle._stop_user_manager('_wl-foo')
        self.assertTrue(acted)
        cmds = [c.args[0] for c in run.call_args_list]
        self.assertIn(['loginctl', 'terminate-user', '10005'], cmds)
        self.assertIn(['loginctl', 'disable-linger', '10005'], cmds)

    def test_missing_user_is_noop(self):
        with patch.object(cmd_lifecycle.pwd, 'getpwnam',
                          side_effect=KeyError), \
             patch.object(cmd_lifecycle.subprocess, 'run',
                          MagicMock()) as run:
            acted = cmd_lifecycle._stop_user_manager('_wl-gone')
        self.assertFalse(acted)
        run.assert_not_called()


class TestPurgeBestEffort(unittest.TestCase):
    """cmd_disable --purge attempts every removal independently (one failure
    never skips the rest) and treats a never-provisioned user as already-clean."""

    def _run_purge(self, getpwnam_side, *, userdel_leaves_user=False):
        """Drive cmd_disable(--purge) with the host-touching bits stubbed.

        Uses a VM workload so the purge path skips the subuid/subgid host-file
        mutation (which touches /run/lock + /etc and isn't relevant here),
        keeping the test focused on best-effort independence + idempotency.

        Returns (exit_code or None, set of rmtree'd paths, the WORKLOADS_BASE
        temp dir holding a pre-created data dir for the workload).
        """
        with _Env(VM_TOML, 'pp') as (config, _env_dir):
            base = Path(tempfile.mkdtemp())
            data_dir = base / 'pp'
            data_dir.mkdir()
            removed = []

            def fake_rmtree(path, *a, **k):
                removed.append(str(path))

            # userdel "success" means the user is gone afterwards; getpwnam is
            # called once up front and once post-userdel to confirm removal.
            calls = {'n': 0}
            def getpwnam(_name):
                calls['n'] += 1
                if calls['n'] == 1:
                    return getpwnam_side()  # up-front lookup
                # post-userdel confirmation
                if userdel_leaves_user:
                    return SimpleNamespace(pw_uid=10005)
                raise KeyError(_name)

            args = SimpleNamespace(workload='pp', purge=True)
            exit_code = None
            with patch.object(cmd_lifecycle, 'require_root', lambda: None), \
                 patch.object(cmd_lifecycle, 'WORKLOADS_BASE', base), \
                 patch.object(workload_lib, 'WORKLOADS_BASE', base), \
                 patch.object(cmd_lifecycle.subprocess, 'run', MagicMock()), \
                 patch.object(cmd_lifecycle.time, 'sleep', lambda *_: None), \
                 patch.object(cmd_lifecycle, '_stop_user_manager', MagicMock()), \
                 patch.object(cmd_lifecycle, '_run_host_setup', MagicMock()), \
                 patch.object(cmd_lifecycle, '_apply_selinux_policy', MagicMock()), \
                 patch.object(cmd_lifecycle, 'workload_run_files', MagicMock(return_value=[])), \
                 patch.object(cmd_lifecycle, '_remove_runtime_env_files', MagicMock()), \
                 patch.object(cmd_lifecycle, '_stop_bridge_if_last_vm', MagicMock()), \
                 patch.object(cmd_lifecycle, 'workload_enabled_marker',
                              MagicMock(return_value=MagicMock())), \
                 patch.object(cmd_lifecycle.shutil, 'rmtree', fake_rmtree), \
                 patch.object(cmd_lifecycle.pwd, 'getpwnam', side_effect=getpwnam):
                try:
                    cmd_lifecycle.cmd_disable(args, MagicMock())
                except SystemExit as e:
                    exit_code = e.code
            return exit_code, removed, data_dir

    def test_never_provisioned_user_is_idempotent_and_still_removes_data(self):
        # User absent up front: must NOT error, and must still sweep the data dir.
        def absent():
            raise KeyError('_wl-pp')
        exit_code, removed, data_dir = self._run_purge(absent)
        self.assertIsNone(exit_code)  # clean exit, no sys.exit(1)
        self.assertIn(str(data_dir), removed)

    def test_userdel_failure_still_removes_data_then_exits_nonzero(self):
        # User exists but userdel leaves it behind: the data dir is STILL
        # removed (independent best-effort), but the command exits non-zero.
        exit_code, removed, data_dir = self._run_purge(
            lambda: SimpleNamespace(pw_uid=10005),
            userdel_leaves_user=True,
        )
        self.assertEqual(exit_code, 1)
        self.assertIn(str(data_dir), removed)  # not skipped despite userdel fail

    def test_early_step_failure_does_not_skip_later_teardown(self):
        # An exception in an early teardown step (host setup) must not abort the
        # rest of disable: the later /run unit-file removal still runs, and the
        # command still exits non-zero to surface the failure.
        with _Env(VM_TOML, 'pp') as (config, _env_dir):
            stranded = Path(tempfile.mkdtemp()) / "workload-pp.service"
            stranded.write_text("# unit\n")
            args = SimpleNamespace(workload='pp', purge=False)
            exit_code = None
            with patch.object(cmd_lifecycle, 'require_root', lambda: None), \
                 patch.object(cmd_lifecycle.subprocess, 'run', MagicMock()), \
                 patch.object(cmd_lifecycle, '_run_host_setup',
                              MagicMock(side_effect=RuntimeError("boom"))), \
                 patch.object(cmd_lifecycle, '_apply_selinux_policy', MagicMock()), \
                 patch.object(cmd_lifecycle, 'workload_run_files',
                              MagicMock(return_value=[
                                  SimpleNamespace(kind='unit', path=stranded)])), \
                 patch.object(cmd_lifecycle, '_stop_user_manager', MagicMock(return_value=False)), \
                 patch.object(cmd_lifecycle, '_stop_bridge_if_last_vm', MagicMock()), \
                 patch.object(cmd_lifecycle, 'workload_enabled_marker',
                              MagicMock(return_value=MagicMock())):
                try:
                    cmd_lifecycle.cmd_disable(args, MagicMock())
                except SystemExit as e:
                    exit_code = e.code
        # later step ran despite the earlier failure
        self.assertFalse(stranded.exists())
        self.assertEqual(exit_code, 1)   # failure surfaced


class TestDisableRemovesRunFiles(unittest.TestCase):
    """cmd_disable removes the workload's generated /run/systemd/system unit
    files itself (the generator only ever writes)."""

    def test_run_files_removed_on_disable(self):
        run = Path(tempfile.mkdtemp())
        with _Env(SINGLE_TOML, 'pp') as (config, _env_dir):
            # Stage the files the generator would have written for 'pp', plus a
            # sibling 'pp-extra' file that must NOT be touched, plus the drop-in.
            (run / "multi-user.target.wants").mkdir()
            mine = [
                run / "workload-pp.service",
                run / "workload-pp-setup.service",
                run / "workload-pp.conf",
                run / "multi-user.target.wants" / "workload-pp.service",
            ]
            for p in mine:
                p.write_text("x\n")
            dropin = run / "user@10005.service.d" / "50-workload.conf"
            dropin.parent.mkdir()
            dropin.write_text("x\n")
            sibling = run / "workload-pp-extra.service"   # belongs to 'pp-extra'
            sibling.write_text("x\n")

            args = SimpleNamespace(workload='pp', purge=False)
            with patch.object(cmd_lifecycle, 'require_root', lambda: None), \
                 patch.object(cmd_lifecycle, 'RUN_SYSTEMD_SYSTEM', run), \
                 patch.object(workload_lib, 'RUN_SYSTEMD_SYSTEM', run), \
                 patch.object(cmd_lifecycle.subprocess, 'run', MagicMock()), \
                 patch.object(cmd_lifecycle, '_run_host_setup', MagicMock()), \
                 patch.object(cmd_lifecycle, '_apply_selinux_policy', MagicMock()), \
                 patch.object(cmd_lifecycle, '_stop_user_manager', MagicMock(return_value=False)), \
                 patch.object(cmd_lifecycle, '_stop_bridge_if_last_vm', MagicMock()), \
                 patch.object(cmd_lifecycle, 'workload_enabled_marker',
                              MagicMock(return_value=MagicMock())), \
                 patch.object(type(config), 'uid', property(lambda self: 10005)):
                cmd_lifecycle.cmd_disable(args, MagicMock())

        for p in mine:
            self.assertFalse(p.exists(), f"{p} should have been removed")
        self.assertFalse(dropin.exists())
        self.assertFalse(dropin.parent.exists(), "empty drop-in dir should be pruned")
        # Exact-name removal must not touch the prefix-sibling's file.
        self.assertTrue(sibling.exists(), "sibling 'pp-extra' must be untouched")

    def test_run_file_removal_tolerates_absent_user(self):
        # Regression: a second disable (or any disable after the user is already
        # gone) must not abort. The container drop-in path is keyed by the
        # workload UID, whose passwd lookup raises WorkloadUserNotFound once the
        # user is removed — this must be tolerated (drop-in skipped), and the
        # UID-independent /run units must still be removed. /run removal runs for
        # both purge and plain disable, so purge=False exercises it without the
        # purge block's host-file mutation. Uses the REAL workload_run_files (not
        # a stub), since the stub hid this bug.
        run = Path(tempfile.mkdtemp())
        with _Env(SINGLE_TOML, 'pp') as (config, _env_dir):
            (run / "multi-user.target.wants").mkdir()
            mine = [
                run / "workload-pp.service",
                run / "workload-pp-setup.service",
                run / "workload-pp.conf",
                run / "multi-user.target.wants" / "workload-pp.service",
            ]
            for p in mine:
                p.write_text("x\n")

            def raise_absent(self):
                raise workloadctl_core.WorkloadUserNotFound('pp')

            args = SimpleNamespace(workload='pp', purge=False)
            exit_code = None
            with patch.object(cmd_lifecycle, 'require_root', lambda: None), \
                 patch.object(cmd_lifecycle, 'RUN_SYSTEMD_SYSTEM', run), \
                 patch.object(workload_lib, 'RUN_SYSTEMD_SYSTEM', run), \
                 patch.object(cmd_lifecycle.subprocess, 'run', MagicMock()), \
                 patch.object(cmd_lifecycle, '_run_host_setup', MagicMock()), \
                 patch.object(cmd_lifecycle, '_apply_selinux_policy', MagicMock()), \
                 patch.object(cmd_lifecycle, '_stop_user_manager', MagicMock(return_value=False)), \
                 patch.object(cmd_lifecycle, '_stop_bridge_if_last_vm', MagicMock()), \
                 patch.object(cmd_lifecycle, 'workload_enabled_marker',
                              MagicMock(return_value=MagicMock())), \
                 patch.object(type(config), 'uid', property(raise_absent)):
                try:
                    cmd_lifecycle.cmd_disable(args, MagicMock())
                except SystemExit as e:
                    exit_code = e.code

        self.assertIsNone(exit_code, "absent user must not abort disable")
        for p in mine:
            self.assertFalse(p.exists(), f"{p} should still be removed with user gone")


class TestDisableStopsWholeTopology(unittest.TestCase):
    """cmd_disable must stop BOTH the -pod and -net helpers regardless of the
    workload's CURRENT mode.

    Regression guard: the stop-list is sourced from the run-file superset, not
    the emitted subset. If a workload was enabled as mode="pod" and the TOML is
    later edited to mode="bridge" before `disable` runs, the config now reflects
    bridge — but the still-active pod helper (whose fragment _remove_run_files
    unlinks anyway) must still be stopped, or it lingers loaded until reboot.
    """

    def _stopped_units(self, toml, name):
        run = Path(tempfile.mkdtemp())
        with _Env(toml, name) as (config, _env_dir):
            args = SimpleNamespace(workload=name, purge=False)
            fake_run = MagicMock()
            with patch.object(cmd_lifecycle, 'require_root', lambda: None), \
                 patch.object(cmd_lifecycle, 'RUN_SYSTEMD_SYSTEM', run), \
                 patch.object(workload_lib, 'RUN_SYSTEMD_SYSTEM', run), \
                 patch.object(cmd_lifecycle.subprocess, 'run', fake_run), \
                 patch.object(cmd_lifecycle, '_run_host_setup', MagicMock()), \
                 patch.object(cmd_lifecycle, '_apply_selinux_policy', MagicMock()), \
                 patch.object(cmd_lifecycle, '_stop_user_manager', MagicMock(return_value=False)), \
                 patch.object(cmd_lifecycle, '_stop_bridge_if_last_vm', MagicMock()), \
                 patch.object(cmd_lifecycle, 'workload_enabled_marker',
                              MagicMock(return_value=MagicMock())):
                cmd_lifecycle.cmd_disable(args, MagicMock())
        stopped = set()
        for c in fake_run.call_args_list:
            argv = c.args[0]
            if len(argv) >= 3 and argv[0] == 'systemctl' and argv[1] == 'stop':
                stopped.add(argv[2])
        return stopped

    def test_bridge_mode_still_stops_pod_helper(self):
        stopped = self._stopped_units(BRIDGE_TOML, 'wp')
        # The other mode's helper (not emitted for bridge) must still be stopped.
        self.assertIn('workload-wp-pod.service', stopped)
        self.assertIn('workload-wp-net.service', stopped)

    def test_pod_mode_still_stops_net_helper(self):
        stopped = self._stopped_units(MULTI_TOML, 'stack')  # mode = "pod"
        # The other mode's helper (not emitted for pod) must still be stopped.
        self.assertIn('workload-stack-net.service', stopped)
        self.assertIn('workload-stack-pod.service', stopped)


if __name__ == '__main__':
    unittest.main()
