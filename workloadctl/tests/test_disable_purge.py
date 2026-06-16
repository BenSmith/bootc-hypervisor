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

import cmd_lifecycle
import workloadctl_core
from workloadctl_core import WorkloadConfig


SINGLE_TOML = """\
[workload]
name = "{name}"
enabled = false

[container]
image = "example.com/test:latest"
"""

MULTI_TOML = """\
[workload]
name = "{name}"
mode = "pod"
enabled = false

[[containers]]
name = "web"
[containers.container]
image = "example.com/web:latest"

[[containers]]
name = "db"
[containers.container]
image = "example.com/db:latest"
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
        (wl_path / f'{self._name}.toml').write_text(self._toml)
        self._wl_patch = patch.object(workloadctl_core, 'WORKLOAD_DIR', wl_path)
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


if __name__ == '__main__':
    unittest.main()
