#!/usr/bin/env python3
"""Characterization tests for cmd_inspect.cmd_health.

Focus: Check 3, the user-manager slice-placement probe. This is the safety net
for converging that check's inline `systemctl is-active user@<uid>.service` onto
service_runtime — the tests pin the observable health output so the refactor can
be proven behaviour-preserving. See docs/wip/refactor-service-runtime-and-naming.md.
"""

import io
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import MagicMock, PropertyMock, patch

_LIB = os.path.join(os.path.dirname(__file__), '..', 'lib')
sys.path.insert(0, _LIB)

import workload_lib
import cmd_inspect
from workloadctl_core import WorkloadConfig


def _ok(stdout='', returncode=0):
    return CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr='')


def _args(**kw):
    d = dict(json=True, workload='test-wl')
    d.update(kw)
    return types.SimpleNamespace(**d)


MINIMAL_TOML = """\
[workload]
name = "test-wl"

[container]
image = "example.com/test:latest"
"""

SLICE_TOML = """\
[workload]
name = "test-wl"

[container]
image = "example.com/test:latest"

[resources]
slice = "custom.slice"
"""


class _WorkloadDir:
    """Temp WORKLOAD_CONFIG_DIR holding one <name>/workload.toml."""

    def __init__(self, toml=MINIMAL_TOML, name='test-wl'):
        self._toml, self._name = toml, name

    def __enter__(self):
        self._tmp = tempfile.mkdtemp()
        p = Path(self._tmp)
        (p / self._name).mkdir()
        (p / self._name / 'workload.toml').write_text(self._toml)
        self._patcher = patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p)
        self._patcher.start()
        return p

    def __exit__(self, *_):
        self._patcher.stop()
        shutil.rmtree(self._tmp, ignore_errors=True)


class TestHealthUserManagerPlacement(unittest.TestCase):
    """cmd_health Check 3 — user@<uid>.service slice placement.

    Every other check is driven to a healthy outcome (service active, user
    exists, container running, no health-check/ports) so `overall` reflects the
    placement result in isolation.
    """

    UID = 10005

    def _run_health(self, *, manager_active, actual_slice, toml=MINIMAL_TOML):
        def fake_run(cmd, **kw):
            if cmd[:2] == ['systemctl', 'is-active']:
                target = cmd[2]
                if target.startswith('user@'):
                    # Faithful: real `systemctl is-active` returns rc and the
                    # state string together. Keeping both agreeing keeps this
                    # test valid whether the gate reads returncode or stdout.
                    if manager_active:
                        return _ok(stdout='active\n', returncode=0)
                    return _ok(stdout='inactive\n', returncode=3)
                return _ok(stdout='active\n', returncode=0)   # workload service
            if 'show' in cmd and 'Slice' in cmd:               # Check 3 slice
                return _ok(stdout=actual_slice + '\n')
            return _ok()                                       # uptime show, etc.

        manager = MagicMock()
        manager.user_exists.return_value = True
        manager.podman.return_value.container_status.return_value = 'running'

        buf = io.StringIO()
        with _WorkloadDir(toml), \
             patch.object(WorkloadConfig, 'uid', new_callable=PropertyMock,
                          return_value=self.UID), \
             patch('subprocess.run', side_effect=fake_run), \
             patch('sys.stdout', buf):
            try:
                cmd_inspect.cmd_health(_args(), manager)
            except SystemExit:
                pass
        return json.loads(buf.getvalue())

    @staticmethod
    def _placement(data):
        for c in data['checks']:
            if c['check'] == 'user_manager_placement':
                return c
        return None

    def test_placement_ok_when_slice_matches(self):
        data = self._run_health(manager_active=True, actual_slice='workloads.slice')
        chk = self._placement(data)
        self.assertIsNotNone(chk)
        self.assertTrue(chk['healthy'])
        self.assertEqual(chk['details'], {'slice': 'workloads.slice'})
        self.assertEqual(data['overall'], 'HEALTHY')

    def test_placement_mismatch_flags_unhealthy(self):
        data = self._run_health(manager_active=True, actual_slice='user.slice')
        chk = self._placement(data)
        self.assertIsNotNone(chk)
        self.assertFalse(chk['healthy'])
        self.assertEqual(
            chk['details'],
            {'actual_slice': 'user.slice', 'expected_slice': 'workloads.slice'},
        )
        self.assertIn(f'restart user@{self.UID}.service', chk['message'])
        self.assertEqual(data['overall'], 'UNHEALTHY')

    def test_placement_skipped_when_manager_inactive(self):
        data = self._run_health(manager_active=False, actual_slice='workloads.slice')
        self.assertIsNone(self._placement(data))

    def test_expected_slice_read_from_config(self):
        data = self._run_health(manager_active=True, actual_slice='custom.slice',
                                toml=SLICE_TOML)
        chk = self._placement(data)
        self.assertIsNotNone(chk)
        self.assertTrue(chk['healthy'])
        self.assertEqual(chk['details'], {'slice': 'custom.slice'})


if __name__ == '__main__':
    unittest.main()
