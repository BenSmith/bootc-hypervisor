#!/usr/bin/env python3
"""Characterization tests for cmd_inspect.cmd_health.

Focus: Check 3, the user-manager slice-placement probe. This is the safety net
for converging that check's inline `systemctl is-active user@<uid>.service` onto
service_runtime — the tests pin the observable health output so the refactor can
be proven behaviour-preserving.
"""

import io
import json
import shutil
import tempfile
import types
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import MagicMock, PropertyMock, patch


import workload_lib
import cmd_health
import cmd_images
import cmd_info
import cmd_inspect
import cmd_stats
from substrate_vm import VMSubstrate
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

VM_TOML = """\
[workload]
name = "test-vm"

[vm]
image = "example.com/guest:latest"
memory = "2048M"
vcpus = 2
"""

POD_TOML = """\
[workload]
name = "test-pod"
mode = "pod"

[[containers]]
name = "api"
[containers.container]
image = "example.com/api:latest"

[[containers]]
name = "db"
[containers.container]
image = "example.com/db:latest"
"""

PORTS_HEALTH_TOML = """\
[workload]
name = "test-wl"

[container]
image = "example.com/test:latest"

[container.health]
cmd = ["curl", "-f", "http://localhost/"]

[network]
mode = "pasta"
ports = ["8080:80"]
"""


class _MultiWorkloadDir:
    """Temp WORKLOAD_CONFIG_DIR holding several <name>/workload.toml entries."""

    def __init__(self, entries):
        self._entries = entries  # {name: toml}

    def __enter__(self):
        self._tmp = tempfile.mkdtemp()
        p = Path(self._tmp)
        for name, toml in self._entries.items():
            (p / name).mkdir()
            (p / name / 'workload.toml').write_text(toml)
        self._patcher = patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p)
        self._patcher.start()
        return p

    def __exit__(self, *_):
        self._patcher.stop()
        shutil.rmtree(self._tmp, ignore_errors=True)


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
                cmd_health.cmd_health(_args(), manager)
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


class TestCmdList(unittest.TestCase):
    """cmd_list — human table and --json output across single/multi/vm."""

    def _manager(self, *, user_exists=False, image_id=None):
        from workloadctl_core import WorkloadManager
        manager = WorkloadManager()
        manager.user_exists = MagicMock(return_value=user_exists)
        manager.get_image_id = MagicMock(return_value=image_id)
        return manager

    def test_list_json_empty(self):
        with _MultiWorkloadDir({}):
            manager = self._manager()
            buf = io.StringIO()
            with patch('sys.stdout', buf):
                cmd_inspect.cmd_list(_args(json=True, workload=None), manager)
            data = json.loads(buf.getvalue())
            self.assertEqual(data['workloads'], [])

    def test_list_human_no_configs(self):
        with _MultiWorkloadDir({}):
            manager = self._manager()
            buf = io.StringIO()
            with patch('sys.stdout', buf):
                cmd_inspect.cmd_list(_args(json=False, workload=None), manager)
            self.assertIn('No workload configs found', buf.getvalue())

    def test_list_json_single_and_vm_and_pod(self):
        with _MultiWorkloadDir({'test-wl': MINIMAL_TOML, 'test-vm': VM_TOML,
                                 'test-pod': POD_TOML}):
            manager = self._manager(user_exists=True, image_id='deadbeef' * 8)
            buf = io.StringIO()
            with patch.object(cmd_inspect, '_effective_state',
                               return_value=('running', None)):
                with patch('sys.stdout', buf):
                    cmd_inspect.cmd_list(_args(json=True, workload=None), manager)
            data = json.loads(buf.getvalue())
            by_name = {w['name']: w for w in data['workloads']}
            self.assertEqual(by_name['test-vm']['image'], 'example.com/guest:latest')
            self.assertEqual(by_name['test-vm']['containers'], 0)
            self.assertEqual(by_name['test-pod']['mode'], 'pod')
            self.assertEqual(by_name['test-pod']['containers'], 2)
            self.assertEqual(by_name['test-wl']['image'], 'example.com/test:latest')

    def test_list_human_shows_failed_warning_and_image_id(self):
        with _MultiWorkloadDir({'test-wl': MINIMAL_TOML}):
            manager = self._manager(user_exists=True, image_id='a' * 24)

            def fake_state(config):
                return 'failed', 'workload-setup.service'

            buf = io.StringIO()
            with patch.object(cmd_inspect, '_effective_state', side_effect=fake_state):
                with patch.object(WorkloadConfig, 'enabled', new_callable=PropertyMock,
                                   return_value=True):
                    with patch('sys.stdout', buf):
                        cmd_inspect.cmd_list(_args(json=False, workload=None), manager)
            out = buf.getvalue()
            self.assertIn('WARNING', out)
            self.assertIn('workload-setup.service failed', out)
            self.assertIn('a' * 12, out)

    def test_list_json_uid_lookup_failure_yields_none(self):
        from workloadctl_core import WorkloadUserNotFound
        with _MultiWorkloadDir({'test-wl': MINIMAL_TOML}):
            manager = self._manager(user_exists=False)
            buf = io.StringIO()
            with patch.object(WorkloadConfig, 'uid', new_callable=PropertyMock,
                               side_effect=WorkloadUserNotFound('nope')):
                with patch('sys.stdout', buf):
                    cmd_inspect.cmd_list(_args(json=True, workload=None), manager)
            data = json.loads(buf.getvalue())
            self.assertIsNone(data['workloads'][0]['uid'])

    def test_list_human_image_id_lookup_exception_is_swallowed(self):
        with _MultiWorkloadDir({'test-wl': MINIMAL_TOML}):
            manager = self._manager(user_exists=True)
            manager.get_image_id = MagicMock(side_effect=RuntimeError('boom'))
            buf = io.StringIO()
            with patch('sys.stdout', buf):
                cmd_inspect.cmd_list(_args(json=False, workload=None), manager)
            # Should not raise; image_id column falls back to '-'
            self.assertIn('test-wl', buf.getvalue())


class TestCmdStatus(unittest.TestCase):
    def test_status_no_workload_delegates_to_list(self):
        with _MultiWorkloadDir({}):
            from workloadctl_core import WorkloadManager
            manager = WorkloadManager()
            buf = io.StringIO()
            with patch('sys.stdout', buf):
                cmd_inspect.cmd_status(_args(json=False, workload=None), manager)
            self.assertIn('No workload configs found', buf.getvalue())

    def test_status_json_single(self):
        def fake_run(cmd, **kw):
            if cmd[:2] == ['systemctl', 'show']:
                return _ok(stdout='ActiveState=active\nMainPID=123\n'
                                   'MemoryCurrent=1024\nTasksCurrent=3\n'
                                   'Result=success\nActiveEnterTimestamp=@1700000000\n'
                                   'UnitFileState=enabled\n')
            if cmd[:2] == ['systemctl', 'is-enabled']:
                return _ok(returncode=0)
            return _ok()

        with _WorkloadDir(MINIMAL_TOML):
            manager = MagicMock()
            buf = io.StringIO()
            with patch('subprocess.run', side_effect=fake_run), patch('sys.stdout', buf):
                cmd_inspect.cmd_status(_args(json=True), manager)
            data = json.loads(buf.getvalue())
            self.assertEqual(data['state'], 'active')
            self.assertTrue(data['enabled'])
            self.assertEqual(data['main_pid'], 123)
            self.assertEqual(data['memory_current'], 1024)
            self.assertEqual(data['active_since'], 1700000000)

    def test_status_json_multi_includes_sub_containers(self):
        def fake_run(cmd, **kw):
            if cmd[:2] == ['systemctl', 'show']:
                return _ok(stdout='ActiveState=active\n')
            if cmd[:2] == ['systemctl', 'is-enabled']:
                return _ok(returncode=0)
            return _ok()

        with _WorkloadDir(POD_TOML, name='test-pod'):
            manager = MagicMock()
            buf = io.StringIO()
            with patch('subprocess.run', side_effect=fake_run), patch('sys.stdout', buf):
                cmd_inspect.cmd_status(_args(json=True, workload='test-pod'), manager)
            data = json.loads(buf.getvalue())
            self.assertEqual(data['mode'], 'pod')
            self.assertEqual(len(data['containers']), 2)
            self.assertEqual({c['name'] for c in data['containers']}, {'api', 'db'})

    def test_status_human_multi_calls_systemctl_with_pod_helper_unit(self):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return _ok()

        with _WorkloadDir(POD_TOML, name='test-pod'):
            manager = MagicMock()
            with patch('subprocess.run', side_effect=fake_run):
                cmd_inspect.cmd_status(_args(json=False, workload='test-pod'), manager)
            status_call = [c for c in calls if c[:2] == ['systemctl', 'status']][0]
            self.assertIn('workload-test-pod-pod.service', status_call)
            self.assertIn('workload-test-pod-api.service', status_call)

    def test_status_human_single_includes_gating_units(self):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return _ok()

        sub = MagicMock()
        sub.gating_units.return_value = ['workload-test-wl-setup.service']
        with _WorkloadDir(MINIMAL_TOML):
            manager = MagicMock()
            with patch.object(cmd_inspect, 'get_substrate', return_value=sub):
                with patch('subprocess.run', side_effect=fake_run):
                    cmd_inspect.cmd_status(_args(json=False, workload='test-wl'), manager)
            status_call = [c for c in calls if c[:2] == ['systemctl', 'status']][0]
            self.assertIn('workload-test-wl-setup.service', status_call)
            self.assertIn('workload-test-wl.service', status_call)

    def test_status_human_stale_config_prints_warning(self):
        with _WorkloadDir(MINIMAL_TOML):
            manager = MagicMock()
            sub = MagicMock()
            sub.gating_units.return_value = []
            buf = io.StringIO()
            with patch.object(cmd_inspect, 'get_substrate', return_value=sub):
                with patch.object(cmd_inspect, 'units_outdated', return_value=True):
                    with patch('subprocess.run', return_value=_ok()):
                        with patch('sys.stdout', buf):
                            cmd_inspect.cmd_status(_args(json=False, workload='test-wl'), manager)
            self.assertIn('units are stale', buf.getvalue())


class TestCmdImages(unittest.TestCase):
    def test_images_json_lists_vm_skipped_and_multi_per_container(self):
        with _MultiWorkloadDir({'test-wl': MINIMAL_TOML, 'test-vm': VM_TOML,
                                 'test-pod': POD_TOML}):
            from workloadctl_core import WorkloadManager
            manager = WorkloadManager()
            manager.user_exists = MagicMock(return_value=True)
            podman = MagicMock()
            podman.image_info.return_value = {'Size': 12345, 'Created': '2024-01-01T00:00:00Z'}
            manager.podman = MagicMock(return_value=podman)
            buf = io.StringIO()
            with patch('sys.stdout', buf):
                cmd_images.cmd_images(_args(json=True, workload=None,
                                              subcommand='list'), manager)
            data = json.loads(buf.getvalue())
            workloads = {i['workload'] for i in data['images']}
            self.assertNotIn('test-vm', workloads)
            self.assertIn('test-pod', workloads)
            self.assertEqual(data['total'], 3)  # test-wl + api + db

    def test_images_human_no_images_found(self):
        with _MultiWorkloadDir({}):
            from workloadctl_core import WorkloadManager
            manager = WorkloadManager()
            buf = io.StringIO()
            with patch('sys.stdout', buf):
                cmd_images.cmd_images(_args(json=False, workload=None,
                                              subcommand='list'), manager)
            self.assertIn('No workload images found', buf.getvalue())

    def test_images_human_missing_image_info_skipped(self):
        with _MultiWorkloadDir({'test-wl': MINIMAL_TOML}):
            from workloadctl_core import WorkloadManager
            manager = WorkloadManager()
            manager.user_exists = MagicMock(return_value=True)
            podman = MagicMock()
            podman.image_info.return_value = None
            manager.podman = MagicMock(return_value=podman)
            buf = io.StringIO()
            with patch('sys.stdout', buf):
                cmd_images.cmd_images(_args(json=False, workload=None,
                                              subcommand='list'), manager)
            self.assertIn('No workload images found', buf.getvalue())

    def test_images_prune_runs_for_matching_users(self):
        entry = types.SimpleNamespace(pw_name='_wl-test', pw_uid=10005, pw_dir='/var/lib/workloads/test')
        other = types.SimpleNamespace(pw_name='root', pw_uid=0, pw_dir='/root')
        podman_instance = MagicMock()
        podman_instance.run.return_value = _ok(stdout='deadbeef\n')
        buf = io.StringIO()
        with patch.object(cmd_images, 'require_root'):
            with patch('pwd.getpwall', return_value=[entry, other]):
                with patch.object(cmd_images.Podman, 'for_user',
                                   return_value=podman_instance):
                    with patch('sys.stdout', buf):
                        cmd_images.cmd_images(
                            _args(json=False, workload=None, subcommand='prune'),
                            MagicMock())
        self.assertIn('Pruning images for _wl-test', buf.getvalue())
        self.assertIn('Image pruning complete', buf.getvalue())

    def test_images_prune_no_images_message(self):
        buf = io.StringIO()
        with patch.object(cmd_images, 'require_root'):
            with patch('pwd.getpwall', return_value=[]):
                with patch('sys.stdout', buf):
                    cmd_images.cmd_images(
                        _args(json=False, workload=None, subcommand='prune'),
                        MagicMock())
        self.assertIn('No images to prune', buf.getvalue())


class TestCmdInfo(unittest.TestCase):
    def _base_run(self):
        def fake_run(cmd, **kw):
            if cmd[:2] == ['systemctl', 'show']:
                return _ok(stdout='ActiveState=active\nActiveEnterTimestamp=@1700000000\n')
            return _ok()
        return fake_run

    def test_info_vm_json_minimal(self):
        with _WorkloadDir(VM_TOML, name='test-vm'):
            manager = MagicMock()
            manager.user_exists.return_value = False
            buf = io.StringIO()
            with patch('subprocess.run', side_effect=self._base_run()), \
                 patch.object(cmd_info, '_vm_qmp_status', return_value=None), \
                 patch('substrate_vm._vm_guest_addresses', return_value=[]), \
                 patch('sys.stdout', buf):
                cmd_info.cmd_info(_args(json=True, workload='test-vm'), manager)
            data = json.loads(buf.getvalue())
            self.assertEqual(data['vm']['memory'], '2048M')
            self.assertEqual(data['vm']['vcpus'], 2)
            self.assertIsNone(data['vm']['system_disk'])
            # No lease yet is an empty list, not null and not a missing key:
            # the substrate port answers "supported, nothing right now" in band.
            self.assertEqual(data['vm']['guest_ips'], [])
            self.assertFalse(data['user']['exists'])

    def test_info_vm_json_reports_every_address(self):
        """A guest can have more than one address (IPv4 + IPv6, second NIC), so
        --json carries the whole list the port returns rather than the first."""
        with _WorkloadDir(VM_TOML, name='test-vm'):
            manager = MagicMock()
            manager.user_exists.return_value = False
            buf = io.StringIO()
            with patch('subprocess.run', side_effect=self._base_run()), \
                 patch.object(cmd_info, '_vm_qmp_status', return_value=None), \
                 patch.object(VMSubstrate, 'addresses',
                              return_value=['192.168.1.5', 'fd00::5']), \
                 patch('sys.stdout', buf):
                cmd_info.cmd_info(_args(json=True, workload='test-vm'), manager)
            data = json.loads(buf.getvalue())
            self.assertEqual(data['vm']['guest_ips'], ['192.168.1.5', 'fd00::5'])

    def test_info_vm_human_pluralises_multiple_addresses(self):
        with _WorkloadDir(VM_TOML, name='test-vm'):
            manager = MagicMock()
            manager.user_exists.return_value = False
            buf = io.StringIO()
            with patch('subprocess.run', side_effect=self._base_run()), \
                 patch.object(cmd_info, '_vm_qmp_status', return_value=None), \
                 patch.object(VMSubstrate, 'addresses',
                              return_value=['192.168.1.5', 'fd00::5']), \
                 patch('sys.stdout', buf):
                cmd_info.cmd_info(_args(json=False, workload='test-vm'), manager)
            self.assertIn('Guest IPs:  192.168.1.5, fd00::5', buf.getvalue())

    def test_info_vm_human_with_disks_and_ip(self):
        with _WorkloadDir(VM_TOML, name='test-vm') as p:
            home = p / 'test-vm'
            (home / 'system.qcow2').write_text('x')
            (home / 'system.qcow2.gen-1').write_text('x')
            manager = MagicMock()
            manager.user_exists.return_value = True
            buf = io.StringIO()
            with patch('subprocess.run', side_effect=self._base_run()), \
                 patch.object(cmd_info, '_vm_qmp_status', return_value='running'), \
                 patch('substrate_vm._vm_guest_addresses', return_value=['192.168.1.5']), \
                 patch.object(WorkloadConfig, 'uid', new_callable=PropertyMock,
                              return_value=10010), \
                 patch.object(WorkloadConfig, 'home_dir', new_callable=PropertyMock,
                              return_value=home), \
                 patch('sys.stdout', buf):
                cmd_info.cmd_info(_args(json=False, workload='test-vm'), manager)
            out = buf.getvalue()
            self.assertIn('[VM]', out)
            self.assertIn('System disk:', out)
            self.assertIn('Rollback generations: gen-1', out)
            self.assertIn('Guest IP:   192.168.1.5', out)
            self.assertIn('QMP status: running', out)
            self.assertIn('active (running) since', out)

    def test_info_multi_json_and_human(self):
        with _WorkloadDir(POD_TOML, name='test-pod'):
            manager = MagicMock()
            manager.user_exists.return_value = True
            manager.podman.return_value.image_id.side_effect = lambda img: {
                'example.com/api:latest': 'apiimageidapiimageid',
                'example.com/db:latest': 'dbimageiddbimageid',
            }.get(img)
            buf = io.StringIO()
            with patch('subprocess.run', side_effect=self._base_run()), patch('sys.stdout', buf):
                cmd_info.cmd_info(_args(json=True, workload='test-pod'), manager)
            data = json.loads(buf.getvalue())
            names = {c['name']: c for c in data['containers']}
            self.assertEqual(names['api']['image_id'], 'apiimageidapiimageid')
            self.assertIsNone(data['container'])

            buf2 = io.StringIO()
            with patch('subprocess.run', side_effect=self._base_run()), patch('sys.stdout', buf2):
                cmd_info.cmd_info(_args(json=False, workload='test-pod'), manager)
            out = buf2.getvalue()
            self.assertIn('Containers (pod mode):', out)
            self.assertIn('api: example.com/api:latest', out)

    def test_info_single_human_no_user(self):
        with _WorkloadDir(MINIMAL_TOML):
            manager = MagicMock()
            manager.user_exists.return_value = False
            buf = io.StringIO()
            with patch('subprocess.run', side_effect=self._base_run()), patch('sys.stdout', buf):
                cmd_info.cmd_info(_args(json=False, workload='test-wl'), manager)
            out = buf.getvalue()
            self.assertIn('(User not created - workload not enabled)', out)
            self.assertIn('Quick commands:', out)

    def test_info_files_json_and_human(self):
        with _WorkloadDir(MINIMAL_TOML):
            manager = MagicMock()
            buf = io.StringIO()
            with patch('sys.stdout', buf):
                cmd_info.cmd_info(
                    types.SimpleNamespace(json=True, workload='test-wl', files=True),
                    manager)
            data = json.loads(buf.getvalue())
            self.assertEqual(data['workload'], 'test-wl')
            self.assertIn('control_files', data)

            buf2 = io.StringIO()
            with patch('sys.stdout', buf2):
                cmd_info.cmd_info(
                    types.SimpleNamespace(json=False, workload='test-wl', files=True),
                    manager)
            self.assertIn('Control files for test-wl', buf2.getvalue())


class TestCollectControlFiles(unittest.TestCase):
    def test_collect_control_files_merges_override_and_bundle_and_invalid_setup(self):
        with _WorkloadDir(MINIMAL_TOML):
            config = WorkloadConfig('test-wl')
            config.config = {**config.config, 'host': {'setup': '../../etc/passwd'}}
            files = cmd_info._collect_control_files(config)
            invalid = [f for f in files if f['source'] == 'invalid']
            self.assertTrue(invalid, 'traversal setup path should surface as invalid')

    def test_print_control_files_no_files_message(self):
        with _WorkloadDir(MINIMAL_TOML):
            config = WorkloadConfig('test-wl')
            buf = io.StringIO()
            with patch.object(cmd_info, '_collect_control_files', return_value=[]):
                with patch('sys.stdout', buf):
                    cmd_info._print_control_files(config, json_mode=False)
            self.assertIn('No control files', buf.getvalue())


class TestVmQmpStatus(unittest.TestCase):
    def test_no_socket_returns_none(self):
        with patch('pathlib.Path.exists', return_value=False):
            self.assertIsNone(cmd_info._vm_qmp_status('nope'))

    def test_socket_present_but_connect_fails_returns_none(self):
        with patch('pathlib.Path.exists', return_value=True):
            with patch.object(cmd_info.QMPClient, 'connect',
                               side_effect=OSError('nope')):
                self.assertIsNone(cmd_info._vm_qmp_status('nope'))

    def test_socket_present_status_returned(self):
        fake_qmp = MagicMock()
        fake_qmp.execute.return_value = {'return': {'status': 'running'}}
        with patch('pathlib.Path.exists', return_value=True):
            with patch.object(cmd_info, 'QMPClient', return_value=fake_qmp):
                result = cmd_info._vm_qmp_status('name')
        self.assertEqual(result, 'running')
        fake_qmp.close.assert_called_once()


class TestReadSubid(unittest.TestCase):
    def test_missing_file_returns_none_none(self):
        with patch('builtins.open', side_effect=FileNotFoundError):
            self.assertEqual(cmd_info._read_subid('bob', '/etc/subuid'), (None, None))

    def test_finds_matching_line(self):
        content = "alice:100000:65536\nbob:165536:65536\n"
        m = unittest.mock.mock_open(read_data=content)
        with patch('builtins.open', m):
            self.assertEqual(cmd_info._read_subid('bob', '/etc/subuid'), (165536, 65536))

    def test_no_matching_line_returns_none_none(self):
        content = "alice:100000:65536\n"
        m = unittest.mock.mock_open(read_data=content)
        with patch('builtins.open', m):
            self.assertEqual(cmd_info._read_subid('bob', '/etc/subuid'), (None, None))


class TestCmdStats(unittest.TestCase):
    def test_stats_json_and_follow_conflict_exits(self):
        manager = MagicMock()
        with self.assertRaises(SystemExit) as cm:
            cmd_stats.cmd_stats(_args(json=True, follow=True, workload=None), manager)
        self.assertEqual(cm.exception.code, 1)

    def test_stats_vm_not_applicable_exits_zero(self):
        from substrate import NotApplicable
        with _WorkloadDir(VM_TOML, name='test-vm'):
            manager = MagicMock()
            sub = MagicMock()
            sub.resource_usage.side_effect = NotApplicable('vm workloads have no stats')
            buf = io.StringIO()
            with patch.object(cmd_stats, 'get_substrate', return_value=sub):
                with patch('sys.stdout', buf):
                    with self.assertRaises(SystemExit) as cm:
                        cmd_stats.cmd_stats(
                            _args(json=False, follow=False, workload='test-vm'), manager)
            self.assertEqual(cm.exception.code, 0)
            self.assertIn('not applicable', buf.getvalue())

    def test_stats_user_not_found_exits_one(self):
        with _WorkloadDir(MINIMAL_TOML):
            manager = MagicMock()
            manager.user_exists.return_value = False
            sub = MagicMock()
            with patch.object(cmd_stats, 'get_substrate', return_value=sub):
                with self.assertRaises(SystemExit) as cm:
                    cmd_stats.cmd_stats(
                        _args(json=False, follow=False, workload='test-wl'), manager)
            self.assertEqual(cm.exception.code, 1)

    def test_stats_json_single_workload_parses_row(self):
        with _WorkloadDir(MINIMAL_TOML):
            manager = MagicMock()
            manager.user_exists.return_value = True
            sub = MagicMock()
            row = {
                'workload': 'test-wl', 'username': '_wl-test-wl',
                'container': 'workload-test-wl', 'cpu_percent': 1.23,
                'mem_usage': 10_000_000, 'mem_limit': 100_000_000, 'mem_percent': 10.0,
                'net_input': 1000, 'net_output': 2000,
                'block_input': 3000, 'block_output': 4000, 'pids': 5,
            }
            sub.resource_usage.return_value = [row]
            buf = io.StringIO()
            with patch.object(cmd_stats, 'get_substrate', return_value=sub):
                with patch('sys.stdout', buf):
                    cmd_stats.cmd_stats(
                        _args(json=True, follow=False, workload='test-wl'), manager)
            data = json.loads(buf.getvalue())
            self.assertEqual(len(data['stats']), 1)
            s = data['stats'][0]
            self.assertEqual(s['cpu_percent'], 1.23)
            self.assertEqual(s['pids'], 5)
            self.assertGreater(s['mem_usage'], 0)

    def test_stats_all_workloads_human_no_running(self):
        with _MultiWorkloadDir({'test-wl': MINIMAL_TOML}):
            from workloadctl_core import WorkloadManager
            manager = WorkloadManager()
            manager.user_exists = MagicMock(return_value=False)
            buf = io.StringIO()
            with patch('sys.stdout', buf):
                cmd_stats.cmd_stats(_args(json=False, follow=False, workload=None), manager)
            self.assertIn('No running workloads found', buf.getvalue())

    def test_stats_all_workloads_json_aggregates_running(self):
        with _MultiWorkloadDir({'test-wl': MINIMAL_TOML}) as p:
            (p / 'test-wl' / '.enabled').write_text('')
            from workloadctl_core import WorkloadManager
            manager = WorkloadManager()
            manager.user_exists = MagicMock(return_value=True)
            podman = MagicMock()
            podman.container_exists.return_value = True
            manager.podman = MagicMock(return_value=podman)
            sub = MagicMock()
            row = {'workload': 'test-wl', 'username': '_wl-test-wl',
                   'container': 'workload-test-wl', 'cpu_percent': 0.0,
                   'mem_usage': 0, 'mem_limit': 0, 'mem_percent': 0.0,
                   'net_input': 0, 'net_output': 0,
                   'block_input': 0, 'block_output': 0, 'pids': 1}
            sub.resource_usage.return_value = [row]
            buf = io.StringIO()
            with patch.object(cmd_stats, 'get_substrate', return_value=sub):
                with patch('sys.stdout', buf):
                    cmd_stats.cmd_stats(_args(json=True, follow=False, workload=None), manager)
            data = json.loads(buf.getvalue())
            self.assertEqual(len(data['stats']), 1)


class TestCmdHealthAdditional(unittest.TestCase):
    def test_health_vm_json(self):
        with _WorkloadDir(VM_TOML, name='test-vm'):
            manager = MagicMock()
            manager.user_exists.return_value = True
            sub = MagicMock()
            sub.liveness.return_value = {'service_active': True, 'service_state': 'active'}
            buf = io.StringIO()
            with patch.object(cmd_health, 'get_substrate', return_value=sub):
                with patch('sys.stdout', buf):
                    with self.assertRaises(SystemExit) as cm:
                        cmd_health.cmd_health(_args(json=True, workload='test-vm'), manager)
            self.assertEqual(cm.exception.code, 0)
            data = json.loads(buf.getvalue())
            self.assertEqual(data['overall'], 'HEALTHY')

    def test_health_vm_human_unhealthy_when_user_missing(self):
        with _WorkloadDir(VM_TOML, name='test-vm'):
            manager = MagicMock()
            manager.user_exists.return_value = False
            sub = MagicMock()
            sub.liveness.return_value = {'service_active': True, 'service_state': 'active'}
            buf = io.StringIO()
            with patch.object(cmd_health, 'get_substrate', return_value=sub):
                with patch('sys.stdout', buf):
                    with self.assertRaises(SystemExit) as cm:
                        cmd_health.cmd_health(_args(json=False, workload='test-vm'), manager)
            self.assertEqual(cm.exception.code, 1)
            self.assertIn('UNHEALTHY', buf.getvalue())

    def test_health_multi_json_specific_container_not_found(self):
        with _WorkloadDir(POD_TOML, name='test-pod'):
            manager = MagicMock()
            with patch('sys.stdout', io.StringIO()):
                with self.assertRaises(SystemExit) as cm:
                    cmd_health.cmd_health(
                        _args(json=True, workload='test-pod/nope'), manager)
            self.assertEqual(cm.exception.code, 2)

    def test_health_multi_human_all_containers(self):
        def fake_run(cmd, **kw):
            return _ok(stdout='active\n', returncode=0)

        with _WorkloadDir(POD_TOML, name='test-pod'):
            manager = MagicMock()
            manager.user_exists.return_value = True
            manager.podman.return_value.container_status.return_value = 'running'
            buf = io.StringIO()
            with patch('subprocess.run', side_effect=fake_run):
                with patch('sys.stdout', buf):
                    with self.assertRaises(SystemExit) as cm:
                        cmd_health.cmd_health(
                            _args(json=False, workload='test-pod'), manager)
            self.assertEqual(cm.exception.code, 0)
            out = buf.getvalue()
            self.assertIn('api: service active, running', out)
            self.assertIn('db: service active, running', out)

    def test_health_single_full_checks_with_ports_and_healthcheck(self):
        def fake_run(cmd, **kw):
            if cmd[:2] == ['systemctl', 'is-active']:
                return _ok(stdout='active\n', returncode=0)
            if 'show' in cmd and 'Slice' in cmd:
                return _ok(stdout='workloads.slice\n')
            if '--property=ActiveEnterTimestamp' in cmd:
                return _ok(stdout='@1700000000\n', returncode=0)
            return _ok()

        with _WorkloadDir(PORTS_HEALTH_TOML):
            manager = MagicMock()
            manager.user_exists.return_value = True
            manager.podman.return_value.container_status.return_value = 'running'
            manager.podman.return_value.container_health.return_value = 'healthy'
            buf = io.StringIO()
            with patch.object(WorkloadConfig, 'uid', new_callable=PropertyMock,
                               return_value=10020):
                with patch.object(cmd_health, 'manager_active', return_value=False):
                    with patch('socket.socket') as sock_cls:
                        sock_cls.return_value.connect_ex.return_value = 1  # closed
                        with patch('subprocess.run', side_effect=fake_run):
                            with patch('sys.stdout', buf):
                                with self.assertRaises(SystemExit) as cm:
                                    cmd_health.cmd_health(
                                        _args(json=True, workload='test-wl'), manager)
            data = json.loads(buf.getvalue())
            checks = {c['check']: c for c in data['checks']}
            self.assertTrue(checks['container_health']['healthy'])
            self.assertFalse(checks['port_accessibility']['healthy'])
            self.assertEqual(data['overall'], 'UNHEALTHY')  # port closed
            self.assertEqual(cm.exception.code, 1)

    def test_health_single_no_container_running(self):
        def fake_run(cmd, **kw):
            if cmd[:2] == ['systemctl', 'is-active']:
                return _ok(stdout='inactive\n', returncode=3)
            return _ok()

        with _WorkloadDir(MINIMAL_TOML):
            manager = MagicMock()
            manager.user_exists.return_value = True
            manager.podman.return_value.container_status.return_value = None
            buf = io.StringIO()
            with patch.object(WorkloadConfig, 'uid', new_callable=PropertyMock,
                               return_value=10021):
                with patch.object(cmd_health, 'manager_active', return_value=False):
                    with patch('subprocess.run', side_effect=fake_run):
                        with patch('sys.stdout', buf):
                            with self.assertRaises(SystemExit) as cm:
                                cmd_health.cmd_health(
                                    _args(json=True, workload='test-wl'), manager)
            data = json.loads(buf.getvalue())
            checks = {c['check']: c for c in data['checks']}
            self.assertFalse(checks['container_running']['healthy'])
            self.assertEqual(data['overall'], 'UNHEALTHY')
            self.assertEqual(cm.exception.code, 1)


class TestCmdListMore(unittest.TestCase):
    """Extra cmd_list coverage: json image_id exception, human-table elision
    (long ports/image/name), VM and multi-container image columns."""

    def test_list_json_image_id_exception_swallowed(self):
        with _MultiWorkloadDir({'test-wl': MINIMAL_TOML}):
            from workloadctl_core import WorkloadManager
            manager = WorkloadManager()
            manager.user_exists = MagicMock(return_value=True)
            manager.get_image_id = MagicMock(side_effect=RuntimeError('no sudo'))
            buf = io.StringIO()
            with patch('sys.stdout', buf):
                cmd_inspect.cmd_list(_args(json=True, workload=None), manager)
            data = json.loads(buf.getvalue())
            self.assertIsNone(data['workloads'][0]['image_id'])

    def test_list_human_elides_long_columns_and_shows_vm_and_multi_image(self):
        long_name = 'a' * 25
        toml_long = MINIMAL_TOML.replace('name = "test-wl"', f'name = "{long_name}"')
        long_ports_toml = """\
[workload]
name = "ports-wl"

[container]
image = "example.com/test:latest"

[network]
mode = "pasta"
ports = ["18080:80", "18081:81", "18082:82", "18083:83"]
"""
        long_image_toml = """\
[workload]
name = "img-wl"

[container]
image = "example.com/this-is-a-very-long-image-name-indeed:latest"
"""
        entries = {
            long_name: toml_long,
            'ports-wl': long_ports_toml,
            'img-wl': long_image_toml,
            'test-vm': VM_TOML,
            'test-pod': POD_TOML,
        }
        with _MultiWorkloadDir(entries):
            from workloadctl_core import WorkloadManager
            manager = WorkloadManager()
            manager.user_exists = MagicMock(return_value=False)
            manager.get_image_id = MagicMock(return_value=None)
            buf = io.StringIO()
            with patch('sys.stdout', buf):
                cmd_inspect.cmd_list(_args(json=False, workload=None), manager)
            out = buf.getvalue()
            self.assertIn('...', out)  # some column got elided
            self.assertIn('(2 containers, pod)', out)  # multi image column
            self.assertIn('example.com/guest:latest', out)  # vm image column


class TestCmdStatusMore(unittest.TestCase):
    """cmd_status json: non-numeric MainPID and non-@ timestamp both fall
    back to None instead of raising."""

    def test_status_json_bad_pid_and_timestamp_yield_none(self):
        def fake_run(cmd, **kw):
            if cmd[:2] == ['systemctl', 'show']:
                return _ok(stdout='ActiveState=active\nMainPID=notanumber\n'
                                   'ActiveEnterTimestamp=garbage\n')
            return _ok(returncode=1)

        with _WorkloadDir(MINIMAL_TOML):
            manager = MagicMock()
            buf = io.StringIO()
            with patch('subprocess.run', side_effect=fake_run), patch('sys.stdout', buf):
                cmd_inspect.cmd_status(_args(json=True, workload='test-wl'), manager)
            data = json.loads(buf.getvalue())
            self.assertIsNone(data['main_pid'])
            self.assertIsNone(data['active_since'])
            self.assertFalse(data['enabled'])


class TestCmdImagesMore(unittest.TestCase):
    """cmd_images: prune-loop exceptions are swallowed, and the human listing
    prints real rows (with a >50 char image elided) plus the totals line."""

    def test_prune_swallows_per_user_exception_and_reports_no_images(self):
        entry = types.SimpleNamespace(pw_name='_wl-test', pw_uid=10000, pw_dir='/nonexistent')
        with patch('pwd.getpwall', return_value=[entry]), \
             patch.object(cmd_images, 'require_root'), \
             patch.object(cmd_images.Podman, 'for_user', side_effect=RuntimeError('boom')), \
             patch('sys.stdout', io.StringIO()) as buf:
            cmd_images.cmd_images(_args(subcommand='prune'), MagicMock())
        self.assertIn('No images to prune', buf.getvalue())

    def test_human_listing_prints_rows_and_total_with_long_image_elided(self):
        with _MultiWorkloadDir({'test-wl': MINIMAL_TOML}):
            from workloadctl_core import WorkloadManager
            manager = WorkloadManager()
            manager.user_exists = MagicMock(return_value=True)
            podman = MagicMock()
            podman.image_info.return_value = {
                'Size': 12345, 'Created': '2024-01-01T00:00:00Z',
            }
            manager.podman = MagicMock(return_value=podman)
            buf = io.StringIO()
            with patch('sys.stdout', buf):
                cmd_images.cmd_images(_args(json=False, subcommand=None), manager)
            out = buf.getvalue()
            self.assertIn('test-wl', out)
            self.assertIn('Total: 1 workload image(s)', out)


class TestVmQmpStatusMore(unittest.TestCase):
    def test_reply_without_return_key_yields_none(self):
        fake_qmp = MagicMock()
        fake_qmp.execute.return_value = {'error': 'nope'}
        with patch('pathlib.Path.exists', return_value=True):
            with patch.object(cmd_info, 'QMPClient', return_value=fake_qmp):
                self.assertIsNone(cmd_info._vm_qmp_status('name'))


class TestPrintControlFilesMore(unittest.TestCase):
    def test_human_output_lists_each_source_kind(self):
        config = MagicMock()
        config.name = 'wl'
        config.bundle = 'wl'
        config.override_dir = Path('/etc/workloads.d/wl')
        config.bundle_dir = Path('/usr/share/workloadctl/workloads/wl')
        files = [
            {'file': 'setup.sh', 'source': 'etc', 'path': '/etc/x', 'exists': True},
            {'file': 'build.sh', 'source': 'abs', 'path': '/abs/x', 'exists': True},
            {'file': 'bad', 'source': 'invalid', 'path': '(err)', 'exists': False},
            {'file': 'Containerfile', 'source': 'usr', 'path': '/usr/x', 'exists': True},
            {'file': 'missing.sh', 'source': 'usr', 'path': '/usr/y', 'exists': False},
        ]
        buf = io.StringIO()
        with patch.object(cmd_info, '_collect_control_files', return_value=files):
            with patch('sys.stdout', buf):
                cmd_info._print_control_files(config, json_mode=False)
        out = buf.getvalue()
        self.assertIn('override', out)
        self.assertIn('absolute', out)
        self.assertIn('invalid', out)
        self.assertIn('shipped', out)
        self.assertIn('missing', out)
        self.assertIn('Edit a control file', out)


class TestCmdInfoMore(unittest.TestCase):
    def _base_run(self):
        def fake_run(cmd, **kw):
            if cmd[:2] == ['systemctl', 'show']:
                return _ok(stdout='ActiveState=active\nActiveEnterTimestamp=@1700000000\n')
            return _ok()
        return fake_run

    def test_info_vm_human_user_exists_with_subid_and_inactive_service(self):
        def fake_run(cmd, **kw):
            if cmd[:2] == ['systemctl', 'show']:
                return _ok(stdout='ActiveState=inactive\n')
            return _ok()

        with _WorkloadDir(VM_TOML, name='test-vm') as p:
            home = p / 'test-vm'
            (home / 'system.qcow2').write_text('x')
            data_dir = p / 'test-vm-data'
            data_dir.mkdir()
            (data_dir / 'data.qcow2').write_text('x')
            manager = MagicMock()
            manager.user_exists.return_value = True
            buf = io.StringIO()
            with patch('subprocess.run', side_effect=fake_run), \
                 patch.object(cmd_info, '_vm_qmp_status', return_value=None), \
                 patch('substrate_vm._vm_guest_addresses', return_value=[]), \
                 patch.object(WorkloadConfig, 'uid', new_callable=PropertyMock,
                              return_value=10030), \
                 patch.object(WorkloadConfig, 'home_dir', new_callable=PropertyMock,
                              return_value=home), \
                 patch.object(WorkloadConfig, 'data_dir', new_callable=PropertyMock,
                              return_value=data_dir), \
                 patch('cmd_info._read_subid',
                       side_effect=[(200000, 65536), (200000, 65536)]), \
                 patch('sys.stdout', buf):
                cmd_info.cmd_info(_args(json=False, workload='test-vm'), manager)
            out = buf.getvalue()
            self.assertIn('Data disk:', out)
            self.assertIn('SubUID: 200000 (65536 IDs)', out)
            self.assertIn('SubGID: 200000 (65536 IDs)', out)
            self.assertIn('Active: inactive', out)

    def test_info_multi_json_image_id_lookup_exception_swallowed(self):
        with _WorkloadDir(POD_TOML, name='test-pod'):
            manager = MagicMock()
            manager.user_exists.return_value = True
            manager.podman.return_value.image_id.side_effect = RuntimeError('boom')
            buf = io.StringIO()
            with patch('subprocess.run', side_effect=self._base_run()), patch('sys.stdout', buf):
                cmd_info.cmd_info(_args(json=True, workload='test-pod'), manager)
            data = json.loads(buf.getvalue())
            self.assertIsNone(data['containers'][0]['image_id'])

    def test_info_single_human_full_user_details_and_ports(self):
        toml = """\
[workload]
name = "test-wl"

[container]
image = "example.com/test:latest"

[network]
mode = "pasta"
ports = ["8080:80"]
"""
        with _WorkloadDir(toml):
            manager = MagicMock()
            manager.user_exists.return_value = True
            manager.get_image_id.return_value = 'deadbeefcafebabe1234'
            buf = io.StringIO()
            fake_pw = types.SimpleNamespace(pw_dir='/home/_wl-test-wl', pw_gid=10005)
            with patch('subprocess.run', side_effect=self._base_run()), \
                 patch.object(WorkloadConfig, 'uid', new_callable=PropertyMock,
                              return_value=10005), \
                 patch('pwd.getpwnam', return_value=fake_pw), \
                 patch('os.getgrouplist', return_value=[10005]), \
                 patch('grp.getgrgid', return_value=types.SimpleNamespace(gr_name='_wl-test-wl')), \
                 patch('cmd_info._read_subid',
                       side_effect=[(100000, 65536), (100000, 65536)]), \
                 patch.object(WorkloadConfig, 'home_dir', new_callable=PropertyMock,
                              return_value=Path('/nonexistent/home')), \
                 patch.object(cmd_info, 'get_substrate') as gs, \
                 patch('sys.stdout', buf):
                gs.return_value.endpoints.return_value = [
                    {'host': 'http://x:8080', 'container': '80'},
                    {'host': 'http://y:9090', 'container': None},
                ]
                cmd_info.cmd_info(_args(json=False, workload='test-wl'), manager)
            out = buf.getvalue()
            self.assertIn('ID:     sha256:deadbeefcafe...', out)
            self.assertIn('UID:    10005', out)
            self.assertIn('Home:   /home/_wl-test-wl', out)
            self.assertIn('Groups: _wl-test-wl', out)
            self.assertIn('SubUID: 100000 (65536 IDs)', out)
            self.assertIn('SubGID: 100000 (65536 IDs)', out)
            self.assertIn('Accessible at:', out)
            self.assertIn('→ container:80', out)
            self.assertIn('http://y:9090', out)
            self.assertIn('(not created)', out)  # storage_home set, but dir absent

    def test_info_single_human_storage_exists_shows_du_size(self):
        with _WorkloadDir(MINIMAL_TOML) as p:
            home = p / 'home'
            home.mkdir()

            def fake_run(cmd, **kw):
                if cmd[:2] == ['systemctl', 'show']:
                    return _ok(stdout='ActiveState=active\nActiveEnterTimestamp=@bogus\n')
                if cmd[0] == 'du':
                    return _ok(stdout='42M\t/whatever\n')
                return _ok()

            manager = MagicMock()
            manager.user_exists.return_value = True
            manager.get_image_id.return_value = None
            buf = io.StringIO()
            with patch('subprocess.run', side_effect=fake_run), \
                 patch.object(WorkloadConfig, 'home_dir', new_callable=PropertyMock,
                              return_value=home), \
                 patch('pwd.getpwnam', side_effect=KeyError('no such user')), \
                 patch('sys.stdout', buf):
                cmd_info.cmd_info(_args(json=False, workload='test-wl'), manager)
            out = buf.getvalue()
            self.assertIn('Home:   ' + str(home) + ' (42M used)', out)
            # ActiveEnterTimestamp wasn't a valid @-float -> falls back to state string
            self.assertIn('Active: active', out)


class TestStatsHelpersMore(unittest.TestCase):
    def test_parse_percent_invalid_string_returns_zero(self):
        import substrate
        self.assertEqual(substrate._stat_percent(object()), 0.0)
        self.assertEqual(substrate._stat_percent('n/a'), 0.0)

    def test_parse_io_without_separator_returns_zero_zero(self):
        import substrate
        self.assertEqual(substrate._stat_io_pair('garbage'), (0, 0))


class TestCmdStatsMore(unittest.TestCase):
    def test_single_workload_not_applicable_after_user_exists_check(self):
        from substrate import NotApplicable
        with _WorkloadDir(MINIMAL_TOML):
            manager = MagicMock()
            manager.user_exists.return_value = True
            sub = MagicMock()
            sub.resource_usage.side_effect = NotApplicable('no stats here')
            buf = io.StringIO()
            with patch.object(cmd_stats, 'get_substrate', return_value=sub):
                with patch('sys.stdout', buf):
                    with self.assertRaises(SystemExit) as cm:
                        cmd_stats.cmd_stats(
                            _args(json=False, follow=False, workload='test-wl'), manager)
            self.assertEqual(cm.exception.code, 0)
            self.assertIn('not applicable', buf.getvalue())

    def test_all_workloads_json_skips_not_applicable(self):
        from substrate import NotApplicable
        with _MultiWorkloadDir({'test-wl': MINIMAL_TOML}):
            from workloadctl_core import WorkloadManager
            manager = WorkloadManager()
            manager.user_exists = MagicMock(return_value=True)
            podman = MagicMock()
            podman.container_exists.return_value = True
            manager.podman = MagicMock(return_value=podman)
            sub = MagicMock()
            sub.resource_usage.side_effect = NotApplicable('nope')
            buf = io.StringIO()
            with patch.object(cmd_stats, 'get_substrate', return_value=sub):
                with patch('sys.stdout', buf):
                    cmd_stats.cmd_stats(_args(json=True, follow=False, workload=None), manager)
            data = json.loads(buf.getvalue())
            self.assertEqual(data['stats'], [])

    def test_all_workloads_vm_included_in_running_targets(self):
        with _MultiWorkloadDir({'test-vm': VM_TOML}) as p:
            (p / 'test-vm' / '.enabled').write_text('')
            from workloadctl_core import WorkloadManager
            manager = WorkloadManager()
            manager.user_exists = MagicMock(return_value=True)
            sub = MagicMock()
            buf = io.StringIO()
            with patch.object(cmd_stats, 'get_substrate', return_value=sub):
                with patch('sys.stdout', buf):
                    cmd_stats.cmd_stats(_args(json=False, follow=False, workload=None), manager)
            self.assertNotIn('No running workloads found', buf.getvalue())
            sub.resource_usage.assert_called_once_with([])

    def test_all_workloads_human_prints_each_and_follow_shows_only_first(self):
        with _MultiWorkloadDir({'test-wl': MINIMAL_TOML}) as p:
            (p / 'test-wl' / '.enabled').write_text('')
            from workloadctl_core import WorkloadManager
            manager = WorkloadManager()
            manager.user_exists = MagicMock(return_value=True)
            podman = MagicMock()
            podman.container_exists.return_value = True
            manager.podman = MagicMock(return_value=podman)
            sub = MagicMock()
            buf = io.StringIO()
            with patch.object(cmd_stats, 'get_substrate', return_value=sub):
                with patch('sys.stdout', buf):
                    cmd_stats.cmd_stats(_args(json=False, follow=True, workload=None), manager)
            out = buf.getvalue()
            self.assertIn('--follow with multiple workloads shows only test-wl', out)
            sub.resource_usage.assert_called_once()


class TestCmdHealthMore(unittest.TestCase):
    """Human (non-json) single-container output, and the container-health /
    port-parsing edge branches."""

    def test_health_single_human_output(self):
        def fake_run(cmd, **kw):
            if cmd[:2] == ['systemctl', 'is-active']:
                return _ok(stdout='active\n', returncode=0)
            return _ok()

        with _WorkloadDir(MINIMAL_TOML):
            manager = MagicMock()
            manager.user_exists.return_value = True
            manager.podman.return_value.container_status.return_value = 'running'
            buf = io.StringIO()
            with patch.object(WorkloadConfig, 'uid', new_callable=PropertyMock,
                               return_value=10040):
                with patch.object(cmd_health, 'manager_active', return_value=False):
                    with patch('subprocess.run', side_effect=fake_run):
                        with patch('sys.stdout', buf):
                            with self.assertRaises(SystemExit) as cm:
                                cmd_health.cmd_health(
                                    _args(json=False, workload='test-wl'), manager)
            out = buf.getvalue()
            self.assertIn('Workload: test-wl', out)
            self.assertIn('Overall: HEALTHY', out)
            self.assertIn('✓ Service active and running', out)
            self.assertEqual(cm.exception.code, 0)

    def test_health_single_container_health_check_unavailable(self):
        def fake_run(cmd, **kw):
            if cmd[:2] == ['systemctl', 'is-active']:
                return _ok(stdout='active\n', returncode=0)
            return _ok()

        with _WorkloadDir(PORTS_HEALTH_TOML.replace('ports = ["8080:80"]', 'ports = []')):
            manager = MagicMock()
            manager.user_exists.return_value = True
            manager.podman.return_value.container_status.return_value = 'running'
            manager.podman.return_value.container_health.return_value = None
            buf = io.StringIO()
            with patch.object(WorkloadConfig, 'uid', new_callable=PropertyMock,
                               return_value=10041):
                with patch.object(cmd_health, 'manager_active', return_value=False):
                    with patch('subprocess.run', side_effect=fake_run):
                        with patch('sys.stdout', buf):
                            with self.assertRaises(SystemExit) as cm:
                                cmd_health.cmd_health(
                                    _args(json=True, workload='test-wl'), manager)
            data = json.loads(buf.getvalue())
            checks = {c['check']: c for c in data['checks']}
            self.assertFalse(checks['container_health']['healthy'])
            self.assertEqual(checks['container_health']['message'],
                              'Container health check not available')
            self.assertEqual(data['overall'], 'UNHEALTHY')
            self.assertEqual(cm.exception.code, 1)

    def test_health_probes_host_side_of_publish_spec(self):
        """port_accessibility must probe the host-published port, not the
        container port. `18080:80` publishes host 18080 -> container 80, so the
        probe (and its details) must reference 18080."""
        toml = PORTS_HEALTH_TOML.replace('ports = ["8080:80"]', 'ports = ["18080:80"]')

        def fake_run(cmd, **kw):
            if cmd[:2] == ['systemctl', 'is-active']:
                return _ok(stdout='active\n', returncode=0)
            return _ok()

        with _WorkloadDir(toml):
            manager = MagicMock()
            manager.user_exists.return_value = True
            manager.podman.return_value.container_status.return_value = 'running'
            manager.podman.return_value.container_health.return_value = 'healthy'
            buf = io.StringIO()
            with patch.object(WorkloadConfig, 'uid', new_callable=PropertyMock,
                               return_value=10043):
                with patch.object(cmd_health, 'manager_active', return_value=False):
                    with patch('socket.socket') as sock_cls:
                        sock_cls.return_value.connect_ex.return_value = 0  # open
                        with patch('subprocess.run', side_effect=fake_run):
                            with patch('sys.stdout', buf):
                                with self.assertRaises(SystemExit) as cm:
                                    cmd_health.cmd_health(
                                        _args(json=True, workload='test-wl'), manager)
            # It must have connected to the host port 18080, never 80.
            connected_ports = [c.args[0][1]
                               for c in sock_cls.return_value.connect_ex.call_args_list]
            self.assertIn(18080, connected_ports)
            self.assertNotIn(80, connected_ports)
            data = json.loads(buf.getvalue())
            checks = {c['check']: c for c in data['checks']}
            self.assertTrue(checks['port_accessibility']['healthy'])
            self.assertEqual(checks['port_accessibility']['details']['port'], '18080')
            self.assertEqual(cm.exception.code, 0)

    def test_health_random_host_port_publish_not_probed(self):
        """A bare container port (`80`) has podman pick a random host port, so
        there is no deterministic port to probe — the check is skipped, not run
        against the container port."""
        toml = PORTS_HEALTH_TOML.replace('ports = ["8080:80"]', 'ports = ["80"]')

        def fake_run(cmd, **kw):
            if cmd[:2] == ['systemctl', 'is-active']:
                return _ok(stdout='active\n', returncode=0)
            return _ok()

        with _WorkloadDir(toml):
            manager = MagicMock()
            manager.user_exists.return_value = True
            manager.podman.return_value.container_status.return_value = 'running'
            manager.podman.return_value.container_health.return_value = 'healthy'
            buf = io.StringIO()
            with patch.object(WorkloadConfig, 'uid', new_callable=PropertyMock,
                               return_value=10044):
                with patch.object(cmd_health, 'manager_active', return_value=False):
                    with patch('subprocess.run', side_effect=fake_run):
                        with patch('sys.stdout', buf):
                            with self.assertRaises(SystemExit) as cm:
                                cmd_health.cmd_health(
                                    _args(json=True, workload='test-wl'), manager)
            data = json.loads(buf.getvalue())
            checks = [c['check'] for c in data['checks']]
            self.assertNotIn('port_accessibility', checks)
            self.assertEqual(data['overall'], 'HEALTHY')
            self.assertEqual(cm.exception.code, 0)

    def test_publish_host_port_parsing(self):
        cases = {
            "8080:80": "8080",
            "80": None,
            "127.0.0.1:8080:80": "8080",
            "0.0.0.0:8080:80/tcp": "8080",
            "8080:80/udp": "8080",
            "::80": None,          # ip::containerPort -> random host port
            "8080-8090:80-90": None,  # range, no single port
            "[::1]:8080:80": "8080",  # IPv6 bind address
        }
        for spec, expected in cases.items():
            with self.subTest(spec=spec):
                self.assertEqual(cmd_health._publish_host_port(spec), expected)

    def test_health_single_invalid_port_number_skipped(self):
        toml = PORTS_HEALTH_TOML.replace('ports = ["8080:80"]', 'ports = ["notaport"]')

        def fake_run(cmd, **kw):
            if cmd[:2] == ['systemctl', 'is-active']:
                return _ok(stdout='active\n', returncode=0)
            return _ok()

        with _WorkloadDir(toml):
            manager = MagicMock()
            manager.user_exists.return_value = True
            manager.podman.return_value.container_status.return_value = 'running'
            manager.podman.return_value.container_health.return_value = 'healthy'
            buf = io.StringIO()
            with patch.object(WorkloadConfig, 'uid', new_callable=PropertyMock,
                               return_value=10042):
                with patch.object(cmd_health, 'manager_active', return_value=False):
                    with patch('subprocess.run', side_effect=fake_run):
                        with patch('sys.stdout', buf):
                            with self.assertRaises(SystemExit) as cm:
                                cmd_health.cmd_health(
                                    _args(json=True, workload='test-wl'), manager)
            data = json.loads(buf.getvalue())
            checks = [c['check'] for c in data['checks']]
            self.assertNotIn('port_accessibility', checks)
            self.assertEqual(data['overall'], 'HEALTHY')
            self.assertEqual(cm.exception.code, 0)


if __name__ == '__main__':
    unittest.main()
