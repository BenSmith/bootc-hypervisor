#!/usr/bin/env python3
"""Unit tests for workloadctl JSON output — covers plan tasks 1.1 through 2.6."""

import importlib.machinery
import importlib.util
import io
import json
import os
import pwd
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

# ── module load ───────────────────────────────────────────────────────────────

_LIB = os.path.join(os.path.dirname(__file__), '..', 'lib')
sys.path.insert(0, _LIB)

_SCRIPT = os.path.join(os.path.dirname(__file__), '..', 'bin', 'workloadctl')
_loader = importlib.machinery.SourceFileLoader('workloadctl', _SCRIPT)
_spec = importlib.util.spec_from_loader('workloadctl', _loader, origin=_SCRIPT)
wctl = importlib.util.module_from_spec(_spec)
# The script resolves its lib/ dir relative to __file__; module_from_spec does
# not set it when origin is passed explicitly, so set it before exec.
wctl.__file__ = _SCRIPT
_spec.loader.exec_module(wctl)

# ── shared helpers ────────────────────────────────────────────────────────────

def _ok(stdout='', stderr='', returncode=0):
    return CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)

def _fail(stderr='', returncode=1):
    return CompletedProcess(args=[], returncode=returncode, stdout='', stderr=stderr)

def _args(**kwargs):
    defaults = dict(
        json=False, workload=None, follow=False, apply=False, all=False,
        output=None, no_stop=False, subcommand=None,
    )
    defaults.update(kwargs)
    return types.SimpleNamespace(**defaults)


MINIMAL_TOML = """\
[workload]
name = "test-wl"
enabled = false

[container]
image = "example.com/test:latest"
"""

ENABLED_TOML = """\
[workload]
name = "test-wl"
enabled = true

[container]
image = "example.com/test:latest"

[network]
mode = "pasta"
ports = ["8080:80"]
"""

HOST_NET_TOML = """\
[workload]
name = "test-wl"
enabled = true

[container]
image = "example.com/test:latest"

[network]
mode = "host"
ports = ["8080"]
"""

VM_TOML = """\
[workload]
name = "test-vm"
enabled = false

[vm]
image = "example.com/guest:latest"
"""


class _WorkloadDir:
    """Temp WORKLOAD_DIR with one TOML, WORKLOAD_DIR patched on the module."""

    def __init__(self, toml=MINIMAL_TOML, name='test-wl'):
        self._toml = toml
        self._name = name
        self._tmp = None
        self._patcher = None

    def __enter__(self):
        self._tmp = tempfile.mkdtemp()
        tmp_path = Path(self._tmp)
        (tmp_path / f'{self._name}.toml').write_text(self._toml)
        self._patcher = patch.object(wctl, 'WORKLOAD_DIR', tmp_path)
        self._patcher.start()
        return tmp_path

    def __exit__(self, *_):
        self._patcher.stop()
        shutil.rmtree(self._tmp, ignore_errors=True)


def _capture_json(fn):
    buf = io.StringIO()
    with patch('sys.stdout', buf):
        fn()
    return json.loads(buf.getvalue())


def _capture_json_exitok(fn):
    """Like _capture_json but swallows SystemExit (for commands that call sys.exit)."""
    buf = io.StringIO()
    with patch('sys.stdout', buf):
        try:
            fn()
        except SystemExit:
            pass
    return json.loads(buf.getvalue())


# ── Task 1.1 — status --json ──────────────────────────────────────────────────

_SHOW_ACTIVE = (
    "ActiveState=active\n"
    "UnitFileState=enabled\n"
    "MainPID=12345\n"
    "MemoryCurrent=104857600\n"
    "TasksCurrent=5\n"
    "Result=success\n"
    "ActiveEnterTimestamp=@1746230400\n"
)

_SHOW_INACTIVE = (
    "ActiveState=inactive\n"
    "UnitFileState=disabled\n"
    "MainPID=0\n"
    "MemoryCurrent=18446744073709551615\n"
    "TasksCurrent=18446744073709551615\n"
    "Result=\n"
    "ActiveEnterTimestamp=\n"
)


class TestStatusJson(unittest.TestCase):

    def _run(self, show_stdout, is_enabled_rc=0):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            args = _args(workload='test-wl', json=True)

            def fake_run(cmd, **kw):
                if 'show' in cmd:
                    return _ok(stdout=show_stdout)
                if 'is-enabled' in cmd:
                    return _ok() if is_enabled_rc == 0 else _fail(returncode=is_enabled_rc)
                return _ok()

            with patch('subprocess.run', side_effect=fake_run):
                return _capture_json(lambda: wctl.cmd_status(args, wctl.WorkloadManager()))

    def test_active_service_values(self):
        data = self._run(_SHOW_ACTIVE)
        self.assertEqual(data['workload'], 'test-wl')
        self.assertEqual(data['service'], 'workload-test-wl.service')
        self.assertEqual(data['state'], 'active')
        self.assertTrue(data['enabled'])
        self.assertEqual(data['active_since'], 1746230400)
        self.assertEqual(data['main_pid'], 12345)
        self.assertEqual(data['memory_current'], 104857600)
        self.assertEqual(data['tasks_current'], 5)
        self.assertEqual(data['result'], 'success')

    def test_uint64_max_sentinel_becomes_null(self):
        data = self._run(_SHOW_INACTIVE, is_enabled_rc=1)
        self.assertIsNone(data['memory_current'])
        self.assertIsNone(data['tasks_current'])
        self.assertIsNone(data['active_since'])
        self.assertIsNone(data['result'])
        self.assertFalse(data['enabled'])

    def test_nva_sentinel_becomes_null(self):
        show = (
            "ActiveState=inactive\n"
            "MainPID=[n/a]\n"
            "MemoryCurrent=[n/a]\n"
            "TasksCurrent=[n/a]\n"
            "Result=[n/a]\n"
            "ActiveEnterTimestamp=[n/a]\n"
        )
        data = self._run(show)
        self.assertIsNone(data['main_pid'])
        self.assertIsNone(data['memory_current'])
        self.assertIsNone(data['tasks_current'])

    def test_all_keys_always_present(self):
        data = self._run(_SHOW_ACTIVE)
        for key in ('workload', 'service', 'state', 'enabled', 'active_since',
                    'main_pid', 'memory_current', 'tasks_current', 'result'):
            self.assertIn(key, data, f'missing key: {key}')

    def test_active_since_is_int(self):
        data = self._run(_SHOW_ACTIVE)
        self.assertIsInstance(data['active_since'], int)


# ── Task 1.2 — list drops state_map, emits raw is-active strings ─────────────

class TestListJson(unittest.TestCase):

    def _manager(self, user_exists=False, image_id=''):
        m = wctl.WorkloadManager()
        m.user_exists = MagicMock(return_value=user_exists)
        m.get_image_id = MagicMock(return_value=image_id)
        return m

    def test_disabled_workload_state_is_null(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            args = _args(json=True)
            with patch('subprocess.run', return_value=_ok('inactive\n')):
                data = _capture_json(lambda: wctl.cmd_list(args, self._manager()))
        self.assertIsNone(data['workloads'][0]['state'])

    def test_enabled_workload_state_is_raw_string(self):
        with _WorkloadDir(ENABLED_TOML, 'test-wl'):
            args = _args(json=True)
            with patch('subprocess.run', return_value=_ok('inactive\n')):
                data = _capture_json(lambda: wctl.cmd_list(args, self._manager(user_exists=True)))
        self.assertEqual(data['workloads'][0]['state'], 'inactive')

    def test_activating_not_remapped(self):
        with _WorkloadDir(ENABLED_TOML, 'test-wl'):
            args = _args(json=True)
            with patch('subprocess.run', return_value=_ok('activating\n')):
                data = _capture_json(lambda: wctl.cmd_list(args, self._manager(user_exists=True)))
        wl = data['workloads'][0]
        self.assertEqual(wl['state'], 'activating')
        self.assertNotEqual(wl['state'], 'starting')

    def test_failed_not_remapped(self):
        with _WorkloadDir(ENABLED_TOML, 'test-wl'):
            args = _args(json=True)
            with patch('subprocess.run', return_value=_ok('failed\n', returncode=3)):
                data = _capture_json(lambda: wctl.cmd_list(args, self._manager(user_exists=True)))
        self.assertEqual(data['workloads'][0]['state'], 'failed')

    def test_workload_shape(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            args = _args(json=True)
            with patch('subprocess.run', return_value=_ok('inactive\n')):
                data = _capture_json(lambda: wctl.cmd_list(args, self._manager()))
        self.assertIn('workloads', data)
        wl = data['workloads'][0]
        for key in ('filename', 'name', 'enabled', 'state', 'image', 'image_id', 'ports'):
            self.assertIn(key, wl, f'missing key: {key}')


# ── Task 1.3 — info stable schema ────────────────────────────────────────────

class TestInfoJson(unittest.TestCase):

    def _manager(self, user_exists=False):
        m = wctl.WorkloadManager()
        m.user_exists = MagicMock(return_value=user_exists)
        m.get_image_id = MagicMock(return_value='sha256:abcdef' if user_exists else '')
        return m

    def _run(self, user_exists=False, show_out=None):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            args = _args(workload='test-wl', json=True)
            if show_out is None:
                show_out = "ActiveState=inactive\nActiveEnterTimestamp=\n"

            def fake_run(cmd, **kw):
                if 'show' in cmd:
                    return _ok(stdout=show_out)
                return _ok()

            with patch('subprocess.run', side_effect=fake_run):
                return _capture_json(lambda: wctl.cmd_info(args, self._manager(user_exists)))

    def test_all_top_level_sections_present(self):
        data = self._run()
        for section in ('workload', 'container', 'user', 'network', 'storage', 'service'):
            self.assertIn(section, data, f'missing section: {section}')

    def test_user_section_nulls_when_no_user(self):
        data = self._run(user_exists=False)
        self.assertFalse(data['user']['exists'])
        self.assertIsNone(data['user']['uid'])
        self.assertIsNone(data['user']['home'])
        self.assertIsNone(data['user']['groups'])

    def test_storage_section_nulls_when_no_user(self):
        data = self._run(user_exists=False)
        self.assertIsNone(data['storage']['home'])
        self.assertIsNone(data['storage']['exists'])

    def test_active_since_null_when_not_running(self):
        data = self._run()
        self.assertIsNone(data['service']['active_since'])

    def test_active_since_unix_int_when_running(self):
        show = "ActiveState=active\nActiveEnterTimestamp=@1746230400\n"
        data = self._run(show_out=show)
        self.assertEqual(data['service']['active_since'], 1746230400)
        self.assertIsInstance(data['service']['active_since'], int)

    def test_service_section_always_present(self):
        data = self._run()
        svc = data['service']
        for key in ('name', 'state', 'active_since'):
            self.assertIn(key, svc, f'service section missing key: {key}')


# ── Task 1.4 — ports accessible_at always dicts ──────────────────────────────

class TestPortsJson(unittest.TestCase):

    def test_bridge_entry_is_dict_with_host_and_container(self):
        with _WorkloadDir(ENABLED_TOML, 'test-wl'):
            args = _args(workload='test-wl', json=True)
            data = _capture_json(lambda: wctl.cmd_ports(args, wctl.WorkloadManager()))
        entry = data['accessible_at'][0]
        self.assertIsInstance(entry, dict)
        self.assertEqual(entry['host'], 'localhost:8080')
        self.assertEqual(entry['container'], '80')

    def test_bridge_entry_not_a_string(self):
        with _WorkloadDir(ENABLED_TOML, 'test-wl'):
            args = _args(workload='test-wl', json=True)
            data = _capture_json(lambda: wctl.cmd_ports(args, wctl.WorkloadManager()))
        for entry in data['accessible_at']:
            self.assertNotIsInstance(entry, str)

    def test_host_network_container_field_is_null(self):
        with _WorkloadDir(HOST_NET_TOML, 'test-wl'):
            args = _args(workload='test-wl', json=True)
            with patch('subprocess.run', return_value=_ok(stdout='192.168.1.1\n')):
                data = _capture_json(lambda: wctl.cmd_ports(args, wctl.WorkloadManager()))
        for entry in data['accessible_at']:
            self.assertIn('container', entry)
            self.assertIsNone(entry['container'])

    def test_no_ports_gives_empty_accessible_at(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            args = _args(workload='test-wl', json=True)
            data = _capture_json(lambda: wctl.cmd_ports(args, wctl.WorkloadManager()))
        self.assertEqual(data['accessible_at'], [])

    def test_host_network_includes_ip_variants(self):
        with _WorkloadDir(HOST_NET_TOML, 'test-wl'):
            args = _args(workload='test-wl', json=True)
            with patch('subprocess.run', return_value=_ok(stdout='10.0.0.1 192.168.1.1\n')):
                data = _capture_json(lambda: wctl.cmd_ports(args, wctl.WorkloadManager()))
        hosts = [e['host'] for e in data['accessible_at']]
        self.assertIn('localhost:8080', hosts)
        self.assertIn('10.0.0.1:8080', hosts)
        self.assertIn('192.168.1.1:8080', hosts)


# ── Task 1.5 — images list raw values ────────────────────────────────────────

class TestImagesListJson(unittest.TestCase):

    def _manager_with_image(self, info):
        m = wctl.WorkloadManager()
        m.user_exists = MagicMock(return_value=True)
        mock_podman = MagicMock()
        mock_podman.image_info.return_value = info
        m.podman = MagicMock(return_value=mock_podman)
        return m

    def test_size_bytes_is_int(self):
        with _WorkloadDir(ENABLED_TOML, 'test-wl'):
            args = _args(subcommand='list', json=True)
            manager = self._manager_with_image({'Size': 129499136, 'Created': None})
            data = _capture_json(lambda: wctl.cmd_images(args, manager))
        self.assertIsInstance(data['images'][0]['size_bytes'], int)
        self.assertEqual(data['images'][0]['size_bytes'], 129499136)

    def test_created_is_int_from_iso_string(self):
        with _WorkloadDir(ENABLED_TOML, 'test-wl'):
            args = _args(subcommand='list', json=True)
            manager = self._manager_with_image({'Size': 1000, 'Created': '2024-11-15T10:30:00Z'})
            data = _capture_json(lambda: wctl.cmd_images(args, manager))
        self.assertIsInstance(data['images'][0]['created'], int)

    def test_created_null_when_none(self):
        with _WorkloadDir(ENABLED_TOML, 'test-wl'):
            args = _args(subcommand='list', json=True)
            manager = self._manager_with_image({'Size': 1000, 'Created': None})
            data = _capture_json(lambda: wctl.cmd_images(args, manager))
        self.assertIsNone(data['images'][0]['created'])

    def test_no_human_strings_in_size(self):
        with _WorkloadDir(ENABLED_TOML, 'test-wl'):
            args = _args(subcommand='list', json=True)
            manager = self._manager_with_image({'Size': 99000000, 'Created': None})
            data = _capture_json(lambda: wctl.cmd_images(args, manager))
        size = data['images'][0]['size_bytes']
        self.assertNotIn('MB', str(size))
        self.assertNotIn('GB', str(size))

    def test_image_keys(self):
        with _WorkloadDir(ENABLED_TOML, 'test-wl'):
            args = _args(subcommand='list', json=True)
            manager = self._manager_with_image({'Size': 1000, 'Created': None})
            data = _capture_json(lambda: wctl.cmd_images(args, manager))
        img = data['images'][0]
        for key in ('workload', 'image', 'size_bytes', 'created'):
            self.assertIn(key, img, f'missing key: {key}')


# ── Task 1.6 — validate_single severity field ────────────────────────────────

class TestValidateSingleSeverity(unittest.TestCase):

    def _run_validate(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            config = wctl.WorkloadConfig('test-wl')
            manager = wctl.WorkloadManager()
            manager.get_image_id = MagicMock(return_value='')
            return wctl.validate_single(config, manager)

    def test_every_check_has_severity(self):
        result = self._run_validate()
        for check in result['checks']:
            self.assertIn('severity', check,
                          f"check '{check.get('check')}' missing severity field")

    def test_severity_values_are_valid(self):
        result = self._run_validate()
        valid = {'ok', 'warning', 'error'}
        for check in result['checks']:
            self.assertIn(check['severity'], valid,
                          f"check '{check.get('check')}' has invalid severity '{check.get('severity')}'")

    def test_passed_checks_have_ok_severity(self):
        result = self._run_validate()
        for check in result['checks']:
            if check['passed']:
                self.assertEqual(check['severity'], 'ok',
                                 f"passed check '{check.get('check')}' should have severity 'ok'")


# ── Task 2.1 — stats --json ───────────────────────────────────────────────────

_STATS_ROW = {
    "name": "workload-test-wl",
    "cpu_percent": "1.50%",
    "mem_usage": "100MiB / 8GiB",
    "mem_percent": "1.22%",
    "net_io": "1.0kB / 2.0kB",
    "block_io": "3.0kB / 4.0kB",
    "pids": "10",
}


class TestStatsJson(unittest.TestCase):

    def test_json_and_follow_together_errors(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            args = _args(json=True, follow=True, workload='test-wl')
            with self.assertRaises(SystemExit):
                wctl.cmd_stats(args, wctl.WorkloadManager())

    def test_single_workload_shape(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            args = _args(workload='test-wl', json=True, follow=False)
            m = wctl.WorkloadManager()
            m.user_exists = MagicMock(return_value=True)
            m.run_podman = MagicMock(return_value=_ok(stdout=json.dumps([_STATS_ROW])))
            data = _capture_json(lambda: wctl.cmd_stats(args, m))

        self.assertIn('stats', data)
        self.assertEqual(len(data['stats']), 1)
        row = data['stats'][0]
        self.assertEqual(row['workload'], 'test-wl')
        self.assertIsInstance(row['cpu_percent'], float)
        self.assertAlmostEqual(row['cpu_percent'], 1.5)

    def test_numeric_types(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            args = _args(workload='test-wl', json=True, follow=False)
            m = wctl.WorkloadManager()
            m.user_exists = MagicMock(return_value=True)
            m.run_podman = MagicMock(return_value=_ok(stdout=json.dumps([_STATS_ROW])))
            data = _capture_json(lambda: wctl.cmd_stats(args, m))

        row = data['stats'][0]
        self.assertIsInstance(row['mem_usage'], int)
        self.assertIsInstance(row['mem_limit'], int)
        self.assertIsInstance(row['net_input'], int)
        self.assertIsInstance(row['net_output'], int)
        self.assertIsInstance(row['block_input'], int)
        self.assertIsInstance(row['block_output'], int)
        self.assertIsInstance(row['pids'], int)
        self.assertEqual(row['pids'], 10)

    def test_stat_keys(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            args = _args(workload='test-wl', json=True, follow=False)
            m = wctl.WorkloadManager()
            m.user_exists = MagicMock(return_value=True)
            m.run_podman = MagicMock(return_value=_ok(stdout=json.dumps([_STATS_ROW])))
            data = _capture_json(lambda: wctl.cmd_stats(args, m))

        row = data['stats'][0]
        for key in ('workload', 'username', 'container', 'cpu_percent', 'mem_usage',
                    'mem_limit', 'mem_percent', 'net_input', 'net_output',
                    'block_input', 'block_output', 'pids'):
            self.assertIn(key, row, f'missing stat key: {key}')

    def test_empty_stats_when_container_not_running(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            args = _args(workload='test-wl', json=True, follow=False)
            m = wctl.WorkloadManager()
            m.user_exists = MagicMock(return_value=True)
            m.run_podman = MagicMock(return_value=_ok(stdout=''))
            data = _capture_json(lambda: wctl.cmd_stats(args, m))
        self.assertEqual(data['stats'], [])


# ── Task 2.2 — secret list --json ────────────────────────────────────────────

class TestSecretListJson(unittest.TestCase):

    def _path_redirect(self, real_dir):
        real_Path = wctl.Path

        def fake_path(*args, **kwargs):
            result = real_Path(*args, **kwargs)
            if result == real_Path('/etc/credstore.encrypted'):
                return real_Path(real_dir)
            return result

        return MagicMock(side_effect=fake_path)

    def test_empty_dir_returns_empty_credentials(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            args = _args(subcommand='list', json=True)
            with patch.object(wctl, 'Path', self._path_redirect(tmpdir)):
                data = _capture_json(lambda: wctl.cmd_secret(args, wctl.WorkloadManager()))
        self.assertEqual(data, {'credentials': []})

    def test_credentials_shape(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / 'api-key').write_bytes(b'x' * 42)
            (Path(tmpdir) / 'db-pass').write_bytes(b'y' * 20)
            args = _args(subcommand='list', json=True)
            with patch.object(wctl, 'Path', self._path_redirect(tmpdir)):
                data = _capture_json(lambda: wctl.cmd_secret(args, wctl.WorkloadManager()))

        self.assertEqual(len(data['credentials']), 2)
        names = {c['name'] for c in data['credentials']}
        self.assertEqual(names, {'api-key', 'db-pass'})
        for cred in data['credentials']:
            self.assertIsInstance(cred['size'], int)
            self.assertIsInstance(cred['modified'], int)
            self.assertGreater(cred['size'], 0)

    def test_nonexistent_cred_dir_gives_empty(self):
        real_Path = wctl.Path

        def redirect_missing(*args, **kwargs):
            result = real_Path(*args, **kwargs)
            if result == real_Path('/etc/credstore.encrypted'):
                return real_Path('/nonexistent/credstore-test-12345')
            return result

        args = _args(subcommand='list', json=True)
        with patch.object(wctl, 'Path', MagicMock(side_effect=redirect_missing)):
            data = _capture_json(lambda: wctl.cmd_secret(args, wctl.WorkloadManager()))
        self.assertEqual(data, {'credentials': []})

    def test_credential_sizes_match_file_content(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / 'mykey').write_bytes(b'a' * 100)
            args = _args(subcommand='list', json=True)
            with patch.object(wctl, 'Path', self._path_redirect(tmpdir)):
                data = _capture_json(lambda: wctl.cmd_secret(args, wctl.WorkloadManager()))
        self.assertEqual(data['credentials'][0]['size'], 100)


# ── Task 2.3 — uid-map --json ────────────────────────────────────────────────

class TestUidMapJson(unittest.TestCase):

    def _fake_open(self, username, subuid_start=100000, subuid_count=65536):
        import builtins
        real_open = builtins.open

        def fake(path, *args, **kwargs):
            if str(path) == '/etc/subuid':
                return io.StringIO(f'{username}:{subuid_start}:{subuid_count}\n')
            if str(path) == '/etc/subgid':
                return io.StringIO(f'{username}:{subuid_start}:{subuid_count}\n')
            return real_open(path, *args, **kwargs)

        return fake

    def _mock_pw(self, uid=20001, gid=20001):
        pw = MagicMock()
        pw.pw_uid = uid
        pw.pw_gid = gid
        return pw

    def test_shape(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            args = _args(workload='test-wl', json=True)
            m = wctl.WorkloadManager()
            m.user_exists = MagicMock(return_value=True)
            with patch('pwd.getpwnam', return_value=self._mock_pw()):
                with patch('builtins.open', side_effect=self._fake_open('_wl-test-wl')):
                    data = _capture_json(lambda: wctl.cmd_uid_map(args, m))

        for key in ('workload', 'username', 'host_uid', 'host_gid',
                    'subuid', 'subgid', 'userns_mode', 'mapped_uid', 'mapped_gid'):
            self.assertIn(key, data, f'missing key: {key}')

    def test_default_keep_id_mapped_uid_equals_host_uid(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            args = _args(workload='test-wl', json=True)
            m = wctl.WorkloadManager()
            m.user_exists = MagicMock(return_value=True)
            with patch('pwd.getpwnam', return_value=self._mock_pw(uid=20001, gid=20001)):
                with patch('builtins.open', side_effect=self._fake_open('_wl-test-wl')):
                    data = _capture_json(lambda: wctl.cmd_uid_map(args, m))

        self.assertEqual(data['host_uid'], 20001)
        self.assertEqual(data['mapped_uid'], 20001)
        self.assertEqual(data['subuid'], {'start': 100000, 'count': 65536})

    def test_keep_id_with_uid_gid_override(self):
        toml = """\
[workload]
name = "test-wl"
enabled = false

[container]
image = "example.com/test:latest"

[security]
userns = "keep-id:uid=999,gid=888"
"""
        with _WorkloadDir(toml, 'test-wl'):
            args = _args(workload='test-wl', json=True)
            m = wctl.WorkloadManager()
            m.user_exists = MagicMock(return_value=True)
            with patch('pwd.getpwnam', return_value=self._mock_pw()):
                with patch('builtins.open', side_effect=self._fake_open('_wl-test-wl')):
                    data = _capture_json(lambda: wctl.cmd_uid_map(args, m))

        self.assertEqual(data['mapped_uid'], 999)
        self.assertEqual(data['mapped_gid'], 888)
        self.assertEqual(data['userns_mode'], 'keep-id:uid=999,gid=888')

    def test_subuid_null_when_not_configured(self):
        import builtins
        real_open = builtins.open

        def no_subuid(path, *args, **kwargs):
            if str(path) in ('/etc/subuid', '/etc/subgid'):
                return io.StringIO('')
            return real_open(path, *args, **kwargs)

        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            args = _args(workload='test-wl', json=True)
            m = wctl.WorkloadManager()
            m.user_exists = MagicMock(return_value=True)
            with patch('pwd.getpwnam', return_value=self._mock_pw()):
                with patch('builtins.open', side_effect=no_subuid):
                    data = _capture_json(lambda: wctl.cmd_uid_map(args, m))

        self.assertIsNone(data['subuid']['start'])
        self.assertIsNone(data['subuid']['count'])


# ── Task 2.4 — verify --json ─────────────────────────────────────────────────

class TestVerifyJson(unittest.TestCase):

    def _run_no_user(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            args = _args(workload='test-wl', json=True)
            m = wctl.WorkloadManager()
            m.user_exists = MagicMock(return_value=False)
            m.get_image_id = MagicMock(return_value='')

            def fake_run(cmd, **kw):
                if 'is-enabled' in cmd:
                    return _fail(returncode=1)
                if 'is-active' in cmd:
                    return _ok(stdout='inactive\n', returncode=3)
                return _ok()

            with patch.object(wctl, 'require_root'):
                with patch('subprocess.run', side_effect=fake_run):
                    return _capture_json_exitok(lambda: wctl.cmd_verify(args, m))

    def test_top_level_shape(self):
        data = self._run_no_user()
        for key in ('workload', 'passed', 'checks_passed', 'checks_total', 'checks'):
            self.assertIn(key, data, f'missing key: {key}')

    def test_workload_name_correct(self):
        data = self._run_no_user()
        self.assertEqual(data['workload'], 'test-wl')

    def test_passed_is_bool(self):
        data = self._run_no_user()
        self.assertIsInstance(data['passed'], bool)

    def test_failed_when_user_missing(self):
        data = self._run_no_user()
        self.assertFalse(data['passed'])

    def test_checks_passed_plus_failed_equals_total(self):
        data = self._run_no_user()
        passed = sum(1 for c in data['checks'] if c['passed'])
        self.assertEqual(data['checks_passed'], passed)
        self.assertEqual(data['checks_total'], len(data['checks']))

    def test_each_check_has_required_fields(self):
        data = self._run_no_user()
        for check in data['checks']:
            self.assertIn('check', check)
            self.assertIn('passed', check)
            self.assertIn('message', check)

    def test_user_exists_check_failed(self):
        data = self._run_no_user()
        user_check = next((c for c in data['checks'] if c['check'] == 'user_exists'), None)
        self.assertIsNotNone(user_check)
        self.assertFalse(user_check['passed'])


# ── Task 2.5 — cleanup --json ────────────────────────────────────────────────

class TestCleanupJson(unittest.TestCase):

    def _configured_pw(self):
        pw = MagicMock()
        pw.pw_name = '_wl-test-wl'
        pw.pw_uid = 20001
        return pw

    def _orphan_pw(self):
        pw = MagicMock()
        pw.pw_name = '_wl-orphan'
        pw.pw_uid = 20002
        return pw

    def test_schema_keys_always_present(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl') as tmp:
            args = _args(json=True, apply=False)
            with patch.object(wctl, 'require_root'):
                with patch('pwd.getpwall', return_value=[]):
                    with patch.object(wctl, 'WORKLOADS_BASE', Path(tmp) / 'none'):
                        data = _capture_json(lambda: wctl.cmd_cleanup(args, wctl.WorkloadManager()))
        for key in ('dry_run', 'orphan_users', 'orphan_dirs', 'orphan_modules',
                    'removed_users', 'removed_dirs', 'removed_modules'):
            self.assertIn(key, data, f'missing key: {key}')

    def test_dry_run_flag_is_true(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl') as tmp:
            args = _args(json=True, apply=False)
            with patch.object(wctl, 'require_root'):
                with patch('pwd.getpwall', return_value=[]):
                    with patch.object(wctl, 'WORKLOADS_BASE', Path(tmp) / 'none'):
                        data = _capture_json(lambda: wctl.cmd_cleanup(args, wctl.WorkloadManager()))
        self.assertTrue(data['dry_run'])

    def test_configured_user_not_reported_as_orphan(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl') as tmp:
            args = _args(json=True, apply=False)
            with patch.object(wctl, 'require_root'):
                with patch('pwd.getpwall', return_value=[self._configured_pw()]):
                    with patch.object(wctl, 'WORKLOADS_BASE', Path(tmp) / 'none'):
                        data = _capture_json(lambda: wctl.cmd_cleanup(args, wctl.WorkloadManager()))
        self.assertEqual(data['orphan_users'], [])

    def test_orphan_user_reported(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl') as tmp:
            args = _args(json=True, apply=False)
            with patch.object(wctl, 'require_root'):
                with patch('pwd.getpwall',
                           return_value=[self._configured_pw(), self._orphan_pw()]):
                    with patch.object(wctl, 'WORKLOADS_BASE', Path(tmp) / 'none'):
                        data = _capture_json(lambda: wctl.cmd_cleanup(args, wctl.WorkloadManager()))
        self.assertIn('_wl-orphan', data['orphan_users'])

    def test_dry_run_removed_lists_are_empty(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl') as tmp:
            args = _args(json=True, apply=False)
            with patch.object(wctl, 'require_root'):
                with patch('pwd.getpwall', return_value=[self._orphan_pw()]):
                    with patch.object(wctl, 'WORKLOADS_BASE', Path(tmp) / 'none'):
                        data = _capture_json(lambda: wctl.cmd_cleanup(args, wctl.WorkloadManager()))
        self.assertEqual(data['removed_users'], [])
        self.assertEqual(data['removed_dirs'], [])

    @staticmethod
    def _semodule_l(modules):
        """side_effect for subprocess.run that fakes `semodule -l`."""
        def _run(cmd, *a, **k):
            if cmd[:2] == ['semodule', '-l']:
                return CompletedProcess(cmd, 0, stdout='\n'.join(modules) + '\n', stderr='')
            return CompletedProcess(cmd, 0, stdout='', stderr='')
        return _run

    def test_orphan_module_reported(self):
        # test-wl does not declare selinux_policy, so a loaded wl_orphan module
        # (and even wl_test_wl) has nothing backing it. Base/seatd modules are
        # ignored (no wl_ prefix).
        with _WorkloadDir(MINIMAL_TOML, 'test-wl') as tmp:
            args = _args(json=True, apply=False)
            with patch.object(wctl, 'require_root'), \
                 patch('pwd.getpwall', return_value=[]), \
                 patch('shutil.which', return_value='/usr/sbin/semodule'), \
                 patch('subprocess.run',
                       side_effect=self._semodule_l(['wl_orphan', 'container', 'seatd_container'])), \
                 patch.object(wctl, 'WORKLOADS_BASE', Path(tmp) / 'none'):
                data = _capture_json(lambda: wctl.cmd_cleanup(args, wctl.WorkloadManager()))
        self.assertIn('wl_orphan', data['orphan_modules'])
        self.assertNotIn('container', data['orphan_modules'])
        self.assertNotIn('seatd_container', data['orphan_modules'])

    def test_declared_module_not_orphan(self):
        toml = MINIMAL_TOML + '\n[security]\nselinux_policy = true\n'
        with _WorkloadDir(toml, 'test-wl') as tmp:
            args = _args(json=True, apply=False)
            with patch.object(wctl, 'require_root'), \
                 patch('pwd.getpwall', return_value=[]), \
                 patch('shutil.which', return_value='/usr/sbin/semodule'), \
                 patch('subprocess.run',
                       side_effect=self._semodule_l(['wl_test_wl', 'container'])), \
                 patch.object(wctl, 'WORKLOADS_BASE', Path(tmp) / 'none'):
                data = _capture_json(lambda: wctl.cmd_cleanup(args, wctl.WorkloadManager()))
        self.assertEqual(data['orphan_modules'], [])


# ── Task 2.6 — backup --json ─────────────────────────────────────────────────

class TestBackupJson(unittest.TestCase):

    def test_single_backup_shape(self):
        with tempfile.TemporaryDirectory() as out_tmp:
            with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
                args = _args(workload='test-wl', json=True, all=False,
                             output=out_tmp, no_stop=False)
                with patch.object(wctl, 'require_root'):
                    with patch.object(wctl, '_backup_one', return_value=98304):
                        data = _capture_json(
                            lambda: wctl.cmd_backup(args, wctl.WorkloadManager()))

        self.assertIn('backups', data)
        self.assertEqual(len(data['backups']), 1)
        entry = data['backups'][0]
        self.assertEqual(entry['workload'], 'test-wl')
        self.assertIn('archive', entry)
        self.assertIsInstance(entry['archive'], str)
        self.assertEqual(entry['size_bytes'], 98304)

    def test_backup_keys(self):
        with tempfile.TemporaryDirectory() as out_tmp:
            with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
                args = _args(workload='test-wl', json=True, all=False,
                             output=out_tmp, no_stop=False)
                with patch.object(wctl, 'require_root'):
                    with patch.object(wctl, '_backup_one', return_value=0):
                        data = _capture_json(
                            lambda: wctl.cmd_backup(args, wctl.WorkloadManager()))

        for key in ('workload', 'archive', 'size_bytes'):
            self.assertIn(key, data['backups'][0], f'missing key: {key}')

    def test_backup_all_produces_list(self):
        with tempfile.TemporaryDirectory() as out_tmp:
            with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
                args = _args(workload=None, json=True, all=True,
                             output=out_tmp, no_stop=False)
                with patch.object(wctl, 'require_root'):
                    with patch.object(wctl, '_backup_one', return_value=4096):
                        data = _capture_json(
                            lambda: wctl.cmd_backup(args, wctl.WorkloadManager()))

        self.assertIsInstance(data['backups'], list)
        self.assertGreater(len(data['backups']), 0)

    def test_archive_path_in_output_dir(self):
        with tempfile.TemporaryDirectory() as out_tmp:
            with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
                args = _args(workload='test-wl', json=True, all=False,
                             output=out_tmp, no_stop=False)
                with patch.object(wctl, 'require_root'):
                    with patch.object(wctl, '_backup_one', return_value=1024):
                        data = _capture_json(
                            lambda: wctl.cmd_backup(args, wctl.WorkloadManager()))

        archive = data['backups'][0]['archive']
        self.assertTrue(archive.startswith(out_tmp))
        self.assertIn('test-wl', archive)

    def test_vm_no_stop_single_refused(self):
        # --no-stop on a VM risks a corrupt live qcow2 → hard refuse, no backup.
        with tempfile.TemporaryDirectory() as out_tmp:
            with _WorkloadDir(VM_TOML, 'test-vm'):
                args = _args(workload='test-vm', json=False, all=False,
                             output=out_tmp, no_stop=True)
                mock_backup = MagicMock(return_value=0)
                with patch.object(wctl, 'require_root'):
                    with patch.object(wctl, '_backup_one', mock_backup):
                        with patch('sys.stderr', io.StringIO()):
                            with self.assertRaises(SystemExit) as cm:
                                wctl.cmd_backup(args, wctl.WorkloadManager())
        self.assertEqual(cm.exception.code, 1)
        mock_backup.assert_not_called()

    def test_vm_no_stop_all_skips_vm_keeps_container(self):
        # --no-stop --all: skip the VM (with a skipped[] entry) but still back up containers.
        with tempfile.TemporaryDirectory() as out_tmp:
            with _WorkloadDir(MINIMAL_TOML, 'test-wl') as wdir:
                (wdir / 'test-vm.toml').write_text(VM_TOML)
                args = _args(workload=None, json=True, all=True,
                             output=out_tmp, no_stop=True)
                mock_backup = MagicMock(return_value=4096)
                with patch.object(wctl, 'require_root'):
                    with patch.object(wctl, '_backup_one', mock_backup):
                        with patch('sys.stderr', io.StringIO()):
                            data = _capture_json(
                                lambda: wctl.cmd_backup(args, wctl.WorkloadManager()))

        backed_up = {b['workload'] for b in data['backups']}
        self.assertIn('test-wl', backed_up)
        self.assertNotIn('test-vm', backed_up)
        self.assertEqual(data.get('skipped'), ['test-vm'])
        self.assertEqual(mock_backup.call_count, 1)


if __name__ == '__main__':
    unittest.main()
