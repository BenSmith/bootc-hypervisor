#!/usr/bin/env python3
"""Unit tests for workloadctl JSON output — covers plan tasks 1.1 through 2.6."""

import io
from contextlib import redirect_stderr
import json
import shutil
import tempfile
import types
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

# ── imports from lib ──────────────────────────────────────────────────────────


import workload_lib
import cmd_diagnose
import cmd_validate
import cmd_backup
import cmd_cleanup
import cmd_images
import cmd_info
import cmd_inspect
import cmd_stats
import provisioning
import cmd_secret
import substrate
import substrate_container
from workloadctl_core import WorkloadConfig, WorkloadManager

# ── shared helpers ────────────────────────────────────────────────────────────

def _ok(stdout='', stderr='', returncode=0):
    return CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)

def _fail(stderr='', returncode=1):
    return CompletedProcess(args=[], returncode=returncode, stdout='', stderr=stderr)

def _args(**kwargs):
    defaults = dict(
        json=False, workload=None, follow=False, apply=False, all=False,
        output=None, consistency="cold", subcommand=None,
    )
    defaults.update(kwargs)
    return types.SimpleNamespace(**defaults)


MINIMAL_TOML = """\
[workload]
name = "test-wl"

[container]
image = "example.com/test:latest"
"""

ENABLED_TOML = """\
[workload]
name = "test-wl"

[container]
image = "example.com/test:latest"

[network]
mode = "pasta"
ports = ["8080:80"]
"""

HOST_NET_TOML = """\
[workload]
name = "test-wl"

[container]
image = "example.com/test:latest"

[network]
mode = "host"
ports = ["8080"]
"""

VM_TOML = """\
[workload]
name = "test-vm"

[vm.network]
egress = "open"

[vm]
image = "example.com/guest:latest"
"""


class _WorkloadDir:
    """Temp WORKLOAD_DIR with one TOML, WORKLOAD_DIR patched on the module."""

    def __init__(self, toml=MINIMAL_TOML, name='test-wl', enabled=False):
        self._toml = toml
        self._name = name
        self._enabled = enabled
        self._tmp = None
        self._patcher = None

    def __enter__(self):
        self._tmp = tempfile.mkdtemp()
        tmp_path = Path(self._tmp)
        (tmp_path / self._name).mkdir()
        (tmp_path / self._name / 'workload.toml').write_text(self._toml)
        if self._enabled:
            (tmp_path / self._name / '.enabled').touch()
        self._patcher = patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', tmp_path)
        self._patcher.start()
        return tmp_path

    def __exit__(self, *_):
        assert self._patcher is not None and self._tmp is not None
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
                return _capture_json(lambda: cmd_inspect.cmd_status(args, WorkloadManager()))

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
        m = WorkloadManager()
        m.user_exists = MagicMock(return_value=user_exists)  # type: ignore[method-assign]
        m.get_image_id = MagicMock(return_value=image_id)  # type: ignore[method-assign]
        return m

    def test_disabled_workload_state_is_null(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            args = _args(json=True)
            with patch('subprocess.run', return_value=_ok('inactive\n')):
                data = _capture_json(lambda: cmd_inspect.cmd_list(args, self._manager()))
        self.assertIsNone(data['workloads'][0]['state'])

    def test_enabled_workload_state_is_raw_string(self):
        with _WorkloadDir(ENABLED_TOML, 'test-wl', enabled=True):
            args = _args(json=True)
            with patch('subprocess.run', return_value=_ok('inactive\n')):
                data = _capture_json(lambda: cmd_inspect.cmd_list(args, self._manager(user_exists=True)))
        self.assertEqual(data['workloads'][0]['state'], 'inactive')

    def test_activating_not_remapped(self):
        with _WorkloadDir(ENABLED_TOML, 'test-wl', enabled=True):
            args = _args(json=True)
            with patch('subprocess.run', return_value=_ok('activating\n')):
                data = _capture_json(lambda: cmd_inspect.cmd_list(args, self._manager(user_exists=True)))
        wl = data['workloads'][0]
        self.assertEqual(wl['state'], 'activating')
        self.assertNotEqual(wl['state'], 'starting')

    def test_failed_not_remapped(self):
        with _WorkloadDir(ENABLED_TOML, 'test-wl', enabled=True):
            args = _args(json=True)
            with patch('subprocess.run', return_value=_ok('failed\n', returncode=3)):
                data = _capture_json(lambda: cmd_inspect.cmd_list(args, self._manager(user_exists=True)))
        self.assertEqual(data['workloads'][0]['state'], 'failed')

    def test_workload_shape(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            args = _args(json=True)
            with patch('subprocess.run', return_value=_ok('inactive\n')):
                data = _capture_json(lambda: cmd_inspect.cmd_list(args, self._manager()))
        self.assertIn('workloads', data)
        wl = data['workloads'][0]
        for key in ('name', 'enabled', 'state', 'image', 'image_id', 'ports'):
            self.assertIn(key, wl, f'missing key: {key}')


# ── Task 1.3 — info stable schema ────────────────────────────────────────────

class TestInfoJson(unittest.TestCase):

    def _manager(self, user_exists=False):
        m = WorkloadManager()
        m.user_exists = MagicMock(return_value=user_exists)  # type: ignore[method-assign]
        m.get_image_id = MagicMock(return_value='sha256:abcdef' if user_exists else '')  # type: ignore[method-assign]
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
                return _capture_json(lambda: cmd_info.cmd_info(args, self._manager(user_exists)))

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

    def test_user_section_has_subuid_subgid(self):
        data = self._run()
        self.assertIn('subuid', data['user'])
        self.assertIn('subgid', data['user'])
        self.assertIn('start', data['user']['subuid'])
        self.assertIn('count', data['user']['subuid'])

    def test_network_section_has_accessible_at(self):
        data = self._run()
        self.assertIn('accessible_at', data['network'])
        self.assertIsInstance(data['network']['accessible_at'], list)


# ── Task 1.4 — endpoint helper always returns dicts (ports folded into info) ──

class TestPortsJson(unittest.TestCase):
    """Tests for substrate_container._accessible_at_config(), the endpoint helper behind
    ContainerSubstrate.endpoints() / cmd_info's network section."""

    def test_bridge_entry_is_dict_with_host_and_container(self):
        with _WorkloadDir(ENABLED_TOML, 'test-wl', enabled=True):
            result = substrate_container._accessible_at_config(WorkloadConfig('test-wl'))
        self.assertEqual(len(result), 1)
        entry = result[0]
        self.assertIsInstance(entry, dict)
        self.assertEqual(entry['host'], 'localhost:8080')
        self.assertEqual(entry['container'], '80')

    def test_bridge_entry_not_a_string(self):
        with _WorkloadDir(ENABLED_TOML, 'test-wl', enabled=True):
            result = substrate_container._accessible_at_config(WorkloadConfig('test-wl'))
        for entry in result:
            self.assertNotIsInstance(entry, str)

    def test_host_network_container_field_is_null(self):
        with _WorkloadDir(HOST_NET_TOML, 'test-wl', enabled=True):
            result = substrate_container._accessible_at_config(WorkloadConfig('test-wl'))
        for entry in result:
            self.assertIn('container', entry)
            self.assertIsNone(entry['container'])

    def test_no_ports_gives_empty_accessible_at(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            result = substrate_container._accessible_at_config(WorkloadConfig('test-wl'))
        self.assertEqual(result, [])

    def test_three_part_ip_host_container(self):
        toml = """\
[workload]
name = "test-wl"

[container]
image = "example.com/test:latest"

[network]
mode = "pasta"
ports = ["127.0.0.1:4317:4317"]
"""
        with _WorkloadDir(toml, 'test-wl'):
            result = substrate_container._accessible_at_config(WorkloadConfig('test-wl'))
        entry = result[0]
        self.assertEqual(entry['host'], '127.0.0.1:4317')
        self.assertEqual(entry['container'], '4317')

    def test_host_network_localhost_entry(self):
        with _WorkloadDir(HOST_NET_TOML, 'test-wl', enabled=True):
            result = substrate_container._accessible_at_config(WorkloadConfig('test-wl'))
        hosts = [e['host'] for e in result]
        self.assertIn('localhost:8080', hosts)


# ── Task 1.5 — images list raw values ────────────────────────────────────────

class TestImagesListJson(unittest.TestCase):

    def _manager_with_image(self, info):
        m = WorkloadManager()
        m.user_exists = MagicMock(return_value=True)  # type: ignore[method-assign]
        mock_podman = MagicMock()
        mock_podman.image_info.return_value = info
        m.podman = MagicMock(return_value=mock_podman)  # type: ignore[method-assign]
        return m

    def test_size_bytes_is_int(self):
        with _WorkloadDir(ENABLED_TOML, 'test-wl', enabled=True):
            args = _args(subcommand='list', json=True)
            manager = self._manager_with_image({'Size': 129499136, 'Created': None})
            data = _capture_json(lambda: cmd_images.cmd_images(args, manager))
        self.assertIsInstance(data['images'][0]['size_bytes'], int)
        self.assertEqual(data['images'][0]['size_bytes'], 129499136)

    def test_created_is_int_from_iso_string(self):
        with _WorkloadDir(ENABLED_TOML, 'test-wl', enabled=True):
            args = _args(subcommand='list', json=True)
            manager = self._manager_with_image({'Size': 1000, 'Created': '2024-11-15T10:30:00Z'})
            data = _capture_json(lambda: cmd_images.cmd_images(args, manager))
        self.assertIsInstance(data['images'][0]['created'], int)

    def test_created_null_when_none(self):
        with _WorkloadDir(ENABLED_TOML, 'test-wl', enabled=True):
            args = _args(subcommand='list', json=True)
            manager = self._manager_with_image({'Size': 1000, 'Created': None})
            data = _capture_json(lambda: cmd_images.cmd_images(args, manager))
        self.assertIsNone(data['images'][0]['created'])

    def test_no_human_strings_in_size(self):
        with _WorkloadDir(ENABLED_TOML, 'test-wl', enabled=True):
            args = _args(subcommand='list', json=True)
            manager = self._manager_with_image({'Size': 99000000, 'Created': None})
            data = _capture_json(lambda: cmd_images.cmd_images(args, manager))
        size = data['images'][0]['size_bytes']
        self.assertNotIn('MB', str(size))
        self.assertNotIn('GB', str(size))

    def test_image_keys(self):
        with _WorkloadDir(ENABLED_TOML, 'test-wl', enabled=True):
            args = _args(subcommand='list', json=True)
            manager = self._manager_with_image({'Size': 1000, 'Created': None})
            data = _capture_json(lambda: cmd_images.cmd_images(args, manager))
        img = data['images'][0]
        for key in ('workload', 'image', 'size_bytes', 'created'):
            self.assertIn(key, img, f'missing key: {key}')


# ── Task 1.6 — validate_single severity field ────────────────────────────────

class TestValidateSingleSeverity(unittest.TestCase):

    def _run_validate(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            config = WorkloadConfig('test-wl')
            manager = WorkloadManager()
            manager.get_image_id = MagicMock(return_value='')  # type: ignore[method-assign]
            return cmd_validate.validate_single(config, manager)

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
                cmd_stats.cmd_stats(args, WorkloadManager())

    def _make_stats_manager(self, podman_stdout):
        """Return a WorkloadManager mock whose podman().run() returns podman_stdout."""
        m = MagicMock()
        m.user_exists.return_value = True
        fake_podman = MagicMock()
        fake_podman.run.return_value = _ok(stdout=podman_stdout)
        m.podman.return_value = fake_podman
        return m

    def test_single_workload_shape(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            args = _args(workload='test-wl', json=True, follow=False)
            m = self._make_stats_manager(json.dumps([_STATS_ROW]))
            data = _capture_json(lambda: cmd_stats.cmd_stats(args, m))

        self.assertIn('stats', data)
        self.assertEqual(len(data['stats']), 1)
        row = data['stats'][0]
        self.assertEqual(row['workload'], 'test-wl')
        self.assertIsInstance(row['cpu_percent'], float)
        self.assertAlmostEqual(row['cpu_percent'], 1.5)

    def test_numeric_types(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            args = _args(workload='test-wl', json=True, follow=False)
            m = self._make_stats_manager(json.dumps([_STATS_ROW]))
            data = _capture_json(lambda: cmd_stats.cmd_stats(args, m))

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
            m = self._make_stats_manager(json.dumps([_STATS_ROW]))
            data = _capture_json(lambda: cmd_stats.cmd_stats(args, m))

        row = data['stats'][0]
        for key in ('workload', 'username', 'container', 'cpu_percent', 'mem_usage',
                    'mem_limit', 'mem_percent', 'net_input', 'net_output',
                    'block_input', 'block_output', 'pids'):
            self.assertIn(key, row, f'missing stat key: {key}')

    def test_empty_stats_when_container_not_running(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            args = _args(workload='test-wl', json=True, follow=False)
            m = self._make_stats_manager('')
            data = _capture_json(lambda: cmd_stats.cmd_stats(args, m))
        self.assertEqual(data['stats'], [])


# ── Task 2.2 — secret list --json ────────────────────────────────────────────

class TestSecretListJson(unittest.TestCase):

    def _path_redirect(self, real_dir):
        real_Path = cmd_secret.Path

        def fake_path(*args, **kwargs):
            result = real_Path(*args, **kwargs)
            if result == real_Path('/etc/credstore.encrypted'):
                return real_Path(real_dir)
            return result

        return MagicMock(side_effect=fake_path)

    def test_empty_dir_returns_empty_credentials(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            args = _args(subcommand='list', json=True)
            with patch.object(cmd_secret, 'Path', self._path_redirect(tmpdir)):
                data = _capture_json(lambda: cmd_secret.cmd_secret(args, WorkloadManager()))
        self.assertEqual(data, {'credentials': []})

    def test_credentials_shape(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / 'api-key').write_bytes(b'x' * 42)
            (Path(tmpdir) / 'db-pass').write_bytes(b'y' * 20)
            args = _args(subcommand='list', json=True)
            with patch.object(cmd_secret, 'Path', self._path_redirect(tmpdir)):
                data = _capture_json(lambda: cmd_secret.cmd_secret(args, WorkloadManager()))

        self.assertEqual(len(data['credentials']), 2)
        names = {c['name'] for c in data['credentials']}
        self.assertEqual(names, {'api-key', 'db-pass'})
        for cred in data['credentials']:
            self.assertIsInstance(cred['size'], int)
            self.assertIsInstance(cred['modified'], int)
            self.assertGreater(cred['size'], 0)

    def test_nonexistent_cred_dir_gives_empty(self):
        real_Path = cmd_secret.Path

        def redirect_missing(*args, **kwargs):
            result = real_Path(*args, **kwargs)
            if result == real_Path('/etc/credstore.encrypted'):
                return real_Path('/nonexistent/credstore-test-12345')
            return result

        args = _args(subcommand='list', json=True)
        with patch.object(cmd_secret, 'Path', MagicMock(side_effect=redirect_missing)):
            data = _capture_json(lambda: cmd_secret.cmd_secret(args, WorkloadManager()))
        self.assertEqual(data, {'credentials': []})

    def test_credential_sizes_match_file_content(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / 'mykey').write_bytes(b'a' * 100)
            args = _args(subcommand='list', json=True)
            with patch.object(cmd_secret, 'Path', self._path_redirect(tmpdir)):
                data = _capture_json(lambda: cmd_secret.cmd_secret(args, WorkloadManager()))
        self.assertEqual(data['credentials'][0]['size'], 100)


# ── Task 2.3 — _read_subid (uid/subid data folded into info) ─────────────────

class TestReadSubid(unittest.TestCase):
    """Tests for _read_subid(), the subuid/subgid file parser used by cmd_info."""

    def _fake_open(self, username, start=100000, count=65536):
        import builtins
        real_open = builtins.open

        def fake(path, *args, **kwargs):
            if str(path) == '/etc/subuid':
                return io.StringIO(f'{username}:{start}:{count}\n')
            if str(path) == '/etc/subgid':
                return io.StringIO(f'{username}:{start}:{count}\n')
            return real_open(path, *args, **kwargs)

        return fake

    def test_returns_start_and_count(self):
        with patch('builtins.open', side_effect=self._fake_open('_wl-test-wl', 100000, 65536)):
            start, count = cmd_info._read_subid('_wl-test-wl', '/etc/subuid')
        self.assertEqual(start, 100000)
        self.assertEqual(count, 65536)

    def test_returns_none_none_when_no_entry(self):
        import builtins
        real_open = builtins.open

        def no_entry(path, *args, **kwargs):
            if str(path) in ('/etc/subuid', '/etc/subgid'):
                return io.StringIO('')
            return real_open(path, *args, **kwargs)

        with patch('builtins.open', side_effect=no_entry):
            start, count = cmd_info._read_subid('_wl-test-wl', '/etc/subuid')
        self.assertIsNone(start)
        self.assertIsNone(count)

    def test_returns_none_none_when_file_missing(self):
        with patch('builtins.open', side_effect=FileNotFoundError):
            start, count = cmd_info._read_subid('_wl-test-wl', '/etc/subuid')
        self.assertIsNone(start)
        self.assertIsNone(count)

    def test_ignores_other_users(self):
        import builtins
        real_open = builtins.open

        def other_user(path, *args, **kwargs):
            if str(path) == '/etc/subuid':
                return io.StringIO('other-user:200000:65536\n')
            return real_open(path, *args, **kwargs)

        with patch('builtins.open', side_effect=other_user):
            start, count = cmd_info._read_subid('_wl-test-wl', '/etc/subuid')
        self.assertIsNone(start)


# ── Task 2.4 — diagnose --json ───────────────────────────────────────────────

class TestDiagnoseJson(unittest.TestCase):

    def _run_no_user(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            args = _args(workload='test-wl', json=True)
            m = WorkloadManager()
            m.user_exists = MagicMock(return_value=False)  # type: ignore[method-assign]
            m.get_image_id = MagicMock(return_value='')  # type: ignore[method-assign]

            def fake_run(cmd, **kw):
                if 'is-enabled' in cmd:
                    return _fail(returncode=1)
                if 'is-active' in cmd:
                    return _ok(stdout='inactive\n', returncode=3)
                return _ok()

            with patch.object(cmd_diagnose, 'require_root'):
                with patch('subprocess.run', side_effect=fake_run):
                    return _capture_json_exitok(lambda: cmd_diagnose.cmd_diagnose(args, m))

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
        assert user_check is not None
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
            with patch.object(cmd_cleanup, 'require_root'):
                with patch('pwd.getpwall', return_value=[]):
                    with patch.object(cmd_cleanup, 'WORKLOADS_BASE', Path(tmp) / 'none'):
                        data = _capture_json(lambda: cmd_cleanup.cmd_cleanup(args, WorkloadManager()))
        for key in ('dry_run', 'orphan_users', 'orphan_dirs', 'orphan_modules',
                    'skipped_other_deployment',
                    'removed_users', 'removed_dirs', 'removed_modules'):
            self.assertIn(key, data, f'missing key: {key}')

    def test_dry_run_flag_is_true(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl') as tmp:
            args = _args(json=True, apply=False)
            with patch.object(cmd_cleanup, 'require_root'):
                with patch('pwd.getpwall', return_value=[]):
                    with patch.object(cmd_cleanup, 'WORKLOADS_BASE', Path(tmp) / 'none'):
                        data = _capture_json(lambda: cmd_cleanup.cmd_cleanup(args, WorkloadManager()))
        self.assertTrue(data['dry_run'])

    def test_configured_user_not_reported_as_orphan(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl') as tmp:
            args = _args(json=True, apply=False)
            with patch.object(cmd_cleanup, 'require_root'):
                with patch('pwd.getpwall', return_value=[self._configured_pw()]):
                    with patch.object(cmd_cleanup, 'WORKLOADS_BASE', Path(tmp) / 'none'):
                        data = _capture_json(lambda: cmd_cleanup.cmd_cleanup(args, WorkloadManager()))
        self.assertEqual(data['orphan_users'], [])

    def test_orphan_user_reported(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl') as tmp:
            args = _args(json=True, apply=False)
            with patch.object(cmd_cleanup, 'require_root'):
                with patch('pwd.getpwall',
                           return_value=[self._configured_pw(), self._orphan_pw()]):
                    with patch.object(cmd_cleanup, 'WORKLOADS_BASE', Path(tmp) / 'none'):
                        data = _capture_json(lambda: cmd_cleanup.cmd_cleanup(args, WorkloadManager()))
        self.assertIn('_wl-orphan', data['orphan_users'])

    def test_dry_run_removed_lists_are_empty(self):
        with _WorkloadDir(MINIMAL_TOML, 'test-wl') as tmp:
            args = _args(json=True, apply=False)
            with patch.object(cmd_cleanup, 'require_root'):
                with patch('pwd.getpwall', return_value=[self._orphan_pw()]):
                    with patch.object(cmd_cleanup, 'WORKLOADS_BASE', Path(tmp) / 'none'):
                        data = _capture_json(lambda: cmd_cleanup.cmd_cleanup(args, WorkloadManager()))
        self.assertEqual(data['removed_users'], [])
        self.assertEqual(data['removed_dirs'], [])

    def test_backup_dir_not_reported_as_orphan_dir(self):
        # B2: the shared backup output dir under WORKLOADS_BASE has no _wl-
        # user; cleanup must not flag it (and --apply must not delete it).
        with _WorkloadDir(MINIMAL_TOML, 'test-wl') as tmp:
            base = Path(tmp) / 'workloads'
            backups = base / cmd_backup.BACKUP_DIR.name
            backups.mkdir(parents=True)
            (backups / 'test-wl-20260610.tar.zst').write_text('x')
            (base / 'orphan').mkdir()
            args = _args(json=True, apply=False)
            with patch.object(cmd_cleanup, 'require_root'):
                with patch('pwd.getpwall', return_value=[]):
                    with patch.object(cmd_cleanup, 'WORKLOADS_BASE', base):
                        data = _capture_json(lambda: cmd_cleanup.cmd_cleanup(args, WorkloadManager()))
        self.assertEqual(data['orphan_dirs'], [str(base / 'orphan')])

    def test_configured_dir_without_user_not_orphan(self):
        # Regression for the 2026-07 review: a workload whose config is present
        # but whose _wl- user was never created (the documented "pre-flight
        # failed -> stage files -> re-run enable" recovery state) must NOT be
        # reported as an orphan dir, or --apply would rmtree operator-staged
        # data. test-wl is configured by _WorkloadDir; only its dir + an
        # unrelated orphan exist, no matching user.
        with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
            base = Path(tempfile.mkdtemp())
            self.addCleanup(shutil.rmtree, base, ignore_errors=True)
            (base / 'test-wl').mkdir()          # configured, user-less
            (base / 'orphan').mkdir()           # genuinely orphaned
            args = _args(json=True, apply=False)
            with patch.object(cmd_cleanup, 'require_root'):
                with patch('pwd.getpwall', return_value=[]):
                    with patch.object(cmd_cleanup, 'WORKLOADS_BASE', base):
                        data = _capture_json(lambda: cmd_cleanup.cmd_cleanup(args, WorkloadManager()))
        self.assertEqual(data['orphan_dirs'], [str(base / 'orphan')])

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
            with patch.object(cmd_cleanup, 'require_root'), \
                 patch('pwd.getpwall', return_value=[]), \
                 patch('shutil.which', return_value='/usr/sbin/semodule'), \
                 patch('subprocess.run',
                       side_effect=self._semodule_l(['wl_orphan', 'container', 'seatd_container'])), \
                 patch.object(cmd_cleanup, 'WORKLOADS_BASE', Path(tmp) / 'none'):
                data = _capture_json(lambda: cmd_cleanup.cmd_cleanup(args, WorkloadManager()))
        self.assertIn('wl_orphan', data['orphan_modules'])
        self.assertNotIn('container', data['orphan_modules'])
        self.assertNotIn('seatd_container', data['orphan_modules'])

    def test_declared_module_not_orphan(self):
        toml = MINIMAL_TOML + '\n[security]\nselinux_policy = true\n'
        with _WorkloadDir(toml, 'test-wl') as tmp:
            args = _args(json=True, apply=False)
            with patch.object(cmd_cleanup, 'require_root'), \
                 patch('pwd.getpwall', return_value=[]), \
                 patch('shutil.which', return_value='/usr/sbin/semodule'), \
                 patch('subprocess.run',
                       side_effect=self._semodule_l(['wl_test_wl', 'container'])), \
                 patch.object(cmd_cleanup, 'WORKLOADS_BASE', Path(tmp) / 'none'):
                data = _capture_json(lambda: cmd_cleanup.cmd_cleanup(args, WorkloadManager()))
        self.assertEqual(data['orphan_modules'], [])


# ── selinux_policy bool-or-string → selinux_bundle ───────────────────────────

class TestSelinuxBundleResolution(unittest.TestCase):
    """`selinux_policy` is boolean; the CIL is sourced from the resolved
    `[workload] bundle` (defaults to the workload name). `selinux_bundle`
    surfaces that source, decoupled from the (renameable) workload name."""

    def _config(self, security_block='', bundle=None):
        # config dict + name are loaded in __init__, so the object is usable
        # after the temp dir is torn down (selinux_bundle does no file I/O).
        workload = '[workload]\nname = "test-wl"\n'
        if bundle is not None:
            workload += f'bundle = "{bundle}"\n'
        toml = workload + '\n[container]\nimage = "example.com/test:latest"\n' + security_block
        with _WorkloadDir(toml, 'test-wl'):
            return WorkloadConfig('test-wl')

    def test_true_keys_off_workload_name(self):
        cfg = self._config('\n[security]\nselinux_policy = true\n')
        self.assertTrue(cfg.selinux_policy)
        self.assertEqual(cfg.selinux_bundle, 'test-wl')

    def test_bundle_field_names_source_explicitly(self):
        cfg = self._config('\n[security]\nselinux_policy = true\n', bundle='vncdesktop-sway')
        self.assertTrue(cfg.selinux_policy)
        self.assertEqual(cfg.selinux_bundle, 'vncdesktop-sway')

    def test_false_has_no_bundle(self):
        cfg = self._config('\n[security]\nselinux_policy = false\n')
        self.assertFalse(cfg.selinux_policy)
        self.assertIsNone(cfg.selinux_bundle)

    def test_absent_has_no_bundle(self):
        cfg = self._config('')
        self.assertFalse(cfg.selinux_policy)
        self.assertIsNone(cfg.selinux_bundle)

    def test_apply_rejects_path_traversal_bundle(self):
        # `bundle` goes straight into a filesystem path; a value that isn't a
        # plain workload-style name must be rejected before lookup.
        cfg = self._config('\n[security]\nselinux_policy = true\n', bundle='../etc/evil')
        self.assertEqual(cfg.selinux_bundle, '../etc/evil')
        with patch.object(provisioning, '_selinux_available', return_value=True):
            with self.assertRaises(provisioning.SelinuxPolicyError):
                provisioning.apply_selinux_policy(cfg, 'enable')

    def test_underscore_bundle_suggests_hyphenated_form(self):
        # Footgun: users copy the SELinux *type* name (underscores) into
        # `bundle`, but the bundle is a hyphenated directory name. The
        # invalid-bundle error should suggest the hyphenated form.
        cfg = self._config('\n[security]\nselinux_policy = true\n', bundle='vncdesktop_wayfire')
        err = io.StringIO()
        with patch.object(provisioning, '_selinux_available', return_value=True):
            with redirect_stderr(err):
                with self.assertRaises(provisioning.SelinuxPolicyError):
                    provisioning.apply_selinux_policy(cfg, 'enable')
        self.assertIn('vncdesktop-wayfire', err.getvalue())

    def test_missing_bundle_lists_available(self):
        # A well-formed but nonexistent bundle should list the bundles that do
        # ship a CIL, plus a close-match suggestion.
        cfg = self._config('\n[security]\nselinux_policy = true\n', bundle='vncdesktop-wayfir')
        err = io.StringIO()
        with patch.object(provisioning, '_selinux_available', return_value=True), \
                patch.object(provisioning, '_available_bundles',
                             return_value=['vncdesktop-sway', 'vncdesktop-wayfire']):
            with redirect_stderr(err):
                with self.assertRaises(provisioning.SelinuxPolicyError):
                    provisioning.apply_selinux_policy(cfg, 'enable')
        out = err.getvalue()
        self.assertIn('available bundles', out)
        self.assertIn('vncdesktop-wayfire', out)


# ── Task 2.6 — backup --json ─────────────────────────────────────────────────

class TestBackupJson(unittest.TestCase):

    def test_single_backup_shape(self):
        with tempfile.TemporaryDirectory() as out_tmp:
            with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
                args = _args(workload='test-wl', json=True, all=False,
                             output=out_tmp, consistency='cold')
                with patch.object(cmd_backup, 'require_root'):
                    with patch.object(cmd_backup, '_backup_one', return_value=98304):
                        data = _capture_json(
                            lambda: cmd_backup.cmd_backup(args, WorkloadManager()))

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
                             output=out_tmp, consistency='cold')
                with patch.object(cmd_backup, 'require_root'):
                    with patch.object(cmd_backup, '_backup_one', return_value=0):
                        data = _capture_json(
                            lambda: cmd_backup.cmd_backup(args, WorkloadManager()))

        for key in ('workload', 'archive', 'size_bytes'):
            self.assertIn(key, data['backups'][0], f'missing key: {key}')

    def test_backup_all_produces_list(self):
        with tempfile.TemporaryDirectory() as out_tmp:
            with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
                args = _args(workload=None, json=True, all=True,
                             output=out_tmp, consistency='cold')
                with patch.object(cmd_backup, 'require_root'):
                    with patch.object(cmd_backup, '_backup_one', return_value=4096):
                        data = _capture_json(
                            lambda: cmd_backup.cmd_backup(args, WorkloadManager()))

        self.assertIsInstance(data['backups'], list)
        self.assertGreater(len(data['backups']), 0)

    def test_archive_path_in_output_dir(self):
        with tempfile.TemporaryDirectory() as out_tmp:
            with _WorkloadDir(MINIMAL_TOML, 'test-wl'):
                args = _args(workload='test-wl', json=True, all=False,
                             output=out_tmp, consistency='cold')
                with patch.object(cmd_backup, 'require_root'):
                    with patch.object(cmd_backup, '_backup_one', return_value=1024):
                        data = _capture_json(
                            lambda: cmd_backup.cmd_backup(args, WorkloadManager()))

        archive = data['backups'][0]['archive']
        self.assertTrue(archive.startswith(out_tmp))
        self.assertIn('test-wl', archive)

    def test_vm_crash_consistency_accepted(self):
        # --consistency crash on a VM is now valid (QMP-paused path).
        with tempfile.TemporaryDirectory() as out_tmp:
            with _WorkloadDir(VM_TOML, 'test-vm'):
                args = _args(workload='test-vm', json=True, all=False,
                             output=out_tmp, consistency='crash')
                mock_backup = MagicMock(return_value=1024)
                with patch.object(cmd_backup, 'require_root'):
                    with patch.object(cmd_backup, '_backup_one', mock_backup):
                        _capture_json(
                            lambda: cmd_backup.cmd_backup(args, WorkloadManager()))
        mock_backup.assert_called_once()
        # Verify consistency='crash' was threaded through
        _, call_kwargs = mock_backup.call_args
        self.assertEqual(call_kwargs.get('consistency') or mock_backup.call_args[0][2], 'crash')

    def test_vm_crash_all_backs_up_both(self):
        # --consistency crash --all: both container and VM workloads are backed up.
        with tempfile.TemporaryDirectory() as out_tmp:
            with _WorkloadDir(MINIMAL_TOML, 'test-wl') as wdir:
                (wdir / 'test-vm').mkdir()
                (wdir / 'test-vm' / 'workload.toml').write_text(VM_TOML)
                args = _args(workload=None, json=True, all=True,
                             output=out_tmp, consistency='crash')
                mock_backup = MagicMock(return_value=4096)
                with patch.object(cmd_backup, 'require_root'):
                    with patch.object(cmd_backup, '_backup_one', mock_backup):
                        data = _capture_json(
                            lambda: cmd_backup.cmd_backup(args, WorkloadManager()))

        backed_up = {b['workload'] for b in data['backups']}
        self.assertIn('test-wl', backed_up)
        self.assertIn('test-vm', backed_up)
        self.assertNotIn('skipped', data)
        self.assertEqual(mock_backup.call_count, 2)

    def test_all_isolates_backup_error(self):
        # A BackupError on one workload (e.g. a VM with an unreachable QMP
        # monitor) must NOT abort the whole --all run: the others still get
        # backed up, the failure is reported under 'failed', and the command
        # exits nonzero.
        def fake_backup(config, output, consistency, quiet=False):
            if config.name == 'test-vm':
                raise substrate.BackupError("QMP unreachable for VM 'test-vm'")
            return 4096

        with tempfile.TemporaryDirectory() as out_tmp:
            with _WorkloadDir(MINIMAL_TOML, 'test-wl') as wdir:
                (wdir / 'test-vm').mkdir()
                (wdir / 'test-vm' / 'workload.toml').write_text(VM_TOML)
                args = _args(workload=None, json=True, all=True,
                             output=out_tmp, consistency='crash')
                with patch.object(cmd_backup, 'require_root'):
                    with patch.object(cmd_backup, '_backup_one', side_effect=fake_backup):
                        # cmd exits nonzero because one workload failed.
                        data = _capture_json_exitok(
                            lambda: cmd_backup.cmd_backup(args, WorkloadManager()))

        backed_up = {b['workload'] for b in data['backups']}
        self.assertEqual(backed_up, {'test-wl'})  # the good one still ran
        self.assertIn('failed', data)
        failed = {f['workload'] for f in data['failed']}
        self.assertEqual(failed, {'test-vm'})

    def test_all_output_file_rejected(self):
        # --all with --output pointing at an existing regular file must error
        # (otherwise every workload would clobber the same archive).
        with tempfile.TemporaryDirectory() as out_tmp:
            out_file = Path(out_tmp) / "single.tar.zst"
            out_file.write_text("")  # exists as a regular file, not a dir
            with _WorkloadDir(MINIMAL_TOML, 'test-wl') as wdir:
                (wdir / 'test-vm').mkdir()
                (wdir / 'test-vm' / 'workload.toml').write_text(VM_TOML)
                args = _args(workload=None, json=True, all=True,
                             output=str(out_file), consistency='cold')
                with patch.object(cmd_backup, 'require_root'):
                    with patch.object(cmd_backup, '_backup_one', return_value=4096):
                        with patch('sys.stderr', io.StringIO()):
                            with self.assertRaises(SystemExit) as cm:
                                cmd_backup.cmd_backup(args, WorkloadManager())
        self.assertNotEqual(cm.exception.code, 0)

    def test_all_output_dir_gives_distinct_archives(self):
        # --all with --output dir writes one distinct archive per workload.
        seen = []

        def fake_backup(config, output, consistency, quiet=False):
            seen.append(str(output))
            return 4096

        with tempfile.TemporaryDirectory() as out_tmp:
            with _WorkloadDir(MINIMAL_TOML, 'test-wl') as wdir:
                (wdir / 'test-vm').mkdir()
                (wdir / 'test-vm' / 'workload.toml').write_text(VM_TOML)
                args = _args(workload=None, json=True, all=True,
                             output=out_tmp, consistency='cold')
                with patch.object(cmd_backup, 'require_root'):
                    with patch.object(cmd_backup, '_backup_one', side_effect=fake_backup):
                        _capture_json(
                            lambda: cmd_backup.cmd_backup(args, WorkloadManager()))
        self.assertEqual(len(seen), 2)
        self.assertEqual(len(set(seen)), 2)  # distinct per-workload paths
        for p in seen:
            self.assertTrue(p.startswith(out_tmp))

    def test_backup_one_normalizes_copy_fault(self):
        # A cold-path copy fault (tar exits nonzero, disk full, permission) must
        # be normalized to BackupError so the --all loop can isolate it instead
        # of aborting the whole run with a traceback.
        import subprocess
        cfg = types.SimpleNamespace(name='test-wl')
        sub = MagicMock()
        sub.capture.side_effect = subprocess.CalledProcessError(2, ['tar'])
        with patch.object(cmd_backup, 'get_substrate', return_value=sub):
            with self.assertRaises(substrate.BackupError):
                cmd_backup._backup_one(cfg, Path('/tmp/x.tar.zst'), 'cold')  # type: ignore[arg-type]

    def test_backup_one_passes_through_backup_error(self):
        # An existing BackupError (e.g. QMP unreachable) is re-raised unchanged,
        # not re-wrapped.
        cfg = types.SimpleNamespace(name='test-vm')
        sub = MagicMock()
        original = substrate.BackupError("QMP unreachable for VM 'test-vm'")
        sub.capture.side_effect = original
        with patch.object(cmd_backup, 'get_substrate', return_value=sub):
            with self.assertRaises(substrate.BackupError) as cm:
                cmd_backup._backup_one(cfg, Path('/tmp/x.tar.zst'), 'crash')  # type: ignore[arg-type]
        self.assertIs(cm.exception, original)

    def test_all_nonzero_exit_on_failure(self):
        # The single-workload / --all failure path must signal nonzero exit.
        with tempfile.TemporaryDirectory() as out_tmp:
            with _WorkloadDir(VM_TOML, 'test-vm'):
                args = _args(workload='test-vm', json=True, all=False,
                             output=out_tmp, consistency='crash')
                with patch.object(cmd_backup, 'require_root'):
                    with patch.object(cmd_backup, '_backup_one',
                                      side_effect=substrate.BackupError("boom")):
                        with patch('sys.stdout', io.StringIO()):
                            with self.assertRaises(SystemExit) as cm:
                                cmd_backup.cmd_backup(args, WorkloadManager())
        self.assertNotEqual(cm.exception.code, 0)


if __name__ == '__main__':
    unittest.main()
