#!/usr/bin/env python3
"""Tests for substrate dispatch, parity fixes, and workloadctl drift."""

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
from unittest.mock import MagicMock, patch

# ── imports from lib ──────────────────────────────────────────────────────────

_LIB = os.path.join(os.path.dirname(__file__), '..', 'lib')
sys.path.insert(0, _LIB)

import workload_lib
import workloadctl_core
import substrate as _substrate_mod
from substrate import (
    ContainerSubstrate,
    VMSubstrate,
    NotApplicable,
    BackupError,
    get_substrate,
)
import cmd_backup
import cmd_drift
import cmd_inspect


# ── helpers ───────────────────────────────────────────────────────────────────

def _ok(stdout='', stderr='', returncode=0):
    return CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _args(**kwargs):
    defaults = dict(
        json=False, workload=None, follow=False,
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

VM_TOML = """\
[workload]
name = "test-vm"
enabled = false

[vm]
image = "example.com/guest:latest"
"""


class _WorkloadDir:
    def __init__(self, toml=MINIMAL_TOML, name='test-wl'):
        self._toml = toml
        self._name = name
        self._tmp = None
        self._patcher = None

    def __enter__(self):
        self._tmp = tempfile.mkdtemp()
        tmp_path = Path(self._tmp)
        (tmp_path / self._name).mkdir()
        (tmp_path / self._name / 'workload.toml').write_text(self._toml)
        self._patcher = patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', tmp_path)
        self._patcher.start()
        return tmp_path

    def __exit__(self, *_):
        self._patcher.stop()
        shutil.rmtree(self._tmp, ignore_errors=True)


# ── VMSubstrate.liveness() ───────────────────────────────────────────────────

def _make_vm_config():
    """Build a test-vm WorkloadConfig backed by a temp dir (avoids sys.modules races)."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / 'test-vm').mkdir()
        (p / 'test-vm' / 'workload.toml').write_text(VM_TOML)
        with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p):
            return workloadctl_core.WorkloadConfig('test-vm')


class TestVMLiveness(unittest.TestCase):

    def _make_config(self):
        return _make_vm_config()

    def test_vm_healthy_when_service_active(self):
        config = self._make_config()
        substrate = VMSubstrate(config, None)
        with patch('subprocess.run', return_value=_ok(stdout='active\n')):
            live = substrate.liveness()
        self.assertTrue(live['service_active'])
        self.assertTrue(live['healthy'])
        self.assertIsNone(live['container_running'])

    def test_vm_unhealthy_when_service_inactive(self):
        config = self._make_config()
        substrate = VMSubstrate(config, None)
        with patch('subprocess.run', return_value=_ok(stdout='inactive\n', returncode=3)):
            live = substrate.liveness()
        self.assertFalse(live['service_active'])
        self.assertFalse(live['healthy'])

    def test_vm_liveness_never_calls_podman(self):
        """VMSubstrate.liveness() must never reach podman."""
        config = self._make_config()
        manager = MagicMock()
        substrate = VMSubstrate(config, manager)
        with patch('subprocess.run', return_value=_ok(stdout='active\n')):
            substrate.liveness()
        manager.podman.assert_not_called()


# ── VMSubstrate.resource_usage() → NotApplicable ─────────────────────────────

class TestVMStats(unittest.TestCase):

    def _make_config(self):
        return _make_vm_config()

    def test_vm_stats_raises_not_applicable(self):
        config = self._make_config()
        substrate = VMSubstrate(config, None)
        with self.assertRaises(NotApplicable):
            substrate.resource_usage([])

    def test_cmd_stats_vm_prints_not_applicable(self):
        """cmd_stats on a VM workload prints a not-applicable message and exits 0."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test-vm').mkdir()
            (p / 'test-vm' / 'workload.toml').write_text(VM_TOML)
            args = _args(workload='test-vm', json=False, follow=False)
            manager = MagicMock()
            manager.user_exists.return_value = True
            buf_out = io.StringIO()
            buf_err = io.StringIO()
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p), \
                 patch('sys.stdout', buf_out), patch('sys.stderr', buf_err):
                with self.assertRaises(SystemExit) as cm:
                    cmd_inspect.cmd_stats(args, manager)
            self.assertEqual(cm.exception.code, 0)
            output = buf_out.getvalue() + buf_err.getvalue()
            self.assertIn('not applicable', output.lower())


# ── --consistency seam: VMSubstrate.capture() ────────────────────────────────

class TestVMBackupConsistency(unittest.TestCase):
    """Tests for the --consistency seam on VMSubstrate.capture()."""

    def _make_config(self):
        return _make_vm_config()

    def test_cold_routes_to_backup_vm(self):
        """consistency='cold' calls _backup_vm (stop-then-backup path)."""
        config = self._make_config()
        substrate = VMSubstrate(config, None)
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            with patch.object(_substrate_mod, '_backup_vm', return_value=42) as mock_bvm, \
                 patch.object(_substrate_mod, '_backup_vm_crash') as mock_crash:
                result = substrate.capture(output, consistency='cold')
        mock_bvm.assert_called_once_with(config, output, quiet=False)
        mock_crash.assert_not_called()
        self.assertEqual(result, 42)

    def test_default_consistency_is_cold(self):
        """Omitting consistency= defaults to cold (backward-compat)."""
        config = self._make_config()
        substrate = VMSubstrate(config, None)
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            with patch.object(_substrate_mod, '_backup_vm', return_value=99) as mock_bvm, \
                 patch.object(_substrate_mod, '_backup_vm_crash') as mock_crash:
                result = substrate.capture(output)
        mock_bvm.assert_called_once()
        mock_crash.assert_not_called()
        self.assertEqual(result, 99)

    def test_crash_routes_to_backup_vm_crash(self):
        """consistency='crash' calls _backup_vm_crash (QMP-paused live path)."""
        config = self._make_config()
        substrate = VMSubstrate(config, None)
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            with patch.object(_substrate_mod, '_backup_vm_crash', return_value=7) as mock_crash, \
                 patch.object(_substrate_mod, '_backup_vm') as mock_bvm:
                result = substrate.capture(output, consistency='crash')
        mock_crash.assert_called_once_with(config, output, quiet=False)
        mock_bvm.assert_not_called()
        self.assertEqual(result, 7)


# ── --consistency seam: ContainerSubstrate.capture() ─────────────────────────

class TestContainerBackupConsistency(unittest.TestCase):
    """Tests for the --consistency seam on ContainerSubstrate.capture()."""

    def _make_config(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test-wl').mkdir()
            (p / 'test-wl' / 'workload.toml').write_text(MINIMAL_TOML)
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p):
                return workloadctl_core.WorkloadConfig('test-wl')

    def test_cold_passes_no_stop_false(self):
        """consistency='cold' calls _backup_container with no_stop=False."""
        config = self._make_config()
        substrate = ContainerSubstrate(config, None)
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            with patch.object(_substrate_mod, '_backup_container', return_value=10) as mock_bc:
                result = substrate.capture(output, consistency='cold')
        mock_bc.assert_called_once_with(config, output, no_stop=False, quiet=False)
        self.assertEqual(result, 10)

    def test_crash_passes_no_stop_true(self):
        """consistency='crash' calls _backup_container with no_stop=True (live copy)."""
        config = self._make_config()
        substrate = ContainerSubstrate(config, None)
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            with patch.object(_substrate_mod, '_backup_container', return_value=20) as mock_bc:
                result = substrate.capture(output, consistency='crash')
        mock_bc.assert_called_once_with(config, output, no_stop=True, quiet=False)
        self.assertEqual(result, 20)

    def test_default_consistency_is_cold(self):
        """Omitting consistency= defaults to cold (backward-compat)."""
        config = self._make_config()
        substrate = ContainerSubstrate(config, None)
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            with patch.object(_substrate_mod, '_backup_container', return_value=5) as mock_bc:
                result = substrate.capture(output)
        mock_bc.assert_called_once_with(config, output, no_stop=False, quiet=False)
        self.assertEqual(result, 5)


# ── VM crash-consistent backup: _backup_vm_crash ─────────────────────────────

class TestBackupVMCrash(unittest.TestCase):
    """Tests for the crash-consistent VM backup via QMP pause/resume."""

    def _make_config(self):
        return _make_vm_config()

    def _make_qmp(self, stop_reply=None, cont_reply=None):
        """Build a QMPClient mock with configurable stop/cont replies."""
        qmp = MagicMock()
        stop_reply = stop_reply or {"return": {}}
        cont_reply = cont_reply or {"return": {}}
        qmp.execute.side_effect = lambda cmd, *a, **kw: {
            "stop": stop_reply,
            "cont": cont_reply,
        }[cmd]
        return qmp

    def test_inactive_vm_falls_back_to_cold(self):
        """If the VM service is not active, fall back to the cold path."""
        config = self._make_config()
        inactive = MagicMock(return_value=MagicMock(returncode=1))
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            with patch('substrate.subprocess.run', inactive), \
                 patch.object(_substrate_mod, '_backup_vm', return_value=55) as mock_cold:
                result = _substrate_mod._backup_vm_crash(config, output, quiet=True)
        mock_cold.assert_called_once_with(config, output, quiet=True)
        self.assertEqual(result, 55)

    def _patch_active_vm(self, config_name, d):
        """Return a context-manager stack that makes the VM appear active + QMP socket present."""
        import contextlib
        # Create the fake qmp.sock path so Path.exists() returns True
        sock_dir = Path(d) / config_name
        sock_dir.mkdir(parents=True, exist_ok=True)
        (sock_dir / "qmp.sock").touch()
        return patch.object(_substrate_mod, 'VM_SOCKET_DIR', Path(d))

    def test_crash_calls_qmp_stop_then_cont(self):
        """Active VM: QMP 'stop' is issued before copy, 'cont' after."""
        config = self._make_config()
        qmp_mock = self._make_qmp()

        with tempfile.TemporaryDirectory() as d:
            output = MagicMock()
            output.stat.return_value.st_size = 123
            vm_sock_patch = self._patch_active_vm(config.name, d)
            with patch('substrate.subprocess.run',
                       return_value=MagicMock(returncode=0)), \
                 vm_sock_patch, \
                 patch.object(_substrate_mod, 'QMPClient', return_value=qmp_mock), \
                 patch.object(_substrate_mod, '_backup_impl'):
                _substrate_mod._backup_vm_crash(config, output, quiet=True)

        calls = [c[0][0] for c in qmp_mock.execute.call_args_list]
        self.assertIn('stop', calls)
        self.assertIn('cont', calls)
        self.assertLess(calls.index('stop'), calls.index('cont'))

    def test_cont_called_even_if_copy_raises(self):
        """cont is issued in finally: copy failure must not leave vCPUs paused."""
        config = self._make_config()

        stop_called = []
        cont_called = []

        class FakeQMP:
            def connect(self, *a, **kw): pass
            def negotiate(self): pass
            def execute(self, cmd, *a, **kw):
                if cmd == "stop":
                    stop_called.append(True)
                elif cmd == "cont":
                    cont_called.append(True)
                return {"return": {}}
            def close(self): pass

        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            vm_sock_patch = self._patch_active_vm(config.name, d)
            with patch('substrate.subprocess.run',
                       return_value=MagicMock(returncode=0)), \
                 vm_sock_patch, \
                 patch.object(_substrate_mod, 'QMPClient', FakeQMP), \
                 patch.object(_substrate_mod, '_backup_impl',
                               side_effect=RuntimeError("copy failed")):
                with self.assertRaises(RuntimeError):
                    _substrate_mod._backup_vm_crash(config, output, quiet=True)

        self.assertTrue(stop_called, "QMP 'stop' was not called")
        self.assertTrue(cont_called, "QMP 'cont' was NOT called after copy failure — vCPUs left paused")

    def test_no_qmp_socket_raises_backup_error(self):
        """If QMP socket is absent, raise BackupError (caught per-workload in
        --all) rather than copying a live disk or aborting the whole run."""
        config = self._make_config()

        def fake_run(cmd, **kw):
            return MagicMock(returncode=0)  # service active

        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            # VM_SOCKET_DIR points to d but qmp.sock doesn't exist there
            with patch('substrate.subprocess.run', side_effect=fake_run), \
                 patch.object(_substrate_mod, 'VM_SOCKET_DIR', Path(d)):
                buf = io.StringIO()
                with patch('sys.stderr', buf):
                    with self.assertRaises(BackupError):
                        _substrate_mod._backup_vm_crash(config, output, quiet=True)
        self.assertIn('cold', buf.getvalue())  # mentions --consistency cold fallback

    def test_stop_error_raises_backup_error_without_resuming(self):
        """A failed QMP 'stop' raises BackupError and does NOT issue 'cont'
        (vCPUs were never paused, so there is nothing to resume)."""
        config = self._make_config()
        qmp_mock = self._make_qmp(stop_reply={"error": {"desc": "boom"}})

        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            vm_sock_patch = self._patch_active_vm(config.name, d)
            with patch('substrate.subprocess.run',
                       return_value=MagicMock(returncode=0)), \
                 vm_sock_patch, \
                 patch.object(_substrate_mod, 'QMPClient', return_value=qmp_mock), \
                 patch.object(_substrate_mod, '_backup_impl') as mock_impl:
                with patch('sys.stderr', io.StringIO()):
                    with self.assertRaises(BackupError):
                        _substrate_mod._backup_vm_crash(config, output, quiet=True)

        calls = [c[0][0] for c in qmp_mock.execute.call_args_list]
        self.assertIn('stop', calls)
        self.assertNotIn('cont', calls)
        mock_impl.assert_not_called()

    def test_cont_error_reply_warns_but_does_not_raise(self):
        """A QMP error *reply* to 'cont' (not an exception) must still warn that
        the VM may be left paused — the backup itself succeeds."""
        config = self._make_config()
        qmp_mock = self._make_qmp(cont_reply={"error": {"desc": "cannot resume"}})

        with tempfile.TemporaryDirectory() as d:
            output = MagicMock()
            output.stat.return_value.st_size = 123
            vm_sock_patch = self._patch_active_vm(config.name, d)
            buf = io.StringIO()
            with patch('substrate.subprocess.run',
                       return_value=MagicMock(returncode=0)), \
                 vm_sock_patch, \
                 patch.object(_substrate_mod, 'QMPClient', return_value=qmp_mock), \
                 patch.object(_substrate_mod, '_backup_impl'), \
                 patch('sys.stderr', buf):
                result = _substrate_mod._backup_vm_crash(config, output, quiet=True)

        self.assertEqual(result, 123)
        self.assertIn('may remain paused', buf.getvalue())

    def test_cont_valueerror_warns_but_does_not_escape(self):
        """A malformed (non-OSError) reply to 'cont' must warn, not abort the
        backup or escape un-isolated; the backup still succeeds."""
        config = self._make_config()
        qmp_mock = MagicMock()

        def execute(cmd, *a, **kw):
            if cmd == "cont":
                raise ValueError("bad json from monitor")
            return {"return": {}}
        qmp_mock.execute.side_effect = execute

        with tempfile.TemporaryDirectory() as d:
            output = MagicMock()
            output.stat.return_value.st_size = 77
            vm_sock_patch = self._patch_active_vm(config.name, d)
            buf = io.StringIO()
            with patch('substrate.subprocess.run',
                       return_value=MagicMock(returncode=0)), \
                 vm_sock_patch, \
                 patch.object(_substrate_mod, 'QMPClient', return_value=qmp_mock), \
                 patch.object(_substrate_mod, '_backup_impl'), \
                 patch('sys.stderr', buf):
                result = _substrate_mod._backup_vm_crash(config, output, quiet=True)

        self.assertEqual(result, 77)
        self.assertIn('may remain paused', buf.getvalue())
        qmp_mock.close.assert_called_once()

    def test_stop_oserror_raises_backup_error_without_resuming(self):
        """A protocol/socket fault on 'stop' becomes BackupError and never
        issues 'cont' (vCPUs were never paused) nor copies."""
        config = self._make_config()
        qmp_mock = MagicMock()

        def execute(cmd, *a, **kw):
            if cmd == "stop":
                raise OSError("socket reset")
            return {"return": {}}
        qmp_mock.execute.side_effect = execute

        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            vm_sock_patch = self._patch_active_vm(config.name, d)
            with patch('substrate.subprocess.run',
                       return_value=MagicMock(returncode=0)), \
                 vm_sock_patch, \
                 patch.object(_substrate_mod, 'QMPClient', return_value=qmp_mock), \
                 patch.object(_substrate_mod, '_backup_impl') as mock_impl, \
                 patch('sys.stderr', io.StringIO()):
                with self.assertRaises(BackupError):
                    _substrate_mod._backup_vm_crash(config, output, quiet=True)

        calls = [c[0][0] for c in qmp_mock.execute.call_args_list]
        self.assertIn('stop', calls)
        self.assertNotIn('cont', calls)
        mock_impl.assert_not_called()
        qmp_mock.close.assert_called_once()

    def test_negotiate_failure_closes_socket(self):
        """If negotiate() raises after connect() opened the socket, close() must
        still run (no leaked fd) and a BackupError is raised."""
        config = self._make_config()
        qmp_mock = MagicMock()
        qmp_mock.negotiate.side_effect = OSError("greeting never arrived")

        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            vm_sock_patch = self._patch_active_vm(config.name, d)
            with patch('substrate.subprocess.run',
                       return_value=MagicMock(returncode=0)), \
                 vm_sock_patch, \
                 patch.object(_substrate_mod, 'QMPClient', return_value=qmp_mock), \
                 patch.object(_substrate_mod, '_backup_impl') as mock_impl:
                with patch('sys.stderr', io.StringIO()):
                    with self.assertRaises(BackupError):
                        _substrate_mod._backup_vm_crash(config, output, quiet=True)

        qmp_mock.close.assert_called_once()  # fd released despite the failure
        # never paused, so nothing to copy or resume
        qmp_mock.execute.assert_not_called()
        mock_impl.assert_not_called()


# ── ContainerSubstrate.liveness() multi-container semantics ──────────────────

SINGLE_TOML = """\
[workload]
name = "test-wl"
enabled = true

[container]
image = "example.com/test:latest"
"""

POD_TOML = """\
[workload]
name = "test-pod"
mode = "pod"
enabled = true

[[containers]]
name = "web"
image = "example.com/web:latest"

[[containers]]
name = "db"
image = "example.com/db:latest"
"""


def _make_config(toml, name):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / name).mkdir()
        (p / name / 'workload.toml').write_text(toml)
        with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p):
            return workloadctl_core.WorkloadConfig(name)


class TestContainerLiveness(unittest.TestCase):

    def _substrate(self, toml, name, statuses):
        """Build a ContainerSubstrate whose container_status() returns from `statuses`.

        `statuses` maps container_status() argument → returned status string
        (or None for not-running).
        """
        config = _make_config(toml, name)
        manager = MagicMock()
        manager.user_exists.return_value = True
        manager.podman.return_value.container_status.side_effect = (
            lambda cname: statuses.get(cname)
        )
        return ContainerSubstrate(config, manager)

    def test_single_running_is_healthy(self):
        substrate = self._substrate(SINGLE_TOML, 'test-wl', {'workload-test-wl': 'running'})
        with patch('subprocess.run', return_value=_ok(stdout='active\n')):
            live = substrate.liveness()
        self.assertTrue(live['healthy'])
        self.assertTrue(live['container_running'])
        self.assertEqual(live['container_status'], 'running')

    def test_single_stopped_is_unhealthy(self):
        substrate = self._substrate(SINGLE_TOML, 'test-wl', {'workload-test-wl': None})
        with patch('subprocess.run', return_value=_ok(stdout='active\n')):
            live = substrate.liveness()
        self.assertFalse(live['healthy'])
        self.assertFalse(live['container_running'])

    def test_multi_all_running_is_healthy(self):
        statuses = {'workload-test-pod-web': 'running', 'workload-test-pod-db': 'running'}
        substrate = self._substrate(POD_TOML, 'test-pod', statuses)
        with patch('subprocess.run', return_value=_ok(stdout='active\n')):
            live = substrate.liveness()
        self.assertTrue(live['healthy'])
        self.assertTrue(live['container_running'])

    def test_multi_partial_down_is_unhealthy(self):
        """A pod with one container down must NOT report healthy."""
        statuses = {'workload-test-pod-web': 'running', 'workload-test-pod-db': None}
        substrate = self._substrate(POD_TOML, 'test-pod', statuses)
        with patch('subprocess.run', return_value=_ok(stdout='active\n')):
            live = substrate.liveness()
        self.assertFalse(live['healthy'])
        self.assertFalse(live['container_running'])
        # Still surfaces the running container's status for display.
        self.assertEqual(live['container_status'], 'running')

    def test_service_inactive_skips_podman(self):
        substrate = self._substrate(SINGLE_TOML, 'test-wl', {'workload-test-wl': 'running'})
        with patch('subprocess.run', return_value=_ok(stdout='inactive\n', returncode=3)):
            live = substrate.liveness()
        self.assertFalse(live['service_active'])
        self.assertFalse(live['healthy'])
        substrate.manager.podman.assert_not_called()


class TestContainerResourceUsage(unittest.TestCase):

    def _substrate(self, run_result):
        config = _make_config(SINGLE_TOML, 'test-wl')
        manager = MagicMock()
        manager.podman.return_value.run.return_value = run_result
        return ContainerSubstrate(config, manager)

    def test_json_returns_result(self):
        """json_out path returns the raw subprocess result to the caller."""
        result = _ok(stdout='[]')
        substrate = self._substrate(result)
        returned = substrate.resource_usage(['test-wl'], json_out=True)
        self.assertIs(returned, result)

    def test_stream_returns_none(self):
        """Non-json (streaming) path returns None."""
        substrate = self._substrate(_ok())
        returned = substrate.resource_usage(['test-wl'])
        self.assertIsNone(returned)


# ── cmd_drift ─────────────────────────────────────────────────────────────────

class TestCmdDrift(unittest.TestCase):

    def _write_unit(self, directory: Path, name: str, content: str):
        (directory / name).write_text(content)

    def test_no_drift_exits_zero(self):
        """When generated == live, exit 0 and print no-drift message."""
        unit_content = "[Unit]\nDescription=test\n"
        with tempfile.TemporaryDirectory() as gen_dir, \
             tempfile.TemporaryDirectory() as live_dir:
            gd = Path(gen_dir)
            ld = Path(live_dir)
            # Same content in both directories
            self._write_unit(gd, 'workload-foo.service', unit_content)
            self._write_unit(ld, 'workload-foo.service', unit_content)

            # Patch the generator to just copy our prepared gen_dir contents
            def fake_run(cmd, **kw):
                # cmd[0] is generator path, cmd[1] is output dir (already gen_dir)
                return CompletedProcess(args=cmd, returncode=0, stdout='', stderr='')

            args = _args(workload=None, json=False)
            buf = io.StringIO()
            with patch('subprocess.run', side_effect=fake_run), \
                 patch.object(cmd_drift, 'LIVE_UNITS_DIR', ld), \
                 patch('tempfile.TemporaryDirectory') as mock_td:
                # Make TemporaryDirectory return gen_dir so our pre-written units are used
                mock_td.return_value.__enter__ = lambda s: gen_dir
                mock_td.return_value.__exit__ = lambda s, *a: None
                with patch('sys.stdout', buf):
                    with self.assertRaises(SystemExit) as cm:
                        cmd_drift.cmd_drift(args, None)
            self.assertEqual(cm.exception.code, 0)

    def test_drift_detected_exits_one(self):
        """When generated != live, exit 1 and print diff."""
        live_content = "[Unit]\nDescription=old\n"
        gen_content = "[Unit]\nDescription=new\n"
        with tempfile.TemporaryDirectory() as gen_dir, \
             tempfile.TemporaryDirectory() as live_dir:
            gd = Path(gen_dir)
            ld = Path(live_dir)
            self._write_unit(gd, 'workload-foo.service', gen_content)
            self._write_unit(ld, 'workload-foo.service', live_content)

            def fake_run(cmd, **kw):
                return CompletedProcess(args=cmd, returncode=0, stdout='', stderr='')

            args = _args(workload=None, json=False)
            buf = io.StringIO()
            with patch('subprocess.run', side_effect=fake_run), \
                 patch.object(cmd_drift, 'LIVE_UNITS_DIR', ld), \
                 patch('tempfile.TemporaryDirectory') as mock_td:
                mock_td.return_value.__enter__ = lambda s: gen_dir
                mock_td.return_value.__exit__ = lambda s, *a: None
                with patch('sys.stdout', buf):
                    with self.assertRaises(SystemExit) as cm:
                        cmd_drift.cmd_drift(args, None)
            self.assertEqual(cm.exception.code, 1)
            self.assertIn('-Description=old', buf.getvalue())
            self.assertIn('+Description=new', buf.getvalue())

    def test_drift_json_output(self):
        """--json flag produces machine-readable output."""
        live_content = "[Unit]\nDescription=old\n"
        gen_content = "[Unit]\nDescription=new\n"
        with tempfile.TemporaryDirectory() as gen_dir, \
             tempfile.TemporaryDirectory() as live_dir:
            gd = Path(gen_dir)
            ld = Path(live_dir)
            self._write_unit(gd, 'workload-foo.service', gen_content)
            self._write_unit(ld, 'workload-foo.service', live_content)

            def fake_run(cmd, **kw):
                return CompletedProcess(args=cmd, returncode=0, stdout='', stderr='')

            args = _args(workload=None, json=True)
            buf = io.StringIO()
            with patch('subprocess.run', side_effect=fake_run), \
                 patch.object(cmd_drift, 'LIVE_UNITS_DIR', ld), \
                 patch('tempfile.TemporaryDirectory') as mock_td:
                mock_td.return_value.__enter__ = lambda s: gen_dir
                mock_td.return_value.__exit__ = lambda s, *a: None
                with patch('sys.stdout', buf):
                    with self.assertRaises(SystemExit) as cm:
                        cmd_drift.cmd_drift(args, None)
            self.assertEqual(cm.exception.code, 1)
            data = json.loads(buf.getvalue())
            self.assertTrue(data['drifted'])
            self.assertEqual(len(data['units']), 1)
            self.assertEqual(data['units'][0]['unit'], 'workload-foo.service')

    def test_orphan_live_unit_is_drift(self):
        """A live unit with no generated counterpart is reported as drift."""
        with tempfile.TemporaryDirectory() as gen_dir, \
             tempfile.TemporaryDirectory() as live_dir:
            ld = Path(live_dir)
            self._write_unit(ld, 'workload-orphan.service', "[Unit]\n")
            # gen_dir is empty — no unit generated

            def fake_run(cmd, **kw):
                return CompletedProcess(args=cmd, returncode=0, stdout='', stderr='')

            args = _args(workload=None, json=True)
            buf = io.StringIO()
            with patch('subprocess.run', side_effect=fake_run), \
                 patch.object(cmd_drift, 'LIVE_UNITS_DIR', ld), \
                 patch('tempfile.TemporaryDirectory') as mock_td:
                mock_td.return_value.__enter__ = lambda s: gen_dir
                mock_td.return_value.__exit__ = lambda s, *a: None
                with patch('sys.stdout', buf):
                    with self.assertRaises(SystemExit) as cm:
                        cmd_drift.cmd_drift(args, None)
            self.assertEqual(cm.exception.code, 1)
            data = json.loads(buf.getvalue())
            self.assertTrue(data['drifted'])
            self.assertEqual(data['units'][0]['unit'], 'workload-orphan.service')

    def test_drift_workload_filter(self):
        """Drift filtered to a specific workload ignores other units."""
        with tempfile.TemporaryDirectory() as gen_dir, \
             tempfile.TemporaryDirectory() as live_dir:
            gd = Path(gen_dir)
            ld = Path(live_dir)
            # Two units: one for 'foo', one for 'bar'
            foo_content = "[Unit]\nDescription=foo\n"
            bar_content_live = "[Unit]\nDescription=bar-old\n"
            bar_content_gen = "[Unit]\nDescription=bar-new\n"
            self._write_unit(gd, 'workload-foo.service', foo_content)
            self._write_unit(ld, 'workload-foo.service', foo_content)
            self._write_unit(gd, 'workload-bar.service', bar_content_gen)
            self._write_unit(ld, 'workload-bar.service', bar_content_live)

            def fake_run(cmd, **kw):
                return CompletedProcess(args=cmd, returncode=0, stdout='', stderr='')

            args = _args(workload='foo', json=True)
            buf = io.StringIO()
            with patch('subprocess.run', side_effect=fake_run), \
                 patch.object(cmd_drift, 'LIVE_UNITS_DIR', ld), \
                 patch('tempfile.TemporaryDirectory') as mock_td:
                mock_td.return_value.__enter__ = lambda s: gen_dir
                mock_td.return_value.__exit__ = lambda s, *a: None
                with patch('sys.stdout', buf):
                    with self.assertRaises(SystemExit) as cm:
                        cmd_drift.cmd_drift(args, None)
            # foo is in sync → should be exit 0 even though bar drifted
            self.assertEqual(cm.exception.code, 0)
            data = json.loads(buf.getvalue())
            self.assertFalse(data['drifted'])


# ── cmd_drift: drop-in coverage ──────────────────────────────────────────────

class TestCmdDriftDropins(unittest.TestCase):

    def _write_unit(self, directory: Path, name: str, content: str):
        p = directory / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    def _run_drift(self, gen_dir, live_dir, json_output=True):
        def fake_run(cmd, **kw):
            return CompletedProcess(args=cmd, returncode=0, stdout='', stderr='')

        args = _args(workload=None, json=json_output)
        buf = io.StringIO()
        with patch('subprocess.run', side_effect=fake_run), \
             patch.object(cmd_drift, 'LIVE_UNITS_DIR', Path(live_dir)), \
             patch('tempfile.TemporaryDirectory') as mock_td:
            mock_td.return_value.__enter__ = lambda s: gen_dir
            mock_td.return_value.__exit__ = lambda s, *a: None
            with patch('sys.stdout', buf):
                with self.assertRaises(SystemExit) as cm:
                    cmd_drift.cmd_drift(args, None)
        return cm.exception.code, buf.getvalue()

    def test_insync_dropin_exits_zero(self):
        """When generated and live drop-ins match, no drift is reported."""
        dropin_content = "[Service]\nSlice=workloads.slice\n"
        with tempfile.TemporaryDirectory() as gen_dir, \
             tempfile.TemporaryDirectory() as live_dir:
            gd = Path(gen_dir)
            ld = Path(live_dir)
            self._write_unit(gd, "user@10001.service.d/50-workload.conf", dropin_content)
            self._write_unit(ld, "user@10001.service.d/50-workload.conf", dropin_content)
            code, out = self._run_drift(gen_dir, live_dir)
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertFalse(data['drifted'])

    def test_drifted_dropin_exits_one(self):
        """When a live drop-in differs from the generated one, drift is detected."""
        gen_content = "[Service]\nSlice=workloads.slice\nMemoryMax=2G\n"
        live_content = "[Service]\nSlice=workloads.slice\n"
        with tempfile.TemporaryDirectory() as gen_dir, \
             tempfile.TemporaryDirectory() as live_dir:
            gd = Path(gen_dir)
            ld = Path(live_dir)
            self._write_unit(gd, "user@10001.service.d/50-workload.conf", gen_content)
            self._write_unit(ld, "user@10001.service.d/50-workload.conf", live_content)
            code, out = self._run_drift(gen_dir, live_dir)
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertTrue(data['drifted'])
        self.assertEqual(data['units'][0]['unit'], 'user@10001.service.d/50-workload.conf')

    def test_orphan_dropin_is_drift(self):
        """A live drop-in with no generated counterpart is orphan drift."""
        with tempfile.TemporaryDirectory() as gen_dir, \
             tempfile.TemporaryDirectory() as live_dir:
            ld = Path(live_dir)
            self._write_unit(ld, "user@10099.service.d/50-workload.conf",
                             "[Service]\nSlice=workloads.slice\n")
            # gen_dir is empty — workload was removed from TOML
            code, out = self._run_drift(gen_dir, live_dir)
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertTrue(data['drifted'])
        self.assertEqual(data['units'][0]['unit'], 'user@10099.service.d/50-workload.conf')


# ── cmd_health: user manager placement ───────────────────────────────────────

CONTAINER_TOML = """\
[workload]
name = "test-wl"
enabled = true

[container]
image = "example.com/test:latest"
"""

CONTAINER_TOML_CUSTOM_SLICE = """\
[workload]
name = "test-wl"
enabled = true

[container]
image = "example.com/test:latest"

[resources]
slice = "custom.slice"
"""


class TestCmdHealthPlacement(unittest.TestCase):
    """Verify that cmd_health detects user@<uid>.service in the wrong slice."""

    def _run_health(self, toml, fake_run, user_exists=True):
        """Run cmd_health and return (exit_code, health_data_dict)."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test-wl').mkdir()
            (p / 'test-wl' / 'workload.toml').write_text(toml)
            args = _args(workload='test-wl', json=True)
            manager = MagicMock()
            manager.user_exists.return_value = user_exists
            # container_status returns a plain string so JSON serialization works
            manager.podman.return_value.container_status.return_value = "running"
            manager.podman.return_value.container_health.return_value = None
            buf_out = io.StringIO()
            buf_err = io.StringIO()
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p), \
                 patch('subprocess.run', side_effect=fake_run), \
                 patch('sys.stdout', buf_out), patch('sys.stderr', buf_err):
                with self.assertRaises(SystemExit) as cm:
                    cmd_inspect.cmd_health(args, manager)
            output = buf_out.getvalue()
            data = json.loads(output) if output.strip() else {}
            return cm.exception.code, data

    def test_placement_ok_when_in_correct_slice(self):
        """user@<uid>.service in workloads.slice → placement check healthy."""
        call_count = [0]

        def fake_run(cmd, **kw):
            call_count[0] += 1
            cmd_str = ' '.join(str(c) for c in cmd)
            if 'is-active' in cmd_str and 'user@' in cmd_str:
                return _ok(stdout='active\n', returncode=0)
            if 'show' in cmd_str and 'user@' in cmd_str and 'Slice' in cmd_str:
                return _ok(stdout='workloads.slice\n')
            # Other checks (service_status, uptime, etc.)
            return _ok(stdout='active\n', returncode=0)

        with patch('pwd.getpwnam') as mock_pw:
            pw = MagicMock()
            pw.pw_uid = 10001
            mock_pw.return_value = pw
            code, data = self._run_health(CONTAINER_TOML, fake_run)

        placement = next(
            (c for c in data.get('checks', []) if c['check'] == 'user_manager_placement'),
            None,
        )
        self.assertIsNotNone(placement, "placement check missing from output")
        self.assertTrue(placement['healthy'])

    def test_placement_unhealthy_when_wrong_slice(self):
        """user@<uid>.service in user.slice instead of workloads.slice → unhealthy."""
        def fake_run(cmd, **kw):
            cmd_str = ' '.join(str(c) for c in cmd)
            if 'is-active' in cmd_str and 'user@' in cmd_str:
                return _ok(stdout='active\n', returncode=0)
            if 'show' in cmd_str and 'user@' in cmd_str and 'Slice' in cmd_str:
                return _ok(stdout='user.slice\n')
            return _ok(stdout='active\n', returncode=0)

        with patch('pwd.getpwnam') as mock_pw:
            pw = MagicMock()
            pw.pw_uid = 10001
            mock_pw.return_value = pw
            code, data = self._run_health(CONTAINER_TOML, fake_run)

        placement = next(
            (c for c in data.get('checks', []) if c['check'] == 'user_manager_placement'),
            None,
        )
        self.assertIsNotNone(placement)
        self.assertFalse(placement['healthy'])
        self.assertIn('user.slice', placement['message'])
        self.assertIn('workloads.slice', placement['message'])
        self.assertEqual(code, 1)

    def test_placement_skipped_when_user_manager_not_running(self):
        """user@<uid>.service not active → placement check is omitted (skip, not fail)."""
        def fake_run(cmd, **kw):
            cmd_str = ' '.join(str(c) for c in cmd)
            if 'is-active' in cmd_str and 'user@' in cmd_str:
                return _ok(stdout='inactive\n', returncode=3)
            return _ok(stdout='active\n', returncode=0)

        with patch('pwd.getpwnam') as mock_pw:
            pw = MagicMock()
            pw.pw_uid = 10001
            mock_pw.return_value = pw
            code, data = self._run_health(CONTAINER_TOML, fake_run)

        placement = next(
            (c for c in data.get('checks', []) if c['check'] == 'user_manager_placement'),
            None,
        )
        self.assertIsNone(placement, "placement check should be absent when user@ not running")

    def test_placement_uses_custom_slice(self):
        """Workload with [resources] slice = custom.slice checks against that slice."""
        def fake_run(cmd, **kw):
            cmd_str = ' '.join(str(c) for c in cmd)
            if 'is-active' in cmd_str and 'user@' in cmd_str:
                return _ok(stdout='active\n', returncode=0)
            if 'show' in cmd_str and 'user@' in cmd_str and 'Slice' in cmd_str:
                return _ok(stdout='custom.slice\n')
            return _ok(stdout='active\n', returncode=0)

        with patch('pwd.getpwnam') as mock_pw:
            pw = MagicMock()
            pw.pw_uid = 10001
            mock_pw.return_value = pw
            code, data = self._run_health(CONTAINER_TOML_CUSTOM_SLICE, fake_run)

        placement = next(
            (c for c in data.get('checks', []) if c['check'] == 'user_manager_placement'),
            None,
        )
        self.assertIsNotNone(placement)
        self.assertTrue(placement['healthy'])

    def test_placement_not_run_when_user_missing(self):
        """When user doesn't exist yet, placement check is not attempted."""
        def fake_run(cmd, **kw):
            return _ok(stdout='inactive\n', returncode=3)

        code, data = self._run_health(CONTAINER_TOML, fake_run, user_exists=False)

        placement = next(
            (c for c in data.get('checks', []) if c['check'] == 'user_manager_placement'),
            None,
        )
        self.assertIsNone(placement)


# ── Capability matrix: optional primitives auto-raise NotApplicable ──────────

class TestCapabilityMatrix(unittest.TestCase):
    """Verify that absent optional primitives auto-raise NotApplicable with a
    generated reason, not a hand-written one."""

    def _vm_config(self):
        return _make_vm_config()

    def _container_config(self):
        return _make_config(SINGLE_TOML, 'test-wl')

    # VMSubstrate: resource_usage absent → NotApplicable
    def test_vm_resource_usage_raises_not_applicable(self):
        substrate = VMSubstrate(self._vm_config(), None)
        with self.assertRaises(NotApplicable) as cm:
            substrate.resource_usage([])
        self.assertIn('resource_usage', cm.exception.reason)
        self.assertIn('VMs', cm.exception.reason)

    # VMSubstrate: logs runs the host-journal command directly (a VM's QEMU
    # service journal is on the host journal, same as a container's service).
    def test_vm_logs_invokes_subprocess(self):
        substrate = VMSubstrate(self._vm_config(), None)
        with patch('subprocess.run') as mock_run:
            substrate.logs(["journalctl", "-u", "workload-test-vm.service"])
        mock_run.assert_called_once()
        self.assertEqual(mock_run.call_args[0][0][0], "journalctl")

    # VMSubstrate: endpoints absent → NotApplicable
    def test_vm_endpoints_raises_not_applicable(self):
        substrate = VMSubstrate(self._vm_config(), None)
        with self.assertRaises(NotApplicable) as cm:
            substrate.endpoints()
        self.assertIn('endpoints', cm.exception.reason)

    # ContainerSubstrate: resource_usage present → no NotApplicable
    def test_container_resource_usage_does_not_raise(self):
        manager = MagicMock()
        manager.podman.return_value.run.return_value = _ok(stdout='[]')
        substrate = ContainerSubstrate(self._container_config(), manager)
        # Should not raise NotApplicable
        result = substrate.resource_usage(['x'], json_out=True)
        self.assertIsNotNone(result)

    # ContainerSubstrate: logs present → delegates to subprocess
    def test_container_logs_invokes_subprocess(self):
        substrate = ContainerSubstrate(self._container_config(), MagicMock())
        with patch('subprocess.run') as mock_run:
            substrate.logs(["journalctl", "-u", "test.service"])
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        self.assertEqual(call_args[0], "journalctl")

    # ContainerSubstrate: endpoints present → returns list
    def test_container_endpoints_returns_list(self):
        toml_with_ports = """\
[workload]
name = "test-ep"
enabled = true

[container]
image = "example.com/test:latest"

[network]
ports = ["8080:80"]
"""
        config = _make_config(toml_with_ports, 'test-ep')
        substrate = ContainerSubstrate(config, MagicMock())
        eps = substrate.endpoints()
        self.assertIsInstance(eps, list)
        self.assertTrue(any('8080' in ep.get('host', '') for ep in eps))

    # ContainerSubstrate: endpoints empty when no ports
    def test_container_endpoints_empty_when_no_ports(self):
        config = _make_config(SINGLE_TOML, 'test-wl')
        substrate = ContainerSubstrate(config, MagicMock())
        self.assertEqual(substrate.endpoints(), [])

    # NotApplicable reason always names the primitive
    def test_auto_reason_names_primitive(self):
        substrate = VMSubstrate(self._vm_config(), None)
        cases = [
            ('resource_usage', lambda s: s.resource_usage([])),
            ('endpoints', lambda s: s.endpoints()),
        ]
        for prim, call in cases:
            with self.assertRaises(NotApplicable) as cm:
                call(substrate)
            self.assertIn(prim, cm.exception.reason, f"reason for {prim!r} missing primitive name")


# ── rollback_targets / rollback_to ────────────────────────────────────────────

class TestContainerRollbackTargets(unittest.TestCase):

    def _substrate(self, image_ids: dict):
        """image_ids maps tag/image → id (or None for absent)."""
        config = _make_config(SINGLE_TOML, 'test-wl')
        manager = MagicMock()
        manager.podman.return_value.image_id.side_effect = lambda tag: image_ids.get(tag)
        return ContainerSubstrate(config, manager)

    def test_returns_empty_when_no_rollback_image(self):
        substrate = self._substrate({})
        targets = substrate.rollback_targets()
        self.assertEqual(targets, [])

    def test_returns_target_when_rollback_image_exists(self):
        from substrate import rollback_tag
        tag = rollback_tag('test-wl')
        substrate = self._substrate({
            tag: 'abc123',
            'example.com/test:latest': 'def456',
        })
        targets = substrate.rollback_targets()
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]['rollback_id'], 'abc123')
        self.assertEqual(targets[0]['current_id'], 'def456')

    def test_rollback_to_calls_tag(self):
        from substrate import rollback_tag
        tag = rollback_tag('test-wl')
        manager = MagicMock()
        manager.podman.return_value.image_id.side_effect = lambda t: 'abc' if t == tag else 'def'
        config = _make_config(SINGLE_TOML, 'test-wl')
        substrate = ContainerSubstrate(config, manager)
        target = {
            'label': 'test-wl',
            'tag': tag,
            'image': 'example.com/test:latest',
            'current_id': 'def456de',
            'rollback_id': 'abc123ab',
        }
        buf = io.StringIO()
        with patch('sys.stdout', buf):
            substrate.rollback_to(target)
        manager.podman.return_value.tag.assert_called_once_with(tag, 'example.com/test:latest')
        self.assertIn('def456de', buf.getvalue())
        self.assertIn('abc123ab', buf.getvalue())


class TestVMRollbackTargets(unittest.TestCase):

    def _vm_substrate_with_gens(self, home: Path, gen_numbers):
        """Create a VMSubstrate whose home dir has the given gen-N files."""
        config = _make_vm_config()
        for n in gen_numbers:
            (home / f"system.qcow2.gen-{n}").touch()
        substrate = VMSubstrate(config, None)
        with patch.object(type(config), 'home_dir', new_callable=lambda: property(lambda self: home)):
            targets = substrate.rollback_targets()
        return targets

    def test_returns_empty_when_no_gens(self):
        with tempfile.TemporaryDirectory() as d:
            targets = self._vm_substrate_with_gens(Path(d), [])
        self.assertEqual(targets, [])

    def test_returns_sorted_gens(self):
        with tempfile.TemporaryDirectory() as d:
            targets = self._vm_substrate_with_gens(Path(d), [3, 1, 2])
        gens = [t['gen'] for t in targets]
        self.assertEqual(gens, [1, 2, 3])

    def test_target_has_expected_keys(self):
        with tempfile.TemporaryDirectory() as d:
            targets = self._vm_substrate_with_gens(Path(d), [1])
        self.assertEqual(len(targets), 1)
        t = targets[0]
        self.assertIn('label', t)
        self.assertIn('gen', t)
        self.assertIn('path', t)
        self.assertEqual(t['gen'], 1)

    def test_rollback_to_stops_swaps_starts(self):
        config = _make_vm_config()
        calls = []
        def fake_run(cmd, **kw):
            calls.append(cmd)
            return _ok()
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            system_disk = home / "system.qcow2"
            system_disk.touch()
            gen_path = home / "system.qcow2.gen-1"
            gen_path.touch()
            substrate = VMSubstrate(config, None)
            target = {'label': 'system.qcow2.gen-1', 'gen': 1, 'path': gen_path}
            buf = io.StringIO()
            with patch.object(type(config), 'home_dir', new_callable=lambda: property(lambda self: home)), \
                 patch('subprocess.run', side_effect=fake_run), \
                 patch('sys.stdout', buf):
                substrate.rollback_to(target)
        stop_cmds = [c for c in calls if 'stop' in c]
        start_cmds = [c for c in calls if 'start' in c]
        self.assertTrue(stop_cmds, "stop should be called before swapping disk")
        self.assertTrue(start_cmds, "start should be called after swapping disk")
        self.assertFalse(gen_path.exists(), "gen file should be renamed/removed after rollback_to")


# ── lifecycle() primitive ──────────────────────────────────────────────────────

class TestContainerLifecycle(unittest.TestCase):

    def _substrate(self):
        config = _make_config(SINGLE_TOML, 'test-wl')
        manager = MagicMock()
        manager.user_exists.return_value = False
        return ContainerSubstrate(config, manager)

    def test_start_calls_systemctl_start(self):
        substrate = self._substrate()
        with patch('subprocess.run', return_value=_ok()) as mock_run:
            substrate.lifecycle("start")
        cmds = [call[0][0] for call in mock_run.call_args_list]
        self.assertTrue(any('start' in c for c in cmds), f"start not found in {cmds}")

    def test_stop_calls_systemctl_stop(self):
        substrate = self._substrate()
        with patch('subprocess.run', return_value=_ok()) as mock_run:
            substrate.lifecycle("stop")
        cmds = [call[0][0] for call in mock_run.call_args_list]
        self.assertTrue(any('stop' in c for c in cmds), f"stop not found in {cmds}")

    def test_unknown_action_raises_value_error(self):
        substrate = self._substrate()
        with self.assertRaises(ValueError):
            substrate.lifecycle("bogus")


class TestVMLifecycle(unittest.TestCase):

    def _substrate(self):
        config = _make_vm_config()
        return VMSubstrate(config, None)

    def test_start_calls_systemctl_start(self):
        substrate = self._substrate()
        with patch('subprocess.run', return_value=_ok()) as mock_run:
            substrate.lifecycle("start")
        combined = ' '.join(str(c) for call in mock_run.call_args_list for c in call[0][0])
        self.assertIn('start', combined)

    def test_stop_calls_systemctl_stop(self):
        substrate = self._substrate()
        with patch('subprocess.run', return_value=_ok()) as mock_run:
            substrate.lifecycle("stop")
        combined = ' '.join(str(c) for call in mock_run.call_args_list for c in call[0][0])
        self.assertIn('stop', combined)

    def test_unknown_action_raises_value_error(self):
        substrate = self._substrate()
        with self.assertRaises(ValueError):
            substrate.lifecycle("bogus")


# ── reprovision(recreate=True) ─────────────────────────────────────────────────

class TestContainerReprovisionRecreate(unittest.TestCase):

    def test_recreate_skips_pull_restarts_service(self):
        config = _make_config(SINGLE_TOML, 'test-wl')
        manager = MagicMock()
        manager.user_exists.return_value = False
        substrate = ContainerSubstrate(config, manager)
        with patch('subprocess.run', return_value=_ok()) as mock_run:
            result = substrate.reprovision(recreate=True)
        self.assertIsNone(result)
        cmds = [call[0][0] for call in mock_run.call_args_list]
        self.assertTrue(any('restart' in c for c in cmds),
                        f"restart expected in {cmds}")
        # pull must NOT have been called
        manager.podman.return_value.pull.assert_not_called()


class TestVMReprovisionRecreate(unittest.TestCase):

    def test_recreate_restarts_setup_and_service(self):
        config = _make_vm_config()
        substrate = VMSubstrate(config, None)
        calls = []
        with patch('subprocess.run', side_effect=lambda cmd, **kw: calls.append(cmd) or _ok()):
            result = substrate.reprovision(recreate=True)
        self.assertIsNone(result)
        combined = ' '.join(str(t) for c in calls for t in c)
        self.assertIn('restart', combined)
        self.assertIn('setup', combined)


# ── rollback --list (cmd_rollback) ────────────────────────────────────────────

class TestCmdRollbackList(unittest.TestCase):

    def test_rollback_list_prints_targets(self):
        """rollback --list prints available targets and returns without rolling back."""
        import cmd_update

        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test-wl').mkdir()
            (p / 'test-wl' / 'workload.toml').write_text(SINGLE_TOML)

            from substrate import rollback_tag
            tag = rollback_tag('test-wl')
            manager = MagicMock()
            manager.user_exists.return_value = True
            # Simulate a saved rollback image
            manager.podman.return_value.image_id.side_effect = (
                lambda t: 'abc123' if t == tag else 'def456'
            )

            args = types.SimpleNamespace(workload='test-wl', list=True)
            buf = io.StringIO()
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p), \
                 patch.object(cmd_update, 'require_root'), \
                 patch('sys.stdout', buf):
                cmd_update.cmd_rollback(args, manager)

        output = buf.getvalue()
        self.assertIn('test-wl', output)
        # Must NOT call rollback
        manager.podman.return_value.tag.assert_not_called()

    def test_rollback_list_no_targets_prints_message(self):
        """rollback --list with no saved images prints a friendly message."""
        import cmd_update

        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test-wl').mkdir()
            (p / 'test-wl' / 'workload.toml').write_text(SINGLE_TOML)

            manager = MagicMock()
            manager.user_exists.return_value = True
            manager.podman.return_value.image_id.return_value = None

            args = types.SimpleNamespace(workload='test-wl', list=True)
            buf = io.StringIO()
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p), \
                 patch.object(cmd_update, 'require_root'), \
                 patch('sys.stdout', buf):
                cmd_update.cmd_rollback(args, manager)

        self.assertIn('No rollback', buf.getvalue())

    def test_rollback_without_list_still_rolls_back(self):
        """rollback with no --list flag calls rollback() as before."""
        import cmd_update

        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test-wl').mkdir()
            (p / 'test-wl' / 'workload.toml').write_text(SINGLE_TOML)

            manager = MagicMock()
            manager.user_exists.return_value = True
            # No rollback images — will sys.exit(1) via rollback()
            manager.podman.return_value.image_id.return_value = None

            args = types.SimpleNamespace(workload='test-wl', list=False)
            buf_err = io.StringIO()
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p), \
                 patch.object(cmd_update, 'require_root'), \
                 patch('sys.stderr', buf_err):
                with self.assertRaises(SystemExit) as cm:
                    cmd_update.cmd_rollback(args, manager)
        # Should exit non-zero (no rollback image found)
        self.assertNotEqual(cm.exception.code, 0)


# ── control() primitive — incant ──────────────────────────────────────────────

class TestContainerControl(unittest.TestCase):
    """ContainerSubstrate.control() delegates to manager.run_podman with argv."""

    def _substrate(self):
        config = _make_config(SINGLE_TOML, 'test-wl')
        manager = MagicMock()
        manager.run_podman.return_value = _ok(returncode=0)
        return ContainerSubstrate(config, manager), manager

    def test_control_delegates_to_run_podman(self):
        substrate, manager = self._substrate()
        rc = substrate.control(["volume", "ls"])
        manager.run_podman.assert_called_once_with(substrate.config, "volume", "ls")
        self.assertEqual(rc, 0)

    def test_control_propagates_nonzero_returncode(self):
        substrate, manager = self._substrate()
        manager.run_podman.return_value = _ok(returncode=1)
        rc = substrate.control(["network", "create", "mynet"])
        self.assertEqual(rc, 1)
        manager.run_podman.assert_called_once_with(
            substrate.config, "network", "create", "mynet"
        )

    def test_control_passes_all_argv_tokens(self):
        substrate, manager = self._substrate()
        substrate.control(["system", "df", "--format", "json"])
        manager.run_podman.assert_called_once_with(
            substrate.config, "system", "df", "--format", "json"
        )


class TestVMControl(unittest.TestCase):
    """VMSubstrate.control() sends a QMP command via QMPClient."""

    def _substrate(self):
        config = _make_vm_config()
        return VMSubstrate(config, None)

    def test_control_sends_qmp_command(self):
        from substrate import VM_SOCKET_DIR as _VM_SOCKET_DIR
        substrate = self._substrate()
        mock_qmp = MagicMock()
        mock_qmp.execute.return_value = {"return": {}}
        sock_path = _VM_SOCKET_DIR / substrate.config.name / "qmp.sock"
        with patch('substrate.QMPClient', return_value=mock_qmp), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('builtins.print'):
            rc = substrate.control(["query-status"])
        mock_qmp.connect.assert_called_once_with(str(sock_path))
        mock_qmp.negotiate.assert_called_once()
        mock_qmp.execute.assert_called_once_with("query-status", None)
        self.assertEqual(rc, 0)

    def test_control_parses_key_value_args(self):
        substrate = self._substrate()
        mock_qmp = MagicMock()
        mock_qmp.execute.return_value = {"return": {}}
        with patch('substrate.QMPClient', return_value=mock_qmp), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('builtins.print'):
            substrate.control(["migrate", "uri=tcp:0:4444"])
        mock_qmp.execute.assert_called_once_with("migrate", {"uri": "tcp:0:4444"})

    def test_control_returns_1_on_qmp_error_reply(self):
        substrate = self._substrate()
        mock_qmp = MagicMock()
        mock_qmp.execute.return_value = {"error": {"class": "CommandNotFound", "desc": "no such"}}
        with patch('substrate.QMPClient', return_value=mock_qmp), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('builtins.print'):
            rc = substrate.control(["badcmd"])
        self.assertEqual(rc, 1)

    def test_control_missing_socket_returns_1(self):
        substrate = self._substrate()
        buf = io.StringIO()
        with patch('pathlib.Path.exists', return_value=False), \
             patch('sys.stderr', buf):
            rc = substrate.control(["query-status"])
        self.assertEqual(rc, 1)
        self.assertIn("QMP socket not found", buf.getvalue())

    def test_control_empty_argv_returns_2(self):
        substrate = self._substrate()
        buf = io.StringIO()
        with patch('sys.stderr', buf):
            rc = substrate.control([])
        self.assertEqual(rc, 2)

    def test_control_bad_arg_format_returns_2(self):
        substrate = self._substrate()
        buf = io.StringIO()
        with patch('pathlib.Path.exists', return_value=True), \
             patch('sys.stderr', buf):
            rc = substrate.control(["cmd", "notakeyvaluepair"])
        self.assertEqual(rc, 2)
        self.assertIn("key=value", buf.getvalue())


# ── cmd_incant arg parsing + dispatch ─────────────────────────────────────────

class TestCmdIncant(unittest.TestCase):
    """cmd_incant arg parsing, workload-ref parsing, and substrate.control dispatch."""

    def _make_manager(self, *, user_exists=True):
        manager = MagicMock()
        manager.user_exists.return_value = user_exists
        return manager

    def test_incant_dispatches_to_control(self):
        import cmd_interact
        config_toml = SINGLE_TOML
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test-wl').mkdir()
            (p / 'test-wl' / 'workload.toml').write_text(config_toml)
            manager = self._make_manager()
            manager.run_podman.return_value = _ok(returncode=0)

            args = types.SimpleNamespace(workload='test-wl', argv=['--', 'volume', 'ls'])
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p), \
                 patch('sys.exit') as mock_exit:
                cmd_interact.cmd_incant(args, manager)
        mock_exit.assert_called_once_with(0)
        manager.run_podman.assert_called_once()

    def test_incant_workload_ref_slash_container(self):
        """<wl>/<ctr> form is parsed correctly (container arg passed to control)."""
        import cmd_interact
        # For a single-container workload, parse_workload_ref splits the ref but
        # ContainerSubstrate.control doesn't use the container arg — the
        # important thing is that parse_workload_ref doesn't crash.
        config_toml = SINGLE_TOML
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test-wl').mkdir()
            (p / 'test-wl' / 'workload.toml').write_text(config_toml)
            manager = self._make_manager()
            manager.run_podman.return_value = _ok(returncode=0)

            args = types.SimpleNamespace(workload='test-wl/mycontainer', argv=['volume', 'ls'])
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p), \
                 patch('sys.exit'):
                cmd_interact.cmd_incant(args, manager)
        manager.run_podman.assert_called_once()

    def test_incant_user_not_found_exits(self):
        import cmd_interact
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test-wl').mkdir()
            (p / 'test-wl' / 'workload.toml').write_text(SINGLE_TOML)
            manager = self._make_manager(user_exists=False)
            args = types.SimpleNamespace(workload='test-wl', argv=['volume', 'ls'])
            buf = io.StringIO()
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p), \
                 patch('sys.stderr', buf):
                with self.assertRaises(SystemExit) as cm:
                    cmd_interact.cmd_incant(args, manager)
        self.assertNotEqual(cm.exception.code, 0)
        self.assertIn("does not exist", buf.getvalue())

    def test_incant_empty_argv_exits(self):
        import cmd_interact
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test-wl').mkdir()
            (p / 'test-wl' / 'workload.toml').write_text(SINGLE_TOML)
            manager = self._make_manager()
            args = types.SimpleNamespace(workload='test-wl', argv=[])
            buf = io.StringIO()
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p), \
                 patch('sys.stderr', buf):
                with self.assertRaises(SystemExit) as cm:
                    cmd_interact.cmd_incant(args, manager)
        self.assertEqual(cm.exception.code, 2)


# ── attach/network removed from parser ───────────────────────────────────────

class TestRemovedVerbs(unittest.TestCase):
    """attach and network are no longer accepted by the CLI parser."""

    def _invoke(self, argv):
        """Run bin/workloadctl with the given argv list; return (stdout, stderr, exitcode)."""
        import subprocess
        wctl = str(Path(__file__).parent.parent / 'bin' / 'workloadctl')
        result = subprocess.run(
            ['python3', wctl, *argv],
            capture_output=True, text=True,
            env={**__import__('os').environ, 'PYTHONPATH': str(Path(__file__).parent.parent / 'lib')},
        )
        return result.stdout, result.stderr, result.returncode

    def test_attach_not_in_help(self):
        stdout, _, _ = self._invoke(['--help'])
        self.assertNotIn('attach', stdout)

    def test_network_not_in_help(self):
        stdout, _, _ = self._invoke(['--help'])
        self.assertNotIn('network', stdout)

    def test_incant_in_help(self):
        stdout, _, _ = self._invoke(['--help'])
        self.assertIn('incant', stdout)

    def test_attach_verb_rejected(self):
        _, stderr, rc = self._invoke(['attach', 'somewl'])
        self.assertNotEqual(rc, 0)

    def test_network_verb_rejected(self):
        _, stderr, rc = self._invoke(['network', 'testnet', 'create', 'somewl'])
        self.assertNotEqual(rc, 0)


if __name__ == '__main__':
    unittest.main()
