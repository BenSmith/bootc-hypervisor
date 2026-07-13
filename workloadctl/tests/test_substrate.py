#!/usr/bin/env python3
"""Tests for substrate dispatch, parity fixes, and workloadctl drift."""

import io
import json
import shutil
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch


# ── imports from lib ──────────────────────────────────────────────────────────

import workload_lib
import workloadctl_core
import backup as _backup_mod
import substrate_container as _container_mod
import substrate_vm as _vm_mod
from substrate import (
    NotApplicable,
    BackupError,
    LifecycleError,
    service_active,
)
from substrate_container import ContainerSubstrate
from substrate_vm import VMSubstrate, _vm_ssh_command
import cmd_drift
import cmd_health
import cmd_stats


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

[container]
image = "example.com/test:latest"
"""


from tests import REPO_ROOT, script_env
VM_TOML = """\
[workload]
name = "test-vm"

[vm]
image = "example.com/guest:latest"
"""

VM_TOML_WITH_MEMORY = """\
[workload]
name = "test-vm"

[vm]
image = "example.com/guest:latest"
memory = "2048M"
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
        assert self._patcher is not None and self._tmp is not None
        self._patcher.stop()
        shutil.rmtree(self._tmp, ignore_errors=True)


# ── _vm_ssh_command host-key pinning (S1) ────────────────────────────────────

class TestVmSshCommandPinning(unittest.TestCase):
    def test_pins_host_key_no_permissive_options(self):
        config = _make_vm_config()
        cmd = _vm_ssh_command(config, "192.168.200.5", exec_args=["true"])
        joined = " ".join(cmd)
        # Verifies against a per-workload known_hosts keyed by the stable name.
        self.assertIn("StrictHostKeyChecking=yes", cmd)
        self.assertIn(f"HostKeyAlias={config.name}", cmd)
        self.assertIn(
            f"UserKnownHostsFile={config.home_dir}/.ssh/vm_known_hosts", cmd)
        # No trust-on-first-use / throwaway known_hosts remain.
        self.assertNotIn("StrictHostKeyChecking=no", joined)
        self.assertNotIn("/dev/null", joined)


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
                    cmd_stats.cmd_stats(args, manager)
            self.assertEqual(cm.exception.code, 0)
            output = buf_out.getvalue() + buf_err.getvalue()
            self.assertIn('not applicable', output.lower())


# ── VMSubstrate.resource_usage() — QMP-sourced stat row ──────────────────────

class TestVMResourceUsage(unittest.TestCase):
    """VMSubstrate.resource_usage() derives cpu_percent from two QMP samples
    CPU_SAMPLE_SECONDS apart; mem_usage comes from the balloon, mem_limit from
    [vm].memory; net/block/pids are always None (no source)."""

    def _make_config(self):
        return _make_config(VM_TOML_WITH_MEMORY, 'test-vm')

    def test_cpu_percent_derived_from_vcpu_seconds_delta(self):
        config = self._make_config()
        substrate = VMSubstrate(config, None)
        first = {"vcpu_0_cpu_seconds_total": 1.0, "vcpu_1_cpu_seconds_total": 1.0,
                 "balloon_actual_bytes": 123456}
        second = {"vcpu_0_cpu_seconds_total": 1.2, "vcpu_1_cpu_seconds_total": 1.3,
                  "balloon_actual_bytes": 123456}
        with _patch_uid(10001), \
             patch.object(_vm_mod, 'get_vm_qmp_metrics', side_effect=[first, second]), \
             patch.object(_vm_mod.time, 'sleep') as mock_sleep:
            rows = substrate.resource_usage([], json_out=True)
        mock_sleep.assert_called_once_with(VMSubstrate.CPU_SAMPLE_SECONDS)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        # delta = (1.2+1.3) - (1.0+1.0) = 0.5 over 0.5s → 100%.
        self.assertAlmostEqual(row['cpu_percent'], 100.0)

    def test_json_row_mem_usage_from_balloon_net_block_pids_none(self):
        config = self._make_config()
        substrate = VMSubstrate(config, None)
        first = {"vcpu_0_cpu_seconds_total": 1.0, "balloon_actual_bytes": 555555}
        second = {"vcpu_0_cpu_seconds_total": 1.0, "balloon_actual_bytes": 555555}
        with _patch_uid(10001), \
             patch.object(_vm_mod, 'get_vm_qmp_metrics', side_effect=[first, second]), \
             patch.object(_vm_mod.time, 'sleep'):
            rows = substrate.resource_usage([], json_out=True)
        row = rows[0]
        self.assertEqual(row['mem_usage'], 555555)
        self.assertEqual(row['mem_limit'], 2048 * 1024 * 1024)
        self.assertEqual(row['container'], None)
        self.assertIsNone(row['net_input'])
        self.assertIsNone(row['net_output'])
        self.assertIsNone(row['block_input'])
        self.assertIsNone(row['block_output'])
        self.assertIsNone(row['pids'])

    def test_empty_first_sample_raises_not_applicable(self):
        config = self._make_config()
        substrate = VMSubstrate(config, None)
        with _patch_uid(10001), \
             patch.object(_vm_mod, 'get_vm_qmp_metrics', return_value={}) as mock_qmp, \
             patch.object(_vm_mod.time, 'sleep') as mock_sleep:
            with self.assertRaises(NotApplicable):
                substrate.resource_usage([], json_out=True)
        mock_qmp.assert_called_once()
        mock_sleep.assert_not_called()

    def test_follow_raises_not_applicable(self):
        config = self._make_config()
        substrate = VMSubstrate(config, None)
        with _patch_uid(10001), \
             patch.object(_vm_mod, 'get_vm_qmp_metrics') as mock_qmp:
            with self.assertRaises(NotApplicable):
                substrate.resource_usage([], follow=True)
        mock_qmp.assert_not_called()


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
            with patch.object(_vm_mod, 'backup_vm', return_value=42) as mock_bvm, \
                 patch.object(_vm_mod, 'backup_vm_crash') as mock_crash:
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
            with patch.object(_vm_mod, 'backup_vm', return_value=99) as mock_bvm, \
                 patch.object(_vm_mod, 'backup_vm_crash') as mock_crash:
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
            with patch.object(_vm_mod, 'backup_vm_crash', return_value=7) as mock_crash, \
                 patch.object(_vm_mod, 'backup_vm') as mock_bvm:
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
        """consistency='cold' calls _backup_impl with no_stop=False, vm=False."""
        config = self._make_config()
        substrate = ContainerSubstrate(config, None)
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            output.write_bytes(b'x' * 10)
            with patch.object(_container_mod, 'backup_impl') as mock_impl:
                result = substrate.capture(output, consistency='cold')
        mock_impl.assert_called_once_with(config, output, no_stop=False, quiet=False, vm=False)
        self.assertEqual(result, 10)

    def test_crash_passes_no_stop_true(self):
        """consistency='crash' calls _backup_impl with no_stop=True (live copy)."""
        config = self._make_config()
        substrate = ContainerSubstrate(config, None)
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            output.write_bytes(b'x' * 20)
            with patch.object(_container_mod, 'backup_impl') as mock_impl:
                result = substrate.capture(output, consistency='crash')
        mock_impl.assert_called_once_with(config, output, no_stop=True, quiet=False, vm=False)
        self.assertEqual(result, 20)

    def test_default_consistency_is_cold(self):
        """Omitting consistency= defaults to cold (backward-compat)."""
        config = self._make_config()
        substrate = ContainerSubstrate(config, None)
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            output.write_bytes(b'x' * 5)
            with patch.object(_container_mod, 'backup_impl') as mock_impl:
                result = substrate.capture(output)
        mock_impl.assert_called_once_with(config, output, no_stop=False, quiet=False, vm=False)
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
            with patch('backup.subprocess.run', inactive), \
                 patch.object(_backup_mod, 'backup_vm', return_value=55) as mock_cold:
                result = _backup_mod.backup_vm_crash(config, output, quiet=True)
        mock_cold.assert_called_once_with(config, output, quiet=True)
        self.assertEqual(result, 55)

    def test_inactive_vm_falls_back_to_cold_prints_when_not_quiet(self):
        """quiet=False: the fallback notice is printed before delegating."""
        config = self._make_config()
        inactive = MagicMock(return_value=MagicMock(returncode=1))
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            buf = io.StringIO()
            with patch('backup.subprocess.run', inactive), \
                 patch.object(_backup_mod, 'backup_vm', return_value=55) as mock_cold, \
                 patch('sys.stdout', buf):
                result = _backup_mod.backup_vm_crash(config, output, quiet=False)
        mock_cold.assert_called_once_with(config, output, quiet=False)
        self.assertEqual(result, 55)
        self.assertIn('not active', buf.getvalue())
        self.assertIn('cold backup path', buf.getvalue())

    def _patch_active_vm(self, config_name, d):
        """Return a context-manager stack that makes the VM appear active + QMP socket present."""
        # Create the fake qmp.sock path so Path.exists() returns True
        sock_dir = Path(d) / config_name
        sock_dir.mkdir(parents=True, exist_ok=True)
        (sock_dir / "qmp.sock").touch()
        return patch.object(_backup_mod, 'VM_SOCKET_DIR', Path(d))

    def test_crash_calls_qmp_stop_then_cont(self):
        """Active VM: QMP 'stop' is issued before copy, 'cont' after."""
        config = self._make_config()
        qmp_mock = self._make_qmp()

        with tempfile.TemporaryDirectory() as d:
            output = MagicMock()
            output.stat.return_value.st_size = 123
            vm_sock_patch = self._patch_active_vm(config.name, d)
            with patch('backup.subprocess.run',
                       return_value=MagicMock(returncode=0)), \
                 vm_sock_patch, \
                 patch.object(_backup_mod, 'QMPClient', return_value=qmp_mock), \
                 patch.object(_backup_mod, 'backup_impl'):
                _backup_mod.backup_vm_crash(config, output, quiet=True)

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
            with patch('backup.subprocess.run',
                       return_value=MagicMock(returncode=0)), \
                 vm_sock_patch, \
                 patch.object(_backup_mod, 'QMPClient', FakeQMP), \
                 patch.object(_backup_mod, 'backup_impl',
                               side_effect=RuntimeError("copy failed")):
                with self.assertRaises(RuntimeError):
                    _backup_mod.backup_vm_crash(config, output, quiet=True)

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
            with patch('backup.subprocess.run', side_effect=fake_run), \
                 patch.object(_backup_mod, 'VM_SOCKET_DIR', Path(d)):
                buf = io.StringIO()
                with patch('sys.stderr', buf):
                    with self.assertRaises(BackupError):
                        _backup_mod.backup_vm_crash(config, output, quiet=True)
        self.assertIn('cold', buf.getvalue())  # mentions --consistency cold fallback

    def test_stop_error_raises_backup_error_without_resuming(self):
        """A failed QMP 'stop' raises BackupError and does NOT issue 'cont'
        (vCPUs were never paused, so there is nothing to resume)."""
        config = self._make_config()
        qmp_mock = self._make_qmp(stop_reply={"error": {"desc": "boom"}})

        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            vm_sock_patch = self._patch_active_vm(config.name, d)
            with patch('backup.subprocess.run',
                       return_value=MagicMock(returncode=0)), \
                 vm_sock_patch, \
                 patch.object(_backup_mod, 'QMPClient', return_value=qmp_mock), \
                 patch.object(_backup_mod, 'backup_impl') as mock_impl:
                with patch('sys.stderr', io.StringIO()):
                    with self.assertRaises(BackupError):
                        _backup_mod.backup_vm_crash(config, output, quiet=True)

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
            with patch('backup.subprocess.run',
                       return_value=MagicMock(returncode=0)), \
                 vm_sock_patch, \
                 patch.object(_backup_mod, 'QMPClient', return_value=qmp_mock), \
                 patch.object(_backup_mod, 'backup_impl'), \
                 patch('sys.stderr', buf):
                result = _backup_mod.backup_vm_crash(config, output, quiet=True)

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
            with patch('backup.subprocess.run',
                       return_value=MagicMock(returncode=0)), \
                 vm_sock_patch, \
                 patch.object(_backup_mod, 'QMPClient', return_value=qmp_mock), \
                 patch.object(_backup_mod, 'backup_impl'), \
                 patch('sys.stderr', buf):
                result = _backup_mod.backup_vm_crash(config, output, quiet=True)

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
            with patch('backup.subprocess.run',
                       return_value=MagicMock(returncode=0)), \
                 vm_sock_patch, \
                 patch.object(_backup_mod, 'QMPClient', return_value=qmp_mock), \
                 patch.object(_backup_mod, 'backup_impl') as mock_impl, \
                 patch('sys.stderr', io.StringIO()):
                with self.assertRaises(BackupError):
                    _backup_mod.backup_vm_crash(config, output, quiet=True)

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
            with patch('backup.subprocess.run',
                       return_value=MagicMock(returncode=0)), \
                 vm_sock_patch, \
                 patch.object(_backup_mod, 'QMPClient', return_value=qmp_mock), \
                 patch.object(_backup_mod, 'backup_impl') as mock_impl:
                with patch('sys.stderr', io.StringIO()):
                    with self.assertRaises(BackupError):
                        _backup_mod.backup_vm_crash(config, output, quiet=True)

        qmp_mock.close.assert_called_once()  # fd released despite the failure
        # never paused, so nothing to copy or resume
        qmp_mock.execute.assert_not_called()
        mock_impl.assert_not_called()


# ── ContainerSubstrate.liveness() multi-container semantics ──────────────────

SINGLE_TOML = """\
[workload]
name = "test-wl"

[container]
image = "example.com/test:latest"
"""

POD_TOML = """\
[workload]
name = "test-pod"
mode = "pod"

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


def _patch_uid(uid):
    """Patch pwd.getpwnam so WorkloadConfig.uid resolves without a real user."""
    pw = MagicMock()
    pw.pw_uid = uid
    pw.pw_gid = uid
    return patch('pwd.getpwnam', return_value=pw)


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


class TestServiceActive(unittest.TestCase):
    """The shared is-active primitive every health path now routes through."""

    def test_active_returns_true_and_state(self):
        with patch('subprocess.run', return_value=_ok(stdout='active\n')):
            active, state = service_active('workload-x.service')
        self.assertTrue(active)
        self.assertEqual(state, 'active')

    def test_inactive_returns_false_and_word(self):
        with patch('subprocess.run',
                   return_value=_ok(stdout='inactive\n', returncode=3)):
            active, state = service_active('workload-x.service')
        self.assertFalse(active)
        self.assertEqual(state, 'inactive')

    def test_empty_stdout_yields_bare_string(self):
        # Callers apply their own default; the primitive returns the raw ''.
        with patch('subprocess.run', return_value=_ok(stdout='', returncode=4)):
            active, state = service_active('workload-x.service')
        self.assertFalse(active)
        self.assertEqual(state, '')


class TestContainerLivenessRows(unittest.TestCase):
    """Per-container liveness rows — the single source _multi_container_health
    and diagnose now consume instead of re-deriving name/unit math."""

    def _substrate(self, toml, name, *, unit_states, statuses, user_exists=True):
        config = _make_config(toml, name)
        manager = MagicMock()
        manager.user_exists.return_value = user_exists
        manager.podman.return_value.container_status.side_effect = (
            lambda cname: statuses.get(cname)
        )
        sub = ContainerSubstrate(config, manager)

        def fake_is_active(argv, *a, **k):
            unit = argv[-1]
            state = unit_states.get(unit, 'inactive')
            return _ok(stdout=state + '\n', returncode=0 if state == 'active' else 3)

        self._is_active = fake_is_active
        return sub

    def test_single_row_keyed_on_main_service(self):
        sub = self._substrate(
            SINGLE_TOML, 'test-wl',
            unit_states={'workload-test-wl.service': 'active'},
            statuses={'workload-test-wl': 'running'},
        )
        with patch('subprocess.run', side_effect=self._is_active):
            rows = sub.container_liveness()
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r['container'], 'test-wl')
        self.assertEqual(r['podman_name'], 'workload-test-wl')
        self.assertEqual(r['unit'], 'workload-test-wl.service')
        self.assertTrue(r['healthy'])

    def test_multi_rows_per_container_units(self):
        sub = self._substrate(
            POD_TOML, 'test-pod',
            unit_states={
                'workload-test-pod-web.service': 'active',
                'workload-test-pod-db.service': 'failed',
            },
            statuses={'workload-test-pod-web': 'running',
                      'workload-test-pod-db': None},
        )
        with patch('subprocess.run', side_effect=self._is_active):
            rows = sub.container_liveness()
        by = {r['container']: r for r in rows}
        self.assertEqual(set(by), {'web', 'db'})
        self.assertEqual(by['web']['unit'], 'workload-test-pod-web.service')
        self.assertTrue(by['web']['healthy'])
        self.assertFalse(by['db']['healthy'])   # failed unit + not running

    def test_absent_user_leaves_all_not_running(self):
        sub = self._substrate(
            POD_TOML, 'test-pod',
            unit_states={'workload-test-pod-web.service': 'active',
                         'workload-test-pod-db.service': 'active'},
            statuses={'workload-test-pod-web': 'running'},
            user_exists=False,
        )
        with patch('subprocess.run', side_effect=self._is_active):
            rows = sub.container_liveness()
        self.assertTrue(all(not r['running'] for r in rows))
        self.assertTrue(all(not r['healthy'] for r in rows))
        sub.manager.podman.assert_not_called()


class TestContainerResourceUsage(unittest.TestCase):

    def _substrate(self, run_result):
        config = _make_config(SINGLE_TOML, 'test-wl')
        manager = MagicMock()
        manager.podman.return_value.run.return_value = run_result
        return ContainerSubstrate(config, manager)

    def test_json_returns_result(self):
        """json_out path returns a list of normalized STAT_ROW_KEYS rows."""
        result = _ok(stdout='[]')
        substrate = self._substrate(result)
        returned = substrate.resource_usage(['test-wl'], json_out=True)
        self.assertEqual(returned, [])

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

[container]
image = "example.com/test:latest"
"""

CONTAINER_TOML_CUSTOM_SLICE = """\
[workload]
name = "test-wl"

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
                    cmd_health.cmd_health(args, manager)
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
        assert placement is not None
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
        assert placement is not None
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
        assert placement is not None
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

    # VMSubstrate.resource_usage is implemented (sourced from QMP), so a VM
    # that isn't running raises NotApplicable naming the QMP socket, not the
    # generic "no primitive" reason.
    def test_vm_resource_usage_raises_not_applicable(self):
        substrate = VMSubstrate(self._vm_config(), None)
        with self.assertRaises(NotApplicable) as cm:
            substrate.resource_usage([])
        self.assertIn('resource_usage', cm.exception.reason)
        self.assertIn('QMP', cm.exception.reason)

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

    def test_rollback_to_retag_failure_raises_lifecycle_error(self):
        from podman import PodmanError
        from substrate import rollback_tag
        tag = rollback_tag('test-wl')
        manager = MagicMock()
        manager.podman.return_value.tag.side_effect = PodmanError(1, "tag error", ["tag"])
        config = _make_config(SINGLE_TOML, 'test-wl')
        substrate = ContainerSubstrate(config, manager)
        target = {
            'label': 'test-wl',
            'tag': tag,
            'image': 'example.com/test:latest',
            'current_id': 'def456de',
            'rollback_id': 'abc123ab',
        }
        with patch('sys.stderr', io.StringIO()):
            with self.assertRaises(LifecycleError) as cm:
                substrate.rollback_to(target)
        self.assertEqual(cm.exception.returncode, 1)


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

    def _rollback(self, home, target, config):
        buf = io.StringIO()
        with patch.object(type(config), 'home_dir',
                          new_callable=lambda: property(lambda self: home)), \
             patch('subprocess.run', return_value=_ok()), \
             patch('sys.stdout', buf):
            VMSubstrate(config, None).rollback_to(target)

    def test_rollback_is_non_destructive(self):
        # ADR 003: rolling back preserves the pre-rollback disk as a new
        # generation so a roll-forward is possible.
        config = _make_vm_config()
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            (home / "system.qcow2").write_bytes(b"CURRENT")
            (home / "system.qcow2.gen-1").write_bytes(b"GEN1")
            (home / "system.qcow2.gen-2").write_bytes(b"GEN2")
            target = {'label': 'system.qcow2.gen-1', 'gen': 1,
                      'path': home / "system.qcow2.gen-1"}
            self._rollback(home, target, config)
            # Target became the active disk.
            self.assertEqual((home / "system.qcow2").read_bytes(), b"GEN1")
            # Pre-rollback disk survived as a new (highest) generation, gen-3.
            self.assertTrue((home / "system.qcow2.gen-3").exists())
            self.assertEqual((home / "system.qcow2.gen-3").read_bytes(), b"CURRENT")
            # Roll-forward is possible: the preserved disk is a rollback target.
            with patch.object(type(config), 'home_dir',
                              new_callable=lambda: property(lambda self: home)):
                gens = [t['gen'] for t in VMSubstrate(config, None).rollback_targets()]
            self.assertIn(3, gens)

    def test_rollback_respects_rollback_keep(self):
        # rollback_keep (default 2) still bounds the generation count; the
        # rotated-out disk is pruned like any other generation.
        config = _make_vm_config()
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            (home / "system.qcow2").write_bytes(b"CURRENT")
            for n in (1, 2, 3, 4):
                (home / f"system.qcow2.gen-{n}").write_bytes(f"GEN{n}".encode())
            target = {'label': 'system.qcow2.gen-1', 'gen': 1,
                      'path': home / "system.qcow2.gen-1"}
            self._rollback(home, target, config)
            remaining = sorted(
                int(p.suffix[5:]) for p in home.glob("system.qcow2.gen-*"))
        # keep=2 older + the exempt rotated-out gen-5 = 3 total; oldest (gen-2)
        # pruned. gen-1 was consumed as the active disk.
        self.assertEqual(remaining, [3, 4, 5])

    def test_rollback_keep_zero_prunes_all_rotated_generations(self):
        # Regression: rollback_keep=0 must prune every generation except the
        # exempt rotated-out disk. The old `gens[:-keep]` slice degenerated to
        # gens[:0] == [] for keep==0, so nothing was pruned and gen files grew
        # without bound.
        config = _make_vm_config()
        config.config.setdefault("vm", {})["rollback_keep"] = 0
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            (home / "system.qcow2").write_bytes(b"CURRENT")
            for n in (1, 2, 3):
                (home / f"system.qcow2.gen-{n}").write_bytes(f"GEN{n}".encode())
            target = {'label': 'system.qcow2.gen-1', 'gen': 1,
                      'path': home / "system.qcow2.gen-1"}
            self._rollback(home, target, config)
            remaining = sorted(
                int(p.suffix[5:]) for p in home.glob("system.qcow2.gen-*"))
        # keep=0: only the exempt rotated-out gen-4 (the pre-rollback disk)
        # survives; gen-2 and gen-3 are pruned, gen-1 became the active disk.
        self.assertEqual(remaining, [4])

    def test_rollback_restores_current_disk_when_swap_fails(self):
        # Regression (ADR 003 atomicity): if swapping the target generation in
        # fails after the current disk was already rotated out, the pre-rollback
        # disk must be put back so the VM still has an active system.qcow2 —
        # rather than being left with none and an unhandled traceback.
        config = _make_vm_config()
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            (home / "system.qcow2").write_bytes(b"CURRENT")
            (home / "system.qcow2.gen-1").write_bytes(b"GEN1")
            target = {'label': 'system.qcow2.gen-1', 'gen': 1,
                      'path': home / "system.qcow2.gen-1"}
            buf = io.StringIO()
            with patch.object(type(config), 'home_dir',
                              new_callable=lambda: property(lambda self: home)), \
                 patch('subprocess.run', return_value=_ok()), \
                 patch('sys.stdout', buf), patch('sys.stderr', buf), \
                 patch.object(Path, 'replace', side_effect=OSError("no space")):
                with self.assertRaises(LifecycleError):
                    VMSubstrate(config, None).rollback_to(target)
            # The active disk is restored to the pre-rollback contents, not left
            # missing; the target generation is untouched (swap never completed).
            self.assertTrue((home / "system.qcow2").exists())
            self.assertEqual((home / "system.qcow2").read_bytes(), b"CURRENT")
            self.assertTrue((home / "system.qcow2.gen-1").exists())


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

    def test_restart_calls_systemctl_restart(self):
        substrate = self._substrate()
        with patch('subprocess.run', return_value=_ok()) as mock_run:
            substrate.lifecycle("restart")
        cmds = [call[0][0] for call in mock_run.call_args_list]
        self.assertTrue(any('restart' in c for c in cmds), f"restart not found in {cmds}")

    def test_restart_failure_raises_lifecycle_error(self):
        substrate = self._substrate()
        with patch('subprocess.run', return_value=_ok(returncode=5)):
            with self.assertRaises(LifecycleError) as cm:
                substrate.lifecycle("restart")
        self.assertEqual(cm.exception.returncode, 5)

    def test_restart_maps_called_process_error_for_enabled_workload(self):
        """The provisioned path goes through restart_workload_service(), whose
        CalledProcessError has to surface as LifecycleError, not a traceback."""
        config = _make_config(SINGLE_TOML, 'test-wl')
        manager = MagicMock()
        manager.user_exists.return_value = True
        substrate = ContainerSubstrate(config, manager)
        err = subprocess.CalledProcessError(3, ['systemctl', 'restart'])
        with _patch_uid(10001), \
             patch.object(_container_mod, 'restart_workload_service', side_effect=err):
            with self.assertRaises(LifecycleError) as cm:
                substrate.lifecycle("restart")
        self.assertEqual(cm.exception.returncode, 3)

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

    def test_restart_bounces_main_unit_only(self):
        """A bounce must not re-run the setup oneshot: re-rendering the cloud-init
        seed from a changed TOML is recreate's job, not restart's."""
        substrate = self._substrate()
        with patch('subprocess.run', return_value=_ok()) as mock_run:
            substrate.lifecycle("restart")
        units = [call[0][0][-1] for call in mock_run.call_args_list]
        self.assertEqual(units, [substrate.config.service_name])

    def test_restart_failure_raises_lifecycle_error(self):
        substrate = self._substrate()
        with patch('subprocess.run', return_value=_ok(returncode=4)):
            with self.assertRaises(LifecycleError) as cm:
                substrate.lifecycle("restart")
        self.assertEqual(cm.exception.returncode, 4)

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
        with patch('subprocess.run', side_effect=lambda cmd, **kw: calls.append(cmd) or _ok()):  # type: ignore[func-returns-value]
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
            # No rollback images — rollback() raises LifecycleError
            manager.podman.return_value.image_id.return_value = None

            args = types.SimpleNamespace(workload='test-wl', list=False)
            buf_err = io.StringIO()
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p), \
                 patch.object(cmd_update, 'require_root'), \
                 patch('sys.stderr', buf_err):
                with self.assertRaises(LifecycleError) as cm:
                    cmd_update.cmd_rollback(args, manager)
        # Should exit non-zero (no rollback image found)
        self.assertNotEqual(cm.exception.returncode, 0)


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
        from vm import VM_SOCKET_DIR as _VM_SOCKET_DIR
        substrate = self._substrate()
        mock_qmp = MagicMock()
        mock_qmp.execute.return_value = {"return": {}}
        sock_path = _VM_SOCKET_DIR / substrate.config.name / "qmp.sock"
        with patch('substrate_vm.QMPClient', return_value=mock_qmp), \
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
        with patch('substrate_vm.QMPClient', return_value=mock_qmp), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('builtins.print'):
            substrate.control(["migrate", "uri=tcp:0:4444"])
        mock_qmp.execute.assert_called_once_with("migrate", {"uri": "tcp:0:4444"})

    def test_control_returns_1_on_qmp_error_reply(self):
        substrate = self._substrate()
        mock_qmp = MagicMock()
        mock_qmp.execute.return_value = {"error": {"class": "CommandNotFound", "desc": "no such"}}
        with patch('substrate_vm.QMPClient', return_value=mock_qmp), \
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
        wctl = str(REPO_ROOT / 'bin' / 'workloadctl')
        result = subprocess.run(
            ['python3', wctl, *argv],
            capture_output=True, text=True, env=script_env(),
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


# ── ContainerSubstrate.exec() / open_shell() ──────────────────────────────────

class TestContainerExecShell(unittest.TestCase):

    def _substrate(self):
        config = _make_config(SINGLE_TOML, 'test-wl')
        manager = MagicMock()
        return ContainerSubstrate(config, manager), manager

    def test_exec_returns_returncode(self):
        substrate, manager = self._substrate()
        manager.run_podman_exec.return_value = _ok(returncode=3)
        rc = substrate.exec(["echo", "hi"])
        self.assertEqual(rc, 3)
        manager.run_podman_exec.assert_called_once()

    def test_open_shell_console_raises_not_applicable(self):
        substrate, _ = self._substrate()
        with self.assertRaises(NotApplicable):
            substrate.open_shell(console=True)

    def test_open_shell_tries_bash_first(self):
        substrate, manager = self._substrate()
        manager.run_podman_exec.return_value = _ok(returncode=0)
        buf = io.StringIO()
        with patch('sys.stdout', buf):
            substrate.open_shell()
        # Only one call: bash succeeded (rc=0), no fallback to sh.
        manager.run_podman_exec.assert_called_once()
        args = manager.run_podman_exec.call_args[0][1]
        self.assertIn('/bin/bash', args)

    def test_open_shell_falls_back_to_sh_on_127(self):
        substrate, manager = self._substrate()
        manager.run_podman_exec.side_effect = [_ok(returncode=127), _ok(returncode=0)]
        buf = io.StringIO()
        with patch('sys.stdout', buf):
            substrate.open_shell()
        self.assertEqual(manager.run_podman_exec.call_count, 2)
        second_args = manager.run_podman_exec.call_args_list[1][0][1]
        self.assertIn('/bin/sh', second_args)

    def test_open_shell_with_container_user_sets_env(self):
        toml = """\
[workload]
name = "test-wl"

[container]
image = "example.com/test:latest"

[container.environment]
CONTAINER_USER = "appuser"
CONTAINER_UID = "2000"
"""
        config = _make_config(toml, 'test-wl')
        manager = MagicMock()
        manager.run_podman_exec.return_value = _ok(returncode=0)
        substrate = ContainerSubstrate(config, manager)
        buf = io.StringIO()
        with patch('sys.stdout', buf):
            substrate.open_shell()
        args = manager.run_podman_exec.call_args[0][1]
        self.assertIn('--user', args)
        self.assertIn('appuser', args)
        self.assertIn('HOME=/home/appuser', args)


# ── ContainerSubstrate.lifecycle() reboot / user_exists branches ─────────────

class TestContainerLifecycleMore(unittest.TestCase):

    def _substrate(self, user_exists=False):
        config = _make_config(SINGLE_TOML, 'test-wl')
        manager = MagicMock()
        manager.user_exists.return_value = user_exists
        return ContainerSubstrate(config, manager), manager

    def test_start_with_user_calls_restart_workload_service(self):
        substrate, manager = self._substrate(user_exists=True)
        with _patch_uid(10001), \
             patch.object(_container_mod, 'restart_workload_service') as mock_r:
            substrate.lifecycle("start")
        mock_r.assert_called_once_with(
            10001, substrate.config.service_name, action="start"
        )

    def test_start_with_user_calledprocesserror_exits(self):
        import subprocess as sp
        substrate, manager = self._substrate(user_exists=True)
        with _patch_uid(10001), patch.object(
            _container_mod, 'restart_workload_service',
            side_effect=sp.CalledProcessError(returncode=5, cmd=['x']),
        ):
            with self.assertRaises(LifecycleError) as cm:
                substrate.lifecycle("start")
        self.assertEqual(cm.exception.returncode, 5)

    def test_restart_with_user_calls_restart_workload_service(self):
        substrate, manager = self._substrate(user_exists=True)
        with _patch_uid(10001), patch.object(_container_mod, 'restart_workload_service') as mock_r:
            substrate.lifecycle("restart")
        mock_r.assert_called_once_with(10001, substrate.config.service_name)

    def test_restart_without_user_calls_systemctl(self):
        substrate, manager = self._substrate(user_exists=False)
        with patch('subprocess.run', return_value=_ok()) as mock_run:
            substrate.lifecycle("restart")
        mock_run.assert_called_once()
        self.assertIn('restart', mock_run.call_args[0][0])

    def test_reboot_success_prints_confirmation(self):
        substrate, manager = self._substrate()
        manager.run_podman_exec.return_value = _ok(returncode=0)
        buf = io.StringIO()
        with patch('sys.stdout', buf):
            substrate.lifecycle("reboot")
        self.assertIn('soft-rebooted', buf.getvalue())

    def test_reboot_failure_exits_1(self):
        substrate, manager = self._substrate()
        manager.run_podman_exec.return_value = _ok(returncode=1)
        buf = io.StringIO()
        with patch('sys.stderr', buf):
            with self.assertRaises(LifecycleError) as cm:
                substrate.lifecycle("reboot")
        self.assertEqual(cm.exception.returncode, 1)


# ── ContainerSubstrate.reprovision() full pull/restart flow ──────────────────

class TestContainerReprovisionFlow(unittest.TestCase):

    def _substrate(self, user_exists=True):
        config = _make_config(SINGLE_TOML, 'test-wl')
        manager = MagicMock()
        manager.user_exists.return_value = user_exists
        return ContainerSubstrate(config, manager), manager

    def test_pull_never_raises_not_applicable(self):
        toml = """\
[workload]
name = "test-wl"

[container]
image = "example.com/test:latest"
pull = "never"
"""
        config = _make_config(toml, 'test-wl')
        manager = MagicMock()
        substrate = ContainerSubstrate(config, manager)
        with self.assertRaises(NotApplicable):
            substrate.reprovision()

    def test_user_missing_returns_none(self):
        substrate, manager = self._substrate(user_exists=False)
        result = substrate.reprovision()
        self.assertIsNone(result)

    def test_no_change_returns_none(self):
        substrate, manager = self._substrate()
        pod = manager.podman.return_value
        pod.image_id.return_value = 'same-id'
        result = substrate.reprovision()
        self.assertIsNone(result)
        pod.pull.assert_called_once()

    def test_changed_image_restarts_and_returns_config_and_ids(self):
        substrate, manager = self._substrate()
        pod = manager.podman.return_value
        pod.image_id.side_effect = ['old-id', 'new-id']
        with _patch_uid(10001), \
             patch.object(_container_mod, 'restart_workload_service') as mock_r:
            result = substrate.reprovision()
        self.assertIsNotNone(result)
        cfg, old_ids = result
        self.assertEqual(old_ids['test-wl'], 'old-id')
        mock_r.assert_called_once()
        pod.tag.assert_called_once()

    def test_empty_old_id_retries_and_recovers(self):
        """A transient empty image_id() (just-restarted rootless store) must
        be retried, not treated as 'no previous image' — otherwise a
        successful update loses its rollback target."""
        substrate, manager = self._substrate()
        pod = manager.podman.return_value
        # 1st call (initial old_id) empty, 2nd+3rd retry empty, 4th recovers,
        # then new_id call for change detection.
        pod.image_id.side_effect = ['', '', '', 'old-id', 'new-id']
        with _patch_uid(10001), \
             patch.object(_container_mod, 'restart_workload_service'), \
             patch.object(_container_mod, 'ensure_runtime_dir') as mock_ensure, \
             patch.object(_container_mod.time, 'sleep') as mock_sleep:
            result = substrate.reprovision()
        mock_ensure.assert_called_once_with(10001)
        cfg, old_ids = result
        self.assertEqual(old_ids['test-wl'], 'old-id')
        pod.tag.assert_called_once()
        self.assertEqual(mock_sleep.call_count, 3)

    def test_old_id_stays_empty_after_exhausting_retries(self):
        """If image_id() never resolves within the retry budget, the old_id
        is recorded as empty and no rollback tag is written for it — but the
        update must still proceed rather than hang or crash."""
        substrate, manager = self._substrate()
        pod = manager.podman.return_value
        # Every image_id() call (initial + 10 retries + final new_id check)
        # returns empty/None so nothing ever resolves.
        pod.image_id.return_value = None
        with _patch_uid(10001), \
             patch.object(_container_mod, 'restart_workload_service'), \
             patch.object(_container_mod, 'ensure_runtime_dir') as mock_ensure, \
             patch.object(_container_mod.time, 'sleep') as mock_sleep:
            result = substrate.reprovision(force=True)
        mock_ensure.assert_called_once_with(10001)
        self.assertEqual(mock_sleep.call_count, 10)
        cfg, old_ids = result
        self.assertIsNone(old_ids['test-wl'])
        pod.tag.assert_not_called()

    def test_pull_failure_raises_provision_failed(self):
        from podman import PodmanError
        substrate, manager = self._substrate()
        pod = manager.podman.return_value
        pod.image_id.return_value = 'old-id'
        pod.pull.side_effect = PodmanError(1, "pull error", ["pull", "image"])
        from substrate import ProvisionFailed
        with patch('sys.stderr', io.StringIO()):
            with self.assertRaises(ProvisionFailed):
                substrate.reprovision()

    def test_force_restarts_even_without_change(self):
        substrate, manager = self._substrate()
        pod = manager.podman.return_value
        pod.image_id.return_value = 'same-id'
        with _patch_uid(10001), \
             patch.object(_container_mod, 'restart_workload_service') as mock_r:
            result = substrate.reprovision(force=True)
        self.assertIsNotNone(result)
        mock_r.assert_called_once()


# ── ContainerSubstrate.rollback() ─────────────────────────────────────────────

class TestContainerRollback(unittest.TestCase):

    def _substrate(self, image_ids: dict):
        config = _make_config(SINGLE_TOML, 'test-wl')
        manager = MagicMock()
        manager.podman.return_value.image_id.side_effect = lambda t: image_ids.get(t)
        return ContainerSubstrate(config, manager), manager

    def test_no_rollback_tag_exits_1(self):
        substrate, manager = self._substrate({})
        buf = io.StringIO()
        with patch('sys.stderr', buf):
            with self.assertRaises(LifecycleError) as cm:
                substrate.rollback()
        self.assertEqual(cm.exception.returncode, 1)
        self.assertIn('No rollback image', buf.getvalue())

    def test_already_at_rollback_image_no_restart(self):
        from substrate import rollback_tag
        tag = rollback_tag('test-wl')
        # rollback tag exists but current == rollback (so rollback_targets()
        # filters it out via current_id check being irrelevant — targets()
        # only excludes on missing rollback_id, so simulate "already applied"
        # by making current_id equal rollback_id too, which still appears as
        # a target since rollback_targets() doesn't dedupe by equality).
        # Instead: simulate rollback_targets() empty but a tag existing via
        # _has_any_rollback_tag by having image_id for the working image AND
        # rollback tag itself both defined only for `tag`, while
        # container_images()'s live image isn't tagged (so targets() has an
        # entry). To hit the "no targets but has_any_tag" branch, we patch
        # rollback_targets directly.
        substrate, manager = self._substrate({tag: 'abc'})
        with patch.object(substrate, 'rollback_targets', return_value=[]), \
             patch.object(substrate, '_has_any_rollback_tag', return_value=True):
            buf = io.StringIO()
            with patch('sys.stdout', buf):
                substrate.rollback()
        self.assertIn('Already running', buf.getvalue())

    def test_rollback_applies_targets_and_restarts(self):
        from substrate import rollback_tag
        tag = rollback_tag('test-wl')
        substrate, manager = self._substrate({
            tag: 'abc123', 'example.com/test:latest': 'def456',
        })
        with _patch_uid(10001), \
             patch.object(_container_mod, 'restart_workload_service') as mock_r:
            buf = io.StringIO()
            with patch('sys.stdout', buf):
                substrate.rollback()
        mock_r.assert_called_once()
        self.assertIn('Rolled back', buf.getvalue())


# ── VMSubstrate.exec() / open_shell() ─────────────────────────────────────────

class TestVMExecShell(unittest.TestCase):

    def _substrate(self):
        config = _make_vm_config()
        return VMSubstrate(config, None)

    def test_exec_no_ip_exits_1(self):
        substrate = self._substrate()
        with patch.object(_vm_mod, '_vm_guest_ip', return_value=None), \
             patch('sys.stderr', io.StringIO()):
            with self.assertRaises(LifecycleError) as cm:
                substrate.exec(["ls"])
        self.assertEqual(cm.exception.returncode, 1)

    def test_exec_runs_ssh_and_returns_code(self):
        substrate = self._substrate()
        with patch.object(_vm_mod, '_vm_guest_ip', return_value='10.0.0.5'), \
             patch('subprocess.run', return_value=_ok(returncode=7)) as mock_run:
            rc = substrate.exec(["ls"])
        self.assertEqual(rc, 7)
        ssh_argv = mock_run.call_args[0][0]
        self.assertIn('ssh', ssh_argv)

    def test_open_shell_ssh_success_returns_normally(self):
        """A clean SSH session is success: return, don't raise, don't fall back."""
        substrate = self._substrate()
        with patch.object(_vm_mod, '_vm_guest_ip', return_value='10.0.0.5'), \
             patch('subprocess.run', return_value=_ok(returncode=0)), \
             patch.object(_vm_mod.os, 'execvp') as mock_execvp:
            substrate.open_shell()
        mock_execvp.assert_not_called()

    def test_open_shell_ssh_remote_failure_propagates_code(self):
        """A nonzero exit from the remote shell surfaces as that exact code."""
        substrate = self._substrate()
        with patch.object(_vm_mod, '_vm_guest_ip', return_value='10.0.0.5'), \
             patch('subprocess.run', return_value=_ok(returncode=17)):
            with self.assertRaises(LifecycleError) as cm:
                substrate.open_shell()
        self.assertEqual(cm.exception.returncode, 17)

    def test_open_shell_ssh_failure_falls_back_to_console(self):
        substrate = self._substrate()
        with patch.object(_vm_mod, '_vm_guest_ip', return_value='10.0.0.5'), \
             patch('subprocess.run', return_value=_ok(returncode=255)), \
             patch('pathlib.Path.exists', return_value=False), \
             patch('sys.stderr', io.StringIO()):
            with self.assertRaises(LifecycleError) as cm:
                substrate.open_shell()
        self.assertEqual(cm.exception.returncode, 1)

    def test_open_shell_no_ip_falls_to_console_missing_socket(self):
        substrate = self._substrate()
        with patch.object(_vm_mod, '_vm_guest_ip', return_value=None), \
             patch('pathlib.Path.exists', return_value=False), \
             patch('sys.stderr', io.StringIO()):
            with self.assertRaises(LifecycleError) as cm:
                substrate.open_shell()
        self.assertEqual(cm.exception.returncode, 1)

    def test_open_shell_console_connects_via_socat(self):
        substrate = self._substrate()
        with patch.object(_vm_mod, '_vm_guest_ip', return_value=None), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('os.execvp') as mock_exec, \
             patch('sys.stderr', io.StringIO()), \
             patch('builtins.print'):
            substrate.open_shell(console=True)
        mock_exec.assert_called_once()
        self.assertEqual(mock_exec.call_args[0][0], 'socat')


# ── VMSubstrate.lifecycle() reboot ─────────────────────────────────────────────

class TestVMLifecycleReboot(unittest.TestCase):

    def _substrate(self):
        config = _make_vm_config()
        return VMSubstrate(config, None)

    def test_reboot_no_ip_exits_1(self):
        substrate = self._substrate()
        with patch.object(_vm_mod, '_vm_guest_ip', return_value=None), \
             patch('sys.stderr', io.StringIO()):
            with self.assertRaises(LifecycleError) as cm:
                substrate.lifecycle("reboot")
        self.assertEqual(cm.exception.returncode, 1)

    def test_reboot_ssh_success_prints_confirmation(self):
        substrate = self._substrate()
        with patch.object(_vm_mod, '_vm_guest_ip', return_value='10.0.0.5'), \
             patch('subprocess.run', return_value=_ok(returncode=0)):
            buf = io.StringIO()
            with patch('sys.stdout', buf):
                substrate.lifecycle("reboot")
        self.assertIn('soft-reboot initiated', buf.getvalue())

    def test_reboot_ssh_failure_exits_1(self):
        substrate = self._substrate()
        with patch.object(_vm_mod, '_vm_guest_ip', return_value='10.0.0.5'), \
             patch('subprocess.run', return_value=_ok(returncode=1)), \
             patch('sys.stderr', io.StringIO()):
            with self.assertRaises(LifecycleError) as cm:
                substrate.lifecycle("reboot")
        self.assertEqual(cm.exception.returncode, 1)


# ── VMSubstrate.reprovision() (non-recreate) ──────────────────────────────────

class TestVMReprovisionFlow(unittest.TestCase):

    def _substrate(self, lifecycle="cattle"):
        toml = f"""\
[workload]
name = "test-vm"
lifecycle = "{lifecycle}"

[vm]
image = "example.com/guest:latest"
"""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test-vm').mkdir()
            (p / 'test-vm' / 'workload.toml').write_text(toml)
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p):
                config = workloadctl_core.WorkloadConfig('test-vm')
        return VMSubstrate(config, None)

    def test_pet_vm_skips_rebuild_restarts_only(self):
        substrate = self._substrate(lifecycle="pet")
        with patch('subprocess.run', return_value=_ok(returncode=0)) as mock_run:
            buf = io.StringIO()
            with patch('sys.stdout', buf):
                result = substrate.reprovision()
        self.assertIsNone(result)
        self.assertIn('restarted (disk unchanged)', buf.getvalue())
        mock_run.assert_called_once()

    def test_pet_vm_restart_failure_raises_provision_failed(self):
        from substrate import ProvisionFailed
        substrate = self._substrate(lifecycle="pet")
        with patch('subprocess.run', return_value=_ok(returncode=1)), \
             patch('sys.stderr', io.StringIO()):
            with self.assertRaises(ProvisionFailed):
                substrate.reprovision()

    def test_cattle_vm_rebuild_and_restart_success(self):
        substrate = self._substrate(lifecycle="cattle")
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return _ok(returncode=0)

        with patch('subprocess.run', side_effect=fake_run):
            buf = io.StringIO()
            with patch('sys.stdout', buf):
                result = substrate.reprovision()
        self.assertIsNone(result)
        self.assertIn('rebuilt and restarted', buf.getvalue())
        self.assertTrue(any('workload-vm-build-disk' in str(c[0]) for c in calls))

    def test_cattle_vm_build_failure_raises_provision_failed(self):
        from substrate import ProvisionFailed
        substrate = self._substrate(lifecycle="cattle")

        def fake_run(cmd, **kw):
            if 'workload-vm-build-disk' in str(cmd[0]):
                return _ok(returncode=1)
            return _ok(returncode=0)

        with patch('subprocess.run', side_effect=fake_run), \
             patch('sys.stderr', io.StringIO()):
            with self.assertRaises(ProvisionFailed):
                substrate.reprovision()

    def test_cattle_vm_restart_failure_raises_provision_failed(self):
        from substrate import ProvisionFailed
        substrate = self._substrate(lifecycle="cattle")

        def fake_run(cmd, **kw):
            if 'workload-vm-build-disk' in str(cmd[0]):
                return _ok(returncode=0)
            return _ok(returncode=1)  # restart fails

        with patch('subprocess.run', side_effect=fake_run), \
             patch('sys.stderr', io.StringIO()):
            with self.assertRaises(ProvisionFailed):
                substrate.reprovision()


# ── VMSubstrate.rollback() pet guard ──────────────────────────────────────────

class TestVMRollbackPetGuard(unittest.TestCase):

    def test_pet_vm_rollback_exits_1(self):
        toml = """\
[workload]
name = "test-vm"
lifecycle = "pet"

[vm]
image = "example.com/guest:latest"
"""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test-vm').mkdir()
            (p / 'test-vm' / 'workload.toml').write_text(toml)
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p):
                config = workloadctl_core.WorkloadConfig('test-vm')
        substrate = VMSubstrate(config, None)
        buf = io.StringIO()
        with patch('sys.stderr', buf):
            with self.assertRaises(LifecycleError) as cm:
                substrate.rollback()
        self.assertEqual(cm.exception.returncode, 1)
        self.assertIn('pet', buf.getvalue())

    def test_no_targets_exits_1(self):
        config = _make_vm_config()
        substrate = VMSubstrate(config, None)
        with patch.object(substrate, 'rollback_targets', return_value=[]), \
             patch('sys.stderr', io.StringIO()):
            with self.assertRaises(LifecycleError) as cm:
                substrate.rollback()
        self.assertEqual(cm.exception.returncode, 1)

    def test_rollback_applies_latest_generation(self):
        config = _make_vm_config()
        substrate = VMSubstrate(config, None)
        targets = [
            {'label': 'system.qcow2.gen-1', 'gen': 1, 'path': Path('/tmp/g1')},
            {'label': 'system.qcow2.gen-2', 'gen': 2, 'path': Path('/tmp/g2')},
        ]
        with patch.object(substrate, 'rollback_targets', return_value=targets), \
             patch.object(substrate, 'rollback_to') as mock_rt:
            substrate.rollback()
        mock_rt.assert_called_once_with(targets[-1])


# ── _backup_impl / ContainerSubstrate.capture / _backup_vm / _print_backup_size

class TestBackupImplAndHelpers(unittest.TestCase):
    """_backup_impl() reads the workload TOML via workload_config_path(name) at
    call time (not just at WorkloadConfig construction), so the WORKLOAD_CONFIG_DIR
    patch must stay active for the whole test body, not just during _make_config()."""

    def setUp(self):
        self._cfg_dir = tempfile.mkdtemp()
        p = Path(self._cfg_dir)
        (p / 'test-wl').mkdir()
        (p / 'test-wl' / 'workload.toml').write_text(MINIMAL_TOML)
        self._cfg_patcher = patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p)
        self._cfg_patcher.start()
        self.addCleanup(self._cfg_patcher.stop)
        self.addCleanup(shutil.rmtree, self._cfg_dir, True)

    def _make_config(self):
        return workloadctl_core.WorkloadConfig('test-wl')

    def test_backup_container_writes_tar_and_prints_size(self):
        """ContainerSubstrate.capture() (cold) drives _backup_impl directly —
        no intermediate _backup_container delegation (B9)."""
        config = self._make_config()

        def fake_run(cmd, **kw):
            if cmd[:1] == ['tar']:
                # Simulate tar creating the output file.
                out_idx = cmd.index('-cf') + 1
                Path(cmd[out_idx]).write_bytes(b'x' * 42)
            return _ok(returncode=0)

        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'sub' / 'out.tar.zst'
            buf = io.StringIO()
            with _patch_uid(10001), \
                 patch('subprocess.run', side_effect=fake_run), \
                 patch.object(_backup_mod, 'auto_detect_credentials', return_value=set()), \
                 patch('sys.stdout', buf):
                size = ContainerSubstrate(config, None).capture(output, consistency='cold', quiet=False)
        self.assertEqual(size, 42)
        self.assertIn('Backup:', buf.getvalue())

    def test_backup_vm_writes_tar_and_prints_size(self):
        """_backup_vm() (the cold VM backup path) is called directly here
        rather than through _backup_vm_crash's fallback, so the mock in
        TestBackupVMCrash.test_inactive_vm_falls_back_to_cold never exercises
        its actual body."""
        p = Path(self._cfg_dir)
        (p / 'test-vm').mkdir()
        (p / 'test-vm' / 'workload.toml').write_text(VM_TOML)
        config = workloadctl_core.WorkloadConfig('test-vm')

        def fake_run(cmd, **kw):
            if cmd[:1] == ['tar']:
                out_idx = cmd.index('-cf') + 1
                Path(cmd[out_idx]).write_bytes(b'y' * 99)
            return _ok(returncode=0)

        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            buf = io.StringIO()
            with patch('subprocess.run', side_effect=fake_run), \
                 patch.object(_backup_mod, 'auto_detect_credentials', return_value=set()), \
                 patch('sys.stdout', buf):
                size = _backup_mod.backup_vm(config, output, quiet=False)
        self.assertEqual(size, 99)
        self.assertIn('Backup:', buf.getvalue())

    def test_backup_impl_stops_and_restarts_active_service(self):
        config = self._make_config()
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            if cmd[:1] == ['tar']:
                out_idx = cmd.index('-cf') + 1
                Path(cmd[out_idx]).write_bytes(b'data')
            if cmd[:2] == ['systemctl', 'is-active']:
                return _ok(returncode=0)  # active
            return _ok(returncode=0)

        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            with _patch_uid(10001), \
                 patch('subprocess.run', side_effect=fake_run), \
                 patch.object(_backup_mod, 'auto_detect_credentials', return_value=set()), \
                 patch.object(_backup_mod, 'restart_workload_service') as mock_r:
                _backup_mod.backup_impl(config, output, no_stop=False, quiet=True, vm=False)
        stop_calls = [c for c in calls if 'stop' in c]
        self.assertTrue(stop_calls, "service should be stopped when active and no_stop=False")
        mock_r.assert_called_once_with(10001, config.service_name, action="start")

    def test_backup_impl_vm_restart_uses_plain_systemctl(self):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            if cmd[:1] == ['tar']:
                out_idx = cmd.index('-cf') + 1
                Path(cmd[out_idx]).write_bytes(b'data')
            return _ok(returncode=0)

        # Override setUp's test-wl dir with a test-vm workload for this test.
        p = Path(self._cfg_dir)
        (p / 'test-vm').mkdir()
        (p / 'test-vm' / 'workload.toml').write_text(VM_TOML)
        config = workloadctl_core.WorkloadConfig('test-vm')

        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            with patch('subprocess.run', side_effect=fake_run), \
                 patch.object(_backup_mod, 'auto_detect_credentials', return_value=set()):
                _backup_mod.backup_impl(config, output, no_stop=False, quiet=True, vm=True)
        start_calls = [c for c in calls if 'start' in c]
        self.assertTrue(start_calls, "VM should be restarted via plain systemctl start")

    def test_backup_impl_no_stop_skips_stop_start(self):
        config = self._make_config()
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            if cmd[:1] == ['tar']:
                out_idx = cmd.index('-cf') + 1
                Path(cmd[out_idx]).write_bytes(b'data')
            return _ok(returncode=0)

        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            with patch('subprocess.run', side_effect=fake_run), \
                 patch.object(_backup_mod, 'auto_detect_credentials', return_value=set()):
                _backup_mod.backup_impl(config, output, no_stop=True, quiet=True, vm=False)
        self.assertFalse(any('stop' in c for c in calls))

    def test_backup_impl_copies_credentials(self):
        config = self._make_config()

        def fake_run(cmd, **kw):
            if cmd[:1] == ['tar']:
                out_idx = cmd.index('-cf') + 1
                Path(cmd[out_idx]).write_bytes(b'data')
            return _ok(returncode=0)

        with tempfile.TemporaryDirectory() as credstore_d, \
             tempfile.TemporaryDirectory() as out_d:
            credstore = Path(credstore_d)
            (credstore / 'mycred').write_text('secret')
            output = Path(out_d) / 'out.tar.zst'
            with patch('subprocess.run', side_effect=fake_run), \
                 patch.object(_backup_mod, 'auto_detect_credentials', return_value={'mycred'}), \
                 patch.object(_backup_mod, 'CREDSTORE_DIR', credstore):
                _backup_mod.backup_impl(config, output, no_stop=True, quiet=True, vm=False)
        # No assertion failure means the credential copy path executed without error.

    def test_backup_impl_missing_credential_warns(self):
        config = self._make_config()

        def fake_run(cmd, **kw):
            if cmd[:1] == ['tar']:
                out_idx = cmd.index('-cf') + 1
                Path(cmd[out_idx]).write_bytes(b'data')
            return _ok(returncode=0)

        with tempfile.TemporaryDirectory() as out_d:
            output = Path(out_d) / 'out.tar.zst'
            buf = io.StringIO()
            with patch('subprocess.run', side_effect=fake_run), \
                 patch.object(_backup_mod, 'auto_detect_credentials', return_value={'missing-cred'}), \
                 patch.object(_backup_mod, 'CREDSTORE_DIR', Path('/nonexistent-credstore')), \
                 patch('sys.stderr', buf):
                _backup_mod.backup_impl(config, output, no_stop=True, quiet=False, vm=False)
        # A skipped credential is a warning: stderr, so it survives --quiet and
        # stays out of a piped stdout.
        self.assertIn('not found', buf.getvalue())

    def test_credstore_dir_is_shared_and_encrypted(self):
        # Regression for the 2026-07 review: substrate carried a divergent
        # CREDSTORE_DIR = /etc/credstore while secrets are created/loaded from
        # /etc/credstore.encrypted, so backup captured nothing. Unit tests that
        # patch CREDSTORE_DIR to a temp dir can't catch that divergence — pin
        # the production default and that all consumers share one constant.
        import cmd_backup
        import cmd_secret
        self.assertEqual(workload_lib.CREDSTORE_DIR,
                         Path('/etc/credstore.encrypted'))
        self.assertIs(_backup_mod.CREDSTORE_DIR, workload_lib.CREDSTORE_DIR)
        self.assertIs(cmd_backup.CREDSTORE_DIR, workload_lib.CREDSTORE_DIR)
        self.assertIs(cmd_secret.CREDSTORE_DIR, workload_lib.CREDSTORE_DIR)

    def test_print_backup_size_formats_bytes(self):
        buf = io.StringIO()
        with patch('sys.stdout', buf):
            _backup_mod.print_backup_size(Path('/x'), 500)
        self.assertIn('500B', buf.getvalue())

    def test_print_backup_size_formats_kilobytes(self):
        buf = io.StringIO()
        with patch('sys.stdout', buf):
            _backup_mod.print_backup_size(Path('/x'), 5_000)
        self.assertIn('5.0K', buf.getvalue())

    def test_print_backup_size_formats_megabytes(self):
        buf = io.StringIO()
        with patch('sys.stdout', buf):
            _backup_mod.print_backup_size(Path('/x'), 5_000_000)
        self.assertIn('5.0M', buf.getvalue())

    def test_print_backup_size_formats_gigabytes(self):
        buf = io.StringIO()
        with patch('sys.stdout', buf):
            _backup_mod.print_backup_size(Path('/x'), 5_000_000_000)
        self.assertIn('5.0G', buf.getvalue())


# ── _vm_guest_ip() lookup chain ────────────────────────────────────────────────

class TestVmGuestIp(unittest.TestCase):

    def test_dnsmasq_lease_match(self):
        with tempfile.TemporaryDirectory() as d:
            run_dir = Path(d) / 'run'
            (run_dir).mkdir()
            (run_dir / 'bridge-managed').touch()
            lease_file = Path(d) / 'leases'
            lease_file.write_text("1234 aa:bb:cc:dd:ee:ff 192.168.1.5 myvm 01:aa\n")
            with patch('substrate_vm.Path'):
                # Only patch the bridge-managed marker check and lease file path;
                # simplest is to patch the two module-level Path constants directly.
                pass
        # Simpler: patch the two constants used inside the function.
        with patch.object(_vm_mod, 'VM_DHCP_LEASE_FILE') as mock_lease:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.leases', delete=False) as f:
                f.write("1234 aa:bb:cc:dd:ee:ff 192.168.1.5 myvm 01:aa\n")
                lease_path = Path(f.name)
            try:
                mock_lease.exists.return_value = True
                mock_lease.read_text.return_value = lease_path.read_text()
                with patch('pathlib.Path.exists', return_value=True):
                    ip = _vm_mod._vm_guest_ip('myvm')
            finally:
                lease_path.unlink()
        self.assertEqual(ip, '192.168.1.5')

    def test_no_bridge_managed_falls_to_arp(self):
        with patch('pathlib.Path.exists', return_value=False), \
             patch.object(_vm_mod, 'vm_mac_address', return_value='aa:bb:cc:dd:ee:ff'), \
             patch('subprocess.run') as mock_run:
            mock_run.side_effect = [
                _ok(stdout="192.168.1.9 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"),  # ip neigh
            ]
            ip = _vm_mod._vm_guest_ip('myvm')
        self.assertEqual(ip, '192.168.1.9')

    def test_arp_no_match_falls_to_mdns(self):
        with patch('pathlib.Path.exists', return_value=False), \
             patch.object(_vm_mod, 'vm_mac_address', return_value='aa:bb:cc:dd:ee:ff'), \
             patch('subprocess.run') as mock_run:
            mock_run.side_effect = [
                _ok(stdout="192.168.1.9 lladdr 11:22:33:44:55:66 REACHABLE\n"),  # no match
                _ok(returncode=0, stdout="192.168.1.20 myvm.local\n"),  # getent
            ]
            ip = _vm_mod._vm_guest_ip('myvm')
        self.assertEqual(ip, '192.168.1.20')

    def test_all_lookups_fail_returns_none(self):
        with patch('pathlib.Path.exists', return_value=False), \
             patch.object(_vm_mod, 'vm_mac_address', return_value='aa:bb:cc:dd:ee:ff'), \
             patch('subprocess.run') as mock_run:
            mock_run.side_effect = [
                _ok(stdout=""),
                _ok(returncode=2, stdout=""),
            ]
            ip = _vm_mod._vm_guest_ip('myvm')
        self.assertIsNone(ip)


# ── _accessible_at_config() endpoint parsing branches ─────────────────────────

class TestAccessibleAtConfig(unittest.TestCase):

    def test_host_network_mode(self):
        toml = """\
[workload]
name = "test-ep"

[container]
image = "example.com/test:latest"

[network]
mode = "host"
ports = ["8080/tcp"]
"""
        config = _make_config(toml, 'test-ep')
        result = _container_mod._accessible_at_config(config)
        self.assertEqual(result, [{"host": "localhost:8080", "container": None}])

    def test_ip_host_container_triple(self):
        toml = """\
[workload]
name = "test-ep"

[container]
image = "example.com/test:latest"

[network]
ports = ["127.0.0.1:8080:80"]
"""
        config = _make_config(toml, 'test-ep')
        result = _container_mod._accessible_at_config(config)
        self.assertEqual(result, [{"host": "127.0.0.1:8080", "container": "80"}])

    def test_dynamic_host_port(self):
        toml = """\
[workload]
name = "test-ep"

[container]
image = "example.com/test:latest"

[network]
ports = [":80"]
"""
        config = _make_config(toml, 'test-ep')
        result = _container_mod._accessible_at_config(config)
        self.assertEqual(result, [{"host": "localhost:(dynamic)", "container": "80"}])

    def test_no_ports_returns_empty(self):
        config = _make_config(SINGLE_TOML, 'test-wl')
        self.assertEqual(_container_mod._accessible_at_config(config), [])


if __name__ == '__main__':
    unittest.main()
