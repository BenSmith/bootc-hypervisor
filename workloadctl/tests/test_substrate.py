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

import workloadctl_core
from substrate import (
    ContainerSubstrate,
    VMSubstrate,
    NotApplicable,
    get_substrate,
    _ignore_vm_rebuild,
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
        (tmp_path / f'{self._name}.toml').write_text(self._toml)
        self._patcher = patch.object(workloadctl_core, 'WORKLOAD_DIR', tmp_path)
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
        (p / 'test-vm.toml').write_text(VM_TOML)
        with patch.object(workloadctl_core, '_get_workload_dir', return_value=p):
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
            (p / 'test-vm.toml').write_text(VM_TOML)
            args = _args(workload='test-vm', json=False, follow=False)
            manager = MagicMock()
            manager.user_exists.return_value = True
            buf_out = io.StringIO()
            buf_err = io.StringIO()
            with patch.object(workloadctl_core, '_get_workload_dir', return_value=p), \
                 patch('sys.stdout', buf_out), patch('sys.stderr', buf_err):
                with self.assertRaises(SystemExit) as cm:
                    cmd_inspect.cmd_stats(args, manager)
            self.assertEqual(cm.exception.code, 0)
            output = buf_out.getvalue() + buf_err.getvalue()
            self.assertIn('not applicable', output.lower())


# ── VMSubstrate.capture() with --no-stop ─────────────────────────────────────

class TestVMBackupNoStop(unittest.TestCase):

    def _make_config(self):
        return _make_vm_config()

    def test_no_stop_exits_nonzero(self):
        config = self._make_config()
        substrate = VMSubstrate(config, None)
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            buf = io.StringIO()
            with patch('sys.stderr', buf):
                with self.assertRaises(SystemExit) as cm:
                    substrate.capture(output, no_stop=True)
        self.assertNotEqual(cm.exception.code, 0)

    def test_no_stop_error_message(self):
        config = self._make_config()
        substrate = VMSubstrate(config, None)
        buf = io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'out.tar.zst'
            with patch('sys.stderr', buf):
                with self.assertRaises(SystemExit):
                    substrate.capture(output, no_stop=True)
        self.assertIn('--no-stop', buf.getvalue())

    def test_cmd_backup_vm_no_stop_exits_nonzero(self):
        """cmd_backup --no-stop on a VM workload exits non-zero (VM guard, not require_root)."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test-vm.toml').write_text(VM_TOML)
            args = _args(
                workload='test-vm', all=False, no_stop=True, json=False, output=None,
            )
            manager = MagicMock()
            buf_err = io.StringIO()
            with patch.object(workloadctl_core, '_get_workload_dir', return_value=p), \
                 patch.object(cmd_backup, 'require_root'), \
                 patch('sys.stderr', buf_err):
                with self.assertRaises(SystemExit) as cm:
                    cmd_backup.cmd_backup(args, manager)
            self.assertNotEqual(cm.exception.code, 0)
            # Should mention the VM-specific reason, not a generic error
            self.assertIn('vm', buf_err.getvalue().lower())


# ── _ignore_vm_rebuild ────────────────────────────────────────────────────────

class TestIgnoreVMRebuild(unittest.TestCase):

    def test_skips_system_qcow2(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            ignore = _ignore_vm_rebuild(base)
            skipped = ignore(str(base), ['system.qcow2', 'data.qcow2', 'cloud-init.iso'])
        self.assertIn('system.qcow2', skipped)
        self.assertNotIn('data.qcow2', skipped)
        self.assertNotIn('cloud-init.iso', skipped)

    def test_skips_gen_variants(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            ignore = _ignore_vm_rebuild(base)
            contents = ['system.qcow2.gen-1', 'system.qcow2.gen-2', 'data.qcow2']
            skipped = ignore(str(base), contents)
        self.assertIn('system.qcow2.gen-1', skipped)
        self.assertIn('system.qcow2.gen-2', skipped)
        self.assertNotIn('data.qcow2', skipped)

    def test_skips_image_cache(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            ignore = _ignore_vm_rebuild(base)
            contents = ['fedora.image-cache', 'data.qcow2']
            skipped = ignore(str(base), contents)
        self.assertIn('fedora.image-cache', skipped)
        self.assertNotIn('data.qcow2', skipped)

    def test_does_not_skip_in_subdirs(self):
        """Rebuild artifacts outside the base dir are not skipped."""
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            ignore = _ignore_vm_rebuild(base)
            subdir = str(base / 'subdir')
            skipped = ignore(subdir, ['system.qcow2'])
        self.assertNotIn('system.qcow2', skipped)


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
            (p / 'test-wl.toml').write_text(toml)
            args = _args(workload='test-wl', json=True)
            manager = MagicMock()
            manager.user_exists.return_value = user_exists
            # container_status returns a plain string so JSON serialization works
            manager.podman.return_value.container_status.return_value = "running"
            manager.podman.return_value.container_health.return_value = None
            buf_out = io.StringIO()
            buf_err = io.StringIO()
            with patch.object(workloadctl_core, '_get_workload_dir', return_value=p), \
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


if __name__ == '__main__':
    unittest.main()
