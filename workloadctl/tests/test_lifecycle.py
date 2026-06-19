#!/usr/bin/env python3
"""Tests for the lifecycle = "pet" | "cattle" feature (P2).

Covers:
  1. WorkloadConfig.lifecycle accessor (default "cattle", reads "pet").
  2. validate_single rejects invalid lifecycle values.
  3. Generator: cattle produces byte-identical --rm / podman-run units.
  4. Generator: pet produces create-once + start -a shape, no --rm, no rm.
  5. Generator: pet in pod/bridge mode falls back to cattle with a warning.
  6. ContainerSubstrate.reprovision(recreate=True): pet calls podman commit
     before destroying the container; cattle does not.
  7. ContainerSubstrate.reprovision (update path): pet calls podman commit
     before restarting; cattle does not.
  8. VMSubstrate.reprovision (update): pet skips disk rebuild / gen rotation;
     cattle still calls workload-vm-build-disk.
  9. VMSubstrate.rollback: pet exits non-zero without touching any disk;
     cattle continues normally.
"""

import io
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import types
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import MagicMock, call, patch

# ── lib path ──────────────────────────────────────────────────────────────────

_LIB = os.path.join(os.path.dirname(__file__), '..', 'lib')
sys.path.insert(0, _LIB)

import workloadctl_core
from workloadctl_core import WorkloadConfig
import substrate
from substrate import ContainerSubstrate, VMSubstrate

# ── generator helpers (shared with test_generator.py) ─────────────────────────

_GEN = os.path.join(os.path.dirname(__file__), '..', 'generators', 'workload-generate')


def _run_generator(config_dir, services_dir, sysusers_dir):
    env = os.environ.copy()
    env["WORKLOAD_CONFIG_DIR"] = str(config_dir)
    env["SYSUSERS_DIR"] = str(sysusers_dir)
    env["PYTHONPATH"] = _LIB
    env["WORKLOAD_GENERATE_LOG_STDERR"] = "1"
    return subprocess.run(
        [sys.executable, _GEN, str(services_dir)],
        capture_output=True, text=True, env=env,
    )


def _write_cfg(config_dir, name, toml_content):
    path = Path(config_dir) / f"{name}.toml"
    path.write_text(textwrap.dedent(toml_content))
    return path


# ── TOML fixtures ──────────────────────────────────────────────────────────────

_CATTLE_TOML = """\
[workload]
name = "cattle-wl"
enabled = true

[container]
image = "docker.io/nginx:latest"
"""

_PET_TOML = """\
[workload]
name = "pet-wl"
enabled = true
lifecycle = "pet"

[container]
image = "docker.io/nginx:latest"
"""

_PET_POD_TOML = """\
[workload]
name = "pet-pod"
enabled = true
lifecycle = "pet"

[[containers]]
name = "web"
[containers.container]
image = "docker.io/nginx:latest"

[[containers]]
name = "db"
[containers.container]
image = "docker.io/postgres:latest"
"""

_CONTAINER_TOML = """\
[workload]
name = "test-wl"
enabled = false

[container]
image = "example.com/test:latest"
"""

_PET_CONTAINER_TOML = """\
[workload]
name = "test-wl"
enabled = false
lifecycle = "pet"

[container]
image = "example.com/test:latest"
"""

_VM_TOML = """\
[workload]
name = "test-vm"
enabled = false

[vm]
image = "example.com/guest:latest"
"""

_PET_VM_TOML = """\
[workload]
name = "test-vm"
enabled = false
lifecycle = "pet"

[vm]
image = "example.com/guest:latest"
"""


def _make_config(toml: str, name: str) -> WorkloadConfig:
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / f'{name}.toml').write_text(toml)
        with patch.object(workloadctl_core, '_get_workload_dir', return_value=p):
            return WorkloadConfig(name)


# =============================================================================
# 1. WorkloadConfig.lifecycle accessor
# =============================================================================

class TestLifecycleAccessor(unittest.TestCase):

    def test_default_is_cattle(self):
        cfg = _make_config(_CONTAINER_TOML, 'test-wl')
        self.assertEqual(cfg.lifecycle, "cattle")

    def test_explicit_cattle(self):
        toml = _CONTAINER_TOML.replace(
            'enabled = false', 'enabled = false\nlifecycle = "cattle"'
        )
        cfg = _make_config(toml, 'test-wl')
        self.assertEqual(cfg.lifecycle, "cattle")

    def test_explicit_pet(self):
        cfg = _make_config(_PET_CONTAINER_TOML, 'test-wl')
        self.assertEqual(cfg.lifecycle, "pet")

    def test_vm_default_is_cattle(self):
        cfg = _make_config(_VM_TOML, 'test-vm')
        self.assertEqual(cfg.lifecycle, "cattle")

    def test_vm_pet(self):
        cfg = _make_config(_PET_VM_TOML, 'test-vm')
        self.assertEqual(cfg.lifecycle, "pet")


# =============================================================================
# 2. validate_single rejects invalid lifecycle values
# =============================================================================

class TestLifecycleValidation(unittest.TestCase):

    def _validate(self, toml, name):
        import cmd_admin
        cfg = _make_config(toml, name)
        manager = MagicMock()
        manager.get_all_configs.return_value = [cfg]
        return cmd_admin.validate_single(cfg, manager)

    def test_valid_cattle_passes(self):
        result = self._validate(_CONTAINER_TOML, 'test-wl')
        lifecycle_check = next(
            (c for c in result["checks"] if c["check"] == "lifecycle"), None
        )
        self.assertIsNotNone(lifecycle_check)
        self.assertTrue(lifecycle_check["passed"])

    def test_valid_pet_passes(self):
        result = self._validate(_PET_CONTAINER_TOML, 'test-wl')
        lifecycle_check = next(
            (c for c in result["checks"] if c["check"] == "lifecycle"), None
        )
        self.assertIsNotNone(lifecycle_check)
        self.assertTrue(lifecycle_check["passed"])

    def test_invalid_value_fails(self):
        bad_toml = _CONTAINER_TOML.replace(
            'enabled = false', 'enabled = false\nlifecycle = "immortal"'
        )
        result = self._validate(bad_toml, 'test-wl')
        lifecycle_check = next(
            (c for c in result["checks"] if c["check"] == "lifecycle"), None
        )
        self.assertIsNotNone(lifecycle_check)
        self.assertFalse(lifecycle_check["passed"])
        self.assertEqual(lifecycle_check["severity"], "error")
        self.assertIn("immortal", lifecycle_check["message"])

    def test_invalid_value_increments_error_count(self):
        bad_toml = _CONTAINER_TOML.replace(
            'enabled = false', 'enabled = false\nlifecycle = "immortal"'
        )
        result = self._validate(bad_toml, 'test-wl')
        self.assertGreater(result["errors"], 0)


# =============================================================================
# 3 & 4. Generator: cattle vs pet unit shape
# =============================================================================

class TestGeneratorLifecycleCattle(unittest.TestCase):
    """Cattle path must be byte-identical to the pre-lifecycle code."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def _service(self, name):
        return (Path(self.services_dir) / f"workload-{name}.service").read_text()

    def test_cattle_has_rm(self):
        _write_cfg(self.config_dir, "cattle-wl", _CATTLE_TOML)
        r = _run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(r.returncode, 0, r.stderr)
        svc = self._service("cattle-wl")
        self.assertIn("--rm", svc)

    def test_cattle_has_podman_run(self):
        _write_cfg(self.config_dir, "cattle-wl", _CATTLE_TOML)
        _run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        svc = self._service("cattle-wl")
        self.assertIn("ExecStart=/usr/bin/podman run", svc)

    def test_cattle_has_execstoppost_rm(self):
        _write_cfg(self.config_dir, "cattle-wl", _CATTLE_TOML)
        _run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        svc = self._service("cattle-wl")
        self.assertIn("ExecStopPost=-/usr/bin/podman rm -f", svc)

    def test_cattle_no_create_start_a(self):
        _write_cfg(self.config_dir, "cattle-wl", _CATTLE_TOML)
        _run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        svc = self._service("cattle-wl")
        self.assertNotIn("podman create", svc)
        self.assertNotIn("podman start -a", svc)


class TestGeneratorLifecyclePet(unittest.TestCase):
    """Pet path: create-once + start -a, no --rm, no ExecStopPost rm."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def _service(self, name):
        return (Path(self.services_dir) / f"workload-{name}.service").read_text()

    def test_pet_no_rm_flag(self):
        _write_cfg(self.config_dir, "pet-wl", _PET_TOML)
        r = _run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(r.returncode, 0, r.stderr)
        svc = self._service("pet-wl")
        # --rm must not appear anywhere in the service (not even in comments)
        for line in svc.splitlines():
            if line.lstrip().startswith("#"):
                continue
            self.assertNotIn("--rm", line, f"Unexpected --rm in: {line!r}")

    def test_pet_has_podman_create(self):
        _write_cfg(self.config_dir, "pet-wl", _PET_TOML)
        _run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        svc = self._service("pet-wl")
        # The create command appears as ExecStartPre
        self.assertIn("/usr/bin/podman create", svc)
        self.assertIn("ExecStartPre=-/usr/bin/podman create", svc)

    def test_pet_has_start_a(self):
        _write_cfg(self.config_dir, "pet-wl", _PET_TOML)
        _run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        svc = self._service("pet-wl")
        self.assertIn('ExecStart=/usr/bin/podman start -a "workload-pet-wl"', svc)

    def test_pet_no_execstoppost_rm(self):
        """Pet must not have a destructive ExecStopPost rm (overlay must survive stop)."""
        _write_cfg(self.config_dir, "pet-wl", _PET_TOML)
        _run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        svc = self._service("pet-wl")
        self.assertNotIn("ExecStopPost=-/usr/bin/podman rm", svc)

    def test_pet_has_execstop(self):
        """Pet must still have an ExecStop to stop the container gracefully."""
        _write_cfg(self.config_dir, "pet-wl", _PET_TOML)
        _run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        svc = self._service("pet-wl")
        self.assertIn("ExecStop=/usr/bin/podman stop", svc)


class TestGeneratorLifecyclePetPodFallback(unittest.TestCase):
    """Pet in pod mode falls back to cattle with a warning."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def test_pod_with_pet_falls_back_to_cattle(self):
        _write_cfg(self.config_dir, "pet-pod", _PET_POD_TOML)
        r = _run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(r.returncode, 0, r.stderr)
        # warning must mention the fallback
        self.assertIn("falling back to cattle", r.stderr)

    def test_pod_with_pet_produces_cattle_units(self):
        _write_cfg(self.config_dir, "pet-pod", _PET_POD_TOML)
        _run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        # pod member services use per-container names
        web_svc = (
            Path(self.services_dir) / "workload-pet-pod-web.service"
        ).read_text()
        self.assertIn("--rm", web_svc)
        self.assertNotIn("podman create", web_svc)


# =============================================================================
# 5. ContainerSubstrate.reprovision — snapshot-on-destroy
# =============================================================================

class _CfgDir:
    """Context manager: writes a TOML, patches WORKLOAD_DIR, returns config."""
    def __init__(self, toml, name):
        self._toml = toml
        self._name = name
        self._tmp = None
        self._patcher = None

    def __enter__(self):
        self._tmp = tempfile.mkdtemp()
        p = Path(self._tmp)
        (p / f'{self._name}.toml').write_text(self._toml)
        self._patcher = patch.object(workloadctl_core, '_get_workload_dir', return_value=p)
        self._patcher.start()
        return workloadctl_core.WorkloadConfig(self._name)

    def __exit__(self, *_):
        self._patcher.stop()
        shutil.rmtree(self._tmp, ignore_errors=True)


def _make_manager(user_exists=True):
    m = MagicMock()
    m.user_exists.return_value = user_exists
    m.podman.return_value = MagicMock()
    return m


class TestContainerReprovisionsSnapshot(unittest.TestCase):
    """snapshot-on-destroy: pet calls commit; cattle does not."""

    def _make_substrate(self, toml, name, user_exists=True):
        with _CfgDir(toml, name) as cfg:
            manager = _make_manager(user_exists)
            sub = ContainerSubstrate(cfg, manager)
            # keep cfg alive (CfgDir teardown would remove the temp dir,
            # but the config object is already parsed)
            sub._cfg_tmp = None
            return sub, cfg, manager

    def test_pet_recreate_calls_commit(self):
        with _CfgDir(_PET_CONTAINER_TOML, 'test-wl') as cfg:
            manager = _make_manager(user_exists=True)
            sub = ContainerSubstrate(cfg, manager)
            # Patch uid to avoid passwd lookup and restart to avoid systemctl
            with patch.object(type(cfg), 'uid', new_callable=lambda: property(lambda _: 12345)):
                with patch('workloadctl_core.restart_workload_service', return_value=None):
                    with patch.object(sub, '_pet_snapshot_and_remove') as mock_snap:
                        sub.reprovision(recreate=True)
            mock_snap.assert_called_once()

    def test_cattle_recreate_does_not_call_commit(self):
        with _CfgDir(_CONTAINER_TOML, 'test-wl') as cfg:
            manager = _make_manager(user_exists=True)
            sub = ContainerSubstrate(cfg, manager)
            with patch.object(type(cfg), 'uid', new_callable=lambda: property(lambda _: 12345)):
                with patch('workloadctl_core.restart_workload_service', return_value=None):
                    with patch.object(sub, '_pet_snapshot_and_remove') as mock_snap:
                        sub.reprovision(recreate=True)
            mock_snap.assert_not_called()

    def test_pet_pod_recreate_does_not_call_commit(self):
        """A pet workload in pod/bridge mode falls back to cattle (the generator
        emits cattle units for it), so the substrate must NOT snapshot either —
        config.container_name doesn't match the per-container pod names."""
        with _CfgDir(_PET_POD_TOML, 'pet-pod') as cfg:
            manager = _make_manager(user_exists=True)
            sub = ContainerSubstrate(cfg, manager)
            with patch.object(type(cfg), 'uid', new_callable=lambda: property(lambda _: 12345)):
                with patch('workloadctl_core.restart_workload_service', return_value=None):
                    with patch.object(sub, '_pet_snapshot_and_remove') as mock_snap:
                        sub.reprovision(recreate=True)
            mock_snap.assert_not_called()

    def test_pet_snapshot_and_remove_calls_commit(self):
        """_pet_snapshot_and_remove: calls pod.commit then pod.run rm."""
        with _CfgDir(_PET_CONTAINER_TOML, 'test-wl') as cfg:
            manager = _make_manager()
            pod_mock = MagicMock()
            sub = ContainerSubstrate(cfg, manager)
            sub._pet_snapshot_and_remove(pod_mock, "workload-test-wl")
            # commit must have been called
            pod_mock.commit.assert_called_once()
            commit_args = pod_mock.commit.call_args[0]
            self.assertEqual(commit_args[0], "workload-test-wl")
            snapshot_ref = commit_args[1]
            self.assertIn("localhost/workload-snapshot/test-wl:", snapshot_ref)
            # rm must have been called
            pod_mock.run.assert_called_once()
            rm_args = pod_mock.run.call_args[0]
            self.assertIn("rm", rm_args)
            self.assertIn("workload-test-wl", rm_args)

    def test_pet_snapshot_and_remove_tolerates_commit_failure(self):
        """If commit fails (e.g. container never ran), remove still proceeds."""
        with _CfgDir(_PET_CONTAINER_TOML, 'test-wl') as cfg:
            manager = _make_manager()
            pod_mock = MagicMock()
            pod_mock.commit.side_effect = RuntimeError("container not found")
            sub = ContainerSubstrate(cfg, manager)
            # Should not raise
            sub._pet_snapshot_and_remove(pod_mock, "workload-test-wl")
            pod_mock.run.assert_called_once()


# =============================================================================
# 6. VMSubstrate.reprovision — pet skips disk rebuild
# =============================================================================

class TestVMLifecycle(unittest.TestCase):

    @patch('subprocess.run')
    def test_cattle_vm_reprovision_calls_build_disk(self, mock_run):
        """Cattle VM update calls workload-vm-build-disk --update."""
        mock_run.return_value = CompletedProcess([], 0)
        with _CfgDir(_VM_TOML, 'test-vm') as cfg:
            manager = MagicMock()
            sub = VMSubstrate(cfg, manager)
            sub.reprovision()
        build_disk_calls = [
            c for c in mock_run.call_args_list
            if any('workload-vm-build-disk' in str(a) for a in c[0])
        ]
        self.assertTrue(build_disk_calls, "Expected workload-vm-build-disk call")

    @patch('subprocess.run')
    def test_pet_vm_reprovision_skips_build_disk(self, mock_run):
        """Pet VM update must NOT call workload-vm-build-disk."""
        mock_run.return_value = CompletedProcess([], 0)
        with _CfgDir(_PET_VM_TOML, 'test-vm') as cfg:
            manager = MagicMock()
            sub = VMSubstrate(cfg, manager)
            sub.reprovision()
        build_disk_calls = [
            c for c in mock_run.call_args_list
            if any('workload-vm-build-disk' in str(a) for a in c[0])
        ]
        self.assertFalse(build_disk_calls, "Pet VM must not call workload-vm-build-disk")

    @patch('subprocess.run')
    def test_pet_vm_reprovision_still_restarts(self, mock_run):
        """Pet VM update must still restart the service."""
        mock_run.return_value = CompletedProcess([], 0)
        with _CfgDir(_PET_VM_TOML, 'test-vm') as cfg:
            manager = MagicMock()
            sub = VMSubstrate(cfg, manager)
            sub.reprovision()
        restart_calls = [
            c for c in mock_run.call_args_list
            if 'restart' in str(c[0])
        ]
        self.assertTrue(restart_calls, "Pet VM must still restart the service")

    @patch('subprocess.run')
    def test_cattle_vm_recreate_does_not_skip_setup_restart(self, mock_run):
        """Cattle VM recreate: re-renders cloud-init + restarts QEMU."""
        mock_run.return_value = CompletedProcess([], 0)
        with _CfgDir(_VM_TOML, 'test-vm') as cfg:
            manager = MagicMock()
            sub = VMSubstrate(cfg, manager)
            sub.reprovision(recreate=True)
        calls_str = str(mock_run.call_args_list)
        self.assertIn("setup.service", calls_str)

    # ── VM rollback pet guard ─────────────────────────────────────────────────

    def test_pet_vm_rollback_exits_nonzero(self):
        """Pet VM rollback must exit non-zero (no gens exist)."""
        with _CfgDir(_PET_VM_TOML, 'test-vm') as cfg:
            manager = MagicMock()
            sub = VMSubstrate(cfg, manager)
            with self.assertRaises(SystemExit) as cm:
                sub.rollback()
            self.assertNotEqual(cm.exception.code, 0)

    def test_pet_vm_rollback_does_not_touch_disk(self):
        """Pet VM rollback must not call subprocess.run (no disk rotation)."""
        with _CfgDir(_PET_VM_TOML, 'test-vm') as cfg:
            manager = MagicMock()
            sub = VMSubstrate(cfg, manager)
            with patch('subprocess.run') as mock_run:
                with self.assertRaises(SystemExit):
                    sub.rollback()
                mock_run.assert_not_called()

    def test_cattle_vm_rollback_uses_gen_snapshots(self):
        """Cattle VM rollback proceeds when gens exist."""
        with _CfgDir(_VM_TOML, 'test-vm') as cfg:
            manager = MagicMock()
            sub = VMSubstrate(cfg, manager)
            # Provide a fake gen so rollback_targets() returns something
            with tempfile.TemporaryDirectory() as hd:
                gen_path = Path(hd) / "system.qcow2.gen-1"
                gen_path.write_bytes(b"")
                active = Path(hd) / "system.qcow2"
                active.write_bytes(b"")
                with patch.object(type(cfg), 'home_dir', new_callable=lambda: property(lambda _: Path(hd))):
                    with patch('subprocess.run', return_value=CompletedProcess([], 0)):
                        # Should NOT raise SystemExit
                        sub.rollback()


if __name__ == '__main__':
    unittest.main()
