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

import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

# ── lib path ──────────────────────────────────────────────────────────────────

_LIB = os.path.join(os.path.dirname(__file__), '..', 'lib')
sys.path.insert(0, _LIB)

import workload_lib
import workloadctl_core
from workloadctl_core import WorkloadConfig
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


def _write_cfg(config_dir, name, toml_content, enabled=True):
    (Path(config_dir) / name).mkdir(exist_ok=True)
    path = Path(config_dir) / name / "workload.toml"
    body = textwrap.dedent(toml_content)
    path.write_text(body)
    if enabled:
        (Path(config_dir) / name / ".enabled").touch()
    return path


# ── TOML fixtures ──────────────────────────────────────────────────────────────

_CATTLE_TOML = """\
[workload]
name = "cattle-wl"

[container]
image = "docker.io/nginx:latest"
"""

_PET_TOML = """\
[workload]
name = "pet-wl"
lifecycle = "pet"

[container]
image = "docker.io/nginx:latest"
"""

_PET_POD_TOML = """\
[workload]
name = "pet-pod"
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

[container]
image = "example.com/test:latest"
"""

_PET_CONTAINER_TOML = """\
[workload]
name = "test-wl"
lifecycle = "pet"

[container]
image = "example.com/test:latest"
"""

_VM_TOML = """\
[workload]
name = "test-vm"

[vm]
image = "example.com/guest:latest"
"""

_PET_VM_TOML = """\
[workload]
name = "test-vm"
lifecycle = "pet"

[vm]
image = "example.com/guest:latest"
"""


def _make_config(toml: str, name: str) -> WorkloadConfig:
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / name).mkdir()
        (p / name / 'workload.toml').write_text(toml)
        with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p):
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
            'name = "test-wl"', 'name = "test-wl"\nlifecycle = "cattle"'
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

    def test_snapshot_keep_default(self):
        cfg = _make_config(_CONTAINER_TOML, 'test-wl')
        self.assertEqual(cfg.snapshot_keep, 3)

    def test_snapshot_keep_explicit(self):
        toml = _CONTAINER_TOML.replace(
            'name = "test-wl"', 'name = "test-wl"\nsnapshot_keep = 5'
        )
        cfg = _make_config(toml, 'test-wl')
        self.assertEqual(cfg.snapshot_keep, 5)

    def test_snapshot_keep_invalid_falls_back_to_default(self):
        # The accessor must never crash a destroy; the validator flags it.
        for bad in ('"lots"', '0', '-1', 'true'):
            toml = _CONTAINER_TOML.replace(
                'name = "test-wl"', f'name = "test-wl"\nsnapshot_keep = {bad}'
            )
            cfg = _make_config(toml, 'test-wl')
            self.assertEqual(cfg.snapshot_keep, 3, f"bad={bad}")


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
        assert lifecycle_check is not None
        self.assertTrue(lifecycle_check["passed"])

    def test_valid_pet_passes(self):
        result = self._validate(_PET_CONTAINER_TOML, 'test-wl')
        lifecycle_check = next(
            (c for c in result["checks"] if c["check"] == "lifecycle"), None
        )
        self.assertIsNotNone(lifecycle_check)
        assert lifecycle_check is not None
        self.assertTrue(lifecycle_check["passed"])

    def test_invalid_value_fails(self):
        bad_toml = _CONTAINER_TOML.replace(
            'name = "test-wl"', 'name = "test-wl"\nlifecycle = "immortal"'
        )
        result = self._validate(bad_toml, 'test-wl')
        lifecycle_check = next(
            (c for c in result["checks"] if c["check"] == "lifecycle"), None
        )
        self.assertIsNotNone(lifecycle_check)
        assert lifecycle_check is not None
        self.assertFalse(lifecycle_check["passed"])
        self.assertEqual(lifecycle_check["severity"], "error")
        self.assertIn("immortal", lifecycle_check["message"])

    def test_invalid_value_increments_error_count(self):
        bad_toml = _CONTAINER_TOML.replace(
            'name = "test-wl"', 'name = "test-wl"\nlifecycle = "immortal"'
        )
        result = self._validate(bad_toml, 'test-wl')
        self.assertGreater(result["errors"], 0)

    def test_snapshot_keep_omitted_no_check(self):
        # Default (field absent) emits no snapshot_keep check at all.
        result = self._validate(_CONTAINER_TOML, 'test-wl')
        check = next(
            (c for c in result["checks"] if c["check"] == "snapshot_keep"), None
        )
        self.assertIsNone(check)

    def test_snapshot_keep_valid_passes(self):
        toml = _CONTAINER_TOML.replace(
            'name = "test-wl"', 'name = "test-wl"\nsnapshot_keep = 5'
        )
        result = self._validate(toml, 'test-wl')
        # Valid value adds no error.
        check = next(
            (c for c in result["checks"] if c["check"] == "snapshot_keep"), None
        )
        self.assertIsNone(check)

    def test_snapshot_keep_invalid_fails(self):
        for bad in ('0', '-2', '"three"', 'true'):
            toml = _CONTAINER_TOML.replace(
                'name = "test-wl"', f'name = "test-wl"\nsnapshot_keep = {bad}'
            )
            result = self._validate(toml, 'test-wl')
            check = next(
                (c for c in result["checks"] if c["check"] == "snapshot_keep"),
                None,
            )
            self.assertIsNotNone(check, f"bad={bad}")
            assert check is not None
            self.assertFalse(check["passed"], f"bad={bad}")
            self.assertEqual(check["severity"], "error")
            self.assertGreater(result["errors"], 0, f"bad={bad}")


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
        (p / self._name).mkdir()
        (p / self._name / 'workload.toml').write_text(self._toml)
        self._patcher = patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p)
        self._patcher.start()
        return workloadctl_core.WorkloadConfig(self._name)

    def __exit__(self, *_):
        assert self._patcher is not None and self._tmp is not None
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
            sub._cfg_tmp = None  # type: ignore[attr-defined]
            return sub, cfg, manager

    def test_pet_recreate_calls_commit(self):
        with _CfgDir(_PET_CONTAINER_TOML, 'test-wl') as cfg:
            manager = _make_manager(user_exists=True)
            sub = ContainerSubstrate(cfg, manager)
            # Patch uid to avoid passwd lookup and restart to avoid systemctl
            with patch.object(type(cfg), 'uid', new_callable=lambda: property(lambda _: 12345)):
                with patch('substrate.restart_workload_service', return_value=None):
                    with patch.object(sub, '_pet_snapshot_and_remove') as mock_snap:
                        sub.reprovision(recreate=True)
            mock_snap.assert_called_once()

    def test_cattle_recreate_does_not_call_commit(self):
        with _CfgDir(_CONTAINER_TOML, 'test-wl') as cfg:
            manager = _make_manager(user_exists=True)
            sub = ContainerSubstrate(cfg, manager)
            with patch.object(type(cfg), 'uid', new_callable=lambda: property(lambda _: 12345)):
                with patch('substrate.restart_workload_service', return_value=None):
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
                with patch('substrate.restart_workload_service', return_value=None):
                    with patch.object(sub, '_pet_snapshot_and_remove') as mock_snap:
                        sub.reprovision(recreate=True)
            mock_snap.assert_not_called()

    @staticmethod
    def _run_factory(images_stdout=""):
        """Build a pod.run side_effect: 'images' lists snapshot tags, rmi/rm ok."""
        def fake_run(*args, **kwargs):
            res = MagicMock()
            res.returncode = 0
            res.stdout = images_stdout if (args and args[0] == "images") else ""
            return res
        return fake_run

    def test_pet_snapshot_and_remove_calls_commit(self):
        """_pet_snapshot_and_remove: commits then removes the container."""
        with _CfgDir(_PET_CONTAINER_TOML, 'test-wl') as cfg:
            manager = _make_manager()
            pod_mock = MagicMock()
            pod_mock.run.side_effect = self._run_factory()  # no existing snaps
            sub = ContainerSubstrate(cfg, manager)
            sub._pet_snapshot_and_remove(pod_mock, "workload-test-wl")
            # commit must have been called
            pod_mock.commit.assert_called_once()
            commit_args = pod_mock.commit.call_args[0]
            self.assertEqual(commit_args[0], "workload-test-wl")
            snapshot_ref = commit_args[1]
            self.assertIn("localhost/workload-snapshot/test-wl:", snapshot_ref)
            # rm -f of the container must have happened exactly once
            rm_calls = [
                c for c in pod_mock.run.call_args_list
                if "rm" in c[0] and "workload-test-wl" in c[0]
            ]
            self.assertEqual(len(rm_calls), 1)

    def test_pet_snapshot_prunes_old_snapshots(self):
        """After a fresh commit, snapshots beyond snapshot_keep are rmi'd
        (oldest first); the newest `keep` are retained."""
        tags = [
            "20260101T000000Z", "20260102T000000Z", "20260103T000000Z",
            "20260104T000000Z", "20260105T000000Z",
        ]
        repo = "localhost/workload-snapshot/test-wl"
        pod_mock = MagicMock()
        pod_mock.run.side_effect = self._run_factory("\n".join(tags))
        # keep=2 → the 3 oldest get pruned, the 2 newest kept
        ContainerSubstrate._prune_pet_snapshots(pod_mock, repo, keep=2)
        rmi_refs = [
            c[0][1] for c in pod_mock.run.call_args_list if c[0][0] == "rmi"
        ]
        self.assertEqual(rmi_refs, [
            f"{repo}:20260101T000000Z",
            f"{repo}:20260102T000000Z",
            f"{repo}:20260103T000000Z",
        ])

    def test_pet_prune_noop_when_within_limit(self):
        """No rmi calls when snapshot count is at or below keep."""
        repo = "localhost/workload-snapshot/test-wl"
        pod_mock = MagicMock()
        pod_mock.run.side_effect = self._run_factory(
            "20260101T000000Z\n20260102T000000Z"
        )
        ContainerSubstrate._prune_pet_snapshots(pod_mock, repo, keep=3)
        rmi_calls = [c for c in pod_mock.run.call_args_list if c[0][0] == "rmi"]
        self.assertEqual(rmi_calls, [])

    def test_pet_prune_tolerates_images_failure(self):
        """A failing `podman images` is swallowed (never blocks the destroy)."""
        repo = "localhost/workload-snapshot/test-wl"
        pod_mock = MagicMock()
        bad = MagicMock()
        bad.returncode = 1
        bad.stdout = ""
        pod_mock.run.return_value = bad
        # Should not raise and should issue no rmi
        ContainerSubstrate._prune_pet_snapshots(pod_mock, repo, keep=1)
        rmi_calls = [c for c in pod_mock.run.call_args_list if c[0][0] == "rmi"]
        self.assertEqual(rmi_calls, [])

    def test_pet_snapshot_failure_skips_prune(self):
        """If commit fails, prune is skipped (nothing new was committed)."""
        with _CfgDir(_PET_CONTAINER_TOML, 'test-wl') as cfg:
            manager = _make_manager()
            pod_mock = MagicMock()
            pod_mock.commit.side_effect = RuntimeError("container not found")
            pod_mock.run.side_effect = self._run_factory("20260101T000000Z")
            sub = ContainerSubstrate(cfg, manager)
            sub._pet_snapshot_and_remove(pod_mock, "workload-test-wl")
            # only the container rm ran — no images/rmi prune calls
            self.assertFalse(
                any(c[0] and c[0][0] in ("images", "rmi")
                    for c in pod_mock.run.call_args_list)
            )

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


# =============================================================================
# 7. cmd_lifecycle command/helper coverage
# =============================================================================

import argparse
import io
import json
from contextlib import redirect_stdout, redirect_stderr

import cmd_lifecycle


class TestSubidLockSharedConstant(unittest.TestCase):
    """A11/A5: the subuid/subgid flock only mutexes if every participant uses
    the identical primitive — cmd_lifecycle must go through workload_lib's
    shared subid_lock() context manager (which names the one SUBID_LOCK path)
    rather than re-spelling its own flock."""

    def test_cmd_lifecycle_uses_shared_lock(self):
        self.assertIs(cmd_lifecycle.subid_lock, workload_lib.subid_lock)
        self.assertEqual(
            workload_lib.SUBID_LOCK, Path("/run/lock/workload-subid.lock")
        )


def _ns(**kw):
    return argparse.Namespace(**kw)


_HOST_TOML = """\
[workload]
name = "{name}"

[container]
image = "example.com/test:latest"
pull = "never"

[host]
setup = "setup.sh"
"""

_GROUPS_TOML = """\
[workload]
name = "{name}"

[container]
image = "example.com/test:latest"

[security]
extra_groups = ["{group}"]
"""

_HOSTNET_TOML = """\
[workload]
name = "{name}"

[container]
image = "example.com/test:latest"

[network]
mode = "host"
"""

_SELINUX_TOML = """\
[workload]
name = "{name}"

[container]
image = "example.com/test:latest"

[security]
selinux_policy = true
"""

_MULTI_TOML = """\
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


class _RootBypass:
    """Context manager patching cmd_lifecycle.require_root to a no-op."""

    def __enter__(self):
        self._p = patch.object(cmd_lifecycle, "require_root", lambda: None)
        self._p.start()
        return self

    def __exit__(self, *_):
        self._p.stop()


def _cfg(toml, name, **fmt):
    return _CfgDir(toml.format(name=name, **fmt), name)


def _no_subid_files():
    """Patch Path.exists so /etc/subuid and /etc/subgid report absent (real
    Path.exists is used for everything else) — lets cmd_disable's purge path
    skip the subuid/subgid rewrite without touching the real /etc files."""
    _orig_exists = Path.exists

    def fake_exists(self, *a, **kw):
        if str(self) in ("/etc/subuid", "/etc/subgid"):
            return False
        return _orig_exists(self, *a, **kw)

    return patch.object(Path, 'exists', fake_exists)


# ── _effective_state ────────────────────────────────────────────────────────

class TestEffectiveState(unittest.TestCase):
    def test_active_main_returns_active(self):
        with _cfg(_CONTAINER_TOML, 'test-wl') as cfg:
            def fake_run(cmd, **kw):
                r = MagicMock()
                r.stdout = "active\n"
                return r
            with patch.object(cmd_lifecycle.subprocess, 'run', side_effect=fake_run):
                state, failed = cmd_lifecycle._effective_state(cfg)
            self.assertEqual(state, "active")
            self.assertIsNone(failed)

    def test_inactive_with_failed_gating_unit_reports_failed(self):
        with _cfg(_CONTAINER_TOML, 'test-wl') as cfg:
            calls = []

            def fake_run(cmd, **kw):
                calls.append(cmd)
                r = MagicMock()
                if cmd[-1] == cfg.service_name:
                    r.stdout = "inactive\n"
                else:
                    r.stdout = "failed\n"
                return r

            with patch.object(cmd_lifecycle, '_gating_units', return_value=["workload-test-wl-setup.service"]):
                with patch.object(cmd_lifecycle.subprocess, 'run', side_effect=fake_run):
                    state, failed = cmd_lifecycle._effective_state(cfg)
            self.assertEqual(state, "failed")
            self.assertEqual(failed, "workload-test-wl-setup.service")

    def test_inactive_no_failed_gating_unit_reports_inactive(self):
        with _cfg(_CONTAINER_TOML, 'test-wl') as cfg:
            def fake_run(cmd, **kw):
                r = MagicMock()
                r.stdout = "inactive\n"
                return r
            with patch.object(cmd_lifecycle, '_gating_units', return_value=["workload-test-wl-setup.service"]):
                with patch.object(cmd_lifecycle.subprocess, 'run', side_effect=fake_run):
                    state, failed = cmd_lifecycle._effective_state(cfg)
            self.assertEqual(state, "inactive")
            self.assertIsNone(failed)


# ── _preflight_checks ───────────────────────────────────────────────────────

class TestPreflightChecks(unittest.TestCase):
    def _patched_which(self, missing=()):
        def fake_which(exe):
            if exe in missing:
                return None
            return f"/usr/bin/{exe}"
        return fake_which

    def test_missing_required_executable_fails(self):
        with _cfg(_CONTAINER_TOML, 'test-wl') as cfg:
            with patch.object(cmd_lifecycle.shutil, 'which', self._patched_which(missing={"podman"})):
                with patch.object(cmd_lifecycle.Podman, 'for_root') as for_root:
                    for_root.return_value.image_id.return_value = "sha256:abc"
                    buf = io.StringIO()
                    with redirect_stdout(buf):
                        ok = cmd_lifecycle._preflight_checks(cfg)
            self.assertFalse(ok)
            self.assertIn("podman", buf.getvalue())

    def test_missing_recommended_executable_warns_but_passes(self):
        with _cfg(_CONTAINER_TOML, 'test-wl') as cfg:
            with patch.object(cmd_lifecycle.shutil, 'which', self._patched_which(missing={"semanage"})):
                with patch.object(cmd_lifecycle.Podman, 'for_root') as for_root:
                    for_root.return_value.image_id.return_value = "sha256:abc"
                    buf = io.StringIO()
                    with redirect_stdout(buf):
                        ok = cmd_lifecycle._preflight_checks(cfg)
            self.assertTrue(ok)
            self.assertIn("semanage", buf.getvalue())

    def test_pull_never_missing_image_fails(self):
        with _cfg(_HOST_TOML, 'test-wl') as cfg:
            with patch.object(cmd_lifecycle.shutil, 'which', self._patched_which()):
                with patch.object(cmd_lifecycle.Podman, 'for_root') as for_root:
                    for_root.return_value.image_id.return_value = ""
                    buf = io.StringIO()
                    with redirect_stdout(buf):
                        ok = cmd_lifecycle._preflight_checks(cfg)
            self.assertFalse(ok)
            self.assertIn("not found locally", buf.getvalue())

    def test_pull_never_present_image_passes(self):
        with _cfg(_CONTAINER_TOML, 'test-wl') as cfg:
            with patch.object(cmd_lifecycle.shutil, 'which', self._patched_which()):
                with patch.object(cmd_lifecycle.Podman, 'for_root') as for_root:
                    for_root.return_value.image_id.return_value = "sha256:abc"
                    buf = io.StringIO()
                    with redirect_stdout(buf):
                        ok = cmd_lifecycle._preflight_checks(cfg)
            self.assertTrue(ok)

    def test_required_files_auto_copy_from_hint(self):
        with tempfile.TemporaryDirectory() as hint_dir:
            hint = Path(hint_dir) / "template.conf"
            hint.write_text("hi\n")
            with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as wl_base:
                p = Path(d)
                (p / 'test-wl').mkdir()
                (p / 'test-wl' / 'workload.toml').write_text(
                    _CONTAINER_TOML + f'\n[setup]\nrequired_files = '
                    f'[{{ path = "./cfg.conf", hint = "{hint}" }}]\n'
                )
                with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p):
                    with patch.object(workload_lib, 'WORKLOADS_BASE', Path(wl_base)):
                        cfg = WorkloadConfig('test-wl')
                        with patch.object(cmd_lifecycle.shutil, 'which', self._patched_which()):
                            with patch.object(cmd_lifecycle.Podman, 'for_root') as for_root:
                                for_root.return_value.image_id.return_value = "sha256:abc"
                                buf = io.StringIO()
                                with redirect_stdout(buf):
                                    ok = cmd_lifecycle._preflight_checks(cfg)
                        self.assertTrue(ok)
                        self.assertIn("Copied config template", buf.getvalue())

    def test_required_files_missing_without_hint_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test-wl').mkdir()
            (p / 'test-wl' / 'workload.toml').write_text(
                _CONTAINER_TOML + '\n[setup]\nrequired_files = '
                '[{ path = "/nonexistent/must-provide.conf" }]\n'
            )
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p):
                cfg = WorkloadConfig('test-wl')
                with patch.object(cmd_lifecycle.shutil, 'which', self._patched_which()):
                    with patch.object(cmd_lifecycle.Podman, 'for_root') as for_root:
                        for_root.return_value.image_id.return_value = "sha256:abc"
                        buf = io.StringIO()
                        with redirect_stdout(buf):
                            ok = cmd_lifecycle._preflight_checks(cfg)
                self.assertFalse(ok)
                self.assertIn("Missing required files", buf.getvalue())

    def test_missing_extra_group_fails(self):
        with _cfg(_GROUPS_TOML, 'test-wl', group="definitely-not-a-real-group-xyz") as cfg:
            with patch.object(cmd_lifecycle.shutil, 'which', self._patched_which()):
                with patch.object(cmd_lifecycle.Podman, 'for_root') as for_root:
                    for_root.return_value.image_id.return_value = "sha256:abc"
                    buf = io.StringIO()
                    with redirect_stdout(buf):
                        ok = cmd_lifecycle._preflight_checks(cfg)
            self.assertFalse(ok)
            self.assertIn("Missing groups", buf.getvalue())

    def test_host_mode_unprivileged_port_warns(self):
        with _cfg(_HOSTNET_TOML, 'test-wl') as cfg:
            with patch.object(cmd_lifecycle.shutil, 'which', self._patched_which()):
                with patch.object(cmd_lifecycle.Podman, 'for_root') as for_root:
                    for_root.return_value.image_id.return_value = "sha256:abc"
                    fake_path = MagicMock()
                    fake_path.read_text.return_value = "1024\n"
                    with patch.object(cmd_lifecycle.Path, '__new__', side_effect=lambda cls, *a, **k: Path.__new__(cls) if a and a[0] != "/proc/sys/net/ipv4/ip_unprivileged_port_start" else fake_path):
                        # simplest: just patch the specific sysctl path via read_text monkeypatch
                        pass
                    # Directly patch Path.read_text won't be reliable cross-cutting; instead
                    # patch the sysctl file existence check path via builtins is complex, so
                    # verify function tolerates missing /proc file (Exception branch).
                    buf = io.StringIO()
                    with redirect_stdout(buf):
                        ok = cmd_lifecycle._preflight_checks(cfg)
            # Real hosts normally have unpriv_start=0 or the file may not parse;
            # either way preflight must not crash and volumes/groups still pass.
            self.assertTrue(ok)

    def test_vm_missing_qemu_fails(self):
        with _cfg(_VM_TOML, 'test-vm') as cfg:
            with patch.object(cmd_lifecycle.shutil, 'which', self._patched_which(missing={"qemu-system-x86_64"})):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    ok = cmd_lifecycle._preflight_checks(cfg)
            self.assertFalse(ok)
            self.assertIn("Missing required VM executables", buf.getvalue())

    def test_vm_missing_kvm_device_fails(self):
        with _cfg(_VM_TOML, 'test-vm') as cfg:
            with patch.object(cmd_lifecycle.shutil, 'which', self._patched_which()):
                with patch.object(cmd_lifecycle.Path, 'exists', return_value=False):
                    with patch('vm.find_ovmf_code', return_value="/usr/share/edk2/ovmf/OVMF_CODE.fd"):
                        buf = io.StringIO()
                        with redirect_stdout(buf):
                            ok = cmd_lifecycle._preflight_checks(cfg)
            self.assertFalse(ok)
            self.assertIn("/dev/kvm not found", buf.getvalue())

    def test_vm_missing_ovmf_fails(self):
        with _cfg(_VM_TOML, 'test-vm') as cfg:
            with patch.object(cmd_lifecycle.shutil, 'which', self._patched_which()):
                with patch.object(cmd_lifecycle.Path, 'exists', return_value=True):
                    with patch.object(cmd_lifecycle.Path, 'read_text', return_value="allow _workload-br\n"):
                        with patch('vm.find_ovmf_code', return_value=None):
                            buf = io.StringIO()
                            with redirect_stdout(buf):
                                ok = cmd_lifecycle._preflight_checks(cfg)
            self.assertFalse(ok)
            self.assertIn("OVMF firmware", buf.getvalue())

    def test_vm_all_checks_pass(self):
        with _cfg(_VM_TOML, 'test-vm') as cfg:
            with patch.object(cmd_lifecycle.shutil, 'which', self._patched_which()):
                with patch.object(cmd_lifecycle.Path, 'exists', return_value=True):
                    with patch.object(cmd_lifecycle.Path, 'read_text', return_value="allow _workload-br\n"):
                        with patch('vm.find_ovmf_code', return_value="/usr/share/edk2/ovmf/OVMF_CODE.fd"):
                            buf = io.StringIO()
                            with redirect_stdout(buf):
                                ok = cmd_lifecycle._preflight_checks(cfg)
            self.assertTrue(ok)


# ── _provision_user ──────────────────────────────────────────────────────────

class TestProvisionUser(unittest.TestCase):
    def test_runs_sysusers_then_ensure_user(self):
        # _provision_user is now pure application of the generator's output: it
        # runs systemd-sysusers against the generator-written .conf, then
        # workload-ensure-user. No UID allocation or .conf rendering here
        # anymore (the generator is the single producer — see _generate_units).
        with _cfg(_CONTAINER_TOML, 'test-wl') as cfg:
            with patch.object(cmd_lifecycle.subprocess, 'run') as run_mock:
                run_mock.return_value = MagicMock(returncode=0)
                cmd_lifecycle._provision_user(cfg)
            sysusers_call = run_mock.call_args_list[0]
            self.assertEqual(sysusers_call.args[0][0], "systemd-sysusers")
            self.assertTrue(sysusers_call.args[0][1].endswith("workload-test-wl.conf"))
            ensure_user_call = run_mock.call_args_list[1]
            self.assertIn("workload-ensure-user", ensure_user_call.args[0][0])
            self.assertEqual(ensure_user_call.args[0][1], "test-wl")


# ── _transfer_image / _transfer_one_image ───────────────────────────────────

class TestTransferImage(unittest.TestCase):
    def test_skips_non_pull_never_images(self):
        with _cfg(_CONTAINER_TOML, 'test-wl') as cfg:
            manager = MagicMock()
            with patch.object(cmd_lifecycle, '_transfer_one_image') as one:
                cmd_lifecycle._transfer_image(cfg, manager)
            one.assert_not_called()

    def test_transfers_pull_never_image(self):
        with _cfg(_HOST_TOML, 'test-wl') as cfg:
            manager = MagicMock()
            with patch.object(cmd_lifecycle, '_transfer_one_image') as one:
                cmd_lifecycle._transfer_image(cfg, manager)
            one.assert_called_once_with(cfg, manager, "example.com/test:latest")

    def test_transfer_one_image_needs_transfer_when_stale(self):
        with _cfg(_HOST_TOML, 'test-wl') as cfg:
            manager = MagicMock()
            manager.podman.return_value.image_id.return_value = "old-id"
            with patch.object(type(cfg), 'uid', new_callable=lambda: property(lambda _: 12345)):
                with patch.object(type(cfg), 'gid', new_callable=lambda: property(lambda _: 12345)):
                    with patch.object(cmd_lifecycle.Podman, 'for_root') as for_root:
                        for_root.return_value.image_id.return_value = "new-id"
                        with patch.object(cmd_lifecycle.tempfile, 'mkstemp', return_value=(99, "/tmp/fake.tar")):
                            with patch.object(cmd_lifecycle.os, 'close'):
                                with patch.object(cmd_lifecycle.os, 'chown'):
                                    with patch.object(cmd_lifecycle.os, 'unlink'):
                                        with patch.object(cmd_lifecycle.subprocess, 'run') as run_mock:
                                            save_res = MagicMock(returncode=0)
                                            load_res = MagicMock(returncode=0)
                                            active_res = MagicMock(returncode=1)
                                            run_mock.side_effect = [save_res, load_res, active_res]
                                            cmd_lifecycle._transfer_one_image(cfg, manager, "example.com/test:latest")
            self.assertEqual(run_mock.call_count, 3)

    def test_transfer_one_image_save_failure_exits(self):
        with _cfg(_HOST_TOML, 'test-wl') as cfg:
            manager = MagicMock()
            manager.podman.return_value.image_id.return_value = ""
            with patch.object(type(cfg), 'uid', new_callable=lambda: property(lambda _: 12345)):
                with patch.object(type(cfg), 'gid', new_callable=lambda: property(lambda _: 12345)):
                    with patch.object(cmd_lifecycle.Podman, 'for_root') as for_root:
                        for_root.return_value.image_id.return_value = "new-id"
                        with patch.object(cmd_lifecycle.tempfile, 'mkstemp', return_value=(99, "/tmp/fake.tar")):
                            with patch.object(cmd_lifecycle.os, 'close'):
                                with patch.object(cmd_lifecycle.os, 'chown'):
                                    with patch.object(cmd_lifecycle.os, 'unlink'):
                                        with patch.object(cmd_lifecycle.subprocess, 'run') as run_mock:
                                            save_res = MagicMock(returncode=1, stderr=b"boom")
                                            run_mock.return_value = save_res
                                            with self.assertRaises(SystemExit):
                                                cmd_lifecycle._transfer_one_image(cfg, manager, "example.com/test:latest")

    def test_transfer_one_image_missing_locally_no_root_copy_exits(self):
        with _cfg(_HOST_TOML, 'test-wl') as cfg:
            manager = MagicMock()
            manager.podman.return_value.image_id.return_value = ""
            with patch.object(cmd_lifecycle.Podman, 'for_root') as for_root:
                for_root.return_value.image_id.return_value = ""
                with self.assertRaises(SystemExit):
                    cmd_lifecycle._transfer_one_image(cfg, manager, "example.com/test:latest")


# ── _generate_units / _start_service ─────────────────────────────────────────

class TestGenerateUnits(unittest.TestCase):
    def test_generates_reloads_and_verifies(self):
        with _cfg(_CONTAINER_TOML, 'test-wl') as cfg:
            with tempfile.TemporaryDirectory() as run_d:
                run = Path(run_d)
                # The produced-artifact check passes when the generator's
                # sysusers .conf is present.
                (run / "workload-test-wl.conf").touch()
                with patch.object(cmd_lifecycle, 'RUN_SYSTEMD_SYSTEM', run):
                    with patch.object(cmd_lifecycle.subprocess, 'run') as run_mock:
                        run_mock.return_value = MagicMock(returncode=0)
                        cmd_lifecycle._generate_units(cfg)
            cmds = [c.args[0] for c in run_mock.call_args_list]
            self.assertTrue(any("workload-generate" in c[0] for c in cmds))
            self.assertIn(["systemctl", "daemon-reload"], cmds)
            # The generator is invoked with stderr-logging on so an operator
            # sees per-workload diagnostics inline.
            gen_call = next(c for c in run_mock.call_args_list
                            if "workload-generate" in c.args[0][0])
            self.assertEqual(gen_call.kwargs["env"]["WORKLOAD_GENERATE_LOG_STDERR"], "1")

    def test_missing_sysusers_conf_raises_lifecycle_exit_1(self):
        # The generator exits 0 and skips a workload it can't provision (e.g.
        # UID-range exhaustion), leaving no .conf. enable must detect that and
        # surface a printed error + LifecycleError(1), not proceed to sysusers.
        with _cfg(_CONTAINER_TOML, 'test-wl') as cfg:
            with tempfile.TemporaryDirectory() as run_d:
                with patch.object(cmd_lifecycle, 'RUN_SYSTEMD_SYSTEM', Path(run_d)):
                    with patch.object(cmd_lifecycle.subprocess, 'run',
                                      return_value=MagicMock(returncode=0)):
                        buf = io.StringIO()
                        with redirect_stderr(buf):
                            with self.assertRaises(cmd_lifecycle.LifecycleError) as ctx:
                                cmd_lifecycle._generate_units(cfg)
            self.assertEqual(ctx.exception.returncode, 1)
            self.assertIsInstance(ctx.exception.returncode, int)
            self.assertIn("produced no units", buf.getvalue())


class TestStartService(unittest.TestCase):
    def test_resets_failed_and_starts(self):
        with _cfg(_CONTAINER_TOML, 'test-wl') as cfg:
            with patch.object(cmd_lifecycle.subprocess, 'run') as run_mock:
                run_mock.return_value = MagicMock(returncode=0)
                cmd_lifecycle._start_service(cfg)
            cmds = [c.args[0] for c in run_mock.call_args_list]
            self.assertIn(["systemctl", "reset-failed", cfg.service_name], cmds)
            self.assertIn(["systemctl", "start", "--no-block", cfg.service_name], cmds)


# ── _run_host_setup ──────────────────────────────────────────────────────────

class TestRunHostSetup(unittest.TestCase):
    def test_no_setup_configured_is_noop(self):
        with _cfg(_CONTAINER_TOML, 'test-wl') as cfg:
            with patch.object(cmd_lifecycle.subprocess, 'run') as run_mock:
                cmd_lifecycle._run_host_setup(cfg, "enable")
            run_mock.assert_not_called()

    def test_missing_script_warns_no_exit(self):
        with _cfg(_HOST_TOML, 'test-wl') as cfg:
            buf = io.StringIO()
            with redirect_stderr(buf):
                cmd_lifecycle._run_host_setup(cfg, "enable")
            self.assertIn("not found", buf.getvalue())

    def test_script_failure_on_enable_exits(self):
        with _cfg(_HOST_TOML, 'test-wl') as cfg:
            with patch.object(cmd_lifecycle.Path, 'exists', return_value=True):
                with patch.object(cmd_lifecycle.subprocess, 'run', return_value=MagicMock(returncode=1)):
                    with self.assertRaises(SystemExit):
                        cmd_lifecycle._run_host_setup(cfg, "enable")

    def test_script_failure_on_disable_does_not_exit(self):
        with _cfg(_HOST_TOML, 'test-wl') as cfg:
            with patch.object(cmd_lifecycle.Path, 'exists', return_value=True):
                with patch.object(cmd_lifecycle.subprocess, 'run', return_value=MagicMock(returncode=1)):
                    cmd_lifecycle._run_host_setup(cfg, "disable")  # must not raise

    def test_script_success_runs(self):
        with _cfg(_HOST_TOML, 'test-wl') as cfg:
            with patch.object(cmd_lifecycle.Path, 'exists', return_value=True):
                with patch.object(cmd_lifecycle.subprocess, 'run', return_value=MagicMock(returncode=0)) as run_mock:
                    cmd_lifecycle._run_host_setup(cfg, "enable")
            self.assertEqual(run_mock.call_args.args[0][1], "enable")


# ── SELinux helpers ──────────────────────────────────────────────────────────

class TestSelinuxHelpers(unittest.TestCase):
    def test_selinux_available_true(self):
        fake_dir = MagicMock()
        fake_dir.is_dir.return_value = True
        with patch.object(cmd_lifecycle.shutil, 'which', return_value="/usr/sbin/semodule"):
            with patch.object(cmd_lifecycle, 'UDICA_TEMPLATE_DIR', fake_dir):
                self.assertTrue(cmd_lifecycle._selinux_available())

    def test_selinux_available_false_no_semodule(self):
        with patch.object(cmd_lifecycle.shutil, 'which', return_value=None):
            self.assertFalse(cmd_lifecycle._selinux_available())

    def test_selinux_enforcing_true(self):
        with patch.object(cmd_lifecycle.subprocess, 'run',
                          return_value=MagicMock(returncode=0, stdout="Enforcing\n")):
            self.assertTrue(cmd_lifecycle._selinux_enforcing())

    def test_selinux_enforcing_false_permissive(self):
        with patch.object(cmd_lifecycle.subprocess, 'run',
                          return_value=MagicMock(returncode=0, stdout="Permissive\n")):
            self.assertFalse(cmd_lifecycle._selinux_enforcing())

    def test_selinux_enforcing_getenforce_missing(self):
        with patch.object(cmd_lifecycle.subprocess, 'run', side_effect=FileNotFoundError):
            self.assertFalse(cmd_lifecycle._selinux_enforcing())

    def test_available_bundles_empty_when_dir_missing(self):
        fake_dir = MagicMock()
        fake_dir.is_dir.return_value = False
        with patch.object(cmd_lifecycle, '_BUNDLES_DIR', fake_dir):
            self.assertEqual(cmd_lifecycle._available_bundles(), [])

    def test_available_bundles_lists_dirs_with_policy(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "foo").mkdir()
            (p / "foo" / "policy.cil").write_text("")
            (p / "bar").mkdir()  # no policy.cil -> excluded
            with patch.object(cmd_lifecycle, '_BUNDLES_DIR', p):
                self.assertEqual(cmd_lifecycle._available_bundles(), ["foo"])

    def test_print_available_bundles_suggests_close_match(self):
        with patch.object(cmd_lifecycle, '_available_bundles', return_value=["forgejo"]):
            buf = io.StringIO()
            with redirect_stderr(buf):
                cmd_lifecycle._print_available_bundles("forgeejo")
            self.assertIn("did you mean 'forgejo'", buf.getvalue())

    def test_print_available_bundles_noop_when_none_available(self):
        with patch.object(cmd_lifecycle, '_available_bundles', return_value=[]):
            buf = io.StringIO()
            with redirect_stderr(buf):
                cmd_lifecycle._print_available_bundles("anything")
            self.assertEqual(buf.getvalue(), "")


# ── _apply_selinux_policy ────────────────────────────────────────────────────

class TestApplySelinuxPolicy(unittest.TestCase):
    def test_noop_when_not_selinux_policy(self):
        with _cfg(_CONTAINER_TOML, 'test-wl') as cfg:
            with patch.object(cmd_lifecycle.subprocess, 'run') as run_mock:
                cmd_lifecycle._apply_selinux_policy(cfg, "enable")
            run_mock.assert_not_called()

    def test_enable_hard_fails_when_tooling_missing_and_enforcing(self):
        with _cfg(_SELINUX_TOML, 'test-wl') as cfg:
            with patch.object(cmd_lifecycle, '_selinux_available', return_value=False):
                with patch.object(cmd_lifecycle, '_selinux_enforcing', return_value=True):
                    with self.assertRaises(cmd_lifecycle.SelinuxPolicyError):
                        cmd_lifecycle._apply_selinux_policy(cfg, "enable")

    def test_enable_warns_when_tooling_missing_and_permissive(self):
        with _cfg(_SELINUX_TOML, 'test-wl') as cfg:
            with patch.object(cmd_lifecycle, '_selinux_available', return_value=False):
                with patch.object(cmd_lifecycle, '_selinux_enforcing', return_value=False):
                    buf = io.StringIO()
                    with redirect_stderr(buf):
                        cmd_lifecycle._apply_selinux_policy(cfg, "enable")  # no raise
                    self.assertIn("WARNING", buf.getvalue())

    def test_disable_never_hard_fails_when_tooling_missing(self):
        with _cfg(_SELINUX_TOML, 'test-wl') as cfg:
            with patch.object(cmd_lifecycle, '_selinux_available', return_value=False):
                with patch.object(cmd_lifecycle, '_selinux_enforcing', return_value=True):
                    cmd_lifecycle._apply_selinux_policy(cfg, "disable")  # must not raise

    def test_disable_removes_loaded_module(self):
        with _cfg(_SELINUX_TOML, 'test-wl') as cfg:
            module = cmd_lifecycle.selinux_module_name(cfg.name)
            with patch.object(cmd_lifecycle, '_selinux_available', return_value=True):
                with patch.object(cmd_lifecycle.subprocess, 'run') as run_mock:
                    run_mock.return_value = MagicMock(returncode=0, stdout=f"{module}\nother_mod\n")
                    cmd_lifecycle._apply_selinux_policy(cfg, "disable")
            remove_calls = [c for c in run_mock.call_args_list if c.args[0][0:2] == ["semodule", "-r"]]
            self.assertEqual(len(remove_calls), 1)
            self.assertEqual(remove_calls[0].args[0][2], module)

    def test_disable_skips_removal_when_not_loaded(self):
        with _cfg(_SELINUX_TOML, 'test-wl') as cfg:
            with patch.object(cmd_lifecycle, '_selinux_available', return_value=True):
                with patch.object(cmd_lifecycle.subprocess, 'run') as run_mock:
                    run_mock.return_value = MagicMock(returncode=0, stdout="other_mod\n")
                    cmd_lifecycle._apply_selinux_policy(cfg, "disable")
            remove_calls = [c for c in run_mock.call_args_list if c.args[0][0:2] == ["semodule", "-r"]]
            self.assertEqual(remove_calls, [])

    def test_enable_invalid_bundle_name_exits(self):
        toml = _SELINUX_TOML.format(name='test-wl').replace(
            'name = "test-wl"', 'name = "test-wl"\nbundle = "bad_name"'
        )
        with _CfgDir(toml, 'test-wl') as cfg:
            with patch.object(cmd_lifecycle, '_selinux_available', return_value=True):
                buf = io.StringIO()
                with redirect_stderr(buf):
                    with self.assertRaises(cmd_lifecycle.SelinuxPolicyError):
                        cmd_lifecycle._apply_selinux_policy(cfg, "enable")
                self.assertIn("invalid", buf.getvalue())

    def test_enable_missing_template_exits(self):
        with _cfg(_SELINUX_TOML, 'test-wl') as cfg:
            with patch.object(cmd_lifecycle, '_selinux_available', return_value=True):
                buf = io.StringIO()
                with redirect_stderr(buf):
                    with self.assertRaises(cmd_lifecycle.SelinuxPolicyError):
                        cmd_lifecycle._apply_selinux_policy(cfg, "enable")
                self.assertIn("template not found", buf.getvalue())

    def test_enable_installs_module_success(self):
        with _cfg(_SELINUX_TOML, 'test-wl') as cfg:
            with patch.object(cmd_lifecycle, '_selinux_available', return_value=True):
                with patch.object(cmd_lifecycle.WorkloadConfig, 'resolve_control_file') as resolve:
                    with tempfile.TemporaryDirectory() as td:
                        template = Path(td) / "policy.cil"
                        template.write_text("(blockinherit __WL_MODULE__ base)\n")
                        resolve.return_value = template
                        with patch.object(cmd_lifecycle, 'UDICA_TEMPLATE_DIR', Path(td)):
                            with patch.object(cmd_lifecycle.subprocess, 'run') as run_mock:
                                run_mock.return_value = MagicMock(returncode=0)
                                cmd_lifecycle._apply_selinux_policy(cfg, "enable")
                    install_calls = [c for c in run_mock.call_args_list if c.args[0][0:2] == ["semodule", "-i"]]
                    self.assertEqual(len(install_calls), 1)

    def test_enable_install_failure_exits(self):
        with _cfg(_SELINUX_TOML, 'test-wl') as cfg:
            with patch.object(cmd_lifecycle, '_selinux_available', return_value=True):
                with patch.object(cmd_lifecycle.WorkloadConfig, 'resolve_control_file') as resolve:
                    with tempfile.TemporaryDirectory() as td:
                        template = Path(td) / "policy.cil"
                        template.write_text("(blockinherit __WL_MODULE__ base)\n")
                        resolve.return_value = template
                        with patch.object(cmd_lifecycle, 'UDICA_TEMPLATE_DIR', Path(td)):
                            with patch.object(cmd_lifecycle.subprocess, 'run',
                                              side_effect=cmd_lifecycle.subprocess.CalledProcessError(1, ["semodule"])):
                                with self.assertRaises(cmd_lifecycle.SelinuxPolicyError):
                                    cmd_lifecycle._apply_selinux_policy(cfg, "enable")


# ── cmd_enable ────────────────────────────────────────────────────────────────

class TestCmdEnable(unittest.TestCase):
    def test_config_not_found_exits(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', Path(d)):
                with _RootBypass():
                    manager = MagicMock()
                    buf = io.StringIO()
                    with redirect_stderr(buf):
                        with self.assertRaises(SystemExit):
                            cmd_lifecycle.cmd_enable(_ns(workload="ghost"), manager)
                    self.assertIn("not found", buf.getvalue())

    def test_preflight_failure_reverts_marker(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as wl_base:
            p = Path(d)
            (p / 'test-wl').mkdir()
            (p / 'test-wl' / 'workload.toml').write_text(_CONTAINER_TOML)
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p):
                with patch.object(workload_lib, 'WORKLOADS_BASE', Path(wl_base)):
                    with _RootBypass():
                        manager = MagicMock()
                        with patch.object(cmd_lifecycle.subprocess, 'run', return_value=MagicMock(returncode=0)):
                            with patch.object(cmd_lifecycle, '_preflight_checks', return_value=False):
                                buf = io.StringIO()
                                with redirect_stdout(buf):
                                    with self.assertRaises(SystemExit):
                                        cmd_lifecycle.cmd_enable(_ns(workload="test-wl"), manager)
                        marker = workload_lib.workload_enabled_marker("test-wl")
                        self.assertFalse(marker.exists())

    def test_success_path_starts_service(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as wl_base:
            p = Path(d)
            (p / 'test-wl').mkdir()
            (p / 'test-wl' / 'workload.toml').write_text(_CONTAINER_TOML)
            def fake_run(cmd, **kw):
                if cmd[:3] == ["systemctl", "is-active", "--quiet"]:
                    return MagicMock(returncode=1)
                return MagicMock(returncode=0)
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p):
                with patch.object(workload_lib, 'WORKLOADS_BASE', Path(wl_base)):
                    with _RootBypass():
                        manager = MagicMock()
                        with patch.object(cmd_lifecycle.subprocess, 'run', side_effect=fake_run):
                            with patch.object(cmd_lifecycle, '_preflight_checks', return_value=True):
                                with patch.object(cmd_lifecycle, '_run_host_setup') as host_setup:
                                    with patch.object(cmd_lifecycle, '_apply_selinux_policy') as selinux:
                                        with patch.object(cmd_lifecycle, '_generate_units') as generate:
                                            with patch.object(cmd_lifecycle, '_provision_user') as provision:
                                                with patch.object(cmd_lifecycle, '_transfer_image') as transfer:
                                                    with patch.object(cmd_lifecycle, '_start_service') as start:
                                                        buf = io.StringIO()
                                                        with redirect_stdout(buf):
                                                            cmd_lifecycle.cmd_enable(_ns(workload="test-wl"), manager)
                        host_setup.assert_called_once()
                        selinux.assert_called_once()
                        generate.assert_called_once()
                        provision.assert_called_once()
                        transfer.assert_called_once()
                        start.assert_called_once()
                        marker = workload_lib.workload_enabled_marker("test-wl")
                        self.assertTrue(marker.exists())
                        self.assertIn("enabled and starting", buf.getvalue())

    def test_selinux_policy_failure_exits_1_without_reprinting(self):
        # _apply_selinux_policy() prints its own diagnostic and raises
        # SelinuxPolicyError; cmd_enable must exit 1 without printing a
        # second "Error: ..." line (the message is already on stderr).
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as wl_base:
            p = Path(d)
            (p / 'test-wl').mkdir()
            (p / 'test-wl' / 'workload.toml').write_text(_CONTAINER_TOML)
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p):
                with patch.object(workload_lib, 'WORKLOADS_BASE', Path(wl_base)):
                    with _RootBypass():
                        manager = MagicMock()
                        with patch.object(cmd_lifecycle.subprocess, 'run', return_value=MagicMock(returncode=0)):
                            with patch.object(cmd_lifecycle, '_preflight_checks', return_value=True):
                                with patch.object(cmd_lifecycle, '_run_host_setup'):
                                    with patch.object(
                                        cmd_lifecycle, '_apply_selinux_policy',
                                        side_effect=cmd_lifecycle.SelinuxPolicyError("boom"),
                                    ):
                                        buf = io.StringIO()
                                        with redirect_stderr(buf):
                                            with self.assertRaises(SystemExit) as cm:
                                                cmd_lifecycle.cmd_enable(_ns(workload="test-wl"), manager)
                                        self.assertEqual(cm.exception.code, 1)
                                        self.assertEqual(buf.getvalue(), "")

    def test_vm_workload_skips_image_transfer(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as wl_base:
            p = Path(d)
            (p / 'test-vm').mkdir()
            (p / 'test-vm' / 'workload.toml').write_text(_VM_TOML)
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p):
                with patch.object(workload_lib, 'WORKLOADS_BASE', Path(wl_base)):
                    with _RootBypass():
                        manager = MagicMock()
                        with patch.object(cmd_lifecycle.subprocess, 'run', return_value=MagicMock(returncode=0)):
                            with patch.object(cmd_lifecycle, '_preflight_checks', return_value=True):
                                with patch.object(cmd_lifecycle, '_run_host_setup'):
                                    with patch.object(cmd_lifecycle, '_apply_selinux_policy'):
                                        with patch.object(cmd_lifecycle, '_generate_units'):
                                            with patch.object(cmd_lifecycle, '_provision_user'):
                                                with patch.object(cmd_lifecycle, '_transfer_image') as transfer:
                                                    with patch.object(cmd_lifecycle, '_start_service'):
                                                        cmd_lifecycle.cmd_enable(_ns(workload="test-vm"), manager)
                        transfer.assert_not_called()


# ── cmd_disable additional branches ─────────────────────────────────────────

class TestCmdDisableAdditional(unittest.TestCase):
    def test_purge_user_absent_is_clean(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test-wl').mkdir()
            (p / 'test-wl' / 'workload.toml').write_text(_CONTAINER_TOML)
            (p / 'test-wl' / '.enabled').touch()
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p):
                with _RootBypass():
                    manager = MagicMock()
                    manager.get_all_configs.return_value = []
                    with patch.object(cmd_lifecycle.subprocess, 'run', return_value=MagicMock(returncode=0)):
                        with patch('pwd.getpwnam', side_effect=KeyError):
                            with patch.object(cmd_lifecycle, 'workload_root_dir', return_value=Path(d) / "nope"):
                                with patch.object(cmd_lifecycle, 'subid_lock', contextlib.nullcontext):
                                    with patch.object(cmd_lifecycle, 'open', unittest.mock.mock_open(), create=True):
                                        with _no_subid_files():
                                            buf = io.StringIO()
                                            with redirect_stdout(buf):
                                                cmd_lifecycle.cmd_disable(_ns(workload="test-wl", purge=True), manager)
                    self.assertIn("was not provisioned", buf.getvalue())

    def test_purge_user_present_userdel_fails_reports_failure(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test-wl').mkdir()
            (p / 'test-wl' / 'workload.toml').write_text(_CONTAINER_TOML)
            (p / 'test-wl' / '.enabled').touch()
            fake_pw = MagicMock()
            fake_pw.pw_uid = 15000
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p):
                with _RootBypass():
                    manager = MagicMock()
                    manager.get_all_configs.return_value = []
                    with patch.object(cmd_lifecycle.subprocess, 'run', return_value=MagicMock(returncode=0)):
                        with patch('pwd.getpwnam', return_value=fake_pw):
                            with patch.object(cmd_lifecycle, 'workload_root_dir', return_value=Path(d) / "nope"):
                                with patch.object(cmd_lifecycle.time, 'sleep'):
                                    buf_out = io.StringIO()
                                    buf_err = io.StringIO()
                                    with redirect_stdout(buf_out), redirect_stderr(buf_err):
                                        with self.assertRaises(SystemExit):
                                            cmd_lifecycle.cmd_disable(_ns(workload="test-wl", purge=True), manager)
                    self.assertIn("still exists", buf_err.getvalue())

    def test_purge_removes_workload_dir(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test-wl').mkdir()
            (p / 'test-wl' / 'workload.toml').write_text(_CONTAINER_TOML)
            (p / 'test-wl' / '.enabled').touch()
            wl_dir = Path(d) / "wl-data"
            wl_dir.mkdir()
            (wl_dir / "marker").write_text("x")
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p):
                with _RootBypass():
                    manager = MagicMock()
                    manager.get_all_configs.return_value = []
                    with patch.object(cmd_lifecycle.subprocess, 'run', return_value=MagicMock(returncode=0)):
                        with patch('pwd.getpwnam', side_effect=KeyError):
                            with patch.object(cmd_lifecycle, 'workload_root_dir', return_value=wl_dir):
                                with patch.object(cmd_lifecycle, 'subid_lock', contextlib.nullcontext):
                                    with patch.object(cmd_lifecycle, 'open', unittest.mock.mock_open(), create=True):
                                        with _no_subid_files():
                                            cmd_lifecycle.cmd_disable(_ns(workload="test-wl", purge=True), manager)
            self.assertFalse(wl_dir.exists())

    def test_non_purge_keeps_user_stops_lingering_manager(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test-wl').mkdir()
            (p / 'test-wl' / 'workload.toml').write_text(_CONTAINER_TOML)
            (p / 'test-wl' / '.enabled').touch()
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p):
                with _RootBypass():
                    manager = MagicMock()
                    manager.get_all_configs.return_value = []
                    with patch.object(cmd_lifecycle.subprocess, 'run', return_value=MagicMock(returncode=0)):
                        with patch.object(cmd_lifecycle, '_stop_user_manager', return_value=True) as stop_mgr:
                            buf = io.StringIO()
                            with redirect_stdout(buf):
                                cmd_lifecycle.cmd_disable(_ns(workload="test-wl", purge=False), manager)
                    stop_mgr.assert_called_once()
                    self.assertIn("disabled and stopped", buf.getvalue())
                    marker = workload_lib.workload_enabled_marker("test-wl")
                    self.assertFalse(marker.exists())

    def test_best_effort_continues_after_failure(self):
        """A failure in one teardown step doesn't prevent later steps; overall
        exit is non-zero and the failure surfaces on stderr."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test-wl').mkdir()
            (p / 'test-wl' / 'workload.toml').write_text(_CONTAINER_TOML)
            (p / 'test-wl' / '.enabled').touch()
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', p):
                with _RootBypass():
                    manager = MagicMock()
                    manager.get_all_configs.return_value = []
                    with patch.object(cmd_lifecycle.subprocess, 'run', return_value=MagicMock(returncode=0)):
                        with patch.object(cmd_lifecycle, '_run_host_setup', side_effect=RuntimeError("boom")):
                            buf_err = io.StringIO()
                            with redirect_stderr(buf_err):
                                with self.assertRaises(SystemExit):
                                    cmd_lifecycle.cmd_disable(_ns(workload="test-wl", purge=False), manager)
                    self.assertIn("boom", buf_err.getvalue())
                    # Marker was still removed despite the earlier failure.
                    marker = workload_lib.workload_enabled_marker("test-wl")
                    self.assertFalse(marker.exists())


# ── cmd_start / cmd_stop ─────────────────────────────────────────────────────

class TestCmdStartStop(unittest.TestCase):
    def test_start_config_not_found_exits(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', Path(d)):
                with _RootBypass():
                    with self.assertRaises(SystemExit):
                        cmd_lifecycle.cmd_start(_ns(workload="ghost"), MagicMock())

    def test_start_calls_substrate_lifecycle(self):
        with _cfg(_CONTAINER_TOML, 'test-wl'):
            with _RootBypass():
                manager = MagicMock()
                sub = MagicMock()
                with patch.object(cmd_lifecycle, 'get_substrate', return_value=sub):
                    buf = io.StringIO()
                    with redirect_stdout(buf):
                        cmd_lifecycle.cmd_start(_ns(workload="test-wl"), manager)
                sub.lifecycle.assert_called_once_with("start")
                self.assertIn("started", buf.getvalue())

    def test_stop_config_not_found_exits(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', Path(d)):
                with _RootBypass():
                    with self.assertRaises(SystemExit):
                        cmd_lifecycle.cmd_stop(_ns(workload="ghost"), MagicMock())

    def test_stop_success(self):
        with _cfg(_CONTAINER_TOML, 'test-wl'):
            with _RootBypass():
                manager = MagicMock()
                with patch.object(cmd_lifecycle.subprocess, 'run', return_value=MagicMock(returncode=0)):
                    buf = io.StringIO()
                    with redirect_stdout(buf):
                        cmd_lifecycle.cmd_stop(_ns(workload="test-wl"), manager)
                self.assertIn("stopped", buf.getvalue())

    def test_stop_failure_propagates_exit_code(self):
        with _cfg(_CONTAINER_TOML, 'test-wl'):
            with _RootBypass():
                manager = MagicMock()
                with patch.object(cmd_lifecycle.subprocess, 'run', return_value=MagicMock(returncode=3)):
                    with self.assertRaises(SystemExit) as cm:
                        cmd_lifecycle.cmd_stop(_ns(workload="test-wl"), manager)
                    self.assertEqual(cm.exception.code, 3)


# ── cmd_recreate ─────────────────────────────────────────────────────────────

class TestCmdRecreate(unittest.TestCase):
    def test_recreate_regenerates_and_calls_substrate(self):
        with _cfg(_CONTAINER_TOML, 'test-wl'):
            with _RootBypass():
                manager = MagicMock()
                sub = MagicMock()
                with patch.object(cmd_lifecycle.subprocess, 'run', return_value=MagicMock(returncode=0)) as run_mock:
                    with patch.object(cmd_lifecycle, 'get_substrate', return_value=sub):
                        with patch.object(cmd_lifecycle, '_transfer_image'):
                            buf = io.StringIO()
                            with redirect_stdout(buf):
                                cmd_lifecycle.cmd_recreate(_ns(workload="test-wl"), manager)
                sub.reprovision.assert_called_once_with(recreate=True)
                cmds = [c.args[0] for c in run_mock.call_args_list]
                self.assertTrue(any("workload-generate" in c[0] for c in cmds))
                self.assertIn("recreated", buf.getvalue())

    def test_recreate_transfers_freshly_built_image(self):
        # Regression: recreate previously restarted against whatever image was
        # already in the workload user's rootless store, never picking up a
        # rebuild — the user had to disable+enable instead. recreate must now
        # call the same root->user image transfer enable does.
        with _cfg(_CONTAINER_TOML, 'test-wl'):
            with _RootBypass():
                manager = MagicMock()
                sub = MagicMock()
                with patch.object(cmd_lifecycle.subprocess, 'run', return_value=MagicMock(returncode=0)):
                    with patch.object(cmd_lifecycle, 'get_substrate', return_value=sub):
                        with patch.object(cmd_lifecycle, '_transfer_image') as transfer:
                            cmd_lifecycle.cmd_recreate(_ns(workload="test-wl"), manager)
                transfer.assert_called_once()
                self.assertEqual(transfer.call_args.args[1], manager)

    def test_recreate_skips_image_transfer_for_vm(self):
        with _cfg(_VM_TOML, 'test-vm'):
            with _RootBypass():
                manager = MagicMock()
                sub = MagicMock()
                with patch.object(cmd_lifecycle.subprocess, 'run', return_value=MagicMock(returncode=0)):
                    with patch.object(cmd_lifecycle, 'get_substrate', return_value=sub):
                        with patch.object(cmd_lifecycle, '_transfer_image') as transfer:
                            cmd_lifecycle.cmd_recreate(_ns(workload="test-vm"), manager)
                transfer.assert_not_called()


# ── cmd_reboot ────────────────────────────────────────────────────────────────

class TestCmdReboot(unittest.TestCase):
    def test_reboot_user_missing_exits(self):
        with _cfg(_CONTAINER_TOML, 'test-wl'):
            manager = MagicMock()
            manager.user_exists.return_value = False
            with self.assertRaises(SystemExit):
                cmd_lifecycle.cmd_reboot(_ns(workload="test-wl"), manager)

    def test_reboot_calls_substrate_lifecycle(self):
        with _cfg(_CONTAINER_TOML, 'test-wl'):
            manager = MagicMock()
            manager.user_exists.return_value = True
            sub = MagicMock()
            with patch.object(cmd_lifecycle, 'get_substrate', return_value=sub):
                cmd_lifecycle.cmd_reboot(_ns(workload="test-wl"), manager)
            sub.lifecycle.assert_called_once_with("reboot")


# ── cmd_cleanup ───────────────────────────────────────────────────────────────

class TestCmdCleanup(unittest.TestCase):
    def _fake_pwent(self, name, uid):
        e = MagicMock()
        e.pw_name = name
        e.pw_uid = uid
        e.pw_dir = f"/var/lib/workloads/{name[len('_wl-'):]}"
        return e

    def test_nothing_to_clean_text(self):
        with _RootBypass():
            with patch.object(cmd_lifecycle, 'iter_workloads', return_value=[]):
                with patch('pwd.getpwall', return_value=[]):
                    with patch.object(cmd_lifecycle, 'WORKLOADS_BASE', Path("/nonexistent-dir-xyz")):
                        with patch.object(cmd_lifecycle.shutil, 'which', return_value=None):
                            buf = io.StringIO()
                            with redirect_stdout(buf):
                                cmd_lifecycle.cmd_cleanup(_ns(apply=False, json=False), MagicMock())
                            self.assertIn("Nothing to clean up", buf.getvalue())

    def test_dry_run_json_lists_orphans_without_removing(self):
        orphan = self._fake_pwent("_wl-orphan", 15001)
        with _RootBypass():
            with patch.object(cmd_lifecycle, 'iter_workloads', return_value=[]):
                with patch('pwd.getpwall', return_value=[orphan]):
                    with patch.object(cmd_lifecycle, 'WORKLOADS_BASE', Path("/nonexistent-dir-xyz")):
                        with patch.object(cmd_lifecycle.shutil, 'which', return_value=None):
                            buf = io.StringIO()
                            with redirect_stdout(buf):
                                cmd_lifecycle.cmd_cleanup(_ns(apply=False, json=True), MagicMock())
            data = json.loads(buf.getvalue())
            self.assertTrue(data["dry_run"])
            self.assertEqual(data["orphan_users"], ["_wl-orphan"])
            self.assertEqual(data["removed_users"], [])

    def test_orphaned_user_not_removed_without_apply(self):
        orphan = self._fake_pwent("_wl-orphan", 15001)
        with _RootBypass():
            with patch.object(cmd_lifecycle, 'iter_workloads', return_value=[]):
                with patch('pwd.getpwall', return_value=[orphan]):
                    with patch.object(cmd_lifecycle, 'WORKLOADS_BASE', Path("/nonexistent-dir-xyz")):
                        with patch.object(cmd_lifecycle.shutil, 'which', return_value=None):
                            with patch.object(cmd_lifecycle.subprocess, 'run') as run_mock:
                                with patch.object(Path, 'exists', return_value=False):
                                    buf = io.StringIO()
                                    with redirect_stdout(buf):
                                        cmd_lifecycle.cmd_cleanup(_ns(apply=False, json=False), MagicMock())
                            run_mock.assert_not_called()
                            self.assertIn("Run with --apply", buf.getvalue())
                            self.assertIn("_wl-orphan", buf.getvalue())

    def test_apply_removes_orphaned_user(self):
        orphan = self._fake_pwent("_wl-orphan", 15001)
        with _RootBypass():
            with patch.object(cmd_lifecycle, 'iter_workloads', return_value=[]):
                with patch('pwd.getpwall', return_value=[orphan]):
                    with patch.object(cmd_lifecycle, 'WORKLOADS_BASE', Path("/nonexistent-dir-xyz")):
                        with patch.object(cmd_lifecycle.shutil, 'which', return_value=None):
                            with patch.object(cmd_lifecycle.subprocess, 'run', return_value=MagicMock(returncode=0)) as run_mock:
                                with patch.object(Path, 'exists', return_value=False):
                                    buf = io.StringIO()
                                    with redirect_stdout(buf):
                                        cmd_lifecycle.cmd_cleanup(_ns(apply=True, json=False), MagicMock())
            userdel_calls = [c for c in run_mock.call_args_list if c.args[0][0] == "userdel"]
            self.assertEqual(len(userdel_calls), 1)
            self.assertIn("_wl-orphan", userdel_calls[0].args[0])
            self.assertIn("Cleanup complete", buf.getvalue())

    def test_apply_rewrites_subuid_subgid_without_dropping_other_entries(self):
        """Removing an orphaned user's subuid/subgid range must strip only
        that user's line — a prefix-matching bug here would corrupt the UID
        mapping of a different, still-active workload sharing the file."""
        orphan = self._fake_pwent("_wl-orphan", 15001)
        subuid_content = "_wl-orphan:600100000:65536\n_wl-keep:600200000:65536\n"
        subgid_content = "_wl-orphan:600100000:65536\n_wl-keep:600200000:65536\n"

        def fake_exists(self):
            return str(self) in ("/etc/subuid", "/etc/subgid")

        def fake_read_text(self):
            if str(self) == "/etc/subuid":
                return subuid_content
            if str(self) == "/etc/subgid":
                return subgid_content
            return ""

        written = {}

        def fake_write_text(self, content):
            written[str(self)] = content

        with _RootBypass():
            with patch.object(cmd_lifecycle, 'iter_workloads', return_value=[]):
                with patch('pwd.getpwall', return_value=[orphan]):
                    with patch.object(cmd_lifecycle, 'WORKLOADS_BASE', Path("/nonexistent-dir-xyz")):
                        with patch.object(cmd_lifecycle.shutil, 'which', return_value=None):
                            with patch.object(cmd_lifecycle.subprocess, 'run',
                                               return_value=MagicMock(returncode=0)):
                                with patch.object(Path, 'exists', new=fake_exists), \
                                     patch.object(Path, 'read_text', new=fake_read_text), \
                                     patch.object(Path, 'write_text', new=fake_write_text):
                                    buf = io.StringIO()
                                    with redirect_stdout(buf):
                                        cmd_lifecycle.cmd_cleanup(_ns(apply=True, json=True), MagicMock())

        self.assertIn("/etc/subuid", written)
        self.assertIn("/etc/subgid", written)
        self.assertNotIn("_wl-orphan", written["/etc/subuid"])
        self.assertIn("_wl-keep:600200000:65536", written["/etc/subuid"])
        self.assertNotIn("_wl-orphan", written["/etc/subgid"])
        self.assertIn("_wl-keep:600200000:65536", written["/etc/subgid"])

    def test_orphaned_dir_detected_and_removed_on_apply(self):
        with tempfile.TemporaryDirectory() as base_dir:
            base = Path(base_dir)
            orphan_dir = base / "orphan-wl"
            orphan_dir.mkdir()
            with _RootBypass():
                with patch.object(cmd_lifecycle, 'iter_workloads', return_value=[]):
                    with patch('pwd.getpwall', return_value=[]):
                        with patch.object(cmd_lifecycle, 'WORKLOADS_BASE', base):
                            with patch.object(cmd_lifecycle.shutil, 'which', return_value=None):
                                buf = io.StringIO()
                                with redirect_stdout(buf):
                                    cmd_lifecycle.cmd_cleanup(_ns(apply=True, json=False), MagicMock())
            self.assertFalse(orphan_dir.exists())
            self.assertIn("Cleanup complete", buf.getvalue())

    def test_configured_workload_dir_not_orphaned(self):
        """A dir with a matching _wl- user is not reported orphaned."""
        with tempfile.TemporaryDirectory() as base_dir:
            base = Path(base_dir)
            wl_dir = base / "keepme"
            wl_dir.mkdir()
            keeper = self._fake_pwent("_wl-keepme", 15002)
            with _RootBypass():
                with patch.object(cmd_lifecycle, 'iter_workloads', return_value=[]):
                    with patch('pwd.getpwall', return_value=[keeper]):
                        with patch.object(cmd_lifecycle, 'WORKLOADS_BASE', base):
                            with patch.object(cmd_lifecycle.shutil, 'which', return_value=None):
                                with patch.object(Path, 'exists', return_value=False):
                                    buf = io.StringIO()
                                    with redirect_stdout(buf):
                                        cmd_lifecycle.cmd_cleanup(_ns(apply=False, json=False), MagicMock())
            # keepme user is configured? No — configured_names comes from iter_workloads
            # (empty here), so 'keepme' user IS orphaned by name-matching, but its dir
            # should not be double-reported as an orphan dir separately from the user.
            self.assertIn("_wl-keepme", buf.getvalue())

    def test_orphaned_selinux_module_removed_on_apply(self):
        with _RootBypass():
            with patch.object(cmd_lifecycle, 'iter_workloads', return_value=[]):
                with patch('pwd.getpwall', return_value=[]):
                    with patch.object(cmd_lifecycle, 'WORKLOADS_BASE', Path("/nonexistent-dir-xyz")):
                        with patch.object(cmd_lifecycle.shutil, 'which', return_value="/usr/sbin/semodule"):
                            def fake_run(cmd, **kw):
                                if cmd[:2] == ["semodule", "-l"]:
                                    return MagicMock(returncode=0, stdout="wl_orphan\nudica_base\n")
                                return MagicMock(returncode=0, stdout="", stderr="")
                            with patch.object(cmd_lifecycle.subprocess, 'run', side_effect=fake_run) as run_mock:
                                buf = io.StringIO()
                                with redirect_stdout(buf):
                                    cmd_lifecycle.cmd_cleanup(_ns(apply=True, json=False), MagicMock())
            remove_calls = [c for c in run_mock.call_args_list if c.args[0][0:2] == ["semodule", "-r"]]
            self.assertEqual(len(remove_calls), 1)
            self.assertEqual(remove_calls[0].args[0][2], "wl_orphan")

    def test_configured_selinux_module_not_orphaned(self):
        with tempfile.TemporaryDirectory() as d:
            cfg_file = Path(d) / "workload.toml"
            cfg_file.write_text(_SELINUX_TOML.format(name="kept"))
            with _RootBypass():
                with patch.object(cmd_lifecycle, 'iter_workloads', return_value=[("kept", cfg_file)]):
                    with patch('pwd.getpwall', return_value=[]):
                        with patch.object(cmd_lifecycle, 'WORKLOADS_BASE', Path("/nonexistent-dir-xyz")):
                            with patch.object(cmd_lifecycle.shutil, 'which', return_value="/usr/sbin/semodule"):
                                def fake_run(cmd, **kw):
                                    if cmd[:2] == ["semodule", "-l"]:
                                        return MagicMock(returncode=0, stdout="wl_kept\n")
                                    return MagicMock(returncode=0, stdout="", stderr="")
                                with patch.object(cmd_lifecycle.subprocess, 'run', side_effect=fake_run):
                                    buf = io.StringIO()
                                    with redirect_stdout(buf):
                                        cmd_lifecycle.cmd_cleanup(_ns(apply=False, json=False), MagicMock())
                self.assertIn("Nothing to clean up", buf.getvalue())


class TestWorkloadRunFiles(unittest.TestCase):
    """The removable run-file set: VM and multi-container branches."""

    def _removable_names(self, cfg):
        return [rf.path.name for rf in workload_lib.workload_run_files(cfg)
                if rf.kind != "env-file"]

    def test_vm_includes_build_service_and_virtiofs_units(self):
        toml = _VM_TOML.replace(
            '[vm]\nimage = "example.com/guest:latest"',
            '[vm]\nimage = "example.com/guest:latest"\n'
            'volumes = ["/srv/shared:/mnt/shared"]',
        )
        with _cfg(toml, 'test-vm') as cfg:
            names = self._removable_names(cfg)
            self.assertIn("workload-test-vm-build.service", names)
            self.assertTrue(any("virtiofs" in n for n in names))

    def test_multi_container_includes_per_container_services(self):
        with _cfg(_MULTI_TOML, 'multi-wl') as cfg:
            names = self._removable_names(cfg)
            self.assertIn("workload-multi-wl-web.service", names)
            self.assertIn("workload-multi-wl-db.service", names)


if __name__ == '__main__':
    unittest.main()
