#!/usr/bin/env python3
"""Unit tests for the runtime-dir re-pin helper, the `images` VM-skip, and the
non-interactive `edit` confirmation.

These cover three robustness fixes made after a cli_surface run on tp surfaced:
  - `workloadctl images` crashing on a VM workload (qcow2 URL fed to
    `podman inspect --type=image`);
  - `update`/`recreate`/`start` restarts failing 226/NAMESPACE because
    /run/user/<uid> was GC'd and the setup oneshot doesn't re-run on a bare
    restart (service_runtime.ensure_runtime_dir re-pins it);
  - `edit` crashing with EOFError on a non-interactive apply prompt.
"""

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


import cmd_edit
import cmd_images
import service_runtime


class TestEnsureRuntimeDir(unittest.TestCase):
    """service_runtime.ensure_runtime_dir.

    The gate is the *manager* (user@<uid>.service) being active, not the mere
    existence of /run/user/<uid> — a transient login session creates that dir
    too, so a dir-only check false-positives while no lingering manager runs.
    """

    def test_already_effective_skips_actions(self):
        # Manager active AND dir present → no loginctl/systemctl side effects.
        with patch.object(service_runtime, 'manager_active',
                          return_value=True), \
             patch.object(service_runtime.os.path, 'isdir', return_value=True), \
             patch.object(service_runtime.subprocess, 'run') as run:
            ok = service_runtime.ensure_runtime_dir(10005)
        self.assertTrue(ok)
        run.assert_not_called()

    def test_dir_present_but_manager_inactive_starts_manager(self):
        # The thrash case: /run/user/<uid> exists (transient login session) but
        # user@<uid>.service is NOT active. Must enable-linger AND start the
        # manager, not short-circuit on the dir.
        active = iter([False, True])  # fast-path inactive, then active
        with patch.object(service_runtime, 'manager_active',
                          side_effect=lambda *_: next(active)), \
             patch.object(service_runtime.os.path, 'isdir', return_value=True), \
             patch.object(service_runtime.subprocess, 'run') as run, \
             patch.object(service_runtime.time, 'sleep'):
            ok = service_runtime.ensure_runtime_dir(10005, timeout=1.0)
        self.assertTrue(ok)
        verbs = [c[0][0] for c in run.call_args_list]
        self.assertIn(['loginctl', 'enable-linger', '10005'], verbs)
        self.assertIn(['systemctl', 'start', 'user@10005.service'], verbs)

    def test_never_effective_returns_false(self):
        with patch.object(service_runtime, 'manager_active',
                          return_value=False), \
             patch.object(service_runtime.os.path, 'isdir', return_value=True), \
             patch.object(service_runtime.subprocess, 'run'), \
             patch.object(service_runtime.time, 'sleep'), \
             patch.object(service_runtime.time, 'monotonic',
                          side_effect=[0.0, 0.0, 5.0]):
            ok = service_runtime.ensure_runtime_dir(10005, timeout=1.0)
        self.assertFalse(ok)

    def test_subprocess_failure_is_swallowed(self):
        active = iter([False, True])
        with patch.object(service_runtime, 'manager_active',
                          side_effect=lambda *_: next(active)), \
             patch.object(service_runtime.os.path, 'isdir', return_value=True), \
             patch.object(service_runtime.subprocess, 'run',
                          side_effect=OSError("boom")), \
             patch.object(service_runtime.time, 'sleep'):
            ok = service_runtime.ensure_runtime_dir(10005, timeout=1.0)
        self.assertTrue(ok)


class TestRestartWorkloadService(unittest.TestCase):
    """service_runtime.restart_workload_service — self-healing (re)start."""

    def _proc(self, rc):
        return SimpleNamespace(returncode=rc, stdout="", stderr="")

    def test_success_first_try_no_reset(self):
        with patch.object(service_runtime, 'ensure_runtime_dir') as erd, \
             patch.object(service_runtime.subprocess, 'run',
                          return_value=self._proc(0)) as run:
            service_runtime.restart_workload_service(10005, "workload-x.service")
        erd.assert_called_once_with(10005)
        # Exactly the restart call, no reset-failed.
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args[0][0],
                         ["systemctl", "restart", "workload-x.service"])

    def test_action_start_uses_start_verb(self):
        with patch.object(service_runtime, 'ensure_runtime_dir'), \
             patch.object(service_runtime.subprocess, 'run',
                          return_value=self._proc(0)) as run:
            service_runtime.restart_workload_service(
                10005, "workload-x.service", action="start")
        self.assertEqual(run.call_args[0][0],
                         ["systemctl", "start", "workload-x.service"])

    def test_retry_resets_failed_repins_then_succeeds(self):
        # restart fails, then reset-failed, then restart succeeds.
        runs = [self._proc(1), self._proc(0), self._proc(0)]
        with patch.object(service_runtime, 'ensure_runtime_dir') as erd, \
             patch.object(service_runtime.subprocess, 'run',
                          side_effect=runs) as run, \
             patch.object(service_runtime.time, 'sleep'):
            service_runtime.restart_workload_service(10005, "workload-x.service")
        verbs = [c[0][0] for c in run.call_args_list]
        self.assertIn(["systemctl", "reset-failed", "workload-x.service"], verbs)
        # Re-pinned again on retry (initial + once on retry).
        self.assertEqual(erd.call_count, 2)

    def test_persistent_failure_raises(self):
        import subprocess as sp
        with patch.object(service_runtime, 'ensure_runtime_dir'), \
             patch.object(service_runtime.subprocess, 'run',
                          return_value=self._proc(1)), \
             patch.object(service_runtime.time, 'sleep'):
            with self.assertRaises(sp.CalledProcessError):
                service_runtime.restart_workload_service(10005, "workload-x.service")


class TestImagesSkipsVM(unittest.TestCase):
    """cmd_images must not feed a VM's qcow2 URL into podman inspect."""

    def _run(self, configs):
        manager = MagicMock()
        manager.get_all_configs.return_value = configs
        manager.user_exists.return_value = True
        pod = MagicMock()
        pod.image_info.return_value = {"Size": 1, "Created": None}
        manager.podman.return_value = pod
        args = SimpleNamespace(subcommand="list", json=True)
        with patch('sys.stdout'):
            cmd_images.cmd_images(args, manager)
        return manager, pod

    def test_vm_workload_is_skipped(self):
        vm = MagicMock()
        vm.is_vm = True
        ctr = MagicMock()
        ctr.is_vm = False
        ctr.name = "web"
        ctr.container_specs.return_value = [("web", "example.com/web:latest", "missing")]
        manager, pod = self._run([vm, ctr])
        # podman() / image_info only called for the container, never the VM.
        manager.podman.assert_called_once_with(ctr)
        vm.container_specs.assert_not_called()


class TestAskYesNo(unittest.TestCase):
    """cmd_edit._ask_yes_no tolerates EOF (non-interactive stdin)."""

    def test_eof_is_no(self):
        with patch('builtins.input', side_effect=EOFError), patch('sys.stdout'):
            self.assertFalse(cmd_edit._ask_yes_no("Apply? [y/N] "))

    def test_yes(self):
        with patch('builtins.input', return_value="y"):
            self.assertTrue(cmd_edit._ask_yes_no("Apply? [y/N] "))

    def test_blank_is_no(self):
        with patch('builtins.input', return_value=""):
            self.assertFalse(cmd_edit._ask_yes_no("Apply? [y/N] "))


if __name__ == '__main__':
    unittest.main()
