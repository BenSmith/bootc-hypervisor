#!/usr/bin/env python3
"""Unit tests for cmd_create (flag -> TOML) and the validate_single VM guard.

cmd_create turns ~20 CLI flags into a workload TOML; this pins the section/key
emission and the up-front name/duplicate rejection. validate_single previously
ran the container-image check unconditionally — for a VM that meant a pointless
`podman image inspect "(vm)"`; the guard added alongside these tests skips it,
and test_validate_single_vm_skips_image_check locks that in.
"""

import argparse
import io
import os
import sys
import tempfile
import tomllib
import types
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

LIB = os.path.join(os.path.dirname(__file__), "..", "lib")
if LIB not in sys.path:
    sys.path.insert(0, LIB)

import workload_lib          # noqa: E402
import cmd_admin            # noqa: E402
from workloadctl_core import WorkloadConfig, WorkloadManager  # noqa: E402


def _create_ns(**kw):
    """Namespace with every attribute cmd_create reads, defaulted off."""
    base = dict(
        name=None, image=None, systemd=None, groups=None,
        device=None, gpu=None, input=False, audio=False, virtualization=False,
        network=None, ports=None, volumes=None,
        cpu_quota=None, cpu_weight=None, memory_max=None, memory_high=None,
        memory_swap_max=None, io_weight=None, tasks_max=None, shm_size=None,
        enable=False,
    )
    base.update(kw)
    return argparse.Namespace(**base)


class CreateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        self.enterContext(mock.patch.object(cmd_admin, "require_root", lambda: None))
        # Isolate flag->TOML from the validation pass (covered separately).
        self.enterContext(mock.patch.object(
            cmd_admin, "validate_single", lambda c, m, json_mode=False: {"passed": True}))
        self.manager = mock.Mock()

    def _create(self, **kw):
        out, err = io.StringIO(), io.StringIO()
        code = None
        try:
            with redirect_stdout(out), redirect_stderr(err):
                cmd_admin.cmd_create(_create_ns(**kw), self.manager)
        except SystemExit as e:
            code = e.code
        self._err = err.getvalue()
        return code

    def _toml(self, name):
        return tomllib.loads((self.tmp / name / "workload.toml").read_text())

    # --- rejection paths ---------------------------------------------------

    def test_rejects_invalid_name(self):
        code = self._create(name="../evil", image="nginx")
        self.assertEqual(code, 1)
        self.assertIn("Error", self._err)
        self.assertFalse(list(self.tmp.glob("*/workload.toml")))  # nothing written

    def test_rejects_duplicate(self):
        (self.tmp / "web").mkdir()
        (self.tmp / "web" / "workload.toml").write_text("[workload]\nname = \"web\"\n")
        code = self._create(name="web", image="nginx")
        self.assertEqual(code, 1)
        self.assertIn("already exists", self._err)

    # --- flag -> TOML ------------------------------------------------------

    def test_minimal(self):
        self.assertIsNone(self._create(name="web", image="nginx:latest"))
        data = self._toml("web")
        self.assertEqual(data["workload"]["name"], "web")
        # Created workloads start disabled: no `enabled` key is written and no
        # .enabled marker exists.
        self.assertNotIn("enabled", data["workload"])
        self.assertFalse((self.tmp / "web" / ".enabled").exists())
        self.assertEqual(data["container"]["image"], "nginx:latest")
        for absent in ("devices", "network", "storage", "resources", "security"):
            self.assertNotIn(absent, data)

    def test_systemd_flag(self):
        self._create(name="web", image="x", systemd="/sbin/init")
        self.assertEqual(self._toml("web")["container"]["systemd"], "/sbin/init")

    def test_device_flags(self):
        self._create(name="gpubox", image="x", gpu="all",
                     audio=True, virtualization=True, device=["/dev/foo"])
        dev = self._toml("gpubox")["devices"]
        self.assertEqual(dev["gpu"], "all")
        self.assertTrue(dev["audio"])
        self.assertTrue(dev["virtualization"])
        self.assertEqual(dev["devices"], ["/dev/foo"])

    def test_ports_default_to_pasta(self):
        # ports without an explicit network mode default to pasta.
        self._create(name="web", image="x", ports=["8080:80"])
        net = self._toml("web")["network"]
        self.assertEqual(net["mode"], "pasta")
        self.assertEqual(net["ports"], ["8080:80"])

    def test_host_network_drops_ports(self):
        # host/none modes can't publish ports — the ports key must be omitted.
        self._create(name="web", image="x", network="host", ports=["8080:80"])
        net = self._toml("web")["network"]
        self.assertEqual(net["mode"], "host")
        self.assertNotIn("ports", net)

    def test_volumes(self):
        self._create(name="web", image="x", volumes=["./data:/data", "/etc/h:/h:ro"])
        self.assertEqual(self._toml("web")["storage"]["volumes"],
                         ["./data:/data", "/etc/h:/h:ro"])

    def test_resources(self):
        self._create(name="web", image="x", memory_max="512M",
                     cpu_weight=50, tasks_max=128)
        res = self._toml("web")["resources"]
        self.assertEqual(res["memory_max"], "512M")
        self.assertEqual(res["cpu_weight"], 50)
        self.assertEqual(res["tasks_max"], 128)

    def test_groups(self):
        self._create(name="web", image="x", groups=["render", "video"])
        self.assertEqual(self._toml("web")["security"]["extra_groups"],
                         ["render", "video"])


_VM_TOML = """\
[workload]
name = "clitest-vmguard"

[vm]
cloud_image_url = "https://example.invalid/f.qcow2"
vcpus = 1
memory = "1024M"
system_disk_size = "10G"
user = "workload"
"""


class ValidateSingleVMGuardTest(unittest.TestCase):
    """A VM has no container image; validate_single must not try to inventory
    one (no `podman image inspect "(vm)"`)."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        (self.tmp / "clitest-vmguard").mkdir()
        (self.tmp / "clitest-vmguard" / "workload.toml").write_text(_VM_TOML)
        # Make the workload "user" resolvable so the user_exists path runs.
        fake_pw = types.SimpleNamespace(
            pw_uid=10001, pw_gid=10001, pw_dir=str(self.tmp / "home"))
        self.enterContext(mock.patch("pwd.getpwnam", lambda n: fake_pw))
        # Stub the host probes validate_single fires under user_exists.
        fake_proc = types.SimpleNamespace(returncode=1, stdout="", stderr="")
        self.enterContext(mock.patch.object(cmd_admin.subprocess, "run",
                                            lambda *a, **k: fake_proc))

    def test_validate_single_vm_skips_image_check(self):
        config = WorkloadConfig("clitest-vmguard")
        self.assertTrue(config.is_vm)

        manager = mock.Mock(spec=WorkloadManager)
        manager.user_exists.return_value = True
        manager.get_all_configs.return_value = []
        # If the guard regressed, this would be invoked → assert it isn't.
        manager.get_image_id.side_effect = AssertionError(
            "validate_single must not inventory an image for a VM workload")
        pod = mock.Mock()
        pod.container_status.return_value = ""
        pod.image_id.return_value = ""
        manager.podman.return_value = pod

        result = cmd_admin.validate_single(config, manager, json_mode=True)

        manager.get_image_id.assert_not_called()
        # No check should reference the "(vm)" image sentinel.
        joined = " ".join(c.get("message", "") for c in result["checks"])
        self.assertNotIn("(vm)", joined)


class CleanupOverrideDirTest(unittest.TestCase):
    """_cleanup_override_dir must not delete the instance dir when workload.toml
    lives inside it (post-subdir flip).  A naive rmdir-to-base would evict the
    config, disabling the workload silently.
    """

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        # Seed a workload with the new subdir layout.
        instance_dir = self.tmp / "myapp"
        instance_dir.mkdir()
        (instance_dir / "workload.toml").write_text(
            '[workload]\nname = "myapp"\n'
            '\n[container]\nimage = "localhost/myapp:latest"\n'
        )
        self.instance_dir = instance_dir

    def test_workload_toml_survives_cleanup(self):
        """Dropping an override file from override_dir must leave workload.toml
        (and the dir itself) intact — the OSError on rmdir is the correct stop."""
        config = WorkloadConfig("myapp")

        # Plant a control-file override directly in override_dir, then remove
        # it (simulating what cmd_admin does before calling _cleanup_override_dir).
        override_file = self.instance_dir / "Containerfile"
        override_file.write_text("FROM scratch\n")
        override_file.unlink()

        cmd_admin._cleanup_override_dir(config, override_file)

        # workload.toml must survive — rmdir hit OSError and stopped correctly.
        self.assertTrue((self.instance_dir / "workload.toml").exists(),
                        "workload.toml was deleted by _cleanup_override_dir")
        self.assertTrue(self.instance_dir.exists(),
                        "instance dir was deleted by _cleanup_override_dir")


if __name__ == "__main__":
    unittest.main()
