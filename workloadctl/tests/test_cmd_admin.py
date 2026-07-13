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
import json
import os
import sys
import tempfile
import tomllib
import types
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock


import workload_lib          # noqa: E402
import cmd_admin            # noqa: E402
import workloadctl_core      # noqa: E402
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


class ValidateSingleVmMemoryPrecisionTest(unittest.TestCase):
    """vm.memory in 'K' notation truncates via integer division to MiB
    (parse_memory_mib rounds down) — validate_single should surface that
    precision loss as a warning instead of leaving it silent."""

    def _write_vm_config(self, name, memory):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        (self.tmp / name).mkdir()
        checksum = "0" * 64
        (self.tmp / name / "workload.toml").write_text(f"""
[workload]
name = "{name}"

[vm]
cloud_image_url = "https://example.invalid/f.qcow2"
cloud_image_checksum = "sha256:{checksum}"
vcpus = 1
memory = "{memory}"
system_disk_size = "10G"
user = "workload"
""")
        fake_pw = types.SimpleNamespace(
            pw_uid=10001, pw_gid=10001, pw_dir=str(self.tmp / "home"))
        self.enterContext(mock.patch("pwd.getpwnam", lambda n: fake_pw))
        fake_proc = types.SimpleNamespace(returncode=1, stdout="", stderr="")
        self.enterContext(mock.patch.object(cmd_admin.subprocess, "run",
                                            lambda *a, **k: fake_proc))
        config = WorkloadConfig(name)
        manager = mock.Mock(spec=WorkloadManager)
        manager.user_exists.return_value = True
        manager.get_all_configs.return_value = []
        pod = mock.Mock()
        pod.container_status.return_value = ""
        pod.image_id.return_value = ""
        manager.podman.return_value = pod
        return cmd_admin.validate_single(config, manager, json_mode=True)

    def test_lossy_k_value_warns(self):
        # 500000K // 1024 = 488M with a 288K remainder — lossy, and still
        # above the 256 MiB schema minimum so the check is isolated.
        result = self._write_vm_config("clitest-vmmem-lossy", "500000K")

        precision = [c for c in result["checks"] if c["check"] == "vm_memory_precision"]
        self.assertTrue(precision, "expected a vm_memory_precision check")
        self.assertEqual(precision[0]["severity"], "warning")
        self.assertIn("500000K", precision[0]["message"])
        self.assertIn("488M", precision[0]["message"])
        self.assertEqual(result["warnings"], 1)
        self.assertTrue(result["passed"])  # a warning must not fail validation

    def test_exact_k_value_does_not_warn(self):
        result = self._write_vm_config("clitest-vmmem-exact", "262144K")

        precision = [c for c in result["checks"] if c["check"] == "vm_memory_precision"]
        self.assertFalse(precision)

    def test_m_suffix_does_not_warn(self):
        result = self._write_vm_config("clitest-vmmem-mib", "1024M")

        precision = [c for c in result["checks"] if c["check"] == "vm_memory_precision"]
        self.assertFalse(precision)


class ValidateSingleSchemaTest(unittest.TestCase):
    """validate_single runs the same schema checks as the boot generator, so a
    mode/shape mismatch is caught by `validate`/`install` before a boot."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        (self.tmp / "clitest-badmode").mkdir()
        (self.tmp / "clitest-badmode" / "workload.toml").write_text(
            '[workload]\nname = "clitest-badmode"\nmode = "pod"\n\n'
            '[container]\nimage = "x:latest"\n'
        )

    def test_schema_error_surfaced(self):
        config = WorkloadConfig("clitest-badmode")
        manager = mock.Mock(spec=WorkloadManager)
        manager.user_exists.return_value = False
        manager.get_all_configs.return_value = []

        result = cmd_admin.validate_single(config, manager, json_mode=True)

        schema = [c for c in result["checks"] if c["check"] == "schema"]
        self.assertTrue(schema and not schema[0]["passed"])
        self.assertIn("requires [[containers]]", schema[0]["message"])


class ValidateSingleGeneratorWarningsTest(unittest.TestCase):
    """validate_single surfaces the generator's otherwise-kmsg-only warnings
    (invalid userns, bridge-mode ports ignored, pet-in-multi, unknown
    requires/after) as non-fatal warning checks (U4)."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))

    def _validate(self, name, toml, known=()):
        (self.tmp / name).mkdir()
        (self.tmp / name / "workload.toml").write_text(toml)
        config = WorkloadConfig(name)
        manager = mock.Mock(spec=WorkloadManager)
        manager.user_exists.return_value = False
        manager.get_all_configs.return_value = [
            types.SimpleNamespace(name=n, path=None) for n in known
        ]
        return cmd_admin.validate_single(config, manager, json_mode=True)

    def test_invalid_userns_surfaced_as_warning(self):
        result = self._validate(
            "clitest-userns",
            '[workload]\nname = "clitest-userns"\n\n'
            '[container]\nimage = "x:latest"\n\n'
            '[security]\nuserns = "private"\n',
        )
        warns = [c for c in result["checks"] if c["check"] == "generator_warning"]
        self.assertTrue(any("invalid userns" in c["message"] for c in warns))
        self.assertTrue(result["passed"], "a warning must not fail validation")
        self.assertGreaterEqual(result["warnings"], 1)

    def test_unknown_requires_surfaced(self):
        result = self._validate(
            "clitest-req",
            '[workload]\nname = "clitest-req"\nrequires = ["ghost"]\n\n'
            '[container]\nimage = "x:latest"\n',
            known=("clitest-req",),
        )
        warns = [c for c in result["checks"] if c["check"] == "generator_warning"]
        self.assertTrue(any("ghost" in c["message"] for c in warns))


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

    def test_climbs_and_removes_empty_nested_dirs(self):
        """A nested override (sub/file) leaves an empty `sub/` after removal;
        cleanup must climb up and rmdir it, stopping at the config dir (base)."""
        config = WorkloadConfig("myapp")
        sub = self.instance_dir / "rootfs"
        sub.mkdir()
        override_file = sub / "extra.conf"
        # File already removed; only the now-empty sub/ remains to be reaped.
        cmd_admin._cleanup_override_dir(config, override_file)
        self.assertFalse(sub.exists(), "empty nested override dir not removed")
        self.assertTrue((self.instance_dir / "workload.toml").exists())
        self.assertTrue(self.instance_dir.exists())


class DiagnoseTest(unittest.TestCase):
    """cmd_diagnose on a workload whose user was never created: the user-gated
    checks are skipped and the run reports failure. Exercises the check spine,
    service-state probes, and both json/text output branches."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        self.enterContext(mock.patch.object(cmd_admin, "require_root", lambda: None))
        (self.tmp / "app").mkdir()
        (self.tmp / "app" / "workload.toml").write_text(
            '[workload]\nname = "app"\n\n[container]\nimage = "localhost/app:latest"\n'
        )
        self.manager = mock.Mock()
        self.manager.user_exists.return_value = False
        # All systemctl/loginctl probes report "not enabled / not active".
        self.enterContext(mock.patch.object(
            cmd_admin.subprocess, "run",
            return_value=mock.Mock(returncode=1, stdout="", stderr="")))

    def _run(self, json_mode):
        out, err = io.StringIO(), io.StringIO()
        ns = argparse.Namespace(workload="app", json=json_mode)
        code = None
        try:
            with redirect_stdout(out), redirect_stderr(err):
                cmd_admin.cmd_diagnose(ns, self.manager)
        except SystemExit as e:
            code = e.code
        return code, out.getvalue()

    def test_collector_returns_checks_without_printing(self):
        # The seam doctor consumes: (checks, passed), no root gate, no output.
        out = io.StringIO()
        with redirect_stdout(out):
            checks, passed = cmd_admin.collect_diagnose_checks(
                cmd_admin.WorkloadConfig("app"), self.manager)
        self.assertEqual(out.getvalue(), "")
        self.assertFalse(passed)
        self.assertIn("user_exists", {c["check"] for c in checks})

    def test_json_reports_failure(self):
        code, out = self._run(json_mode=True)
        self.assertEqual(code, 1)
        import json as _json
        data = _json.loads(out)
        self.assertFalse(data["passed"])
        self.assertEqual(data["workload"], "app")
        names = {c["check"] for c in data["checks"]}
        self.assertIn("user_exists", names)
        # user-gated checks must be absent when the user does not exist
        self.assertNotIn("subid_configured", names)

    def test_text_lists_issues_and_exits_1(self):
        code, out = self._run(json_mode=False)
        self.assertEqual(code, 1)
        self.assertIn("Diagnosing workload: app", out)
        self.assertIn("Issues found:", out)
        self.assertIn("workloadctl enable app", out)


class AskYesNoTest(unittest.TestCase):
    def test_yes_variants_true(self):
        for ans in ("y", "Y", "yes", "YES", " yes "):
            with mock.patch("builtins.input", return_value=ans):
                self.assertTrue(cmd_admin._ask_yes_no("? "))

    def test_no_and_empty_false(self):
        for ans in ("n", "no", "", "maybe"):
            with mock.patch("builtins.input", return_value=ans):
                self.assertFalse(cmd_admin._ask_yes_no("? "))

    def test_eof_is_no(self):
        with mock.patch("builtins.input", side_effect=EOFError), \
             redirect_stdout(io.StringIO()):
            self.assertFalse(cmd_admin._ask_yes_no("? "))


class ValidateControlFileNameTest(unittest.TestCase):
    def test_nested_relative_ok(self):
        cmd_admin._validate_control_file_name("rootfs/app.conf")  # no raise

    def test_empty_rejected(self):
        for bad in ("", "   "):
            with self.assertRaises(ValueError):
                cmd_admin._validate_control_file_name(bad)

    def test_absolute_rejected(self):
        with self.assertRaises(ValueError):
            cmd_admin._validate_control_file_name("/etc/passwd")

    def test_traversal_rejected(self):
        with self.assertRaises(ValueError):
            cmd_admin._validate_control_file_name("../../etc/passwd")


class AssertNoSymlinkEscapeTest(unittest.TestCase):
    def setUp(self):
        self.base = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def test_clean_path_ok(self):
        target = self.base / "sub" / "file"
        (self.base / "sub").mkdir()
        cmd_admin._assert_no_symlink_escape(self.base, target)  # no raise

    def test_symlinked_component_rejected(self):
        (self.base / "sub").symlink_to("/tmp")
        target = self.base / "sub" / "file"
        with self.assertRaises(ValueError):
            cmd_admin._assert_no_symlink_escape(self.base, target)

    def test_symlinked_base_rejected(self):
        real = Path(self.enterContext(tempfile.TemporaryDirectory()))
        link = real / "link"
        link.symlink_to("/tmp")
        with self.assertRaises(ValueError):
            cmd_admin._assert_no_symlink_escape(link, link / "file")


class PrintControlFileNextStepsTest(unittest.TestCase):
    def _cfg(self, setup=""):
        cfg = mock.Mock()
        cfg.config = {"host": {"setup": setup}}
        cfg.build_containerfile = "Containerfile"
        cfg.build_script = "build.sh"
        cfg.name = "app"
        cfg.override_dir = Path("/etc/workloads.d/app")
        return cfg

    def _steps(self, rel, setup=""):
        out = io.StringIO()
        with redirect_stdout(out):
            cmd_admin._print_control_file_next_steps(self._cfg(setup), rel)
        return out.getvalue()

    def test_policy_cil_hints_enable(self):
        self.assertIn("enable app", self._steps("policy.cil"))

    def test_build_file_hints_rebuild(self):
        out = self._steps("Containerfile")
        self.assertIn("build app", out)
        self.assertIn("recreate app", out)

    def test_setup_file_hints_enable(self):
        self.assertIn("enable app", self._steps("setup.sh", setup="setup.sh"))

    def test_generic_file_hints_recreate(self):
        self.assertIn("recreate app", self._steps("caddy/Caddyfile"))


def _open_router(fake_paths, real_open=open):
    """open() side_effect: serve `fake_paths` (path str -> content str or None
    for FileNotFoundError) and fall through to the real open() for everything
    else."""
    def _opener(path, *a, **k):
        p = str(path)
        if p in fake_paths:
            content = fake_paths[p]
            if content is None:
                raise FileNotFoundError(p)
            return io.StringIO(content)
        return real_open(path, *a, **k)
    return _opener


class DiagnoseUserExistsTest(unittest.TestCase):
    """cmd_diagnose with an existing user: exercises the user-gated check
    spine (subid, linger, session, selinux, runtime/home dirs, image
    availability, service files, config-current, enabled/active, container
    running, volumes, uid mapping)."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        self.enterContext(mock.patch.object(cmd_admin, "require_root", lambda: None))
        (self.tmp / "app").mkdir()
        (self.tmp / "app" / "workload.toml").write_text(
            '[workload]\nname = "app"\n\n[container]\nimage = "localhost/app:latest"\n'
            '\n[storage]\nvolumes = ["./data:/data"]\n'
        )
        self.home = self.tmp / "home-app"
        fake_pw = types.SimpleNamespace(pw_uid=10005, pw_gid=10005, pw_dir=str(self.home))
        self.enterContext(mock.patch("pwd.getpwnam", lambda n: fake_pw))
        self.enterContext(mock.patch.object(cmd_admin, "units_outdated", lambda name: False))

        self.manager = mock.Mock()
        self.manager.user_exists.return_value = True
        self.pod = mock.Mock()
        self.manager.podman.return_value = self.pod
        self.manager.get_image_id.return_value = "deadbeef1234"

        # Default: subuid/subgid present, everything "yes"/active.
        self._subuid = "_wl-app:100000:65536\n"
        self._subgid = "_wl-app:100000:65536\n"
        self._proc_map = {}  # argv tuple -> Mock(returncode, stdout)

    def _exists_patch(self, false_substrings=()):
        """Path.exists stand-in: real filesystem for anything under self.tmp
        (workload.toml, .enabled marker, overrides — must reflect what the
        test actually wrote), True for everything else (synthetic /run,
        /var/lib/workloads paths this test doesn't create on disk) unless its
        path contains one of `false_substrings`."""
        real_exists = Path.exists
        tmp_str = str(self.tmp)

        def _exists(path_self):
            p = str(path_self)
            if p.startswith(tmp_str):
                return real_exists(path_self)
            if any(sub in p for sub in false_substrings):
                return False
            return True
        return _exists

    def _run(self, json_mode=True, false_substrings=()):
        opener = _open_router({
            "/etc/subuid": self._subuid,
            "/etc/subgid": self._subgid,
        })

        def _run_side_effect(argv, **kw):
            key = tuple(argv)
            if key in self._proc_map:
                return self._proc_map[key]
            return mock.Mock(returncode=1, stdout="", stderr="")

        self.enterContext(mock.patch("builtins.open", side_effect=opener))
        self.enterContext(mock.patch.object(cmd_admin.subprocess, "run", side_effect=_run_side_effect))
        self.enterContext(mock.patch.object(Path, "exists", self._exists_patch(false_substrings)))

        out, err = io.StringIO(), io.StringIO()
        ns = argparse.Namespace(workload="app", json=json_mode)
        code = None
        try:
            with redirect_stdout(out), redirect_stderr(err):
                cmd_admin.cmd_diagnose(ns, self.manager)
        except SystemExit as e:
            code = e.code
        return code, out.getvalue()

    def _set_proc(self, argv, returncode=0, stdout=""):
        self._proc_map[tuple(argv)] = mock.Mock(returncode=returncode, stdout=stdout, stderr="")

    def test_all_pass_when_healthy(self):
        self._set_proc(["loginctl", "show-user", "10005", "--property=Linger", "--value"],
                        returncode=0, stdout="yes")
        self._set_proc(["systemctl", "is-active", "user@10005.service"], returncode=0)
        self._set_proc(["systemctl", "is-enabled", cmd_admin.WorkloadConfig("app").service_name],
                        returncode=0)
        self._set_proc(["systemctl", "is-active", cmd_admin.WorkloadConfig("app").service_name],
                        returncode=0, stdout="active")
        self.pod.container_status.return_value = "running"

        code, out = self._run(json_mode=True)
        data = json.loads(out)
        self.assertTrue(data["passed"], data["checks"])
        self.assertEqual(code, 0)
        names = {c["check"] for c in data["checks"]}
        self.assertIn("subid_configured", names)
        self.assertIn("linger_enabled", names)
        self.assertIn("user_session", names)
        self.assertIn("image_available", names)
        self.assertIn("container_running", names)
        self.assertIn("volume_paths", names)

    def test_subid_missing_reports_failure(self):
        self._subuid = ""  # no matching entry
        code, out = self._run(json_mode=True)
        data = json.loads(out)
        check = next(c for c in data["checks"] if c["check"] == "subid_configured")
        self.assertFalse(check["passed"])
        self.assertIn("workload-ensure-user", check["fix"])

    def test_linger_disabled_skips_session_check(self):
        # linger stays False (default "no" reply) -> user_session check absent.
        code, out = self._run(json_mode=True)
        data = json.loads(out)
        names = {c["check"] for c in data["checks"]}
        self.assertNotIn("user_session", names)
        linger_check = next(c for c in data["checks"] if c["check"] == "linger_enabled")
        self.assertFalse(linger_check["passed"])
        self.assertIn("enable-linger", linger_check["fix"])

    def test_session_dead_despite_linger(self):
        self._set_proc(["loginctl", "show-user", "10005", "--property=Linger", "--value"],
                        returncode=0, stdout="yes")
        # user@<uid>.service is-active left failing (default).
        code, out = self._run(json_mode=True)
        data = json.loads(out)
        check = next(c for c in data["checks"] if c["check"] == "user_session")
        self.assertFalse(check["passed"])
        self.assertIn("do NOT use 'loginctl terminate-user'", check["fix"])

    def test_runtime_dir_missing_with_linger_hints_restart(self):
        self._set_proc(["loginctl", "show-user", "10005", "--property=Linger", "--value"],
                        returncode=0, stdout="yes")
        code, out = self._run(json_mode=True, false_substrings=("/run/user/",))
        data = json.loads(out)
        check = next(c for c in data["checks"] if c["check"] == "runtime_dir")
        self.assertFalse(check["passed"])
        self.assertIn("restart user@10005.service", check["fix"])
        self.assertNotIn("enable-linger", check["fix"])

    def test_runtime_dir_missing_without_linger_hints_enable_linger(self):
        code, out = self._run(json_mode=True, false_substrings=("/run/user/",))
        data = json.loads(out)
        check = next(c for c in data["checks"] if c["check"] == "runtime_dir")
        self.assertFalse(check["passed"])
        self.assertIn("enable-linger", check["fix"])

    def test_image_not_available_pull_missing_default(self):
        self.manager.get_image_id.return_value = ""
        code, out = self._run(json_mode=True)
        data = json.loads(out)
        check = next(c for c in data["checks"] if c["check"] == "image_available")
        self.assertFalse(check["passed"])
        self.assertEqual(check["fix"], "Image will be pulled on first start")

    def test_image_not_available_pull_never_no_build_script(self):
        (self.tmp / "app" / "workload.toml").write_text(
            '[workload]\nname = "app"\n\n[container]\nimage = "localhost/app:latest"\n'
            'pull = "never"\n'
        )
        self.manager.get_image_id.return_value = ""
        code, out = self._run(json_mode=True, false_substrings=("build.sh",))
        data = json.loads(out)
        check = next(c for c in data["checks"] if c["check"] == "image_available")
        self.assertFalse(check["passed"])
        self.assertIn("Build or provide", check["fix"])

    def test_config_current_outdated(self):
        self.enterContext(mock.patch.object(cmd_admin, "units_outdated", lambda name: True))
        code, out = self._run(json_mode=True)
        data = json.loads(out)
        check = next(c for c in data["checks"] if c["check"] == "config_current")
        self.assertFalse(check["passed"])
        self.assertIn("stale", check["message"])

    def test_service_not_active_disabled_workload(self):
        # config.enabled is False (no marker); service_active failure fix
        # should say "disabled" not "check logs".
        code, out = self._run(json_mode=True)
        data = json.loads(out)
        check = next(c for c in data["checks"] if c["check"] == "service_active")
        self.assertFalse(check["passed"])
        self.assertIn("disabled", check["fix"])

    def test_service_active_enabled_workload_hints_journalctl(self):
        (self.tmp / "app" / ".enabled").touch()
        code, out = self._run(json_mode=True)
        data = json.loads(out)
        check = next(c for c in data["checks"] if c["check"] == "service_active")
        self.assertFalse(check["passed"])
        self.assertIn("journalctl", check["fix"])

    def test_container_not_running(self):
        self.pod.container_status.return_value = ""
        code, out = self._run(json_mode=True)
        data = json.loads(out)
        check = next(c for c in data["checks"] if c["check"] == "container_running")
        self.assertFalse(check["passed"])
        self.assertIn("journalctl", check["fix"])

    def test_volume_paths_missing(self):
        code, out = self._run(json_mode=True, false_substrings=("/data",))
        data = json.loads(out)
        check = next(c for c in data["checks"] if c["check"] == "volume_paths")
        self.assertFalse(check["passed"])
        self.assertIn("mkdir -p", check["fix"])

    def test_uid_mapping_host_mode(self):
        (self.tmp / "app" / "workload.toml").write_text(
            '[workload]\nname = "app"\n\n[container]\nimage = "localhost/app:latest"\n'
            '\n[security]\nuserns = "host"\n'
        )
        code, out = self._run(json_mode=True)
        data = json.loads(out)
        check = next(c for c in data["checks"] if c["check"] == "uid_mapping")
        self.assertTrue(check["passed"])
        self.assertIn("host UIDs 100000-165535", check["message"])

    def test_uid_mapping_host_mode_no_subuid_entry(self):
        (self.tmp / "app" / "workload.toml").write_text(
            '[workload]\nname = "app"\n\n[container]\nimage = "localhost/app:latest"\n'
            '\n[security]\nuserns = "host"\n'
        )
        self._subuid = ""
        code, out = self._run(json_mode=True)
        data = json.loads(out)
        check = next(c for c in data["checks"] if c["check"] == "uid_mapping")
        self.assertFalse(check["passed"])
        self.assertIn("Cannot calculate", check["message"])

    def test_selinux_module_missing_tool(self):
        (self.tmp / "app" / "workload.toml").write_text(
            '[workload]\nname = "app"\n\n[container]\nimage = "localhost/app:latest"\n'
            '\n[security]\nselinux_policy = true\n'
        )
        with mock.patch.object(cmd_admin.shutil, "which", return_value=None):
            code, out = self._run(json_mode=True)
        data = json.loads(out)
        check = next(c for c in data["checks"] if c["check"] == "selinux_module")
        self.assertFalse(check["passed"])
        self.assertIn("dnf install", check["fix"])

    def test_selinux_module_not_loaded(self):
        (self.tmp / "app" / "workload.toml").write_text(
            '[workload]\nname = "app"\n\n[container]\nimage = "localhost/app:latest"\n'
            '\n[security]\nselinux_policy = true\n'
        )
        self._set_proc(["semodule", "-l"], returncode=0, stdout="some_other_module\n")
        with mock.patch.object(cmd_admin.shutil, "which", return_value="/usr/sbin/semodule"):
            code, out = self._run(json_mode=True)
        data = json.loads(out)
        check = next(c for c in data["checks"] if c["check"] == "selinux_module")
        self.assertFalse(check["passed"])
        self.assertIn("workloadctl enable", check["fix"])

    def test_vm_workload_skips_image_check(self):
        (self.tmp / "app" / "workload.toml").write_text(
            '[workload]\nname = "app"\n\n[vm]\ncloud_image_url = "https://x/f.qcow2"\n'
            'vcpus = 1\nmemory = "512M"\nsystem_disk_size = "5G"\nuser = "w"\n'
        )
        code, out = self._run(json_mode=True)
        data = json.loads(out)
        names = {c["check"] for c in data["checks"]}
        self.assertNotIn("image_available", names)
        self.manager.get_image_id.assert_not_called()

    def test_text_mode_all_pass_prints_healthy(self):
        self._set_proc(["loginctl", "show-user", "10005", "--property=Linger", "--value"],
                        returncode=0, stdout="yes")
        self._set_proc(["systemctl", "is-active", "user@10005.service"], returncode=0)
        self._set_proc(["systemctl", "is-enabled", "workload-app.service"], returncode=0)
        self._set_proc(["systemctl", "is-active", "workload-app.service"], returncode=0, stdout="active")
        self.pod.container_status.return_value = "running"
        code, out = self._run(json_mode=False)
        self.assertEqual(code, 0)
        self.assertIn("All checks passed", out)


class CmdValidateTest(unittest.TestCase):
    """cmd_validate: --all vs single-workload, json vs text, exit codes."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        (self.tmp / "app").mkdir()
        (self.tmp / "app" / "workload.toml").write_text(
            '[workload]\nname = "app"\n\n[container]\nimage = "localhost/app:latest"\n'
        )
        self.manager = mock.Mock()
        self.manager.get_all_configs.return_value = [WorkloadConfig("app")]
        self.enterContext(mock.patch("pwd.getpwnam", side_effect=KeyError))
        self.enterContext(mock.patch.object(
            cmd_admin.grp, "getgrnam", side_effect=KeyError))

    def _run(self, ns):
        out, err = io.StringIO(), io.StringIO()
        code = None
        try:
            with redirect_stdout(out), redirect_stderr(err):
                cmd_admin.cmd_validate(ns, self.manager)
        except SystemExit as e:
            code = e.code
        return code, out.getvalue()

    def test_missing_workload_name_errors(self):
        code, _ = self._run(argparse.Namespace(all=False, workload=None, json=False))
        self.assertEqual(code, 1)

    def test_single_workload_json(self):
        code, out = self._run(argparse.Namespace(all=False, workload="app", json=True))
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["workload"], "app")
        self.assertTrue(data["passed"])

    def test_all_json_aggregates(self):
        code, out = self._run(argparse.Namespace(all=True, workload=None, json=True))
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertTrue(data["all_passed"])
        self.assertEqual(len(data["validation_results"]), 1)

    def test_all_text_mode(self):
        code, out = self._run(argparse.Namespace(all=True, workload=None, json=False))
        self.assertEqual(code, 0)
        self.assertIn("Validating: app", out)

    def test_all_json_reports_failure_exit_1(self):
        # A missing extra-group makes validation fail; --all must exit 1 and
        # mark all_passed False.
        (self.tmp / "app" / "workload.toml").write_text(
            '[workload]\nname = "app"\n\n[container]\nimage = "x"\n'
            '\n[security]\nextra_groups = ["ghost-group"]\n')
        self.manager.get_all_configs.return_value = [WorkloadConfig("app")]
        code, out = self._run(argparse.Namespace(all=True, workload=None, json=True))
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertFalse(data["all_passed"])


class EditControlFileTest(unittest.TestCase):
    """_edit_control_file: seeding, editor-failure rollback, and the two
    no-op-discard branches (identical-to-default, empty new file)."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        (self.tmp / "app").mkdir()
        (self.tmp / "app" / "workload.toml").write_text(
            '[workload]\nname = "app"\n\n[container]\nimage = "localhost/app:latest"\n'
        )
        self.bundles = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.bundles / "app").mkdir()
        self.enterContext(mock.patch.object(workloadctl_core, "WORKLOAD_BUNDLES_DIR", self.bundles))
        self.manager = mock.Mock()

    def _run(self, filename, editor_side_effect):
        ns = argparse.Namespace(workload="app", file=filename)
        out, err = io.StringIO(), io.StringIO()
        code = None
        with mock.patch.object(cmd_admin.subprocess, "run", side_effect=editor_side_effect):
            try:
                with redirect_stdout(out), redirect_stderr(err):
                    cmd_admin._edit_control_file(ns, self.manager)
            except SystemExit as e:
                code = e.code
        return code, out.getvalue(), err.getvalue()

    def test_missing_config_errors(self):
        ns = argparse.Namespace(workload="ghost", file="foo.conf")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            with self.assertRaises(SystemExit) as cm:
                cmd_admin._edit_control_file(ns, self.manager)
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("not found", err.getvalue())

    def test_invalid_file_name_errors(self):
        code, out, err = self._run("../escape", lambda *a, **k: mock.Mock(returncode=0))
        self.assertEqual(code, 1)
        self.assertIn("invalid control-file name", err)

    def test_new_file_seeded_and_saved(self):
        def fake_editor(argv, **kw):
            # simulate the user writing content into the seeded file
            Path(argv[-1]).write_text("hello=1\n")
            return mock.Mock(returncode=0)
        code, out, err = self._run("custom.conf", fake_editor)
        self.assertIsNone(code)
        self.assertIn("No shipped default", out)
        self.assertIn("Override saved", out)
        self.assertEqual((self.tmp / "app" / "custom.conf").read_text(), "hello=1\n")

    def test_editor_failure_rolls_back_seeded_file(self):
        code, out, err = self._run(
            "custom.conf", lambda *a, **k: mock.Mock(returncode=1))
        self.assertEqual(code, 1)
        self.assertIn("Editor exited with error code", err)
        self.assertFalse((self.tmp / "app" / "custom.conf").exists())

    def test_empty_untouched_new_file_discarded(self):
        code, out, err = self._run(
            "custom.conf", lambda *a, **k: mock.Mock(returncode=0))
        self.assertIsNone(code)
        self.assertIn("Empty file", out)
        self.assertFalse((self.tmp / "app" / "custom.conf").exists())

    def test_identical_to_default_discarded(self):
        (self.bundles / "app" / "shipped.conf").write_text("same\n")

        def fake_editor(argv, **kw):
            return mock.Mock(returncode=0)  # leave content == seeded == default
        code, out, err = self._run("shipped.conf", fake_editor)
        self.assertIsNone(code)
        self.assertIn("Seeded override from shipped default", out)
        self.assertIn("No change from the shipped default", out)
        self.assertFalse((self.tmp / "app" / "shipped.conf").exists())


class ValidateSingleErrorsTest(unittest.TestCase):
    """validate_single is the config correctness/security boundary shared by
    create/edit/validate. Each error/warning branch must fire on bad input and
    stay quiet on good input."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        self.manager = mock.Mock()
        self.manager.get_all_configs.return_value = []

    def _cfg(self, toml, name="app"):
        d = self.tmp / name
        d.mkdir(exist_ok=True)
        (d / "workload.toml").write_text(toml)
        return WorkloadConfig(name)

    def _validate(self, config, json_mode=True):
        out = io.StringIO()
        with redirect_stdout(out):
            res = cmd_admin.validate_single(config, self.manager, json_mode=json_mode)
        self._out = out.getvalue()
        return res

    def _check(self, res, name):
        return next((c for c in res["checks"] if c["check"] == name), None)

    def test_username_too_long_is_error(self):
        # Workload names are capped at 27 chars on load, so a >=32-char username
        # is only reachable defensively; patch the property to hit the guard.
        cfg = self._cfg('[workload]\nname = "app"\n\n[container]\nimage = "x"\n')
        with mock.patch.object(type(cfg), "username",
                               new_callable=mock.PropertyMock,
                               return_value="_wl-" + "a" * 30):
            res = self._validate(cfg)
        self.assertFalse(res["passed"])
        c = self._check(res, "username_length")
        self.assertFalse(c["passed"])
        self.assertEqual(c["severity"], "error")

    def test_uid_out_of_range_is_error(self):
        cfg = self._cfg('[workload]\nname = "app"\n\n[container]\nimage = "x"\n')
        fake_pw = types.SimpleNamespace(pw_uid=5000, pw_gid=5000, pw_dir="/x")
        with mock.patch("pwd.getpwnam", lambda n: fake_pw):
            res = self._validate(cfg)
        c = self._check(res, "uid_range")
        self.assertFalse(c["passed"])
        self.assertIn("out of range", c["message"])
        self.assertFalse(res["passed"])

    def test_uid_in_range_ok(self):
        cfg = self._cfg('[workload]\nname = "app"\n\n[container]\nimage = "x"\n')
        fake_pw = types.SimpleNamespace(pw_uid=10500, pw_gid=10500, pw_dir="/x")
        with mock.patch("pwd.getpwnam", lambda n: fake_pw):
            res = self._validate(cfg)
        self.assertTrue(self._check(res, "uid_range")["passed"])

    def test_name_conflict_is_error(self):
        cfg = self._cfg('[workload]\nname = "app"\n\n[container]\nimage = "x"\n')
        other = types.SimpleNamespace(name="app", path="other-file")
        self.manager.get_all_configs.return_value = [other]
        res = self._validate(cfg)
        c = self._check(res, "name_uniqueness")
        self.assertFalse(c["passed"])
        self.assertIn("other-file", c["message"])
        self.assertFalse(res["passed"])

    def test_invalid_lifecycle_is_error(self):
        cfg = self._cfg('[workload]\nname = "app"\nlifecycle = "bogus"\n'
                        '\n[container]\nimage = "x"\n')
        res = self._validate(cfg)
        c = self._check(res, "lifecycle")
        self.assertFalse(c["passed"])
        self.assertIn("Invalid lifecycle", c["message"])

    def test_bad_snapshot_keep_is_error(self):
        for bad in ("0", '"x"', "true"):
            cfg = self._cfg('[workload]\nname = "app"\n'
                            f'snapshot_keep = {bad}\n\n[container]\nimage = "x"\n')
            res = self._validate(cfg)
            c = self._check(res, "snapshot_keep")
            self.assertIsNotNone(c, f"snapshot_keep {bad} not flagged")
            self.assertFalse(c["passed"])

    def test_valid_snapshot_keep_no_error(self):
        cfg = self._cfg('[workload]\nname = "app"\nsnapshot_keep = 5\n'
                        '\n[container]\nimage = "x"\n')
        res = self._validate(cfg)
        self.assertIsNone(self._check(res, "snapshot_keep"))

    def test_bad_bundle_is_error(self):
        cfg = self._cfg('[workload]\nname = "app"\nbundle = "Bad_Bundle"\n'
                        '\n[container]\nimage = "x"\n')
        res = self._validate(cfg)
        c = self._check(res, "bundle")
        self.assertFalse(c["passed"])
        self.assertIn("Invalid bundle", c["message"])

    def test_good_bundle_ok(self):
        cfg = self._cfg('[workload]\nname = "app"\nbundle = "shared-web"\n'
                        '\n[container]\nimage = "x"\n')
        res = self._validate(cfg)
        self.assertTrue(self._check(res, "bundle")["passed"])

    def test_selinux_policy_string_is_warning(self):
        cfg = self._cfg('[workload]\nname = "app"\n\n[container]\nimage = "x"\n'
                        '\n[security]\nselinux_policy = "some-dir"\n')
        res = self._validate(cfg)
        c = self._check(res, "selinux_policy_string")
        self.assertFalse(c["passed"])
        self.assertEqual(c["severity"], "warning")
        # It's a warning, not an error — validation still passes.
        self.assertTrue(res["passed"])
        self.assertEqual(res["warnings"], 1)

    def test_build_containerfile_traversal_is_error(self):
        cfg = self._cfg('[workload]\nname = "app"\n\n[container]\nimage = "x"\n'
                        '\n[build]\ncontainerfile = "../evil"\n')
        res = self._validate(cfg)
        c = self._check(res, "build_containerfile")
        self.assertFalse(c["passed"])
        self.assertIn("no '..'", c["message"])

    def test_build_containerfile_absolute_is_error(self):
        cfg = self._cfg('[workload]\nname = "app"\n\n[container]\nimage = "x"\n'
                        '\n[build]\ncontainerfile = "/etc/passwd"\n')
        res = self._validate(cfg)
        self.assertFalse(self._check(res, "build_containerfile")["passed"])

    def test_build_with_script_summary(self):
        cfg = self._cfg('[workload]\nname = "app"\n\n[container]\nimage = "x"\n'
                        '\n[build]\ncontainerfile = "Containerfile"\nscript = "build.sh"\n')
        res = self._validate(cfg)
        c = self._check(res, "build")
        self.assertTrue(c["passed"])
        self.assertIn("script=build.sh", c["message"])

    def test_build_ok_relative(self):
        cfg = self._cfg('[workload]\nname = "app"\n\n[container]\nimage = "x"\n'
                        '\n[build]\ncontainerfile = "Containerfile"\n')
        res = self._validate(cfg)
        self.assertTrue(self._check(res, "build")["passed"])

    def test_volume_missing_path_is_error(self):
        cfg = self._cfg('[workload]\nname = "app"\n\n[container]\nimage = "x"\n'
                        '\n[storage]\nvolumes = ["/nonexistent/xyz:/d"]\n')
        res = self._validate(cfg)
        vol = next(c for c in res["checks"] if c["check"] == "volume_path")
        self.assertFalse(vol["passed"])
        self.assertIn("does not exist", vol["message"])
        self.assertFalse(res["passed"])

    def test_volume_existing_path_ok(self):
        cfg = self._cfg('[workload]\nname = "app"\n\n[container]\nimage = "x"\n'
                        f'\n[storage]\nvolumes = ["{self.tmp}:/d"]\n')
        res = self._validate(cfg)
        vol = next(c for c in res["checks"] if c["check"] == "volume_path")
        self.assertTrue(vol["passed"])
        self.assertIn("exists", vol["message"])

    def test_volume_under_workload_root_created_on_enable(self):
        cfg0 = self._cfg('[workload]\nname = "app"\n\n[container]\nimage = "x"\n')
        root = str(cfg0.home_dir.parent)
        cfg = self._cfg('[workload]\nname = "app"\n\n[container]\nimage = "x"\n'
                        f'\n[storage]\nvolumes = ["{root}/vol:/d"]\n')
        res = self._validate(cfg)
        vol = next(c for c in res["checks"] if c["check"] == "volume_path")
        self.assertTrue(vol["passed"])
        self.assertIn("created on enable", vol["message"])

    def test_volume_in_required_files_ok(self):
        cfg = self._cfg('[workload]\nname = "app"\n\n[container]\nimage = "x"\n'
                        '\n[storage]\nvolumes = ["./req:/d"]\n'
                        '\n[[setup.required_files]]\npath = "./req"\n')
        res = self._validate(cfg)
        vol = next(c for c in res["checks"] if c["check"] == "volume_path")
        self.assertTrue(vol["passed"])
        self.assertIn("required_files", vol["message"])

    def test_missing_group_is_error(self):
        cfg = self._cfg('[workload]\nname = "app"\n\n[container]\nimage = "x"\n'
                        '\n[security]\nextra_groups = ["no-such-group-xyz"]\n')
        with mock.patch.object(cmd_admin.grp, "getgrnam", side_effect=KeyError):
            res = self._validate(cfg)
        c = next(c for c in res["checks"] if c["check"] == "group_exists")
        self.assertFalse(c["passed"])
        self.assertFalse(res["passed"])

    def test_existing_group_ok(self):
        cfg = self._cfg('[workload]\nname = "app"\n\n[container]\nimage = "x"\n'
                        '\n[security]\nextra_groups = ["render"]\n')
        with mock.patch.object(cmd_admin.grp, "getgrnam", lambda g: object()):
            res = self._validate(cfg)
        self.assertTrue(
            next(c for c in res["checks"] if c["check"] == "group_exists")["passed"])

    def test_custom_directive_conflict_is_warning(self):
        cfg = self._cfg('[workload]\nname = "app"\n\n[container]\nimage = "x"\n'
                        '\n[resources.custom_directives]\nExecStart = "/bin/false"\n')
        res = self._validate(cfg)
        c = next(c for c in res["checks"] if c["check"] == "custom_directives_conflict")
        self.assertEqual(c["severity"], "warning")
        self.assertTrue(res["passed"])  # warning only

    def test_text_mode_prints_symbols_and_failure_summary(self):
        # A config with both an error (missing group) and a warning
        # (selinux string) exercises the ✗/⚠ symbol branches + fix lines and
        # the "Validation failed" summary.
        cfg = self._cfg('[workload]\nname = "app"\n\n[container]\nimage = "x"\n'
                        '\n[security]\nselinux_policy = "d"\nextra_groups = ["nope"]\n')
        with mock.patch.object(cmd_admin.grp, "getgrnam", side_effect=KeyError):
            res = self._validate(cfg, json_mode=False)
        self.assertFalse(res["passed"])
        self.assertIn("✗", self._out)
        self.assertIn("⚠", self._out)
        self.assertIn("Suggested fix:", self._out)
        self.assertIn("Validation failed", self._out)

    def test_text_mode_passes_with_warning_summary(self):
        cfg = self._cfg('[workload]\nname = "app"\n\n[container]\nimage = "x"\n'
                        '\n[security]\nselinux_policy = "d"\n')
        res = self._validate(cfg, json_mode=False)
        self.assertTrue(res["passed"])
        self.assertIn("passed with 1 warning", self._out)


class CreateExtraFlagsTest(CreateTest):
    """Additional cmd_create flag branches not covered by CreateTest."""

    def test_input_flag(self):
        self._create(name="in", image="x", input=True)
        self.assertTrue(self._toml("in")["devices"]["input"])

    def test_all_resource_flags(self):
        self._create(name="res", image="x", shm_size="64M", cpu_quota="50%",
                     cpu_weight=None, memory_max="1G", memory_high="512M",
                     memory_swap_max="0", io_weight=None, tasks_max=None)
        res = self._toml("res")["resources"]
        self.assertEqual(res["shm_size"], "64M")
        self.assertEqual(res["cpu_quota"], "50%")
        self.assertEqual(res["memory_max"], "1G")
        self.assertEqual(res["memory_high"], "512M")
        self.assertEqual(res["memory_swap_max"], "0")

    def test_io_weight_flag(self):
        self._create(name="io", image="x", io_weight=200)
        self.assertEqual(self._toml("io")["resources"]["io_weight"], 200)


class CreateValidationEnableTest(unittest.TestCase):
    """cmd_create post-write behaviour: validation-failure cleanup and the
    --enable hand-off."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        self.enterContext(mock.patch.object(cmd_admin, "require_root", lambda: None))
        self.manager = mock.Mock()

    def _create(self, **kw):
        out, err = io.StringIO(), io.StringIO()
        code = None
        try:
            with redirect_stdout(out), redirect_stderr(err):
                cmd_admin.cmd_create(_create_ns(**kw), self.manager)
        except SystemExit as e:
            code = e.code
        self._out, self._err = out.getvalue(), err.getvalue()
        return code

    def test_validation_failure_exits_1_keeps_config(self):
        # Real validation runs; a bad volume path makes it fail, cmd_create
        # exits 1 but leaves the written config in place for the user to fix.
        with mock.patch.object(
                cmd_admin, "validate_single",
                lambda c, m, json_mode=False: {"passed": False}):
            code = self._create(name="web", image="nginx")
        self.assertEqual(code, 1)
        self.assertIn("Validation found issues", self._err)
        self.assertTrue((self.tmp / "web" / "workload.toml").exists())

    def test_validate_raises_unlinks_config(self):
        with mock.patch.object(
                cmd_admin, "validate_single",
                side_effect=RuntimeError("boom")):
            code = self._create(name="web", image="nginx")
        self.assertEqual(code, 1)
        self.assertIn("Failed to validate", self._err)
        self.assertFalse((self.tmp / "web" / "workload.toml").exists())

    def test_enable_flag_invokes_cmd_enable(self):
        called = {}

        def fake_enable(args, manager):
            called["workload"] = args.workload

        with mock.patch.object(
                cmd_admin, "validate_single",
                lambda c, m, json_mode=False: {"passed": True}), \
             mock.patch.dict(sys.modules, {"cmd_lifecycle": types.SimpleNamespace(cmd_enable=fake_enable)}):
            code = self._create(name="web", image="nginx", enable=True)
        self.assertIsNone(code)
        self.assertEqual(called["workload"], "web")


class DiagnoseMultiContainerTest(unittest.TestCase):
    """cmd_diagnose over a multi-container (pod) workload: exercises the
    per-container image / service-file / running-status branches."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        self.enterContext(mock.patch.object(cmd_admin, "require_root", lambda: None))
        (self.tmp / "app").mkdir()
        (self.tmp / "app" / "workload.toml").write_text(
            '[workload]\nname = "app"\nmode = "pod"\n'
            '\n[[containers]]\nname = "web"\n[containers.container]\nimage = "img/web"\n'
            '\n[[containers]]\nname = "db"\n[containers.container]\nimage = "img/db"\n'
        )
        fake_pw = types.SimpleNamespace(pw_uid=10005, pw_gid=10005, pw_dir=str(self.tmp / "h"))
        self.enterContext(mock.patch("pwd.getpwnam", lambda n: fake_pw))
        self.enterContext(mock.patch.object(cmd_admin, "units_outdated", lambda name: False))
        self.manager = mock.Mock()
        self.manager.user_exists.return_value = True
        self.pod = mock.Mock()
        self.manager.podman.return_value = self.pod
        self.enterContext(mock.patch.object(
            cmd_admin.subprocess, "run",
            return_value=mock.Mock(returncode=1, stdout="", stderr="")))

    def _run(self):
        out = io.StringIO()
        ns = argparse.Namespace(workload="app", json=True)
        code = None
        try:
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                cmd_admin.cmd_diagnose(ns, self.manager)
        except SystemExit as e:
            code = e.code
        return code, json.loads(out.getvalue())

    def test_multi_container_checks_present(self):
        self.pod.image_id.side_effect = lambda img: "abc123def456" if img == "img/web" else ""
        self.pod.container_status.side_effect = lambda pn: "running" if pn.endswith("web") else ""
        code, data = self._run()
        names = {c["check"] for c in data["checks"]}
        self.assertIn("image_available[web]", names)
        self.assertIn("image_available[db]", names)
        self.assertIn("container_running[web]", names)
        self.assertIn("container_running[db]", names)
        # per-container service files probed (all missing → daemon-reload fix)
        self.assertTrue(any(n.startswith("service_file[workload-app-") for n in names))
        db_img = next(c for c in data["checks"] if c["check"] == "image_available[db]")
        self.assertFalse(db_img["passed"])
        web_img = next(c for c in data["checks"] if c["check"] == "image_available[web]")
        self.assertTrue(web_img["passed"])

    def test_multi_sub_service_files_present(self):
        # /run unit files exist → sub-service-file checks pass.
        self.pod.image_id.return_value = ""
        self.pod.container_status.return_value = ""
        with mock.patch.object(Path, "exists", lambda self: True):
            code, data = self._run()
        sub = [c for c in data["checks"]
               if c["check"].startswith("service_file[workload-app-")]
        self.assertTrue(sub)
        self.assertTrue(all(c["passed"] for c in sub))


class DiagnoseEdgeBranchesTest(DiagnoseUserExistsTest):
    """Extra single-container diagnose branches: subid file absent, SELinux
    module loaded, home dir missing, pull=never malformed bundle, uid-mapping
    parse error."""

    def test_subid_files_absent(self):
        self._subuid = None  # /etc/subuid raises FileNotFoundError
        self._subgid = None
        code, out = self._run(json_mode=True)
        data = json.loads(out)
        check = next(c for c in data["checks"] if c["check"] == "subid_configured")
        self.assertFalse(check["passed"])

    def test_selinux_module_loaded(self):
        (self.tmp / "app" / "workload.toml").write_text(
            '[workload]\nname = "app"\n\n[container]\nimage = "localhost/app:latest"\n'
            '\n[security]\nselinux_policy = true\n')
        module = workload_lib.selinux_module_name("app")
        self._set_proc(["semodule", "-l"], returncode=0, stdout=f"foo\n{module}\nbar\n")
        with mock.patch.object(cmd_admin.shutil, "which", return_value="/usr/sbin/semodule"):
            code, out = self._run(json_mode=True)
        data = json.loads(out)
        check = next(c for c in data["checks"] if c["check"] == "selinux_module")
        self.assertTrue(check["passed"])
        self.assertIn("module loaded", check["message"])

    def test_home_dir_missing(self):
        cfg = cmd_admin.WorkloadConfig("app")
        code, out = self._run(json_mode=True, false_substrings=(str(cfg.home_dir),))
        data = json.loads(out)
        check = next(c for c in data["checks"] if c["check"] == "home_dir")
        self.assertFalse(check["passed"])
        self.assertIn("workload-ensure-user", check["fix"])

    def test_pull_never_malformed_bundle_reported_as_fix(self):
        (self.tmp / "app" / "workload.toml").write_text(
            '[workload]\nname = "app"\nbundle = "Bad_Bundle"\n'
            '\n[container]\nimage = "localhost/app:latest"\npull = "never"\n')
        self.manager.get_image_id.return_value = ""
        code, out = self._run(json_mode=True)
        data = json.loads(out)
        check = next(c for c in data["checks"] if c["check"] == "image_available")
        self.assertFalse(check["passed"])
        self.assertIn("Fix [workload] bundle", check["fix"])

    def test_uid_mapping_parse_error(self):
        (self.tmp / "app" / "workload.toml").write_text(
            '[workload]\nname = "app"\n\n[container]\nimage = "localhost/app:latest"\n'
            '\n[security]\nuserns = "host"\n')
        self._subuid = "_wl-app:notanumber:alsobad\n"
        code, out = self._run(json_mode=True)
        data = json.loads(out)
        check = next(c for c in data["checks"] if c["check"] == "uid_mapping")
        self.assertFalse(check["passed"])
        self.assertIn("Error reading subuid", check["message"])


class EditControlFileExtraTest(EditControlFileTest):
    """_edit_control_file: symlink-escape guard and executable-bit handling."""

    def test_symlink_component_rejected(self):
        (self.tmp / "app" / "sub").symlink_to("/tmp")
        code, out, err = self._run("sub/x.conf", lambda *a, **k: mock.Mock(returncode=0))
        self.assertEqual(code, 1)
        self.assertIn("symlink", err)

    def test_new_sh_file_is_executable(self):
        def editor(argv, **kw):
            Path(argv[-1]).write_text("#!/bin/sh\necho hi\n")
            return mock.Mock(returncode=0)
        code, out, err = self._run("hook.sh", editor)
        self.assertIsNone(code)
        f = self.tmp / "app" / "hook.sh"
        self.assertTrue(f.exists())
        self.assertTrue(os.stat(f).st_mode & 0o111, "hook.sh not executable")

    def test_new_extensionless_shebang_made_executable(self):
        def editor(argv, **kw):
            Path(argv[-1]).write_text("#!/bin/sh\necho hi\n")
            return mock.Mock(returncode=0)
        code, out, err = self._run("runhook", editor)
        self.assertIsNone(code)
        f = self.tmp / "app" / "runhook"
        self.assertTrue(os.stat(f).st_mode & 0o111, "shebang file not executable")


class CmdEditTomlTest(unittest.TestCase):
    """cmd_edit (the workload.toml editor path): no-change short-circuit,
    disabled-save, validation-failure restore, and the enabled apply/no-apply
    branches."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        self.enterContext(mock.patch.object(cmd_admin, "require_root", lambda: None))
        (self.tmp / "app").mkdir()
        self.cfg_path = self.tmp / "app" / "workload.toml"
        self.orig = '[workload]\nname = "app"\n\n[container]\nimage = "localhost/app:latest"\n'
        self.cfg_path.write_text(self.orig)
        self.manager = mock.Mock()
        self.enterContext(mock.patch.dict(os.environ, {"EDITOR": "myeditor"}))

    def _run(self, edited_content, editor_rc=0, extra_run=None, yes=False,
             validate_result=None):
        """edited_content: what the fake editor writes (None → leave unchanged).
        validate_result: dict returned by a mocked validate_single, or None to
        run the real validator."""
        ns = argparse.Namespace(workload="app", file=None, yes=yes)

        def run_side_effect(argv, **kw):
            if argv[0] == "myeditor":
                if edited_content is not None:
                    self.cfg_path.write_text(edited_content)
                return mock.Mock(returncode=editor_rc)
            if extra_run is not None:
                r = extra_run(argv, **kw)
                if r is not None:
                    return r
            return mock.Mock(returncode=0)

        patches = [mock.patch.object(cmd_admin.subprocess, "run", side_effect=run_side_effect)]
        if validate_result is not None:
            patches.append(mock.patch.object(
                cmd_admin, "validate_single",
                lambda c, m, json_mode=False: validate_result))
        out, err = io.StringIO(), io.StringIO()
        code = None
        try:
            with redirect_stdout(out), redirect_stderr(err):
                for p in patches:
                    self.enterContext(p)
                cmd_admin.cmd_edit(ns, self.manager)
        except SystemExit as e:
            code = e.code
        return code, out.getvalue(), err.getvalue()

    def test_missing_config_errors(self):
        (self.cfg_path).unlink()
        code, out, err = self._run(edited_content=None)
        self.assertEqual(code, 1)
        self.assertIn("not found", err)

    def test_editor_with_flags_is_split(self):
        # EDITOR="code --wait" must be shlex-split into argv, not passed as a
        # single literal executable name (which would fail to exec).
        ns = argparse.Namespace(workload="app", file=None, yes=False)
        captured = []

        def run_side_effect(argv, **kw):
            captured.append(list(argv))
            return mock.Mock(returncode=0)

        with mock.patch.dict(os.environ, {"EDITOR": "code --wait"}):
            with mock.patch.object(cmd_admin.subprocess, "run", side_effect=run_side_effect):
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    cmd_admin.cmd_edit(ns, self.manager)

        self.assertEqual(captured[0][:-1], ["code", "--wait"])
        self.assertEqual(Path(captured[0][-1]), self.cfg_path)

    def test_malformed_editor_falls_back_to_nano(self):
        # Regression: a malformed $EDITOR (unbalanced quote) must not crash
        # cmd_edit with an uncaught shlex ValueError — it falls back to nano.
        ns = argparse.Namespace(workload="app", file=None, yes=False)
        captured = []

        def run_side_effect(argv, **kw):
            captured.append(list(argv))
            return mock.Mock(returncode=0)

        with mock.patch.dict(os.environ, {"EDITOR": '"vim'}):
            with mock.patch.object(cmd_admin.subprocess, "run", side_effect=run_side_effect):
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    cmd_admin.cmd_edit(ns, self.manager)

        self.assertEqual(captured[0][0], "nano")
        self.assertEqual(Path(captured[0][-1]), self.cfg_path)
        self.assertIn("malformed", err.getvalue())

    def test_editor_failure_removes_backup_exits_1(self):
        code, out, err = self._run(edited_content=None, editor_rc=1)
        self.assertEqual(code, 1)
        self.assertIn("Editor exited with error", err)

    def test_no_change_short_circuits(self):
        code, out, err = self._run(edited_content=self.orig)
        self.assertIsNone(code)
        self.assertIn("No changes made", out)

    def test_changed_valid_disabled_saves(self):
        new = self.orig + '\n[network]\nmode = "host"\n'
        code, out, err = self._run(edited_content=new,
                                   validate_result={"passed": True})
        self.assertIsNone(code)
        self.assertIn("workload is disabled", out)
        self.assertEqual(self.cfg_path.read_text(), new)

    def test_changed_invalid_restore_backup(self):
        # Valid TOML that loads fine, but validate_single (mocked) fails —
        # exercises the validation-failed restore branch (not the load-error one).
        new = self.orig + '\n[network]\nmode = "host"\n'
        with mock.patch.object(cmd_admin, "_ask_yes_no", return_value=True):
            code, out, err = self._run(edited_content=new,
                                       validate_result={"passed": False})
        self.assertEqual(code, 1)
        self.assertIn("Backup restored", out)
        # original content restored
        self.assertEqual(self.cfg_path.read_text(), self.orig)

    def test_changed_invalid_keep_edited(self):
        new = self.orig + "\nkeepme = true\n"
        with mock.patch.object(cmd_admin, "_ask_yes_no", return_value=False):
            code, out, err = self._run(edited_content=new,
                                       validate_result={"passed": False})
        self.assertEqual(code, 1)
        self.assertIn("fix before enabling", out)
        self.assertEqual(self.cfg_path.read_text(), new)

    def test_validate_raises_restores_backup(self):
        new = self.orig + "\nx = 1\n"
        with mock.patch.object(cmd_admin, "validate_single",
                               side_effect=RuntimeError("bad toml")), \
             mock.patch.object(cmd_admin, "_ask_yes_no", return_value=True):
            ns = argparse.Namespace(workload="app", file=None, yes=False)

            def run_side_effect(argv, **kw):
                if argv[0] == "myeditor":
                    self.cfg_path.write_text(new)
                return mock.Mock(returncode=0)
            out, err = io.StringIO(), io.StringIO()
            code = None
            with mock.patch.object(cmd_admin.subprocess, "run", side_effect=run_side_effect):
                try:
                    with redirect_stdout(out), redirect_stderr(err):
                        cmd_admin.cmd_edit(ns, self.manager)
                except SystemExit as e:
                    code = e.code
        self.assertEqual(code, 1)
        self.assertIn("Error loading config", err.getvalue())
        self.assertEqual(self.cfg_path.read_text(), self.orig)

    def test_changed_valid_enabled_apply_container(self):
        (self.tmp / "app" / ".enabled").touch()
        new = self.orig + '\n[network]\nmode = "host"\n'
        self.manager.user_exists.return_value = True
        fake_pw = types.SimpleNamespace(pw_uid=10005, pw_gid=10005, pw_dir="/x")
        restarted = {}
        with mock.patch("pwd.getpwnam", lambda n: fake_pw), \
             mock.patch.object(cmd_admin, "restart_workload_service",
                               side_effect=lambda uid, svc: restarted.update(uid=uid, svc=svc)):
            code, out, err = self._run(edited_content=new, yes=True,
                                       validate_result={"passed": True})
        self.assertIsNone(code)
        self.assertIn("Changes applied and service restarted", out)
        self.assertEqual(restarted["uid"], 10005)

    def test_changed_valid_enabled_no_apply(self):
        (self.tmp / "app" / ".enabled").touch()
        new = self.orig + '\n[network]\nmode = "host"\n'
        with mock.patch.object(cmd_admin, "_ask_yes_no", return_value=False):
            code, out, err = self._run(edited_content=new, yes=False,
                                       validate_result={"passed": True})
        self.assertIsNone(code)
        self.assertIn("not applied", out)

    def test_changed_valid_enabled_apply_user_absent(self):
        (self.tmp / "app" / ".enabled").touch()
        new = self.orig + '\n[network]\nmode = "host"\n'
        self.manager.user_exists.return_value = False
        code, out, err = self._run(edited_content=new, yes=True,
                                   validate_result={"passed": True})
        self.assertIsNone(code)
        self.assertIn("Changes applied", out)

    def test_file_arg_dispatches_to_control_file_edit(self):
        ns = argparse.Namespace(workload="app", file="Containerfile", yes=False)
        with mock.patch.object(cmd_admin, "_edit_control_file") as ecf:
            cmd_admin.cmd_edit(ns, self.manager)
        ecf.assert_called_once()

    def test_changed_valid_enabled_apply_vm(self):
        (self.tmp / "app" / ".enabled").touch()
        # A VM workload: apply restarts the setup oneshot + main service.
        vm = ('[workload]\nname = "app"\n\n[vm]\ncloud_image_url = "https://x/f.qcow2"\n'
              'vcpus = 1\nmemory = "512M"\nsystem_disk_size = "5G"\nuser = "w"\n')
        self.cfg_path.write_text(vm)
        restarts = []

        def extra_run(argv, **kw):
            if argv[0] == "systemctl" and argv[1] == "restart":
                restarts.append(argv[2])
            return None

        code, out, err = self._run(edited_content=vm + "vga = false\n", yes=True,
                                   extra_run=extra_run,
                                   validate_result={"passed": True})
        self.assertIsNone(code)
        self.assertIn("Changes applied", out)
        self.assertTrue(any("setup" in r for r in restarts),
                        f"setup oneshot not restarted: {restarts}")


if __name__ == "__main__":
    unittest.main()
