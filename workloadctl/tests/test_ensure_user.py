#!/usr/bin/env python3
"""Unit tests for workload-ensure-user helpers.

The script lives in libexec/ and has no __main__ guard around its imports;
load it via SourceFileLoader so we can exercise the user-data rendering
and cloud-init template substitution paths without running the rest of
the (root-only) user-provisioning flow.
"""

import importlib.machinery
import importlib.util
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

LIB_DIR = os.path.join(os.path.dirname(__file__), '..', 'lib')
SCRIPT = os.path.join(os.path.dirname(__file__), '..', 'libexec', 'workload-ensure-user')


def _load_script():
    if LIB_DIR not in sys.path:
        sys.path.insert(0, LIB_DIR)
    loader = importlib.machinery.SourceFileLoader("workload_ensure_user", SCRIPT)
    spec = importlib.util.spec_from_loader("workload_ensure_user", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _fake_pw(home: Path, uid: int = 9999, gid: int = 9999):
    """Minimal pwd-like struct sufficient for the code under test."""
    pw = types.SimpleNamespace()
    pw.pw_dir = str(home)
    pw.pw_uid = uid
    pw.pw_gid = gid
    pw.pw_name = "_wl-test"
    return pw


class TestRenderDefaultUserData(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()

    def test_minimal_no_mounts_no_data_disk(self):
        out = self.mod._render_default_user_data(
            name="myvm", guest_user="fedora",
            pubkey="ssh-ed25519 AAAA fedora@build",
            mounts=[], has_data_disk=False,
        )
        self.assertTrue(out.startswith("#cloud-config\n"), out[:40])
        self.assertIn("hostname: myvm", out)
        self.assertIn("fqdn: myvm.local", out)
        self.assertIn("- name: fedora", out)
        self.assertIn("ssh-ed25519 AAAA fedora@build", out)
        self.assertIn("sudo: ALL=(ALL) NOPASSWD:ALL", out)
        self.assertNotIn("mounts:", out)
        self.assertNotIn("runcmd:", out)
        self.assertNotIn("mkfs", out)

    def test_with_mounts(self):
        mounts = [
            ("shareA", "/mnt/a", "virtiofs", "defaults"),
            ("shareB", "/mnt/b", "virtiofs", "ro"),
        ]
        out = self.mod._render_default_user_data(
            name="myvm", guest_user="fedora",
            pubkey="ssh-ed25519 X",
            mounts=mounts, has_data_disk=False,
        )
        self.assertIn("mounts:", out)
        self.assertIn("'shareA'", out)
        self.assertIn("'/mnt/a'", out)
        self.assertIn("'virtiofs'", out)
        self.assertIn("'defaults'", out)
        self.assertIn("'shareB'", out)
        self.assertIn("'/mnt/b'", out)
        self.assertIn("'ro'", out)

    def test_with_data_disk_emits_format_runcmd(self):
        out = self.mod._render_default_user_data(
            name="myvm", guest_user="fedora",
            pubkey="ssh-ed25519 X",
            mounts=[], has_data_disk=True,
        )
        self.assertIn("runcmd:", out)
        self.assertIn("/dev/vdb", out)
        self.assertIn("mkfs.ext4", out)
        self.assertIn("LABEL=workload-data", out)
        # Guarded against re-format on subsequent boots.
        self.assertIn("blkid /dev/vdb", out)

    def test_with_mounts_and_data_disk(self):
        out = self.mod._render_default_user_data(
            name="myvm", guest_user="fedora",
            pubkey="ssh-ed25519 X",
            mounts=[("t", "/m", "virtiofs", "defaults")],
            has_data_disk=True,
        )
        self.assertIn("mounts:", out)
        self.assertIn("runcmd:", out)
        # mounts must appear before runcmd so cloud-init mounts the share
        # before any runcmd that might touch it.
        self.assertLess(out.index("mounts:"), out.index("runcmd:"))

    def test_format_invariants(self):
        out = self.mod._render_default_user_data(
            name="vm", guest_user="u", pubkey="K",
            mounts=[], has_data_disk=False,
        )
        # Must contain final_message and the no-package-upgrade flags so
        # boots stay quick and deterministic.
        self.assertIn("package_update: false", out)
        self.assertIn("package_upgrade: false", out)
        self.assertIn("final_message:", out)
        # Trailing newline so concatenation/append is safe.
        self.assertTrue(out.endswith("\n"))


class TestBuildCloudInitIsoTemplateMode(unittest.TestCase):
    """Exercise the template-mode path of build_cloud_init_iso end-to-end.

    Mocks _decrypt_systemd_credential (filesystem-bound), os.chown (root-only),
    and subprocess.run for the ISO tool so the test can run as any user.
    """

    def setUp(self):
        self.mod = _load_script()
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp) / "home"
        self.home.mkdir()
        (self.home / ".ssh").mkdir()
        (self.home / ".ssh" / "id_ed25519.pub").write_text(
            "ssh-ed25519 AAAAFAKEKEY user@host\n"
        )
        self.config_dir = Path(self.tmp) / "cfg"
        self.config_dir.mkdir()
        # The ISO is built into VM_SOCKET_DIR/{name} (tmpfs in production);
        # redirect it under tmp so the build can mkdir/chmod it as a non-root
        # test user instead of touching the real /run/workload-vm.
        self.runtime = Path(self.tmp) / "run"
        self.runtime.mkdir()
        self.pw = _fake_pw(self.home)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def _fake_iso_run(self, *args, **kwargs):
        """Fake subprocess.run that touches the ISO output file."""
        argv = args[0]
        # Both genisoimage/mkisofs use `-output PATH`; xorriso uses `-o PATH`.
        for flag in ("-output", "-o"):
            if flag in argv:
                Path(argv[argv.index(flag) + 1]).write_bytes(b"")
                break
        return types.SimpleNamespace(returncode=0, stderr="", stdout="")

    def _run_build(self, config: dict, name: str = "myvm"):
        import shutil as _shutil
        with mock.patch.object(self.mod.os, "chown", lambda *a, **kw: None), \
             mock.patch.object(self.mod, "VM_SOCKET_DIR", self.runtime), \
             mock.patch.object(self.mod.subprocess, "run", self._fake_iso_run), \
             mock.patch.object(_shutil, "which",
                               lambda name: "/usr/bin/genisoimage"
                                            if name == "genisoimage" else None), \
             mock.patch.object(self.mod.shutil, "rmtree"):
            self.mod.build_cloud_init_iso(
                self.pw, config, name,
                config_path=self.config_dir / f"{name}.toml",
            )

    def _iso_path(self, name: str = "myvm") -> Path:
        return self.runtime / name / "cloud-init.iso"

    def _read_user_data(self) -> str:
        return (self.home / ".cloud-init-seed" / "user-data").read_text()

    def test_template_substitutes_template_vars(self):
        ud = self.config_dir / "user-data"
        ud.write_text("#cloud-config\nhostname: ${HOST}\nrepo: ${REPO}\n")
        cfg = {"vm": {
            "user": "fedora",
            "cloud_init": {
                "user_data_file": "user-data",
                "template_vars": {"HOST": "forge", "REPO": "https://x/y.git"},
            },
        }}
        self._run_build(cfg)
        text = self._read_user_data()
        self.assertIn("hostname: forge", text)
        self.assertIn("repo: https://x/y.git", text)

    def test_template_injects_magic_ssh_key(self):
        ud = self.config_dir / "user-data"
        ud.write_text("#cloud-config\nkey: ${WORKLOADCTL_SSH_KEY}\n")
        cfg = {"vm": {"cloud_init": {"user_data_file": "user-data"}}}
        self._run_build(cfg)
        text = self._read_user_data()
        self.assertIn("ssh-ed25519 AAAAFAKEKEY", text)

    def test_template_injects_magic_workload_name(self):
        ud = self.config_dir / "user-data"
        ud.write_text("#cloud-config\nname: ${WORKLOADCTL_WORKLOAD_NAME}\n")
        cfg = {"vm": {"cloud_init": {"user_data_file": "user-data"}}}
        self._run_build(cfg, name="myforge")
        text = self._read_user_data()
        self.assertIn("name: myforge", text)

    def test_template_resolves_secrets(self):
        ud = self.config_dir / "user-data"
        ud.write_text("#cloud-config\ntoken: ${SECRET:runner-token}\n")
        cfg = {"vm": {"cloud_init": {
            "user_data_file": "user-data",
        }}}
        with mock.patch.object(self.mod, "_decrypt_systemd_credential",
                               return_value="DECRYPTED-TOKEN"):
            self._run_build(cfg)
        text = self._read_user_data()
        self.assertIn("token: DECRYPTED-TOKEN", text)
        self.assertNotIn("${SECRET:", text)

    def test_template_prepends_cloud_config_header_when_missing(self):
        ud = self.config_dir / "user-data"
        ud.write_text("hostname: ${WORKLOADCTL_WORKLOAD_NAME}\n")
        cfg = {"vm": {"cloud_init": {"user_data_file": "user-data"}}}
        self._run_build(cfg, name="myvm")
        text = self._read_user_data()
        self.assertTrue(text.startswith("#cloud-config\n"))

    def test_template_missing_file_raises(self):
        cfg = {"vm": {"cloud_init": {"user_data_file": "does-not-exist"}}}
        with self.assertRaises(FileNotFoundError):
            self._run_build(cfg)

    def test_template_missing_var_raises_runtime_error(self):
        ud = self.config_dir / "user-data"
        ud.write_text("#cloud-config\nx: ${UNRESOLVED}\n")
        cfg = {"vm": {"cloud_init": {"user_data_file": "user-data"}}}
        with self.assertRaises(RuntimeError) as ctx:
            self._run_build(cfg)
        self.assertIn("substitution failed", str(ctx.exception))

    def test_template_relative_path_anchored_to_config_dir(self):
        sub = self.config_dir / "cloud-init"
        sub.mkdir()
        (sub / "user-data").write_text("#cloud-config\nx: ${X}\n")
        cfg = {"vm": {"cloud_init": {
            "user_data_file": "cloud-init/user-data",
            "template_vars": {"X": "value"},
        }}}
        self._run_build(cfg)
        self.assertIn("x: value", self._read_user_data())

    def test_fingerprint_changes_when_user_data_file_edited(self):
        # Editing the user_data_file content must trigger a rebuild.
        ud = self.config_dir / "user-data"
        ud.write_text("#cloud-config\nv: 1\n")
        cfg = {"vm": {"cloud_init": {"user_data_file": "user-data"}}}
        self._run_build(cfg)
        fp_first = (self.home / ".cloud-init-fingerprint").read_text()

        ud.write_text("#cloud-config\nv: 2\n")
        self._run_build(cfg)
        fp_second = (self.home / ".cloud-init-fingerprint").read_text()
        self.assertNotEqual(fp_first, fp_second)

    def test_fingerprint_changes_when_template_var_edited(self):
        # Regression: editing [vm.cloud_init].template_vars WITHOUT touching the
        # user_data_file must still rebuild the ISO. The rendered content
        # changed even though the file (and its mtime) did not — the old
        # pubkey+mtime fingerprint missed this and reused a stale ISO.
        ud = self.config_dir / "user-data"
        ud.write_text("#cloud-config\nv: ${V}\n")
        cfg = {"vm": {"cloud_init": {
            "user_data_file": "user-data",
            "template_vars": {"V": "first"},
        }}}
        self._run_build(cfg)
        fp_first = (self.home / ".cloud-init-fingerprint").read_text()
        self.assertIn("v: first", self._read_user_data())

        cfg["vm"]["cloud_init"]["template_vars"]["V"] = "second"
        self._run_build(cfg)
        fp_second = (self.home / ".cloud-init-fingerprint").read_text()
        self.assertNotEqual(fp_first, fp_second)
        self.assertIn("v: second", self._read_user_data())

    def test_no_rebuild_when_nothing_changes(self):
        # Idempotence: re-running with identical inputs must NOT rebuild the
        # ISO (fingerprint stable, ISO file untouched).
        ud = self.config_dir / "user-data"
        ud.write_text("#cloud-config\nv: ${V}\n")
        cfg = {"vm": {"cloud_init": {
            "user_data_file": "user-data",
            "template_vars": {"V": "x"},
        }}}
        self._run_build(cfg)
        fp_first = (self.home / ".cloud-init-fingerprint").read_text()
        iso_mtime_first = self._iso_path().stat().st_mtime_ns

        self._run_build(cfg)
        fp_second = (self.home / ".cloud-init-fingerprint").read_text()
        iso_mtime_second = self._iso_path().stat().st_mtime_ns
        self.assertEqual(fp_first, fp_second)
        self.assertEqual(iso_mtime_first, iso_mtime_second)

    def test_user_data_written_0600(self):
        ud = self.config_dir / "user-data"
        ud.write_text("#cloud-config\nhostname: test\n")
        cfg = {"vm": {"cloud_init": {"user_data_file": "user-data"}}}
        import shutil as _shutil
        with mock.patch.object(self.mod.os, "chown", lambda *a, **kw: None), \
             mock.patch.object(self.mod, "VM_SOCKET_DIR", self.runtime), \
             mock.patch.object(self.mod.subprocess, "run", self._fake_iso_run), \
             mock.patch.object(_shutil, "which",
                               lambda name: "/usr/bin/genisoimage"
                                            if name == "genisoimage" else None), \
             mock.patch.object(self.mod.shutil, "rmtree"):
            self.mod.build_cloud_init_iso(
                self.pw, cfg, "myvm",
                config_path=self.config_dir / "myvm.toml",
            )
        ud_path = self.home / ".cloud-init-seed" / "user-data"
        mode = oct(ud_path.stat().st_mode & 0o777)
        self.assertEqual(mode, "0o600")

    def test_seed_dir_removed_after_iso_build(self):
        ud = self.config_dir / "user-data"
        ud.write_text("#cloud-config\nhostname: test\n")
        cfg = {"vm": {"cloud_init": {"user_data_file": "user-data"}}}
        import shutil as _shutil
        rmtree_calls = []
        with mock.patch.object(self.mod.os, "chown", lambda *a, **kw: None), \
             mock.patch.object(self.mod, "VM_SOCKET_DIR", self.runtime), \
             mock.patch.object(self.mod.subprocess, "run", self._fake_iso_run), \
             mock.patch.object(_shutil, "which",
                               lambda name: "/usr/bin/genisoimage"
                                            if name == "genisoimage" else None), \
             mock.patch.object(self.mod.shutil, "rmtree",
                               side_effect=lambda p, **kw: rmtree_calls.append(p)):
            self.mod.build_cloud_init_iso(
                self.pw, cfg, "myvm",
                config_path=self.config_dir / "myvm.toml",
            )
        seed_dir = self.home / ".cloud-init-seed"
        self.assertTrue(any(str(seed_dir) in str(p) for p in rmtree_calls),
                        f"seed_dir not removed; rmtree calls: {rmtree_calls}")

    def test_default_mode_used_when_no_user_data_file(self):
        # No [vm.cloud_init].user_data_file → built-in cloud-config (no
        # template substitution surface). Sanity check: no error, and the
        # rendered user-data contains the default scaffolding.
        cfg = {"vm": {"user": "fedora"}}
        self._run_build(cfg, name="defvm")
        text = self._read_user_data()
        self.assertTrue(text.startswith("#cloud-config\n"))
        self.assertIn("hostname: defvm", text)
        self.assertIn("- name: fedora", text)
        self.assertIn("ssh-ed25519 AAAAFAKEKEY", text)


class TestSetupVmVolumeDirectories(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()

    def test_relative_path_created_under_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            pw = _fake_pw(home)
            config = {"vm": {"volumes": ["./data:/data"]}}
            with mock.patch("os.chown"), mock.patch("os.chmod"):
                self.mod.setup_vm_volume_directories(pw, config)
            self.assertTrue((home / "data").is_dir())

    def test_absolute_path_outside_home_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            pw = _fake_pw(home)
            config = {"vm": {"volumes": ["/etc/passwd:/etc/passwd"]}}
            with mock.patch("os.chown"), mock.patch("os.chmod"):
                self.mod.setup_vm_volume_directories(pw, config)
            # /etc/passwd must not have been turned into a directory
            self.assertFalse((home / "etc" / "passwd").exists())

    def test_empty_volumes_is_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            pw = _fake_pw(Path(tmp))
            config = {"vm": {}}
            with mock.patch("os.chown"), mock.patch("os.chmod"):
                self.mod.setup_vm_volume_directories(pw, config)

    def test_existing_dir_is_chowned(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            existing = home / "data"
            existing.mkdir()
            pw = _fake_pw(home, uid=1234, gid=1234)
            config = {"vm": {"volumes": ["./data:/data"]}}
            chown_calls = []
            with mock.patch("os.chown", side_effect=lambda p, u, g: chown_calls.append((str(p), u, g))):
                with mock.patch("os.chmod"):
                    self.mod.setup_vm_volume_directories(pw, config)
            self.assertTrue(any(str(existing) in c[0] for c in chown_calls))


class TestSetupVolumeDirectoriesMultiContainer(unittest.TestCase):
    """C1: multi-container workload volume dirs are created."""

    def setUp(self):
        self.mod = _load_script()

    def test_multi_container_volumes_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "state"
            home.mkdir()
            pw = _fake_pw(home)
            config = {
                "workload": {"name": "myapp"},
                "containers": [
                    {
                        "name": "web",
                        "container": {"image": "nginx"},
                        "storage": {"volumes": ["./web-data:/data"]},
                    },
                    {
                        "name": "db",
                        "container": {"image": "postgres"},
                        "storage": {"volumes": ["./db-data:/var/lib/postgresql"]},
                    },
                ],
            }
            with mock.patch("os.chown"), mock.patch("os.chmod"):
                self.mod.setup_volume_directories(pw, config)
            # ./X anchors now resolve to the sibling data/ subdir
            self.assertTrue((root / "data" / "web-data").is_dir())
            self.assertTrue((root / "data" / "db-data").is_dir())


class TestConfigureSubuidSubgid(unittest.TestCase):
    """Tests for configure_subuid_subgid — formula and grandfathering logic."""

    def setUp(self):
        self.mod = _load_script()

    def _run(self, uid, subuid_content="", subgid_content="", config=None):
        """Call configure_subuid_subgid with mocked /etc/subuid|subgid."""
        pw = _fake_pw(Path("/home/_wl-test"), uid=uid)
        pw.pw_name = "_wl-test"
        if config is None:
            config = {}

        subuid_written = []
        subgid_written = []

        def fake_open(path, mode="r"):
            if mode == "r":
                if "subuid" in str(path):
                    return mock.mock_open(read_data=subuid_content)()
                if "subgid" in str(path):
                    return mock.mock_open(read_data=subgid_content)()
            if mode == "a":
                if "subuid" in str(path):
                    buf = []
                    m = mock.MagicMock()
                    m.write = lambda s: buf.append(s) or subuid_written.append(s)
                    m.__enter__ = lambda s: m
                    m.__exit__ = mock.MagicMock(return_value=False)
                    return m
                if "subgid" in str(path):
                    buf = []
                    m = mock.MagicMock()
                    m.write = lambda s: buf.append(s) or subgid_written.append(s)
                    m.__enter__ = lambda s: m
                    m.__exit__ = mock.MagicMock(return_value=False)
                    return m
            # lock file
            m = mock.MagicMock()
            m.__enter__ = lambda s: m
            m.__exit__ = mock.MagicMock(return_value=False)
            m.fileno = lambda: 0
            return m

        with mock.patch("builtins.open", side_effect=fake_open), \
             mock.patch.object(self.mod.fcntl, "flock"), \
             mock.patch.object(self.mod, "subprocess", mock.MagicMock()), \
             mock.patch.object(self.mod.Path, "mkdir"):
            self.mod.configure_subuid_subgid(pw, config)

        return subuid_written, subgid_written

    def test_new_user_uid_10000_gets_new_formula(self):
        written, _ = self._run(uid=10000)
        self.assertEqual(len(written), 1)
        entry = written[0].strip()
        # offset=0 → 600100000 + 0 = 600100000
        self.assertEqual(entry, "_wl-test:600100000:65536")

    def test_new_user_uid_52948_gets_new_formula(self):
        written, _ = self._run(uid=52948)
        self.assertEqual(len(written), 1)
        entry = written[0].strip()
        # offset=42948 → 600100000 + 42948*65536 = 3414740128
        self.assertEqual(entry, "_wl-test:3414740128:65536")

    def test_existing_entry_not_rewritten(self):
        old_entry = "_wl-test:100000:65536\n"
        written, _ = self._run(uid=10000, subuid_content=old_entry, subgid_content=old_entry)
        # Main entry must not be added again — old range is grandfathered
        self.assertEqual(written, [])


class TestDecryptSystemdCredential(unittest.TestCase):
    """The decrypt helper consults real paths; we patch Path resolution."""

    def setUp(self):
        self.mod = _load_script()

    def test_raises_when_neither_path_exists(self):
        with mock.patch.object(self.mod.Path, "exists", return_value=False):
            with self.assertRaises(FileNotFoundError) as ctx:
                self.mod._decrypt_systemd_credential("nope")
            # Error mentions both candidate locations so operators know
            # where to drop the credential.
            self.assertIn("credstore", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
