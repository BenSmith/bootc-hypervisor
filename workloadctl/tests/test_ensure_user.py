#!/usr/bin/env python3
"""Unit tests for workload-ensure-user helpers.

The script lives in libexec/ and has no __main__ guard around its imports;
load it via SourceFileLoader so we can exercise the user-data rendering
and cloud-init template substitution paths without running the rest of
the (root-only) user-provisioning flow.
"""

import contextlib
import importlib.machinery
import importlib.util
import os
import shutil
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
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


# Stand-in VM host keypair (S1). The private half is a multi-line PEM so tests
# exercise the block-scalar indentation path; the (c) contract check keys off
# this exact text appearing in the rendered user-data.
FAKE_HOST_PRIV = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAFAKEFAKEFAKEFAKE\n"
    "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOO\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)
FAKE_HOST_PUB = "ssh-ed25519 AAAAFAKEHOSTKEY host@myvm"


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
        # Pin the primary user to uid 1000 so virtiofsd's guest<->host uid
        # translation is deterministic and the guest user can write shares.
        self.assertIn("uid: 1000", out)
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
        # VM host keypair (S1) — build_cloud_init_iso reads + pins these.
        (self.home / ".ssh" / "vm_host_ed25519_key").write_text(FAKE_HOST_PRIV)
        (self.home / ".ssh" / "vm_host_ed25519_key.pub").write_text(FAKE_HOST_PUB + "\n")
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

    def _run_build(self, config: dict, name: str = "myvm",
                   inject_host_key: bool = True):
        # A custom seed must install the workload's SSH host key or
        # build_cloud_init_iso fails the S1 (c) contract. Unless a test is
        # exercising that failure (inject_host_key=False), append a reference to
        # the magic var so the rendered user-data carries the host key. The
        # value is a multi-line PEM; the tests never parse the YAML, so a
        # trailing block is harmless — it only has to satisfy the substring pin.
        udf = config.get("vm", {}).get("cloud_init", {}).get("user_data_file")
        if udf and inject_host_key:
            path = Path(udf)
            if not path.is_absolute():
                path = self.config_dir / udf
            if path.exists():
                body = path.read_text()
                if "WORKLOADCTL_VM_HOST_KEY" not in body:
                    path.write_text(body + "\nhost_key: ${WORKLOADCTL_VM_HOST_KEY}\n")
        import shutil as _shutil
        with mock.patch.object(self.mod.os, "chown", lambda *a, **kw: None), \
             mock.patch.object(self.mod, "VM_SOCKET_DIR", self.runtime), \
             mock.patch.object(self.mod, "workload_state_dir",
                               lambda _name: self.home), \
             mock.patch.object(self.mod.subprocess, "run", self._fake_iso_run), \
             mock.patch.object(_shutil, "which",
                               lambda name: "/usr/bin/genisoimage"
                                            if name == "genisoimage" else None), \
             mock.patch.object(self.mod.shutil, "rmtree"):
            self.mod.build_cloud_init_iso(
                self.pw, config, name,
                config_path=self.config_dir / "workload.toml",
            )

    def _iso_path(self, name: str = "myvm") -> Path:
        return self.runtime / name / "cloud-init.iso"

    def _seed_dir(self, name: str = "myvm") -> Path:
        # The seed is staged on the tmpfs runtime dir (S6), never the home.
        return self.runtime / name / ".cloud-init-seed"

    def _read_user_data(self, name: str = "myvm") -> str:
        return (self._seed_dir(name) / "user-data").read_text()

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
        text = self._read_user_data("myforge")
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
        cfg: dict = {"vm": {"cloud_init": {
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
        ud.write_text("#cloud-config\nhostname: test\n"
                      "host_key: ${WORKLOADCTL_VM_HOST_KEY}\n")
        cfg = {"vm": {"cloud_init": {"user_data_file": "user-data"}}}
        import shutil as _shutil
        with mock.patch.object(self.mod.os, "chown", lambda *a, **kw: None), \
             mock.patch.object(self.mod, "VM_SOCKET_DIR", self.runtime), \
             mock.patch.object(self.mod, "workload_state_dir",
                               lambda _name: self.home), \
             mock.patch.object(self.mod.subprocess, "run", self._fake_iso_run), \
             mock.patch.object(_shutil, "which",
                               lambda name: "/usr/bin/genisoimage"
                                            if name == "genisoimage" else None), \
             mock.patch.object(self.mod.shutil, "rmtree"):
            self.mod.build_cloud_init_iso(
                self.pw, cfg, "myvm",
                config_path=self.config_dir / "myvm.toml",
            )
        ud_path = self._seed_dir() / "user-data"
        mode = oct(ud_path.stat().st_mode & 0o777)
        self.assertEqual(mode, "0o600")

    def test_seed_dir_removed_after_iso_build(self):
        ud = self.config_dir / "user-data"
        ud.write_text("#cloud-config\nhostname: test\n"
                      "host_key: ${WORKLOADCTL_VM_HOST_KEY}\n")
        cfg = {"vm": {"cloud_init": {"user_data_file": "user-data"}}}
        import shutil as _shutil
        rmtree_calls = []
        with mock.patch.object(self.mod.os, "chown", lambda *a, **kw: None), \
             mock.patch.object(self.mod, "VM_SOCKET_DIR", self.runtime), \
             mock.patch.object(self.mod, "workload_state_dir",
                               lambda _name: self.home), \
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
        seed_dir = self._seed_dir()
        self.assertTrue(any(str(seed_dir) in str(p) for p in rmtree_calls),
                        f"seed_dir not removed; rmtree calls: {rmtree_calls}")

    def test_seed_dir_staged_on_tmpfs_not_home(self):
        """S6: the plaintext-secret seed is staged on the tmpfs runtime dir, so
        it never lands at rest in the persistent home even if the rmtree is
        cut short by a crash (rmtree is mocked here to simulate that)."""
        ud = self.config_dir / "user-data"
        ud.write_text("#cloud-config\nhostname: test\n"
                      "host_key: ${WORKLOADCTL_VM_HOST_KEY}\n")
        cfg = {"vm": {"cloud_init": {"user_data_file": "user-data"}}}
        # _run_build mocks shutil.rmtree, so the seed dir survives the build —
        # standing in for a crash before the post-build cleanup runs.
        self._run_build(cfg)
        self.assertTrue((self._seed_dir() / "user-data").exists())
        self.assertFalse((self.home / ".cloud-init-seed").exists(),
                         "plaintext seed leaked into the persistent home")

    def test_default_mode_used_when_no_user_data_file(self):
        # No [vm.cloud_init].user_data_file → built-in cloud-config (no
        # template substitution surface). Sanity check: no error, and the
        # rendered user-data contains the default scaffolding.
        cfg = {"vm": {"user": "fedora"}}
        self._run_build(cfg, name="defvm")
        text = self._read_user_data("defvm")
        self.assertTrue(text.startswith("#cloud-config\n"))
        self.assertIn("hostname: defvm", text)
        self.assertIn("- name: fedora", text)
        self.assertIn("ssh-ed25519 AAAAFAKEKEY", text)

    # --- S1 host-key pinning ---------------------------------------------

    def test_default_mode_injects_host_key_block(self):
        """Default seed installs the generated host key via ssh_keys:, with the
        private PEM as an indented block scalar and the public key inline."""
        cfg = {"vm": {"user": "fedora"}}
        self._run_build(cfg, name="defvm")
        text = self._read_user_data("defvm")
        self.assertIn("ssh_keys:", text)
        self.assertIn("  ed25519_private: |", text)
        self.assertIn(f"  ed25519_public: {FAKE_HOST_PUB}", text)
        # Private PEM lines are indented 4 spaces under the block scalar.
        self.assertIn("    -----BEGIN OPENSSH PRIVATE KEY-----", text)

    def test_build_pins_host_key_in_known_hosts(self):
        """build_cloud_init_iso writes vm_known_hosts keyed by the workload
        name (the HostKeyAlias the CLI verifies against)."""
        cfg = {"vm": {"user": "fedora"}}
        self._run_build(cfg, name="defvm")
        known = (self.home / ".ssh" / "vm_known_hosts").read_text()
        self.assertEqual(known, f"defvm {FAKE_HOST_PUB}\n")

    def test_custom_seed_missing_host_key_fails(self):
        """(c) contract: a custom seed that doesn't install the host key fails
        provisioning rather than shipping an unverifiable VM (no TOFU)."""
        ud = self.config_dir / "user-data"
        ud.write_text("#cloud-config\nhostname: test\n")  # deliberately no host key
        cfg = {"vm": {"cloud_init": {"user_data_file": "user-data"}}}
        with self.assertRaises(RuntimeError) as ctx:
            self._run_build(cfg, inject_host_key=False)
        self.assertIn("host key", str(ctx.exception).lower())
        # No pin is written when provisioning is refused.
        self.assertFalse((self.home / ".ssh" / "vm_known_hosts").exists())

    def test_custom_seed_with_host_key_pins(self):
        """A custom seed that wires ${WORKLOADCTL_VM_HOST_KEY} passes the
        contract and gets pinned."""
        ud = self.config_dir / "user-data"
        ud.write_text(
            "#cloud-config\nssh_keys:\n  ed25519_private: |\n"
            "    ${WORKLOADCTL_VM_HOST_KEY}\n"
            "  ed25519_public: ${WORKLOADCTL_VM_HOST_PUBKEY}\n"
        )
        cfg = {"vm": {"cloud_init": {"user_data_file": "user-data"}}}
        self._run_build(cfg, inject_host_key=False)  # seed already carries it
        known = (self.home / ".ssh" / "vm_known_hosts").read_text()
        self.assertEqual(known, f"myvm {FAKE_HOST_PUB}\n")

    def test_custom_seed_with_host_key_b64_pins(self):
        """The write_files + base64 form (what the shipped seeds use) also
        satisfies the (c) contract."""
        ud = self.config_dir / "user-data"
        ud.write_text(
            "#cloud-config\nwrite_files:\n"
            "  - path: /etc/ssh/ssh_host_ed25519_key\n"
            "    encoding: b64\n"
            "    content: ${WORKLOADCTL_VM_HOST_KEY_B64}\n"
        )
        cfg = {"vm": {"cloud_init": {"user_data_file": "user-data"}}}
        self._run_build(cfg, inject_host_key=False)
        # The rendered seed carries the base64 of the host key, and the pin is
        # written.
        import base64 as _b64
        want_b64 = _b64.b64encode(FAKE_HOST_PRIV.encode()).decode()
        self.assertIn(want_b64, self._read_user_data())
        known = (self.home / ".ssh" / "vm_known_hosts").read_text()
        self.assertEqual(known, f"myvm {FAKE_HOST_PUB}\n")

    def test_missing_host_keypair_raises(self):
        """A missing host keypair (setup step skipped) fails the ISO build."""
        (self.home / ".ssh" / "vm_host_ed25519_key").unlink()
        cfg = {"vm": {"user": "fedora"}}
        with self.assertRaises(RuntimeError) as ctx:
            self._run_build(cfg, name="defvm")
        self.assertIn("host keypair missing", str(ctx.exception).lower())


class TestVmHostKeyGeneration(unittest.TestCase):
    """generate_vm_host_keypair + write_vm_known_hosts (S1)."""

    def setUp(self):
        self.mod = _load_script()
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp) / "home"
        self.home.mkdir()
        self.pw = _fake_pw(self.home)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    @unittest.skipUnless(shutil.which("ssh-keygen"),
                         "ssh-keygen not installed (minimal CI container)")
    def test_generates_host_keypair_idempotently(self):
        with mock.patch.object(self.mod.os, "chown", lambda *a, **kw: None):
            self.mod.generate_vm_host_keypair(self.pw, "myvm")
            priv = self.home / ".ssh" / "vm_host_ed25519_key"
            pub = priv.with_suffix(".pub")
            self.assertTrue(priv.exists() and pub.exists())
            first = priv.read_bytes()
            # Re-run must not regenerate (stable pin).
            self.mod.generate_vm_host_keypair(self.pw, "myvm")
            self.assertEqual(priv.read_bytes(), first)

    def test_write_vm_known_hosts_line_format(self):
        (self.home / ".ssh").mkdir()
        with mock.patch.object(self.mod.os, "chown", lambda *a, **kw: None):
            self.mod.write_vm_known_hosts(self.pw, "myvm", "ssh-ed25519 AAAAHOST")
        known = (self.home / ".ssh" / "vm_known_hosts").read_text()
        self.assertEqual(known, "myvm ssh-ed25519 AAAAHOST\n")


class TestSetupVmVolumeDirectories(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()

    def _patch(self, root):
        """Anchor the canonical path helpers into the temp tree (the function
        keys off these, not pw.pw_dir, so it's correct even with a mismatched passwd home)."""
        return (
            mock.patch.object(self.mod, "workload_state_dir", lambda n: root / "state"),
            mock.patch.object(self.mod, "workload_data_dir", lambda n: root / "data"),
            mock.patch.object(self.mod, "workload_root_dir", lambda n: root),
        )

    def test_relative_anchor_created_under_data(self):
        # ./ anchors to the precious data/ subtree, matching the virtiofsd
        # sidecars the generator emits (NOT the old state-relative behavior).
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "state").mkdir()
            config = {"workload": {"name": "vmx"}, "vm": {"volumes": ["./shared:/data"]}}
            ps, pd, pr = self._patch(root)
            with ps, pd, pr, mock.patch("os.fchown"), mock.patch("os.fchmod"):
                self.mod.setup_vm_volume_directories(_fake_pw(root / "state"), config)
            self.assertTrue((root / "data" / "shared").is_dir())

    def test_absolute_path_outside_workload_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "state").mkdir()
            config = {"workload": {"name": "vmx"},
                      "vm": {"volumes": ["/etc/passwd:/etc/passwd"]}}
            ps, pd, pr = self._patch(root)
            with ps, pd, pr, mock.patch("os.fchown"), mock.patch("os.fchmod"):
                self.mod.setup_vm_volume_directories(_fake_pw(root / "state"), config)
            self.assertFalse((root / "etc" / "passwd").exists())

    def test_empty_volumes_is_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "state").mkdir()
            ps, pd, pr = self._patch(root)
            with ps, pd, pr, mock.patch("os.fchown"), mock.patch("os.fchmod"):
                self.mod.setup_vm_volume_directories(
                    _fake_pw(root / "state"), {"workload": {"name": "vmx"}, "vm": {}})

    def test_existing_dir_is_chowned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "state").mkdir()
            existing = root / "data" / "shared"
            existing.mkdir(parents=True)
            config = {"workload": {"name": "vmx"}, "vm": {"volumes": ["./shared:/data"]}}
            chown_calls = []

            def rec_fchown(fd, u, g):
                # provisioning fchowns an O_NOFOLLOW fd, not a path — resolve it
                # back to a path via /proc to assert on the target.
                chown_calls.append((os.readlink(f"/proc/self/fd/{fd}"), u, g))

            ps, pd, pr = self._patch(root)
            with ps, pd, pr, \
                 mock.patch("os.fchown", side_effect=rec_fchown), \
                 mock.patch("os.fchmod"):
                self.mod.setup_vm_volume_directories(
                    _fake_pw(root / "state", uid=1234, gid=1234), config)
            self.assertTrue(any(str(existing) in c[0] for c in chown_calls))

    def test_symlink_component_is_refused_not_chowned(self):
        # B1 (root TOCTOU): the volume path's final component is a symlink whose
        # target is INSIDE the workload root, so the resolve()-based containment
        # gate passes — but provisioning must still refuse to follow it, or root
        # would chown the symlink target. The O_NOFOLLOW walk aborts and never
        # fchowns anything for that path.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "state").mkdir()
            (root / "data").mkdir()
            target = root / "data" / "real"
            target.mkdir()
            # ./shared -> data/real  (target legitimately inside root)
            os.symlink(target, root / "data" / "shared")
            config = {"workload": {"name": "vmx"}, "vm": {"volumes": ["./shared:/data"]}}
            fchown_fds = []
            ps, pd, pr = self._patch(root)
            with ps, pd, pr, \
                 mock.patch("os.fchown", side_effect=lambda fd, u, g: fchown_fds.append(fd)), \
                 mock.patch("os.fchmod"), \
                 mock.patch.object(self.mod, "log"):
                self.mod.setup_vm_volume_directories(
                    _fake_pw(root / "state", uid=1234, gid=1234), config)
            # Refused: nothing was chowned via the symlinked component.
            self.assertEqual(fchown_fds, [])

    def test_workload_root_itself_is_refused_not_chowned(self):
        # An absolute volume spec equal to the workload root passes the
        # containment gate (relative path "."), but provisioning must refuse:
        # chowning the anchor would hand the workload user ownership of the
        # root-owned trust boundary the O_NOFOLLOW walk relies on.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "state").mkdir()
            config = {"workload": {"name": "vmx"},
                      "vm": {"volumes": [f"{root}:/mnt"]}}
            fchown_fds = []
            ps, pd, pr = self._patch(root)
            with ps, pd, pr, \
                 mock.patch("os.fchown", side_effect=lambda fd, u, g: fchown_fds.append(fd)), \
                 mock.patch("os.fchmod"), \
                 mock.patch.object(self.mod, "log"):
                self.mod.setup_vm_volume_directories(
                    _fake_pw(root / "state", uid=1234, gid=1234), config)
            self.assertEqual(fchown_fds, [])


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
            with mock.patch.object(self.mod, "workload_state_dir", lambda n: root / "state"), \
                 mock.patch.object(self.mod, "workload_root_dir", lambda n: root), \
                 mock.patch("os.fchown"), mock.patch("os.fchmod"):
                self.mod.setup_volume_directories(pw, config)
            # ./X anchors now resolve to the sibling data/ subdir
            self.assertTrue((root / "data" / "web-data").is_dir())
            self.assertTrue((root / "data" / "db-data").is_dir())

    def test_mismatched_passwd_home_still_provisions_canonically(self):
        # A user whose passwd home doesn't match the expected state/ dir must
        # still get ./ volumes under data/, because provisioning keys off
        # workload_state_dir(name), not pw.pw_dir.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "state").mkdir()
            stale_pw = _fake_pw(root)  # passwd home = root (mismatched)
            config = {
                "workload": {"name": "myapp"},
                "containers": [{"name": "web", "container": {"image": "x"},
                                "storage": {"volumes": ["./web-data:/data"]}}],
            }
            with mock.patch.object(self.mod, "workload_state_dir", lambda n: root / "state"), \
                 mock.patch.object(self.mod, "workload_root_dir", lambda n: root), \
                 mock.patch("os.fchown"), mock.patch("os.fchmod"):
                self.mod.setup_volume_directories(stale_pw, config)
            self.assertTrue((root / "data" / "web-data").is_dir())


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
                    m.write = lambda s: buf.append(s) or subuid_written.append(s)  # type: ignore[func-returns-value]
                    m.__enter__ = lambda s: m
                    m.__exit__ = mock.MagicMock(return_value=False)
                    return m
                if "subgid" in str(path):
                    buf = []
                    m = mock.MagicMock()
                    m.write = lambda s: buf.append(s) or subgid_written.append(s)  # type: ignore[func-returns-value]
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
             mock.patch.object(self.mod, "subid_lock", contextlib.nullcontext), \
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


class TestWarnIfStaleHome(unittest.TestCase):
    """warn_if_stale_home flags mismatched passwd home dirs (which silently break
    podman healthchecks) without trying to fix them."""

    def setUp(self):
        self.mod = _load_script()

    def _capture(self, pw, name):
        msgs: list = []
        with mock.patch.object(self.mod, "log", side_effect=msgs.append):
            self.mod.warn_if_stale_home(pw, name)
        return "\n".join(msgs)

    def test_silent_when_home_is_state_dir(self):
        pw = _fake_pw(self.mod.workload_state_dir("myapp"))
        self.assertEqual(self._capture(pw, "myapp"), "")

    def test_warns_on_mismatched_home(self):
        stale = self.mod.workload_state_dir("myapp").parent
        pw = _fake_pw(stale, uid=10005)
        out = self._capture(pw, "myapp")
        self.assertIn("mismatched home", out)
        self.assertIn("frozen at 'starting'", out)
        # Remediation names the exact usermod target + the unit to bounce.
        self.assertIn(f"usermod -d {self.mod.workload_state_dir('myapp')}", out)
        self.assertIn("user@10005.service", out)


class TestResolveCloudInitInstanceId(unittest.TestCase):
    """The instance-id reuse vs rotate decision for a (re)built seed ISO.

    Rotating the id on every host reboot (tmpfs ISO wiped) makes the guest
    re-run all its per-instance cloud-init modules; the id must be reused when
    the user-data fingerprint is unchanged so a reboot is a cheap rehydration.
    """

    def setUp(self):
        self.mod = _load_script()
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.id_file = self.tmp / ".cloud-init-instance-id"

    def _resolve(self, fp_unchanged):
        return self.mod._resolve_cloud_init_instance_id(
            "myvm", self.id_file, fp_unchanged)

    def test_first_provision_mints_when_no_file(self):
        # No persisted id yet → mint, regardless of fingerprint state.
        iid, minted = self._resolve(fp_unchanged=True)
        self.assertTrue(minted)
        self.assertTrue(iid.startswith("myvm-"))

    def test_host_reboot_reuses_id(self):
        # Unchanged content + an existing id == tmpfs ISO wiped by a reboot.
        self.id_file.write_text("myvm-deadbeef")
        iid, minted = self._resolve(fp_unchanged=True)
        self.assertEqual(iid, "myvm-deadbeef")
        self.assertFalse(minted)               # reused → caller must NOT rewrite

    def test_content_change_rotates_id(self):
        # A real config/secret edit (fingerprint changed) → fresh instance.
        self.id_file.write_text("myvm-deadbeef")
        iid, minted = self._resolve(fp_unchanged=False)
        self.assertNotEqual(iid, "myvm-deadbeef")
        self.assertTrue(iid.startswith("myvm-"))
        self.assertTrue(minted)

    def test_empty_id_file_mints(self):
        # A truncated/empty persisted id is not reusable → mint.
        self.id_file.write_text("   \n")
        iid, minted = self._resolve(fp_unchanged=True)
        self.assertTrue(minted)
        self.assertTrue(iid.startswith("myvm-"))


class TestSetupSelinuxPolicy(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()

    def test_creates_policy_when_absent(self):
        calls = []

        def fake_run(argv, **kw):
            calls.append(argv)
            if argv[:2] == ["semanage", "fcontext"] and argv[2] == "-l":
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch.object(self.mod.subprocess, "run", side_effect=fake_run):
            self.mod.setup_selinux_policy()
        add_calls = [c for c in calls if "-a" in c]
        self.assertEqual(len(add_calls), 1)
        self.assertIn("container_file_t", add_calls[0])

    def test_noop_when_policy_already_present(self):
        existing = f"{self.mod.WORKLOADS_BASE}(/.*)?  system_u:object_r:container_file_t:s0\n"

        def fake_run(argv, **kw):
            if "-l" in argv:
                return types.SimpleNamespace(returncode=0, stdout=existing, stderr="")
            raise AssertionError("should not attempt to add when already present")

        with mock.patch.object(self.mod.subprocess, "run", side_effect=fake_run):
            self.mod.setup_selinux_policy()  # must not raise

    def test_list_failure_warns_and_returns(self):
        msgs = []

        def fake_run(argv, **kw):
            return types.SimpleNamespace(returncode=1, stdout="", stderr="semanage broken")

        with mock.patch.object(self.mod.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(self.mod, "log", side_effect=msgs.append):
            self.mod.setup_selinux_policy()
        self.assertTrue(any("semanage fcontext -l failed" in m for m in msgs))

    def test_exception_is_caught_and_logged(self):
        msgs = []
        with mock.patch.object(self.mod.subprocess, "run", side_effect=OSError("boom")), \
             mock.patch.object(self.mod, "log", side_effect=msgs.append):
            self.mod.setup_selinux_policy()  # must not raise
        self.assertTrue(any("Failed to set up SELinux policy" in m for m in msgs))


class TestSetupHomeDirectory(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()

    def test_creates_state_and_data_dirs_with_perms(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            data = root / "data"
            pw = _fake_pw(state, uid=10001, gid=10001)
            chown_calls = []
            with mock.patch.object(self.mod, "workload_state_dir", lambda n: state), \
                 mock.patch.object(self.mod, "workload_data_dir", lambda n: data), \
                 mock.patch("os.chown", side_effect=lambda p, u, g: chown_calls.append((str(p), u, g))):
                self.mod.setup_home_directory(pw, "myapp")
            self.assertTrue(state.is_dir())
            self.assertTrue(data.is_dir())
            self.assertEqual(oct(state.stat().st_mode & 0o777), "0o700")
            self.assertEqual(oct(data.stat().st_mode & 0o777), "0o700")
            self.assertTrue(any(str(state) == c[0] for c in chown_calls))
            self.assertTrue(any(str(data) == c[0] for c in chown_calls))

    def test_idempotent_on_existing_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            data = root / "data"
            state.mkdir()
            data.mkdir()
            pw = _fake_pw(state, uid=10001, gid=10001)
            with mock.patch.object(self.mod, "workload_state_dir", lambda n: state), \
                 mock.patch.object(self.mod, "workload_data_dir", lambda n: data), \
                 mock.patch("os.chown"):
                self.mod.setup_home_directory(pw, "myapp")  # must not raise
            self.assertTrue(state.is_dir())
            self.assertTrue(data.is_dir())


class TestRestoreSelinuxLabels(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()

    def test_invokes_restorecon_on_workload_root(self):
        calls = []
        with mock.patch.object(self.mod, "workload_root_dir", lambda n: Path("/var/lib/workloads/myapp")), \
             mock.patch.object(self.mod.subprocess, "run",
                               side_effect=lambda argv, **kw: (calls.append(argv),
                                                                types.SimpleNamespace(returncode=0, stderr=""))[1]):
            self.mod.restore_selinux_labels("myapp")
        self.assertEqual(calls[0][:2], ["restorecon", "-R"])
        self.assertIn("/var/lib/workloads/myapp", calls[0])

    def test_logs_warning_on_failure(self):
        msgs = []
        with mock.patch.object(self.mod, "workload_root_dir", lambda n: Path("/x")), \
             mock.patch.object(self.mod.subprocess, "run",
                               return_value=types.SimpleNamespace(returncode=1, stderr="denied")), \
             mock.patch.object(self.mod, "log", side_effect=msgs.append):
            self.mod.restore_selinux_labels("myapp")
        self.assertTrue(any("restorecon failed" in m for m in msgs))


class TestDetectHostIp(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()

    def test_parses_src_token(self):
        out = "1.1.1.1 via 192.168.0.1 dev eth0 src 192.168.0.42 uid 0\n"
        with mock.patch.object(self.mod.subprocess, "check_output", return_value=out):
            self.assertEqual(self.mod._detect_host_ip(), "192.168.0.42")

    def test_returns_empty_on_failure(self):
        with mock.patch.object(self.mod.subprocess, "check_output",
                               side_effect=self.mod.subprocess.CalledProcessError(1, "ip")):
            self.assertEqual(self.mod._detect_host_ip(), "")

    def test_returns_empty_when_no_src_token(self):
        with mock.patch.object(self.mod.subprocess, "check_output",
                               return_value="1.1.1.1 via 192.168.0.1 dev eth0\n"):
            self.assertEqual(self.mod._detect_host_ip(), "")


class TestWriteEnvironmentFile(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()

    def test_writes_uid_and_host_ip(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_dir = Path(tmp) / "run" / "workload-env"
            pw = _fake_pw(Path(tmp), uid=10042, gid=10042)
            with mock.patch.object(self.mod, "Path", side_effect=lambda p: (
                env_dir if p == "/run/workload-env" else Path(p))), \
                 mock.patch.object(self.mod, "_detect_host_ip", return_value="10.0.0.5"):
                self.mod.write_environment_file("myapp", pw, {})
            content = (env_dir / "workload-myapp.env").read_text()
            self.assertIn("XDG_RUNTIME_DIR=/run/user/10042", content)
            self.assertIn("HOST_IP=10.0.0.5", content)

    def test_env_dir_created_mode_0700(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_dir = Path(tmp) / "run" / "workload-env"
            pw = _fake_pw(Path(tmp), uid=10042, gid=10042)
            with mock.patch.object(self.mod, "Path", side_effect=lambda p: (
                env_dir if p == "/run/workload-env" else Path(p))), \
                 mock.patch.object(self.mod, "_detect_host_ip", return_value=""):
                self.mod.write_environment_file("myapp", pw, {})
            self.assertEqual(oct(env_dir.stat().st_mode & 0o777), "0o700")


class TestEnableLinger(unittest.TestCase):
    """enable_linger delegates the start/wait to service_runtime.ensure_runtime_dir
    (B5), but first sets the persistent linger marker unconditionally: ensure_
    runtime_dir short-circuits (skipping `loginctl enable-linger`) when a possibly
    transient user@<uid>.service is already active, so the provisioning path must
    guarantee the marker itself. It also adds fail-loud semantics on top."""

    def setUp(self):
        self.mod = _load_script()

    def test_enable_linger_success(self):
        pw = _fake_pw(Path("/home/_wl-test"), uid=10001, gid=10001)
        pw.pw_name = "_wl-test"
        with mock.patch.object(self.mod.subprocess, "run",
                               return_value=mock.Mock(returncode=0, stderr="")) as run, \
             mock.patch.object(self.mod.service_runtime, "ensure_runtime_dir",
                               return_value=True) as ensure, \
             mock.patch.object(self.mod, "log"):
            self.mod.enable_linger(pw)  # must not raise
        # The marker is set unconditionally, before ensure_runtime_dir.
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0],
                         ["loginctl", "enable-linger", "10001"])
        ensure.assert_called_once_with(10001, timeout=15)

    def test_raises_when_enable_linger_fails(self):
        pw = _fake_pw(Path("/home/_wl-test"), uid=10001, gid=10001)
        pw.pw_name = "_wl-test"
        with mock.patch.object(self.mod.subprocess, "run",
                               return_value=mock.Mock(returncode=1, stderr="boom")), \
             mock.patch.object(self.mod.service_runtime, "ensure_runtime_dir",
                               return_value=True) as ensure, \
             mock.patch.object(self.mod, "log"):
            with self.assertRaises(RuntimeError) as ctx:
                self.mod.enable_linger(pw)
            self.assertIn("enable-linger failed", str(ctx.exception))
        # Marker set failed → never bother waiting on the runtime dir.
        ensure.assert_not_called()

    def test_raises_when_manager_never_active(self):
        pw = _fake_pw(Path("/home/_wl-test"), uid=10001, gid=10001)
        pw.pw_name = "_wl-test"
        with mock.patch.object(self.mod.subprocess, "run",
                               return_value=mock.Mock(returncode=0, stderr="")), \
             mock.patch.object(self.mod.service_runtime, "ensure_runtime_dir",
                               return_value=False), \
             mock.patch.object(self.mod, "log"):
            with self.assertRaises(RuntimeError) as ctx:
                self.mod.enable_linger(pw)
            self.assertIn("did not become active", str(ctx.exception))


class TestSetupVmBridge(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()

    def test_creates_bridge_conf_and_adds_allow_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "qemu" / "bridge.conf"
            with mock.patch.object(self.mod, "Path", side_effect=lambda p: (
                conf if p == "/etc/qemu/bridge.conf" else Path(p))):
                self.mod.setup_vm_bridge("myvm", "_workload-br")
            self.assertIn("allow _workload-br", conf.read_text())

    def test_idempotent_when_allow_line_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "qemu" / "bridge.conf"
            conf.parent.mkdir(parents=True)
            conf.write_text("allow _workload-br\n")
            with mock.patch.object(self.mod, "Path", side_effect=lambda p: (
                conf if p == "/etc/qemu/bridge.conf" else Path(p))):
                self.mod.setup_vm_bridge("myvm", "_workload-br")
            self.assertEqual(conf.read_text().count("allow _workload-br"), 1)

    def test_second_bridge_appended(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "qemu" / "bridge.conf"
            conf.parent.mkdir(parents=True)
            conf.write_text("allow br0\n")
            with mock.patch.object(self.mod, "Path", side_effect=lambda p: (
                conf if p == "/etc/qemu/bridge.conf" else Path(p))):
                self.mod.setup_vm_bridge("myvm", "_workload-br")
            text = conf.read_text()
            self.assertIn("allow br0", text)
            self.assertIn("allow _workload-br", text)

    def test_prefix_collision_does_not_suppress_allow_line(self):
        # Regression: an existing "allow br0-lan" line must not suppress adding
        # "allow br0" — a substring check (`"allow br0" in existing`) would
        # false-positive on "allow br0-lan" and silently skip the append.
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "qemu" / "bridge.conf"
            conf.parent.mkdir(parents=True)
            conf.write_text("allow br0-lan\n")
            with mock.patch.object(self.mod, "Path", side_effect=lambda p: (
                conf if p == "/etc/qemu/bridge.conf" else Path(p))):
                self.mod.setup_vm_bridge("myvm", "br0")
            lines = conf.read_text().splitlines()
            self.assertIn("allow br0-lan", lines)
            self.assertIn("allow br0", lines)


class TestSetupNvram(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()

    def test_copies_ovmf_vars_when_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            ovmf = Path(tmp) / "OVMF_VARS.fd"
            ovmf.write_bytes(b"nvramdata")
            pw = _fake_pw(home, uid=10001, gid=10001)
            with mock.patch.object(self.mod, "find_ovmf_vars", return_value=str(ovmf)), \
                 mock.patch("os.chown"):
                self.mod.setup_nvram(pw, {})
            dst = home / "nvram.fd"
            self.assertTrue(dst.exists())
            self.assertEqual(dst.read_bytes(), b"nvramdata")
            self.assertEqual(oct(dst.stat().st_mode & 0o777), "0o600")

    def test_noop_when_nvram_already_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            dst = home / "nvram.fd"
            dst.write_bytes(b"existing")
            pw = _fake_pw(home, uid=10001, gid=10001)
            with mock.patch.object(self.mod, "find_ovmf_vars") as m:
                self.mod.setup_nvram(pw, {})
                m.assert_not_called()
            self.assertEqual(dst.read_bytes(), b"existing")

    def test_raises_when_ovmf_vars_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            pw = _fake_pw(home, uid=10001, gid=10001)
            with mock.patch.object(self.mod, "find_ovmf_vars", return_value=None):
                with self.assertRaises(RuntimeError) as ctx:
                    self.mod.setup_nvram(pw, {})
                self.assertIn("OVMF_VARS.fd not found", str(ctx.exception))


class TestSetupVmSocketDir(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()

    def test_creates_socket_dir_mode_0750(self):
        with tempfile.TemporaryDirectory() as tmp:
            socket_base = Path(tmp) / "run" / "workload-vm"
            pw = _fake_pw(Path(tmp), uid=10001, gid=10001)
            with mock.patch.object(self.mod, "VM_SOCKET_DIR", socket_base), \
                 mock.patch("os.chown"):
                self.mod.setup_vm_socket_dir(pw, "myvm")
            sock_dir = socket_base / "myvm"
            self.assertTrue(sock_dir.is_dir())
            self.assertEqual(oct(sock_dir.stat().st_mode & 0o777), "0o750")

    def test_idempotent_on_existing_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            socket_base = Path(tmp) / "run" / "workload-vm"
            (socket_base / "myvm").mkdir(parents=True)
            pw = _fake_pw(Path(tmp), uid=10001, gid=10001)
            with mock.patch.object(self.mod, "VM_SOCKET_DIR", socket_base), \
                 mock.patch("os.chown"):
                self.mod.setup_vm_socket_dir(pw, "myvm")  # must not raise


class TestGenerateSshKeypair(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()

    def test_generates_keypair_when_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            pw = _fake_pw(home, uid=10001, gid=10001)

            def fake_keygen(argv, **kw):
                key_path = Path(argv[argv.index("-f") + 1])
                key_path.write_text("PRIVATE")
                key_path.with_suffix(".pub").write_text("PUBLIC")
                return types.SimpleNamespace(returncode=0, stderr="")

            with mock.patch.object(self.mod.subprocess, "run", side_effect=fake_keygen), \
                 mock.patch("os.chown"):
                self.mod.generate_ssh_keypair(pw, "myvm")
            self.assertTrue((home / ".ssh" / "id_ed25519").exists())
            self.assertTrue((home / ".ssh" / "id_ed25519.pub").exists())
            self.assertEqual(oct((home / ".ssh").stat().st_mode & 0o777), "0o700")

    def test_noop_when_key_already_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            (home / ".ssh").mkdir(parents=True)
            (home / ".ssh" / "id_ed25519").write_text("EXISTING")
            pw = _fake_pw(home, uid=10001, gid=10001)
            with mock.patch.object(self.mod.subprocess, "run") as m, \
                 mock.patch("os.chown"):
                self.mod.generate_ssh_keypair(pw, "myvm")
                m.assert_not_called()

    def test_raises_on_keygen_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            pw = _fake_pw(home, uid=10001, gid=10001)
            with mock.patch.object(self.mod.subprocess, "run",
                                   return_value=types.SimpleNamespace(returncode=1, stderr="bad args")), \
                 mock.patch("os.chown"):
                with self.assertRaises(RuntimeError) as ctx:
                    self.mod.generate_ssh_keypair(pw, "myvm")
                self.assertIn("ssh-keygen failed", str(ctx.exception))


class TestReadSshPubkey(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()

    def test_returns_pubkey_when_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            (home / ".ssh").mkdir(parents=True)
            (home / ".ssh" / "id_ed25519.pub").write_text("ssh-ed25519 AAA user@host\n")
            pw = _fake_pw(home)
            self.assertEqual(self.mod._read_ssh_pubkey(pw), "ssh-ed25519 AAA user@host")

    def test_returns_empty_when_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            pw = _fake_pw(home)
            self.assertEqual(self.mod._read_ssh_pubkey(pw), "")


class TestBundleWorkloadctlRpm(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()

    def test_copies_when_cached_rpm_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            cached = Path(tmp) / "cached.rpm"
            cached.write_bytes(b"RPMDATA")
            seed_dir = Path(tmp) / "seed"
            seed_dir.mkdir()
            with mock.patch.object(self.mod, "Path", side_effect=lambda p: (
                cached if p == "/usr/share/workloadctl/workloadctl.rpm" else Path(p))):
                result = self.mod._bundle_workloadctl_rpm(seed_dir)
            self.assertTrue(result)
            self.assertEqual((seed_dir / "workloadctl.rpm").read_bytes(), b"RPMDATA")

    def test_returns_false_when_no_cached_rpm(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "nope.rpm"
            seed_dir = Path(tmp) / "seed"
            seed_dir.mkdir()
            with mock.patch.object(self.mod, "Path", side_effect=lambda p: (
                missing if p == "/usr/share/workloadctl/workloadctl.rpm" else Path(p))):
                result = self.mod._bundle_workloadctl_rpm(seed_dir)
            self.assertFalse(result)
            self.assertFalse((seed_dir / "workloadctl.rpm").exists())


class TestLoadConfig(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()

    def test_loads_toml_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "workload.toml"
            cfg_path.write_text('[workload]\nname = "myapp"\n')
            with mock.patch.object(self.mod, "workload_config_path", lambda n: cfg_path):
                cfg = self.mod.load_config("myapp")
            self.assertEqual(cfg["workload"]["name"], "myapp")


class TestDecryptSystemdCredentialMore(unittest.TestCase):
    """Additional coverage for the encrypted-success, encrypted-failure and
    plain-fallback branches of _decrypt_systemd_credential."""

    def setUp(self):
        self.mod = _load_script()

    def test_encrypted_success_decodes_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            enc_dir = Path(tmp) / "credstore.encrypted"
            enc_dir.mkdir()
            enc_file = enc_dir / "mysecret"
            enc_file.write_bytes(b"ENCRYPTED")
            with mock.patch.object(self.mod, "Path", side_effect=lambda p: (
                enc_file if p == "/etc/credstore.encrypted/mysecret" else Path(p))), \
                 mock.patch.object(self.mod.subprocess, "run",
                                   return_value=types.SimpleNamespace(
                                       returncode=0, stdout=b"decrypted-value\n", stderr=b"")):
                result = self.mod._decrypt_systemd_credential("mysecret")
            self.assertEqual(result, "decrypted-value")

    def test_encrypted_failure_raises_runtime_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            enc_dir = Path(tmp) / "credstore.encrypted"
            enc_dir.mkdir()
            enc_file = enc_dir / "mysecret"
            enc_file.write_bytes(b"ENCRYPTED")
            with mock.patch.object(self.mod, "Path", side_effect=lambda p: (
                enc_file if p == "/etc/credstore.encrypted/mysecret" else Path(p))), \
                 mock.patch.object(self.mod.subprocess, "run",
                                   return_value=types.SimpleNamespace(
                                       returncode=1, stdout=b"", stderr=b"bad tpm")):
                with self.assertRaises(RuntimeError) as ctx:
                    self.mod._decrypt_systemd_credential("mysecret")
                self.assertIn("decrypt failed", str(ctx.exception))

    def test_plain_fallback_when_no_encrypted_form(self):
        with tempfile.TemporaryDirectory() as tmp:
            enc_file = Path(tmp) / "credstore.encrypted" / "mysecret"
            plain_file = Path(tmp) / "credstore" / "mysecret"
            plain_file.parent.mkdir(parents=True)
            plain_file.write_text("plaintext-secret\n")
            with mock.patch.object(self.mod, "Path", side_effect=lambda p: {
                "/etc/credstore.encrypted/mysecret": enc_file,
                "/etc/credstore/mysecret": plain_file,
            }.get(p, Path(p))):
                result = self.mod._decrypt_systemd_credential("mysecret")
            self.assertEqual(result, "plaintext-secret")


class TestConfigureSubuidSubgidMore(unittest.TestCase):
    """Additional coverage: uid-below-minimum, extra_groups, userns=host skip,
    podman migrate success/failure/timeout branches."""

    def setUp(self):
        self.mod = _load_script()

    def test_uid_below_minimum_raises(self):
        pw = _fake_pw(Path("/home/_wl-test"), uid=999)
        pw.pw_name = "_wl-test"
        with self.assertRaises(ValueError) as ctx:
            self.mod.configure_subuid_subgid(pw, {})
        self.assertIn("below minimum", str(ctx.exception))

    def test_subuid_range_overflow_raises(self):
        """A UID far enough past the normal allocation range makes the
        subid_start + count - 1 formula exceed uint32 max — the guard must
        raise rather than write an unusable subuid/subgid entry."""
        pw = _fake_pw(Path("/home/_wl-test"), uid=66379)
        pw.pw_name = "_wl-test"
        with self.assertRaises(ValueError) as ctx:
            self.mod.configure_subuid_subgid(pw, {})
        self.assertIn("would overflow uint32", str(ctx.exception))

    def test_subuid_range_just_below_overflow_succeeds(self):
        """One UID below the overflow boundary must not raise."""
        pw = _fake_pw(Path("/home/_wl-test"), uid=66378)
        pw.pw_name = "_wl-test"
        self._run_with_lock(pw, {})

    def _run_with_lock(self, pw, config, subprocess_mock=None):
        def fake_open(path, mode="r"):
            m = mock.MagicMock()
            m.__enter__ = lambda s: m
            m.__exit__ = mock.MagicMock(return_value=False)
            m.fileno = lambda: 0
            m.read = lambda: ""
            m.write = lambda s: None
            return m

        with mock.patch("builtins.open", side_effect=fake_open), \
             mock.patch.object(self.mod, "subid_lock", contextlib.nullcontext), \
             mock.patch.object(self.mod.Path, "mkdir"), \
             mock.patch.object(self.mod, "subprocess",
                               subprocess_mock or mock.MagicMock()):
            self.mod.configure_subuid_subgid(pw, config)

    def test_extra_groups_adds_subgid_entry(self):
        pw = _fake_pw(Path("/home/_wl-test"), uid=10000)
        pw.pw_name = "_wl-test"
        config = {"security": {"extra_groups": ["video"]}}
        written = []

        def fake_open(path, mode="r"):
            m = mock.MagicMock()
            m.__enter__ = lambda s: m
            m.__exit__ = mock.MagicMock(return_value=False)
            m.fileno = lambda: 0
            if mode == "a":
                m.write = lambda s: written.append((str(path), s))
            return m

        with mock.patch("builtins.open", side_effect=fake_open), \
             mock.patch.object(self.mod, "subid_lock", contextlib.nullcontext), \
             mock.patch.object(self.mod.Path, "mkdir"), \
             mock.patch.object(self.mod.grp, "getgrnam",
                               return_value=types.SimpleNamespace(gr_gid=44)), \
             mock.patch.object(self.mod, "subprocess", mock.MagicMock()):
            self.mod.configure_subuid_subgid(pw, config)
        subgid_writes = [s for p, s in written if "subgid" in p]
        self.assertTrue(any("_wl-test:44:1" in s for s in subgid_writes))

    def test_missing_extra_group_logs_warning_and_skips(self):
        pw = _fake_pw(Path("/home/_wl-test"), uid=10000)
        pw.pw_name = "_wl-test"
        config = {"security": {"extra_groups": ["nonexistent-group"]}}
        msgs = []

        def fake_open(path, mode="r"):
            m = mock.MagicMock()
            m.__enter__ = lambda s: m
            m.__exit__ = mock.MagicMock(return_value=False)
            m.fileno = lambda: 0
            return m

        with mock.patch("builtins.open", side_effect=fake_open), \
             mock.patch.object(self.mod, "subid_lock", contextlib.nullcontext), \
             mock.patch.object(self.mod.Path, "mkdir"), \
             mock.patch.object(self.mod.grp, "getgrnam", side_effect=KeyError()), \
             mock.patch.object(self.mod, "subprocess", mock.MagicMock()), \
             mock.patch.object(self.mod, "log", side_effect=msgs.append):
            self.mod.configure_subuid_subgid(pw, config)
        self.assertTrue(any("not found" in m for m in msgs))

    def test_userns_host_skips_extra_group_subgid(self):
        pw = _fake_pw(Path("/home/_wl-test"), uid=10000)
        pw.pw_name = "_wl-test"
        config = {"security": {"userns": "host", "extra_groups": ["video"]}}
        written = []

        def fake_open(path, mode="r"):
            m = mock.MagicMock()
            m.__enter__ = lambda s: m
            m.__exit__ = mock.MagicMock(return_value=False)
            m.fileno = lambda: 0
            if mode == "a":
                m.write = lambda s: written.append((str(path), s))
            return m

        with mock.patch("builtins.open", side_effect=fake_open), \
             mock.patch.object(self.mod, "subid_lock", contextlib.nullcontext), \
             mock.patch.object(self.mod.Path, "mkdir"), \
             mock.patch.object(self.mod.grp, "getgrnam") as gg, \
             mock.patch.object(self.mod, "subprocess", mock.MagicMock()):
            self.mod.configure_subuid_subgid(pw, config)
        gg.assert_not_called()
        subgid_writes = [s for p, s in written if "subgid" in p]
        self.assertFalse(any(":44:1" in s or "video" in s for s in subgid_writes))

    def test_podman_migrate_timeout_logs_warning(self):
        pw = _fake_pw(Path("/home/_wl-test"), uid=10000)
        pw.pw_name = "_wl-test"
        msgs = []

        def fake_open(path, mode="r"):
            m = mock.MagicMock()
            m.__enter__ = lambda s: m
            m.__exit__ = mock.MagicMock(return_value=False)
            m.fileno = lambda: 0
            return m

        with mock.patch("builtins.open", side_effect=fake_open), \
             mock.patch.object(self.mod, "subid_lock", contextlib.nullcontext), \
             mock.patch.object(self.mod.Path, "mkdir"), \
             mock.patch.object(self.mod.subprocess, "run",
                               side_effect=self.mod.subprocess.TimeoutExpired("podman", 30)), \
             mock.patch.object(self.mod, "log", side_effect=msgs.append):
            self.mod.configure_subuid_subgid(pw, {})
        self.assertTrue(any("timed out" in m for m in msgs))

    def test_podman_migrate_success_logs(self):
        pw = _fake_pw(Path("/home/_wl-test"), uid=10000)
        pw.pw_name = "_wl-test"
        msgs = []

        def fake_open(path, mode="r"):
            m = mock.MagicMock()
            m.__enter__ = lambda s: m
            m.__exit__ = mock.MagicMock(return_value=False)
            m.fileno = lambda: 0
            return m

        with mock.patch("builtins.open", side_effect=fake_open), \
             mock.patch.object(self.mod, "subid_lock", contextlib.nullcontext), \
             mock.patch.object(self.mod.Path, "mkdir"), \
             mock.patch.object(self.mod.subprocess, "run",
                               return_value=types.SimpleNamespace(returncode=0, stdout="", stderr="")), \
             mock.patch.object(self.mod, "log", side_effect=msgs.append):
            self.mod.configure_subuid_subgid(pw, {})
        self.assertTrue(any("Migrated podman storage" in m for m in msgs))


class TestSetupVolumeDirectoriesSkipBranches(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()

    def test_required_files_path_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "state").mkdir()
            config = {
                "workload": {"name": "myapp"},
                "setup": {"required_files": [{"path": "./secret.env"}]},
                "storage": {"volumes": ["./secret.env:/etc/secret.env"]},
            }
            pw = _fake_pw(root / "state", uid=10001, gid=10001)
            with mock.patch.object(self.mod, "workload_state_dir", lambda n: root / "state"), \
                 mock.patch.object(self.mod, "workload_root_dir", lambda n: root), \
                 mock.patch("os.fchown"), mock.patch("os.fchmod"):
                self.mod.setup_volume_directories(pw, config)
            # required_files path must NOT be created as a directory
            self.assertFalse((root / "data" / "secret.env").exists())

    def test_path_outside_workload_root_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "state").mkdir()
            config = {
                "workload": {"name": "myapp"},
                "storage": {"volumes": ["/etc/passwd:/etc/passwd"]},
            }
            pw = _fake_pw(root / "state", uid=10001, gid=10001)
            with mock.patch.object(self.mod, "workload_state_dir", lambda n: root / "state"), \
                 mock.patch.object(self.mod, "workload_root_dir", lambda n: root), \
                 mock.patch("os.fchown"), mock.patch("os.fchmod"):
                self.mod.setup_volume_directories(pw, config)  # must not raise


class TestBuildCloudInitIsoValidation(unittest.TestCase):
    """Guest-user validation and legacy-ISO cleanup branches."""

    def setUp(self):
        self.mod = _load_script()
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp) / "home"
        self.home.mkdir()
        (self.home / ".ssh").mkdir()
        (self.home / ".ssh" / "id_ed25519.pub").write_text("ssh-ed25519 AAAA user@host\n")
        (self.home / ".ssh" / "vm_host_ed25519_key").write_text(FAKE_HOST_PRIV)
        (self.home / ".ssh" / "vm_host_ed25519_key.pub").write_text(FAKE_HOST_PUB + "\n")
        self.runtime = Path(self.tmp) / "run"
        self.runtime.mkdir()
        self.pw = _fake_pw(self.home)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_invalid_guest_user_raises(self):
        cfg = {"vm": {"user": "Not Valid!"}}
        with mock.patch.object(self.mod.os, "chown", lambda *a, **kw: None), \
             mock.patch.object(self.mod, "VM_SOCKET_DIR", self.runtime), \
             mock.patch.object(self.mod, "workload_state_dir", lambda n: self.home):
            with self.assertRaises(RuntimeError) as ctx:
                self.mod.build_cloud_init_iso(self.pw, cfg, "myvm")
            self.assertIn("not a valid POSIX username", str(ctx.exception))

    def test_missing_pubkey_raises(self):
        (self.home / ".ssh" / "id_ed25519.pub").unlink()
        cfg = {"vm": {}}
        with mock.patch.object(self.mod.os, "chown", lambda *a, **kw: None), \
             mock.patch.object(self.mod, "VM_SOCKET_DIR", self.runtime), \
             mock.patch.object(self.mod, "workload_state_dir", lambda n: self.home):
            with self.assertRaises(RuntimeError) as ctx:
                self.mod.build_cloud_init_iso(self.pw, cfg, "myvm")
            self.assertIn("SSH pubkey missing", str(ctx.exception))

    def test_legacy_iso_removed(self):
        legacy = self.home / "cloud-init.iso"
        legacy.write_bytes(b"OLD")
        cfg = {"vm": {}}
        import shutil as _shutil
        with mock.patch.object(self.mod.os, "chown", lambda *a, **kw: None), \
             mock.patch.object(self.mod, "VM_SOCKET_DIR", self.runtime), \
             mock.patch.object(self.mod, "workload_state_dir", lambda n: self.home), \
             mock.patch.object(_shutil, "which", return_value=None):
            self.mod.build_cloud_init_iso(self.pw, cfg, "myvm")
        self.assertFalse(legacy.exists())

    def test_no_iso_tool_warns_and_returns(self):
        cfg = {"vm": {}}
        msgs = []
        import shutil as _shutil
        with mock.patch.object(self.mod.os, "chown", lambda *a, **kw: None), \
             mock.patch.object(self.mod, "VM_SOCKET_DIR", self.runtime), \
             mock.patch.object(self.mod, "workload_state_dir", lambda n: self.home), \
             mock.patch.object(_shutil, "which", return_value=None), \
             mock.patch.object(self.mod, "log", side_effect=msgs.append):
            self.mod.build_cloud_init_iso(self.pw, cfg, "myvm")
        self.assertTrue(any("No ISO tool found" in m for m in msgs))
        self.assertFalse((self.runtime / "myvm" / "cloud-init.iso").exists())

    def test_iso_build_subprocess_failure_warns(self):
        cfg = {"vm": {}}
        msgs = []
        import shutil as _shutil
        with mock.patch.object(self.mod.os, "chown", lambda *a, **kw: None), \
             mock.patch.object(self.mod, "VM_SOCKET_DIR", self.runtime), \
             mock.patch.object(self.mod, "workload_state_dir", lambda n: self.home), \
             mock.patch.object(_shutil, "which",
                               lambda name: "/usr/bin/genisoimage" if name == "genisoimage" else None), \
             mock.patch.object(self.mod.subprocess, "run",
                               return_value=types.SimpleNamespace(returncode=1, stdout="", stderr="iso failed")), \
             mock.patch.object(self.mod, "log", side_effect=msgs.append):
            self.mod.build_cloud_init_iso(self.pw, cfg, "myvm")
        self.assertTrue(any("ISO build failed" in m for m in msgs))


class TestMain(unittest.TestCase):
    """main() argument handling and control flow (both kinds)."""

    def setUp(self):
        self.mod = _load_script()
        self.pw = _fake_pw(Path("/home/_wl-test"))

    def _patch_common(self, kind):
        """Patch out every side-effecting call main() makes; return the dict
        of mocks so individual tests can assert on calls / raise from one."""
        patches = {
            "workload_username": mock.patch.object(self.mod, "workload_username", return_value="_wl-test"),
            "getpwnam": mock.patch.object(self.mod.pwd, "getpwnam", return_value=self.pw),
            "warn_if_stale_home": mock.patch.object(self.mod, "warn_if_stale_home"),
            "mkdir": mock.patch.object(type(self.mod.WORKLOADS_BASE), "mkdir"),
            "load_config": mock.patch.object(self.mod, "load_config", return_value={"workload": {"name": "test"}}),
            "infer_workload_kind": mock.patch.object(self.mod, "infer_workload_kind", return_value=kind),
            "setup_selinux_policy": mock.patch.object(self.mod, "setup_selinux_policy"),
            "setup_home_directory": mock.patch.object(self.mod, "setup_home_directory"),
            "configure_subuid_subgid": mock.patch.object(self.mod, "configure_subuid_subgid"),
            "setup_volume_directories": mock.patch.object(self.mod, "setup_volume_directories"),
            "write_environment_file": mock.patch.object(self.mod, "write_environment_file"),
            "restore_selinux_labels": mock.patch.object(self.mod, "restore_selinux_labels"),
            "enable_linger": mock.patch.object(self.mod, "enable_linger"),
            "setup_vm_bridge": mock.patch.object(self.mod, "setup_vm_bridge"),
            "setup_nvram": mock.patch.object(self.mod, "setup_nvram"),
            "setup_vm_socket_dir": mock.patch.object(self.mod, "setup_vm_socket_dir"),
            "setup_vm_volume_directories": mock.patch.object(self.mod, "setup_vm_volume_directories"),
            "generate_ssh_keypair": mock.patch.object(self.mod, "generate_ssh_keypair"),
            "generate_vm_host_keypair": mock.patch.object(self.mod, "generate_vm_host_keypair"),
            "build_cloud_init_iso": mock.patch.object(self.mod, "build_cloud_init_iso"),
        }
        mocks = {name: p.start() for name, p in patches.items()}
        for p in patches.values():
            self.addCleanup(p.stop)
        return mocks

    def test_usage_error_wrong_argc(self):
        with mock.patch.object(self.mod.sys, "argv", ["workload-ensure-user"]):
            rc = self.mod.main()
        self.assertEqual(rc, 1)

    def test_unknown_user_returns_1(self):
        with mock.patch.object(self.mod.sys, "argv", ["prog", "myapp"]), \
             mock.patch.object(self.mod, "workload_username", return_value="_wl-myapp"), \
             mock.patch.object(self.mod.pwd, "getpwnam", side_effect=KeyError("no such user")):
            rc = self.mod.main()
        self.assertEqual(rc, 1)

    def test_load_config_failure_returns_1(self):
        mocks = self._patch_common("container")
        mocks["load_config"].side_effect = Exception("bad toml")
        with mock.patch.object(self.mod.sys, "argv", ["prog", "myapp"]):
            rc = self.mod.main()
        self.assertEqual(rc, 1)
        mocks["setup_home_directory"].assert_not_called()

    def test_container_kind_runs_full_sequence(self):
        mocks = self._patch_common("container")
        with mock.patch.object(self.mod.sys, "argv", ["prog", "myapp"]):
            rc = self.mod.main()
        self.assertEqual(rc, 0)
        mocks["configure_subuid_subgid"].assert_called_once()
        mocks["setup_volume_directories"].assert_called_once()
        mocks["write_environment_file"].assert_called_once()
        mocks["restore_selinux_labels"].assert_called_once()
        mocks["enable_linger"].assert_called_once()
        # VM-only steps must not run for container workloads
        mocks["setup_vm_bridge"].assert_not_called()
        mocks["setup_nvram"].assert_not_called()
        mocks["generate_ssh_keypair"].assert_not_called()
        mocks["build_cloud_init_iso"].assert_not_called()

    # The container provisioning steps split into two contracts: must-succeed
    # steps (a failure leaves the workload running-but-wrong, so main() aborts
    # nonzero) and best-effort steps (a failure is logged but provisioning
    # continues). These two tests pin each step to its contract individually so
    # a regression flipping either direction is caught.
    CONTAINER_MUST_SUCCEED = (
        "configure_subuid_subgid",
        "setup_volume_directories",
        "write_environment_file",
        "enable_linger",
    )
    CONTAINER_BEST_EFFORT = (
        "setup_selinux_policy",
        "setup_home_directory",
        "restore_selinux_labels",
    )

    def test_container_must_succeed_step_failures_are_fatal(self):
        mocks = self._patch_common("container")
        for step in self.CONTAINER_MUST_SUCCEED:
            with self.subTest(step=step):
                for m in mocks.values():
                    m.reset_mock()
                    m.side_effect = None
                mocks[step].side_effect = RuntimeError("boom")
                with mock.patch.object(self.mod.sys, "argv", ["prog", "myapp"]):
                    rc = self.mod.main()
                # A must-succeed step's failure aborts main() nonzero
                self.assertEqual(rc, 1)

    def test_container_best_effort_step_failures_are_nonfatal(self):
        mocks = self._patch_common("container")
        for step in self.CONTAINER_BEST_EFFORT:
            with self.subTest(step=step):
                for m in mocks.values():
                    m.reset_mock()
                    m.side_effect = None
                mocks[step].side_effect = Exception("boom")
                with mock.patch.object(self.mod.sys, "argv", ["prog", "myapp"]):
                    rc = self.mod.main()
                # A best-effort failure neither aborts main() nor skips the
                # later must-succeed steps (enable_linger still runs)
                self.assertEqual(rc, 0)
                mocks["enable_linger"].assert_called_once()

    def test_vm_kind_runs_full_sequence(self):
        mocks = self._patch_common("vm")
        with mock.patch.object(self.mod.sys, "argv", ["prog", "myvm"]):
            rc = self.mod.main()
        self.assertEqual(rc, 0)
        mocks["setup_vm_bridge"].assert_called_once()
        mocks["setup_nvram"].assert_called_once()
        mocks["setup_vm_socket_dir"].assert_called_once()
        mocks["setup_vm_volume_directories"].assert_called_once()
        mocks["generate_ssh_keypair"].assert_called_once()
        mocks["generate_vm_host_keypair"].assert_called_once()
        mocks["build_cloud_init_iso"].assert_called_once()
        mocks["write_environment_file"].assert_called_once()
        mocks["restore_selinux_labels"].assert_called_once()
        # Container-only steps must not run for VM workloads
        mocks["configure_subuid_subgid"].assert_not_called()
        mocks["setup_volume_directories"].assert_not_called()
        mocks["enable_linger"].assert_not_called()

    def test_vm_nvram_failure_is_fatal(self):
        mocks = self._patch_common("vm")
        mocks["setup_nvram"].side_effect = Exception("nvram boom")
        with mock.patch.object(self.mod.sys, "argv", ["prog", "myvm"]):
            rc = self.mod.main()
        self.assertEqual(rc, 1)
        # main returns immediately after the fatal NVRAM failure
        mocks["setup_vm_socket_dir"].assert_not_called()
        mocks["generate_ssh_keypair"].assert_not_called()

    def test_vm_ssh_keypair_failure_is_fatal(self):
        mocks = self._patch_common("vm")
        mocks["generate_ssh_keypair"].side_effect = Exception("ssh boom")
        with mock.patch.object(self.mod.sys, "argv", ["prog", "myvm"]):
            rc = self.mod.main()
        self.assertEqual(rc, 1)
        mocks["build_cloud_init_iso"].assert_not_called()

    def test_vm_cloud_init_failure_is_fatal(self):
        mocks = self._patch_common("vm")
        mocks["build_cloud_init_iso"].side_effect = Exception("iso boom")
        with mock.patch.object(self.mod.sys, "argv", ["prog", "myvm"]):
            rc = self.mod.main()
        self.assertEqual(rc, 1)
        mocks["write_environment_file"].assert_not_called()

    def test_vm_non_fatal_step_failures_still_succeed(self):
        mocks = self._patch_common("vm")
        mocks["setup_vm_bridge"].side_effect = Exception("bridge boom")
        mocks["setup_vm_socket_dir"].side_effect = Exception("socket boom")
        with mock.patch.object(self.mod.sys, "argv", ["prog", "myvm"]):
            rc = self.mod.main()
        self.assertEqual(rc, 0)
        mocks["generate_ssh_keypair"].assert_called_once()


class TestEnsureManagerSlice(unittest.TestCase):
    """ensure_manager_slice migrates user@<uid>.service into its target slice
    (ADR 001 1b) by restarting the manager only when it is mis-placed."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_script()

    def _drive(self, cgroups, config=None):
        """Run ensure_manager_slice with a scripted sequence of ControlGroup
        values returned by successive `systemctl show` calls. Returns the list
        of issued commands and the ensure_runtime_dir mock."""
        pending = list(cgroups)
        calls = []

        def fake_run(cmd, *a, **k):
            calls.append(cmd)
            if "show" in cmd and "ControlGroup" in cmd:
                val = pending.pop(0) if pending else ""
                return types.SimpleNamespace(returncode=0, stdout=val + "\n", stderr="")
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        pw = _fake_pw(Path("/nonexistent"), uid=10000)
        with mock.patch.object(self.mod.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(self.mod.service_runtime, "ensure_runtime_dir",
                               return_value=True) as erd:
            self.mod.ensure_manager_slice(pw, config or {})
        return calls, erd

    def _restarted(self, calls):
        return [c for c in calls
                if c[:2] == ["systemctl", "restart"] and "user@10000.service" in c]

    def test_noop_when_already_in_target_slice(self):
        calls, erd = self._drive(["/workloads.slice/user@10000.service"])
        self.assertEqual(self._restarted(calls), [])
        erd.assert_not_called()

    def test_restarts_when_misplaced_then_settles(self):
        calls, erd = self._drive([
            "/user.slice/user-10000.slice/user@10000.service",  # logind placement
            "/workloads.slice/user@10000.service",              # after restart
        ])
        self.assertEqual(len(self._restarted(calls)), 1)
        erd.assert_called_once()

    def test_noop_when_manager_cgroup_unknown(self):
        # Empty ControlGroup (manager not resolvable) → don't touch it.
        calls, erd = self._drive([""])
        self.assertEqual(self._restarted(calls), [])
        erd.assert_not_called()

    def test_warns_but_survives_when_restart_does_not_migrate(self):
        # Still mis-placed after the restart: no exception, still exactly one
        # restart attempt (non-fatal — the workload runs regardless).
        calls, erd = self._drive([
            "/user.slice/user-10000.slice/user@10000.service",
            "/user.slice/user-10000.slice/user@10000.service",
        ])
        self.assertEqual(len(self._restarted(calls)), 1)

    def test_custom_slice_respected(self):
        # A [resources].slice override changes the target; a manager already in
        # that (name-nested) slice is a no-op.
        calls, _ = self._drive(
            ["/gpu.slice/gpu-workloads.slice/user@10000.service"],
            config={"resources": {"slice": "gpu-workloads.slice"}},
        )
        self.assertEqual(self._restarted(calls), [])


if __name__ == "__main__":
    unittest.main()
