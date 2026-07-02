#!/usr/bin/env python3
"""Unit tests for the bundle catalog verbs: catalog, init, duplicate.

These exercise the pure identity-rewrite + resolution logic against the real
shipped bundles under ../workloads/, writing instances into a tmp /etc dir.
"""

import argparse
import io
import json
import sys
import tomllib
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

LIB = str(Path(__file__).resolve().parent.parent / "lib")
if LIB not in sys.path:
    sys.path.insert(0, LIB)

import workload_lib            # noqa: E402
import cmd_catalog            # noqa: E402
import workloadctl_core       # noqa: E402
from workloadctl_core import WorkloadManager  # noqa: E402

REPO_BUNDLES = Path(__file__).resolve().parent.parent / "workloads"


def _ns(**kw):
    return argparse.Namespace(**kw)


class CatalogTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        # init/duplicate write here; WorkloadConfig/Manager read here.
        patches = [
            mock.patch.object(cmd_catalog, "BUNDLES_DIR", REPO_BUNDLES),
            mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp),
            mock.patch.object(cmd_catalog, "require_root", lambda: None),
        ]
        for p in patches:
            self.enterContext(p)
        self.manager = WorkloadManager()

    def _read(self, name):
        return tomllib.loads((self.tmp / name / "workload.toml").read_text())


class TestDiscovery(CatalogTestBase):
    def test_list_bundles_includes_known(self):
        bundles = cmd_catalog.list_bundles()
        self.assertIn("alloy", bundles)
        self.assertIn("virtual-forgejo", bundles)
        self.assertEqual(bundles, sorted(bundles))

    def test_bundle_kind(self):
        self.assertEqual(cmd_catalog._bundle_kind("virtual-forgejo"), "vm")
        self.assertEqual(cmd_catalog._bundle_kind("alloy"), "container")

    def test_list_bundles_includes_vm_base(self):
        self.assertIn("vm-base", cmd_catalog.list_bundles())

    def test_bundle_kind_vm_base(self):
        self.assertEqual(cmd_catalog._bundle_kind("vm-base"), "vm")


class TestSetField(unittest.TestCase):
    def test_replace_existing(self):
        out = cmd_catalog._set_workload_field(
            '[workload]\nname = "old"\n', "name", '"new"')
        self.assertIn('name = "new"', out)
        self.assertNotIn('"old"', out)

    def test_insert_new_field(self):
        out = cmd_catalog._set_workload_field(
            '[workload]\nname = "x"\n\n[container]\nimage = "y"\n', "bundle", '"b"')
        data = tomllib.loads(out)
        self.assertEqual(data["workload"]["bundle"], "b")
        self.assertEqual(data["container"]["image"], "y")  # other section intact

    def test_scoped_to_workload_section(self):
        # a same-named key in another section must not be touched
        src = '[workload]\nname = "x"\n\n[other]\nname = "keep"\n'
        out = cmd_catalog._set_workload_field(src, "name", '"new"')
        data = tomllib.loads(out)
        self.assertEqual(data["workload"]["name"], "new")
        self.assertEqual(data["other"]["name"], "keep")


class TestInit(CatalogTestBase):
    def test_init_same_name_no_bundle_field(self):
        cmd_catalog.cmd_init(_ns(bundle="alloy", as_name=None), self.manager)
        data = self._read("alloy")
        self.assertEqual(data["workload"]["name"], "alloy")
        self.assertNotIn("bundle", data["workload"])  # defaults to name

    def test_init_as_pins_bundle(self):
        cmd_catalog.cmd_init(_ns(bundle="alloy", as_name="alloy-two"), self.manager)
        data = self._read("alloy-two")
        self.assertEqual(data["workload"]["name"], "alloy-two")
        self.assertEqual(data["workload"]["bundle"], "alloy")

    def test_init_missing_bundle_exits(self):
        with self.assertRaises(SystemExit):
            cmd_catalog.cmd_init(_ns(bundle="nope-xyz", as_name=None), self.manager)

    def test_init_duplicate_name_exits(self):
        cmd_catalog.cmd_init(_ns(bundle="alloy", as_name=None), self.manager)
        with self.assertRaises(SystemExit):
            cmd_catalog.cmd_init(_ns(bundle="alloy", as_name=None), self.manager)

    def test_init_invalid_bundle_name_exits(self):
        # A bundle name that isn't NAME_PATTERN-clean is rejected up front,
        # before it's ever turned into a /usr path.
        with self.assertRaises(SystemExit):
            cmd_catalog.cmd_init(_ns(bundle="../etc/evil", as_name="x"), self.manager)


class TestInitScratch(CatalogTestBase):
    def test_scratch_writes_stub_with_interpolated_name(self):
        cmd_catalog.cmd_init(_ns(scratch="coolapp", bundle=None, as_name=None), self.manager)
        dst = self.tmp / "coolapp" / "workload.toml"
        self.assertTrue(dst.exists())
        data = tomllib.loads(dst.read_text())
        self.assertEqual(data["workload"]["name"], "coolapp")
        self.assertNotIn("bundle", data["workload"])
        self.assertEqual(data["container"]["image"], "CHANGE_ME")
        self.assertEqual(data["container"]["pull"], "newer")

    def test_scratch_name_is_interpolated_not_literal(self):
        # Use a distinct name so a hardcoded "myapp" or "{name}" stub is caught.
        cmd_catalog.cmd_init(_ns(scratch="myrealapp", bundle=None, as_name=None), self.manager)
        text = (self.tmp / "myrealapp" / "workload.toml").read_text()
        self.assertIn('name = "myrealapp"', text)
        self.assertNotIn('"myapp"', text)
        self.assertNotIn('"{name}"', text)

    def test_scratch_and_bundle_positional_rejected(self):
        with self.assertRaises(SystemExit):
            cmd_catalog.cmd_init(
                _ns(scratch="coolapp", bundle="alloy", as_name=None), self.manager)

    def test_scratch_and_bundle_rejection_message_contains_mutually(self):
        import io
        buf = io.StringIO()
        with self.assertRaises(SystemExit):
            with mock.patch("sys.stderr", buf):
                cmd_catalog.cmd_init(
                    _ns(scratch="coolapp", bundle="alloy", as_name=None), self.manager)
        self.assertIn("mutually", buf.getvalue())

    def test_scratch_duplicate_name_exits(self):
        cmd_catalog.cmd_init(_ns(scratch="coolapp", bundle=None, as_name=None), self.manager)
        with self.assertRaises(SystemExit):
            cmd_catalog.cmd_init(
                _ns(scratch="coolapp", bundle=None, as_name=None), self.manager)


class TestInitScratchVM(CatalogTestBase):
    def test_scratch_vm_writes_workload_toml_with_vm_table(self):
        """workload.toml is written with a [vm] table and ships disabled."""
        cmd_catalog.cmd_init(
            _ns(scratch_vm="myvm", bundle=None, scratch=None, as_name=None), self.manager)
        dst = self.tmp / "myvm" / "workload.toml"
        self.assertTrue(dst.exists())
        data = tomllib.loads(dst.read_text())
        self.assertEqual(data["workload"]["name"], "myvm")
        # Absence of a .enabled marker means the scaffolded VM starts disabled.
        self.assertNotIn("enabled", data["workload"])
        self.assertFalse((self.tmp / "myvm" / ".enabled").exists())
        self.assertIn("vm", data)

    def test_scratch_vm_user_data_file_is_relative(self):
        """vm.cloud_init.user_data_file must be the relative path 'cloud-init/user-data'."""
        cmd_catalog.cmd_init(
            _ns(scratch_vm="myvm", bundle=None, scratch=None, as_name=None), self.manager)
        data = tomllib.loads((self.tmp / "myvm" / "workload.toml").read_text())
        self.assertEqual(data["vm"]["cloud_init"]["user_data_file"], "cloud-init/user-data")

    def test_scratch_vm_writes_cloud_init_user_data(self):
        """cloud-init/user-data is written with #cloud-config header and required placeholders."""
        cmd_catalog.cmd_init(
            _ns(scratch_vm="myvm", bundle=None, scratch=None, as_name=None), self.manager)
        ud = self.tmp / "myvm" / "cloud-init" / "user-data"
        self.assertTrue(ud.exists())
        text = ud.read_text()
        self.assertTrue(text.startswith("#cloud-config"))
        self.assertIn("${WORKLOADCTL_SSH_KEY}", text)
        self.assertIn("${WORKLOADCTL_WORKLOAD_NAME}", text)

    def test_scratch_vm_and_bundle_rejected(self):
        """scratch_vm and bundle positional are mutually exclusive -> SystemExit."""
        with self.assertRaises(SystemExit):
            cmd_catalog.cmd_init(
                _ns(scratch_vm="a", bundle="alloy", scratch=None, as_name=None), self.manager)

    def test_scratch_vm_and_bundle_rejection_message_contains_mutually(self):
        """The mutual-exclusion error message contains 'mutually'."""
        buf = io.StringIO()
        with self.assertRaises(SystemExit):
            with mock.patch("sys.stderr", buf):
                cmd_catalog.cmd_init(
                    _ns(scratch_vm="a", bundle="alloy", scratch=None, as_name=None), self.manager)
        self.assertIn("mutually", buf.getvalue())

    def test_scratch_vm_and_scratch_rejected(self):
        """scratch_vm and --scratch together are mutually exclusive -> SystemExit."""
        with self.assertRaises(SystemExit):
            cmd_catalog.cmd_init(
                _ns(scratch_vm="a", scratch="b", bundle=None, as_name=None), self.manager)

    def test_scratch_vm_invalid_name_rejected(self):
        """An invalid workload name ('bad/name') raises SystemExit before writing anything."""
        with self.assertRaises(SystemExit):
            cmd_catalog.cmd_init(
                _ns(scratch_vm="bad/name", bundle=None, scratch=None, as_name=None), self.manager)
        # Nothing should have been created under the tmp dir for this name.
        self.assertFalse((self.tmp / "bad").exists())

    def test_scratch_vm_duplicate_name_exits(self):
        """Stamping the same scratch_vm name twice raises SystemExit on the second call."""
        cmd_catalog.cmd_init(
            _ns(scratch_vm="myvm", bundle=None, scratch=None, as_name=None), self.manager)
        with self.assertRaises(SystemExit):
            cmd_catalog.cmd_init(
                _ns(scratch_vm="myvm", bundle=None, scratch=None, as_name=None), self.manager)


class TestVmBaseBundle(CatalogTestBase):
    """Checks on the shipped vm-base bundle in workloads/."""

    def test_vm_base_workload_toml_user_data_file_is_absolute(self):
        """vm-base/workload.toml must carry the absolute /usr/share/... user_data_file."""
        data = tomllib.loads((REPO_BUNDLES / "vm-base" / "workload.toml").read_text())
        expected = "/usr/share/workloadctl/workloads/vm-base/cloud-init/user-data"
        self.assertEqual(data["vm"]["cloud_init"]["user_data_file"], expected)

    def test_vm_base_cloud_init_user_data_matches_constant(self):
        """workloads/vm-base/cloud-init/user-data must be byte-identical to _SCRATCH_VM_USER_DATA."""
        shipped = (REPO_BUNDLES / "vm-base" / "cloud-init" / "user-data").read_text()
        self.assertEqual(shipped, cmd_catalog._SCRATCH_VM_USER_DATA)


class TestDuplicate(CatalogTestBase):
    def test_duplicate_resolves_bundle_to_source_name(self):
        cmd_catalog.cmd_init(_ns(bundle="alloy", as_name=None), self.manager)
        cmd_catalog.cmd_duplicate(_ns(source="alloy", new="alloy-b"), self.manager)
        data = self._read("alloy-b")
        self.assertEqual(data["workload"]["name"], "alloy-b")
        self.assertEqual(data["workload"]["bundle"], "alloy")

    def test_duplicate_of_duplicate_keeps_original_bundle(self):
        # alloy-two has bundle=alloy; duplicating it must keep bundle=alloy,
        # NOT point at alloy-two (which has no /usr bundle dir).
        cmd_catalog.cmd_init(_ns(bundle="alloy", as_name="alloy-two"), self.manager)
        cmd_catalog.cmd_duplicate(_ns(source="alloy-two", new="alloy-three"), self.manager)
        data = self._read("alloy-three")
        self.assertEqual(data["workload"]["bundle"], "alloy")

    def test_duplicate_missing_source_exits(self):
        with self.assertRaises(SystemExit):
            cmd_catalog.cmd_duplicate(_ns(source="ghost", new="x"), self.manager)

    def test_duplicate_lints_published_ports(self):
        # squid publishes host port 3128; duplicating should warn about it.
        cmd_catalog.cmd_init(_ns(bundle="squid", as_name=None), self.manager)
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_catalog.cmd_duplicate(_ns(source="squid", new="squid-b"), self.manager)
        self.assertIn("host port", buf.getvalue())

    def test_duplicate_multi_container_no_crash_and_lints_image(self):
        # Regression: a pod/bridge workload has no top-level [container], so the
        # image-sharing lint's `cfg.image` lookup KeyError'd ('container') and
        # crashed duplicate *after* writing the copy. webproxy-demo is bridge
        # mode (two [[containers]]); duplicating it must not crash, and since the
        # copy shares both images with its source the lint should still fire.
        cmd_catalog.cmd_init(_ns(bundle="webproxy-demo", as_name=None), self.manager)
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_catalog.cmd_duplicate(
                _ns(source="webproxy-demo", new="webproxy-b"), self.manager)
        out = buf.getvalue()
        # The copy was written …
        self.assertTrue((self.tmp / "webproxy-b" / "workload.toml").exists())
        # … and the multi-container image lint named the source as a co-user.
        self.assertIn("image", out.lower())
        self.assertIn("webproxy-demo", out)

    def test_duplicate_lints_shared_secrets(self):
        # A verbatim copy still references the same name-keyed credential as its
        # source; the lint should surface it (rotate-one-without-the-other).
        (self.tmp / "withsec").mkdir(exist_ok=True)
        (self.tmp / "withsec" / "workload.toml").write_text(
            '[workload]\nname = "withsec"\nbundle = "alloy"\n'
            '[container]\nimage = "localhost/x:latest"\n'
            '[container.environment]\nTOKEN = "${SECRET:api-key}"\n')
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_catalog.cmd_duplicate(_ns(source="withsec", new="withsec-b"), self.manager)
        out = buf.getvalue()
        self.assertIn("secret", out.lower())
        self.assertIn("api-key", out)


class TestInstall(CatalogTestBase):
    def _make_src(self, name: str, dir_name: str | None = None) -> Path:
        """Write a minimal workload dir with the given [workload].name."""
        src_name = dir_name or name
        src = Path(self.enterContext(__import__("tempfile").TemporaryDirectory())) / src_name
        src.mkdir()
        (src / "workload.toml").write_text(
            f'[workload]\nname = "{name}"\n'
            '[container]\nimage = "docker.io/library/hello-world:latest"\npull = "newer"\n'
        )
        return src

    def test_install_copies_to_name_derived_destination(self):
        src = self._make_src("myapp")
        cmd_catalog.cmd_install(_ns(src=str(src)), self.manager)
        dst = self.tmp / "myapp" / "workload.toml"
        self.assertTrue(dst.exists())
        data = self._read("myapp")
        self.assertEqual(data["workload"]["name"], "myapp")

    def test_install_destination_derived_from_toml_name_not_dir_name(self):
        # Source directory is called "somedir" but workload.toml declares name = "theapp".
        src = self._make_src("theapp", dir_name="somedir")
        cmd_catalog.cmd_install(_ns(src=str(src)), self.manager)
        # Should install under "theapp", not "somedir".
        self.assertTrue((self.tmp / "theapp" / "workload.toml").exists())
        self.assertFalse((self.tmp / "somedir").exists())

    def test_install_duplicate_name_exits(self):
        src = self._make_src("myapp")
        cmd_catalog.cmd_install(_ns(src=str(src)), self.manager)
        with self.assertRaises(SystemExit):
            cmd_catalog.cmd_install(_ns(src=str(src)), self.manager)

    def test_install_missing_toml_exits(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SystemExit):
                cmd_catalog.cmd_install(_ns(src=d), self.manager)

    def test_install_invalid_toml_exits(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            Path(d, "workload.toml").write_text("not valid toml ][")
            with self.assertRaises(SystemExit):
                cmd_catalog.cmd_install(_ns(src=d), self.manager)

    def test_install_copies_extra_files_and_preserves_mode(self):
        import stat
        src = self._make_src("withfiles")
        setup = src / "setup.sh"
        setup.write_text("#!/bin/sh\necho hi\n")
        setup.chmod(0o755)
        cmd_catalog.cmd_install(_ns(src=str(src)), self.manager)
        dst_setup = self.tmp / "withfiles" / "setup.sh"
        self.assertTrue(dst_setup.exists())
        self.assertTrue(dst_setup.stat().st_mode & stat.S_IXUSR)

    def test_install_excludes_git_and_pycache(self):
        src = self._make_src("cleanapp")
        (src / ".git").mkdir()
        (src / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        (src / "__pycache__").mkdir()
        cmd_catalog.cmd_install(_ns(src=str(src)), self.manager)
        dst = self.tmp / "cleanapp"
        self.assertFalse((dst / ".git").exists())
        self.assertFalse((dst / "__pycache__").exists())


class CatalogListTest(CatalogTestBase):
    """The `catalog` lister itself (cmd_catalog) — text + json + empty."""

    def test_text_lists_real_bundles_with_kind(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_catalog.cmd_catalog(_ns(json=False), self.manager)
        out = buf.getvalue()
        self.assertIn("Available bundles", out)
        self.assertIn("alloy", out)
        self.assertIn("container", out)              # alloy's kind
        self.assertIn("virtual-forgejo", out)
        self.assertIn("vm", out)                     # the forge bundle's kind

    def test_json_emits_bundle_kind_records(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_catalog.cmd_catalog(_ns(json=True), self.manager)
        by_name = {r["bundle"]: r["kind"] for r in json.loads(buf.getvalue())}
        self.assertEqual(by_name.get("alloy"), "container")
        self.assertEqual(by_name.get("virtual-forgejo"), "vm")

    def test_empty_dir_reports_none(self):
        with mock.patch.object(cmd_catalog, "BUNDLES_DIR", self.tmp / "empty"):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cmd_catalog.cmd_catalog(_ns(json=False), self.manager)
            self.assertIn("No bundles found", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
