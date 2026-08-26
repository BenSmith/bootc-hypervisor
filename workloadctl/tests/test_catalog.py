#!/usr/bin/env python3
"""Unit tests for the bundle catalog verbs: catalog, init, duplicate.

These exercise the pure identity-rewrite + resolution logic against the real
shipped bundles under ../workloads/, writing instances into a tmp /etc dir.
"""

import argparse
import io
import json
import tomllib
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


import workload_lib            # noqa: E402
import cmd_catalog            # noqa: E402
from workloadctl_core import WorkloadManager  # noqa: E402

REPO_BUNDLES = Path(__file__).resolve().parent.parent / "workloads"


def _ns(**kw):
    return argparse.Namespace(**kw)


class CatalogTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        # init/duplicate write here; WorkloadConfig/Manager read here.
        patches: list = [
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
        # "missing", not "newer": the stub teaches the house rule that no
        # workload re-pulls at service start (see
        # test_no_bundle_re_pulls_at_service_start).
        self.assertEqual(data["container"]["pull"], "missing")

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


class TestSeedsNeverSpliceRawMultilineVars(CatalogTestBase):
    """A multi-line magic var is only safe where column 0 is where it belongs.

    substitute_template is a plain textual replace: it puts the whole value in
    at the placeholder, so the placeholder's own indentation reaches the FIRST
    line of a multi-line value and nothing after it. Splice a PEM into an
    indented YAML block scalar and every line after the first lands at column
    0 -- which does not fail as a missing anchor. cloud-init cannot parse the
    document at all, so the guest loses its host key, its mounts and everything
    else the seed carried.

    That shipped in this bundle's own CA recipe (`ca_certs: trusted: - |` with
    ${WORKLOADCTL_VM_EGRESS_CA} indented under it), and the test covering it
    asserted only that "BEGIN CERTIFICATE" appeared somewhere in the rendered
    text. It did -- at column 0, in a broken document.

    THE COMMENTED RECIPES COUNT. vm-base is the documented starting point for a
    new VM workload and its CA block is commented out because the bundle is
    `egress = "open"`; an operator uncommenting it is the intended path, so a
    recipe that only works while it is a comment is the same bug.
    """

    # The vars whose value is a multi-line PEM. Their _B64 siblings are one
    # line by construction and can be nested anywhere.
    RAW_MULTILINE = ("${WORKLOADCTL_VM_EGRESS_CA}", "${WORKLOADCTL_VM_HOST_KEY}")

    def _offenders(self, text):
        """(line number, line) for every raw splice at a non-zero column.

        A recipe line is one that ENDS with the placeholder -- `content: ${VAR}`
        or the placeholder alone under a block scalar. Prose that merely names
        the variable mid-sentence is not a splice and is left alone.
        """
        bad = []
        for number, line in enumerate(text.splitlines(), 1):
            # The line's own indentation is the whole question, so it is NOT
            # stripped -- only a comment marker is, and what a commented recipe
            # is indented BY is what it is indented by once uncommented.
            body = line
            if line.lstrip().startswith("#"):   # a commented recipe is a recipe
                body = line.lstrip()[1:]
                body = body[1:] if body.startswith(" ") else body
            for var in self.RAW_MULTILINE:
                if body.rstrip().endswith(var) and not body.startswith(var):
                    bad.append((number, line))
        return bad

    def test_shipped_seeds_never_indent_a_raw_pem_splice(self):
        checked = 0
        for seed in sorted(REPO_BUNDLES.glob("*/cloud-init/user-data")):
            checked += 1
            bad = self._offenders(seed.read_text())
            self.assertEqual(
                bad, [],
                f"{seed} splices a raw multi-line PEM at a non-zero column; "
                f"use the ${{...}}_B64 form, which is one line")
        self.assertGreater(checked, 0, "no shipped VM bundle seeds found")

    def test_the_scratch_seed_constant_has_the_same_property(self):
        """The catalog's copy is what `workloadctl init --scratch-vm` writes."""
        self.assertEqual(
            self._offenders(cmd_catalog._SCRATCH_VM_USER_DATA), [])

    def test_the_check_sees_the_shape_that_shipped(self):
        """The gate itself, against the exact text it was written for."""
        broken = ("ca_certs:\n  trusted:\n    - |\n"
                  "      ${WORKLOADCTL_VM_EGRESS_CA}\n")
        self.assertTrue(self._offenders(broken))
        self.assertTrue(self._offenders("#   " + broken.replace("\n", "\n#   ")))
        self.assertFalse(self._offenders("${WORKLOADCTL_VM_EGRESS_CA}\n"))
        self.assertFalse(self._offenders(
            "    content: ${WORKLOADCTL_VM_EGRESS_CA_B64}\n"))


class TestVmSeedUserIsNotDuplicated(CatalogTestBase):
    """A shipped VM seed must take its login account from [vm].user, not repeat it.

    The CLI SSHes in as [vm].user; a seed that hardcodes a different account
    leaves the VM unreachable, and nothing at build time compares the two.
    """

    def test_shipped_vm_seeds_use_the_magic_var(self):
        checked = 0
        for toml_path in sorted(REPO_BUNDLES.glob("*/workload.toml")):
            data = tomllib.loads(toml_path.read_text())
            vm = data.get("vm")
            if not vm:
                continue
            seed = toml_path.parent / "cloud-init" / "user-data"
            if not seed.exists():
                continue
            text = seed.read_text()
            if "users:" not in text:
                continue
            checked += 1
            user = vm.get("user", "workload")
            self.assertNotIn(f"- name: {user}", text,
                             f"{seed} hardcodes the [vm].user literal; use "
                             f"${{WORKLOADCTL_VM_USER}} instead")
            self.assertIn("- name: ${WORKLOADCTL_VM_USER}", text, str(seed))
        self.assertGreater(checked, 0, "no shipped VM bundle seeds found")


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


class TestWriteNewRace(unittest.TestCase):
    def test_write_new_returns_false_on_existing_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f.txt"
            self.assertTrue(cmd_catalog._write_new(p, "one"))
            self.assertFalse(cmd_catalog._write_new(p, "two"))
            self.assertEqual(p.read_text(), "one")


class TestConfigImagesHelpers(CatalogTestBase):
    def test_config_images_vm_returns_empty(self):
        from workloadctl_core import WorkloadConfig
        (self.tmp / "vmw").mkdir()
        (self.tmp / "vmw" / "workload.toml").write_text(
            '[workload]\nname = "vmw"\n[vm]\ncloud_image_url = "http://x/y.qcow2"\n'
            'cloud_image_checksum = "sha256:aa"\n')
        cfg = WorkloadConfig("vmw")
        self.assertEqual(cmd_catalog._config_images(cfg), set())

    def test_config_images_exception_returns_empty(self):
        from workloadctl_core import WorkloadConfig
        (self.tmp / "badc").mkdir()
        # [container] present but missing the required "image" key -> container_images()
        # raises KeyError internally; the helper must swallow it, not crash duplicate.
        (self.tmp / "badc" / "workload.toml").write_text(
            '[workload]\nname = "badc"\n[container]\npull = "newer"\n')
        cfg = WorkloadConfig("badc")
        self.assertEqual(cmd_catalog._config_images(cfg), set())

    def test_referenced_secrets_from_files_credential(self):
        from workloadctl_core import WorkloadConfig
        (self.tmp / "secf").mkdir()
        (self.tmp / "secf" / "workload.toml").write_text(
            '[workload]\nname = "secf"\n[container]\nimage = "x"\n'
            '[[secrets.files]]\npath = "/run/x"\ncredential = "db-pass"\n')
        cfg = WorkloadConfig("secf")
        self.assertEqual(cmd_catalog._referenced_secrets(cfg), ["db-pass"])

    def test_referenced_secrets_ignores_escaped_ref(self):
        # An escaped `$${SECRET:x}` env value is a literal, not a reference: the
        # copy lint must not claim the workload references credential x (it is
        # never loaded at boot). A real ref alongside it is still reported.
        from workloadctl_core import WorkloadConfig
        (self.tmp / "escsec").mkdir()
        (self.tmp / "escsec" / "workload.toml").write_text(
            '[workload]\nname = "escsec"\n[container]\nimage = "x"\n'
            '[container.environment]\n'
            'LIT = "$${SECRET:phantom}"\nREAL = "${SECRET:used}"\n')
        cfg = WorkloadConfig("escsec")
        self.assertEqual(cmd_catalog._referenced_secrets(cfg), ["used"])


class TestSetFieldNoSection(unittest.TestCase):
    def test_appends_workload_section_when_absent(self):
        out = cmd_catalog._set_workload_field('[container]\nimage = "y"\n', "name", '"new"')
        data = tomllib.loads(out)
        self.assertEqual(data["workload"]["name"], "new")
        self.assertEqual(data["container"]["image"], "y")

    def test_appends_workload_section_no_trailing_newline(self):
        out = cmd_catalog._set_workload_field('[container]\nimage = "y"', "name", '"new"')
        data = tomllib.loads(out)
        self.assertEqual(data["workload"]["name"], "new")


class TestBundleKindMalformed(CatalogTestBase):
    def test_bundle_kind_unparsable_toml_returns_qmark(self):
        (self.tmp / "broken").mkdir()
        (self.tmp / "broken" / "workload.toml").write_text("not [ valid toml")
        with mock.patch.object(cmd_catalog, "BUNDLES_DIR", self.tmp):
            self.assertEqual(cmd_catalog._bundle_kind("broken"), "?")


class TestSuggestBundle(CatalogTestBase):
    def test_suggest_bundle_no_bundles_prints_nothing(self):
        with mock.patch.object(cmd_catalog, "BUNDLES_DIR", self.tmp / "empty"):
            buf = io.StringIO()
            with mock.patch("sys.stderr", buf):
                cmd_catalog._suggest_bundle("whatever")
            self.assertEqual(buf.getvalue(), "")

    def test_suggest_bundle_close_match_hint(self):
        buf = io.StringIO()
        with mock.patch("sys.stderr", buf):
            cmd_catalog._suggest_bundle("alllloy")  # close to "alloy"
        out = buf.getvalue()
        self.assertIn("did you mean", out)
        self.assertIn("available bundles", out)


class TestInitErrorPaths(CatalogTestBase):
    def test_no_bundle_no_scratch_errors(self):
        buf = io.StringIO()
        with self.assertRaises(SystemExit):
            with mock.patch("sys.stderr", buf):
                cmd_catalog.cmd_init(_ns(bundle=None, scratch=None, scratch_vm=None, as_name=None),
                                      self.manager)
        self.assertIn("no bundle specified", buf.getvalue())

    def test_invalid_as_name_exits(self):
        with self.assertRaises(SystemExit):
            cmd_catalog.cmd_init(_ns(bundle="alloy", as_name="bad/name"), self.manager)

    def test_scratch_invalid_name_exits(self):
        with self.assertRaises(SystemExit):
            cmd_catalog.cmd_init(_ns(scratch="bad/name", bundle=None, as_name=None), self.manager)

    def test_scratch_write_race_exits(self):
        # dst.parent didn't exist at check time but _write_new still reports
        # a collision (TOCTOU) -> must still error out cleanly.
        with mock.patch.object(cmd_catalog, "_write_new", return_value=False):
            with self.assertRaises(SystemExit):
                cmd_catalog.cmd_init(_ns(scratch="racer", bundle=None, as_name=None), self.manager)

    def test_scratch_vm_write_race_exits(self):
        with mock.patch.object(cmd_catalog, "_write_new", return_value=False):
            with self.assertRaises(SystemExit):
                cmd_catalog.cmd_init(
                    _ns(scratch_vm="racervm", bundle=None, scratch=None, as_name=None),
                    self.manager)

    def test_bundle_write_race_exits(self):
        with mock.patch.object(cmd_catalog, "_write_new", return_value=False):
            with self.assertRaises(SystemExit):
                cmd_catalog.cmd_init(_ns(bundle="alloy", as_name=None), self.manager)


class TestDuplicateErrorPaths(CatalogTestBase):
    def test_invalid_source_name_exits(self):
        with self.assertRaises(SystemExit):
            cmd_catalog.cmd_duplicate(_ns(source="bad/name", new="x"), self.manager)

    def test_invalid_new_name_exits(self):
        cmd_catalog.cmd_init(_ns(bundle="alloy", as_name=None), self.manager)
        with self.assertRaises(SystemExit):
            cmd_catalog.cmd_duplicate(_ns(source="alloy", new="bad/name"), self.manager)

    def test_new_name_already_exists_exits(self):
        cmd_catalog.cmd_init(_ns(bundle="alloy", as_name=None), self.manager)
        cmd_catalog.cmd_init(_ns(bundle="alloy", as_name="alloy2"), self.manager)
        with self.assertRaises(SystemExit):
            cmd_catalog.cmd_duplicate(_ns(source="alloy", new="alloy2"), self.manager)

    def test_write_race_exits(self):
        cmd_catalog.cmd_init(_ns(bundle="alloy", as_name=None), self.manager)
        with mock.patch.object(cmd_catalog, "_write_new", return_value=False):
            with self.assertRaises(SystemExit):
                cmd_catalog.cmd_duplicate(_ns(source="alloy", new="alloy-b"), self.manager)

    def test_workloadconfig_load_failure_falls_back_to_raw_toml(self):
        # Source workload.toml with no [workload].bundle and a shape that makes
        # WorkloadConfig(src_name) raise (missing required container image) ->
        # cmd_duplicate must fall back to a raw tomllib parse and default the
        # bundle to the source's own name.
        (self.tmp / "raw").mkdir()
        # name != dir name -> WorkloadConfig("raw") raises ValueError in its
        # constructor, forcing cmd_duplicate's raw-tomllib fallback path.
        (self.tmp / "raw" / "workload.toml").write_text(
            '[workload]\nname = "mismatch"\n[container]\nimage = "x"\n')
        cmd_catalog.cmd_duplicate(_ns(source="raw", new="raw-b"), self.manager)
        data = self._read("raw-b")
        self.assertEqual(data["workload"]["bundle"], "raw")


class TestLintDuplicateUnreadable(CatalogTestBase):
    def test_lint_swallows_unreadable_config(self):
        # WorkloadConfig(name) raising inside _lint_duplicate must not propagate;
        # it should just skip the lint silently.
        with mock.patch("cmd_catalog.WorkloadConfig", side_effect=RuntimeError("boom")):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cmd_catalog._lint_duplicate("whatever", self.manager)
            self.assertEqual(buf.getvalue(), "")


class TestPostWriteReportValidateFailure(CatalogTestBase):
    def test_validate_exception_is_reported_not_raised(self):
        with mock.patch("cmd_catalog.WorkloadConfig", side_effect=RuntimeError("nope")):
            buf = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(io.StringIO()):
                cmd_catalog._post_write_report("whatever", self.manager, "created")
            self.assertIn("could not validate yet", buf.getvalue())


class TestInstallErrorPaths(CatalogTestBase):
    def test_missing_name_field_exits(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            Path(d, "workload.toml").write_text('[workload]\n[container]\nimage = "x"\n')
            with self.assertRaises(SystemExit):
                cmd_catalog.cmd_install(_ns(src=d), self.manager)

    def test_invalid_name_field_exits(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            Path(d, "workload.toml").write_text('[workload]\nname = "bad/name"\n')
            with self.assertRaises(SystemExit):
                cmd_catalog.cmd_install(_ns(src=d), self.manager)


if __name__ == "__main__":
    unittest.main()
