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
            mock.patch.object(cmd_catalog, "WORKLOAD_DIR", self.tmp),
            mock.patch.object(workloadctl_core, "WORKLOAD_DIR", self.tmp),
            mock.patch.object(cmd_catalog, "require_root", lambda: None),
        ]
        for p in patches:
            self.enterContext(p)
        self.manager = WorkloadManager()

    def _read(self, name):
        return tomllib.loads((self.tmp / f"{name}.toml").read_text())


class TestDiscovery(CatalogTestBase):
    def test_list_bundles_includes_known(self):
        bundles = cmd_catalog.list_bundles()
        self.assertIn("alloy", bundles)
        self.assertIn("virtual-forgejo", bundles)
        self.assertEqual(bundles, sorted(bundles))

    def test_bundle_kind(self):
        self.assertEqual(cmd_catalog._bundle_kind("virtual-forgejo"), "vm")
        self.assertEqual(cmd_catalog._bundle_kind("alloy"), "container")


class TestSetField(unittest.TestCase):
    def test_replace_existing(self):
        out = cmd_catalog._set_workload_field(
            '[workload]\nname = "old"\nenabled = false\n', "name", '"new"')
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
        self.assertTrue((self.tmp / "webproxy-b.toml").exists())
        # … and the multi-container image lint named the source as a co-user.
        self.assertIn("image", out.lower())
        self.assertIn("webproxy-demo", out)

    def test_duplicate_lints_shared_secrets(self):
        # A verbatim copy still references the same name-keyed credential as its
        # source; the lint should surface it (rotate-one-without-the-other).
        (self.tmp / "withsec.toml").write_text(
            '[workload]\nname = "withsec"\nbundle = "alloy"\nenabled = false\n'
            '[container]\nimage = "localhost/x:latest"\n'
            '[container.environment]\nTOKEN = "${SECRET:api-key}"\n')
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_catalog.cmd_duplicate(_ns(source="withsec", new="withsec-b"), self.manager)
        out = buf.getvalue()
        self.assertIn("secret", out.lower())
        self.assertIn("api-key", out)


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
