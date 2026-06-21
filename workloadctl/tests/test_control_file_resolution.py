#!/usr/bin/env python3
"""Regression guard for WorkloadConfig control-file override resolution (Step 3, A).

Control files (build.sh, setup.sh, policy.cil, …) resolve through a lazy-override
chain: an operator override at /etc/workloads.d/<name>/<file> wins over the
shipped /usr bundle default, mirroring systemd's /usr→/etc drop-in idiom. The
override is keyed on the workload *name*, the shipped default on its *bundle*, so
a duplicate overrides independently of its source. Absolute paths bypass both.

This is the single chokepoint every control-file lookup (enable/recreate/validate
build.sh, [host].setup, SELinux policy.cil) now goes through.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import workloadctl_core as core  # noqa: E402


class TestControlFileResolution(unittest.TestCase):
    def setUp(self):
        # Temp /etc (configs + overrides) and temp /usr (shipped bundles).
        self.etc = Path(tempfile.mkdtemp())
        self.usr = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.etc, ignore_errors=True))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.usr, ignore_errors=True))
        # bundle_dir reads the WORKLOAD_BUNDLES_DIR imported into core's namespace;
        # override_dir reads core.WORKLOAD_DIR via _get_workload_dir().
        self._p1 = mock.patch.object(core, "WORKLOAD_BUNDLES_DIR", self.usr)
        self._p2 = mock.patch.object(core, "WORKLOAD_DIR", self.etc)
        self._p1.start(); self._p2.start()
        self.addCleanup(self._p1.stop); self.addCleanup(self._p2.stop)

    def _config(self, name: str, bundle: str | None = None, *, extra: str = "") -> "core.WorkloadConfig":
        body = (
            "[workload]\n"
            f'name = "{name}"\n'
            "enabled = false\n"
        )
        if bundle is not None:
            body += f'bundle = "{bundle}"\n'
        body += '\n[container]\nimage = "localhost/x:latest"\n' + extra
        (self.etc / f"{name}.toml").write_text(body)
        return core.WorkloadConfig(name)

    def _ship(self, bundle: str, fname: str, content: str = "shipped"):
        d = self.usr / bundle
        d.mkdir(parents=True, exist_ok=True)
        (d / fname).write_text(content)

    def _override(self, name: str, fname: str, content: str = "override"):
        d = self.etc / name
        d.mkdir(parents=True, exist_ok=True)
        (d / fname).write_text(content)

    # --- bundle_dir / override_dir -----------------------------------------

    def test_bundle_dir_defaults_to_name(self):
        cfg = self._config("solo")
        self.assertEqual(cfg.bundle_dir, self.usr / "solo")

    def test_bundle_dir_uses_explicit_bundle(self):
        cfg = self._config("copy", bundle="src-bundle")
        self.assertEqual(cfg.bundle_dir, self.usr / "src-bundle")

    def test_override_dir_keyed_on_name_not_bundle(self):
        cfg = self._config("copy", bundle="src-bundle")
        self.assertEqual(cfg.override_dir, self.etc / "copy")

    # --- bundle_dir validates before pathing (the single chokepoint) --------

    def test_bundle_dir_rejects_traversal(self):
        # A bad bundle must not construct a path that escapes the bundles tree —
        # bundle_dir is the one place the field becomes a path, so it validates.
        cfg = self._config("evil", bundle="../../etc/evil")
        # Construction stays lenient (validate/info can inspect it) ...
        self.assertEqual(cfg.bundle, "../../etc/evil")
        # ... but turning it into a path is rejected.
        with self.assertRaises(ValueError):
            _ = cfg.bundle_dir

    def test_bundle_dir_underscore_hint(self):
        cfg = self._config("typo", bundle="vncdesktop_wayfire")
        with self.assertRaises(ValueError) as ctx:
            _ = cfg.bundle_dir
        self.assertIn("vncdesktop-wayfire", str(ctx.exception))

    def test_resolve_control_file_inherits_bundle_validation(self):
        # Resolution builds bundle_dir / relpath, so a bad bundle is caught here
        # too — closing the build / [host].setup paths that used to be unguarded.
        cfg = self._config("evil", bundle="../x")
        with self.assertRaises(ValueError):
            cfg.resolve_control_file("build.sh")

    # --- resolution chain ---------------------------------------------------

    def test_resolves_to_usr_when_no_override(self):
        self._ship("solo", "build.sh")
        cfg = self._config("solo")
        path, source = cfg.resolve_control_file_with_source("build.sh")
        self.assertEqual(path, self.usr / "solo" / "build.sh")
        self.assertEqual(source, "usr")

    def test_override_wins_over_shipped(self):
        self._ship("solo", "policy.cil")
        self._override("solo", "policy.cil")
        cfg = self._config("solo")
        path, source = cfg.resolve_control_file_with_source("policy.cil")
        self.assertEqual(path, self.etc / "solo" / "policy.cil")
        self.assertEqual(source, "etc")
        self.assertEqual(path.read_text(), "override")

    def test_copy_overrides_independently_of_source_bundle(self):
        # An override for the duplicate must NOT be picked up from the source
        # bundle's name, and the shipped default still resolves under `bundle`.
        self._ship("src-bundle", "build.sh", "from-bundle")
        self._override("copy", "build.sh", "copys-own")
        cfg = self._config("copy", bundle="src-bundle")
        path, source = cfg.resolve_control_file_with_source("build.sh")
        self.assertEqual(path, self.etc / "copy" / "build.sh")
        self.assertEqual(source, "etc")
        # A sibling that shares the bundle but has no override falls through to
        # the one shipped default — bundle-keyed, not name-keyed.
        sib = self._config("sibling", bundle="src-bundle")
        spath, ssource = sib.resolve_control_file_with_source("build.sh")
        self.assertEqual(spath, self.usr / "src-bundle" / "build.sh")
        self.assertEqual(ssource, "usr")

    def test_absolute_path_bypasses_resolution(self):
        cfg = self._config("solo")
        path, source = cfg.resolve_control_file_with_source("/opt/custom/setup.sh")
        self.assertEqual(path, Path("/opt/custom/setup.sh"))
        self.assertEqual(source, "usr")

    def test_missing_file_returns_usr_path_unchecked(self):
        # The /usr leg does not require the file to exist (callers .exists()-check
        # themselves and print build/copy hints); resolution must not depend on it.
        cfg = self._config("solo")
        path, source = cfg.resolve_control_file_with_source("build.sh")
        self.assertEqual(path, self.usr / "solo" / "build.sh")
        self.assertEqual(source, "usr")
        self.assertFalse(path.exists())

    def test_resolve_control_file_returns_path_only(self):
        self._ship("solo", "build.sh")
        cfg = self._config("solo")
        self.assertEqual(cfg.resolve_control_file("build.sh"), cfg.bundle_dir / "build.sh")

    def test_traversal_relpath_rejected(self):
        # A control-file relpath becomes a path that's read+executed as root
        # (Containerfile, [build].script, [host].setup). The single chokepoint
        # must reject '..' so a `[build] containerfile = "../../etc/x"` (or a
        # traversal-laden [host].setup) can't redirect resolution out of the
        # bundle/override trees — the relpath analogue of the bundle_dir guard.
        cfg = self._config("solo")
        for bad in ("../escape", "sub/../../escape", "../../etc/passwd"):
            with self.assertRaises(ValueError):
                cfg.resolve_control_file(bad)
            with self.assertRaises(ValueError):
                cfg.resolve_control_file_with_source(bad)

    def test_absolute_path_still_allowed_after_traversal_guard(self):
        # The guard rejects '..' but must not break the documented absolute-path
        # escape hatch (a fully-qualified setup/script path).
        cfg = self._config("solo")
        path, source = cfg.resolve_control_file_with_source("/opt/x/setup.sh")
        self.assertEqual(path, Path("/opt/x/setup.sh"))
        self.assertEqual(source, "usr")


if __name__ == "__main__":
    unittest.main()
