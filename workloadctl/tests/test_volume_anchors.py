#!/usr/bin/env python3
"""Regression guard: volume anchor expansion is correct and no raw anchors leak
into generated unit files.

Two jobs:
1. Unit-level fast assertions on expand_volume_path for all anchor forms.
2. Generator-level scan: run the generator over all workload TOMLs and assert
   that no --volume or --drive host path still carries a relative anchor prefix.
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GENERATOR = ROOT / "generators" / "workload-generate"
LIB_DIR = ROOT / "lib"
WORKLOADS_DIR = ROOT / "workloads"

sys.path.insert(0, str(LIB_DIR))
from workload_lib import expand_volume_path, workload_state_dir  # noqa: E402


class TestExpandVolumePathAnchors(unittest.TestCase):
    """Unit-level regression guard for all anchor forms."""

    def setUp(self):
        self.home = str(workload_state_dir("foo"))  # /var/lib/workloads/foo/state

    def test_dot_slash_data_maps_into_data(self):
        # ./X is sugar for data/X, so ./data resolves to a 'data' subdir of the
        # data anchor (no special-casing of the literal name 'data').
        result = expand_volume_path("./data:/app/data", self.home)
        self.assertEqual(result, "/var/lib/workloads/foo/data/data:/app/data")

    def test_dot_slash_subdir_maps_into_data(self):
        result = expand_volume_path("./conf:/etc/conf:ro", self.home)
        self.assertEqual(result, "/var/lib/workloads/foo/data/conf:/etc/conf:ro")

    def test_dot_slash_bare_no_container_path(self):
        result = expand_volume_path("./data", self.home)
        self.assertEqual(result, "/var/lib/workloads/foo/data/data")

    def test_dot_slash_subdir_no_container_path(self):
        result = expand_volume_path("./d", self.home)
        self.assertEqual(result, "/var/lib/workloads/foo/data/d")

    def test_at_slash_anchor(self):
        result = expand_volume_path("@/cache:/c", self.home)
        self.assertEqual(result, "/var/lib/workloads/foo/state/volumes/cache:/c")

    def test_data_anchor(self):
        result = expand_volume_path("data/x:/x", self.home)
        self.assertEqual(result, "/var/lib/workloads/foo/data/x:/x")

    def test_state_anchor(self):
        result = expand_volume_path("state/x:/x", self.home)
        self.assertEqual(result, "/var/lib/workloads/foo/state/volumes/x:/x")

    def test_absolute_path_unchanged(self):
        result = expand_volume_path("/srv/data:/app/data", self.home)
        self.assertEqual(result, "/srv/data:/app/data")

    def test_absolute_no_container_path_unchanged(self):
        result = expand_volume_path("/srv/data", self.home)
        self.assertEqual(result, "/srv/data")

    def test_opts_with_colon_preserved(self):
        result = expand_volume_path("./d:/g:ro:context=x", self.home)
        self.assertEqual(result, "/var/lib/workloads/foo/data/d:/g:ro:context=x")

    def test_traversal_rejected(self):
        with self.assertRaises(ValueError):
            expand_volume_path("./../escape:/x", self.home)


# Anchors that must never appear as the host-path segment of an emitted unit.
_RAW_ANCHOR_PREFIXES = ("./", "@/", "data/", "state/")

# Match --volume TOKEN where TOKEN is the next whitespace-delimited argument.
_VOLUME_RE = re.compile(r'--volume\s+(\S+)')
# Match --drive file=PATH or if=pflash,... where file= or if= is the first key.
_DRIVE_RE = re.compile(r'--drive\s+\S*file=([^,\s]+)')


def _volume_and_disk_host_paths(unit_text: str):
    """Yield every host-path token from --volume and --drive lines in a unit."""
    for m in _VOLUME_RE.finditer(unit_text):
        token = m.group(1).strip('"')
        yield token.split(":", 2)[0]
    for m in _DRIVE_RE.finditer(unit_text):
        yield m.group(1)


def _enable_toml(src: Path, dst: Path):
    """Copy a shipped workload TOML into the test config dir and enable it by
    creating the `.enabled` marker beside it."""
    dst.write_text(src.read_text())
    (dst.parent / ".enabled").touch()


class TestNoRawAnchorsInGeneratedUnits(unittest.TestCase):
    """Run the generator over all workloads and verify no anchor leaks through."""

    def test_no_unexpanded_anchors_in_service_files(self):
        tomls = sorted(WORKLOADS_DIR.glob("*/workload.toml"))
        self.assertGreater(len(tomls), 0, "no workload TOMLs found")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            cfg = tmp_path / "cfg"
            svc = tmp_path / "svc"
            sys_d = tmp_path / "sys"
            cfg.mkdir()
            svc.mkdir()
            sys_d.mkdir()

            for src in tomls:
                name = src.parent.name
                (cfg / name).mkdir(exist_ok=True)
                _enable_toml(src, cfg / name / "workload.toml")

            env = os.environ.copy()
            env["WORKLOAD_CONFIG_DIR"] = str(cfg)
            env["SYSUSERS_DIR"] = str(sys_d)
            env["PYTHONPATH"] = str(LIB_DIR)
            env["WORKLOAD_GPU_OVERRIDE"] = "nvidia"

            r = subprocess.run(
                [sys.executable, str(GENERATOR), str(svc)],
                capture_output=True, text=True, env=env,
            )
            self.assertEqual(r.returncode, 0, r.stderr)

            for unit_path in sorted(svc.glob("*.service")):
                unit_text = unit_path.read_text()
                unit_name = unit_path.name
                for token_host in _volume_and_disk_host_paths(unit_text):
                    self.assertFalse(
                        token_host.startswith(_RAW_ANCHOR_PREFIXES),
                        f"unexpanded anchor {token_host!r} reached an ExecStart in {unit_name}",
                    )


class TestRequiredFilesAnchorResolution(unittest.TestCase):
    """get_required_files() must resolve workload-relative anchors through the
    SAME logic as volume mounts, so a precious './config.json' required-file lands
    where its volume actually mounts it (data/, not state/).

    Guards the regression that the unit-scan above CANNOT catch: required_files
    are consumed in CLI preflight (auto-copy + existence check), never emitted into
    a unit's ExecStart, so a divergence here is invisible to TestNoRawAnchors.
    """

    def _config_with(self, toml_text: str):
        import workload_lib
        import workloadctl_core as core
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        (tmp / "wltest").mkdir()
        (tmp / "wltest" / "workload.toml").write_text(toml_text)
        with mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", tmp):
            return core.WorkloadConfig("wltest")

    def test_required_file_resolves_to_data_not_state(self):
        config = self._config_with(
            '[workload]\n'
            'name = "wltest"\n'
            '[container]\n'
            'image = "localhost/x:latest"\n\n'
            '[setup]\n'
            'required_files = [\n'
            '  { path = "./config.json", hint = "/usr/share/x/config.json" },\n'
            ']\n\n'
            '[storage]\n'
            'volumes = ["./config.json:/etc/x/config.json:ro"]\n'
        )
        rf = config.get_required_files()
        self.assertEqual(len(rf), 1)
        resolved = rf[0]["path"]

        # Must land in the data anchor, never under state/ (the $HOME / graphroot).
        self.assertEqual(resolved, "/var/lib/workloads/wltest/data/config.json")
        self.assertNotIn("/state/", resolved)

        # And must be byte-identical to where the matching volume actually mounts
        # from — the whole point: preflight checks/copies the same path the
        # container reads.
        home = str(workload_state_dir("wltest"))
        vol_host = expand_volume_path("./config.json:/etc/x/config.json:ro", home).split(":", 1)[0]
        self.assertEqual(resolved, vol_host)

    def test_absolute_required_file_unchanged(self):
        config = self._config_with(
            '[workload]\n'
            'name = "wltest"\n'
            '[container]\n'
            'image = "localhost/x:latest"\n\n'
            '[setup]\n'
            'required_files = [\n'
            '  { path = "/etc/credstore/foo", hint = "" },\n'
            ']\n'
        )
        rf = config.get_required_files()
        self.assertEqual(rf[0]["path"], "/etc/credstore/foo")


class TestPreflightDataAnchoring(unittest.TestCase):
    """enable's preflight must treat the data/ sibling as part of the workload's
    own tree. Regression (state/data split): the auto-copy + auto-create guards
    anchored on home_dir (= state/), so every `./`-anchored required_file and
    volume dir (which resolve to data/) was wrongly judged "outside the workload"
    — silently skipping the copy and refusing to create the dir. Anchor on the
    workload ROOT, which spans both state/ and data/.
    """

    def _run_preflight(self, base, toml_text):
        import workload_lib
        import workloadctl_core as core
        sys.path.insert(0, str(LIB_DIR))
        import cmd_lifecycle
        toml_dir = base / "tomls"
        toml_dir.mkdir(exist_ok=True)
        (toml_dir / "wltest").mkdir(exist_ok=True)
        (toml_dir / "wltest" / "workload.toml").write_text(toml_text)
        with mock.patch.object(workload_lib, "WORKLOADS_BASE", base), \
             mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", toml_dir):
            config = core.WorkloadConfig("wltest")
            cmd_lifecycle._preflight_checks(config)

    def test_required_file_autocopied_and_data_dir_autocreated(self):
        import shutil as _shutil
        base = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: _shutil.rmtree(base, ignore_errors=True))
        ext = Path(tempfile.mkdtemp())  # writable, OUTSIDE the workload root
        self.addCleanup(lambda: _shutil.rmtree(ext, ignore_errors=True))

        hint = base / "hint-config.json"
        hint.write_text("HINT-CONTENT")
        ext_src = ext / "ext-bind"  # absolute external bind source

        self._run_preflight(base,
            '[workload]\n'
            'name = "wltest"\n'
            '[container]\n'
            'image = "docker.io/x:latest"\n'
            'pull = "missing"\n\n'
            '[setup]\n'
            'required_files = [\n'
            f'  {{ path = "./config.json", hint = "{hint}" }},\n'
            ']\n\n'
            '[storage]\n'
            'volumes = [\n'
            '  "./config.json:/etc/x/config.json:ro",\n'
            '  "./registry:/var/lib/registry",\n'
            f'  "{ext_src}:/ext",\n'
            ']\n'
        )

        # required_file auto-copied from its hint into data/ (not state/)
        dest = base / "wltest" / "data" / "config.json"
        self.assertTrue(dest.exists(), "required_file was not auto-copied into data/")
        self.assertEqual(dest.read_text(), "HINT-CONTENT")

        # `./` volume directory auto-created under data/
        self.assertTrue((base / "wltest" / "data" / "registry").is_dir(),
                        "./ volume dir was not auto-created under data/")

        # a genuinely external bind source is NOT auto-created — operator provides it
        self.assertFalse(ext_src.exists(),
                         "external bind source must stay operator-provisioned")


if __name__ == "__main__":
    unittest.main()
