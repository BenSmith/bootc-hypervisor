#!/usr/bin/env python3
"""Unit tests for workload-vm-build-disk helpers.

The script lives in libexec/ and has a __main__ guard; load it as a module
with importlib so we can exercise the disk-rotation logic without running
the full build (which downloads/copies real qcow2 files).
"""

import hashlib
import importlib.machinery
import importlib.util
import os
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

LIB_DIR = os.path.join(os.path.dirname(__file__), '..', 'lib')
SCRIPT = os.path.join(os.path.dirname(__file__), '..', 'libexec', 'workload-vm-build-disk')


def _load_script():
    if LIB_DIR not in sys.path:
        sys.path.insert(0, LIB_DIR)
    loader = importlib.machinery.SourceFileLoader("workload_vm_build_disk", SCRIPT)
    spec = importlib.util.spec_from_loader("workload_vm_build_disk", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class TestRotateGenerations(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def _make(self, name: str, content: bytes = b"x"):
        (self.home / name).write_bytes(content)

    def _gens(self):
        return sorted(
            int(p.suffix[5:])
            for p in self.home.glob("system.qcow2.gen-*")
            if p.suffix[5:].isdigit()
        )

    def test_no_system_disk_is_noop(self):
        result = self.mod.rotate_generations(self.home, keep=2)
        self.assertIsNone(result)
        self.assertEqual(self._gens(), [])

    def test_first_rotation_creates_gen_1(self):
        self._make("system.qcow2", b"v1")
        result = self.mod.rotate_generations(self.home, keep=2)
        self.assertEqual(result, self.home / "system.qcow2.gen-1")
        self.assertEqual(self._gens(), [1])
        self.assertFalse((self.home / "system.qcow2").exists())
        self.assertEqual((self.home / "system.qcow2.gen-1").read_bytes(), b"v1")

    def test_rotation_picks_next_free_number(self):
        # Pre-existing gens 1 and 2; rotating system.qcow2 should produce gen-3.
        self._make("system.qcow2.gen-1")
        self._make("system.qcow2.gen-2")
        self._make("system.qcow2")
        result = self.mod.rotate_generations(self.home, keep=10)
        self.assertEqual(result, self.home / "system.qcow2.gen-3")
        self.assertEqual(self._gens(), [1, 2, 3])

    def test_pruning_respects_keep(self):
        # Three pre-existing gens, keep=2 → after rotating, the oldest of
        # the *pre-existing* gens should be pruned, but the just-rotated
        # gen must survive.
        for n in (1, 2, 3):
            self._make(f"system.qcow2.gen-{n}", f"old-{n}".encode())
        self._make("system.qcow2", b"current")
        result = self.mod.rotate_generations(self.home, keep=2)
        self.assertEqual(result, self.home / "system.qcow2.gen-4")
        gens = self._gens()
        # Must include the new one (4) and not have grown beyond keep+1
        # (we keep `keep` historical generations + the brand-new one as the
        # only restore point).
        self.assertIn(4, gens)
        self.assertNotIn(1, gens, "oldest gen-1 should have been pruned")

    def test_just_rotated_gen_never_pruned_even_when_keep_is_one(self):
        # Regression for the off-by-one we fixed: with keep=1 and an existing
        # gen, the newly created gen would be the only restore point if the
        # next build fails, so it must not be pruned.
        self._make("system.qcow2.gen-1", b"old")
        self._make("system.qcow2", b"current")
        result = self.mod.rotate_generations(self.home, keep=1)
        self.assertEqual(result, self.home / "system.qcow2.gen-2")
        self.assertTrue(result.exists(), "freshly rotated gen must survive pruning")

    def test_non_numeric_suffix_ignored(self):
        # A stray file like system.qcow2.gen-keep should not crash the int
        # parsing or get pruned by it.
        (self.home / "system.qcow2.gen-keep").write_bytes(b"unrelated")
        self._make("system.qcow2", b"v1")
        result = self.mod.rotate_generations(self.home, keep=2)
        self.assertEqual(result, self.home / "system.qcow2.gen-1")
        self.assertTrue((self.home / "system.qcow2.gen-keep").exists())


class TestVerifyChecksum(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()
        self.tmp = tempfile.mkdtemp()
        self.f = Path(self.tmp) / "img.qcow2"
        self.f.write_bytes(b"hello world")
        self.digest = hashlib.sha256(b"hello world").hexdigest()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_matching_checksum_passes(self):
        # Should not raise.
        self.mod.verify_checksum(self.f, f"sha256:{self.digest}")

    def test_uppercase_expected_is_normalized(self):
        self.mod.verify_checksum(self.f, f"sha256:{self.digest.upper()}")

    def test_mismatch_raises(self):
        with self.assertRaises(ValueError) as cm:
            self.mod.verify_checksum(self.f, "sha256:" + "0" * 64)
        self.assertIn("mismatch", str(cm.exception).lower())

    def test_unsupported_algorithm_raises(self):
        with self.assertRaises(ValueError) as cm:
            self.mod.verify_checksum(self.f, f"md5:{self.digest}")
        self.assertIn("sha256", str(cm.exception))


class TestLoadConfig(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_load_config_parses_toml(self):
        cfg = Path(self.tmp) / "workload.toml"
        cfg.write_bytes(b'[vm]\ncloud_image_url = "http://x/img.qcow2"\n')
        with mock.patch.object(self.mod, "workload_config_path", return_value=cfg):
            result = self.mod.load_config("demo")
        self.assertEqual(result["vm"]["cloud_image_url"], "http://x/img.qcow2")


class TestDownloadCloudImage(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp)
        self.payload = b"cloud-image-bytes"
        self.checksum = "sha256:" + hashlib.sha256(self.payload).hexdigest()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def _fake_response(self, data):
        resp = mock.MagicMock()
        resp.getheader.return_value = str(len(data))
        chunks = [data, b""]
        resp.read.side_effect = lambda n: chunks.pop(0)
        resp.__enter__.return_value = resp
        resp.__exit__.return_value = False
        return resp

    def test_cached_valid_image_is_reused(self):
        cache = self.home / ".image-cache"
        cache.mkdir(parents=True)
        (cache / "img.qcow2").write_bytes(self.payload)
        with mock.patch.object(self.mod.urllib.request, "urlopen") as urlopen:
            path = self.mod.download_cloud_image(
                "http://h/img.qcow2", self.checksum, self.home)
        urlopen.assert_not_called()
        self.assertEqual(path.name, "img.qcow2")

    def test_cached_invalid_image_is_redownloaded(self):
        cache = self.home / ".image-cache"
        cache.mkdir(parents=True)
        (cache / "img.qcow2").write_bytes(b"stale")
        with mock.patch.object(self.mod.urllib.request, "urlopen",
                               return_value=self._fake_response(self.payload)):
            path = self.mod.download_cloud_image(
                "http://h/img.qcow2", self.checksum, self.home)
        self.assertEqual(path.read_bytes(), self.payload)

    def test_fresh_download_verifies_and_saves(self):
        with mock.patch.object(self.mod.urllib.request, "urlopen",
                               return_value=self._fake_response(self.payload)):
            path = self.mod.download_cloud_image(
                "http://h/img.qcow2", self.checksum, self.home)
        self.assertTrue(path.exists())
        self.assertEqual(path.read_bytes(), self.payload)

    def test_download_error_becomes_runtimeerror(self):
        with mock.patch.object(self.mod.urllib.request, "urlopen",
                               side_effect=urllib.error.URLError("boom")):
            with self.assertRaises(RuntimeError):
                self.mod.download_cloud_image(
                    "http://h/img.qcow2", self.checksum, self.home)


class TestBuildFromSources(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp)
        self.system_disk = self.home / "system.qcow2"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_cloud_qcow2_is_reflink_copied(self):
        src = self.home / "src.qcow2"
        src.write_bytes(b"q")
        with mock.patch.object(self.mod, "download_cloud_image", return_value=src), \
             mock.patch.object(self.mod.subprocess, "run") as run:
            self.mod.build_from_cloud_image("u", "c", self.home, self.system_disk)
        self.assertIn("--reflink=auto", run.call_args[0][0])

    def test_cloud_non_qcow2_is_converted(self):
        src = self.home / "src.raw"
        src.write_bytes(b"r")
        with mock.patch.object(self.mod, "download_cloud_image", return_value=src), \
             mock.patch.object(self.mod.subprocess, "run") as run:
            self.mod.build_from_cloud_image("u", "c", self.home, self.system_disk)
        self.assertIn("qemu-img", run.call_args[0][0])
        self.assertIn("convert", run.call_args[0][0])

    def test_local_image_missing_raises(self):
        with self.assertRaises(FileNotFoundError):
            self.mod.build_from_local_image(str(self.home / "nope.qcow2"),
                                            self.system_disk)

    def test_local_image_copied(self):
        src = self.home / "local.qcow2"
        src.write_bytes(b"l")
        with mock.patch.object(self.mod.subprocess, "run") as run:
            self.mod.build_from_local_image(str(src), self.system_disk)
        self.assertIn("--reflink=auto", run.call_args[0][0])

    def test_bootc_missing_builder_raises(self):
        with mock.patch.object(self.mod.shutil, "which", return_value=None):
            with self.assertRaises(RuntimeError):
                self.mod.build_from_bootc_image("img:latest", self.home,
                                                self.system_disk)

    def test_bootc_no_output_raises(self):
        with mock.patch.object(self.mod.shutil, "which", return_value="/usr/bin/bib"), \
             mock.patch.object(self.mod.subprocess, "run",
                               return_value=mock.Mock(returncode=0)):
            with self.assertRaises(RuntimeError) as cm:
                self.mod.build_from_bootc_image("img:latest", self.home,
                                                self.system_disk)
        self.assertIn("no .qcow2", str(cm.exception))

    def test_bootc_nonzero_exit_raises(self):
        with mock.patch.object(self.mod.shutil, "which", return_value="/usr/bin/bib"), \
             mock.patch.object(self.mod.subprocess, "run",
                               return_value=mock.Mock(returncode=1)):
            with self.assertRaises(RuntimeError) as cm:
                self.mod.build_from_bootc_image("img:latest", self.home,
                                                self.system_disk)
        self.assertIn("failed", str(cm.exception).lower())

    def test_bootc_success_copies_built_qcow2(self):
        def fake_run(cmd, **kw):
            build_dir = self.home / ".bib-build" / "qcow2"
            build_dir.mkdir(parents=True, exist_ok=True)
            (build_dir / "disk.qcow2").write_bytes(b"built")
            return mock.Mock(returncode=0)

        with mock.patch.object(self.mod.shutil, "which", return_value="/usr/bin/bib"), \
             mock.patch.object(self.mod.subprocess, "run", side_effect=fake_run) as run:
            self.mod.build_from_bootc_image("img:latest", self.home,
                                            self.system_disk)
        # last run call is the cp of the built image
        self.assertIn("--reflink=auto", run.call_args[0][0])


class TestCreateDataDisk(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()
        self.tmp = tempfile.mkdtemp()
        self.data = Path(self.tmp) / "data"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_creates_when_absent(self):
        with mock.patch.object(self.mod.subprocess, "run") as run:
            self.mod.create_data_disk(self.data, "20G")
        cmd = run.call_args[0][0]
        self.assertEqual(cmd[:4], ["qemu-img", "create", "-f", "qcow2"])
        self.assertEqual(cmd[-1], "20G")

    def test_noop_when_present(self):
        self.data.mkdir(parents=True)
        (self.data / "data.qcow2").write_bytes(b"x")
        with mock.patch.object(self.mod.subprocess, "run") as run:
            self.mod.create_data_disk(self.data, "20G")
        run.assert_not_called()


class TestMain(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()
        self.tmp = tempfile.mkdtemp()
        self.state = Path(self.tmp) / "state"
        self.data = Path(self.tmp) / "data"
        self.cfg = Path(self.tmp) / "workload.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def _run_main(self, argv, toml):
        self.cfg.write_text(toml)
        patches = [
            mock.patch.object(self.mod.sys, "argv", ["build-disk"] + argv),
            mock.patch.object(self.mod, "workload_config_path", return_value=self.cfg),
            mock.patch.object(self.mod, "workload_state_dir", return_value=self.state),
            mock.patch.object(self.mod, "workload_data_dir", return_value=self.data),
        ]
        for p in patches:
            p.start()
        self.addCleanup(mock.patch.stopall)

    def test_no_args_exits(self):
        with mock.patch.object(self.mod.sys, "argv", ["build-disk"]):
            with self.assertRaises(SystemExit) as cm:
                self.mod.main()
        self.assertEqual(cm.exception.code, 1)

    def test_no_image_source_exits(self):
        self._run_main(["demo"], "[vm]\n")
        with self.assertRaises(SystemExit) as cm:
            self.mod.main()
        self.assertEqual(cm.exception.code, 1)

    def test_existing_disk_skips_build_without_update(self):
        self.state.mkdir(parents=True)
        (self.state / "system.qcow2").write_bytes(b"existing")
        self._run_main(["demo"], '[vm]\nlocal_image = "/x.qcow2"\n')
        with mock.patch.object(self.mod, "build_from_local_image") as build:
            self.mod.main()
        build.assert_not_called()

    def test_local_image_build_invoked(self):
        self._run_main(["demo"], '[vm]\nlocal_image = "/x.qcow2"\n')
        with mock.patch.object(self.mod, "build_from_local_image") as build:
            self.mod.main()
        build.assert_called_once()

    def test_build_failure_restores_generation(self):
        self.state.mkdir(parents=True)
        (self.state / "system.qcow2").write_bytes(b"current")
        self._run_main(["demo", "--update"],
                       '[vm]\nlocal_image = "/x.qcow2"\n')
        with mock.patch.object(self.mod, "build_from_local_image",
                               side_effect=RuntimeError("nope")):
            with self.assertRaises(SystemExit):
                self.mod.main()
        # rotated gen-1 restored back to system.qcow2
        self.assertTrue((self.state / "system.qcow2").exists())
        self.assertFalse((self.state / "system.qcow2.gen-1").exists())

    def test_data_disk_created_when_configured(self):
        self._run_main(["demo"],
                       '[vm]\nlocal_image = "/x.qcow2"\ndata_disk_size = "5G"\n')
        with mock.patch.object(self.mod, "build_from_local_image"), \
             mock.patch.object(self.mod, "create_data_disk") as cdd:
            self.mod.main()
        cdd.assert_called_once()


if __name__ == "__main__":
    unittest.main()
