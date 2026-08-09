#!/usr/bin/env python3
"""Unit tests for workload-vm-build-disk helpers.

The script lives in libexec/ and has a __main__ guard; load_script() imports it
as a module so we can exercise the disk-rotation logic without running the full
build (which downloads/copies real qcow2 files).
"""

import email.message
import hashlib
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from tests import load_script


def _load_script():
    return load_script("libexec/workload-vm-build-disk")


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

    def _fake_response(self, data, content_length=...):
        """A stand-in for urlopen()'s result.

        `headers` is a real email.message.Message, and the mock is spec'd, so a
        call to an accessor the object does not actually have (notably
        HTTPResponse.getheader, which addinfourl lacks) fails here instead of
        being rubber-stamped by MagicMock and only surfacing on a real
        file:// URL.
        """
        headers = email.message.Message()
        if content_length is ...:
            content_length = str(len(data))
        if content_length is not None:
            headers["Content-Length"] = content_length

        class _Resp:
            def __init__(self):
                self.headers = headers
                self._chunks = [data, b""]

            def read(self, n):
                return self._chunks.pop(0)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        return _Resp()

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

    def test_missing_content_length_still_downloads(self):
        """No Content-Length just means no progress percentage."""
        with mock.patch.object(self.mod.urllib.request, "urlopen",
                               return_value=self._fake_response(
                                   self.payload, content_length=None)):
            path = self.mod.download_cloud_image(
                "http://h/img.qcow2", self.checksum, self.home)
        self.assertEqual(path.read_bytes(), self.payload)

    def test_malformed_content_length_still_downloads(self):
        """A junk header must not abort a download that is otherwise fine."""
        with mock.patch.object(self.mod.urllib.request, "urlopen",
                               return_value=self._fake_response(
                                   self.payload, content_length="not-a-number")):
            path = self.mod.download_cloud_image(
                "http://h/img.qcow2", self.checksum, self.home)
        self.assertEqual(path.read_bytes(), self.payload)


class TestDownloadCloudImageFileURL(unittest.TestCase):
    """file:// end to end, with urlopen NOT mocked.

    urlopen returns an addinfourl for file://, not an HTTPResponse, and the two
    do not share the same header API. Every other test in this file substitutes
    the response, so only a real fetch pins that difference down; the original
    bug (resp.getheader -> AttributeError on the wrapped BufferedReader) passed
    the mocked suite and failed on the first real local URL.
    """

    def setUp(self):
        self.mod = _load_script()
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp) / "home"
        self.home.mkdir()
        self.payload = b"local-cloud-image-bytes"
        self.checksum = "sha256:" + hashlib.sha256(self.payload).hexdigest()
        self.src = Path(self.tmp) / "img.qcow2"
        self.src.write_bytes(self.payload)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_file_url_downloads_and_verifies(self):
        path = self.mod.download_cloud_image(
            self.src.as_uri(), self.checksum, self.home)
        self.assertEqual(path.read_bytes(), self.payload)
        self.assertEqual(path, self.home / ".image-cache" / "img.qcow2")

    def test_file_url_checksum_mismatch_is_rejected(self):
        bad = "sha256:" + hashlib.sha256(b"different").hexdigest()
        with self.assertRaises(ValueError):
            self.mod.download_cloud_image(self.src.as_uri(), bad, self.home)

    def test_missing_file_url_becomes_runtimeerror(self):
        missing = (Path(self.tmp) / "absent.qcow2").as_uri()
        with self.assertRaises(RuntimeError):
            self.mod.download_cloud_image(missing, self.checksum, self.home)

    def test_no_tempfile_left_behind_after_failure(self):
        missing = (Path(self.tmp) / "absent.qcow2").as_uri()
        with self.assertRaises(RuntimeError):
            self.mod.download_cloud_image(missing, self.checksum, self.home)
        leftovers = list((self.home / ".image-cache").glob("*.tmp"))
        self.assertEqual(leftovers, [])


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

    def test_cloud_vmdk_converted_with_detected_format(self):
        src = self.home / "src.vmdk"
        src.write_bytes(b"v")

        def fake_run(cmd, **kw):
            if cmd[:2] == ["qemu-img", "info"]:
                return mock.Mock(stdout='{"format": "vmdk"}', returncode=0)
            return mock.Mock(returncode=0)

        with mock.patch.object(self.mod, "download_cloud_image", return_value=src), \
             mock.patch.object(self.mod.subprocess, "run", side_effect=fake_run) as run:
            self.mod.build_from_cloud_image("u", "c", self.home, self.system_disk)

        convert_calls = [c for c in run.call_args_list if c.args[0][1] == "convert"]
        self.assertEqual(len(convert_calls), 1)
        argv = convert_calls[0].args[0]
        # Must not hardcode -f raw for a vmdk source; the probed format
        # ("vmdk") should be used instead.
        self.assertNotIn("raw", argv)
        self.assertIn("vmdk", argv)
        self.assertIn("-O", argv)
        self.assertIn("qcow2", argv)

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
