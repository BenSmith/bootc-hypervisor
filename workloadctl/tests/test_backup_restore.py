#!/usr/bin/env python3
"""Security regression for `workloadctl restore`.

A backup archive is the one restore input that crosses a trust boundary — it is
portable and may have been authored on another host. Its embedded workload name
flows straight into root-owned destination paths (config + data dir, written via
copy2/rmtree/copytree as root), so restore MUST validate that name before
building any path. The backup side goes through WorkloadConfig (which enforces
name == filename + validate_workload_name); restore parses raw tomllib, so the
check has to be repeated there or a crafted name like "../../etc/cron.d/x"
escapes the workloads tree.
"""
import argparse
import io
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import workload_lib  # noqa: E402
import cmd_backup  # noqa: E402


def _make_archive(dest: Path, toml_text: str) -> Path:
    """Build a minimal tar.zst restore archive containing just workload.toml."""
    stage = dest / "stage"
    stage.mkdir()
    (stage / "workload.toml").write_text(toml_text)
    archive = dest / "backup.tar.zst"
    subprocess.run(
        ["tar", "-C", str(stage), "--zstd", "-cf", str(archive), "workload.toml"],
        check=True,
    )
    return archive


class TestRestoreNameValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.etc = self.tmp / "etc"
        self.etc.mkdir()
        self.var = self.tmp / "var"
        self.var.mkdir()
        self.enterContext(mock.patch.object(cmd_backup, "require_root", lambda: None))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.etc))
        self.enterContext(mock.patch.object(
            cmd_backup, "workload_data_dir", lambda n: self.var / n / "data"))

    def _restore(self, archive: Path):
        args = argparse.Namespace(archive=str(archive), force=True, enable=False)
        # restore rejects bad names before it ever touches the manager, so the
        # tests deliberately pass None rather than constructing a real one.
        return cmd_backup.cmd_restore(args, manager=None)  # type: ignore[arg-type]

    def test_traversal_name_rejected(self):
        # A name with path separators / .. must be refused before any dest path
        # is constructed, so root never writes outside WORKLOAD_DIR / the
        # workloads tree.
        for bad in ("../../etc/cron.d/pwn", "../escape", "a/b", "_wl-x"):
            archive = _make_archive(
                Path(tempfile.mkdtemp(dir=self.tmp)),
                f'[workload]\nname = "{bad}"\n',
            )
            with self.assertRaises(SystemExit) as cm:
                self._restore(archive)
            self.assertNotEqual(cm.exception.code, 0)
        # Nothing escaped the sandbox: no stray workload.toml written above WORKLOAD_DIR.
        self.assertEqual(list(self.etc.glob("*/workload.toml")), [])
        self.assertFalse((self.tmp / "etc" / "cron.d").exists())

    def test_empty_name_rejected(self):
        archive = _make_archive(
            Path(tempfile.mkdtemp(dir=self.tmp)), '[workload]\n')
        with self.assertRaises(SystemExit) as cm:
            self._restore(archive)
        self.assertNotEqual(cm.exception.code, 0)


class TestAssertNoEscapingSymlinks(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def test_plain_tree_ok(self):
        (self.root / "sub").mkdir()
        (self.root / "sub" / "f").write_text("x")
        cmd_backup._assert_no_escaping_symlinks(self.root)  # no raise

    def test_in_tree_relative_symlink_ok(self):
        (self.root / "real").write_text("x")
        (self.root / "link").symlink_to("real")
        cmd_backup._assert_no_escaping_symlinks(self.root)  # no raise

    def test_absolute_escaping_symlink_rejected(self):
        (self.root / "bad").symlink_to("/etc")
        with self.assertRaises(ValueError):
            cmd_backup._assert_no_escaping_symlinks(self.root)

    def test_relative_escaping_symlink_rejected(self):
        (self.root / "bad").symlink_to("../../etc")
        with self.assertRaises(ValueError):
            cmd_backup._assert_no_escaping_symlinks(self.root)


class TestBackupOne(unittest.TestCase):
    def _config(self, name="app"):
        c = mock.Mock()
        c.name = name
        return c

    def test_returns_substrate_capture_size(self):
        sub = mock.Mock()
        sub.capture.return_value = 4242
        with mock.patch.object(cmd_backup, "get_substrate", return_value=sub):
            n = cmd_backup._backup_one(self._config(), Path("/out.tar.zst"),
                                       "crash", quiet=True)
        self.assertEqual(n, 4242)

    def test_backup_error_propagates(self):
        sub = mock.Mock()
        sub.capture.side_effect = cmd_backup.BackupError("qmp down")
        with mock.patch.object(cmd_backup, "get_substrate", return_value=sub):
            with self.assertRaises(cmd_backup.BackupError):
                cmd_backup._backup_one(self._config(), Path("/o"), "crash")

    def test_oserror_normalized_to_backup_error(self):
        sub = mock.Mock()
        sub.capture.side_effect = OSError("disk full")
        with mock.patch.object(cmd_backup, "get_substrate", return_value=sub):
            with self.assertRaises(cmd_backup.BackupError) as cm:
                cmd_backup._backup_one(self._config(), Path("/o"), "crash")
        self.assertIn("app", str(cm.exception))


class TestCmdBackup(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.object(cmd_backup, "require_root", lambda: None))
        self.manager = mock.Mock()

    def _args(self, **kw):
        base = dict(all=False, workload=None, output=None,
                    consistency="crash", json=False)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_all_with_no_workloads_prints_and_returns(self):
        self.manager.get_all_configs.return_value = []
        import io
        from contextlib import redirect_stdout
        out = io.StringIO()
        with redirect_stdout(out):
            cmd_backup.cmd_backup(self._args(all=True), self.manager)
        self.assertIn("No workloads found", out.getvalue())

    def test_single_without_name_errors(self):
        with self.assertRaises(SystemExit) as cm:
            cmd_backup.cmd_backup(self._args(workload=None), self.manager)
        self.assertEqual(cm.exception.code, 1)

    def test_json_success_reports_backups(self):
        import io
        import json
        from contextlib import redirect_stdout
        cfg = mock.Mock()
        cfg.name = "app"
        with mock.patch.object(cmd_backup, "WorkloadConfig", return_value=cfg), \
             mock.patch.object(cmd_backup, "_backup_one", return_value=999):
            out = io.StringIO()
            with redirect_stdout(out):
                cmd_backup.cmd_backup(self._args(workload="app", json=True),
                                      self.manager)
        data = json.loads(out.getvalue())
        self.assertEqual(data["backups"][0]["size_bytes"], 999)

    def test_failed_workload_exits_nonzero(self):
        import io
        from contextlib import redirect_stdout, redirect_stderr
        cfg = mock.Mock()
        cfg.name = "app"
        with mock.patch.object(cmd_backup, "WorkloadConfig", return_value=cfg), \
             mock.patch.object(cmd_backup, "_backup_one",
                               side_effect=cmd_backup.BackupError("nope")):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as cm:
                    cmd_backup.cmd_backup(self._args(workload="app"), self.manager)
        self.assertEqual(cm.exception.code, 1)


class TestRestoreFlow(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.etc = self.tmp / "etc"
        self.etc.mkdir()
        self.var = self.tmp / "var"
        self.var.mkdir()
        self.enterContext(mock.patch.object(cmd_backup, "require_root", lambda: None))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.etc))
        self.enterContext(mock.patch.object(
            cmd_backup, "workload_data_dir", lambda n: self.var / n / "data"))
        # systemctl stop / any subprocess other than tar → no-op mock, but tar
        # must run for real to extract the archive. Route by argv[0].
        real_run = subprocess.run

        def fake_run(cmd, *a, **kw):
            if cmd and cmd[0] == "tar":
                return real_run(cmd, *a, **kw)
            return mock.Mock(returncode=0, stdout="", stderr="")
        self.enterContext(mock.patch.object(cmd_backup.subprocess, "run",
                                            side_effect=fake_run))

    def _args(self, archive, **kw):
        base = dict(archive=str(archive), force=False, enable=False)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_missing_archive_errors(self):
        with self.assertRaises(SystemExit) as cm:
            cmd_backup.cmd_restore(self._args(self.tmp / "nope.tar.zst"),
                                   manager=None)
        self.assertEqual(cm.exception.code, 1)

    def test_archive_without_toml_errors(self):
        stage = self.tmp / "s1"
        stage.mkdir()
        (stage / "other.txt").write_text("x")
        archive = self.tmp / "a1.tar.zst"
        subprocess.run(["tar", "-C", str(stage), "--zstd", "-cf",
                        str(archive), "other.txt"], check=True)
        with self.assertRaises(SystemExit):
            cmd_backup.cmd_restore(self._args(archive), manager=None)

    def test_successful_restore_writes_config(self):
        import io
        from contextlib import redirect_stdout
        archive = _make_archive(Path(tempfile.mkdtemp(dir=self.tmp)),
                                '[workload]\nname = "goodapp"\n')
        with redirect_stdout(io.StringIO()):
            cmd_backup.cmd_restore(self._args(archive), manager=None)
        self.assertTrue((self.etc / "goodapp" / "workload.toml").exists())

    def test_existing_config_without_force_errors(self):
        (self.etc / "goodapp").mkdir()
        archive = _make_archive(Path(tempfile.mkdtemp(dir=self.tmp)),
                                '[workload]\nname = "goodapp"\n')
        with self.assertRaises(SystemExit) as cm:
            cmd_backup.cmd_restore(self._args(archive), manager=None)
        self.assertEqual(cm.exception.code, 1)


class TestCmdBackupAllMode(unittest.TestCase):
    """Cover --all output-dir validation, per-workload archive naming, and
    the --all summary/failure printing paths (lines 89-93, 101-106, 127,
    130-132)."""

    def setUp(self):
        self.enterContext(mock.patch.object(cmd_backup, "require_root", lambda: None))
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.manager = mock.Mock()

    def _args(self, **kw):
        base = dict(all=False, workload=None, output=None,
                    consistency="crash", json=False)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_all_output_must_be_directory_not_file(self):
        # --output pointing at an existing plain file is rejected before any
        # workload is touched, since --all fans out one archive per workload.
        clash = self.tmp / "notadir"
        clash.write_text("x")
        cfg = mock.Mock()
        cfg.name = "app"
        self.manager.get_all_configs.return_value = [cfg]
        import io
        from contextlib import redirect_stderr
        with redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(SystemExit) as cm:
                cmd_backup.cmd_backup(self._args(all=True, output=str(clash)),
                                      self.manager)
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("must be a directory", err.getvalue())

    def test_all_output_directory_is_used_for_each_archive(self):
        out_dir = self.tmp / "backups"
        cfg1 = mock.Mock()
        cfg1.name = "app1"
        cfg2 = mock.Mock()
        cfg2.name = "app2"
        self.manager.get_all_configs.return_value = [cfg1, cfg2]
        seen_outputs = []

        def fake_backup_one(config, output, consistency, quiet=False):
            seen_outputs.append(output)
            return 111

        import io
        from contextlib import redirect_stdout
        with mock.patch.object(cmd_backup, "_backup_one", side_effect=fake_backup_one):
            with redirect_stdout(io.StringIO()) as out:
                cmd_backup.cmd_backup(self._args(all=True, output=str(out_dir)),
                                      self.manager)
        self.assertEqual(len(seen_outputs), 2)
        for o in seen_outputs:
            self.assertEqual(o.parent, out_dir)
        self.assertIn("Backed up 2 workload(s)", out.getvalue())

    def test_single_output_is_existing_directory_appends_filename(self):
        # args.output points at an existing directory (not --all): the code
        # must append "<name>-<timestamp>.tar.zst" rather than treating the
        # dir itself as the archive path.
        out_dir = self.tmp / "somedir"
        out_dir.mkdir()
        cfg = mock.Mock()
        cfg.name = "app"
        seen = {}

        def fake_backup_one(config, output, consistency, quiet=False):
            seen["output"] = output
            return 5

        with mock.patch.object(cmd_backup, "WorkloadConfig", return_value=cfg), \
             mock.patch.object(cmd_backup, "_backup_one", side_effect=fake_backup_one):
            import io
            from contextlib import redirect_stdout
            with redirect_stdout(io.StringIO()):
                cmd_backup.cmd_backup(
                    self._args(workload="app", output=str(out_dir)), self.manager)
        self.assertEqual(seen["output"].parent, out_dir)
        self.assertTrue(seen["output"].name.startswith("app-"))
        self.assertTrue(seen["output"].name.endswith(".tar.zst"))

    def test_all_mode_partial_failure_reports_and_exits_nonzero(self):
        cfg1 = mock.Mock()
        cfg1.name = "good"
        cfg2 = mock.Mock()
        cfg2.name = "bad"
        self.manager.get_all_configs.return_value = [cfg1, cfg2]

        def fake_backup_one(config, output, consistency, quiet=False):
            if config.name == "bad":
                raise cmd_backup.BackupError("qmp unreachable")
            return 10

        import io
        from contextlib import redirect_stdout, redirect_stderr
        with mock.patch.object(cmd_backup, "_backup_one", side_effect=fake_backup_one):
            with redirect_stdout(io.StringIO()) as out, \
                 redirect_stderr(io.StringIO()) as err:
                with self.assertRaises(SystemExit) as cm:
                    cmd_backup.cmd_backup(self._args(all=True), self.manager)
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("Backed up 1 workload(s)", out.getvalue())
        self.assertIn("Failed to back up 1 workload(s)", err.getvalue())
        self.assertIn("bad", err.getvalue())

    def test_json_mode_reports_failed_list(self):
        cfg = mock.Mock()
        cfg.name = "bad"
        import io
        import json
        from contextlib import redirect_stdout
        with mock.patch.object(cmd_backup, "WorkloadConfig", return_value=cfg), \
             mock.patch.object(cmd_backup, "_backup_one",
                               side_effect=cmd_backup.BackupError("nope")):
            out = io.StringIO()
            with redirect_stdout(out):
                with self.assertRaises(SystemExit):
                    cmd_backup.cmd_backup(self._args(workload="bad", json=True),
                                          self.manager)
        data = json.loads(out.getvalue())
        self.assertEqual(data["failed"][0]["workload"], "bad")
        self.assertEqual(data["backups"], [])


class TestRestoreCredentialsAndDataFlow(unittest.TestCase):
    """Cover credential restore (236-245), data-tree restore incl. force
    rmtree/merge (253-265), TPM warning (276-280), and --enable (284-285)."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.etc = self.tmp / "etc"
        self.etc.mkdir()
        self.var = self.tmp / "var"
        self.var.mkdir()
        self.credstore = self.tmp / "credstore"
        self.enterContext(mock.patch.object(cmd_backup, "require_root", lambda: None))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.etc))
        self.enterContext(mock.patch.object(
            cmd_backup, "workload_data_dir", lambda n: self.var / n / "data"))
        self.enterContext(mock.patch.object(cmd_backup, "CREDSTORE_DIR", self.credstore))

        real_run = subprocess.run
        self.launched = []

        def fake_run(cmd, *a, **kw):
            self.launched.append(cmd)
            if cmd and cmd[0] == "tar":
                return real_run(cmd, *a, **kw)
            return mock.Mock(returncode=0, stdout="", stderr="")
        self.enterContext(mock.patch.object(cmd_backup.subprocess, "run",
                                            side_effect=fake_run))

    def _args(self, archive, **kw):
        base = dict(archive=str(archive), force=False, enable=False)
        base.update(kw)
        return argparse.Namespace(**base)

    def _make_full_archive(self, dest: Path, name="goodapp",
                            cred_files=None, data_files=None):
        stage = dest / "stage"
        stage.mkdir()
        (stage / "workload.toml").write_text(f'[workload]\nname = "{name}"\n')
        members = ["workload.toml"]
        if cred_files:
            cdir = stage / "credentials"
            cdir.mkdir()
            for fname, content in cred_files.items():
                (cdir / fname).write_text(content)
            members.append("credentials")
        if data_files:
            ddir = stage / "data"
            ddir.mkdir()
            for relpath, content in data_files.items():
                p = ddir / relpath
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content)
            members.append("data")
        archive = dest / "backup.tar.zst"
        subprocess.run(
            ["tar", "-C", str(stage), "--zstd", "-cf", str(archive), *members],
            check=True,
        )
        return archive

    def test_credentials_restored_and_tpm_warning_printed(self):
        archive = self._make_full_archive(
            Path(tempfile.mkdtemp(dir=self.tmp)),
            cred_files={"mycred": "sekret"})
        import io
        from contextlib import redirect_stdout
        out = io.StringIO()
        with redirect_stdout(out):
            cmd_backup.cmd_restore(self._args(archive), manager=None)
        self.assertTrue((self.credstore / "mycred").exists())
        self.assertEqual((self.credstore / "mycred").read_text(), "sekret")
        self.assertIn("TPM-bound to the original machine", out.getvalue())
        self.assertIn("secret rotate mycred", out.getvalue())

    def test_existing_credential_skipped_without_force(self):
        self.credstore.mkdir(parents=True)
        (self.credstore / "mycred").write_text("original")
        archive = self._make_full_archive(
            Path(tempfile.mkdtemp(dir=self.tmp)),
            cred_files={"mycred": "new-value"})
        import io
        from contextlib import redirect_stdout
        out = io.StringIO()
        with redirect_stdout(out):
            cmd_backup.cmd_restore(self._args(archive), manager=None)
        self.assertEqual((self.credstore / "mycred").read_text(), "original")
        self.assertIn("already exists, skipping", out.getvalue())
        # No TPM warning since nothing was actually restored.
        self.assertNotIn("TPM-bound", out.getvalue())

    def test_existing_credential_overwritten_with_force(self):
        self.credstore.mkdir(parents=True)
        (self.credstore / "mycred").write_text("original")
        archive = self._make_full_archive(
            Path(tempfile.mkdtemp(dir=self.tmp)),
            cred_files={"mycred": "new-value"})
        import io
        from contextlib import redirect_stdout
        with redirect_stdout(io.StringIO()):
            cmd_backup.cmd_restore(self._args(archive, force=True), manager=None)
        self.assertEqual((self.credstore / "mycred").read_text(), "new-value")

    def test_data_tree_restored_when_absent(self):
        archive = self._make_full_archive(
            Path(tempfile.mkdtemp(dir=self.tmp)),
            data_files={"file1.txt": "hello", "sub/file2.txt": "world"})
        import io
        from contextlib import redirect_stdout
        with redirect_stdout(io.StringIO()):
            cmd_backup.cmd_restore(self._args(archive), manager=None)
        dest_data = self.var / "goodapp" / "data"
        self.assertEqual((dest_data / "file1.txt").read_text(), "hello")
        self.assertEqual((dest_data / "sub" / "file2.txt").read_text(), "world")

    def test_data_tree_merges_without_force_when_exists(self):
        dest_data = self.var / "goodapp" / "data"
        dest_data.mkdir(parents=True)
        (dest_data / "preexisting.txt").write_text("keep-me")
        archive = self._make_full_archive(
            Path(tempfile.mkdtemp(dir=self.tmp)),
            data_files={"newfile.txt": "brand-new"})
        import io
        from contextlib import redirect_stdout
        out = io.StringIO()
        with redirect_stdout(out):
            cmd_backup.cmd_restore(self._args(archive), manager=None)
        # merge: both old and new files present, warning printed
        self.assertTrue((dest_data / "preexisting.txt").exists())
        self.assertTrue((dest_data / "newfile.txt").exists())
        self.assertIn("data/ exists, merging", out.getvalue())

    def test_data_tree_replaced_with_force_when_exists(self):
        dest_data = self.var / "goodapp" / "data"
        dest_data.mkdir(parents=True)
        (dest_data / "old.txt").write_text("stale")
        archive = self._make_full_archive(
            Path(tempfile.mkdtemp(dir=self.tmp)),
            data_files={"newfile.txt": "brand-new"})
        import io
        from contextlib import redirect_stdout
        with redirect_stdout(io.StringIO()):
            cmd_backup.cmd_restore(self._args(archive, force=True), manager=None)
        self.assertFalse((dest_data / "old.txt").exists())
        self.assertTrue((dest_data / "newfile.txt").exists())

    def test_data_tree_with_escaping_symlink_rejected_before_copy(self):
        # Build the archive by hand so we can smuggle a symlink escaping the
        # data/ tree in. tarfile's `data` filter now rejects an
        # absolute-target symlink at extraction time (before staging is even
        # fully populated); `_assert_no_escaping_symlinks` remains as the
        # defense-in-depth check for anything the filter doesn't catch (e.g.
        # a self-consistent relative symlink pointing elsewhere in the tree).
        # Either way nothing must land in dest_data.
        stage = Path(tempfile.mkdtemp(dir=self.tmp))
        (stage / "workload.toml").write_text('[workload]\nname = "goodapp"\n')
        ddir = stage / "data"
        ddir.mkdir()
        (ddir / "evil").symlink_to("/etc")
        archive = stage.parent / "evil.tar.zst"
        subprocess.run(
            ["tar", "-C", str(stage), "--zstd", "-cf", str(archive),
             "workload.toml", "data"],
            check=True,
        )
        import io
        from contextlib import redirect_stdout, redirect_stderr
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(SystemExit) as cm:
                cmd_backup.cmd_restore(self._args(archive), manager=None)
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("Error: failed to extract archive", err.getvalue())
        dest_data = self.var / "goodapp" / "data"
        self.assertFalse(dest_data.exists())

    def test_enable_flag_invokes_workloadctl_enable(self):
        archive = self._make_full_archive(Path(tempfile.mkdtemp(dir=self.tmp)))
        import io
        from contextlib import redirect_stdout
        with redirect_stdout(io.StringIO()):
            cmd_backup.cmd_restore(self._args(archive, enable=True), manager=None)
        enable_calls = [c for c in self.launched
                        if c[:2] == ["workloadctl", "enable"]]
        self.assertEqual(len(enable_calls), 1)
        self.assertEqual(enable_calls[0], ["workloadctl", "enable", "goodapp"])

    def test_no_enable_flag_prints_manual_instructions(self):
        archive = self._make_full_archive(Path(tempfile.mkdtemp(dir=self.tmp)))
        import io
        from contextlib import redirect_stdout
        out = io.StringIO()
        with redirect_stdout(out):
            cmd_backup.cmd_restore(self._args(archive, enable=False), manager=None)
        self.assertIn("sudo workloadctl enable goodapp", out.getvalue())
        enable_calls = [c for c in self.launched
                        if c[:2] == ["workloadctl", "enable"]]
        self.assertEqual(enable_calls, [])


def make_raw_tar_zst(dest: Path, member_name: str, content: bytes = b"pwn") -> Path:
    """Build a .tar.zst by hand (bypassing the `tar` CLI's own path
    sanitization) so a malicious member name reaches tarfile untouched.
    """
    raw_tar = dest / "raw.tar"
    with tarfile.open(raw_tar, mode="w") as tf:
        info = tarfile.TarInfo(name=member_name)
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
    archive = dest / "backup.tar.zst"
    with open(archive, "wb") as out:
        subprocess.run(["zstd", "-c", str(raw_tar)], stdout=out, check=True)
    return archive


@unittest.skipUnless(shutil.which("zstd"), "zstd binary not available")
class TestExtractArchiveDataFilter(unittest.TestCase):
    """`_extract_archive` extracts through tarfile's `filter="data"`, which
    must reject unsafe member shapes (absolute paths, `..` traversal) at
    extract time rather than relying on a given tar binary's defaults.
    """

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def test_absolute_path_member_is_defanged_not_honored(self):
        # The `data` filter strips a leading "/" and re-bases the member
        # under staging rather than raising (PEP 706 behavior) — confirm it
        # lands inside staging, never at the literal absolute path.
        import cmd_backup
        archive = make_raw_tar_zst(self.tmp, "/etc/pwned")
        staging = self.tmp / "staging"
        staging.mkdir()
        cmd_backup._extract_archive(archive, staging)
        self.assertTrue((staging / "etc" / "pwned").exists())
        self.assertFalse(Path("/etc/pwned").exists())

    def test_parent_traversal_member_rejected(self):
        import cmd_backup
        archive = make_raw_tar_zst(self.tmp, "../../etc/pwned")
        staging = self.tmp / "staging"
        staging.mkdir()
        with self.assertRaises(tarfile.TarError):
            cmd_backup._extract_archive(archive, staging)
        self.assertEqual(list(staging.iterdir()), [])

    def test_plain_member_extracted(self):
        import cmd_backup
        archive = make_raw_tar_zst(self.tmp, "workload.toml", b"[workload]\nname = \"ok\"\n")
        staging = self.tmp / "staging"
        staging.mkdir()
        cmd_backup._extract_archive(archive, staging)
        self.assertEqual((staging / "workload.toml").read_bytes(),
                          b"[workload]\nname = \"ok\"\n")


@unittest.skipUnless(shutil.which("zstd"), "zstd binary not available")
class TestRestoreRejectsMaliciousArchive(unittest.TestCase):
    """End-to-end: `cmd_restore` refuses a malicious archive via the tarfile
    `data` filter and reports a clean error, not a traceback.
    """

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.etc = self.tmp / "etc"
        self.etc.mkdir()
        self.var = self.tmp / "var"
        self.var.mkdir()
        import workload_lib
        import cmd_backup
        self.cmd_backup = cmd_backup
        self.enterContext(mock.patch.object(cmd_backup, "require_root", lambda: None))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.etc))
        self.enterContext(mock.patch.object(
            cmd_backup, "workload_data_dir", lambda n: self.var / n / "data"))

    def _args(self, archive, **kw):
        base = dict(archive=str(archive), force=False, enable=False)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_malicious_archive_refused_with_clean_error(self):
        # A member whose name still resolves outside the staging dir after
        # normalization (`..` traversal) is a case the `data` filter cannot
        # defang by re-basing — it must raise, and cmd_restore must turn
        # that into a clean "Error: ..." exit, not a raw traceback.
        archive = make_raw_tar_zst(self.tmp, "../../etc/cron.d/pwn")

        from contextlib import redirect_stderr, redirect_stdout
        out_buf, err_buf = io.StringIO(), io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            with self.assertRaises(SystemExit) as cm:
                self.cmd_backup.cmd_restore(self._args(archive), manager=None)
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("Error: failed to extract archive", err_buf.getvalue())
        # Nothing escaped the sandbox.
        self.assertFalse((self.etc.parent / "cron.d").exists())


if __name__ == "__main__":
    unittest.main()
