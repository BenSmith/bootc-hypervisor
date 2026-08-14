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
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


import workload_lib  # noqa: E402
import backup  # noqa: E402
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


def _lstat_faking_dev(module, fake_paths: set, fake_dev: int):
    """An `os.lstat` replacement that reports `fake_dev` for `fake_paths`.

    A real mount point needs root, so the filesystem boundary is simulated at
    the only place either guard inspects it. Everything else — the walk, the
    copytree, the tree on disk — is real. `st_dev` is index 2 of the 10-tuple
    `os.stat_result` accepts.
    """
    real_lstat = module.os.lstat

    def lstat(path, *args, **kwargs):
        st = real_lstat(path, *args, **kwargs)
        if str(path) in fake_paths:
            fields = list(st[:10])
            fields[2] = fake_dev
            return os.stat_result(tuple(fields))
        return st

    return lstat


def _route_subprocess(case):
    """tar for real, every other command a no-op, for the duration of `case`.

    cmd_restore runs `systemctl stop` before it reaches any of the guards these
    tests are about. That is fine on a developer box and fatal in CI: the image
    build compiles this RPM inside a bare `fedora:latest` container with no
    systemd, where the call raises FileNotFoundError and the test *errors*
    rather than exercising anything.

    tar has to stay real — the archive is genuinely extracted — so route on
    argv[0] rather than mocking subprocess wholesale. Note this patches the
    shared subprocess module, so archive-building calls in the tests themselves
    also come through here, which is the other reason tar cannot be stubbed.
    """
    real_run = subprocess.run

    def fake_run(cmd, *a, **kw):
        if cmd and cmd[0] == "tar":
            return real_run(cmd, *a, **kw)
        return mock.Mock(returncode=0, stdout="", stderr="")

    case.enterContext(mock.patch.object(cmd_backup.subprocess, "run",
                                        side_effect=fake_run))


class TestBackupSkipsOtherFilesystems(unittest.TestCase):
    """Capture must stop at mount points under data/.

    copytree does not stop at filesystem boundaries on its own, so a share
    mounted under data/ would otherwise be pulled wholesale into every archive
    — across the network, with the workload stopped.
    """

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.src = self.tmp / "data"
        self.src.mkdir()
        (self.src / "keep.txt").write_text("precious")
        self.mnt = self.src / "somedir"
        self.mnt.mkdir()
        (self.mnt / "on-the-share.txt").write_text("belongs to the file server")
        self.spool = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def _mountinfo(self, *points):
        path = self.spool / "mountinfo"
        path.write_text("".join(
            f"36 35 0:24 / {p} rw,relatime shared:1 - tmpfs tmpfs rw\n"
            for p in points))
        self.enterContext(mock.patch.object(workload_lib, "MOUNTINFO", path))

    def _ignore(self, fake_paths):
        self.enterContext(mock.patch.object(
            backup.os, "lstat",
            _lstat_faking_dev(backup, fake_paths, fake_dev=999)))
        return backup._ignore_mount_points(self.src, quiet=True)

    def test_same_filesystem_skips_nothing(self):
        ignore = self._ignore(set())
        self.assertEqual(ignore(str(self.src), ["keep.txt", "somedir"]), set())

    def test_entry_on_another_filesystem_is_skipped(self):
        ignore = self._ignore({str(self.mnt)})
        self.assertEqual(ignore(str(self.src), ["keep.txt", "somedir"]), {"somedir"})

    def test_copytree_omits_the_mounted_subtree_but_keeps_the_rest(self):
        # The callback has to satisfy copytree's real contract, not just look
        # right in isolation.
        dest = self.tmp / "staging"
        shutil.copytree(
            self.src, dest, symlinks=True, dirs_exist_ok=False,
            ignore=self._ignore({str(self.mnt)}),
        )
        self.assertEqual((dest / "keep.txt").read_text(), "precious")
        self.assertFalse((dest / "somedir").exists())

    def test_nested_mount_is_skipped_not_just_top_level(self):
        deep = self.src / "a" / "b"
        deep.mkdir(parents=True)
        nested = deep / "share"
        nested.mkdir()
        (nested / "f").write_text("x")
        dest = self.tmp / "staging"
        shutil.copytree(
            self.src, dest, symlinks=True, dirs_exist_ok=False,
            ignore=self._ignore({str(nested)}),
        )
        self.assertTrue((dest / "a" / "b").is_dir())
        self.assertFalse((dest / "a" / "b" / "share").exists())

    def test_symlink_to_another_filesystem_is_still_captured(self):
        # Judged by the filesystem holding the link, which is what
        # symlinks=True copies. Resolving instead would drop ordinary content.
        (self.src / "link").symlink_to("/etc/hostname")
        ignore = self._ignore(set())
        self.assertEqual(ignore(str(self.src), ["link"]), set())

    def test_a_same_device_bind_mount_is_skipped(self):
        """The blind spot. A bind of a directory on the same filesystem reports
        the same st_dev on both sides, so it looked like an ordinary
        subdirectory and went into the archive whole — while restore refuses to
        write over it, leaving the two halves disagreeing about the same path.
        No device faking here: that is the point."""
        self._mountinfo(self.mnt)
        ignore = backup._ignore_mount_points(self.src, quiet=True)
        self.assertEqual(ignore(str(self.src), ["keep.txt", "somedir"]),
                         {"somedir"})

    def test_an_ordinary_directory_on_one_device_is_still_captured(self):
        """The other half: mountinfo naming things elsewhere must not make
        every directory look like a mount."""
        self._mountinfo("/srv/media", self.src)
        ignore = backup._ignore_mount_points(self.src, quiet=True)
        self.assertEqual(ignore(str(self.src), ["keep.txt", "somedir"]), set())

    def test_a_symlink_pointing_at_a_mount_is_not_itself_a_mount(self):
        """The mountinfo test joins onto the resolved *directory*, never the
        entry, for the reason lstat is used over stat: following the link would
        drop an ordinary in-tree symlink for where it happens to point."""
        (self.src / "link").symlink_to(self.mnt)
        self._mountinfo(self.mnt)
        ignore = backup._ignore_mount_points(self.src, quiet=True)
        self.assertEqual(ignore(str(self.src), ["link"]), set())

    def test_backup_skips_exactly_what_restore_refuses(self):
        """The invariant the blind spot broke. An archive that captured a
        subtree restore will not write back is one nobody can fully restore,
        and the mismatch only shows up at restore time."""
        self._mountinfo(self.mnt)
        ignore = backup._ignore_mount_points(self.src, quiet=True)
        skipped = ignore(str(self.src), ["keep.txt", "somedir"])
        self.assertIn("somedir", skipped)
        with self.assertRaises(ValueError):
            cmd_backup._assert_no_mounts_under(self.src)

    def test_skips_are_warned_about_not_silent(self):
        ignore = self.enterContext(mock.patch.object(backup, "warn"))
        self.enterContext(mock.patch.object(
            backup.os, "lstat",
            _lstat_faking_dev(backup, {str(self.mnt)}, fake_dev=999)))
        backup._ignore_mount_points(self.src, quiet=False)(
            str(self.src), ["keep.txt", "somedir"])
        self.assertEqual(ignore.call_count, 1)
        self.assertIn("somedir", ignore.call_args[0][0])


class TestAssertNoMountsUnder(unittest.TestCase):
    """`restore --force` must refuse rather than rmtree through a mount.

    shutil.rmtree would unlink the mounted filesystem's contents and only then
    fail on the busy mount point — after the data is gone.
    """

    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.root / "sub").mkdir()
        (self.root / "sub" / "f").write_text("x")

    def _fake(self, fake_paths):
        self.enterContext(mock.patch.object(
            cmd_backup.os, "lstat",
            _lstat_faking_dev(cmd_backup, fake_paths, fake_dev=999)))

    def test_plain_tree_ok(self):
        self._fake(set())
        cmd_backup._assert_no_mounts_under(self.root)  # no raise

    def test_empty_tree_ok(self):
        self._fake(set())
        cmd_backup._assert_no_mounts_under(
            Path(self.enterContext(tempfile.TemporaryDirectory())))

    def test_mount_at_top_level_rejected(self):
        mnt = self.root / "somedir"
        mnt.mkdir()
        self._fake({str(mnt)})
        with self.assertRaises(ValueError) as cm:
            cmd_backup._assert_no_mounts_under(self.root)
        self.assertIn("somedir", str(cm.exception))

    def test_nested_mount_rejected(self):
        mnt = self.root / "sub" / "share"
        mnt.mkdir()
        self._fake({str(mnt)})
        with self.assertRaises(ValueError):
            cmd_backup._assert_no_mounts_under(self.root)

    def test_error_names_the_path_and_says_what_to_do(self):
        mnt = self.root / "somedir"
        mnt.mkdir()
        self._fake({str(mnt)})
        with self.assertRaises(ValueError) as cm:
            cmd_backup._assert_no_mounts_under(self.root)
        msg = str(cm.exception)
        self.assertIn(str(mnt), msg)
        self.assertIn("Unmount", msg)


class TestBindMountsAreCaughtToo(unittest.TestCase):
    """The case st_dev is structurally unable to see.

    `mount --bind` of a directory that lives on the same filesystem reports the
    same st_dev on both sides, so the device walk finds nothing while rmtree
    still follows it and unlinks the files at the bind *source* — somewhere
    else on that filesystem entirely. It is also the likelier of the two to
    exist, since binding a directory from the same disk needs no second disk.

    mountinfo is the list that knows, so these drive a synthetic one: the
    parser is under test as much as the check.
    """

    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.root / "sub").mkdir()
        self.spool = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def _mountinfo(self, *points):
        """A mountinfo naming `points` as mount points, and nothing else.

        Every entry claims the same device as everything else, which is the
        situation being tested: nothing in the tree looks unusual to lstat.
        """
        path = self.spool / "mountinfo"
        path.write_text("".join(
            f"36 35 0:24 / {p} rw,relatime shared:1 - tmpfs tmpfs rw\n"
            for p in points))
        self.enterContext(mock.patch.object(workload_lib, "MOUNTINFO", path))

    def test_a_same_device_bind_mount_under_the_tree_is_refused(self):
        target = self.root / "sub" / "share"
        target.mkdir()
        self._mountinfo(target)
        with self.assertRaises(ValueError) as cm:
            cmd_backup._assert_no_mounts_under(self.root)
        self.assertIn(str(target), str(cm.exception))
        self.assertIn("Unmount", str(cm.exception))

    def test_a_mount_somewhere_else_is_not_this_tree_s_problem(self):
        self._mountinfo("/srv/media", "/home", self.root.parent)
        cmd_backup._assert_no_mounts_under(self.root)  # no raise

    def test_the_data_dir_being_a_mount_itself_is_not_under_itself(self):
        """Deliberate boundary: this guard is about mounts *inside* the tree.
        An operator who put data/ on its own disk is served by the merge path
        writing into it, which is what they asked for."""
        self._mountinfo(self.root)
        cmd_backup._assert_no_mounts_under(self.root)  # no raise

    def test_a_mount_point_with_a_space_is_decoded(self):
        """mountinfo octal-escapes space, tab, newline and backslash. Left
        encoded, `/mnt/my\\040share` matches no real path and the mount is
        missed — the failure being silent is what makes it worth a test."""
        target = self.root / "my share"
        target.mkdir()
        self._mountinfo(str(target).replace(" ", r"\040"))
        with self.assertRaises(ValueError):
            cmd_backup._assert_no_mounts_under(self.root)

    def test_an_unreadable_mountinfo_falls_back_to_the_device_walk(self):
        """Degrade to the older, narrower check rather than to no check."""
        self.enterContext(mock.patch.object(
            workload_lib, "MOUNTINFO", self.spool / "does-not-exist"))
        mnt = self.root / "sub" / "elsewhere"
        mnt.mkdir()
        self.enterContext(mock.patch.object(
            cmd_backup.os, "lstat",
            _lstat_faking_dev(cmd_backup, {str(mnt)}, fake_dev=999)))
        with self.assertRaises(ValueError):
            cmd_backup._assert_no_mounts_under(self.root)


class TestForceRefusesAMountedDataDir(unittest.TestCase):
    """data/ being a mount point is the one --force cannot survive.

    rmtree empties the mounted filesystem and only then fails EBUSY on the
    mount point, so the loss is complete before anything reports a problem —
    and for a bind mount the files it empties are the bind source's, somewhere
    else entirely. The merge path is deliberately exempt: writing *into* a
    mounted data/ is what an operator with a disk there is asking for.
    """

    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.data = self.root / "data"
        self.data.mkdir()
        self.spool = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def _mountinfo(self, *points):
        path = self.spool / "mountinfo"
        path.write_text("".join(
            f"36 35 0:24 / {p} rw,relatime shared:1 - tmpfs tmpfs rw\n"
            for p in points))
        self.enterContext(mock.patch.object(workload_lib, "MOUNTINFO", path))

    def test_a_mounted_data_dir_is_refused(self):
        self._mountinfo(self.data)
        with self.assertRaises(ValueError) as cm:
            cmd_backup._assert_data_dir_is_not_a_mount(self.data)
        self.assertIn(str(self.data), str(cm.exception))

    def test_the_refusal_offers_the_merge_as_a_way_through(self):
        """An operator with a disk at data/ has somewhere to go: this is the
        one restore they cannot run, not a wall."""
        self._mountinfo(self.data)
        with self.assertRaises(ValueError) as cm:
            cmd_backup._assert_data_dir_is_not_a_mount(self.data)
        self.assertIn("--force", str(cm.exception))
        self.assertIn("Unmount", str(cm.exception))

    def test_an_ordinary_data_dir_is_fine(self):
        self._mountinfo("/srv/media", self.root)
        cmd_backup._assert_data_dir_is_not_a_mount(self.data)  # no raise

    def test_a_mount_under_it_is_not_this_check_s_business(self):
        """That is _assert_no_mounts_under, which runs on both paths. Two
        checks with two scopes; this one must not quietly take on the other's."""
        (self.data / "share").mkdir()
        self._mountinfo(self.data / "share")
        cmd_backup._assert_data_dir_is_not_a_mount(self.data)  # no raise

    def test_a_separate_disk_is_caught_without_mountinfo(self):
        """The fallback: a device that differs from the parent's is a mount.
        Narrower than mountinfo in the same way the device walk is — a
        same-device bind mount is invisible to it — but better than nothing."""
        self.enterContext(mock.patch.object(
            workload_lib, "MOUNTINFO", self.spool / "does-not-exist"))
        self.enterContext(mock.patch.object(
            cmd_backup.os, "lstat",
            _lstat_faking_dev(cmd_backup, {str(self.data)}, fake_dev=999)))
        with self.assertRaises(ValueError):
            cmd_backup._assert_data_dir_is_not_a_mount(self.data)


class TestRestoreRefusesOverMount(unittest.TestCase):
    """The guard has to actually run before the rmtree, not merely exist.

    Both restore paths cross the boundary, in different ways: --force deletes
    through the mount, and the merge writes through it. The archive here carries
    a file at the mount's own path, which is what an archive taken before the
    share was mounted looks like — the ordinary way to arrive at this.
    """

    def _restore_over_a_mount(self, *, force):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        etc, var = tmp / "etc", tmp / "var"
        etc.mkdir()
        dest_data = var / "app" / "data"
        mnt = dest_data / "somedir"
        mnt.mkdir(parents=True)
        share_file = mnt / "on-the-share.txt"
        share_file.write_text("belongs to the file server")

        self.enterContext(mock.patch.object(cmd_backup, "require_root", lambda: None))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", etc))
        self.enterContext(mock.patch.object(
            cmd_backup, "workload_data_dir", lambda n: var / n / "data"))
        self.enterContext(mock.patch.object(
            cmd_backup.os, "lstat",
            _lstat_faking_dev(cmd_backup, {str(mnt)}, fake_dev=999)))
        _route_subprocess(self)

        stage = tmp / "stage"
        (stage / "data" / "somedir").mkdir(parents=True)
        (stage / "data" / "somedir" / "on-the-share.txt").write_text(
            "from an archive that predates the mount")
        (stage / "workload.toml").write_text(
            '[workload]\nname = "app"\n[container]\nimage = "x"\n')
        archive = tmp / "backup.tar.zst"
        subprocess.run(
            ["tar", "-C", str(stage), "--zstd", "-cf", str(archive), "."],
            check=True,
        )

        args = argparse.Namespace(archive=str(archive), force=force, enable=False)
        with self.assertRaises(SystemExit) as cm:
            cmd_backup.cmd_restore(args, manager=None)  # type: ignore[arg-type]
        self.assertEqual(cm.exception.code, 1)
        return share_file

    def test_force_restore_aborts_before_deleting_anything(self):
        share_file = self._restore_over_a_mount(force=True)
        self.assertEqual(share_file.read_text(), "belongs to the file server")

    def test_a_merge_restore_aborts_before_writing_through_the_mount(self):
        """Without --force nothing is deleted, but copytree(dirs_exist_ok=True)
        would land the archive's copy on the operator's file server."""
        share_file = self._restore_over_a_mount(force=False)
        self.assertEqual(share_file.read_text(), "belongs to the file server")


class TestRestoreRefusesToForceOverAMountedDataDir(unittest.TestCase):
    """The guard reaching cmd_restore, not just existing beside it.

    Same shape as TestRestoreRefusesOverMount, one level up: here data/ *is*
    the mount rather than holding one. --force must abort with the files
    intact; the merge must go through, because that is the setup working as
    intended rather than a hazard.
    """

    def _restore(self, *, force):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        etc, var = tmp / "etc", tmp / "var"
        etc.mkdir()
        dest_data = var / "app" / "data"
        dest_data.mkdir(parents=True)
        on_the_disk = dest_data / "on-the-disk.txt"
        on_the_disk.write_text("lives on the mounted disk")

        self.enterContext(mock.patch.object(cmd_backup, "require_root", lambda: None))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", etc))
        self.enterContext(mock.patch.object(
            cmd_backup, "workload_data_dir", lambda n: var / n / "data"))
        # data/ itself is the mount point, and nothing is mounted inside it.
        mountinfo = tmp / "mountinfo"
        mountinfo.write_text(
            f"36 35 0:24 / {dest_data} rw,relatime shared:1 - tmpfs tmpfs rw\n")
        self.enterContext(mock.patch.object(workload_lib, "MOUNTINFO", mountinfo))
        _route_subprocess(self)

        stage = tmp / "stage"
        (stage / "data").mkdir(parents=True)
        (stage / "data" / "from-archive.txt").write_text("restored")
        (stage / "workload.toml").write_text(
            '[workload]\nname = "app"\n[container]\nimage = "x"\n')
        archive = tmp / "backup.tar.zst"
        subprocess.run(
            ["tar", "-C", str(stage), "--zstd", "-cf", str(archive), "."],
            check=True,
        )

        args = argparse.Namespace(archive=str(archive), force=force, enable=False)
        return args, dest_data, on_the_disk

    def test_force_aborts_with_the_disk_untouched(self):
        args, dest_data, on_the_disk = self._restore(force=True)
        with self.assertRaises(SystemExit) as cm:
            cmd_backup.cmd_restore(args, manager=None)  # type: ignore[arg-type]
        self.assertEqual(cm.exception.code, 1)
        self.assertEqual(on_the_disk.read_text(), "lives on the mounted disk")
        self.assertFalse((dest_data / "from-archive.txt").exists())

    def test_a_merge_is_still_allowed_through(self):
        """The exemption, asserted rather than assumed: refusing this too would
        break the operator who put data/ on its own disk on purpose."""
        args, dest_data, on_the_disk = self._restore(force=False)
        cmd_backup.cmd_restore(args, manager=None)  # type: ignore[arg-type]
        self.assertEqual(on_the_disk.read_text(), "lives on the mounted disk")
        self.assertEqual((dest_data / "from-archive.txt").read_text(), "restored")


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
        _route_subprocess(self)

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
