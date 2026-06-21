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
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

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
        self.enterContext(mock.patch.object(cmd_backup, "WORKLOAD_DIR", self.etc))
        self.enterContext(mock.patch.object(
            cmd_backup, "workload_data_dir", lambda n: self.var / n / "data"))

    def _restore(self, archive: Path):
        args = argparse.Namespace(archive=str(archive), force=True, enable=False)
        return cmd_backup.cmd_restore(args, manager=None)

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
        # Nothing escaped the sandbox: no stray .toml written above WORKLOAD_DIR.
        self.assertEqual(list(self.etc.glob("*.toml")), [])
        self.assertFalse((self.tmp / "etc" / "cron.d").exists())

    def test_empty_name_rejected(self):
        archive = _make_archive(
            Path(tempfile.mkdtemp(dir=self.tmp)), '[workload]\n')
        with self.assertRaises(SystemExit) as cm:
            self._restore(archive)
        self.assertNotEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
