#!/usr/bin/env python3
"""Unit tests for oplog — the per-workload operations log.

The load-bearing properties, in order of how much damage getting them wrong
would do:

1. **It can never break the operation it describes.** A missing directory, a
   read-only filesystem, a permission error — all warn and continue. An update
   that worked must not report failure because a log line didn't land.
2. **It records what changed, and only what changed.** Dry-runs and reports
   leave no trace; a purge doesn't warn about the directory it just deleted.
3. **The line and the --json row are the same dict**, so the two can't drift.
"""

import io
import json
import os
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import cli_log
import oplog
import workload_lib


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name) / "var"
        self.etc = Path(self.tmp.name) / "etc"
        self.base.mkdir()
        self.etc.mkdir()
        self.enterContext(
            mock.patch.object(workload_lib, "WORKLOADS_BASE", self.base))
        self.enterContext(
            mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.etc))
        # workload_config_dir() prefers the env var over the module attr, so an
        # inherited WORKLOAD_CONFIG_DIR would silently defeat the patch above.
        self.enterContext(
            mock.patch.dict(os.environ, {}, clear=False))
        os.environ.pop("WORKLOAD_CONFIG_DIR", None)
        self.enterContext(mock.patch.object(oplog, "_warned", False))
        self.enterContext(mock.patch.dict(os.environ, {"SUDO_USER": "ben"}))
        # No login session by default, so the shared cases exercise the SUDO_USER
        # branch deterministically. The host's own audit state must not decide
        # what these tests assert.
        self.enterContext(mock.patch.object(oplog, "_login_uid", lambda: None))
        self.addCleanup(cli_log.reset)
        cli_log.reset()

    def _provision(self, name):
        (self.base / name).mkdir(parents=True)
        return self.base / name / oplog.OPLOG_NAME

    def _declare(self, name):
        """Give a workload a config but no root dir — the state every
        config-authoring verb (create/install/edit) records from."""
        cfg = self.etc / name / "workload.toml"
        cfg.parent.mkdir(parents=True)
        cfg.write_text(f'[workload]\nname = "{name}"\n')
        return self.base / name / oplog.OPLOG_NAME

    def _record(self, command, rows, ok=True):
        err = io.StringIO()
        with redirect_stderr(err):
            oplog.record(command, rows, ok=ok)
        return err.getvalue()


class RecordTest(_Base):

    def test_writes_one_json_line_per_workload(self):
        path = self._provision("web")
        self._provision("cache")
        self._record("update", [
            {"workload": "web", "result": "updated"},
            {"workload": "cache", "result": "rolled-back"},
        ])
        lines = path.read_text().splitlines()
        self.assertEqual(len(lines), 1)          # one file per workload
        entry = json.loads(lines[0])
        self.assertEqual(entry["command"], "update")
        self.assertEqual(entry["workload"], "web")
        self.assertEqual(entry["result"], "updated")
        self.assertTrue(entry["ok"])
        self.assertEqual(entry["user"], "ben")
        self.assertEqual(entry["user_source"], "sudo")
        self.assertRegex(entry["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_carries_the_whole_result_row(self):
        # The line IS the --json row plus provenance — no second format to drift.
        path = self._provision("web")
        self._record("update", [{
            "workload": "web", "kind": "container", "result": "updated",
            "verify": "healthy",
            "images": {"web": {"old": "sha256:aaa", "new": "sha256:bbb"}},
        }])
        entry = json.loads(path.read_text())
        self.assertEqual(entry["verify"], "healthy")
        self.assertEqual(entry["images"]["web"]["new"], "sha256:bbb")

    def test_appends_rather_than_truncates(self):
        path = self._provision("web")
        self._record("enable", [{"workload": "web", "result": "enabled"}])
        self._record("update", [{"workload": "web", "result": "updated"}])
        commands = [json.loads(ln)["command"] for ln in path.read_text().splitlines()]
        self.assertEqual(commands, ["enable", "update"])

    def test_failed_operation_is_recorded_not_ok(self):
        path = self._provision("web")
        self._record("update", [{"workload": "web", "result": "failed",
                                 "reason": "pull failed for x"}], ok=False)
        entry = json.loads(path.read_text())
        self.assertFalse(entry["ok"])
        self.assertEqual(entry["reason"], "pull failed for x")

    def test_file_is_root_readable_0644(self):
        path = self._provision("web")
        self._record("enable", [{"workload": "web", "result": "enabled"}])
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_records_the_login_user_over_sudo_user(self):
        # loginuid is the only unforgeable source and the only one that survives
        # `su -`. When the kernel knows who logged in, we believe it.
        path = self._provision("web")
        with mock.patch.object(oplog, "_login_uid", lambda: os.getuid()):
            self._record("enable", [{"workload": "web", "result": "enabled"}])
        entry = json.loads(path.read_text())
        self.assertEqual(entry["user"], oplog._uid_name(os.getuid()))
        self.assertEqual(entry["user_source"], "login")

    def test_no_login_session_is_recorded_as_system(self):
        # A systemd timer running `update --all` must not look like a human at a
        # root console — that was the whole defect in the SUDO_USER-only version.
        path = self._provision("web")
        with mock.patch.dict(os.environ, {}, clear=True):
            self._record("update", [{"workload": "web", "result": "updated"}])
        entry = json.loads(path.read_text())
        self.assertEqual(entry["user_source"], "system")
        self.assertEqual(entry["user"], oplog._uid_name(os.getuid()))


class InvokerTest(unittest.TestCase):
    """_login_uid() reads the kernel's audit loginuid, or admits it can't."""

    def _loginuid(self, content):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "loginuid"
        path.write_text(content)
        return mock.patch.object(oplog, "LOGINUID_PATH", path)

    def test_reads_a_real_login_session(self):
        with self._loginuid("1000"):
            self.assertEqual(oplog._login_uid(), 1000)

    def test_sentinel_means_no_login_session(self):
        with self._loginuid(f"{oplog.LOGINUID_NONE}\n"):
            self.assertIsNone(oplog._login_uid())

    def test_absent_procfs_entry_means_unknown(self):
        # A kernel built without CONFIG_AUDIT has no loginuid at all. "We don't
        # know" must degrade to the next source, not crash the command.
        with mock.patch.object(oplog, "LOGINUID_PATH", Path("/nonexistent/loginuid")):
            self.assertIsNone(oplog._login_uid())

    def test_garbage_content_means_unknown(self):
        with self._loginuid("not-a-number"):
            self.assertIsNone(oplog._login_uid())


class NonMutatingTest(_Base):
    """A verb that changed nothing leaves no trace."""

    def test_dry_run_records_nothing(self):
        path = self._provision("web")
        self._record("update", [{"workload": "web", "result": "dry-run",
                                 "plan": ["pull x"]}])
        self.assertFalse(path.exists())

    def test_rollback_list_records_nothing(self):
        path = self._provision("web")
        self._record("rollback", [{"workload": "web", "result": "listed",
                                   "targets": []}])
        self.assertFalse(path.exists())

    def test_purge_records_nothing_and_does_not_warn(self):
        # --purge rmtree'd the directory the log lives in. Warning that it's
        # missing would fire on every single purge.
        err = self._record("disable", [{"workload": "gone", "result": "purged"}])
        self.assertEqual(err, "")

    def test_a_no_op_update_records_nothing(self):
        # The regression. `update --all` reports "unchanged" for every workload
        # whose image hasn't moved, and it is the verb most likely to be on a
        # timer — so a no-op run must leave the log exactly as it found it, or a
        # quiet fleet buries its own history under one line per workload per run.
        path = self._provision("web")
        self._record("update", [{"workload": "web", "kind": "container",
                                 "result": "unchanged"}])
        self.assertFalse(path.exists())

    def test_a_skipped_update_records_nothing(self):
        path = self._provision("web")
        self._record("update", [{"workload": "web", "result": "skipped",
                                 "reason": "pull=never"}])
        self.assertFalse(path.exists())

    def test_a_batch_records_only_the_workloads_that_changed(self):
        # `update --all` over a fleet where one workload actually moved: the
        # other two leave no file at all, not an "I did nothing" line.
        moved = self._provision("web")
        still = self._provision("cache")
        self._record("update", [
            {"workload": "web", "result": "updated"},
            {"workload": "cache", "result": "unchanged"},
        ])
        self.assertEqual(json.loads(moved.read_text())["result"], "updated")
        self.assertFalse(still.exists())


class ClassificationTest(_Base):
    """Every result string a verb emits is on exactly one of the two lists."""

    def test_the_two_lists_are_disjoint(self):
        self.assertEqual(oplog.RECORDED_RESULTS & oplog.IGNORED_RESULTS, frozenset())

    def test_an_unclassified_result_is_recorded_and_warned_about(self):
        # The allowlist's failure mode, contained: a verb that grows a new result
        # string nobody registered still gets its line (losing an operation is
        # worse than keeping a doubtful one), and says so loudly enough that the
        # next developer classifies it.
        path = self._provision("web")
        err = self._record("frobnicate", [{"workload": "web", "result": "frobbed"}])
        self.assertIn("unclassified result 'frobbed'", err)
        self.assertEqual(json.loads(path.read_text())["result"], "frobbed")


class UnprovisionedWorkloadTest(_Base):
    """The config-authoring verbs run before `enable` ever makes a workload root.

    `create`, `install`, `duplicate` and `edit` all have operations worth
    recording and all of them can run on a workload that has never been enabled,
    so the root is made on demand rather than the line being dropped.
    """

    def test_a_declared_workload_gets_its_root_made_on_demand(self):
        path = self._declare("fresh")
        err = self._record("create", [{"workload": "fresh", "result": "created"}])
        self.assertEqual(err, "")
        self.assertEqual(json.loads(path.read_text())["result"], "created")

    def test_a_workload_with_no_config_is_not_conjured_into_existence(self):
        # No config anywhere: we'd be writing history for something that doesn't
        # exist. That's a caller bug, so warn — and above all don't create the
        # directory, which would then look like an orphan to `cleanup`.
        err = self._record("enable", [{"workload": "ghost", "result": "enabled"}])
        self.assertIn("operations log", err)
        self.assertIn("no such workload 'ghost'", err)
        self.assertFalse((self.base / "ghost").exists())


class BestEffortTest(_Base):
    """Recording must never be why an operation fails."""

    def test_unwritable_dir_warns_and_continues(self):
        self._provision("web")
        with mock.patch.object(oplog.os, "open", side_effect=OSError("read-only")):
            err = self._record("update", [{"workload": "web", "result": "updated"}])
        self.assertIn("could not write", err)

    def test_uncreatable_root_warns_and_continues(self):
        self._declare("fresh")
        with mock.patch.object(oplog.Path, "mkdir", side_effect=OSError("read-only")):
            err = self._record("create", [{"workload": "fresh", "result": "created"}])
        self.assertIn("could not create", err)

    def test_warns_at_most_once_per_process(self):
        # `update --all` over eight unknown workloads must not print the same
        # complaint eight times.
        err = self._record("update", [
            {"workload": f"ghost{i}", "result": "updated"} for i in range(8)
        ])
        self.assertEqual(err.count("operations log"), 1)


class ReadTest(_Base):

    def test_read_returns_entries_oldest_first(self):
        self._provision("web")
        for cmd, result in (("enable", "enabled"), ("update", "updated"),
                            ("rollback", "rolled-back")):
            self._record(cmd, [{"workload": "web", "result": result}])
        self.assertEqual([e["command"] for e in oplog.read("web")],
                         ["enable", "update", "rollback"])
        self.assertEqual([e["command"] for e in oplog.read("web", limit=2)],
                         ["update", "rollback"])

    def test_read_of_an_unlogged_workload_is_empty(self):
        self.assertEqual(oplog.read("nobody"), [])

    def test_a_torn_line_does_not_poison_the_rest(self):
        path = self._provision("web")
        path.write_text(
            json.dumps({"command": "enable"}) + "\n"
            + '{"command": "update", "res\n'          # power loss mid-append
            + json.dumps({"command": "rollback"}) + "\n"
        )
        self.assertEqual([e["command"] for e in oplog.read("web")],
                         ["enable", "rollback"])


class EmitResultIntegrationTest(_Base):
    """cli_log.emit_result feeds the log whether or not --json is on."""

    def test_records_without_json(self):
        path = self._provision("web")
        with redirect_stderr(io.StringIO()):
            cli_log.configure(command="enable")
            cli_log.emit_result([{"workload": "web", "result": "enabled"}])
        self.assertEqual(json.loads(path.read_text())["command"], "enable")

    def test_records_under_quiet(self):
        # --quiet silences the narration, not the record.
        path = self._provision("web")
        with redirect_stderr(io.StringIO()):
            cli_log.configure(quiet=True, command="stop")
            cli_log.emit_result([{"workload": "web", "result": "stopped"}])
        self.assertEqual(json.loads(path.read_text())["result"], "stopped")

    def test_records_an_admin_verb_that_owns_no_json_document(self):
        # `restore` prints no cli_log result object (it isn't one of the --json
        # verbs), but it rewrites the workload's data directory from a portable
        # archive — the most consequential thing anyone can do to a workload, and
        # it used to leave no trace at all. emit_result() is the seam: with
        # json_mode off it feeds the log and nothing else.
        path = self._provision("web")
        with redirect_stderr(io.StringIO()):
            cli_log.configure(command="restore")
            cli_log.emit_result([{"workload": "web", "result": "restored",
                                  "archive": "/var/lib/workloads/backups/web.tar.zst"}])
        entry = json.loads(path.read_text())
        self.assertEqual(entry["command"], "restore")
        self.assertEqual(entry["result"], "restored")
        self.assertTrue(entry["archive"].endswith("web.tar.zst"))


if __name__ == "__main__":
    unittest.main()
