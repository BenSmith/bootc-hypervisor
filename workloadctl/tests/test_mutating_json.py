#!/usr/bin/env python3
"""Unit tests for the mutating verbs' --json result object and --quiet.

The read verbs have had --json for a long time; these are the ones that *change*
something (enable, disable, start, update, rollback), where the interesting part
isn't the report but the per-workload outcome: what got updated, what was skipped
and why, what failed, what was rolled back.

The mode is process-wide (cli_log.configure), not per-call, so every test here
sets it explicitly and resets it afterwards.
"""

import argparse
import io
import json
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import cli_log
import cmd_enable
import cmd_lifecycle
import cmd_update
import workload_lib
from substrate import NotApplicable, ProvisionFailed


_CONTAINER_TOML = """
[workload]
name = "test-wl"

[container]
image = "docker.io/library/nginx:alpine"
"""


class _FakeVMSub:
    """Stands in for VMSubstrate so isinstance() can pick VMs out of a batch."""


class _FakeSub:
    def __init__(self, result=None, raises=None, vm=False):
        self._result = result
        self._raises = raises
        self.vm = vm

    def reprovision(self, *, force=False, recreate=False):
        if self._raises:
            raise self._raises
        return self._result


class _FakeVM(_FakeVMSub, _FakeSub):
    pass


class _FakeConfig:
    def __init__(self, name, sub):
        self.name = name
        self._sub = sub

    def container_images(self):
        return [(self.name, f"docker.io/{self.name}:latest")]


def _ns(**kw):
    kw.setdefault("force", False)
    kw.setdefault("all", False)
    kw.setdefault("workload", None)
    kw.setdefault("json", True)
    return argparse.Namespace(**kw)


class _JsonMode:
    """Put cli_log in --json mode for one command, and capture stdout/stderr."""

    def __init__(self, command, quiet=False, json_mode=True):
        self.command, self.quiet, self.json_mode = command, quiet, json_mode
        self.out, self.err = io.StringIO(), io.StringIO()

    def __enter__(self):
        cli_log.configure(quiet=self.quiet, json_mode=self.json_mode,
                          command=self.command)
        self._stack = ExitStack()
        self._stack.enter_context(redirect_stdout(self.out))
        self._stack.enter_context(redirect_stderr(self.err))
        return self

    def __exit__(self, *exc):
        self._stack.close()
        cli_log.reset()
        return False

    def payload(self):
        return json.loads(self.out.getvalue())


class UpdateJsonTest(unittest.TestCase):
    """`update` is the verb with real per-workload outcomes to report."""

    def setUp(self):
        self.enterContext(mock.patch.object(cmd_update, "require_root", lambda: None))
        self.enterContext(mock.patch.object(cmd_update, "VMSubstrate", _FakeVMSub))
        self.enterContext(mock.patch.object(
            cmd_update, "get_substrate", lambda c, m: c._sub))
        self.manager = mock.Mock()
        self.manager.podman.return_value.image_id.return_value = "sha256:new"

    def _run_all(self, configs, verify=None):
        self.manager.get_all_configs.return_value = configs

        def fake_verify(updated, m, results=None):
            if results is not None and verify:
                results.update(verify)
            return sum(1 for v in (verify or {}).values() if v["rolled_back"])

        with mock.patch.object(cmd_update, "_verify_all", fake_verify):
            with _JsonMode("update") as mode:
                try:
                    cmd_update.cmd_update(_ns(all=True), self.manager)
                    code = None
                except SystemExit as e:
                    code = e.code
        return mode.payload(), mode, code

    def test_row_per_workload_with_summary(self):
        configs = [
            _FakeConfig("a", _FakeSub(result=("a", {}))),
            _FakeConfig("b", _FakeSub(raises=NotApplicable("pull=never"))),
            _FakeConfig("c", _FakeSub(result=None)),
        ]
        payload, _mode, code = self._run_all(configs)
        self.assertIsNone(code)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["command"], "update")
        self.assertEqual(
            [(r["workload"], r["result"]) for r in payload["workloads"]],
            [("a", "updated"), ("b", "skipped"), ("c", "unchanged")],
        )
        self.assertEqual(payload["workloads"][1]["reason"], "pull=never")
        self.assertEqual(payload["summary"]["updated"], 1)
        self.assertEqual(payload["summary"]["skipped"], 1)
        self.assertEqual(payload["summary"]["unchanged"], 1)

    def test_updated_row_carries_the_image_transition(self):
        # The old→new image ID is the thing a scripted caller most wants back
        # from an update, and it is only knowable at the moment of the pull.
        configs = [_FakeConfig("a", _FakeSub(result=("a", {"a": "sha256:old"})))]
        payload, _mode, _code = self._run_all(configs)
        images = payload["workloads"][0]["images"]
        self.assertEqual(images["a"]["old"], "sha256:old")
        self.assertEqual(images["a"]["new"], "sha256:new")
        self.assertEqual(images["a"]["image"], "docker.io/a:latest")

    def test_prose_stays_off_stdout(self):
        # The whole point: `update --all --json | jq` must not choke on a
        # progress line. Narration goes to nobody; stdout is the document.
        configs = [_FakeConfig("a", _FakeSub(result=("a", {})))]
        _payload, mode, _code = self._run_all(configs)
        self.assertNotIn("Updating", mode.out.getvalue())
        json.loads(mode.out.getvalue())   # parses cleanly, start to finish

    def test_failed_workload_marks_document_not_ok_and_exits_1(self):
        configs = [
            _FakeConfig("a", _FakeSub(result=("a", {}))),
            _FakeConfig("bad", _FakeSub(raises=ProvisionFailed("pull failed for x"))),
        ]
        payload, _mode, code = self._run_all(configs)
        self.assertEqual(code, 1)
        self.assertFalse(payload["ok"])
        bad = payload["workloads"][1]
        self.assertEqual(bad["result"], "failed")
        self.assertEqual(bad["reason"], "pull failed for x")
        self.assertEqual(payload["summary"]["failed"], 1)

    def test_rolled_back_workload_reports_its_verdict(self):
        configs = [_FakeConfig("a", _FakeSub(result=("a", {})))]
        payload, _mode, code = self._run_all(
            configs, verify={"a": {"verify": "crashed", "rolled_back": True}})
        # A rollback is a handled outcome, not a failed command.
        self.assertIsNone(code)
        self.assertTrue(payload["ok"])
        row = payload["workloads"][0]
        self.assertEqual(row["result"], "rolled-back")
        self.assertEqual(row["verify"], "crashed")
        self.assertEqual(payload["summary"]["rolled-back"], 1)

    def test_vm_row_is_kinded_and_updated(self):
        configs = [_FakeConfig("vm1", _FakeVM(result=None, vm=True))]
        payload, _mode, _code = self._run_all(configs)
        row = payload["workloads"][0]
        self.assertEqual(row["kind"], "vm")
        # A VM's reprovision returns None (it has no verification phase), but it
        # rebuilt and restarted the VM — "unchanged" would be a lie.
        self.assertEqual(row["result"], "updated")

    def test_dry_run_reports_the_plan(self):
        cfg = _FakeConfig("a", _FakeSub())
        self.manager.get_all_configs.return_value = [cfg]
        with mock.patch.object(cmd_update, "_update_plan",
                               lambda c, m: ["pull x", "restart y"]):
            with _JsonMode("update") as mode:
                cmd_update.cmd_update(_ns(all=True, dry_run=True), self.manager)
        row = mode.payload()["workloads"][0]
        self.assertEqual(row["result"], "dry-run")
        self.assertEqual(row["plan"], ["pull x", "restart y"])

    def test_single_workload_success(self):
        cfg = _FakeConfig("solo", _FakeSub(result=None))
        with mock.patch.object(cmd_update, "WorkloadConfig", lambda n: cfg):
            with _JsonMode("update") as mode:
                cmd_update.cmd_update(_ns(workload="solo"), self.manager)
        self.assertEqual(mode.payload()["workloads"],
                         [{"workload": "solo", "kind": "container",
                           "result": "unchanged"}])


class RollbackJsonTest(unittest.TestCase):

    def setUp(self):
        self.enterContext(mock.patch.object(cmd_update, "require_root", lambda: None))
        self.manager = mock.Mock()

    def _run(self, sub, **kw):
        cfg = _FakeConfig("web", sub)
        with mock.patch.object(cmd_update, "WorkloadConfig", lambda n: cfg), \
             mock.patch.object(cmd_update, "get_substrate", lambda c, m: sub):
            with _JsonMode("rollback") as mode:
                cmd_update.cmd_rollback(_ns(workload="web", **kw), self.manager)
        return mode.payload()

    def test_rollback_reports_result(self):
        sub = mock.Mock()
        payload = self._run(sub)
        sub.rollback.assert_called_once()
        self.assertEqual(payload["workloads"],
                         [{"workload": "web", "result": "rolled-back"}])

    def test_list_reports_targets_including_paths(self):
        sub = mock.Mock()
        sub.rollback_targets.return_value = [
            {"label": "system.qcow2.gen-3", "gen": 3,
             "path": Path("/var/lib/workloads/web/system.qcow2.gen-3")},
        ]
        payload = self._run(sub, list=True)
        row = payload["workloads"][0]
        self.assertEqual(row["result"], "listed")
        self.assertEqual(row["targets"][0]["gen"], 3)
        self.assertEqual(row["targets"][0]["path"],
                         "/var/lib/workloads/web/system.qcow2.gen-3")


class LifecycleJsonTest(unittest.TestCase):
    """The simple verbs report one row: what they did, to which service."""

    def setUp(self):
        self.enterContext(mock.patch.object(cmd_lifecycle, "require_root", lambda: None))
        self.manager = mock.Mock()

    def _run(self, fn, tmp, name="test-wl"):
        cfg_dir = Path(tmp)
        (cfg_dir / name).mkdir()
        (cfg_dir / name / "workload.toml").write_text(_CONTAINER_TOML)
        sub = mock.Mock()
        with mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", cfg_dir), \
             mock.patch.object(cmd_lifecycle, "get_substrate", lambda c, m: sub):
            with _JsonMode(fn.__name__.removeprefix("cmd_")) as mode:
                fn(_ns(workload=name), self.manager)
        return mode.payload(), sub

    def test_start_reports_started(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            payload, sub = self._run(cmd_lifecycle.cmd_start, tmp)
        sub.lifecycle.assert_called_once_with("start")
        row = payload["workloads"][0]
        self.assertEqual(row["result"], "started")
        self.assertEqual(row["service"], "workload-test-wl.service")

    def test_stop_reports_stopped(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            payload, sub = self._run(cmd_lifecycle.cmd_stop, tmp)
        sub.lifecycle.assert_called_once_with("stop")
        self.assertEqual(payload["workloads"][0]["result"], "stopped")


class QuietTest(unittest.TestCase):
    """--quiet silences narration and nothing else."""

    def test_enable_prose_is_suppressed_but_the_work_still_happens(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as base:
            cfg_dir = Path(d)
            (cfg_dir / "test-wl").mkdir()
            (cfg_dir / "test-wl" / "workload.toml").write_text(_CONTAINER_TOML)

            def fake_run(cmd, **kw):
                if cmd[:3] == ["systemctl", "is-active", "--quiet"]:
                    return mock.MagicMock(returncode=1)
                return mock.MagicMock(returncode=0)

            with ExitStack() as st:
                p = st.enter_context
                p(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", cfg_dir))
                p(mock.patch.object(workload_lib, "WORKLOADS_BASE", Path(base)))
                p(mock.patch.object(cmd_enable, "require_root", lambda: None))
                p(mock.patch.object(cmd_enable.subprocess, "run", side_effect=fake_run))
                p(mock.patch.object(cmd_enable, "preflight_checks", return_value=True))
                p(mock.patch.object(cmd_enable, "run_host_setup"))
                p(mock.patch.object(cmd_enable, "apply_selinux_policy"))
                p(mock.patch.object(cmd_enable, "generate_units"))
                p(mock.patch.object(cmd_enable, "provision_user"))
                p(mock.patch.object(cmd_enable, "transfer_image"))
                start = p(mock.patch.object(cmd_enable, "start_service"))
                with _JsonMode("enable", quiet=True, json_mode=False) as mode:
                    cmd_enable.cmd_enable(
                        argparse.Namespace(workload="test-wl", json=False, quiet=True),
                        mock.MagicMock())

            self.assertEqual(mode.out.getvalue(), "")
            start.assert_called_once()   # silent, not skipped


if __name__ == "__main__":
    unittest.main()
