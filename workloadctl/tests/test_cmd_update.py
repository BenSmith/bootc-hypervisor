#!/usr/bin/env python3
"""Unit tests for cmd_update's command-level dispatch.

The helper math (_parse_duration, _health_wait_seconds, container_specs) is
covered in test_update.py. This module covers the dispatch layer that
test_update.py does not: the `--all` VM/container accounting, the nonzero exit
on failure, and the single-workload error paths — all without a live host, by
faking the substrate.
"""

import argparse
import io
import os
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

LIB = os.path.join(os.path.dirname(__file__), "..", "lib")
if LIB not in sys.path:
    sys.path.insert(0, LIB)

import cmd_update  # noqa: E402
from substrate import NotApplicable, ProvisionFailed  # noqa: E402


class _FakeSub:
    """Stand-in substrate. reprovision() returns a result or raises."""

    def __init__(self, result=None, raises=None):
        self._result = result
        self._raises = raises

    def reprovision(self, *, force=False, recreate=False):
        if self._raises is not None:
            raise self._raises
        return self._result


class _FakeVMSub(_FakeSub):
    """A VM substrate — cmd_update branches on isinstance(.., VMSubstrate)."""


class _FakeConfig:
    def __init__(self, name, sub):
        self.name = name
        self._sub = sub


def _ns(**kw):
    kw.setdefault("force", False)
    kw.setdefault("all", False)
    kw.setdefault("workload", None)
    return argparse.Namespace(**kw)


class UpdateDispatchTest(unittest.TestCase):
    def setUp(self):
        # require_root and VMSubstrate-for-isinstance and _verify_all are the
        # three seams; patch them for every test.
        self.enterContext(mock.patch.object(cmd_update, "require_root", lambda: None))
        self.enterContext(mock.patch.object(cmd_update, "VMSubstrate", _FakeVMSub))
        self.manager = mock.Mock()

    def _run(self, args, configs=None, verify_returns=0):
        """Run cmd_update with get_substrate wired to each config's _sub and
        _verify_all stubbed to report `verify_returns` rollbacks. Returns
        (stdout, raised_systemexit_code_or_None)."""
        if configs is not None:
            self.manager.get_all_configs.return_value = configs
        out = io.StringIO()
        err = io.StringIO()
        code = None
        with mock.patch.object(cmd_update, "get_substrate", lambda c, m: c._sub), \
             mock.patch.object(cmd_update, "_verify_all", lambda updated, m: verify_returns):
            try:
                with redirect_stdout(out), redirect_stderr(err):
                    cmd_update.cmd_update(args, self.manager)
            except SystemExit as e:
                code = e.code
        self._err = err.getvalue()
        return out.getvalue(), code

    # --- --all accounting --------------------------------------------------

    def test_all_no_enabled_workloads(self):
        out, code = self._run(_ns(all=True), configs=[])
        self.assertIn("No enabled workloads found", out)
        self.assertIsNone(code)

    def test_all_containers_all_succeed_no_rollback(self):
        configs = [
            _FakeConfig("a", _FakeSub(result=("a", {}))),
            _FakeConfig("b", _FakeSub(result=("b", {}))),
        ]
        out, code = self._run(_ns(all=True), configs=configs, verify_returns=0)
        self.assertIn("Done: 2 updated, 0 rolled back, 0 skipped", out)
        self.assertNotIn("VMs:", out)   # no VM in the batch
        self.assertIsNone(code)          # clean run, no exit

    def test_all_counts_rollbacks_against_updated(self):
        configs = [
            _FakeConfig("a", _FakeSub(result=("a", {}))),
            _FakeConfig("b", _FakeSub(result=("b", {}))),
        ]
        out, code = self._run(_ns(all=True), configs=configs, verify_returns=1)
        # 2 updated minus 1 rolled back == 1 reported updated.
        self.assertIn("Done: 1 updated, 1 rolled back, 0 skipped", out)
        self.assertIsNone(code)  # a rollback is a handled outcome, not a failure

    def test_all_skips_pull_never(self):
        configs = [
            _FakeConfig("a", _FakeSub(result=("a", {}))),
            _FakeConfig("skip", _FakeSub(raises=NotApplicable("pull=never"))),
        ]
        out, code = self._run(_ns(all=True), configs=configs)
        self.assertIn("1 updated, 0 rolled back, 1 skipped", out)
        self.assertIsNone(code)

    def test_all_container_failure_exits_nonzero(self):
        configs = [
            _FakeConfig("a", _FakeSub(result=("a", {}))),
            _FakeConfig("boom", _FakeSub(raises=ProvisionFailed())),
        ]
        out, code = self._run(_ns(all=True), configs=configs)
        self.assertIn("1 failed", out)
        self.assertEqual(code, 1)

    def test_all_vm_accounting_and_failure(self):
        # One VM updates, one VM fails, one container updates.
        configs = [
            _FakeConfig("vm-ok", _FakeVMSub(result=None)),       # VMs return None
            _FakeConfig("vm-bad", _FakeVMSub(raises=ProvisionFailed())),
            _FakeConfig("ctr", _FakeSub(result=("ctr", {}))),
        ]
        out, code = self._run(_ns(all=True), configs=configs)
        # Container line: only the one container counts as "updated".
        self.assertIn("Done: 1 updated, 0 rolled back, 0 skipped", out)
        # VM line: 2 total, 1 failed.
        self.assertIn("VMs: 1 updated, 1 failed", out)
        # A VM failure (no auto-rollback safety net) must exit nonzero.
        self.assertEqual(code, 1)

    # --- single-workload paths --------------------------------------------

    def test_single_requires_name(self):
        out, code = self._run(_ns(all=False, workload=None))
        self.assertEqual(code, 1)
        self.assertIn("Workload name required", self._err)

    def test_single_not_applicable_reports_reason_and_exits(self):
        cfg = _FakeConfig("x", _FakeSub(raises=NotApplicable("pull=never; nothing to do")))
        with mock.patch.object(cmd_update, "WorkloadConfig", lambda n: cfg):
            out, code = self._run(_ns(all=False, workload="x"))
        self.assertEqual(code, 1)
        self.assertIn("pull=never; nothing to do", self._err)

    def test_single_provision_failed_exits(self):
        cfg = _FakeConfig("x", _FakeSub(raises=ProvisionFailed()))
        with mock.patch.object(cmd_update, "WorkloadConfig", lambda n: cfg):
            out, code = self._run(_ns(all=False, workload="x"))
        self.assertEqual(code, 1)

    def test_single_success_verifies_result(self):
        cfg = _FakeConfig("x", _FakeSub(result=("x", {})))
        seen: dict = {}
        with mock.patch.object(cmd_update, "WorkloadConfig", lambda n: cfg), \
             mock.patch.object(cmd_update, "get_substrate", lambda c, m: c._sub), \
             mock.patch.object(cmd_update, "_verify_all",
                               lambda updated, m: seen.setdefault("updated", updated)):
            cmd_update.cmd_update(_ns(all=False, workload="x"), self.manager)
        # The single success path feeds exactly its one result into verification.
        self.assertEqual(seen["updated"], [("x", {})])


class RollbackDispatchTest(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.object(cmd_update, "require_root", lambda: None))
        self.manager = mock.Mock()

    def _run(self, ns, sub, user_exists=True):
        cfg = mock.Mock()
        cfg.name = "x"
        cfg.username = "_wl-x"
        self.manager.user_exists.return_value = user_exists
        out, err = io.StringIO(), io.StringIO()
        code = None
        with mock.patch.object(cmd_update, "WorkloadConfig", lambda n: cfg), \
             mock.patch.object(cmd_update, "get_substrate", lambda c, m: sub):
            try:
                with redirect_stdout(out), redirect_stderr(err):
                    cmd_update.cmd_rollback(ns, self.manager)
            except SystemExit as e:
                code = e.code
        return out.getvalue(), err.getvalue(), code

    def test_user_missing_exits(self):
        _out, err, code = self._run(_ns(workload="x", list=False), mock.Mock(),
                                    user_exists=False)
        self.assertEqual(code, 1)
        self.assertIn("does not exist", err)

    def test_plain_rollback_invokes_substrate(self):
        sub = mock.Mock()
        self._run(_ns(workload="x", list=False), sub)
        sub.rollback.assert_called_once_with()

    def test_list_empty_targets(self):
        sub = mock.Mock()
        sub.rollback_targets.return_value = []
        out, _err, _code = self._run(_ns(workload="x", list=True), sub)
        self.assertIn("No rollback targets", out)
        sub.rollback.assert_not_called()

    def test_list_prints_targets(self):
        sub = mock.Mock()
        sub.rollback_targets.return_value = [{"label": "gen-1 (2d ago)"},
                                             {"label": "gen-2 (1h ago)"}]
        out, _err, _code = self._run(_ns(workload="x", list=True), sub)
        self.assertIn("gen-1 (2d ago)", out)
        self.assertIn("gen-2 (1h ago)", out)
        sub.rollback.assert_not_called()


class DoRollbackTest(unittest.TestCase):
    def test_retags_when_rollback_image_present(self):
        pod = mock.Mock()
        pod.image_id.return_value = "sha256:old"
        cfg = mock.Mock()
        cfg.name = "app"
        cfg.is_multi = False
        cfg.uid = 10001
        cfg.service_name = "workload-app.service"
        cfg.container_images.return_value = [("app", "localhost/app:latest")]
        mgr = mock.Mock()
        mgr.podman.return_value = pod
        with mock.patch.object(cmd_update, "restart_workload_service") as restart, \
             redirect_stdout(io.StringIO()):
            cmd_update._do_rollback(cfg, mgr)
        pod.tag.assert_called_once_with("localhost/workload-rollback/app:latest",
                                        "localhost/app:latest")
        restart.assert_called_once()

    def test_no_retag_when_rollback_image_absent(self):
        pod = mock.Mock()
        pod.image_id.return_value = None
        cfg = mock.Mock()
        cfg.name = "app"
        cfg.is_multi = False
        cfg.uid = 10001
        cfg.service_name = "workload-app.service"
        cfg.container_images.return_value = [("app", "localhost/app:latest")]
        mgr = mock.Mock()
        mgr.podman.return_value = pod
        with mock.patch.object(cmd_update, "restart_workload_service"), \
             redirect_stdout(io.StringIO()):
            cmd_update._do_rollback(cfg, mgr)
        pod.tag.assert_not_called()


class VerifyAllTest(unittest.TestCase):
    def _cfg(self, name, health, active_ok, is_multi=False):
        c = mock.Mock()
        c.name = name
        c.has_health_check.return_value = health
        c.is_multi = is_multi
        c.service_name = f"workload-{name}.service"
        c.sub_service_names.return_value = [f"workload-{name}.service"]
        return c

    def test_healthy_no_rollback(self):
        cfg = self._cfg("app", health=True, active_ok=True)
        cfg.container_health_blocks.return_value = [("app", "workload-app", {})]
        pod = mock.Mock()
        pod.container_health.return_value = "healthy"
        mgr = mock.Mock()
        mgr.podman.return_value = pod
        with mock.patch.object(cmd_update.time, "sleep"), \
             mock.patch.object(cmd_update, "_health_wait_seconds", return_value=0), \
             redirect_stdout(io.StringIO()):
            n = cmd_update._verify_all([(cfg, {"app": "old"})], mgr)
        self.assertEqual(n, 0)

    def test_unhealthy_with_old_rolls_back(self):
        cfg = self._cfg("app", health=True, active_ok=False)
        cfg.container_health_blocks.return_value = [("app", "workload-app", {})]
        pod = mock.Mock()
        pod.container_health.return_value = "unhealthy"
        mgr = mock.Mock()
        mgr.podman.return_value = pod
        with mock.patch.object(cmd_update.time, "sleep"), \
             mock.patch.object(cmd_update, "_health_wait_seconds", return_value=0), \
             mock.patch.object(cmd_update, "_do_rollback") as rb, \
             redirect_stdout(io.StringIO()):
            n = cmd_update._verify_all([(cfg, {"app": "old"})], mgr)
        self.assertEqual(n, 1)
        rb.assert_called_once()

    def test_starting_then_healthy_no_rollback(self):
        """A container still 'starting' at the first check gets one more
        wait (its health-check interval) before being judged — recovering
        to healthy must not trigger a rollback."""
        cfg = self._cfg("app", health=True, active_ok=True)
        cfg.container_health_blocks.return_value = [("app", "workload-app", {"interval": "5s"})]
        pod = mock.Mock()
        pod.container_health.side_effect = ["starting", "healthy"]
        mgr = mock.Mock()
        mgr.podman.return_value = pod
        with mock.patch.object(cmd_update.time, "sleep") as mock_sleep, \
             mock.patch.object(cmd_update, "_health_wait_seconds", return_value=0), \
             mock.patch.object(cmd_update, "_do_rollback") as rb, \
             redirect_stdout(io.StringIO()):
            n = cmd_update._verify_all([(cfg, {"app": "old"})], mgr)
        self.assertEqual(n, 0)
        rb.assert_not_called()
        # Once for the initial max_wait, once for the extra "starting" grace period.
        self.assertEqual(mock_sleep.call_count, 2)
        mock_sleep.assert_called_with(5)

    def test_starting_then_still_unhealthy_rolls_back(self):
        """If the grace-period recheck still isn't healthy, roll back."""
        cfg = self._cfg("app", health=True, active_ok=False)
        cfg.container_health_blocks.return_value = [("app", "workload-app", {"interval": "5s"})]
        pod = mock.Mock()
        pod.container_health.side_effect = ["starting", "unhealthy"]
        mgr = mock.Mock()
        mgr.podman.return_value = pod
        with mock.patch.object(cmd_update.time, "sleep"), \
             mock.patch.object(cmd_update, "_health_wait_seconds", return_value=0), \
             mock.patch.object(cmd_update, "_do_rollback") as rb, \
             redirect_stdout(io.StringIO()):
            n = cmd_update._verify_all([(cfg, {"app": "old"})], mgr)
        self.assertEqual(n, 1)
        rb.assert_called_once()

    def test_no_health_service_crash_rolls_back(self):
        cfg = self._cfg("app", health=False, active_ok=False)
        mgr = mock.Mock()
        with mock.patch.object(cmd_update.time, "sleep"), \
             mock.patch.object(cmd_update, "_health_wait_seconds", return_value=0), \
             mock.patch.object(cmd_update.subprocess, "run",
                               return_value=mock.Mock(returncode=3)), \
             mock.patch.object(cmd_update, "_do_rollback") as rb, \
             redirect_stdout(io.StringIO()):
            n = cmd_update._verify_all([(cfg, {"app": "old"})], mgr)
        self.assertEqual(n, 1)
        rb.assert_called_once()


if __name__ == "__main__":
    unittest.main()