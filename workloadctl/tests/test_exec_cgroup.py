#!/usr/bin/env python3
"""Unit tests for delegated_unit_cgroup() — the parser that locates a split
container's delegated systemd unit cgroup from /proc/<pid>/cgroup, used by
`workloadctl exec/shell` to make exec work under --cgroups=split."""

import importlib.machinery
import importlib.util
import os
import sys
import unittest

# Import workloadctl as a module (hyphenated filename requires importlib).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
_ctl_path = os.path.join(os.path.dirname(__file__), '..', 'bin', 'workloadctl')
_loader = importlib.machinery.SourceFileLoader("workload_ctl", _ctl_path)
_spec = importlib.util.spec_from_loader("workload_ctl", _loader)
wctl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wctl)


class TestDelegatedUnitCgroup(unittest.TestCase):
    def test_split_single_mode(self):
        # Container payload sits directly under the delegated unit cgroup.
        text = "0::/workloads.slice/workload-bigdevfire.service/libpod-payload-abc123\n"
        self.assertEqual(wctl.delegated_unit_cgroup(text),
                         "/workloads.slice/workload-bigdevfire.service")

    def test_split_bridge_mode(self):
        # Bridge-mode service name carries the container suffix.
        text = "0::/workloads.slice/workload-foo-web.service/libpod-payload-x\n"
        self.assertEqual(wctl.delegated_unit_cgroup(text),
                         "/workloads.slice/workload-foo-web.service")

    def test_runtime_sibling_child(self):
        # The conmon "runtime" sub-cgroup still resolves to the unit cgroup.
        text = "0::/workloads.slice/workload-bigdevfire.service/runtime\n"
        self.assertEqual(wctl.delegated_unit_cgroup(text),
                         "/workloads.slice/workload-bigdevfire.service")

    def test_custom_slice(self):
        text = "0::/myslice.slice/workload-jelly.service/libpod-payload-9\n"
        self.assertEqual(wctl.delegated_unit_cgroup(text),
                         "/myslice.slice/workload-jelly.service")

    def test_user_manager_no_split_returns_none(self):
        # Migrated into the user manager (no workload-*.service ancestor).
        text = ("0::/user.slice/user-10001.slice/user@10001.service/"
                "user.slice/libpod-abc.scope/container\n")
        self.assertIsNone(wctl.delegated_unit_cgroup(text))

    def test_unrelated_service_returns_none(self):
        # A non-workload unit must never match (e.g. user@<uid>.service).
        text = "0::/user.slice/user-1000.slice/user@1000.service/app.scope\n"
        self.assertIsNone(wctl.delegated_unit_cgroup(text))

    def test_empty_and_garbage(self):
        self.assertIsNone(wctl.delegated_unit_cgroup(""))
        self.assertIsNone(wctl.delegated_unit_cgroup("garbage without a v2 line\n"))

    def test_hybrid_file_picks_v2_line(self):
        # cgroup v1/v2 hybrid layout: ignore controller lines, use the "0::" one.
        text = (
            "3:cpu,cpuacct:/some/v1/path\n"
            "0::/workloads.slice/workload-bigdevfire.service/libpod-payload-abc\n"
        )
        self.assertEqual(wctl.delegated_unit_cgroup(text),
                         "/workloads.slice/workload-bigdevfire.service")


class TestCgroupExecModule(unittest.TestCase):
    """The shared lib/cgroup_exec module imports cleanly and exposes the same
    parser (used by both `workloadctl exec` and the split healthcheck libexec)."""

    def test_module_importable_and_parses(self):
        import cgroup_exec
        self.assertTrue(callable(cgroup_exec.delegated_unit_cgroup))
        self.assertTrue(callable(cgroup_exec.cgroup_placed_podman))
        self.assertEqual(
            cgroup_exec.delegated_unit_cgroup(
                "0::/workloads.slice/workload-foo.service/libpod-payload-x\n"),
            "/workloads.slice/workload-foo.service",
        )

    def test_bin_reexports_lib(self):
        # bin/workloadctl imports the parser from cgroup_exec, so it's the same
        # object — exec and the healthcheck libexec can't drift apart.
        import cgroup_exec
        self.assertIs(wctl.delegated_unit_cgroup, cgroup_exec.delegated_unit_cgroup)


if __name__ == "__main__":
    unittest.main()
