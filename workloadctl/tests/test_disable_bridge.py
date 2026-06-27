#!/usr/bin/env python3
"""Unit tests for the shared VM bridge teardown in cmd_disable.

Covers cmd_lifecycle._stop_bridge_if_last_vm: the helper that stops
workload-bridge.service when the disabled workload was the final
managed-bridge VM workload.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

LIB_DIR = os.path.join(os.path.dirname(__file__), '..', 'lib')
sys.path.insert(0, LIB_DIR)

import cmd_lifecycle
import workloadctl_core
from workloadctl_core import WorkloadConfig, VM_BRIDGE_NAME

# Minimal TOML fixtures -------------------------------------------------------

CONTAINER_TOML = """\
[workload]
name = "{name}"
enabled = true

[container]
image = "example.com/test:latest"
"""

VM_TOML_MANAGED = """\
[workload]
name = "{name}"
enabled = {enabled}

[vm]
local_image = "/var/lib/workloads/images/test.qcow2"
"""
# No [vm.network] → bridge defaults to VM_BRIDGE_NAME (_workload-br)

VM_TOML_CUSTOM_BRIDGE = """\
[workload]
name = "{name}"
enabled = true

[vm]
local_image = "/var/lib/workloads/images/test.qcow2"

[vm.network]
bridge = "br0"
"""


class _WlDir:
    """Context manager: temp WORKLOAD_DIR with one or more pre-written TOMLs.

    Usage::

        with _WlDir({"myvm": VM_TOML_MANAGED}) as wl_dir:
            config = WorkloadConfig("myvm")
            ...
    """

    def __init__(self, tomls: dict[str, str]):
        """tomls: mapping of workload-name -> toml text (already formatted)."""
        self._tomls = tomls

    def __enter__(self) -> Path:
        self._tmp = tempfile.mkdtemp()
        wl_path = Path(self._tmp)
        for name, text in self._tomls.items():
            (wl_path / name).mkdir(exist_ok=True)
            (wl_path / name / "workload.toml").write_text(text)
        self._patch = patch.object(workloadctl_core, "WORKLOAD_DIR", wl_path)
        self._patch.start()
        return wl_path

    def __exit__(self, *_):
        self._patch.stop()
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)


def _mock_manager(configs: list[WorkloadConfig]) -> MagicMock:
    """Return a WorkloadManager mock whose get_all_configs(enabled_only=True)
    yields the given list."""
    mgr = MagicMock()
    mgr.get_all_configs.return_value = configs
    return mgr


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestStopBridgeIfLastVm(unittest.TestCase):
    """Direct tests of the _stop_bridge_if_last_vm helper."""

    def _run(self, config_name, manager, toml_text):
        """Load a WorkloadConfig for config_name from a temp dir and call the
        helper with the supplied manager mock."""
        tomls = {config_name: toml_text.format(name=config_name, enabled="false")}
        with _WlDir(tomls):
            config = WorkloadConfig(config_name)
            with patch.object(cmd_lifecycle.subprocess, "run", MagicMock()) as run:
                cmd_lifecycle._stop_bridge_if_last_vm(config, manager)
            return run

    # 1. Last managed-bridge VM → bridge service is stopped -----------------

    def test_last_managed_bridge_vm_stops_bridge(self):
        """No remaining enabled managed-bridge VMs → systemctl stop called."""
        # manager returns empty list (the disabled workload is already excluded)
        mgr = _mock_manager([])
        run = self._run("myvm", mgr, VM_TOML_MANAGED)

        expected = call(
            ["systemctl", "stop", "workload-bridge.service"],
            check=False,
            capture_output=True,
        )
        self.assertIn(expected, run.call_args_list)
        mgr.get_all_configs.assert_called_once_with(enabled_only=True)

    # 2. Another enabled managed-bridge VM present → no stop ----------------

    def test_another_managed_bridge_vm_present_no_stop(self):
        """A second enabled managed-bridge VM remains → bridge left running."""
        # Build a second VM config in a temp dir so we get a real WorkloadConfig
        second_toml = VM_TOML_MANAGED.format(name="othervm", enabled="true")
        with _WlDir({"myvm": VM_TOML_MANAGED.format(name="myvm", enabled="false"),
                     "othervm": second_toml}):
            other_config = WorkloadConfig("othervm")
            mgr = _mock_manager([other_config])

            config = WorkloadConfig("myvm")
            with patch.object(cmd_lifecycle.subprocess, "run", MagicMock()) as run:
                cmd_lifecycle._stop_bridge_if_last_vm(config, mgr)

        # systemctl stop workload-bridge.service must NOT appear
        stop_calls = [
            c for c in run.call_args_list
            if c.args and c.args[0][:2] == ["systemctl", "stop"]
            and "workload-bridge.service" in c.args[0]
        ]
        self.assertEqual(stop_calls, [])

    # 3. Disabling a container (non-VM) workload → no bridge check ----------

    def test_container_workload_skips_bridge_check(self):
        """Non-VM workload: helper returns immediately, get_all_configs not called."""
        mgr = _mock_manager([])
        tomls = {"mywl": CONTAINER_TOML.format(name="mywl")}
        with _WlDir(tomls):
            config = WorkloadConfig("mywl")
            with patch.object(cmd_lifecycle.subprocess, "run", MagicMock()) as run:
                cmd_lifecycle._stop_bridge_if_last_vm(config, mgr)

        mgr.get_all_configs.assert_not_called()
        run.assert_not_called()

    # 4. VM on a user-provided (non-managed) bridge → no stop ---------------

    def test_vm_custom_bridge_no_stop(self):
        """VM on br0 (not _workload-br) → bridge service left alone."""
        tomls = {"customvm": VM_TOML_CUSTOM_BRIDGE.format(name="customvm")}
        mgr = _mock_manager([])
        with _WlDir(tomls):
            config = WorkloadConfig("customvm")
            self.assertNotEqual(config.vm_bridge, VM_BRIDGE_NAME)
            with patch.object(cmd_lifecycle.subprocess, "run", MagicMock()) as run:
                cmd_lifecycle._stop_bridge_if_last_vm(config, mgr)

        mgr.get_all_configs.assert_not_called()
        run.assert_not_called()

    # 5. Belt-and-suspenders: disabled workload in enabled list still excluded

    def test_disabled_vm_in_enabled_list_still_excluded(self):
        """If the disabled VM somehow appears in get_all_configs (shouldn't happen),
        the c.name != config.name guard prevents a false 'still needed' result."""
        with _WlDir({"myvm": VM_TOML_MANAGED.format(name="myvm", enabled="false")}):
            config = WorkloadConfig("myvm")
            # Pretend get_all_configs returned the *same* workload (edge case)
            mgr = _mock_manager([config])

            with patch.object(cmd_lifecycle.subprocess, "run", MagicMock()) as run:
                cmd_lifecycle._stop_bridge_if_last_vm(config, mgr)

        # Should still stop the bridge (self-name is excluded by guard)
        expected = call(
            ["systemctl", "stop", "workload-bridge.service"],
            check=False,
            capture_output=True,
        )
        self.assertIn(expected, run.call_args_list)


if __name__ == "__main__":
    unittest.main()
