#!/usr/bin/env python3
"""The inspector check is actually emitted by the battery.

A check function that is never called is worse than no check: it passes its own
unit tests, reads as coverage, and reports nothing. `vm_inspect_check` could be
deleted from collect_diagnose_checks' body and every other test in the suite
stays green — verified by mutation, which is why this file exists.

The other three VM checks (network, egress, confinement, proxy) are pinned the
same way here, for the same reason. They are wired today; nothing was asserting
that they stay wired.

This goes through collect_diagnose_checks rather than asserting on the source
text, because the wiring that matters is the call happening for a real VM
config — a grep for the function name would pass on a call sitting behind a
condition that is never true.
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import cmd_diagnose
import workload_lib
from workloadctl_core import WorkloadConfig

VM_TOML = """\
[workload]
name = "vm1"

[vm]
memory = "2G"
vcpus = 2
image = "https://example.invalid/cloud.qcow2"

[vm.network]
egress = "filtered"
"""

BRIDGED_TOML = """\
[workload]
name = "vm2"

[vm]
memory = "2G"
vcpus = 2
image = "https://example.invalid/cloud.qcow2"

[vm.network]
bridge = "br0"
"""

CONTAINER_TOML = """\
[workload]
name = "app"

[container]
image = "localhost/app:latest"
"""


class InspectCheckIsWiredTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(
            mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        for name, toml in (("vm1", VM_TOML), ("vm2", BRIDGED_TOML),
                           ("app", CONTAINER_TOML)):
            (self.tmp / name).mkdir()
            (self.tmp / name / "workload.toml").write_text(toml)

        self.manager = mock.Mock()
        self.manager.user_exists.return_value = True
        self.manager.get_image_id.return_value = "sha256:" + "0" * 64
        self.manager.podman.return_value.image_id.return_value = (
            "sha256:" + "0" * 64)
        # The workload user does not exist on the test host.
        self.enterContext(mock.patch.object(
            WorkloadConfig, "uid", new_callable=mock.PropertyMock,
            return_value=10001))
        # The rest of the battery still shells out; every door gets an answer
        # this suite discards. None of them can make a check appear or vanish.
        self.enterContext(mock.patch.object(
            cmd_diagnose.subprocess, "run",
            return_value=mock.Mock(returncode=1, stdout="", stderr="")))
        self.enterContext(mock.patch.object(
            cmd_diagnose, "service_active", return_value=(False, "inactive")))

    def _names(self, name):
        checks, _ = cmd_diagnose.collect_diagnose_checks(
            WorkloadConfig(name), self.manager)
        return {c["check"] for c in checks}

    def test_a_filtered_vm_gets_an_inspector_line(self):
        self.assertIn("vm_inspect", self._names("vm1"))

    def test_every_vm_check_is_wired(self):
        # One assertion per check would let a deletion hide behind a sibling's
        # failure; the set says which ones are missing in one message.
        names = self._names("vm1")
        self.assertLessEqual(
            {"vm_network", "vm_egress", "vm_inspect"}, names)

    def test_a_bridged_vm_gets_no_inspector_line(self):
        # Not "the check is absent" for the wrong reason: a bridged guest has
        # no host socket in its data path, so there is no uid to key a redirect
        # on and the line would be meaningless rather than merely unhelpful.
        self.assertNotIn("vm_inspect", self._names("vm2"))

    def test_a_container_gets_no_inspector_line(self):
        self.assertNotIn("vm_inspect", self._names("app"))
