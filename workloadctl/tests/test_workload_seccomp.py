#!/usr/bin/env python3
"""[security] seccomp_allow: what validate accepts, and the profile every
container of a pod runs under.

The derived profile itself is held to the baseline's checks in
test_seccomp_baseline; the generator's writing of it is in test_generator.
"""
import shutil
import tempfile
import unittest
from pathlib import Path

from tests.test_generator import run_generator, write_config
from validation import validate_workload_config
from workload_seccomp import seccomp_allow

SINGLE = {"workload": {"name": "app"}, "container": {"image": "myapp"}}

POD = {
    "workload": {"name": "stack", "mode": "pod"},
    "containers": [
        {"name": "web", "container": {"image": "web"}},
        {"name": "db", "container": {"image": "db"}},
    ],
}

VM = {"workload": {"name": "forge"},
      "vm": {"image": "/var/lib/images/forge.qcow2"}}


def _with(base, **security):
    return dict(base, security=security)


def _seccomp_errors(config):
    return [e for e in validate_workload_config(config)
            if "seccomp_allow" in e]


class TestValidate(unittest.TestCase):
    def test_a_list_of_syscall_names_is_accepted(self):
        self.assertEqual(_seccomp_errors(_with(
            SINGLE, seccomp_allow=["ptrace", "process_vm_readv"])), [])
        self.assertEqual(_seccomp_errors(_with(
            POD, seccomp_allow=["ptrace"])), [])

    def test_anything_but_a_list_of_syscall_names_is_refused(self):
        for bad in ("ptrace", ["Ptrace"], ["ptrace;"], [""], [1],
                    ["process vm"]):
            with self.subTest(bad=bad):
                self.assertTrue(_seccomp_errors(_with(
                    SINGLE, seccomp_allow=bad)))

    def test_beside_a_seccomp_profile_of_its_own_it_is_refused(self):
        """The names are added to the baseline, which seccomp= replaces."""
        self.assertTrue(_seccomp_errors(_with(
            SINGLE, seccomp_allow=["ptrace"],
            security_opt=["seccomp=/etc/containers/mine.json"])))
        pod = dict(POD, containers=[
            dict(POD["containers"][0],
                 security={"security_opt": ["seccomp=unconfined"]}),
            POD["containers"][1]])
        self.assertTrue(_seccomp_errors(_with(pod, seccomp_allow=["ptrace"])))

    def test_with_privileged_it_is_refused(self):
        self.assertTrue(_seccomp_errors(_with(
            SINGLE, seccomp_allow=["ptrace"], privileged=True)))

    def test_in_a_containers_own_security_it_is_refused(self):
        """One profile serves the workload; a per-container list would be
        silently ignored."""
        pod = dict(POD, containers=[
            dict(POD["containers"][0],
                 security={"seccomp_allow": ["ptrace"]}),
            POD["containers"][1]])
        self.assertTrue(_seccomp_errors(pod))

    def test_on_a_vm_it_is_refused(self):
        self.assertTrue(_seccomp_errors(_with(VM, seccomp_allow=["ptrace"])))

    def test_the_names_are_sorted_once_each(self):
        self.assertEqual(seccomp_allow(_with(
            SINGLE, seccomp_allow=["ptrace", "keyctl", "ptrace"])),
            ["keyctl", "ptrace"])
        self.assertEqual(seccomp_allow(SINGLE), [])


class TestAPod(unittest.TestCase):
    def setUp(self):
        self.dirs = [tempfile.mkdtemp() for _ in range(3)]
        for d in self.dirs:
            self.addCleanup(shutil.rmtree, d)

    def test_every_container_runs_under_the_derived_profile(self):
        config_dir, services_dir, sysusers_dir = self.dirs
        write_config(config_dir, "stack", """\
            [workload]
            name = "stack"
            mode = "pod"

            [security]
            seccomp_allow = ["ptrace"]

            [[containers]]
            name = "web"
            [containers.container]
            image = "web"

            [[containers]]
            name = "db"
            [containers.container]
            image = "db"
        """)
        result = run_generator(config_dir, services_dir, sysusers_dir)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        for c in ("web", "db"):
            unit = (Path(services_dir)
                    / f"workload-stack-{c}.service").read_text()
            self.assertIn("--security-opt=seccomp=/run/systemd/system/"
                          "workload-stack.seccomp.json", unit)
        self.assertTrue((Path(services_dir)
                         / "workload-stack.seccomp.json").exists())


if __name__ == "__main__":
    unittest.main()
