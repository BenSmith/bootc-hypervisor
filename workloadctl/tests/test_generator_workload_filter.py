#!/usr/bin/env python3
"""Coverage for the generator's ``--workload NAME`` filter.

The CLI's single-workload call sites (enable/edit/recreate) pass ``--workload``
so a run scoped to one workload doesn't rewrite every other enabled workload's
units or enqueue a start job for them. The boot path passes no filter and
still emits the whole enabled set. Same fixture idiom as
test_generator_snapshot.py: real generator subprocess, temp config/services/
sysusers dirs.
"""

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from covhelper import python_cmd

from tests import script_env


GENERATOR = os.path.join(os.path.dirname(__file__), '..', 'generators', 'workload-generate')

_ALPHA_TOML = """\
    [workload]
    name = "alpha"

    [container]
    image = "docker.io/library/alpha:latest"
"""

_BETA_TOML = """\
    [workload]
    name = "beta"

    [container]
    image = "docker.io/library/beta:latest"
"""


def write_config(config_dir, name, toml_content, enabled=True):
    (Path(config_dir) / name).mkdir(exist_ok=True)
    path = Path(config_dir) / name / "workload.toml"
    path.write_text(textwrap.dedent(toml_content))
    if enabled:
        (Path(config_dir) / name / ".enabled").touch()
    return path


def run_generator(config_dir, services_dir, sysusers_dir, *extra_args):
    env = script_env(WORKLOAD_CONFIG_DIR=config_dir, SYSUSERS_DIR=sysusers_dir)
    return subprocess.run(
        python_cmd(GENERATOR, str(services_dir), *extra_args),
        capture_output=True, text=True, env=env,
    )


class TestWorkloadFilter(unittest.TestCase):
    """--workload NAME narrows emission to one workload; no filter emits all."""

    def setUp(self):
        self.config_dir = self.enterContext(tempfile.TemporaryDirectory())
        self.services_dir = self.enterContext(tempfile.TemporaryDirectory())
        self.sysusers_dir = self.enterContext(tempfile.TemporaryDirectory())
        write_config(self.config_dir, "alpha", _ALPHA_TOML)
        write_config(self.config_dir, "beta", _BETA_TOML)

    def _files(self):
        services = {p.name for p in Path(self.services_dir).glob("workload-*")}
        services |= {p.name for p in Path(self.sysusers_dir).glob("workload-*.conf")}
        wants = {p.name for p in
                 (Path(self.services_dir) / "multi-user.target.wants").glob("workload-*")}
        return services, wants

    def test_filter_emits_only_named_workload(self):
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir,
                               "--workload", "alpha")
        self.assertEqual(result.returncode, 0, result.stderr)

        services, wants = self._files()
        self.assertIn("workload-alpha.service", services)
        self.assertIn("workload-alpha.conf", services)
        self.assertIn("workload-alpha.service", wants)

        self.assertNotIn("workload-beta.service", services)
        self.assertNotIn("workload-beta.conf", services)
        self.assertNotIn("workload-beta.service", wants)

    def test_no_filter_emits_every_enabled_workload(self):
        # The boot path invokes the generator with no --workload; both
        # workloads' files must still land, unfiltered.
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0, result.stderr)

        services, wants = self._files()
        self.assertIn("workload-alpha.service", services)
        self.assertIn("workload-beta.service", services)
        self.assertIn("workload-alpha.service", wants)
        self.assertIn("workload-beta.service", wants)

    def test_filter_equals_form(self):
        # --workload=NAME (single argv token) must behave identically to the
        # space-separated form.
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir,
                               "--workload=alpha")
        self.assertEqual(result.returncode, 0, result.stderr)

        services, wants = self._files()
        self.assertIn("workload-alpha.service", services)
        self.assertNotIn("workload-beta.service", services)
        self.assertNotIn("workload-beta.service", wants)

    def test_filter_unknown_workload_writes_nothing_and_exits_zero(self):
        # A filter naming a workload that doesn't exist (e.g. a stale CLI
        # invocation racing a purge) must never fail the boot: exit 0, no
        # units written for anyone.
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir,
                               "--workload", "nonexistent")
        self.assertEqual(result.returncode, 0, result.stderr)

        services, wants = self._files()
        self.assertEqual(services, set())
        self.assertEqual(wants, set())


if __name__ == "__main__":
    unittest.main()
