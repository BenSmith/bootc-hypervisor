#!/usr/bin/env python3
"""Structural unit oracle for the generator.

One parametrized check that replaces dozens of brittle `assertIn`s: for a
matrix of workload shapes (single/pod/bridge/vm x userns x network mode) it
asserts *structure*, never exact byte content — that is the snapshot suite's
job. Three properties per emitted unit:

  (a) it parses as an INI/systemd unit (configparser, strict=False so repeated
      keys like ExecStartPre are tolerated);
  (b) it has the required sections ([Unit], [Service]); [Install] appears on the
      main workload unit and never on its pod/net head or member helper units;
  (c) it contains none of the GENERATOR_OWNED opt-in tokens (--privileged,
      --userns=host, --network=host, --network=none) unless the config asked
      for them — a generator leaking host networking or privilege into a unit
      that did not request it is a real security regression.

No root required; the generator writes into temp dirs.
"""

import configparser
import os
import shutil
import tempfile
import textwrap
import unittest
from pathlib import Path

from test_generator import run_generator, write_config

# Opt-in tokens the generator must never emit unless the config requested them.
# Each is a substring searched for in every per-workload service unit.
GENERATOR_OWNED_TOKENS = (
    "--privileged",
    "--userns=host",
    "--network=host",
    "--network=none",
)


class Case:
    """A generator input plus the structural facts we assert against its output."""

    def __init__(self, name, toml, *, containers=(), requested=()):
        self.name = name
        self.toml = textwrap.dedent(toml)
        # Container names for pod/bridge member units; empty for single/vm.
        self.containers = tuple(containers)
        # Opt-in tokens this config legitimately requested (absence not asserted).
        self.requested = frozenset(requested)


CASES = [
    Case("single", """\
        [workload]
        name = "single"
        [container]
        image = "docker.io/nginx:latest"
        [network]
        ports = ["8080:80"]
    """),
    Case("grp", """\
        [workload]
        name = "grp"
        mode = "pod"
        [[containers]]
        name = "db"
        [containers.container]
        image = "postgres:16"
        [[containers]]
        name = "web"
        [containers.container]
        image = "myapp:latest"
    """, containers=("db", "web")),
    Case("brg", """\
        [workload]
        name = "brg"
        mode = "bridge"
        [[containers]]
        name = "web"
        [containers.container]
        image = "myapp:latest"
    """, containers=("web",)),
    Case("fedora-vm", """\
        [workload]
        name = "fedora-vm"
        [vm.network]
        egress = "open"

        [vm]
        vcpus = 2
        memory = "2048M"
        cloud_image_url = "https://example.com/cloud.qcow2"
        cloud_image_checksum = "sha256:%s"
        data_disk_size = "20G"
        user = "fedora"
    """ % ("d" * 64)),
    Case("uns", """\
        [workload]
        name = "uns"
        [container]
        image = "docker.io/nginx:latest"
        [security]
        userns = "host"
        unsafe_host_userns = true
    """, requested=("--userns=host",)),
    Case("nethost", """\
        [workload]
        name = "nethost"
        [container]
        image = "docker.io/nginx:latest"
        [network]
        mode = "host"
    """, requested=("--network=host",)),
    Case("netnone", """\
        [workload]
        name = "netnone"
        [container]
        image = "docker.io/nginx:latest"
        [network]
        mode = "none"
    """, requested=("--network=none",)),
    Case("secretenv", """\
        [workload]
        name = "secretenv"
        [container]
        image = "docker.io/nginx:latest"
        [container.environment]
        DB_PASSWORD = "${SECRET:dbpass}"
    """),
    Case("vols", """\
        [workload]
        name = "vols"
        [container]
        image = "docker.io/nginx:latest"
        [storage]
        volumes = ["./config:/config:ro", "/mnt/data:/data"]
    """),
]


def _parse_unit(text):
    """Parse a systemd unit as INI. strict=False tolerates repeated keys
    (systemd permits multiple ExecStartPre=); interpolation off so `%` and
    `$` in values are literal; `=` is the only delimiter."""
    parser = configparser.ConfigParser(
        strict=False, interpolation=None, delimiters=("=",)
    )
    parser.read_string(text)
    return parser


class TestUnitOracle(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d, ignore_errors=True)

    def _generate(self, case):
        write_config(self.config_dir, case.name, case.toml)
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(
            result.returncode, 0,
            msg=f"[{case.name}] generator failed:\n{result.stderr}",
        )

    def test_matrix(self):
        for case in CASES:
            with self.subTest(case=case.name):
                self._generate(case)
                self._check(case)
                # Isolate cases: each starts from empty service/config dirs.
                for d in (self.config_dir, self.services_dir, self.sysusers_dir):
                    shutil.rmtree(d, ignore_errors=True)
                    os.mkdir(d)

    def _check(self, case):
        main = f"workload-{case.name}.service"
        # Helper units that must never carry [Install]: the pod/net head and
        # every per-container member. Shared infra (vm bridge, virtiofs, build)
        # is out of this oracle's scope.
        helpers = {
            f"workload-{case.name}-pod.service",
            f"workload-{case.name}-net.service",
        } | {f"workload-{case.name}-{c}.service" for c in case.containers}

        emitted = {p.name: p for p in Path(self.services_dir).glob("*.service")}
        self.assertIn(main, emitted, f"[{case.name}] no main unit {main}")

        for fname, path in emitted.items():
            text = path.read_text()
            # (a) parses as a unit.
            try:
                parser = _parse_unit(text)
            except configparser.Error as e:
                self.fail(f"[{case.name}] {fname} did not parse as a unit: {e}")

            # (b) required sections + [Install] placement.
            self.assertIn("Unit", parser, f"[{case.name}] {fname} missing [Unit]")
            self.assertIn("Service", parser, f"[{case.name}] {fname} missing [Service]")
            if fname == main:
                self.assertIn(
                    "Install", parser,
                    f"[{case.name}] main unit {fname} missing [Install]",
                )
            elif fname in helpers:
                self.assertNotIn(
                    "Install", parser,
                    f"[{case.name}] helper unit {fname} must not carry [Install]",
                )

            # (c) no un-requested generator-owned opt-in tokens. Scope to the
            # workload's own units (main + helpers); skip shared infra units.
            if fname == main or fname in helpers:
                for token in GENERATOR_OWNED_TOKENS:
                    if token in case.requested:
                        continue
                    self.assertNotIn(
                        token, text,
                        f"[{case.name}] {fname} leaked un-requested {token!r}",
                    )


if __name__ == "__main__":
    unittest.main()
