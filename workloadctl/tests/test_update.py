#!/usr/bin/env python3
"""Unit tests for workloadctl update/rollback functionality."""

import os
import sys
import unittest
from pathlib import Path

LIB_DIR = os.path.join(os.path.dirname(__file__), '..', 'lib')
sys.path.insert(0, LIB_DIR)

import cmd_update
from substrate import rollback_tag
from workloadctl_core import WorkloadConfig


class TestParseDuration(unittest.TestCase):
    def test_seconds(self):
        self.assertEqual(cmd_update._parse_duration("30s"), 30)
        self.assertEqual(cmd_update._parse_duration("0s"), 0)
        self.assertEqual(cmd_update._parse_duration("5s"), 5)

    def test_minutes(self):
        self.assertEqual(cmd_update._parse_duration("5m"), 300)
        self.assertEqual(cmd_update._parse_duration("1m"), 60)

    def test_hours(self):
        self.assertEqual(cmd_update._parse_duration("1h"), 3600)
        self.assertEqual(cmd_update._parse_duration("2h"), 7200)

    def test_bare_number(self):
        self.assertEqual(cmd_update._parse_duration("42"), 42)

    def test_whitespace(self):
        self.assertEqual(cmd_update._parse_duration("  30s  "), 30)


class TestRollbackTag(unittest.TestCase):
    def test_format(self):
        self.assertEqual(
            rollback_tag("pihole"),
            "localhost/workload-rollback/pihole:latest"
        )

    def test_hyphenated_name(self):
        self.assertEqual(
            rollback_tag("smb-server"),
            "localhost/workload-rollback/smb-server:latest"
        )

    def test_per_container_tag(self):
        self.assertEqual(
            rollback_tag("stack", "web"),
            "localhost/workload-rollback/stack-web:latest"
        )

    def test_none_container_matches_workload_tag(self):
        self.assertEqual(rollback_tag("stack", None), rollback_tag("stack"))


class TestContainerSpecs(unittest.TestCase):
    """WorkloadConfig.container_specs() over single- and multi-container configs."""

    def _fake(self, config, is_multi):
        class FakeConfig:
            pass
        fc = FakeConfig()
        fc.config = config
        fc.is_multi = is_multi
        fc.name = config["workload"]["name"]
        if not is_multi:
            fc.image = config["container"]["image"]
        return fc

    def test_single_container(self):
        fc = self._fake({
            "workload": {"name": "web"},
            "container": {"image": "nginx", "pull": "missing"},
        }, is_multi=False)
        self.assertEqual(
            WorkloadConfig.container_specs(fc),
            [("web", "nginx", "missing")],
        )

    def test_single_container_default_pull(self):
        fc = self._fake({
            "workload": {"name": "web"},
            "container": {"image": "nginx"},
        }, is_multi=False)
        self.assertEqual(WorkloadConfig.container_specs(fc),
                         [("web", "nginx", "missing")])

    def test_multi_container(self):
        fc = self._fake({
            "workload": {"name": "stack"},
            "containers": [
                {"name": "web", "container": {"image": "img-a", "pull": "never"}},
                {"name": "db", "container": {"image": "img-b"}},
            ],
        }, is_multi=True)
        self.assertEqual(
            WorkloadConfig.container_specs(fc),
            [("web", "img-a", "never"), ("db", "img-b", "missing")],
        )

    def test_multi_container_all_volumes(self):
        fc = self._fake({
            "workload": {"name": "stack"},
            "containers": [
                {"name": "web", "container": {"image": "a"},
                 "storage": {"volumes": ["./w:/w"]}},
                {"name": "db", "container": {"image": "b"},
                 "storage": {"volumes": ["./d:/d", "./e:/e"]}},
            ],
        }, is_multi=True)
        self.assertEqual(
            WorkloadConfig.all_volumes(fc),
            ["./w:/w", "./d:/d", "./e:/e"],
        )


class TestHealthWaitSeconds(unittest.TestCase):
    """Test _health_wait_seconds using a mock config object."""

    def _make_config(self, health_section):
        """Create a minimal object exposing the health-related WorkloadConfig API
        that _health_wait_seconds uses: container_health_blocks() returns
        (local_name, podman_name, health_dict) tuples for containers whose
        health.cmd is non-empty."""
        class FakeConfig:
            def __init__(self, health):
                self._health = health
            def has_health_check(self):
                return bool(self._health.get("cmd"))
            def container_health_blocks(self):
                if not self._health.get("cmd"):
                    return []
                return [("c", "workload-c", self._health)]
        return FakeConfig(health_section)

    def test_with_health_check(self):
        config = self._make_config({
            "cmd": "wget -qO- http://localhost/",
            "start_period": "60s",
            "interval": "30s",
        })
        self.assertEqual(cmd_update._health_wait_seconds(config), 90)

    def test_no_health_check(self):
        config = self._make_config({})
        self.assertEqual(cmd_update._health_wait_seconds(config), 0)

    def test_defaults(self):
        # Only cmd set, start_period and interval use defaults (0s and 30s)
        config = self._make_config({"cmd": "true"})
        self.assertEqual(cmd_update._health_wait_seconds(config), 30)

    def test_all_workload_health_configs(self):
        """Verify _health_wait_seconds parses every real workload's health config."""
        import tomllib
        workloads_dir = Path(os.path.dirname(__file__), '..', 'workloads.d')
        for toml_path in sorted(workloads_dir.glob("*/workload.toml")):
            with open(toml_path, "rb") as f:
                toml_config = tomllib.load(f)
            health = toml_config.get("container", {}).get("health", {})
            if not health.get("cmd"):
                continue
            # Build a fake config with the real health section
            config = self._make_config(health)
            wait = cmd_update._health_wait_seconds(config)
            self.assertGreater(wait, 0, f"{toml_path.name}: wait should be > 0")
            # Sanity: no workload should need more than 5 minutes
            self.assertLess(wait, 300, f"{toml_path.name}: wait seems too long ({wait}s)")


class TestEnabledMarker(unittest.TestCase):
    """Enabled-ness is the presence of a `.enabled` marker in the workload's
    config dir."""

    def setUp(self):
        import tempfile
        import workload_lib
        self._tmp = tempfile.mkdtemp()
        self._prev = os.environ.get("WORKLOAD_CONFIG_DIR")
        os.environ["WORKLOAD_CONFIG_DIR"] = self._tmp
        self.workload_lib = workload_lib

    def tearDown(self):
        import shutil
        if self._prev is None:
            os.environ.pop("WORKLOAD_CONFIG_DIR", None)
        else:
            os.environ["WORKLOAD_CONFIG_DIR"] = self._prev
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write(self, name, toml):
        d = Path(self._tmp) / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "workload.toml").write_text(toml)
        return d

    def test_marker_path(self):
        self.assertEqual(
            self.workload_lib.workload_enabled_marker("foo"),
            Path(self._tmp) / "foo" / ".enabled",
        )

    def test_absent_marker_is_disabled(self):
        self._write("foo", '[workload]\nname = "foo"\n[container]\nimage = "x"\n')
        self.assertFalse(self.workload_lib.workload_is_enabled("foo"))
        self.assertFalse(WorkloadConfig("foo").enabled)

    def test_present_marker_is_enabled(self):
        d = self._write("foo", '[workload]\nname = "foo"\n[container]\nimage = "x"\n')
        (d / ".enabled").touch()
        self.assertTrue(self.workload_lib.workload_is_enabled("foo"))
        self.assertTrue(WorkloadConfig("foo").enabled)


if __name__ == "__main__":
    unittest.main()
