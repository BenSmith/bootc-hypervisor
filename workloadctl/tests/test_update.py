#!/usr/bin/env python3
"""Unit tests for workloadctl update/rollback functionality."""

import importlib.util
import os
import sys
import unittest
from pathlib import Path

# Import workloadctl as a module (hyphenated filename requires importlib)
LIB_DIR = os.path.join(os.path.dirname(__file__), '..', 'lib')
sys.path.insert(0, LIB_DIR)

_ctl_path = os.path.join(os.path.dirname(__file__), '..', 'bin', 'workloadctl')
_loader = importlib.machinery.SourceFileLoader("workload_ctl", _ctl_path)
_spec = importlib.util.spec_from_loader("workload_ctl", _loader)
wctl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wctl)


class TestParseDuration(unittest.TestCase):
    def test_seconds(self):
        self.assertEqual(wctl._parse_duration("30s"), 30)
        self.assertEqual(wctl._parse_duration("0s"), 0)
        self.assertEqual(wctl._parse_duration("5s"), 5)

    def test_minutes(self):
        self.assertEqual(wctl._parse_duration("5m"), 300)
        self.assertEqual(wctl._parse_duration("1m"), 60)

    def test_hours(self):
        self.assertEqual(wctl._parse_duration("1h"), 3600)
        self.assertEqual(wctl._parse_duration("2h"), 7200)

    def test_bare_number(self):
        self.assertEqual(wctl._parse_duration("42"), 42)

    def test_whitespace(self):
        self.assertEqual(wctl._parse_duration("  30s  "), 30)


class TestRollbackTag(unittest.TestCase):
    def test_format(self):
        self.assertEqual(
            wctl.rollback_tag("pihole"),
            "localhost/workload-rollback/pihole:latest"
        )

    def test_hyphenated_name(self):
        self.assertEqual(
            wctl.rollback_tag("smb-server"),
            "localhost/workload-rollback/smb-server:latest"
        )


class TestHealthWaitSeconds(unittest.TestCase):
    """Test _health_wait_seconds using a mock config object."""

    def _make_config(self, health_section):
        """Create a minimal object with the config dict that _health_wait_seconds reads."""
        class FakeConfig:
            def __init__(self, config):
                self.config = config
            def has_health_check(self):
                return bool(self.config.get("container", {}).get("health", {}).get("cmd", ""))
        return FakeConfig({"container": {"health": health_section}})

    def test_with_health_check(self):
        config = self._make_config({
            "cmd": "wget -qO- http://localhost/",
            "start_period": "60s",
            "interval": "30s",
        })
        self.assertEqual(wctl._health_wait_seconds(config), 90)

    def test_no_health_check(self):
        config = self._make_config({})
        self.assertEqual(wctl._health_wait_seconds(config), 0)

    def test_defaults(self):
        # Only cmd set, start_period and interval use defaults (0s and 30s)
        config = self._make_config({"cmd": "true"})
        self.assertEqual(wctl._health_wait_seconds(config), 30)

    def test_all_workload_health_configs(self):
        """Verify _health_wait_seconds parses every real workload's health config."""
        import tomllib
        workloads_dir = Path(os.path.dirname(__file__), '..', 'workloads.d')
        for toml_path in sorted(workloads_dir.glob("*.toml")):
            if toml_path.name == "schema-reference.toml":
                continue
            with open(toml_path, "rb") as f:
                toml_config = tomllib.load(f)
            health = toml_config.get("container", {}).get("health", {})
            if not health.get("cmd"):
                continue
            # Build a fake config with the real health section
            config = self._make_config(health)
            wait = wctl._health_wait_seconds(config)
            self.assertGreater(wait, 0, f"{toml_path.name}: wait should be > 0")
            # Sanity: no workload should need more than 5 minutes
            self.assertLess(wait, 300, f"{toml_path.name}: wait seems too long ({wait}s)")


if __name__ == "__main__":
    unittest.main()
