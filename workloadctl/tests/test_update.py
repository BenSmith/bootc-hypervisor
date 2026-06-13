#!/usr/bin/env python3
"""Unit tests for workloadctl update/rollback functionality."""

import os
import sys
import unittest
from pathlib import Path

LIB_DIR = os.path.join(os.path.dirname(__file__), '..', 'lib')
sys.path.insert(0, LIB_DIR)

import cmd_lifecycle
import cmd_update
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
            cmd_update.rollback_tag("pihole"),
            "localhost/workload-rollback/pihole:latest"
        )

    def test_hyphenated_name(self):
        self.assertEqual(
            cmd_update.rollback_tag("smb-server"),
            "localhost/workload-rollback/smb-server:latest"
        )

    def test_per_container_tag(self):
        self.assertEqual(
            cmd_update.rollback_tag("stack", "web"),
            "localhost/workload-rollback/stack-web:latest"
        )

    def test_none_container_matches_workload_tag(self):
        self.assertEqual(cmd_update.rollback_tag("stack", None), cmd_update.rollback_tag("stack"))


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
        for toml_path in sorted(workloads_dir.glob("*.toml")):
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


class TestReplaceWorkloadEnabled(unittest.TestCase):
    """The cmd_enable rewrite must only touch [workload].enabled, even if
    some other section happens to have an `enabled = ...` line."""

    def test_flip_false_to_true(self):
        src = "[workload]\nname = \"x\"\nenabled = false\n"
        out, had = cmd_lifecycle._replace_workload_enabled(src, "true")
        self.assertIn("enabled = true", out)
        self.assertNotIn("enabled = false", out)
        self.assertTrue(had)

    def test_flip_true_to_false(self):
        src = "[workload]\nname = \"x\"\nenabled = true\n"
        out, had = cmd_lifecycle._replace_workload_enabled(src, "false")
        self.assertIn("enabled = false", out)
        self.assertNotIn("enabled = true", out)
        self.assertTrue(had)

    def test_insert_when_missing(self):
        src = "[workload]\nname = \"x\"\n"
        out, had = cmd_lifecycle._replace_workload_enabled(src, "true")
        self.assertIn("enabled = true", out)
        self.assertFalse(had)

    def test_remove_when_present(self):
        src = "[workload]\nname = \"x\"\nenabled = true\n"
        out, had = cmd_lifecycle._replace_workload_enabled(src, None)
        self.assertNotIn("enabled", out)
        self.assertTrue(had)

    def test_does_not_touch_other_sections(self):
        """A future [[containers]] entry (or any other table) with its own
        `enabled` field must be left alone — only [workload].enabled flips."""
        src = (
            "[workload]\n"
            "name = \"x\"\n"
            "enabled = false\n"
            "\n"
            "[[containers]]\n"
            "name = \"web\"\n"
            "enabled = false   # hypothetical per-container field\n"
        )
        out, had = cmd_lifecycle._replace_workload_enabled(src, "true")
        # [workload].enabled flipped:
        self.assertIn("[workload]", out)
        workload_section = out.split("[[containers]]")[0]
        self.assertIn("enabled = true", workload_section)
        # [[containers]] section untouched:
        containers_section = out.split("[[containers]]")[1]
        self.assertIn("enabled = false", containers_section)
        self.assertTrue(had)

    def test_first_match_only(self):
        """If [workload] somehow contains two enabled lines, only the first
        is changed — count=1 keeps the operation deterministic."""
        src = (
            "[workload]\n"
            "enabled = false\n"
            "enabled = false\n"
        )
        out, _ = cmd_lifecycle._replace_workload_enabled(src, "true")
        # Exactly one true, exactly one false
        self.assertEqual(out.count("enabled = true"), 1)
        self.assertEqual(out.count("enabled = false"), 1)

    def test_no_workload_section_creates_one(self):
        src = "[container]\nimage = \"x\"\n"
        out, had = cmd_lifecycle._replace_workload_enabled(src, "true")
        self.assertIn("[workload]", out)
        self.assertIn("enabled = true", out)
        self.assertFalse(had)


if __name__ == "__main__":
    unittest.main()
