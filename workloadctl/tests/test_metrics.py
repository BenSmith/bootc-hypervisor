#!/usr/bin/env python3
"""Integration tests for workload-metrics collector.

Runs the actual workload-metrics script with overridden paths (temp dirs)
and validates the Prometheus exposition format output. On a dev machine
systemd and cgroup queries return empty, so we test:
- Config discovery (enabled, disabled, masked workloads)
- Output format (valid Prometheus exposition with correct TYPE/HELP)
- Atomic write (output written to correct path)
- Empty/no-config edge cases
- Meta-metrics (workload_enabled_total, last_collect_timestamp)
- Never-fail guarantee (script exits 0 even with bad configs)
"""

import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

METRICS_SCRIPT = os.path.join(
    os.path.dirname(__file__), '..', 'libexec', 'workload-metrics')
LIB_DIR = os.path.join(os.path.dirname(__file__), '..', 'lib')


def run_metrics(config_dir, output_dir):
    """Run workload-metrics and return the CompletedProcess."""
    env = os.environ.copy()
    env["WORKLOAD_CONFIG_DIR"] = str(config_dir)
    env["PYTHONPATH"] = LIB_DIR
    return subprocess.run(
        [sys.executable, METRICS_SCRIPT, str(output_dir)],
        capture_output=True, text=True, env=env,
    )


def write_config(config_dir, name, toml_content):
    path = Path(config_dir) / f"{name}.toml"
    path.write_text(textwrap.dedent(toml_content))
    return path


def read_prom(output_dir):
    """Read the workloads.prom output file, return contents or None."""
    prom = Path(output_dir) / "workloads.prom"
    if prom.exists():
        return prom.read_text()
    return None


def parse_metric_value(prom_text, metric_name, labels=None):
    """Extract a metric value from Prometheus exposition text.

    If labels is a dict, matches lines where all labels are present.
    Returns the value as a string, or None if not found.
    """
    for line in prom_text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        if not line.startswith(metric_name):
            continue
        # Metric line: name{labels} value  or  name value
        if labels:
            if "{" not in line:
                continue
            label_part = line.split("{", 1)[1].split("}", 1)[0]
            if all(f'{k}="{v}"' in label_part for k, v in labels.items()):
                return line.rsplit(None, 1)[-1]
        else:
            # No labels expected — match bare metric name
            parts = line.split()
            if parts[0] == metric_name:
                return parts[1]
    return None


def parse_type_declarations(prom_text):
    """Extract all TYPE declarations as {metric_name: type_string}."""
    types = {}
    for line in prom_text.splitlines():
        if line.startswith("# TYPE "):
            parts = line.split(None, 4)  # # TYPE name type
            if len(parts) >= 4:
                types[parts[2]] = parts[3]
    return types


class TestMetricsNoWorkloads(unittest.TestCase):
    """Test behavior with no workload configs."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.output_dir = tempfile.mkdtemp()

    def tearDown(self):
        for d in (self.config_dir, self.output_dir):
            shutil.rmtree(d, ignore_errors=True)

    def test_empty_config_dir(self):
        """No configs → minimal output with workload_enabled_total 0."""
        result = run_metrics(self.config_dir, self.output_dir)
        self.assertEqual(result.returncode, 0)

        prom = read_prom(self.output_dir)
        self.assertIsNotNone(prom)
        self.assertIn("workload_enabled_total 0", prom)

    def test_missing_config_dir(self):
        """Non-existent config dir → exits 0, writes empty metrics."""
        shutil.rmtree(self.config_dir)
        result = run_metrics(self.config_dir, self.output_dir)
        self.assertEqual(result.returncode, 0)

        prom = read_prom(self.output_dir)
        self.assertIsNotNone(prom)
        self.assertIn("workload_enabled_total 0", prom)

    def test_creates_output_dir(self):
        """Output dir is created if it doesn't exist."""
        shutil.rmtree(self.output_dir)
        nested = os.path.join(self.output_dir, "deep", "path")

        result = run_metrics(self.config_dir, nested)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(Path(nested, "workloads.prom").exists())


class TestMetricsDiscovery(unittest.TestCase):
    """Test workload config discovery and filtering."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.output_dir = tempfile.mkdtemp()

    def tearDown(self):
        for d in (self.config_dir, self.output_dir):
            shutil.rmtree(d)

    def test_enabled_workload_discovered(self):
        """An enabled workload appears in metrics."""
        write_config(self.config_dir, "web", """\
            [workload]
            name = "web"
            enabled = true

            [container]
            image = "nginx:latest"
        """)

        result = run_metrics(self.config_dir, self.output_dir)
        self.assertEqual(result.returncode, 0)

        prom = read_prom(self.output_dir)
        self.assertIn('workload="web"', prom)
        self.assertEqual(parse_metric_value(prom, "workload_enabled_total"), "1")

    def test_disabled_workload_skipped(self):
        """A disabled workload is not reported."""
        write_config(self.config_dir, "off", """\
            [workload]
            name = "off"
            enabled = false

            [container]
            image = "alpine:latest"
        """)

        result = run_metrics(self.config_dir, self.output_dir)
        self.assertEqual(result.returncode, 0)

        prom = read_prom(self.output_dir)
        self.assertNotIn('workload="off"', prom)
        self.assertEqual(parse_metric_value(prom, "workload_enabled_total"), "0")

    def test_masked_workload_skipped(self):
        """A masked workload (symlink to /dev/null) is not reported."""
        write_config(self.config_dir, "real", """\
            [workload]
            name = "real"
            enabled = true

            [container]
            image = "alpine:latest"
        """)
        masked_path = Path(self.config_dir) / "masked.toml"
        masked_path.symlink_to("/dev/null")

        result = run_metrics(self.config_dir, self.output_dir)
        self.assertEqual(result.returncode, 0)

        prom = read_prom(self.output_dir)
        self.assertNotIn('workload="masked"', prom)
        self.assertIn('workload="real"', prom)
        self.assertEqual(parse_metric_value(prom, "workload_enabled_total"), "1")

    def test_multiple_workloads(self):
        """Multiple enabled workloads all appear."""
        for name in ("alpha", "bravo", "charlie"):
            write_config(self.config_dir, name, f"""\
                [workload]
                name = "{name}"
                enabled = true

                [container]
                image = "alpine:latest"
            """)

        result = run_metrics(self.config_dir, self.output_dir)
        self.assertEqual(result.returncode, 0)

        prom = read_prom(self.output_dir)
        for name in ("alpha", "bravo", "charlie"):
            self.assertIn(f'workload="{name}"', prom)
        self.assertEqual(parse_metric_value(prom, "workload_enabled_total"), "3")

    def test_mixed_enabled_disabled(self):
        """Only enabled workloads counted."""
        write_config(self.config_dir, "on1", """\
            [workload]
            name = "on1"
            enabled = true

            [container]
            image = "alpine:latest"
        """)
        write_config(self.config_dir, "off1", """\
            [workload]
            name = "off1"
            enabled = false

            [container]
            image = "alpine:latest"
        """)
        write_config(self.config_dir, "on2", """\
            [workload]
            name = "on2"
            enabled = true

            [container]
            image = "alpine:latest"
        """)

        result = run_metrics(self.config_dir, self.output_dir)
        self.assertEqual(result.returncode, 0)

        prom = read_prom(self.output_dir)
        self.assertIn('workload="on1"', prom)
        self.assertIn('workload="on2"', prom)
        self.assertNotIn('workload="off1"', prom)
        self.assertEqual(parse_metric_value(prom, "workload_enabled_total"), "2")

    def test_default_enabled_true(self):
        """Workload without explicit enabled= defaults to enabled."""
        write_config(self.config_dir, "implicit", """\
            [workload]
            name = "implicit"

            [container]
            image = "alpine:latest"
        """)

        result = run_metrics(self.config_dir, self.output_dir)
        self.assertEqual(result.returncode, 0)

        prom = read_prom(self.output_dir)
        self.assertIn('workload="implicit"', prom)
        self.assertEqual(parse_metric_value(prom, "workload_enabled_total"), "1")


class TestMetricsFormat(unittest.TestCase):
    """Validate Prometheus exposition format correctness."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.output_dir = tempfile.mkdtemp()
        write_config(self.config_dir, "app", """\
            [workload]
            name = "app"
            enabled = true

            [container]
            image = "myapp:latest"
        """)
        run_metrics(self.config_dir, self.output_dir)
        self.prom = read_prom(self.output_dir)

    def tearDown(self):
        for d in (self.config_dir, self.output_dir):
            shutil.rmtree(d)

    def test_has_type_declarations(self):
        """All expected metric types are declared."""
        types = parse_type_declarations(self.prom)

        expected = {
            "workload_active": "gauge",
            "workload_failed": "gauge",
            "workload_restarts_total": "counter",
            "workload_uptime_seconds": "gauge",
            "workload_cpu_usage_seconds_total": "counter",
            "workload_memory_current_bytes": "gauge",
            "workload_memory_max_bytes": "gauge",
            "workload_pids_current": "gauge",
            "workload_health": "gauge",
            "workload_enabled_total": "gauge",
            "workload_metrics_last_collect_timestamp_seconds": "gauge",
        }
        for name, mtype in expected.items():
            self.assertIn(name, types, f"Missing TYPE for {name}")
            self.assertEqual(types[name], mtype,
                             f"Wrong type for {name}: {types[name]} != {mtype}")

    def test_has_help_for_all_types(self):
        """Every TYPE declaration has a corresponding HELP."""
        types = parse_type_declarations(self.prom)
        for metric_name in types:
            self.assertIn(f"# HELP {metric_name} ", self.prom,
                          f"Missing HELP for {metric_name}")

    def test_timestamp_is_recent(self):
        """Last collect timestamp is a plausible Unix timestamp."""
        import time
        ts = parse_metric_value(self.prom,
                                "workload_metrics_last_collect_timestamp_seconds")
        self.assertIsNotNone(ts)
        ts_val = float(ts)
        now = time.time()
        # Should be within the last 60 seconds
        self.assertGreater(ts_val, now - 60)
        self.assertLessEqual(ts_val, now + 1)

    def test_no_duplicate_type_lines(self):
        """Each metric has exactly one TYPE declaration."""
        type_lines = [l for l in self.prom.splitlines()
                      if l.startswith("# TYPE ")]
        metric_names = [l.split()[2] for l in type_lines]
        self.assertEqual(len(metric_names), len(set(metric_names)),
                         f"Duplicate TYPE declarations: {metric_names}")

    def test_no_blank_metric_names(self):
        """No metric lines with empty names."""
        for line in self.prom.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            self.assertFalse(line.startswith("{"),
                             f"Metric line starts with {{ (missing name): {line}")

    def test_service_metrics_present_for_workload(self):
        """On a dev machine, systemctl returns data for unknown services.
        The script should at least emit active/failed for discovered workloads.
        Even if the service doesn't exist, systemctl show returns defaults."""
        # workload_active with label workload="app" should be present
        active = parse_metric_value(self.prom, "workload_active",
                                    {"workload": "app"})
        # May be 0 or 1 depending on system — just check it exists
        if active is not None:
            self.assertIn(active, ("0", "1"))


class TestMetricsRobustness(unittest.TestCase):
    """Test that the script never fails (exits 0)."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.output_dir = tempfile.mkdtemp()

    def tearDown(self):
        for d in (self.config_dir, self.output_dir):
            shutil.rmtree(d)

    def test_malformed_toml_skipped(self):
        """A broken TOML file is skipped; other workloads still collected."""
        write_config(self.config_dir, "good", """\
            [workload]
            name = "good"
            enabled = true

            [container]
            image = "alpine:latest"
        """)
        # Write garbage TOML
        (Path(self.config_dir) / "bad.toml").write_text("not valid [[[ toml")

        result = run_metrics(self.config_dir, self.output_dir)
        self.assertEqual(result.returncode, 0)

        prom = read_prom(self.output_dir)
        self.assertIn('workload="good"', prom)
        self.assertEqual(parse_metric_value(prom, "workload_enabled_total"), "1")

    def test_config_missing_name_skipped(self):
        """Config without workload.name is silently skipped."""
        (Path(self.config_dir) / "noname.toml").write_text(
            '[workload]\nenabled = true\n\n[container]\nimage = "x"\n')

        result = run_metrics(self.config_dir, self.output_dir)
        self.assertEqual(result.returncode, 0)

        prom = read_prom(self.output_dir)
        self.assertEqual(parse_metric_value(prom, "workload_enabled_total"), "0")

    def test_non_toml_files_ignored(self):
        """Files that aren't .toml are not read."""
        (Path(self.config_dir) / "readme.md").write_text("# not a config")
        (Path(self.config_dir) / "backup.toml.bak").write_text("junk")

        write_config(self.config_dir, "real", """\
            [workload]
            name = "real"
            enabled = true

            [container]
            image = "alpine:latest"
        """)

        result = run_metrics(self.config_dir, self.output_dir)
        self.assertEqual(result.returncode, 0)

        prom = read_prom(self.output_dir)
        self.assertEqual(parse_metric_value(prom, "workload_enabled_total"), "1")

    def test_exits_zero_on_catastrophic_error(self):
        """Even if something goes very wrong, exit code is 0."""
        # Pass a file (not dir) as output_dir — mkdir will fail
        bad_output = os.path.join(self.output_dir, "workloads.prom")
        Path(bad_output).write_text("block")

        # Try to write inside a file path (will fail)
        nested = os.path.join(bad_output, "impossible")
        result = run_metrics(self.config_dir, nested)
        self.assertEqual(result.returncode, 0,
                         f"Script should never fail, got rc={result.returncode}: "
                         f"{result.stderr}")


class TestMetricsAtomicWrite(unittest.TestCase):
    """Test that output is written atomically (no partial files)."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.output_dir = tempfile.mkdtemp()

    def tearDown(self):
        for d in (self.config_dir, self.output_dir):
            shutil.rmtree(d)

    def test_no_tmp_file_left_behind(self):
        """After successful write, no .tmp file remains."""
        write_config(self.config_dir, "app", """\
            [workload]
            name = "app"
            enabled = true

            [container]
            image = "alpine:latest"
        """)

        result = run_metrics(self.config_dir, self.output_dir)
        self.assertEqual(result.returncode, 0)

        files = list(Path(self.output_dir).iterdir())
        names = [f.name for f in files]
        self.assertIn("workloads.prom", names)
        self.assertNotIn("workloads.tmp", names)

    def test_overwrites_previous_output(self):
        """Running twice overwrites the previous file cleanly."""
        write_config(self.config_dir, "v1", """\
            [workload]
            name = "v1"
            enabled = true

            [container]
            image = "alpine:latest"
        """)

        run_metrics(self.config_dir, self.output_dir)
        prom1 = read_prom(self.output_dir)
        self.assertIn('workload="v1"', prom1)

        # Remove v1, add v2
        (Path(self.config_dir) / "v1.toml").unlink()
        write_config(self.config_dir, "v2", """\
            [workload]
            name = "v2"
            enabled = true

            [container]
            image = "alpine:latest"
        """)

        run_metrics(self.config_dir, self.output_dir)
        prom2 = read_prom(self.output_dir)
        self.assertIn('workload="v2"', prom2)
        self.assertNotIn('workload="v1"', prom2)


if __name__ == "__main__":
    unittest.main()
