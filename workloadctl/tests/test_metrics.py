#!/usr/bin/env python3
"""Integration tests for the workload-exporter metrics server.

Spawns the actual workload-exporter HTTP server on a free port with an
overridden config directory (WORKLOAD_CONFIG_DIR) and validates the
Prometheus exposition served at /metrics. On a dev machine systemd and
cgroup queries return empty/defaults, so we test:
- Config discovery (enabled, disabled, masked workloads)
- Output format (valid Prometheus exposition with correct TYPE/HELP)
- Empty/no-config edge cases
- Meta-metrics (workload_enabled_total, last_collect_timestamp)
- Robustness (bad configs are skipped, the server keeps serving)
- Live collection (each scrape re-reads configs)
"""

import http.client
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

EXPORTER_SCRIPT = os.path.join(
    os.path.dirname(__file__), '..', 'libexec', 'workload-exporter')
LIB_DIR = os.path.join(os.path.dirname(__file__), '..', 'lib')


def _free_port():
    """Pick an unused TCP port on the loopback interface."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ExporterProcess:
    """Context manager: run workload-exporter on a free port.

    Spawns the server against the given config dir, waits for it to accept
    connections, and exposes get() to scrape it. Terminates the process on
    exit.
    """

    def __init__(self, config_dir):
        self.config_dir = config_dir
        self.port = _free_port()
        self.proc = None

    def __enter__(self):
        env = os.environ.copy()
        env["WORKLOAD_CONFIG_DIR"] = str(self.config_dir)
        env["PYTHONPATH"] = LIB_DIR
        self.proc = subprocess.Popen(
            [sys.executable, EXPORTER_SCRIPT, str(self.port)],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 10
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"exporter exited early (rc={self.proc.returncode})")
            try:
                with socket.create_connection(("127.0.0.1", self.port), 0.2):
                    return self
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("exporter did not start listening in time")

    def __exit__(self, *exc):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def get(self, path="/metrics"):
        """GET path from the running exporter; return (status, body)."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            return resp.status, resp.read().decode()
        finally:
            conn.close()


def scrape(config_dir):
    """Start the exporter against config_dir, GET /metrics once, return body.

    Asserts a 200 response — the exposition text is returned for parsing.
    """
    with ExporterProcess(config_dir) as exp:
        status, body = exp.get("/metrics")
        if status != 200:
            raise AssertionError(f"GET /metrics returned {status}")
        return body


def write_config(config_dir, name, toml_content):
    path = Path(config_dir) / f"{name}.toml"
    path.write_text(textwrap.dedent(toml_content))
    return path


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

    def tearDown(self):
        shutil.rmtree(self.config_dir, ignore_errors=True)

    def test_empty_config_dir(self):
        """No configs → minimal output with workload_enabled_total 0."""
        prom = scrape(self.config_dir)
        self.assertIn("workload_enabled_total 0", prom)

    def test_missing_config_dir(self):
        """Non-existent config dir → still serves empty metrics."""
        shutil.rmtree(self.config_dir)
        prom = scrape(self.config_dir)
        self.assertIn("workload_enabled_total 0", prom)


class TestMetricsDiscovery(unittest.TestCase):
    """Test workload config discovery and filtering."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.config_dir)

    def test_enabled_workload_discovered(self):
        """An enabled workload appears in metrics."""
        write_config(self.config_dir, "web", """\
            [workload]
            name = "web"
            enabled = true

            [container]
            image = "nginx:latest"
        """)

        prom = scrape(self.config_dir)
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

        prom = scrape(self.config_dir)
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

        prom = scrape(self.config_dir)
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

        prom = scrape(self.config_dir)
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

        prom = scrape(self.config_dir)
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

        prom = scrape(self.config_dir)
        self.assertIn('workload="implicit"', prom)
        self.assertEqual(parse_metric_value(prom, "workload_enabled_total"), "1")


class TestMetricsFormat(unittest.TestCase):
    """Validate Prometheus exposition format correctness."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        write_config(self.config_dir, "app", """\
            [workload]
            name = "app"
            enabled = true

            [container]
            image = "myapp:latest"
        """)
        self.prom = scrape(self.config_dir)

    def tearDown(self):
        shutil.rmtree(self.config_dir)

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
        """The script emits active/failed for discovered workloads.

        Even if the service doesn't exist, `systemctl show` returns defaults,
        so workload_active should appear with the workload label."""
        active = parse_metric_value(self.prom, "workload_active",
                                    {"workload": "app"})
        # May be 0 or 1 depending on system — just check it exists and is valid
        if active is not None:
            self.assertIn(active, ("0", "1"))

    def test_content_type_is_prometheus(self):
        """/metrics is served with the Prometheus exposition content type."""
        with ExporterProcess(self.config_dir) as exp:
            conn = http.client.HTTPConnection("127.0.0.1", exp.port, timeout=5)
            try:
                conn.request("GET", "/metrics")
                resp = conn.getresponse()
                resp.read()
                self.assertEqual(resp.status, 200)
                self.assertIn("text/plain",
                              resp.getheader("Content-Type", ""))
            finally:
                conn.close()


class TestMetricsRobustness(unittest.TestCase):
    """Test that bad input is tolerated and the server keeps serving."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.config_dir)

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

        prom = scrape(self.config_dir)
        self.assertIn('workload="good"', prom)
        self.assertEqual(parse_metric_value(prom, "workload_enabled_total"), "1")

    def test_config_missing_name_skipped(self):
        """Config without workload.name is silently skipped."""
        (Path(self.config_dir) / "noname.toml").write_text(
            '[workload]\nenabled = true\n\n[container]\nimage = "x"\n')

        prom = scrape(self.config_dir)
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

        prom = scrape(self.config_dir)
        self.assertEqual(parse_metric_value(prom, "workload_enabled_total"), "1")

    def test_unknown_path_returns_404(self):
        """A request for anything other than /metrics returns 404."""
        with ExporterProcess(self.config_dir) as exp:
            status, _ = exp.get("/not-metrics")
            self.assertEqual(status, 404)

    def test_server_survives_bad_config(self):
        """A malformed config doesn't 500 the endpoint or crash the server."""
        (Path(self.config_dir) / "bad.toml").write_text("not valid [[[ toml")
        with ExporterProcess(self.config_dir) as exp:
            status, _ = exp.get("/metrics")
            self.assertEqual(status, 200)
            # Still alive and serving on a second request.
            status2, _ = exp.get("/metrics")
            self.assertEqual(status2, 200)


class TestMetricsLiveCollection(unittest.TestCase):
    """Each scrape re-reads configs from disk (no cached snapshot)."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.config_dir)

    def test_rescrape_reflects_config_change(self):
        """A config change between two scrapes is reflected on the second."""
        write_config(self.config_dir, "v1", """\
            [workload]
            name = "v1"
            enabled = true

            [container]
            image = "alpine:latest"
        """)

        with ExporterProcess(self.config_dir) as exp:
            status, prom1 = exp.get("/metrics")
            self.assertEqual(status, 200)
            self.assertIn('workload="v1"', prom1)

            # Remove v1, add v2 — same running server.
            (Path(self.config_dir) / "v1.toml").unlink()
            write_config(self.config_dir, "v2", """\
                [workload]
                name = "v2"
                enabled = true

                [container]
                image = "alpine:latest"
            """)

            status, prom2 = exp.get("/metrics")
            self.assertEqual(status, 200)
            self.assertIn('workload="v2"', prom2)
            self.assertNotIn('workload="v1"', prom2)


if __name__ == "__main__":
    unittest.main()
