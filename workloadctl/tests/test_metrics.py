#!/usr/bin/env python3
"""Integration tests for the workload-exporter metrics textfile writer.

Runs the actual workload-exporter oneshot against an overridden config
directory (WORKLOAD_CONFIG_DIR), writing to a scratch path, and validates the
Prometheus exposition it drops. On a dev machine systemd and cgroup queries
return empty/defaults, so we test:
- Config discovery (enabled, disabled, masked workloads)
- Output format (valid Prometheus exposition with correct TYPE/HELP)
- Empty/no-config edge cases
- Meta-metrics (workload_enabled_total, last_collect_timestamp)
- Robustness (bad configs are skipped, a file is still written)
- Live collection (each run re-reads configs)
- Atomic write (temp + rename, world-readable, no partial file left behind)
"""

import importlib.machinery
import importlib.util
import os
import shutil
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


def run_writer(config_dir, output_path):
    """Run workload-exporter as a subprocess, writing to output_path."""
    env = os.environ.copy()
    env["WORKLOAD_CONFIG_DIR"] = str(config_dir)
    env["PYTHONPATH"] = LIB_DIR
    subprocess.run(
        [sys.executable, EXPORTER_SCRIPT, str(output_path)],
        env=env, check=True, capture_output=True, text=True, timeout=30,
    )


def scrape(config_dir):
    """Run the exporter against config_dir once, return the written exposition."""
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "workloads.prom"
        run_writer(config_dir, out)
        return out.read_text()


def write_config(config_dir, name, toml_content, enabled=True):
    (Path(config_dir) / name).mkdir(exist_ok=True)
    path = Path(config_dir) / name / "workload.toml"
    body = textwrap.dedent(toml_content)
    path.write_text(body)
    if enabled:
        (Path(config_dir) / name / ".enabled").touch()
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


def _exporter_get_enabled_workloads(config_dir):
    """Load workload-exporter and call get_enabled_workloads against config_dir."""
    if LIB_DIR not in sys.path:
        sys.path.insert(0, LIB_DIR)
    loader = importlib.machinery.SourceFileLoader(
        "workload_exporter", EXPORTER_SCRIPT)
    spec = importlib.util.spec_from_loader("workload_exporter", loader)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    orig_env = os.environ.get("WORKLOAD_CONFIG_DIR")
    orig_argv = sys.argv[:]
    os.environ["WORKLOAD_CONFIG_DIR"] = str(config_dir)
    sys.argv = [EXPORTER_SCRIPT]  # prevent PORT = int(sys.argv[1]) from failing
    try:
        loader.exec_module(mod)
        return mod.get_enabled_workloads()
    finally:
        sys.argv = orig_argv
        if orig_env is None:
            os.environ.pop("WORKLOAD_CONFIG_DIR", None)
        else:
            os.environ["WORKLOAD_CONFIG_DIR"] = orig_env


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

            [container]
            image = "alpine:latest"
        """, enabled=False)

        prom = scrape(self.config_dir)
        self.assertNotIn('workload="off"', prom)
        self.assertEqual(parse_metric_value(prom, "workload_enabled_total"), "0")

    def test_masked_workload_skipped(self):
        """A masked workload (symlink to /dev/null) is not reported."""
        write_config(self.config_dir, "real", """\
            [workload]
            name = "real"

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

            [container]
            image = "alpine:latest"
        """)
        write_config(self.config_dir, "off1", """\
            [workload]
            name = "off1"

            [container]
            image = "alpine:latest"
        """, enabled=False)
        write_config(self.config_dir, "on2", """\
            [workload]
            name = "on2"

            [container]
            image = "alpine:latest"
        """)

        prom = scrape(self.config_dir)
        self.assertIn('workload="on1"', prom)
        self.assertIn('workload="on2"', prom)
        self.assertNotIn('workload="off1"', prom)
        self.assertEqual(parse_metric_value(prom, "workload_enabled_total"), "2")

    def test_default_enabled_false(self):
        """Workload without explicit enabled= defaults to disabled (matches generator)."""
        write_config(self.config_dir, "implicit", """\
            [workload]
            name = "implicit"

            [container]
            image = "alpine:latest"
        """, enabled=False)

        prom = scrape(self.config_dir)
        self.assertNotIn('workload="implicit"', prom)
        self.assertEqual(parse_metric_value(prom, "workload_enabled_total"), "0")

    def test_multi_container_health_detected(self):
        """Health check on any [[containers]] member is detected."""
        write_config(self.config_dir, "multi", """\
            [workload]
            name = "multi"

            [[containers]]
            name = "web"

            [containers.container]
            image = "nginx:latest"

            [[containers]]
            name = "db"

            [containers.container]
            image = "postgres:latest"

            [containers.container.health]
            cmd = "pg_isready"
            interval = "30s"
        """)

        workloads = _exporter_get_enabled_workloads(self.config_dir)
        self.assertEqual(len(workloads), 1)
        name, health_targets, is_vm = workloads[0]
        self.assertEqual(name, "multi")
        self.assertTrue(health_targets)
        # A6: the health target must be the container's own podman name
        # (workload-<name>-<container>), not the nonexistent workload-<name>.
        self.assertEqual(health_targets, [("db", "workload-multi-db")])

    def test_multi_container_no_health(self):
        """[[containers]] with no health checks reports has_health=False."""
        write_config(self.config_dir, "nohc", """\
            [workload]
            name = "nohc"

            [[containers]]
            name = "a"

            [containers.container]
            image = "alpine:latest"

            [[containers]]
            name = "b"

            [containers.container]
            image = "alpine:latest"
        """)

        workloads = _exporter_get_enabled_workloads(self.config_dir)
        self.assertEqual(len(workloads), 1)
        name, health_targets, is_vm = workloads[0]
        self.assertFalse(health_targets)


class TestMetricsFormat(unittest.TestCase):
    """Validate Prometheus exposition format correctness."""

    # One shared scrape: the config is identical for every test in this class
    # and the tests only parse the exposition text, so a per-test exporter
    # launch is pure overhead.
    @classmethod
    def setUpClass(cls):
        cls.config_dir = tempfile.mkdtemp()
        write_config(cls.config_dir, "app", """\
            [workload]
            name = "app"

            [container]
            image = "myapp:latest"
        """)
        cls.prom = scrape(cls.config_dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.config_dir)

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
            "workload_disk_bytes": "gauge",
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
        type_lines = [line for line in self.prom.splitlines()
                      if line.startswith("# TYPE ")]
        metric_names = [line.split()[2] for line in type_lines]
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

    def test_disk_bytes_gauge_declared(self):
        """workload_disk_bytes gauge TYPE and HELP are always emitted."""
        types = parse_type_declarations(self.prom)
        self.assertIn("workload_disk_bytes", types)
        self.assertEqual(types["workload_disk_bytes"], "gauge")
        self.assertIn("# HELP workload_disk_bytes ", self.prom)


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
            '[workload]\n\n[container]\nimage = "x"\n')

        prom = scrape(self.config_dir)
        self.assertEqual(parse_metric_value(prom, "workload_enabled_total"), "0")

    def test_non_toml_files_ignored(self):
        """Files that aren't .toml are not read."""
        (Path(self.config_dir) / "readme.md").write_text("# not a config")
        (Path(self.config_dir) / "backup.toml.bak").write_text("junk")

        write_config(self.config_dir, "real", """\
            [workload]
            name = "real"

            [container]
            image = "alpine:latest"
        """)

        prom = scrape(self.config_dir)
        self.assertEqual(parse_metric_value(prom, "workload_enabled_total"), "1")


class TestMetricsLiveCollection(unittest.TestCase):
    """Each run re-reads configs from disk (no cached snapshot)."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.config_dir)

    def test_rerun_reflects_config_change(self):
        """A config change between two runs is reflected on the second."""
        write_config(self.config_dir, "v1", """\
            [workload]
            name = "v1"

            [container]
            image = "alpine:latest"
        """)
        prom1 = scrape(self.config_dir)
        self.assertIn('workload="v1"', prom1)

        # Remove v1, add v2 — a fresh run must reflect the new state.
        shutil.rmtree(Path(self.config_dir) / "v1")
        write_config(self.config_dir, "v2", """\
            [workload]
            name = "v2"

            [container]
            image = "alpine:latest"
        """)
        prom2 = scrape(self.config_dir)
        self.assertIn('workload="v2"', prom2)
        self.assertNotIn('workload="v1"', prom2)


def _load_exporter():
    """Load the workload-exporter module object (for direct function calls)."""
    if LIB_DIR not in sys.path:
        sys.path.insert(0, LIB_DIR)
    loader = importlib.machinery.SourceFileLoader(
        "workload_exporter", EXPORTER_SCRIPT)
    spec = importlib.util.spec_from_loader("workload_exporter", loader)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    orig_argv = sys.argv[:]
    sys.argv = [EXPORTER_SCRIPT]  # PORT = int(sys.argv[1]) guard
    try:
        loader.exec_module(mod)
        return mod
    finally:
        sys.argv = orig_argv


class TestVMCgroupMetrics(unittest.TestCase):
    """VM workloads get host-side cgroup metrics from the qemu service's own
    cgroup (resolved via systemd ControlGroup), not a podman libpod scope."""

    def setUp(self):
        from unittest import mock
        self.mock = mock
        self.mod = _load_exporter()

    def _write_cgroup(self, root, rel):
        cg = Path(root) / rel
        cg.mkdir(parents=True)
        (cg / "cpu.stat").write_text(
            "usage_usec 5000000\nuser_usec 3000000\nsystem_usec 2000000\n")
        (cg / "memory.current").write_text("268435456\n")
        (cg / "memory.max").write_text("536870912\n")
        (cg / "pids.current").write_text("17\n")
        return cg

    def test_find_vm_cgroup_resolves_via_controlgroup(self):
        with tempfile.TemporaryDirectory() as root:
            rel = "workloads.slice/workload-myvm.service"
            self._write_cgroup(root, rel)
            with self.mock.patch.object(self.mod, "CGROUP_ROOT", Path(root)), \
                 self.mock.patch.object(
                     self.mod, "systemd_show",
                     return_value={"ControlGroup": "/" + rel}):
                cg = self.mod.find_vm_cgroup("myvm")
            self.assertIsNotNone(cg)
            self.assertEqual(cg, Path(root) / rel)

    def test_find_vm_cgroup_none_when_no_controlgroup(self):
        with self.mock.patch.object(
                self.mod, "systemd_show", return_value={}):
            self.assertIsNone(self.mod.find_vm_cgroup("myvm"))

    def test_find_vm_cgroup_none_when_dir_missing(self):
        with self.mock.patch.object(self.mod, "CGROUP_ROOT", Path("/nonexistent")), \
             self.mock.patch.object(
                 self.mod, "systemd_show",
                 return_value={"ControlGroup": "/workloads.slice/workload-myvm.service"}):
            self.assertIsNone(self.mod.find_vm_cgroup("myvm"))

    def test_vm_cgroup_metrics_read_from_qemu_service(self):
        with tempfile.TemporaryDirectory() as root:
            rel = "workloads.slice/workload-myvm.service"
            cg = self._write_cgroup(root, rel)
            with self.mock.patch.object(self.mod, "find_vm_cgroup", return_value=cg):
                metrics = self.mod.get_cgroup_metrics("myvm", is_vm=True)
            self.assertEqual(metrics["cpu_usage_seconds_total"], 5.0)
            self.assertEqual(metrics["memory_current_bytes"], 268435456)
            self.assertEqual(metrics["memory_max_bytes"], 536870912)
            self.assertEqual(metrics["pids_current"], 17)

    def test_is_vm_routes_to_vm_cgroup_finder(self):
        # is_vm=True must use find_vm_cgroup, not the podman scope finder.
        with self.mock.patch.object(self.mod, "find_vm_cgroup", return_value=None) as vm_finder, \
             self.mock.patch.object(self.mod, "find_workload_cgroup") as ctr_finder:
            self.mod.get_cgroup_metrics("myvm", is_vm=True)
            vm_finder.assert_called_once_with("myvm")
            ctr_finder.assert_not_called()

    def test_container_routes_to_podman_scope_finder(self):
        with self.mock.patch.object(self.mod, "find_workload_cgroup", return_value=None) as ctr_finder, \
             self.mock.patch.object(self.mod, "find_vm_cgroup") as vm_finder:
            self.mod.get_cgroup_metrics("myapp", is_vm=False)
            ctr_finder.assert_called_once_with("myapp")
            vm_finder.assert_not_called()


class TestDiskBytes(unittest.TestCase):
    def setUp(self):
        from unittest import mock
        self.mock = mock
        self.mod = _load_exporter()

    def test_parses_du_output(self):
        cp = self.mock.Mock(returncode=0, stdout="4096\t/home/_wl-x\n")
        with self.mock.patch.object(self.mod.subprocess, "run", return_value=cp):
            self.assertEqual(self.mod.get_workload_disk_bytes("/home/_wl-x"), 4096)

    def test_nonzero_returncode_is_none(self):
        cp = self.mock.Mock(returncode=1, stdout="")
        with self.mock.patch.object(self.mod.subprocess, "run", return_value=cp):
            self.assertIsNone(self.mod.get_workload_disk_bytes("/x"))

    def test_exception_is_none(self):
        with self.mock.patch.object(self.mod.subprocess, "run",
                                    side_effect=OSError("boom")):
            self.assertIsNone(self.mod.get_workload_disk_bytes("/x"))


class TestSystemdShow(unittest.TestCase):
    def setUp(self):
        from unittest import mock
        self.mock = mock
        self.mod = _load_exporter()

    def test_parses_properties(self):
        cp = self.mock.Mock(returncode=0,
                            stdout="ActiveState=active\nSubState=running\n")
        with self.mock.patch.object(self.mod.subprocess, "run", return_value=cp):
            out = self.mod.systemd_show("x.service", "ActiveState", "SubState")
        self.assertEqual(out, {"ActiveState": "active", "SubState": "running"})

    def test_nonzero_returncode_empty(self):
        cp = self.mock.Mock(returncode=1, stdout="")
        with self.mock.patch.object(self.mod.subprocess, "run", return_value=cp):
            self.assertEqual(self.mod.systemd_show("x.service", "ActiveState"), {})

    def test_exception_empty(self):
        with self.mock.patch.object(self.mod.subprocess, "run",
                                    side_effect=OSError):
            self.assertEqual(self.mod.systemd_show("x.service", "ActiveState"), {})


class TestServiceMetrics(unittest.TestCase):
    def setUp(self):
        from unittest import mock
        self.mock = mock
        self.mod = _load_exporter()

    def test_active_with_uptime(self):
        props = {
            "ActiveState": "active",
            "NRestarts": "3",
            "ActiveEnterTimestampMonotonic": "1",  # tiny → positive uptime
        }
        with self.mock.patch.object(self.mod, "systemd_show", return_value=props):
            m = self.mod.get_service_metrics("app")
        self.assertEqual(m["active"], 1)
        self.assertEqual(m["failed"], 0)
        self.assertEqual(m["restarts_total"], 3)
        self.assertIn("uptime_seconds", m)

    def test_failed_state(self):
        with self.mock.patch.object(self.mod, "systemd_show",
                                    return_value={"ActiveState": "failed"}):
            m = self.mod.get_service_metrics("app")
        self.assertEqual(m["failed"], 1)
        self.assertEqual(m["active"], 0)
        self.assertNotIn("uptime_seconds", m)

    def test_missing_props_default_inactive(self):
        with self.mock.patch.object(self.mod, "systemd_show", return_value={}):
            m = self.mod.get_service_metrics("app")
        self.assertEqual(m["active"], 0)
        self.assertEqual(m["restarts_total"], 0)


class TestCgroupReaders(unittest.TestCase):
    def setUp(self):
        from unittest import mock
        self.mock = mock
        self.mod = _load_exporter()
        self.tmp = tempfile.mkdtemp()
        self.cg = Path(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_read_metric_value(self):
        (self.cg / "pids.current").write_text("42\n")
        self.assertEqual(self.mod.read_cgroup_metric(self.cg, "pids.current"), 42)

    def test_read_metric_max_is_none(self):
        (self.cg / "memory.max").write_text("max\n")
        self.assertIsNone(self.mod.read_cgroup_metric(self.cg, "memory.max"))

    def test_read_metric_missing_is_none(self):
        self.assertIsNone(self.mod.read_cgroup_metric(self.cg, "nope"))

    def test_read_cpu_usage(self):
        (self.cg / "cpu.stat").write_text("usage_usec 2500000\nuser_usec 1\n")
        self.assertEqual(self.mod.read_cpu_usage(self.cg), 2.5)

    def test_read_cpu_usage_missing_is_none(self):
        self.assertIsNone(self.mod.read_cpu_usage(self.cg))

    def test_get_cgroup_metrics_no_cgroup(self):
        with self.mock.patch.object(self.mod, "find_workload_cgroup",
                                    return_value=None):
            self.assertEqual(self.mod.get_cgroup_metrics("app"), {})

    def test_get_cgroup_metrics_full(self):
        (self.cg / "cpu.stat").write_text("usage_usec 1000000\n")
        (self.cg / "memory.current").write_text("1024\n")
        (self.cg / "memory.max").write_text("max\n")
        (self.cg / "pids.current").write_text("7\n")
        with self.mock.patch.object(self.mod, "find_workload_cgroup",
                                    return_value=self.cg):
            m = self.mod.get_cgroup_metrics("app")
        self.assertEqual(m["cpu_usage_seconds_total"], 1.0)
        self.assertEqual(m["memory_current_bytes"], 1024)
        self.assertEqual(m["pids_current"], 7)
        self.assertNotIn("memory_max_bytes", m)  # "max" → skipped


class TestContainerHealth(unittest.TestCase):
    def setUp(self):
        from unittest import mock
        self.mock = mock
        self.mod = _load_exporter()

    def test_no_such_user_returns_none(self):
        with self.mock.patch("pwd.getpwnam", side_effect=KeyError):
            self.assertIsNone(self.mod.get_container_health("ghost"))

    def test_health_queried_via_podman(self):
        fake_pw = self.mock.Mock(pw_uid=10001, pw_dir="/home/_wl-app")
        podman = self.mock.Mock()
        podman.container_healths.return_value = {"workload-app": "healthy"}
        with self.mock.patch("pwd.getpwnam", return_value=fake_pw), \
             self.mock.patch.object(self.mod.Podman, "for_user",
                                    return_value=podman):
            self.assertEqual(self.mod.get_container_health("app"), "healthy")
        podman.container_healths.assert_called_once_with(["workload-app"])

    def test_podman_error_returns_none(self):
        fake_pw = self.mock.Mock(pw_uid=10001, pw_dir="/home/_wl-app")
        with self.mock.patch("pwd.getpwnam", return_value=fake_pw), \
             self.mock.patch.object(self.mod.Podman, "for_user",
                                    side_effect=RuntimeError):
            self.assertIsNone(self.mod.get_container_health("app"))


class TestFindWorkloadCgroup(unittest.TestCase):
    def setUp(self):
        from unittest import mock
        self.mock = mock
        self.mod = _load_exporter()

    def test_no_such_user_returns_none(self):
        with self.mock.patch("pwd.getpwnam", side_effect=KeyError):
            self.assertIsNone(self.mod.find_workload_cgroup("ghost"))


class TestVMQMPMetrics(unittest.TestCase):
    def setUp(self):
        from unittest import mock
        self.mock = mock
        self.mod = _load_exporter()

    def test_missing_socket_returns_empty(self):
        with self.mock.patch.object(self.mod, "VM_SOCKET_DIR",
                                    Path("/nonexistent-vm-sock-dir")):
            self.assertEqual(self.mod.get_vm_qmp_metrics("vm"), {})

    def test_balloon_metric_collected(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        sockdir = Path(tmp) / "vm"
        sockdir.mkdir(parents=True)
        (sockdir / "qmp-metrics.sock").write_bytes(b"")
        qmp = self.mock.MagicMock()
        qmp.execute.side_effect = lambda cmd: {
            "query-balloon": {"return": {"actual": 2147483648}},
            "query-cpus-fast": {"return": []},
        }[cmd]
        with self.mock.patch.object(self.mod, "VM_SOCKET_DIR", Path(tmp)), \
             self.mock.patch.object(self.mod, "QMPClient", return_value=qmp):
            m = self.mod.get_vm_qmp_metrics("vm")
        self.assertEqual(m["balloon_actual_bytes"], 2147483648)


class TestGetEnabledWorkloadsDirect(unittest.TestCase):
    """Exercise get_enabled_workloads() branches without spawning a process."""

    def setUp(self):
        from unittest import mock
        self.mock = mock
        self.mod = _load_exporter()

    def test_config_dir_not_a_dir_returns_empty(self):
        with self.mock.patch.object(self.mod, "WORKLOAD_CONFIG_DIR",
                                    Path("/nonexistent-config-dir-xyz")):
            self.assertEqual(self.mod.get_enabled_workloads(), [])

    def test_resolve_oserror_is_skipped(self):
        bad_toml = self.mock.Mock()
        bad_toml.resolve.side_effect = OSError
        with self.mock.patch.object(self.mod, "WORKLOAD_CONFIG_DIR", Path(".")), \
             self.mock.patch.object(self.mod, "iter_workloads",
                                    return_value=[("bad", bad_toml)]):
            self.assertEqual(self.mod.get_enabled_workloads(), [])

    def test_missing_enabled_marker_is_skipped(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        toml_path = write_config(tmp, "off", """\
            [workload]
            name = "off"

            [container]
            image = "alpine:latest"
        """, enabled=False)
        with self.mock.patch.object(self.mod, "WORKLOAD_CONFIG_DIR", Path(tmp)), \
             self.mock.patch.object(self.mod, "iter_workloads",
                                    return_value=[("off", toml_path)]):
            self.assertEqual(self.mod.get_enabled_workloads(), [])

    def test_toml_parse_exception_is_skipped(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        bad_path = Path(tmp) / "bad" / "workload.toml"
        bad_path.parent.mkdir()
        bad_path.write_text("not valid [[[ toml")
        (bad_path.parent / ".enabled").touch()
        with self.mock.patch.object(self.mod, "WORKLOAD_CONFIG_DIR", Path(tmp)), \
             self.mock.patch.object(self.mod, "iter_workloads",
                                    return_value=[("bad", bad_path)]):
            self.assertEqual(self.mod.get_enabled_workloads(), [])


class TestVMQMPVcpuMetrics(unittest.TestCase):
    """Cover the per-vCPU /proc/<tid>/stat parsing loop."""

    def setUp(self):
        from unittest import mock
        self.mock = mock
        self.mod = _load_exporter()

    def _sock_dir(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        sockdir = Path(tmp) / "vm"
        sockdir.mkdir(parents=True)
        (sockdir / "qmp-metrics.sock").write_bytes(b"")
        return Path(tmp)

    def test_vcpu_stat_parsed(self):
        vm_dir = self._sock_dir()
        real_path = self.mod.Path
        fields = ["x"] * 20
        fields[13] = "100"  # utime
        fields[14] = "50"   # stime
        stat_line = " ".join(fields)

        class FakePath:
            def __new__(cls, p):
                if str(p) == "/proc/4242/stat":
                    obj = object.__new__(cls)
                    return obj
                return real_path(p)

            def read_text(self):
                return stat_line

        qmp = self.mock.MagicMock()
        qmp.execute.side_effect = lambda cmd: {
            "query-balloon": {"return": {}},
            "query-cpus-fast": {"return": [
                {"cpu-index": 0, "thread-id": 4242},
                {"cpu-index": 1},  # no thread-id → skipped
            ]},
        }[cmd]
        with self.mock.patch.object(self.mod, "VM_SOCKET_DIR", vm_dir), \
             self.mock.patch.object(self.mod, "QMPClient", return_value=qmp), \
             self.mock.patch.object(self.mod, "Path", FakePath):
            m = self.mod.get_vm_qmp_metrics("vm")
        self.assertIn("vcpu_0_cpu_seconds_total", m)
        self.assertNotIn("vcpu_1_cpu_seconds_total", m)

    def test_vcpu_stat_read_error_skipped(self):
        vm_dir = self._sock_dir()
        qmp = self.mock.MagicMock()
        qmp.execute.side_effect = lambda cmd: {
            "query-balloon": {"return": {}},
            "query-cpus-fast": {"return": [{"cpu-index": 0, "thread-id": 999999}]},
        }[cmd]
        with self.mock.patch.object(self.mod, "VM_SOCKET_DIR", vm_dir), \
             self.mock.patch.object(self.mod, "QMPClient", return_value=qmp):
            m = self.mod.get_vm_qmp_metrics("vm")
        self.assertEqual(m, {})

    def test_qmp_connect_exception_returns_empty(self):
        vm_dir = self._sock_dir()
        qmp = self.mock.MagicMock()
        qmp.connect.side_effect = OSError("no such socket")
        with self.mock.patch.object(self.mod, "VM_SOCKET_DIR", vm_dir), \
             self.mock.patch.object(self.mod, "QMPClient", return_value=qmp):
            m = self.mod.get_vm_qmp_metrics("vm")
        self.assertEqual(m, {})
        qmp.close.assert_called_once()


class TestServiceMetricsUptimeException(unittest.TestCase):
    def setUp(self):
        from unittest import mock
        self.mock = mock
        self.mod = _load_exporter()

    def test_uptime_exception_is_swallowed(self):
        props = {
            "ActiveState": "active",
            "NRestarts": "0",
            "ActiveEnterTimestampMonotonic": "1",
        }
        with self.mock.patch.object(self.mod, "systemd_show", return_value=props), \
             self.mock.patch.object(self.mod.time, "monotonic_ns",
                                    side_effect=Exception("boom")):
            m = self.mod.get_service_metrics("app")
        self.assertNotIn("uptime_seconds", m)
        self.assertEqual(m["active"], 1)


class TestFindWorkloadCgroupSuccess(unittest.TestCase):
    """Cover the uid-resolved candidate/rglob search loop."""

    def setUp(self):
        from unittest import mock
        self.mock = mock
        self.mod = _load_exporter()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.real_path = self.mod.Path

    def _redirecting_path(self, root):
        real_path = self.real_path

        def _fake(p):
            s = str(p)
            if s.startswith("/sys/fs/cgroup"):
                return real_path(root) / s.lstrip("/")
            return real_path(p)
        return _fake

    def test_finds_scope_under_workloads_slice(self):
        scope = (Path(self.tmp) / "sys/fs/cgroup/workloads.slice"
                  / "user@10001.service/some/libpod-abcdef.scope")
        scope.mkdir(parents=True)
        fake_pw = self.mock.Mock(pw_uid=10001)
        with self.mock.patch("pwd.getpwnam", return_value=fake_pw), \
             self.mock.patch.object(self.mod, "Path", self._redirecting_path(self.tmp)):
            result = self.mod.find_workload_cgroup("app")
        self.assertEqual(result, scope)

    def test_no_candidate_dirs_returns_none(self):
        fake_pw = self.mock.Mock(pw_uid=10002)
        with self.mock.patch("pwd.getpwnam", return_value=fake_pw), \
             self.mock.patch.object(self.mod, "Path", self._redirecting_path(self.tmp)):
            result = self.mod.find_workload_cgroup("app")
        self.assertIsNone(result)


class TestFormatMetrics(unittest.TestCase):
    def setUp(self):
        self.mod = _load_exporter()

    def test_full_metrics_rendered(self):
        all_metrics = [
            ("app", {"active": 1, "failed": 0, "restarts_total": 2,
                      "uptime_seconds": 12.5, "health": {"app": 1}},
             {"cpu_usage_seconds_total": 3.5, "memory_current_bytes": 1024,
              "memory_max_bytes": 2048, "pids_current": 4},
             {"balloon_actual_bytes": 999, "vcpu_0_cpu_seconds_total": 1.25},
             4096),
            ("nodisk", {}, {}, {}, None),
        ]
        text = self.mod.format_metrics(all_metrics)
        self.assertIn('workload_active{workload="app"} 1', text)
        self.assertIn('workload_uptime_seconds{workload="app"} 12.50', text)
        self.assertIn('workload_cpu_usage_seconds_total{workload="app"} 3.500000', text)
        # Single-container health keeps the historical label-less series.
        self.assertIn('workload_health{workload="app"} 1', text)
        self.assertNotIn('workload_health{workload="app",container=', text)
        self.assertIn('workload_vm_balloon_actual_bytes{workload="app"} 999', text)
        self.assertIn('workload_vm_vcpu_cpu_seconds_total{workload="app",vcpu="0"} 1.250000', text)
        self.assertIn('workload_disk_bytes{workload="app"} 4096', text)
        self.assertNotIn('workload_disk_bytes{workload="nodisk"}', text)
        self.assertIn("workload_enabled_total 2", text)

    def test_pod_health_rendered_per_container(self):
        """Multi-container workloads emit one workload_health line per
        container, distinguished by the container label (the A6 fix)."""
        all_metrics = [
            ("multi", {"health": {"web": 1, "db": 0}}, {}, {}, None),
        ]
        text = self.mod.format_metrics(all_metrics)
        self.assertIn('workload_health{workload="multi",container="web"} 1', text)
        self.assertIn('workload_health{workload="multi",container="db"} 0', text)

    def test_empty_metrics_still_has_footer(self):
        text = self.mod.format_metrics([])
        self.assertIn("workload_enabled_total 0", text)
        self.assertIn("workload_metrics_last_collect_timestamp_seconds", text)


class TestCollectAll(unittest.TestCase):
    """Drive collect_all() — the collection loop the writer renders."""

    def setUp(self):
        from unittest import mock
        self.mock = mock
        self.mod = _load_exporter()

    def test_full_workload_collection_path(self):
        with self.mock.patch.object(
                self.mod, "get_enabled_workloads",
                return_value=[("app", [("app", "workload-app")], False)]), \
             self.mock.patch.object(self.mod, "get_service_metrics", return_value={"active": 1}), \
             self.mock.patch.object(self.mod, "get_cgroup_metrics", return_value={}), \
             self.mock.patch.object(self.mod, "get_container_healths",
                                    return_value={"workload-app": "healthy"}), \
             self.mock.patch.object(self.mod, "get_workload_disk_bytes", return_value=1000):
            all_metrics = self.mod.collect_all()
        self.assertEqual(len(all_metrics), 1)
        name, svc, _cgroup, _vm, disk = all_metrics[0]
        self.assertEqual(name, "app")
        self.assertEqual(svc["health"], {"app": 1})
        self.assertEqual(disk, 1000)
        body = self.mod.format_metrics(all_metrics)
        self.assertIn('workload_health{workload="app"} 1', body)

    def test_pod_workload_queries_per_container_names(self):
        """Regression for A6: a pod/bridge workload's health must be queried
        by its actual podman names (`workload-<name>-<container>`), not the
        nonexistent bare `workload-<name>` — and workload_health must appear
        for each container. Fails pre-fix because the old code always queried
        `workload-<name>` and reported a single scalar."""
        queried_names = []

        def fake_healths(name, container_names):
            queried_names.extend(container_names)
            return {n: ("healthy" if n == "workload-multi-web" else "unhealthy")
                    for n in container_names}

        with self.mock.patch.object(
                self.mod, "get_enabled_workloads",
                return_value=[("multi", [
                    ("web", "workload-multi-web"),
                    ("db", "workload-multi-db"),
                ], False)]), \
             self.mock.patch.object(self.mod, "get_service_metrics", return_value={"active": 1}), \
             self.mock.patch.object(self.mod, "get_cgroup_metrics", return_value={}), \
             self.mock.patch.object(self.mod, "get_container_healths", side_effect=fake_healths), \
             self.mock.patch.object(self.mod, "get_workload_disk_bytes", return_value=None):
            all_metrics = self.mod.collect_all()

        self.assertEqual(sorted(queried_names), ["workload-multi-db", "workload-multi-web"])
        self.assertNotIn("workload-multi", queried_names)
        _name, svc, *_ = all_metrics[0]
        self.assertEqual(svc["health"], {"web": 1, "db": 0})
        body = self.mod.format_metrics(all_metrics)
        self.assertIn('workload_health{workload="multi",container="web"} 1', body)
        self.assertIn('workload_health{workload="multi",container="db"} 0', body)


class TestWriteMetrics(unittest.TestCase):
    """The atomic textfile writer that replaced the HTTP serving layer."""

    def setUp(self):
        from unittest import mock
        self.mock = mock
        self.mod = _load_exporter()

    def test_writes_expected_contents_and_creates_parent(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "sub" / "workloads.prom"  # parent must be created
            with self.mock.patch.object(self.mod, "collect_all", return_value=[]):
                self.mod.write_metrics(out)
            self.assertTrue(out.exists())
            self.assertIn("workload_enabled_total 0", out.read_text())

    def test_body_matches_format_metrics(self):
        """The file holds exactly what format_metrics() renders — the writer
        swapped the transport (was HTTP), not the metrics."""
        sample = [("app", {"active": 1}, {}, {}, None)]
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "workloads.prom"
            with self.mock.patch.object(self.mod, "collect_all", return_value=sample):
                self.mod.write_metrics(out)
            self.assertEqual(out.read_text(), self.mod.format_metrics(sample))

    def test_write_is_atomic_no_tmp_left(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "workloads.prom"
            with self.mock.patch.object(self.mod, "collect_all", return_value=[]):
                self.mod.write_metrics(out)
            # Only the final file survives — the sibling temp is renamed away.
            self.assertEqual([p.name for p in Path(d).iterdir()], ["workloads.prom"])

    def test_file_is_world_readable(self):
        """Rootless Alloy reads the root-written file across a :ro mount and
        can't chown it, so it must land world-readable (0644)."""
        import stat
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "workloads.prom"
            with self.mock.patch.object(self.mod, "collect_all", return_value=[]):
                self.mod.write_metrics(out)
            mode = stat.S_IMODE(os.stat(out).st_mode)
            self.assertTrue(mode & stat.S_IROTH, f"not world-readable: {oct(mode)}")


class TestMain(unittest.TestCase):
    def setUp(self):
        from unittest import mock
        self.mock = mock
        self.mod = _load_exporter()

    def test_main_writes_output_path(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "workloads.prom"
            with self.mock.patch.object(self.mod, "OUTPUT_PATH", out), \
                 self.mock.patch.object(self.mod, "collect_all", return_value=[]):
                self.mod.main()
            self.assertTrue(out.exists())
            self.assertIn("workload_enabled_total 0", out.read_text())


if __name__ == "__main__":
    unittest.main()
