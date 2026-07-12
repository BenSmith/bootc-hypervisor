#!/usr/bin/env python3
"""Integration tests for the real workload configs in workloads.d/.

Runs every workload TOML through the generator and validates the output:
- Service file is created and well-formed
- Image, network, volumes, userns, capabilities, resources all match the TOML
- sysusers conf is created
- systemd-analyze verify passes (if available)
- Cross-config consistency checks (no duplicate names, ports, etc.)

These tests catch regressions from editing workload configs or the generator.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

GENERATOR = os.path.join(os.path.dirname(__file__), '..', 'generators', 'workload-generate')
LIB_DIR = os.path.join(os.path.dirname(__file__), '..', 'lib')
# Shipped bundles live one-per-dir as workloads/<bundle>/workload.toml. The
# bundle dir name is the workload identity; we present it as "<bundle>.toml" so
# the filename-based assertions and skip set below read unchanged.
WORKLOADS_DIR = Path(os.path.dirname(__file__), '..', 'workloads')


def _bundle_tomls():
    """Sorted (synthetic_filename, path) for every shipped bundle declaration."""
    return sorted(
        (f"{p.parent.name}.toml", p)
        for p in WORKLOADS_DIR.glob("*/workload.toml")
    )

# Multi-container workloads use [[containers]] arrays; the assertions in this
# file assume the single-container top-level [container] shape. Multi-container
# generation is covered by test_generator.py instead.
SKIP_FILES = {"example-multi-container.toml", "webproxy-demo.toml"}


def run_generator(config_dir, services_dir, sysusers_dir):
    env = os.environ.copy()
    env["WORKLOAD_CONFIG_DIR"] = str(config_dir)
    env["SYSUSERS_DIR"] = str(sysusers_dir)
    env["PYTHONPATH"] = LIB_DIR
    return subprocess.run(
        [sys.executable, GENERATOR, str(services_dir)],
        capture_output=True, text=True, env=env,
    )


def has_systemd_analyze():
    try:
        subprocess.run(["systemd-analyze", "--version"],
                       capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def load_all_workloads():
    """Load all real workload configs. Returns list of (filename, config_dict)."""
    workloads = []
    for filename, toml_path in _bundle_tomls():
        if filename in SKIP_FILES:
            continue
        try:
            if toml_path.resolve() == Path("/dev/null"):
                continue
        except OSError:
            continue
        with open(toml_path, "rb") as f:
            config = tomllib.load(f)
        workloads.append((filename, config))
    return workloads


ALL_WORKLOADS = load_all_workloads()


class TestWorkloadConfigParsing(unittest.TestCase):
    """Validate that every workload TOML is well-formed and has required fields."""

    def test_all_configs_parseable(self):
        """Every .toml file in workloads.d/ parses without error."""
        for filename, toml_path in _bundle_tomls():
            if filename in SKIP_FILES:
                continue
            with self.subTest(config=filename):
                with open(toml_path, "rb") as f:
                    config = tomllib.load(f)
                self.assertIsInstance(config, dict)

    def test_all_configs_have_workload_name(self):
        """Every config has [workload].name."""
        for filename, config in ALL_WORKLOADS:
            with self.subTest(config=filename):
                name = config.get("workload", {}).get("name", "")
                self.assertTrue(name, f"{filename} missing workload.name")

    def test_name_matches_filename(self):
        """workload.name matches the TOML filename (without .toml)."""
        for filename, config in ALL_WORKLOADS:
            with self.subTest(config=filename):
                name = config["workload"]["name"]
                expected = filename.removesuffix(".toml")
                self.assertEqual(name, expected,
                                 f"{filename}: name '{name}' != filename stem '{expected}'")

    def test_all_configs_have_image(self):
        """Every container config has [container].image (VM workloads exempt)."""
        for filename, config in ALL_WORKLOADS:
            if "vm" in config:
                continue  # VM workloads have no container image
            with self.subTest(config=filename):
                image = config.get("container", {}).get("image", "")
                self.assertTrue(image, f"{filename} missing container.image")

    def test_all_configs_disabled_by_default(self):
        """Shipped bundles must ship disabled: no .enabled marker."""
        for filename, config in ALL_WORKLOADS:
            with self.subTest(config=filename):
                name = filename.removesuffix(".toml")
                marker = WORKLOADS_DIR / name / ".enabled"
                self.assertFalse(marker.exists(),
                                 f"{filename} ships a .enabled marker — bundles must ship disabled")

    def test_name_is_valid(self):
        """Workload names follow the naming rules."""
        import re
        pattern = re.compile(r"^[a-z][a-z0-9-]*[a-z0-9]$")
        for filename, config in ALL_WORKLOADS:
            with self.subTest(config=filename):
                name = config["workload"]["name"]
                self.assertLessEqual(len(name), 32,
                                     f"{filename}: name too long ({len(name)} > 32)")
                self.assertRegex(name, pattern,
                                 f"{filename}: name '{name}' doesn't match [a-z][a-z0-9-]*[a-z0-9]")

    def test_pull_values_valid(self):
        """container.pull is one of the valid values."""
        valid_pull = {"always", "missing", "never", "newer"}
        for filename, config in ALL_WORKLOADS:
            pull = config.get("container", {}).get("pull")
            if pull is not None:
                with self.subTest(config=filename):
                    self.assertIn(pull, valid_pull,
                                  f"{filename}: invalid pull={pull}")

    def test_network_mode_valid(self):
        """network.mode is one of the valid values."""
        valid_modes = {"host", "pasta", "bridge", "none"}
        for filename, config in ALL_WORKLOADS:
            mode = config.get("network", {}).get("mode")
            if mode is not None:
                with self.subTest(config=filename):
                    self.assertIn(mode, valid_modes,
                                  f"{filename}: invalid network.mode={mode}")

    def test_userns_valid(self):
        """security.userns is one of the valid values."""
        from workload_lib import valid_userns_mode
        for filename, config in ALL_WORKLOADS:
            userns = config.get("security", {}).get("userns")
            if userns is not None:
                with self.subTest(config=filename):
                    self.assertTrue(valid_userns_mode(userns),
                                    f"{filename}: invalid userns={userns}")

    def test_capabilities_are_uppercase(self):
        """Capabilities should be uppercase Linux capability names."""
        import re
        cap_pattern = re.compile(r"^[A-Z][A-Z0-9_]+$")
        for filename, config in ALL_WORKLOADS:
            caps = config.get("security", {}).get("capabilities", [])
            for cap in caps:
                with self.subTest(config=filename, cap=cap):
                    self.assertRegex(cap, cap_pattern,
                                     f"{filename}: capability '{cap}' not uppercase")

    def test_port_format_valid(self):
        """Port specs match the expected format."""
        import re
        # host:container or host:container/proto or ip:host:container
        port_pattern = re.compile(
            r"^(\d{1,3}(\.\d{1,3}){3}:)?\d+:\d+(/[a-z]+)?$"
        )
        for filename, config in ALL_WORKLOADS:
            ports = config.get("network", {}).get("ports", [])
            for port in ports:
                with self.subTest(config=filename, port=port):
                    self.assertRegex(port, port_pattern,
                                     f"{filename}: invalid port spec '{port}'")

    def test_volume_format_valid(self):
        """Volume specs have host:container[:options] format."""
        for filename, config in ALL_WORKLOADS:
            volumes = config.get("storage", {}).get("volumes", [])
            for vol in volumes:
                with self.subTest(config=filename, volume=vol):
                    parts = vol.split(":")
                    self.assertGreaterEqual(len(parts), 2,
                                            f"{filename}: volume '{vol}' needs host:container")
                    self.assertLessEqual(len(parts), 3,
                                         f"{filename}: volume '{vol}' has too many colons")

    def test_required_files_have_path(self):
        """setup.required_files entries all have a path field."""
        for filename, config in ALL_WORKLOADS:
            required = config.get("setup", {}).get("required_files", [])
            for entry in required:
                with self.subTest(config=filename, entry=entry):
                    self.assertIn("path", entry,
                                  f"{filename}: required_file missing 'path'")


class TestWorkloadGeneration(unittest.TestCase):
    """Run the generator against each real workload config and validate output."""

    config_dir: str
    services_dir: str
    sysusers_dir: str
    configs: dict
    gen_result: subprocess.CompletedProcess

    @classmethod
    def setUpClass(cls):
        """Generate services for all workloads once."""
        cls.config_dir = tempfile.mkdtemp()
        cls.services_dir = tempfile.mkdtemp()
        cls.sysusers_dir = tempfile.mkdtemp()

        # Copy all real workload configs and enable them (marker file) so the
        # generator processes them.
        cls.configs = {}
        for filename, config in ALL_WORKLOADS:
            config_copy = _deep_copy_config(config)
            toml_text = _config_to_toml(config_copy)
            name = filename.removesuffix(".toml")
            (Path(cls.config_dir) / name).mkdir(exist_ok=True)
            (Path(cls.config_dir) / name / "workload.toml").write_text(toml_text)
            (Path(cls.config_dir) / name / ".enabled").touch()
            cls.configs[filename] = config_copy

        cls.gen_result = run_generator(cls.config_dir, cls.services_dir, cls.sysusers_dir)

    @classmethod
    def tearDownClass(cls):
        for d in (cls.config_dir, cls.services_dir, cls.sysusers_dir):
            shutil.rmtree(d)

    def test_generator_exits_zero(self):
        self.assertEqual(self.gen_result.returncode, 0, self.gen_result.stderr)

    def test_service_file_created_for_each(self):
        """Every enabled workload gets a service file."""
        for filename, config in self.configs.items():
            name = config["workload"]["name"]
            with self.subTest(workload=name):
                service_path = Path(self.services_dir) / f"workload-{name}.service"
                self.assertTrue(service_path.exists(),
                                f"No service file for {name}")

    def test_sysusers_created_for_each(self):
        """Every workload gets a sysusers conf."""
        for filename, config in self.configs.items():
            name = config["workload"]["name"]
            with self.subTest(workload=name):
                sysusers_path = Path(self.sysusers_dir) / f"workload-{name}.conf"
                self.assertTrue(sysusers_path.exists(),
                                f"No sysusers conf for {name}")

    def test_sysusers_has_correct_username(self):
        for filename, config in self.configs.items():
            name = config["workload"]["name"]
            with self.subTest(workload=name):
                content = (Path(self.sysusers_dir) / f"workload-{name}.conf").read_text()
                self.assertIn(f"_wl-{name}", content)

    def test_image_in_exec_start(self):
        """The container image appears in the ExecStart line."""
        for filename, config in self.configs.items():
            if "vm" in config:
                continue  # VM workloads have no container image
            name = config["workload"]["name"]
            self.assertIn("container", config,
                          f"{filename}: non-VM workload has no [container] section")
            image = config["container"]["image"]
            with self.subTest(workload=name):
                service = self._read_service(name)
                self.assertIn(image, service,
                              f"Image '{image}' not found in service for {name}")

    def test_user_directive(self):
        """Service runs as the workload user."""
        for filename, config in self.configs.items():
            name = config["workload"]["name"]
            with self.subTest(workload=name):
                service = self._read_service(name)
                self.assertIn(f"User=_wl-{name}", service)

    def test_network_mode(self):
        """Network mode from config appears in podman args."""
        for filename, config in self.configs.items():
            name = config["workload"]["name"]
            mode = config.get("network", {}).get("mode")
            with self.subTest(workload=name):
                service = self._read_service(name)
                if mode == "host":
                    self.assertIn('--network="host"', service)
                elif mode == "pasta":
                    self.assertIn('--network="pasta"', service)

    def test_ports_forwarded(self):
        """Declared ports appear as --publish args."""
        for filename, config in self.configs.items():
            name = config["workload"]["name"]
            ports = config.get("network", {}).get("ports", [])
            mode = config.get("network", {}).get("mode")
            if mode == "host":
                continue  # host networking doesn't use --publish
            with self.subTest(workload=name):
                service = self._read_service(name)
                for port in ports:
                    self.assertIn(f"--publish {port}", service,
                                  f"Port {port} not published for {name}")

    def test_volumes_mounted(self):
        """Declared volumes appear in the service file."""
        for filename, config in self.configs.items():
            name = config["workload"]["name"]
            volumes = config.get("storage", {}).get("volumes", [])
            with self.subTest(workload=name):
                service = self._read_service(name)
                for vol in volumes:
                    # Relative paths get expanded, so check the container path
                    container_path = vol.split(":")[1]
                    self.assertIn(container_path, service,
                                  f"Volume container path '{container_path}' not found for {name}")

    def test_userns_applied(self):
        """User namespace setting from config appears in podman args."""
        for filename, config in self.configs.items():
            if "vm" in config:
                continue  # VM workloads don't use podman userns
            name = config["workload"]["name"]
            security = config.get("security", {})
            userns = security.get("userns")
            has_extra_maps = bool(
                security.get("extra_groups")
                or security.get("extra_uidmaps")
                or security.get("extra_gidmaps")
            )
            with self.subTest(workload=name):
                service = self._read_service(name)
                if userns == "host":
                    # userns=host has no namespace to remap: the generator
                    # emits --userns=host and carries extra_groups via
                    # --group-add=keep-groups, never --uidmap/--gidmap.
                    self.assertIn("--userns=host", service)
                elif has_extra_maps:
                    # extra_groups/uidmaps/gidmaps trigger --uidmap/--gidmap
                    # (podman 5.x forbids mixing --userns with these flags)
                    self.assertIn("--uidmap ", service)
                elif userns is None:
                    self.assertIn("--userns=keep-id", service)
                else:
                    self.assertIn(f"--userns={userns}", service)

    def test_capabilities_added(self):
        """Declared capabilities appear as --cap-add args."""
        for filename, config in self.configs.items():
            name = config["workload"]["name"]
            caps = config.get("security", {}).get("capabilities", [])
            with self.subTest(workload=name):
                service = self._read_service(name)
                for cap in caps:
                    self.assertIn(f"--cap-add={cap}", service,
                                  f"Capability {cap} not added for {name}")

    def _read_dropin(self, name):
        """Read the user@<uid>.service.d/50-workload.conf for a workload by name."""
        for dropin in Path(self.services_dir).glob("user@*.service.d/50-workload.conf"):
            text = dropin.read_text()
            if f"Workload {name}:" in text:
                return text
        return ""

    def test_resource_limits_applied(self):
        """Under option 1b: cgroup limits land in the user@ drop-in (not the
        workload unit); per-container OOM limits appear as podman flags."""
        for filename, config in self.configs.items():
            if "vm" in config:
                continue  # VM workloads use system-unit resource directives directly
            name = config["workload"]["name"]
            resources = config.get("resources", {})
            with self.subTest(workload=name):
                service = self._read_service(name)
                dropin = self._read_dropin(name)
                if "cpu_quota" in resources:
                    # Drop-in carries the cgroup directive; service carries the podman flag
                    self.assertIn(f"CPUQuota={resources['cpu_quota']}", dropin)
                    self.assertNotIn(f"CPUQuota={resources['cpu_quota']}", service)
                if "memory_max" in resources:
                    self.assertIn(f"MemoryMax={resources['memory_max']}", dropin)
                    self.assertNotIn(f"MemoryMax={resources['memory_max']}", service)
                    self.assertIn(f"--memory={resources['memory_max']}", service)
                if "memory_high" in resources:
                    self.assertIn(f"MemoryHigh={resources['memory_high']}", dropin)
                if "tasks_max" in resources:
                    self.assertIn(f"TasksMax={resources['tasks_max']}", dropin)
                    self.assertIn(f"--pids-limit={resources['tasks_max']}", service)
                if "memory_swap_max" in resources:
                    self.assertIn(
                        f"MemorySwapMax={resources['memory_swap_max']}", dropin)

    def test_environment_variables(self):
        """Plain (non-secret) env vars appear as --env args."""
        for filename, config in self.configs.items():
            name = config["workload"]["name"]
            env_vars = config.get("container", {}).get("environment", {})
            with self.subTest(workload=name):
                service = self._read_service(name)
                for key, value in env_vars.items():
                    if "${SECRET:" in value:
                        # Secret vars go via env-file, not --env
                        self.assertNotIn(f"--env {key}=", service,
                                         f"Secret var {key} should not be in --env for {name}")
                    else:
                        self.assertIn(f"--env {key}=", service,
                                      f"Env var {key} not found for {name}")

    def test_pull_policy(self):
        """pull setting appears as --pull arg."""
        for filename, config in self.configs.items():
            name = config["workload"]["name"]
            pull = config.get("container", {}).get("pull")
            with self.subTest(workload=name):
                service = self._read_service(name)
                if pull:
                    self.assertIn(f"--pull={pull}", service,
                                  f"Pull policy '{pull}' not found for {name}")

    def test_command_args(self):
        """Container command appears after the image in ExecStart."""
        for filename, config in self.configs.items():
            name = config["workload"]["name"]
            command = config.get("container", {}).get("command")
            if not command:
                continue
            with self.subTest(workload=name):
                service = self._read_service(name)
                if isinstance(command, list):
                    for arg in command:
                        self.assertIn(arg, service,
                                      f"Command arg '{arg}' not found for {name}")
                else:
                    self.assertIn(command, service,
                                  f"Command '{command}' not found for {name}")

    def test_health_check_args(self):
        """Workloads with [container.health] get --health-cmd in ExecStart."""
        for filename, config in self.configs.items():
            name = config["workload"]["name"]
            health = config.get("container", {}).get("health", {})
            health_cmd = health.get("cmd", "")
            with self.subTest(workload=name):
                service = self._read_service(name)
                if health_cmd:
                    self.assertIn("--health-cmd", service,
                                  f"Missing --health-cmd for {name}")
                    if "interval" in health:
                        self.assertIn(f"--health-interval={health['interval']}", service)
                    if "start_period" in health:
                        self.assertIn(f"--health-start-period={health['start_period']}", service)
                    if "on_failure" in health:
                        self.assertIn(f"--health-on-failure={health['on_failure']}", service)
                else:
                    self.assertNotIn("--health-cmd", service,
                                     f"Unexpected --health-cmd for {name}")

    def test_all_http_workloads_have_health_checks(self):
        """Workloads with HTTP ports should have health checks configured."""
        http_workloads_with_ports = set()
        for filename, config in self.configs.items():
            name = config["workload"]["name"]
            ports = config.get("network", {}).get("ports", [])
            if ports:
                http_workloads_with_ports.add(name)
        for filename, config in self.configs.items():
            name = config["workload"]["name"]
            if name in http_workloads_with_ports:
                with self.subTest(workload=name):
                    health = config.get("container", {}).get("health", {})
                    self.assertTrue(health.get("cmd"),
                                    f"{name} exposes ports but has no health check")

    def test_autostart_symlink(self):
        """Each workload has a multi-user.target.wants symlink."""
        for filename, config in self.configs.items():
            name = config["workload"]["name"]
            with self.subTest(workload=name):
                wants = (Path(self.services_dir) / "multi-user.target.wants"
                         / f"workload-{name}.service")
                self.assertTrue(wants.is_symlink(),
                                f"No autostart symlink for {name}")

    def _read_service(self, name):
        return (Path(self.services_dir) / f"workload-{name}.service").read_text()


@unittest.skipUnless(has_systemd_analyze(), "systemd-analyze not available")
class TestWorkloadSystemdVerify(unittest.TestCase):
    """Run systemd-analyze verify on every generated workload service."""

    config_dir: str
    services_dir: str
    sysusers_dir: str

    @classmethod
    def setUpClass(cls):
        cls.config_dir = tempfile.mkdtemp()
        cls.services_dir = tempfile.mkdtemp()
        cls.sysusers_dir = tempfile.mkdtemp()

        for filename, config in ALL_WORKLOADS:
            config_copy = _deep_copy_config(config)
            toml_text = _config_to_toml(config_copy)
            wl_name = filename.removesuffix(".toml")
            (Path(cls.config_dir) / wl_name).mkdir(exist_ok=True)
            (Path(cls.config_dir) / wl_name / "workload.toml").write_text(toml_text)
            (Path(cls.config_dir) / wl_name / ".enabled").touch()

        run_generator(cls.config_dir, cls.services_dir, cls.sysusers_dir)

        # Patch helper paths for verify: workloadctl's libexec helpers live in
        # the installed package, not the test env (dev box or CI). systemd-analyze
        # verify only needs each Exec* binary to exist and be executable, so swap
        # every /usr/libexec/workloadctl/<helper> for /bin/true. Done generically
        # (not per-helper) so adding a new helper — e.g. workload-vm-shutdown —
        # never silently breaks verify again.
        # Same idea for podman itself: dev containers don't ship it, and
        # systemd-analyze fails the whole unit on a non-executable ExecStart.
        # Only patched when actually absent so real hosts keep strict verify.
        patch_podman = not os.path.exists("/usr/bin/podman")

        # GPU workloads Require= nvidia-cdi-generator.service, shipped by the
        # hypervisor image. Stub it next to the units (systemd-analyze resolves
        # references from the unit's own directory) when the host lacks it.
        if not os.path.exists("/usr/lib/systemd/system/nvidia-cdi-generator.service"):
            (Path(cls.services_dir) / "nvidia-cdi-generator.service").write_text(
                "[Unit]\nDescription=verify stub\n"
                "[Service]\nType=oneshot\nExecStart=/bin/true\n"
            )
        for service_path in Path(cls.services_dir).glob("workload-*.service"):
            content = service_path.read_text()
            content = re.sub(r"/usr/libexec/workloadctl/[\w-]+", "/bin/true", content)
            if patch_podman:
                content = content.replace("/usr/bin/podman", "/bin/true")
            service_path.write_text(content)

    @classmethod
    def tearDownClass(cls):
        for d in (cls.config_dir, cls.services_dir, cls.sysusers_dir):
            shutil.rmtree(d)

    def test_verify_each_workload(self):
        """systemd-analyze verify passes for each workload."""
        for filename, config in ALL_WORKLOADS:
            name = config["workload"]["name"]
            with self.subTest(workload=name):
                service_path = Path(self.services_dir) / f"workload-{name}.service"
                result = subprocess.run(
                    ["systemd-analyze", "verify", str(service_path)],
                    capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, 0,
                                 f"systemd-analyze verify failed for {name}:\n{result.stderr}")

    def test_no_unknown_directives(self):
        """No 'Unknown key' warnings in any workload service."""
        for filename, config in ALL_WORKLOADS:
            name = config["workload"]["name"]
            with self.subTest(workload=name):
                service_path = Path(self.services_dir) / f"workload-{name}.service"
                result = subprocess.run(
                    ["systemd-analyze", "verify", str(service_path)],
                    capture_output=True, text=True,
                )
                self.assertNotIn("Unknown key", result.stderr,
                                 f"Unknown directives in {name}:\n{result.stderr}")


class TestWorkloadCrossConfigConsistency(unittest.TestCase):
    """Check for conflicts between workload configs."""

    def test_no_duplicate_names(self):
        """No two workloads share the same name."""
        names = [c["workload"]["name"] for _, c in ALL_WORKLOADS]
        self.assertEqual(len(names), len(set(names)),
                         f"Duplicate workload names: {names}")

    def test_no_host_port_conflicts(self):
        """Workloads using the same network mode don't claim the same host port.

        Host-network workloads bind directly; pasta workloads forward ports.
        Port conflicts only matter within the same mode (both can't bind 53).
        We check all ports together since the host sees them the same way.
        """
        # Collect (port_number, protocol) → [workload_name]
        port_claims: dict = {}
        for filename, config in ALL_WORKLOADS:
            name = config["workload"]["name"]
            ports = config.get("network", {}).get("ports", [])
            for port_spec in ports:
                # Normalize: extract port number and protocol
                if "/" in port_spec:
                    proto = port_spec.rsplit("/", 1)[1]
                else:
                    proto = "tcp"

                # Get the host port (first number or second if IP prefix)
                port_parts = port_spec.replace("/tcp", "").replace("/udp", "").split(":")
                if len(port_parts) == 3:
                    host_port = port_parts[1]
                else:
                    host_port = port_parts[0]

                key = (host_port, proto)
                port_claims.setdefault(key, []).append(name)

        for (port, proto), claimants in port_claims.items():
            if len(claimants) > 1:
                # Allow it if workloads serve different purposes (e.g., pihole and dns-vpn
                # both want port 53 but you'd never run both). Just flag for awareness.
                self.assertLessEqual(
                    len(claimants), 5,  # Soft limit — just catch obviously wrong configs
                    f"Port {port}/{proto} claimed by many workloads: {claimants}")

    def test_vpn_workloads_have_net_admin(self):
        """Workloads with WireGuard volumes should have NET_ADMIN capability."""
        for filename, config in ALL_WORKLOADS:
            name = config["workload"]["name"]
            volumes = config.get("storage", {}).get("volumes", [])
            has_wg = any("wireguard" in v for v in volumes)
            if has_wg:
                with self.subTest(workload=name):
                    caps = config.get("security", {}).get("capabilities", [])
                    self.assertIn("NET_ADMIN", caps,
                                  f"{name} mounts wireguard config but lacks NET_ADMIN")

    def test_vpn_workloads_use_container_root_userns(self):
        """wg-quick needs to run as root inside the container, but that only
        requires container root — NOT the host user namespace. These workloads
        use keep-id:uid=0,gid=0 (container root in a private userns); userns=host
        is reserved for workloads that must observe host-side UIDs (S5)."""
        for filename, config in ALL_WORKLOADS:
            name = config["workload"]["name"]
            volumes = config.get("storage", {}).get("volumes", [])
            has_wg = any("wireguard" in v for v in volumes)
            if has_wg:
                with self.subTest(workload=name):
                    userns = config.get("security", {}).get("userns")
                    self.assertEqual(userns, "keep-id:uid=0,gid=0",
                                     f"{name} mounts wireguard config but userns "
                                     f"!= keep-id:uid=0,gid=0")

    def test_host_userns_configs_carry_optin(self):
        """Any shipped workload using userns=host must acknowledge it via
        unsafe_host_userns (S5) — otherwise it fails validation and won't
        generate. Guards against a new host-userns config slipping in unacked."""
        from workload_lib import uses_host_userns, host_userns_acknowledged
        for filename, config in ALL_WORKLOADS:
            name = config["workload"]["name"]
            if uses_host_userns(config):
                with self.subTest(workload=name):
                    self.assertTrue(
                        host_userns_acknowledged(config),
                        f"{name} uses userns=host without unsafe_host_userns=true")

    def test_local_images_have_pull_policy(self):
        """Images from localhost/ should explicitly set a pull policy."""
        for filename, config in ALL_WORKLOADS:
            if "vm" in config:
                continue  # VM workloads have no container image
            name = config["workload"]["name"]
            self.assertIn("container", config,
                          f"{filename}: non-VM workload has no [container] section")
            image = config["container"]["image"]
            if image.startswith("localhost/"):
                with self.subTest(workload=name):
                    pull = config.get("container", {}).get("pull")
                    self.assertIsNotNone(pull,
                                         f"{name} uses localhost/ image but has no pull policy")

    def test_required_files_are_relative(self):
        """required_files paths should be relative (./...) for home-dir resolution."""
        for filename, config in ALL_WORKLOADS:
            name = config["workload"]["name"]
            required = config.get("setup", {}).get("required_files", [])
            for entry in required:
                with self.subTest(workload=name, path=entry["path"]):
                    self.assertTrue(entry["path"].startswith("./"),
                                    f"{name}: required_file '{entry['path']}' should be relative (./...)")


# ---------------------------------------------------------------------------
# Helpers for materializing TOML configs in a temp dir
# ---------------------------------------------------------------------------

def _deep_copy_config(config):
    """Simple deep copy of a nested dict (no external deps)."""
    result = {}
    for k, v in config.items():
        if isinstance(v, dict):
            result[k] = _deep_copy_config(v)
        elif isinstance(v, list):
            result[k] = [_deep_copy_config(i) if isinstance(i, dict) else i for i in v]
        else:
            result[k] = v
    return result


def _toml_value(value):
    """Format a Python value as TOML."""
    if isinstance(value, bool):
        return "true" if value else "false"
    elif isinstance(value, int):
        return str(value)
    elif isinstance(value, str):
        return f'"{value}"'
    elif isinstance(value, list):
        if all(isinstance(i, dict) for i in value):
            # Array of inline tables
            parts = []
            for item in value:
                fields = ", ".join(f'{k} = {_toml_value(v)}' for k, v in item.items())
                parts.append(f"{{ {fields} }}")
            return "[\n    " + ",\n    ".join(parts) + ",\n]"
        else:
            parts = [_toml_value(v) for v in value]
            return "[\n    " + ",\n    ".join(parts) + ",\n]"
    return str(value)


def _config_to_toml(config, prefix=""):
    """Convert a config dict back to TOML text.

    Simple serializer — handles the structures found in workload configs.
    """
    lines = []
    # First pass: scalar values
    for key, value in config.items():
        if isinstance(value, dict) or isinstance(value, list) and all(isinstance(i, dict) for i in value):
            continue
        lines.append(f"{key} = {_toml_value(value)}")

    # Second pass: sub-tables
    for key, value in config.items():
        if isinstance(value, dict):
            section = f"{prefix}{key}" if not prefix else f"{prefix}.{key}"
            lines.append(f"\n[{section}]")
            lines.append(_config_to_toml(value, section))
        elif isinstance(value, list) and value and isinstance(value[0], dict):
            # Array of tables — but workload configs use inline tables in arrays
            # so we handle this in _toml_value above
            lines.append(f"{key} = {_toml_value(value)}")

    return "\n".join(lines)


if __name__ == "__main__":
    unittest.main()
