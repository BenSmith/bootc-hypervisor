#!/usr/bin/env python3
"""Integration tests for the workload generator.

Runs the generator with temp directories and validates the output files.
No root required — all paths are overridden via env vars and argv.
"""

import importlib.machinery
import importlib.util
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

GENERATOR = os.path.join(os.path.dirname(__file__), '..', 'generators', 'workload-generate')
LIB_DIR = os.path.join(os.path.dirname(__file__), '..', 'lib')


def _load_generator_module():
    """Import workload-generate as a module (it has a __main__ guard)."""
    if LIB_DIR not in sys.path:
        sys.path.insert(0, LIB_DIR)
    loader = importlib.machinery.SourceFileLoader("workload_generate", GENERATOR)
    spec = importlib.util.spec_from_loader("workload_generate", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def run_generator(config_dir, services_dir, sysusers_dir):
    """Run the generator and return the CompletedProcess."""
    env = os.environ.copy()
    env["WORKLOAD_CONFIG_DIR"] = str(config_dir)
    env["SYSUSERS_DIR"] = str(sysusers_dir)
    env["PYTHONPATH"] = LIB_DIR
    env["WORKLOAD_GENERATE_LOG_STDERR"] = "1"
    return subprocess.run(
        [sys.executable, GENERATOR, str(services_dir)],
        capture_output=True, text=True, env=env,
    )


def write_config(config_dir, name, toml_content):
    """Write a TOML config file to the config directory."""
    path = Path(config_dir) / f"{name}.toml"
    path.write_text(textwrap.dedent(toml_content))
    return path


class TestGeneratorBasic(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def run_gen(self):
        return run_generator(self.config_dir, self.services_dir, self.sysusers_dir)

    def read_service(self, name):
        return (Path(self.services_dir) / f"workload-{name}.service").read_text()

    def read_sysusers(self, name):
        return (Path(self.sysusers_dir) / f"workload-{name}.conf").read_text()

    def test_basic_workload(self):
        write_config(self.config_dir, "web", """\
            [workload]
            name = "web"
            enabled = true

            [container]
            image = "docker.io/nginx:latest"

            [network]
            ports = ["8080:80"]
        """)

        result = self.run_gen()
        self.assertEqual(result.returncode, 0)

        service = self.read_service("web")
        self.assertIn("ExecStart=/usr/bin/podman run", service)
        self.assertIn('"docker.io/nginx:latest"', service)
        self.assertIn("--publish 8080:80", service)
        self.assertIn("User=_wl-web", service)
        self.assertIn("--network=", service)
        self.assertIn("Slice=workloads.slice", service)

        sysusers = self.read_sysusers("web")
        self.assertIn("u _wl-web", sysusers)

    def test_disabled_workload_skipped(self):
        write_config(self.config_dir, "off", """\
            [workload]
            name = "off"
            enabled = false

            [container]
            image = "nginx"
        """)

        self.run_gen()
        self.assertFalse(
            (Path(self.services_dir) / "workload-off.service").exists()
        )

    def test_missing_name_skipped(self):
        write_config(self.config_dir, "broken", """\
            [workload]
            enabled = true

            [container]
            image = "nginx"
        """)

        result = self.run_gen()
        self.assertEqual(result.returncode, 0)  # generator always exits 0
        self.assertFalse(
            (Path(self.services_dir) / "workload-broken.service").exists()
        )

    def test_symlink_for_autostart(self):
        write_config(self.config_dir, "svc", """\
            [workload]
            name = "svc"
            enabled = true

            [container]
            image = "alpine"
        """)

        self.run_gen()
        wants = Path(self.services_dir) / "multi-user.target.wants" / "workload-svc.service"
        self.assertTrue(wants.is_symlink())
        self.assertEqual(os.readlink(wants), "../workload-svc.service")


class TestGeneratorMultiContainer(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def run_gen(self):
        return run_generator(self.config_dir, self.services_dir, self.sysusers_dir)

    def test_bridge_mode_generates_net_and_per_container_units(self):
        write_config(self.config_dir, "app", """\
            [workload]
            name = "app"
            enabled = true
            mode = "bridge"

            [[containers]]
            name = "db"
            [containers.container]
            image = "postgres:16"

            [[containers]]
            name = "web"
            [containers.container]
            image = "myapp:latest"
            [containers.network]
            ports = ["3000:3000"]
        """)
        r = self.run_gen()
        self.assertEqual(r.returncode, 0, r.stderr)

        net = (Path(self.services_dir) / "workload-app-net.service").read_text()
        self.assertIn("podman network create workload-app-net", net)
        self.assertIn("PartOf=workload-app.service", net)

        web = (Path(self.services_dir) / "workload-app-web.service").read_text()
        self.assertIn("--network=", web)
        self.assertIn("workload-app-net", web)
        self.assertIn("--network-alias=\"web\"", web)
        self.assertIn("--publish 3000:3000", web)
        self.assertIn("BindsTo=workload-app-net.service", web)
        self.assertIn("PartOf=workload-app.service", web)
        self.assertNotIn("--pod=", web)

        db = (Path(self.services_dir) / "workload-app-db.service").read_text()
        self.assertIn("workload-app-net", db)
        self.assertNotIn("--publish", db)

        umbrella = (Path(self.services_dir) / "workload-app.service").read_text()
        self.assertIn("workload-app-net.service", umbrella)
        self.assertNotIn("workload-app-pod.service", umbrella)

    def test_per_container_environment_sibling_form(self):
        """[containers.environment] (sibling of [containers.container]) must
        reach the per-container service as --env flags. This is the form the
        shipped example TOMLs use."""
        write_config(self.config_dir, "app", """\
            [workload]
            name = "app"
            enabled = true
            mode = "bridge"

            [[containers]]
            name = "web"
            [containers.container]
            image = "myapp:latest"
            [containers.environment]
            APP_ENV = "production"
            APP_PORT = "8080"
        """)
        r = self.run_gen()
        self.assertEqual(r.returncode, 0, r.stderr)
        web = (Path(self.services_dir) / "workload-app-web.service").read_text()
        self.assertIn("--env APP_ENV=production", web)
        self.assertIn("--env APP_PORT=8080", web)

    def test_per_container_environment_nested_form(self):
        """[containers.container.environment] (nested under [containers.container])
        is also accepted — it's the form the schema field-allocation block
        documents."""
        write_config(self.config_dir, "app", """\
            [workload]
            name = "app"
            enabled = true
            mode = "bridge"

            [[containers]]
            name = "web"
            [containers.container]
            image = "myapp:latest"
            [containers.container.environment]
            APP_ENV = "production"
        """)
        r = self.run_gen()
        self.assertEqual(r.returncode, 0, r.stderr)
        web = (Path(self.services_dir) / "workload-app-web.service").read_text()
        self.assertIn("--env APP_ENV=production", web)

    def test_per_container_environment_both_forms_rejected(self):
        """Setting env at both [containers.environment] AND
        [containers.container.environment] is ambiguous — generator should
        skip the workload and log an error rather than pick a winner."""
        write_config(self.config_dir, "app", """\
            [workload]
            name = "app"
            enabled = true
            mode = "bridge"

            [[containers]]
            name = "web"
            [containers.container]
            image = "myapp:latest"
            [containers.environment]
            FOO = "sibling"
            [containers.container.environment]
            FOO = "nested"
        """)
        r = self.run_gen()
        self.assertEqual(r.returncode, 0, r.stderr)
        # Generator skips on validation error → no service file written
        self.assertFalse(
            (Path(self.services_dir) / "workload-app-web.service").exists()
        )
        self.assertIn("environment", r.stdout + r.stderr)

    def test_per_container_health_sibling_form(self):
        """[containers.health] should render as --health-* flags on the
        per-container service."""
        write_config(self.config_dir, "app", """\
            [workload]
            name = "app"
            enabled = true
            mode = "bridge"

            [[containers]]
            name = "web"
            [containers.container]
            image = "myapp:latest"
            [containers.health]
            cmd = "curl -f http://localhost/ || exit 1"
            interval = "10s"
            start_period = "5s"
            on_failure = "kill"
        """)
        r = self.run_gen()
        self.assertEqual(r.returncode, 0, r.stderr)
        web = (Path(self.services_dir) / "workload-app-web.service").read_text()
        self.assertIn('--health-cmd "curl -f http://localhost/ || exit 1"', web)
        self.assertIn("--health-interval=10s", web)
        self.assertIn("--health-start-period=5s", web)
        # Under --cgroups=split (bridge mode) podman's own user-manager
        # healthcheck timer is broken, so the generator suppresses it, pins
        # podman's own on-failure action to none (workload-healthcheck owns it),
        # and Wants= a system-manager timer instead.
        self.assertIn("--health-on-failure=none", web)
        self.assertNotIn("--health-on-failure=kill", web)
        self.assertIn("Environment=DISABLE_HC_SYSTEMD=true", web)
        self.assertIn("Wants=workload-app-web-health.timer", web)

    def test_split_healthcheck_units_emitted(self):
        """A split (single-mode) workload with a health.cmd gets a paired
        system-manager healthcheck .service + .timer that runs
        workload-healthcheck, and the workload unit suppresses podman's own
        --user timer."""
        write_config(self.config_dir, "hc", """\
            [workload]
            name = "hc"
            enabled = true
            mode = "single"

            [container]
            image = "myapp:latest"
            [container.health]
            cmd = "test -f /tmp/ok"
            interval = "30s"
            start_period = "15s"
            on_failure = "restart"
        """)
        r = self.run_gen()
        self.assertEqual(r.returncode, 0, r.stderr)
        svc = (Path(self.services_dir) / "workload-hc.service").read_text()
        self.assertIn("Environment=DISABLE_HC_SYSTEMD=true", svc)
        self.assertIn("Wants=workload-hc-health.timer", svc)
        self.assertIn("--health-on-failure=none", svc)

        hsvc = (Path(self.services_dir) / "workload-hc-health.service").read_text()
        self.assertIn(
            "ExecStart=/usr/libexec/workloadctl/workload-healthcheck "
            "hc workload-hc workload-hc.service restart",
            hsvc,
        )
        self.assertIn("Type=oneshot", hsvc)
        self.assertIn("BindsTo=workload-hc.service", hsvc)

        timer = (Path(self.services_dir) / "workload-hc-health.timer").read_text()
        self.assertIn("OnActiveSec=15s", timer)
        self.assertIn("OnUnitActiveSec=30s", timer)
        self.assertIn("BindsTo=workload-hc.service", timer)

    def test_pod_mode_keeps_podman_healthcheck(self):
        """Pod-mode containers run in the user manager where podman's own
        healthcheck timer works, so the generator must NOT suppress it or emit
        its own timer."""
        write_config(self.config_dir, "pm", """\
            [workload]
            name = "pm"
            enabled = true
            mode = "pod"

            [[containers]]
            name = "web"
            [containers.container]
            image = "myapp:latest"
            [containers.health]
            cmd = "true"
            on_failure = "kill"
        """)
        r = self.run_gen()
        self.assertEqual(r.returncode, 0, r.stderr)
        web = (Path(self.services_dir) / "workload-pm-web.service").read_text()
        self.assertIn("--health-on-failure=kill", web)
        self.assertNotIn("DISABLE_HC_SYSTEMD", web)
        self.assertFalse(
            (Path(self.services_dir) / "workload-pm-web-health.timer").exists()
        )

    def test_per_container_secret_env_var(self):
        """${SECRET:name} inside a [containers.environment] block must trigger
        LoadCredentialEncrypted, --env-file, and the workload-write-env
        ExecStartPre with the per-container name. This regresses the original
        Forgejo-example bug where secret env vars were silently dropped."""
        write_config(self.config_dir, "stack", """\
            [workload]
            name = "stack"
            enabled = true
            mode = "bridge"

            [[containers]]
            name = "db"
            [containers.container]
            image = "postgres:16"
            [containers.environment]
            POSTGRES_PASSWORD = "${SECRET:db-pw}"
        """)
        r = self.run_gen()
        self.assertEqual(r.returncode, 0, r.stderr)
        db = (Path(self.services_dir) / "workload-stack-db.service").read_text()
        # Credential gets loaded onto this per-container unit
        self.assertIn("LoadCredentialEncrypted=db-pw:", db)
        # --env-file points at the per-container file, not the shared one
        self.assertIn("--env-file", db)
        self.assertIn("/run/workload-env/workload-stack-db.secrets", db)
        self.assertNotIn("/run/workload-env/workload-stack.secrets", db)
        # write-env invoked with the local container name
        self.assertIn(
            "ExecStartPre=+/usr/libexec/workloadctl/workload-write-env stack db",
            db,
        )
        # Plain env var path is unchanged
        self.assertNotIn("--env POSTGRES_PASSWORD=", db)

    def test_pod_mode_generates_pod_and_per_container_units(self):
        write_config(self.config_dir, "stack", """\
            [workload]
            name = "stack"
            enabled = true

            [network]
            mode = "pasta"
            ports = ["8080:80"]

            [[containers]]
            name = "a"
            [containers.container]
            image = "img-a"

            [[containers]]
            name = "b"
            [containers.container]
            image = "img-b"
        """)
        r = self.run_gen()
        self.assertEqual(r.returncode, 0, r.stderr)

        pod = (Path(self.services_dir) / "workload-stack-pod.service").read_text()
        self.assertIn("podman pod create --name=workload-stack", pod)
        self.assertIn("--network=pasta", pod)
        self.assertIn("--publish 8080:80", pod)
        self.assertIn("PartOf=workload-stack.service", pod)

        a = (Path(self.services_dir) / "workload-stack-a.service").read_text()
        self.assertIn("--pod=", a)
        self.assertIn("workload-stack", a)
        self.assertIn("--name ", a)
        self.assertIn("workload-stack-a", a)
        self.assertNotIn("--publish", a)
        self.assertIn("BindsTo=workload-stack-pod.service", a)
        self.assertIn("PartOf=workload-stack.service", a)

        umbrella = (Path(self.services_dir) / "workload-stack.service").read_text()
        self.assertIn("Type=oneshot", umbrella)
        # Requires= (not Wants=) so sub-service failures propagate to the umbrella —
        # `systemctl is-active workload-<n>.service` then reflects container failures.
        self.assertIn("Requires=workload-stack-a.service workload-stack-b.service", umbrella)


class TestGeneratorPlainEnvVars(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def test_plain_env_vars_as_args(self):
        write_config(self.config_dir, "app", """\
            [workload]
            name = "app"
            enabled = true

            [container]
            image = "myapp"

            [container.environment]
            FOO = "bar"
            PORT = "8080"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-app.service").read_text()

        self.assertIn("--env FOO=", service)
        self.assertIn("--env PORT=", service)
        # No shell wrapper
        self.assertNotIn("/bin/sh -c", service)
        # No env-file (no secrets)
        self.assertNotIn("--env-file", service)
        self.assertNotIn("workload-write-env", service)


class TestGeneratorSecrets(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def test_secret_env_vars_use_env_file(self):
        write_config(self.config_dir, "secret-app", """\
            [workload]
            name = "secret-app"
            enabled = true

            [container]
            image = "myapp"

            [container.environment]
            API_KEY = "${SECRET:api-key}"
            PLAIN = "visible"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-secret-app.service").read_text()

        # Secret env var NOT passed as --env
        self.assertNotIn("--env API_KEY=", service)
        # Plain env var still passed as --env
        self.assertIn("--env PLAIN=", service)
        # env-file for secrets
        self.assertIn("--env-file", service)
        self.assertIn("workload-secret-app.secrets", service)
        # write-env helper in ExecStartPre
        self.assertIn("ExecStartPre=+/usr/libexec/workloadctl/workload-write-env secret-app", service)
        # No shell wrapper
        self.assertNotIn("/bin/sh -c", service)

    def test_load_credential_encrypted_directives(self):
        write_config(self.config_dir, "creds", """\
            [workload]
            name = "creds"
            enabled = true

            [container]
            image = "myapp"

            [container.environment]
            KEY = "${SECRET:my-key}"

            [secrets]
            files = [
                { credential = "tls-cert", path = "/etc/ssl/cert.pem" }
            ]
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-creds.service").read_text()

        self.assertIn("LoadCredentialEncrypted=my-key:", service)
        self.assertIn("LoadCredentialEncrypted=tls-cert:", service)

    def test_secret_file_volume_mount(self):
        write_config(self.config_dir, "filemount", """\
            [workload]
            name = "filemount"
            enabled = true

            [container]
            image = "myapp"

            [secrets]
            files = [
                { credential = "tls-cert", path = "/etc/ssl/cert.pem", mode = "ro" }
            ]
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-filemount.service").read_text()

        self.assertIn("--volume", service)
        self.assertIn("tls-cert", service)
        self.assertIn("/etc/ssl/cert.pem", service)
        # Single-container: source path uses the workload-level service name.
        self.assertIn("/run/credentials/workload-filemount.service/tls-cert", service)
        # No env-file needed (no secret env vars)
        self.assertNotIn("--env-file", service)
        self.assertNotIn("workload-write-env", service)

    def test_secret_file_volume_mount_multi_container(self):
        # Regression: in multi-container mode the credential is loaded onto the
        # per-container service, so the bind-mount source must reference that
        # unit's /run/credentials/ dir — not the umbrella's.
        write_config(self.config_dir, "multi-creds", """\
            [workload]
            name = "multi-creds"
            enabled = true
            mode = "pod"

            [[containers]]
            name = "app"
            [containers.container]
            image = "myapp"
            [containers.secrets]
            files = [
                { credential = "tls-cert", path = "/etc/ssl/cert.pem", mode = "ro" }
            ]

            [[containers]]
            name = "sidecar"
            [containers.container]
            image = "mysidecar"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        app_service = (Path(self.services_dir) / "workload-multi-creds-app.service").read_text()

        self.assertIn("LoadCredentialEncrypted=tls-cert:", app_service)
        self.assertIn(
            "/run/credentials/workload-multi-creds-app.service/tls-cert",
            app_service,
        )
        self.assertNotIn("/run/credentials/workload-multi-creds.service/", app_service)


class TestGeneratorVolumeExpansion(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def test_relative_volume_expanded(self):
        write_config(self.config_dir, "vols", """\
            [workload]
            name = "vols"
            enabled = true

            [container]
            image = "myapp"

            [storage]
            volumes = ["./data:/app/data:rw"]
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-vols.service").read_text()

        self.assertIn("/var/lib/workloads/vols/data", service)
        self.assertNotIn("./data", service)


class TestGeneratorDevices(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def test_gpu_amd(self):
        write_config(self.config_dir, "gpu", """\
            [workload]
            name = "gpu"
            enabled = true

            [container]
            image = "rocm-app"

            [devices]
            gpu = "amd"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-gpu.service").read_text()

        self.assertIn("--device /dev/kfd", service)
        self.assertIn("--device /dev/dri", service)

    def test_generic_device(self):
        write_config(self.config_dir, "usb", """\
            [workload]
            name = "usb"
            enabled = true

            [container]
            image = "myapp"

            [devices]
            devices = ["/dev/ttyUSB0"]
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-usb.service").read_text()

        self.assertIn("--device /dev/ttyUSB0", service)


class TestGeneratorResources(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def test_cpu_and_memory_limits(self):
        write_config(self.config_dir, "limited", """\
            [workload]
            name = "limited"
            enabled = true

            [container]
            image = "myapp"

            [resources]
            cpu_quota = "200%"
            memory_max = "4G"
            tasks_max = 100
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-limited.service").read_text()

        self.assertIn("CPUQuota=200%", service)
        self.assertIn("MemoryMax=4G", service)
        self.assertIn("TasksMax=100", service)

    def test_default_stop_grace_is_ten_seconds(self):
        # No timeout_stop_sec → podman's -t grace stays the historical 10s and
        # systemd's TimeoutStopSec defaults to 30 (comfortable margin above it).
        write_config(self.config_dir, "plain", """\
            [workload]
            name = "plain"
            enabled = true

            [container]
            image = "myapp"
        """)
        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-plain.service").read_text()
        self.assertIn("ExecStop=/usr/bin/podman stop -t 10 ", service)
        self.assertIn("TimeoutStopSec=30", service)

    def test_timeout_stop_sec_plumbs_into_podman_stop_grace(self):
        # A longer drain must reach podman's -t, not just systemd: podman's
        # grace tracks timeout_stop_sec minus a margin so systemd doesn't kill
        # `podman stop` before podman can SIGKILL + reap the container.
        write_config(self.config_dir, "slowdb", """\
            [workload]
            name = "slowdb"
            enabled = true

            [container]
            image = "myapp"

            [resources]
            timeout_stop_sec = 60
        """)
        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-slowdb.service").read_text()
        self.assertIn("ExecStop=/usr/bin/podman stop -t 55 ", service)
        self.assertIn("TimeoutStopSec=60", service)
        # The old hardcoded 10s grace must not linger.
        self.assertNotIn("podman stop -t 10 ", service)

    def test_timeout_stop_sec_as_timespan_falls_back_to_default_grace(self):
        # timeout_stop_sec accepts systemd timespans (e.g. "2min"); we can't
        # safely turn that into a -t seconds value, so podman's grace falls back
        # to 10s while TimeoutStopSec still passes the timespan through verbatim.
        write_config(self.config_dir, "spanstop", """\
            [workload]
            name = "spanstop"
            enabled = true

            [container]
            image = "myapp"

            [resources]
            timeout_stop_sec = "2min"
        """)
        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-spanstop.service").read_text()
        self.assertIn("ExecStop=/usr/bin/podman stop -t 10 ", service)
        self.assertIn("TimeoutStopSec=2min", service)


class TestGeneratorSlice(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def test_default_slice(self):
        write_config(self.config_dir, "app", """\
            [workload]
            name = "app"
            enabled = true

            [container]
            image = "myapp"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-app.service").read_text()
        self.assertIn("Slice=workloads.slice", service)

    def test_custom_slice(self):
        write_config(self.config_dir, "gpu", """\
            [workload]
            name = "gpu"
            enabled = true

            [container]
            image = "gpu-app"

            [resources]
            slice = "gpu-workloads.slice"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-gpu.service").read_text()
        self.assertIn("Slice=gpu-workloads.slice", service)
        self.assertNotIn("Slice=workloads.slice", service)

    def test_system_slice_override(self):
        write_config(self.config_dir, "sys", """\
            [workload]
            name = "sys"
            enabled = true

            [container]
            image = "sysapp"

            [resources]
            slice = "system.slice"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-sys.service").read_text()
        self.assertIn("Slice=system.slice", service)


class TestGeneratorUserns(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def test_default_keep_id(self):
        write_config(self.config_dir, "keepid", """\
            [workload]
            name = "keepid"
            enabled = true

            [container]
            image = "myapp"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-keepid.service").read_text()
        self.assertIn("--userns=keep-id", service)

    def test_host_userns(self):
        write_config(self.config_dir, "hostns", """\
            [workload]
            name = "hostns"
            enabled = true

            [container]
            image = "myapp"

            [security]
            userns = "host"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-hostns.service").read_text()
        self.assertIn("--userns=host", service)

    def test_keep_id_with_uid_gid(self):
        write_config(self.config_dir, "uidgid", """\
            [workload]
            name = "uidgid"
            enabled = true

            [container]
            image = "myapp"

            [security]
            userns = "keep-id:uid=65534,gid=65534"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-uidgid.service").read_text()
        self.assertIn("--userns=keep-id:uid=65534,gid=65534", service)

    def test_keep_id_with_uid_only(self):
        write_config(self.config_dir, "uidonly", """\
            [workload]
            name = "uidonly"
            enabled = true

            [container]
            image = "myapp"

            [security]
            userns = "keep-id:uid=1000"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-uidonly.service").read_text()
        self.assertIn("--userns=keep-id:uid=1000", service)

    def test_keep_id_with_gid_only(self):
        write_config(self.config_dir, "gidonly", """\
            [workload]
            name = "gidonly"
            enabled = true

            [container]
            image = "myapp"

            [security]
            userns = "keep-id:gid=1000"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-gidonly.service").read_text()
        self.assertIn("--userns=keep-id:gid=1000", service)

    def test_invalid_userns_defaults_to_keep_id(self):
        write_config(self.config_dir, "badns", """\
            [workload]
            name = "badns"
            enabled = true

            [container]
            image = "myapp"

            [security]
            userns = "bogus"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-badns.service").read_text()
        self.assertIn("--userns=keep-id", service)

    def test_keep_id_nonnumeric_uid_defaults_to_keep_id(self):
        write_config(self.config_dir, "baduid", """\
            [workload]
            name = "baduid"
            enabled = true

            [container]
            image = "myapp"

            [security]
            userns = "keep-id:uid=abc"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-baduid.service").read_text()
        self.assertIn("--userns=keep-id", service)

    def test_keep_id_unknown_param_defaults_to_keep_id(self):
        write_config(self.config_dir, "badparam", """\
            [workload]
            name = "badparam"
            enabled = true

            [container]
            image = "myapp"

            [security]
            userns = "keep-id:foo=1"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-badparam.service").read_text()
        self.assertIn("--userns=keep-id", service)


class TestGeneratorSelinuxLabel(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def test_single_container_workload_level_label(self):
        write_config(self.config_dir, "labeled", """\
            [workload]
            name = "labeled"
            enabled = true

            [container]
            image = "myapp"

            [security]
            selinux_policy = true
        """)
        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-labeled.service").read_text()
        self.assertIn("--security-opt=label=type:wl_labeled.process", service)

    def test_multi_container_workload_level_label_applied_to_all(self):
        # selinux_policy in top-level [security] → label on every container
        write_config(self.config_dir, "multi-sel", """\
            [workload]
            name = "multi-sel"
            enabled = true
            mode = "pod"

            [security]
            selinux_policy = true

            [[containers]]
            name = "app"
            [containers.container]
            image = "myapp"

            [[containers]]
            name = "sidecar"
            [containers.container]
            image = "mysidecar"
        """)
        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        for cname in ("app", "sidecar"):
            svc = (Path(self.services_dir) / f"workload-multi-sel-{cname}.service").read_text()
            self.assertIn("--security-opt=label=type:wl_multi_sel.process", svc)

    def test_multi_container_per_container_selinux_ignored_with_warning(self):
        # selinux_policy under [containers.security] is ignored; warning emitted
        write_config(self.config_dir, "bad-sel", """\
            [workload]
            name = "bad-sel"
            enabled = true
            mode = "pod"

            [[containers]]
            name = "app"
            [containers.container]
            image = "myapp"
            [containers.security]
            selinux_policy = true
        """)
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        svc = (Path(self.services_dir) / "workload-bad-sel-app.service").read_text()
        self.assertNotIn("label=type:", svc)
        self.assertIn("selinux_policy", result.stderr)
        self.assertIn("top-level [security] block", result.stderr)


class TestGeneratorServiceType(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def run_gen(self):
        return run_generator(self.config_dir, self.services_dir, self.sysusers_dir)

    def read_service(self, name):
        return (Path(self.services_dir) / f"workload-{name}.service").read_text()

    def test_default_service_type_is_exec(self):
        """No service_type set → Type=exec, --sdnotify=ignore."""
        write_config(self.config_dir, "plain", """\
            [workload]
            name = "plain"
            enabled = true

            [container]
            image = "alpine"
        """)
        self.run_gen()
        service = self.read_service("plain")
        self.assertIn("Type=exec", service)
        self.assertIn("--sdnotify=ignore", service)
        self.assertNotIn("Type=notify", service)
        self.assertNotIn("--sdnotify=conmon", service)

    def test_systemd_in_container_uses_exec_not_notify(self):
        """container.systemd = "always" must not change the host service type.

        These workloads run systemd as PID 1 inside the container, which is
        controlled entirely by --systemd=always passed to podman. The host
        service type must still be Type=exec so that systemd does not wait for
        a READY notification that conmon would send from outside the service
        cgroup (which systemd silently drops when linger is active).
        """
        write_config(self.config_dir, "sysd", """\
            [workload]
            name = "sysd"
            enabled = true

            [container]
            image = "systemd-app"
            systemd = "always"
        """)
        self.run_gen()
        service = self.read_service("sysd")
        self.assertIn("Type=exec", service)
        self.assertIn("--sdnotify=ignore", service)
        self.assertIn("--systemd=always", service)
        self.assertNotIn("Type=notify", service)
        self.assertNotIn("--sdnotify=conmon", service)

    def test_explicit_notify_service_type(self):
        """Explicit service_type = "notify" → Type=notify, --sdnotify=conmon."""
        write_config(self.config_dir, "notifywl", """\
            [workload]
            name = "notifywl"
            enabled = true

            [container]
            image = "alpine"

            [resources]
            service_type = "notify"
        """)
        self.run_gen()
        service = self.read_service("notifywl")
        self.assertIn("Type=notify", service)
        self.assertIn("--sdnotify=conmon", service)
        self.assertNotIn("Type=exec", service)
        self.assertNotIn("--sdnotify=ignore", service)

    def test_invalid_service_type_falls_back_to_exec(self):
        """Invalid service_type value → warning emitted, falls back to Type=exec."""
        write_config(self.config_dir, "badtype", """\
            [workload]
            name = "badtype"
            enabled = true

            [container]
            image = "alpine"

            [resources]
            service_type = "turbo"
        """)
        result = self.run_gen()
        service = self.read_service("badtype")
        self.assertIn("Type=exec", service)
        self.assertIn("WARNING", result.stdout + result.stderr)


class TestGeneratorAlwaysExitsZero(unittest.TestCase):
    def test_empty_config_dir(self):
        with tempfile.TemporaryDirectory() as config_dir, \
             tempfile.TemporaryDirectory() as services_dir, \
             tempfile.TemporaryDirectory() as sysusers_dir:
            result = run_generator(config_dir, services_dir, sysusers_dir)
            self.assertEqual(result.returncode, 0)

    def test_missing_config_dir(self):
        with tempfile.TemporaryDirectory() as services_dir, \
             tempfile.TemporaryDirectory() as sysusers_dir:
            result = run_generator("/nonexistent/path", services_dir, sysusers_dir)
            self.assertEqual(result.returncode, 0)

    def test_invalid_toml(self):
        with tempfile.TemporaryDirectory() as config_dir, \
             tempfile.TemporaryDirectory() as services_dir, \
             tempfile.TemporaryDirectory() as sysusers_dir:
            (Path(config_dir) / "bad.toml").write_text("this is not valid toml {{{")
            result = run_generator(config_dir, services_dir, sysusers_dir)
            self.assertEqual(result.returncode, 0)


class TestResolveAutoGpu(unittest.TestCase):
    """Unit tests for resolve_auto_gpu() — vendor + NVIDIA driver detection."""

    @classmethod
    def setUpClass(cls):
        cls.wg = _load_generator_module()

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.drm = Path(self.root) / "sys" / "class" / "drm"
        self.drm.mkdir(parents=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.root)

    def _add_card(self, name, vendor_id, driver=None):
        """Create a fake /sys/class/drm/<name> with a vendor file and
        optionally a 'driver' symlink whose basename is the driver name."""
        device = self.drm / name / "device"
        device.mkdir(parents=True)
        (device / "vendor").write_text(vendor_id + "\n")
        if driver is not None:
            target = Path(self.root) / "_drivers" / driver
            target.mkdir(parents=True, exist_ok=True)
            (device / "driver").symlink_to(target)

    def _resolve(self):
        """Run resolve_auto_gpu() with /sys/class/drm redirected to the fake tree."""
        real_path = self.wg.Path
        drm = self.drm

        def fake_path(arg):
            if str(arg) == "/sys/class/drm":
                return real_path(drm)
            return real_path(arg)

        with mock.patch.object(self.wg, "Path", side_effect=fake_path):
            return self.wg.resolve_auto_gpu()

    def test_amd(self):
        self._add_card("card0", "0x1002")
        self.assertEqual(self._resolve(), "amd")

    def test_intel(self):
        self._add_card("card0", "0x8086")
        self.assertEqual(self._resolve(), "intel")

    def test_nvidia_proprietary(self):
        self._add_card("card0", "0x10de", driver="nvidia")
        self.assertEqual(self._resolve(), "nvidia")

    def test_nvidia_nouveau(self):
        self._add_card("card0", "0x10de", driver="nouveau")
        self.assertEqual(self._resolve(), "nouveau")

    def test_nvidia_no_driver_symlink_falls_back_to_nvidia(self):
        # No driver bound (e.g. modeset/driver not yet attached) → vendor only.
        self._add_card("card0", "0x10de")
        self.assertEqual(self._resolve(), "nvidia")

    def test_no_gpu(self):
        self.assertEqual(self._resolve(), "none")

    def test_unknown_vendor_skipped(self):
        self._add_card("card0", "0xbeef")
        self.assertEqual(self._resolve(), "none")


class TestGeneratorVmWorkload(unittest.TestCase):
    """Snapshot the generated unit files for a VM workload.

    These tests assert structural invariants that were direct fallout from the
    PR review — if any of them regress, real-world VMs would either fail to
    boot, lose their sockets on sidecar restart, or silently degrade.
    """

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def _write_vm_config(self, name="fedora-vm", extra=""):
        write_config(self.config_dir, name, f"""\
            [workload]
            name = "{name}"
            enabled = true

            [vm]
            vcpus = 2
            memory = "2048M"
            cloud_image_url = "https://example.com/cloud.qcow2"
            cloud_image_checksum = "sha256:{'d' * 64}"
            data_disk_size = "20G"
            user = "fedora"
            {extra}
        """)

    def _run(self):
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(
            result.returncode, 0,
            msg=f"generator failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        return result

    def _read(self, filename):
        return (Path(self.services_dir) / filename).read_text()

    def test_main_service_uses_integer_mib(self):
        # parse_memory_mib must normalize "2048M" → 2048 so the memfd
        # backend's size=NM stays valid. A regression here would mean
        # virtiofs VMs fail to start with "invalid size=2048MM".
        self._write_vm_config()
        self._run()
        svc = self._read("workload-fedora-vm.service")
        self.assertIn("-m 2048", svc)
        self.assertNotIn("-m 2048M", svc)

    def test_vm_restart_defaults_to_always(self):
        # QEMU runs with -no-reboot, so a guest reboot is a clean exit;
        # the default must be Restart=always or the VM stays down after its
        # first-boot kernel-upgrade reboot.
        self._write_vm_config()
        self._run()
        svc = self._read("workload-fedora-vm.service")
        self.assertIn("Restart=always", svc)
        self.assertNotIn("Restart=on-failure", svc)

    def test_vm_restart_on_failure_override(self):
        self._write_vm_config(extra='restart = "on-failure"')
        self._run()
        svc = self._read("workload-fedora-vm.service")
        self.assertIn("Restart=on-failure", svc)
        self.assertNotIn("Restart=always", svc)

    def test_vm_restart_on_reboot_falls_back_to_always(self):
        # "on-reboot" is reserved for reason-aware restart that isn't
        # implemented yet; it must degrade to the safe always-on behavior.
        self._write_vm_config(extra='restart = "on-reboot"')
        self._run()
        svc = self._read("workload-fedora-vm.service")
        self.assertIn("Restart=always", svc)

    def test_main_service_owns_runtime_dir_with_preserve(self):
        # The per-VM socket dir must be owned by the *main* VM service (so
        # virtiofsd sidecars don't yank console.sock/qmp.sock when they
        # stop) and preserved across restarts (so systemctl restart doesn't
        # wipe the dir between stop and start).
        self._write_vm_config()
        self._run()
        svc = self._read("workload-fedora-vm.service")
        self.assertIn("RuntimeDirectory=workload-vm/fedora-vm", svc)
        self.assertIn("RuntimeDirectoryPreserve=yes", svc)

    def test_virtiofsd_sidecar_does_not_declare_runtime_dir(self):
        # If the sidecar owned RuntimeDirectory, systemd's refcount would
        # clean up the parent dir on sidecar stop and break the VM.
        self._write_vm_config(extra='volumes = ["/srv/data:/mnt/data"]')
        self._run()
        sidecar = self._read("workload-fedora-vm-virtiofs-mnt-data.service")
        self.assertNotIn("RuntimeDirectory=", sidecar)
        # The shared-dir path must be correctly quoted onto ExecStart.
        self.assertIn("--shared-dir=\"/srv/data\"", sidecar)

    def test_virtiofsd_uses_exec_type_with_socket_poll(self):
        # virtiofsd 1.x only sends sd_notify READY after QEMU connects,
        # which deadlocks with Type=notify + Before=VM.service. We use
        # Type=exec and poll for the socket in ExecStartPost instead.
        self._write_vm_config(extra='volumes = ["/srv/data:/mnt/data"]')
        self._run()
        sidecar = self._read("workload-fedora-vm-virtiofs-mnt-data.service")
        self.assertIn("Type=exec", sidecar)
        self.assertNotIn("Type=notify", sidecar)
        self.assertNotIn("NotifyAccess=", sidecar)
        socket_path = "/run/workload-vm/fedora-vm/virtiofs-mnt-data.sock"
        self.assertIn(f"test -S {socket_path}", sidecar)
        # Must run as root so virtiofsd can faithfully apply guest-requested
        # uid/gid on writes (unprivileged virtiofsd squashes everything to its
        # own uid, breaking multi-user data sharing inside the guest).
        self.assertNotIn("User=", sidecar)
        self.assertIn("--sandbox=chroot", sidecar)

    def test_bridge_service_does_not_swallow_dnsmasq_failures(self):
        # The earlier "|| true" trailing the dnsmasq ExecStart hid genuine
        # failures (missing binary, port in use) and left VMs without DHCP.
        self._write_vm_config()
        self._run()
        bridge = self._read("workload-bridge.service")
        # The dnsmasq ExecStart line itself must not end with "|| true".
        # (Other ExecStop lines may legitimately use || true for cleanup.)
        dnsmasq_lines = [l for l in bridge.splitlines() if "/usr/sbin/dnsmasq" in l]
        self.assertEqual(len(dnsmasq_lines), 1, dnsmasq_lines)
        self.assertNotIn("|| true", dnsmasq_lines[0])
        # The bogus --keep-in-foreground=no flag must not appear.
        self.assertNotIn("--keep-in-foreground=no", bridge)
        # Type=forking only allows one ExecStart= line — the setup steps
        # must be ExecStartPre=, and dnsmasq is the sole ExecStart=.
        # systemd refuses to load the unit otherwise.
        exec_starts = [l for l in bridge.splitlines()
                       if l.startswith("ExecStart=")]
        self.assertEqual(len(exec_starts), 1, exec_starts)
        self.assertIn("/usr/sbin/dnsmasq", exec_starts[0])

    def test_bridge_service_has_no_before_workload_generate(self):
        # workload-generate is a generator that runs before any unit
        # activation; Before= on a finished unit is a no-op and was just
        # noise.
        self._write_vm_config()
        self._run()
        bridge = self._read("workload-bridge.service")
        self.assertNotIn("Before=workload-generate.service", bridge)

    def test_bridge_owns_workload_vm_runtime_dir(self):
        # systemd must create /run/workload-vm/ before dnsmasq writes its
        # pid file into it.
        self._write_vm_config()
        self._run()
        bridge = self._read("workload-bridge.service")
        self.assertIn("RuntimeDirectory=workload-vm", bridge)

    def test_main_service_requires_bridge_and_build(self):
        self._write_vm_config()
        self._run()
        svc = self._read("workload-fedora-vm.service")
        self.assertIn("workload-fedora-vm-build.service", svc)
        self.assertIn("workload-bridge.service", svc)
        self.assertIn("workload-fedora-vm-setup.service", svc)

    def test_execstop_waits_for_graceful_poweroff(self):
        # ExecStop must call workload-vm-shutdown, which *blocks* until the
        # guest powers off. A fire-and-forget `workload-vm-qmp system_powerdown`
        # returns instantly, so systemd SIGTERM's QEMU within milliseconds and
        # every stop becomes an unclean power-off (guest data corruption).
        # TimeoutStopSec must still backstop a guest that ignores ACPI.
        self._write_vm_config()
        self._run()
        svc = self._read("workload-fedora-vm.service")
        exec_stops = [l for l in svc.splitlines() if l.startswith("ExecStop=")]
        self.assertEqual(len(exec_stops), 1, exec_stops)
        self.assertIn("workload-vm-shutdown", exec_stops[0])
        self.assertIn("fedora-vm", exec_stops[0])
        # Regression guard: the old fire-and-forget powerdown must be gone.
        self.assertNotIn("workload-vm-qmp", svc)
        self.assertNotIn("system_powerdown", svc)
        self.assertIn("TimeoutStopSec=90", svc)

    def test_custom_bridge_overrides_qemu_netdev_and_skips_managed_bridge(self):
        # vm.network.bridge = "br0" → QEMU netdev uses br0, AND we don't
        # emit workload-bridge.service or list it as a dependency (the user
        # is responsible for bringing br0 up themselves).
        self._write_vm_config(extra='[vm.network]\nbridge = "br0"')
        self._run()
        svc = self._read("workload-fedora-vm.service")
        self.assertIn("-netdev bridge,id=net0,br=br0", svc)
        self.assertNotIn("br=_workload-br", svc)
        self.assertNotIn("workload-bridge.service", svc)
        # The bridge unit file itself must not be generated for this VM
        self.assertFalse(
            (Path(self.services_dir) / "workload-bridge.service").exists(),
            "workload-bridge.service must not be emitted for custom-bridge VMs",
        )

    def test_default_bridge_still_emits_workload_bridge_service(self):
        # Regression guard: omitting [vm.network] keeps the managed bridge +
        # workload-bridge.service.
        self._write_vm_config()
        self._run()
        svc = self._read("workload-fedora-vm.service")
        self.assertIn("-netdev bridge,id=net0,br=_workload-br", svc)
        self.assertTrue(
            (Path(self.services_dir) / "workload-bridge.service").exists(),
        )

    def test_sysusers_grants_kvm_membership(self):
        self._write_vm_config()
        self._run()
        sysusers = (Path(self.sysusers_dir) / "workload-fedora-vm.conf").read_text()
        self.assertIn("u _wl-fedora-vm", sysusers)
        self.assertIn("m _wl-fedora-vm kvm", sysusers)

    def test_data_disk_attached_when_size_set(self):
        self._write_vm_config()
        self._run()
        svc = self._read("workload-fedora-vm.service")
        self.assertIn("data.qcow2", svc)

    def test_no_data_disk_when_size_omitted(self):
        write_config(self.config_dir, "minvm", f"""\
            [workload]
            name = "minvm"
            enabled = true

            [vm]
            vcpus = 1
            memory = "512M"
            cloud_image_url = "https://example.com/x.qcow2"
            cloud_image_checksum = "sha256:{'a' * 64}"
        """)
        self._run()
        svc = self._read("workload-minvm.service")
        self.assertNotIn("data.qcow2", svc)

    def test_memfd_only_when_virtiofs_in_use(self):
        # Without volumes, no shared-memory backend is needed and adding
        # one would gratuitously double VM memory cost.
        self._write_vm_config()
        self._run()
        no_vfs = self._read("workload-fedora-vm.service")
        self.assertNotIn("memory-backend-memfd", no_vfs)

        # With volumes, memfd is required for virtiofs to work.
        self.tearDown()
        self.setUp()
        self._write_vm_config(extra='volumes = ["/srv/data:/mnt/data"]')
        self._run()
        with_vfs = self._read("workload-fedora-vm.service")
        self.assertIn("memory-backend-memfd", with_vfs)
        self.assertIn("size=2048M", with_vfs)


if __name__ == "__main__":
    unittest.main()
