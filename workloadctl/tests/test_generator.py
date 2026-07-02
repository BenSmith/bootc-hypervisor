#!/usr/bin/env python3
"""Integration tests for the workload generator.

Runs the generator with temp directories and validates the output files.
No root required — all paths are overridden via env vars and argv.
"""

import importlib.machinery
import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
from covhelper import python_cmd

GENERATOR = os.path.join(os.path.dirname(__file__), '..', 'generators', 'workload-generate')
LIB_DIR = os.path.join(os.path.dirname(__file__), '..', 'lib')


def _load_generator_module():
    """Import workload-generate as a module (it has a __main__ guard)."""
    if LIB_DIR not in sys.path:
        sys.path.insert(0, LIB_DIR)
    loader = importlib.machinery.SourceFileLoader("workload_generate", GENERATOR)
    spec = importlib.util.spec_from_loader("workload_generate", loader)
    assert spec is not None
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
        python_cmd(GENERATOR, str(services_dir)),
        capture_output=True, text=True, env=env,
    )


def write_config(config_dir, name, toml_content, enabled=True):
    """Write a TOML config file to the config directory."""
    (Path(config_dir) / name).mkdir(exist_ok=True)
    path = Path(config_dir) / name / "workload.toml"
    body = textwrap.dedent(toml_content)
    path.write_text(body)
    if enabled:
        (Path(config_dir) / name / ".enabled").touch()
    return path


def read_dropin(services_dir):
    """Read the single user@<uid>.service.d/50-workload.conf drop-in.

    The generator allocates the workload UID from the live passwd database
    (get_next_uid scans pwd.getpwall), so the exact slot isn't deterministic
    across hosts — a CI runner with any existing UID in [10000, 52948] shifts
    it off 10000. Glob for the one drop-in rather than assuming the slot.
    """
    matches = sorted(Path(services_dir).glob("user@*.service.d/50-workload.conf"))
    assert len(matches) == 1, f"expected exactly one drop-in, found {matches}"
    return matches[0].read_text()


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

    def test_passthrough_logging_with_named_journal_stream(self):
        """Container logs use --log-driver=passthrough (single journal copy via
        the unit's stream) and the unit names that stream after the container
        so lines read `workload-<name>[pid]: ...`. Members get the combined
        workload-<wl>-<ctr> identifier."""
        write_config(self.config_dir, "web", """\
            [workload]
            name = "web"

            [container]
            image = "docker.io/nginx:latest"
        """)
        write_config(self.config_dir, "stack", """\
            [workload]
            name = "stack"
            mode = "bridge"

            [[containers]]
            name = "db"
            [containers.container]
            image = "postgres:16"
        """)
        result = self.run_gen()
        self.assertEqual(result.returncode, 0, result.stderr)

        web = self.read_service("web")
        self.assertIn("--log-driver=passthrough", web)
        self.assertNotIn("--log-driver=journald", web)
        self.assertIn("SyslogIdentifier=workload-web", web)

        db = (Path(self.services_dir) / "workload-stack-db.service").read_text()
        self.assertIn("--log-driver=passthrough", db)
        self.assertIn("SyslogIdentifier=workload-stack-db", db)

    def test_disabled_workload_skipped(self):
        write_config(self.config_dir, "off", """\
            [workload]
            name = "off"

            [container]
            image = "nginx"
        """, enabled=False)

        self.run_gen()
        self.assertFalse(
            (Path(self.services_dir) / "workload-off.service").exists()
        )

    def test_missing_name_skipped(self):
        write_config(self.config_dir, "broken", """\
            [workload]

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

            [container]
            image = "alpine"
        """)

        self.run_gen()
        wants = Path(self.services_dir) / "multi-user.target.wants" / "workload-svc.service"
        self.assertTrue(wants.is_symlink())
        self.assertEqual(os.readlink(wants), "../workload-svc.service")

    def test_requires_emits_wants(self):
        """[workload].requires = ["caddy"] → Wants=workload-caddy.service."""
        write_config(self.config_dir, "caddy", """\
            [workload]
            name = "caddy"
            [container]
            image = "docker.io/caddy:latest"
        """)
        write_config(self.config_dir, "app", """\
            [workload]
            name = "app"
            requires = ["caddy"]
            [container]
            image = "alpine"
        """)
        self.run_gen()
        service = self.read_service("app")
        self.assertIn("Wants=workload-caddy.service", service)

    def test_after_emits_after(self):
        """[workload].after = ["registry"] → After=workload-registry.service."""
        write_config(self.config_dir, "registry", """\
            [workload]
            name = "registry"
            [container]
            image = "docker.io/registry:2"
        """)
        write_config(self.config_dir, "app", """\
            [workload]
            name = "app"
            after = ["registry"]
            [container]
            image = "alpine"
        """)
        self.run_gen()
        service = self.read_service("app")
        self.assertIn("After=workload-registry.service", service)

    def test_requires_and_after_combined(self):
        """Both requires and after emit their respective systemd directives."""
        for name in ("db", "cache"):
            write_config(self.config_dir, name, f"""\
                [workload]
                name = "{name}"
                [container]
                image = "alpine"
            """)
        write_config(self.config_dir, "web", """\
            [workload]
            name = "web"
            requires = ["db"]
            after = ["cache"]
            [container]
            image = "alpine"
        """)
        self.run_gen()
        service = self.read_service("web")
        self.assertIn("Wants=workload-db.service", service)
        self.assertIn("After=workload-cache.service", service)

    def test_log_rate_limit_defaults_emitted(self):
        """LogRateLimitIntervalSec and LogRateLimitBurst appear in generated units."""
        write_config(self.config_dir, "svc2", """\
            [workload]
            name = "svc2"
            [container]
            image = "alpine"
        """)
        self.run_gen()
        service = self.read_service("svc2")
        self.assertIn("LogRateLimitIntervalSec=30", service)
        self.assertIn("LogRateLimitBurst=250", service)

    def test_log_rate_limit_overridable_via_custom_directives(self):
        """Custom LogRateLimitIntervalSec suppresses the generator default."""
        write_config(self.config_dir, "svc3", """\
            [workload]
            name = "svc3"
            [container]
            image = "alpine"
            [resources]
            custom_directives = {LogRateLimitIntervalSec = "0"}
        """)
        self.run_gen()
        service = self.read_service("svc3")
        self.assertNotIn("LogRateLimitIntervalSec=30", service)
        self.assertIn("LogRateLimitIntervalSec=0", service)


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

    def test_stale_pause_migrate_in_head_units_only(self):
        """The fresh-pause cleanup (`podman system migrate` + rm of
        pause.pid/ns_handles) must run in each workload's first podman-touching
        unit (single service, pod service, net service) and never in pod/bridge
        member services — there it would kill the libpod pause out from under
        the live pod infra / sibling containers. Regresses the pasta
        restart-loop bug: a pause surviving the previous activation pins a mount
        ns whose PrivateTmp /tmp is deleted, the next `podman run` joins it, and
        pasta's pivot_root tmpfs mount gets ENOENT. The rm forces the rootless
        join shortcut to fall through so a fresh pause is built in the live ns.
        """
        migrate = "ExecStartPre=-/usr/bin/podman system migrate"
        # The rm is uid-specific; assert the stable prefix/suffix.
        rm_prefix = "ExecStartPre=-/usr/bin/rm -f /run/user/"
        rm_files = "/libpod/tmp/pause.pid"

        def assert_fresh_pause(unit_text):
            self.assertIn(migrate, unit_text)
            self.assertIn(rm_prefix, unit_text)
            self.assertIn(rm_files, unit_text)
            self.assertIn("/libpod/tmp/ns_handles", unit_text)

        def assert_no_fresh_pause(unit_text):
            self.assertNotIn(migrate, unit_text)
            self.assertNotIn(rm_prefix, unit_text)
        write_config(self.config_dir, "solo", """\
            [workload]
            name = "solo"

            [container]
            image = "docker.io/nginx:latest"
        """)
        write_config(self.config_dir, "grp", """\
            [workload]
            name = "grp"
            mode = "pod"

            [[containers]]
            name = "db"
            [containers.container]
            image = "postgres:16"
        """)
        write_config(self.config_dir, "brg", """\
            [workload]
            name = "brg"
            mode = "bridge"

            [[containers]]
            name = "web"
            [containers.container]
            image = "myapp:latest"
        """)
        r = self.run_gen()
        self.assertEqual(r.returncode, 0, r.stderr)

        solo = (Path(self.services_dir) / "workload-solo.service").read_text()
        assert_fresh_pause(solo)

        pod = (Path(self.services_dir) / "workload-grp-pod.service").read_text()
        assert_fresh_pause(pod)
        pod_member = (Path(self.services_dir) / "workload-grp-db.service").read_text()
        assert_no_fresh_pause(pod_member)

        net = (Path(self.services_dir) / "workload-brg-net.service").read_text()
        assert_fresh_pause(net)
        net_member = (Path(self.services_dir) / "workload-brg-web.service").read_text()
        assert_no_fresh_pause(net_member)

    def test_per_container_environment_sibling_form(self):
        """[containers.environment] (sibling of [containers.container]) must
        reach the per-container service as --env flags. This is the form the
        shipped example TOMLs use."""
        write_config(self.config_dir, "app", """\
            [workload]
            name = "app"
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
        per-container service using podman's native user-manager timer (1b)."""
        write_config(self.config_dir, "app", """\
            [workload]
            name = "app"
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
        # Under option 1b podman's native user-manager healthcheck timer works:
        # on_failure is passed through directly, no DISABLE_HC_SYSTEMD shim,
        # no separate system-manager timer unit.
        self.assertIn("--health-on-failure=kill", web)
        self.assertNotIn("--health-on-failure=none", web)
        self.assertNotIn("DISABLE_HC_SYSTEMD", web)
        self.assertNotIn("Wants=workload-app-web-health.timer", web)
        self.assertFalse(
            (Path(self.services_dir) / "workload-app-web-health.timer").exists()
        )

    def test_native_healthcheck_single_mode(self):
        """Under option 1b all modes use podman's native user-manager timer:
        on_failure passes through, no DISABLE_HC_SYSTEMD shim, no separate
        system-manager timer unit."""
        write_config(self.config_dir, "hc", """\
            [workload]
            name = "hc"
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
        # Health flags pass through directly
        self.assertIn('--health-cmd "test -f /tmp/ok"', svc)
        self.assertIn("--health-interval=30s", svc)
        self.assertIn("--health-start-period=15s", svc)
        self.assertIn("--health-on-failure=restart", svc)
        # No split shim
        self.assertNotIn("DISABLE_HC_SYSTEMD", svc)
        self.assertNotIn("Wants=workload-hc-health.timer", svc)
        # No separate system-manager timer/service files
        self.assertFalse((Path(self.services_dir) / "workload-hc-health.service").exists())
        self.assertFalse((Path(self.services_dir) / "workload-hc-health.timer").exists())

    def test_pod_mode_keeps_podman_healthcheck(self):
        """Pod-mode containers run in the user manager where podman's own
        healthcheck timer works, so the generator must NOT suppress it or emit
        its own timer."""
        write_config(self.config_dir, "pm", """\
            [workload]
            name = "pm"
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

    def test_secret_files_do_not_clobber_workload_mode(self):
        # Regression (B1): the secrets.files loop assigned its per-file mount
        # mode ("ro"/"rw") to `mode`, shadowing generate_system_service()'s
        # workload-mode parameter and corrupting every later mode check.
        write_config(self.config_dir, "clobber", """\
            [workload]
            name = "clobber"

            [container]
            image = "myapp"

            [container.environment]
            API_KEY = "${SECRET:api-key}"

            [secrets]
            files = [
                { credential = "tls-cert", path = "/etc/ssl/cert.pem", mode = "ro" }
            ]
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-clobber.service").read_text()

        # Single mode keeps the one-arg write-env form. The clobbered two-arg
        # form wrote workload-clobber-clobber.secrets while --env-file pointed
        # at workload-clobber.secrets → podman failed to start (missing file).
        self.assertIn(
            "ExecStartPre=+/usr/libexec/workloadctl/workload-write-env clobber\n",
            service,
        )
        self.assertIn('--env-file "/run/workload-env/workload-clobber.secrets"', service)
        # Single-mode unit keeps its [Install] block.
        self.assertIn("WantedBy=multi-user.target", service)

    def test_secret_files_do_not_clobber_pod_member_mode(self):
        # Regression (B1), pod flavor: a member with secrets.files used to be
        # treated as non-pod after the clobber — wrongly getting Delegate=yes
        # and the split-healthcheck wiring (which pins on_failure to none).
        write_config(self.config_dir, "podsec", """\
            [workload]
            name = "podsec"
            mode = "pod"

            [[containers]]
            name = "app"
            [containers.container]
            image = "myapp"
            [containers.container.health]
            cmd = "curl -sf http://localhost/healthz"
            on_failure = "kill"
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
        app = (Path(self.services_dir) / "workload-podsec-app.service").read_text()

        self.assertNotIn("Delegate=yes", app)
        self.assertNotIn("DISABLE_HC_SYSTEMD", app)
        self.assertNotIn("-health.timer", app)
        # Pod members keep podman's own healthcheck action.
        self.assertIn("--health-on-failure=kill", app)


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
        """Under option 1b, workload-level resource limits land in the
        user@<uid>.service.d drop-in (cgroup directives) and as podman flags
        on the container (per-container OOM scoping); not as service directives
        on the workload unit itself."""
        write_config(self.config_dir, "limited", """\
            [workload]
            name = "limited"

            [container]
            image = "myapp"

            [resources]
            cpu_quota = "200%"
            memory_max = "4G"
            tasks_max = 100
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-limited.service").read_text()

        # Cgroup directives are NOT on the workload unit (payload is in user@<uid>.service)
        self.assertNotIn("CPUQuota=200%", service)
        self.assertNotIn("MemoryMax=4G", service)
        self.assertNotIn("TasksMax=100", service)

        # Per-container resource flags bind in the payload scope
        self.assertIn("--cpus=2.0", service)
        self.assertIn("--memory=4G", service)
        self.assertIn("--pids-limit=100", service)

        # Workload-level cgroup limits are in the user@<uid> drop-in
        dropin = read_dropin(self.services_dir)
        self.assertIn("Slice=workloads.slice", dropin)
        self.assertIn("CPUQuota=200%", dropin)
        self.assertIn("MemoryMax=4G", dropin)
        self.assertIn("TasksMax=100", dropin)

    def test_default_stop_grace_is_ten_seconds(self):
        # No timeout_stop_sec → podman's -t grace stays the historical 10s and
        # systemd's TimeoutStopSec defaults to 30 (comfortable margin above it).
        write_config(self.config_dir, "plain", """\
            [workload]
            name = "plain"

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

            [container]
            image = "myapp"

            [resources]
            timeout_stop_sec = "2min"
        """)
        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-spanstop.service").read_text()
        self.assertIn("ExecStop=/usr/bin/podman stop -t 10 ", service)
        self.assertIn("TimeoutStopSec=2min", service)


class TestGeneratorUserDropin(unittest.TestCase):
    """Tests for the user@<uid>.service.d/50-workload.conf drop-in (ADR 001 option 1b)."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def _dropin(self):
        return read_dropin(self.services_dir)

    def test_dropin_emitted_for_single_mode(self):
        """Every container workload gets a user@<uid> drop-in with Slice=workloads.slice."""
        write_config(self.config_dir, "web", """\
            [workload]
            name = "web"
            [container]
            image = "nginx:latest"
        """)
        r = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(r.returncode, 0, r.stderr)
        dropin = self._dropin()
        self.assertIn("Slice=workloads.slice", dropin)
        self.assertIn("Workload web:", dropin)

    def test_dropin_emitted_for_pod_mode(self):
        """Pod-mode workloads also get a drop-in — placement is uniform across modes."""
        write_config(self.config_dir, "pm", """\
            [workload]
            name = "pm"
            mode = "pod"
            [[containers]]
            name = "a"
            [containers.container]
            image = "nginx:latest"
            [[containers]]
            name = "b"
            [containers.container]
            image = "redis:latest"
        """)
        r = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(r.returncode, 0, r.stderr)
        dropin = self._dropin()
        self.assertIn("Slice=workloads.slice", dropin)

    def test_dropin_carries_workload_level_resources(self):
        """Workload-level cgroup directives go into the drop-in, not the unit."""
        write_config(self.config_dir, "capped", """\
            [workload]
            name = "capped"
            [container]
            image = "myapp"
            [resources]
            cpu_quota = "50%"
            cpu_weight = 200
            memory_max = "1G"
            memory_high = "768M"
            memory_swap_max = "500M"
            tasks_max = 512
        """)
        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        dropin = self._dropin()
        self.assertIn("Slice=workloads.slice", dropin)
        self.assertIn("CPUQuota=50%", dropin)
        self.assertIn("CPUWeight=200", dropin)
        self.assertIn("MemoryMax=1G", dropin)
        self.assertIn("MemoryHigh=768M", dropin)
        self.assertIn("MemorySwapMax=500M", dropin)
        self.assertIn("TasksMax=512", dropin)
        # Cgroup directives must NOT appear as [Service] directives on the unit
        service = (Path(self.services_dir) / "workload-capped.service").read_text()
        self.assertNotIn("CPUQuota=", service)
        self.assertNotIn("MemoryMax=", service)
        self.assertNotIn("MemoryHigh=", service)

    def test_dropin_no_unconditional_cpu_io_weight_defaults(self):
        """A workload without explicit cpu_weight/io_weight gets no default
        in the drop-in (workloads.slice already carries CPUWeight=80/IOWeight=80)."""
        write_config(self.config_dir, "plain", """\
            [workload]
            name = "plain"
            [container]
            image = "myapp"
        """)
        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        dropin = self._dropin()
        self.assertIn("Slice=workloads.slice", dropin)
        self.assertNotIn("CPUWeight=", dropin)
        self.assertNotIn("IOWeight=", dropin)

    def test_dropin_no_cgroup_split_or_delegate(self):
        """The workload unit must not contain Delegate=yes or --cgroups=split."""
        write_config(self.config_dir, "clean", """\
            [workload]
            name = "clean"
            [container]
            image = "myapp"
        """)
        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-clean.service").read_text()
        self.assertNotIn("Delegate=yes", service)
        self.assertNotIn("--cgroups=split", service)

    def test_execstoppost_reaps_payload(self):
        """Single and bridge containers get ExecStopPost to clean up the payload
        (which is no longer in the unit's cgroup under option 1b)."""
        write_config(self.config_dir, "rm", """\
            [workload]
            name = "rm"
            [container]
            image = "myapp"
        """)
        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-rm.service").read_text()
        self.assertIn('ExecStopPost=-/usr/bin/podman rm -f -t0 "workload-rm"', service)


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

            [container]
            image = "myapp"

            [security]
            userns = "keep-id:foo=1"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-badparam.service").read_text()
        self.assertIn("--userns=keep-id", service)

    def test_keep_id_param_without_equals_defaults_to_keep_id(self):
        # "keep-id:noequals" — a param with no '=' fails validation → plain keep-id
        write_config(self.config_dir, "noeq", """\
            [workload]
            name = "noeq"

            [container]
            image = "myapp"

            [security]
            userns = "keep-id:noequals"
        """)
        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-noeq.service").read_text()
        self.assertIn("--userns=keep-id", service)
        self.assertNotIn("noequals", service)


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

    wg: Any

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

    def test_virtiofsd_translates_guest_user_to_host_workload_uid(self):
        # The guest's primary user is uid/gid 1000 (cloud-init default), while
        # the host share is owned by the workload user (>=10000). virtiofsd must
        # bidirectionally translate 1000 <-> the workload uid so the guest user
        # can write the share. The exact slot isn't deterministic across hosts
        # (get_next_uid scans the live passwd DB — a CI runner with any UID in
        # [10000, 52948] shifts it off 10000), so derive the allocated uid from
        # the drop-in rather than hardcoding it.
        self._write_vm_config(extra='volumes = ["/srv/data:/mnt/data"]')
        self._run()
        sysusers = (Path(self.sysusers_dir) / "workload-fedora-vm.conf").read_text()
        m = re.search(r"^u _wl-fedora-vm (\d+)", sysusers, re.M)
        assert m is not None
        uid = int(m.group(1))
        self.assertGreaterEqual(uid, 10000)
        sidecar = self._read("workload-fedora-vm-virtiofs-mnt-data.service")
        self.assertIn(f"--translate-uid=map:1000:{uid}:1", sidecar)
        self.assertIn(f"--translate-gid=map:1000:{uid}:1", sidecar)

    def test_bridge_service_does_not_swallow_dnsmasq_failures(self):
        # The earlier "|| true" trailing the dnsmasq ExecStart hid genuine
        # failures (missing binary, port in use) and left VMs without DHCP.
        self._write_vm_config()
        self._run()
        bridge = self._read("workload-bridge.service")
        # The dnsmasq ExecStart line itself must not end with "|| true".
        # (Other ExecStop lines may legitimately use || true for cleanup.)
        dnsmasq_lines = [line for line in bridge.splitlines() if "/usr/sbin/dnsmasq" in line]
        self.assertEqual(len(dnsmasq_lines), 1, dnsmasq_lines)
        self.assertNotIn("|| true", dnsmasq_lines[0])
        # The bogus --keep-in-foreground=no flag must not appear.
        self.assertNotIn("--keep-in-foreground=no", bridge)
        # Type=forking only allows one ExecStart= line — the setup steps
        # must be ExecStartPre=, and dnsmasq is the sole ExecStart=.
        # systemd refuses to load the unit otherwise.
        exec_starts = [line for line in bridge.splitlines()
                       if line.startswith("ExecStart=")]
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
        exec_stops = [line for line in svc.splitlines() if line.startswith("ExecStop=")]
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
        # data.qcow2 (precious) lives in the backup-captured data/ subtree,
        # while system.qcow2 (reconstructible) stays in state/.
        self.assertIn("/fedora-vm/data/data.qcow2", svc)
        self.assertIn("/fedora-vm/state/system.qcow2", svc)

    def test_no_data_disk_when_size_omitted(self):
        write_config(self.config_dir, "minvm", f"""\
            [workload]
            name = "minvm"

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


class TestGeneratorContainerFlags(unittest.TestCase):
    """Cover the many optional container flags emitted into the podman run line."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def _gen(self, extra, name="app"):
        write_config(self.config_dir, name, f"""\
            [workload]
            name = "{name}"

            [container]
            image = "myapp"
            {extra}
        """)
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        svc = (Path(self.services_dir) / f"workload-{name}.service").read_text()
        return svc, result

    def test_container_user_override(self):
        svc, _ = self._gen('user = "1000:1000"')
        self.assertIn("--user=1000:1000", svc)

    def test_capabilities_add(self):
        svc, _ = self._gen("""
            [security]
            capabilities = ["NET_ADMIN", "SYS_TIME"]
        """)
        self.assertIn("--cap-add=NET_ADMIN", svc)
        self.assertIn("--cap-add=SYS_TIME", svc)

    def test_security_opt_passthrough(self):
        svc, _ = self._gen("""
            [security]
            security_opt = ["no-new-privileges"]
        """)
        self.assertIn("--security-opt=no-new-privileges", svc)

    def test_custom_seccomp_suppresses_baseline(self):
        svc, _ = self._gen("""
            [security]
            security_opt = ["seccomp=/custom.json"]
        """)
        self.assertIn("--security-opt=seccomp=/custom.json", svc)
        # baseline is suppressed when the workload provides its own seccomp
        self.assertNotIn(f"seccomp=", svc.replace("seccomp=/custom.json", ""))

    def test_privileged_emits_flag_and_warns(self):
        svc, result = self._gen("""
            [security]
            privileged = true
        """)
        self.assertIn("--privileged", svc)
        self.assertIn("privileged=true", result.stderr)
        # privileged suppresses the seccomp baseline
        self.assertNotIn("--security-opt=seccomp=", svc)

    def test_extra_groups_adds_keep_groups(self):
        import grp
        # pick a group that definitely resolves on this host so the +GID map line lands
        group = grp.getgrall()[0].gr_name
        svc, _ = self._gen(f"""
            [security]
            extra_groups = ["{group}"]
        """)
        self.assertIn("--group-add=keep-groups", svc)

    def test_shm_size(self):
        svc, _ = self._gen("""
            [resources]
            shm_size = "256m"
        """)
        self.assertIn("--shm-size=256m", svc)

    def test_cpu_quota_bad_value_warns_and_skips(self):
        svc, result = self._gen("""
            [resources]
            cpu_quota = "notanumber"
        """)
        self.assertIn("cannot convert cpu_quota", result.stderr)
        self.assertNotIn("--cpus=", svc)

    def test_io_bandwidth_flags(self):
        svc, _ = self._gen("""
            [resources]
            io_read_bandwidth_max = ["/dev/sda 10mb"]
            io_write_bandwidth_max = ["/dev/sda 5mb"]
        """)
        self.assertIn("--device-read-bps=/dev/sda:10mb", svc)
        self.assertIn("--device-write-bps=/dev/sda:5mb", svc)

    def test_memory_high_per_container_warns(self):
        svc, result = self._gen("""
            [resources]
            memory_high = "1G"
        """)
        self.assertIn("per-container memory_high is not settable", result.stderr)

    def test_cpu_weight_flag(self):
        svc, _ = self._gen("""
            [resources]
            cpu_weight = 500
        """)
        self.assertIn("--cpu-shares=500", svc)

    def test_input_devices_shortcut(self):
        svc, _ = self._gen("""
            [devices]
            input = true
        """)
        self.assertIn("--device /dev/input", svc)
        self.assertIn("--device /dev/uinput", svc)

    def test_audio_devices_shortcut(self):
        svc, _ = self._gen("""
            [devices]
            audio = true
        """)
        self.assertIn("--device /dev/snd", svc)
        self.assertIn("/pulse:${XDG_RUNTIME_DIR}/pulse:ro", svc)
        self.assertIn("/pipewire-0:${XDG_RUNTIME_DIR}/pipewire-0:ro", svc)

    def test_virtualization_devices_shortcut(self):
        svc, _ = self._gen("""
            [devices]
            virtualization = true
        """)
        self.assertIn("--device /dev/kvm", svc)
        self.assertIn("--device /dev/vhost-net", svc)
        self.assertIn("--device /dev/vhost-vsock", svc)

    def test_gpu_nvidia_all(self):
        svc, _ = self._gen("""
            [devices]
            gpu = "nvidia"
        """)
        self.assertIn("--device=nvidia.com/gpu=all", svc)
        self.assertIn("--device /dev/dri", svc)

    def test_gpu_nvidia_specific_card(self):
        svc, _ = self._gen("""
            [devices]
            gpu = "nvidia:1"
        """)
        self.assertIn("--device=nvidia.com/gpu=1", svc)
        # single-card CDI injects its own DRM nodes; umbrella /dev/dri omitted
        self.assertNotIn("--device /dev/dri", svc)

    def test_gpu_intel_uses_render_node(self):
        svc, _ = self._gen("""
            [devices]
            gpu = "intel"
        """)
        self.assertIn("--device /dev/dri", svc)

    def test_health_check_directives(self):
        svc, _ = self._gen("""
            [container.health]
            cmd = "curl -f localhost"
            interval = "30s"
            timeout = "5s"
            retries = 3
            start_period = "10s"
            on_failure = "kill"
        """)
        self.assertIn("--health-cmd", svc)
        self.assertIn("--health-interval=30s", svc)
        self.assertIn("--health-timeout=5s", svc)
        self.assertIn("--health-retries=3", svc)
        self.assertIn("--health-start-period=10s", svc)
        self.assertIn("--health-on-failure=kill", svc)

    def test_command_as_list(self):
        svc, _ = self._gen("""
            command = ["sh", "-c", "echo hi"]
        """)
        self.assertIn('"sh"', svc)
        self.assertIn('"-c"', svc)
        self.assertIn('"echo hi"', svc)

    def test_command_as_string(self):
        svc, _ = self._gen("""
            command = "run-me"
        """)
        self.assertIn('"run-me"', svc)

    def test_timeout_start_sec_service_directive(self):
        svc, _ = self._gen("""
            [resources]
            timeout_start_sec = 120
        """)
        self.assertIn("TimeoutStartSec=120", svc)
        self.assertNotIn("TimeoutStartSec=300", svc)

    def test_volume_escaping_workload_dir_warns(self):
        svc, result = self._gen("""
            [storage]
            volumes = ["/etc/hosts:/mnt/hosts:ro"]
        """)
        self.assertIn("outside workload dir", result.stderr)
        self.assertIn("/mnt/hosts", svc)

    def test_pet_lifecycle(self):
        write_config(self.config_dir, "pet", """\
            [workload]
            name = "pet"
            lifecycle = "pet"

            [container]
            image = "myapp"
        """)
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        svc = (Path(self.services_dir) / "workload-pet.service").read_text()
        self.assertIn("/usr/bin/podman create", svc)
        self.assertIn("Pet lifecycle: create-once", svc)
        self.assertIn("ExecStart=/usr/bin/podman start -a", svc)
        # pet must not carry --rm/--replace and must not force-rm on stop
        self.assertNotIn("--rm", svc)
        self.assertNotIn("ExecStopPost=-/usr/bin/podman rm", svc)

    def test_invalid_env_key_skipped_with_warning(self):
        svc, result = self._gen("""
            [container.environment]
            "BAD-KEY" = "x"
            GOOD = "y"
        """)
        self.assertIn("skipping env var with invalid key", result.stderr)
        self.assertIn("--env GOOD=", svc)
        self.assertNotIn("BAD-KEY", svc)

    def test_invalid_container_systemd_skips_single_service(self):
        write_config(self.config_dir, "badsd", """\
            [workload]
            name = "badsd"

            [container]
            image = "myapp"
            systemd = "bogus"
        """)
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Invalid container.systemd='bogus'", result.stderr)
        self.assertIn("Skipping badsd due to config errors", result.stderr)
        self.assertFalse((Path(self.services_dir) / "workload-badsd.service").exists())

    def test_custom_directive_shadowing_generator_owned_warns(self):
        svc, result = self._gen("""
            [resources.custom_directives]
            Restart = "no"
        """)
        self.assertIn("managed", result.stderr)
        self.assertIn("Restart=no", svc)

    def test_named_volume_without_colon(self):
        svc, _ = self._gen("""
            [storage]
            volumes = ["mydata"]
        """)
        self.assertIn('--volume "mydata"', svc)

    def test_secrets_file_missing_credential_skipped(self):
        svc, result = self._gen("""
            [[secrets.files]]
            path = "/run/secret"
        """)
        self.assertIn("missing 'credential' or 'path'", result.stderr)

    def test_secrets_file_invalid_mode_defaults_ro(self):
        svc, result = self._gen("""
            [[secrets.files]]
            credential = "mycred"
            path = "/run/secret"
            mode = "bogus"
        """)
        self.assertIn("Defaulting to 'ro'", result.stderr)
        self.assertIn(":ro", svc)

    def test_pet_lifecycle_multi_mode_falls_back_to_cattle(self):
        write_config(self.config_dir, "petpod", """\
            [workload]
            name = "petpod"
            mode = "pod"
            lifecycle = "pet"

            [[containers]]
            name = "a"
            [containers.container]
            image = "myapp"
        """)
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("lifecycle=pet is only supported in single mode", result.stderr)


class TestGeneratorAutoMaps(unittest.TestCase):
    """keep-id auto UID/GID mapping (the +N:@N:1 branch that omits --userns)."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def _gen(self, extra):
        write_config(self.config_dir, "maps", f"""\
            [workload]
            name = "maps"

            [container]
            image = "myapp"

            [security]
            {extra}
        """)
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        return (Path(self.services_dir) / "workload-maps.service").read_text()

    def test_extra_uidmaps_trigger_auto_maps(self):
        svc = self._gen('extra_uidmaps = ["+1000:@{UID}:1"]')
        # auto-maps branch omits --userns entirely
        self.assertNotIn("--userns=", svc)
        # workload user is auto-mapped (+UID:@UID:1)
        self.assertRegex(svc, r"--uidmap \+\d+:@\d+:1")
        # explicit map with {UID} placeholder substituted to the numeric uid
        self.assertRegex(svc, r"--uidmap \+1000:@\d+:1")

    def test_extra_gidmaps_placeholder_substitution(self):
        svc = self._gen('extra_gidmaps = ["+2000:@{GID}:1"]')
        self.assertNotIn("--userns=", svc)
        self.assertRegex(svc, r"--gidmap \+2000:@\d+:1")

    def test_keep_id_suffix_honored_in_auto_maps(self):
        # keep-id:uid=/gid= remaps the workload user to a fixed in-container id
        svc = self._gen("""userns = "keep-id:uid=1000,gid=1000"
            extra_uidmaps = ["+5:@{UID}:1"]""")
        self.assertNotIn("--userns=", svc)
        self.assertRegex(svc, r"--uidmap \+1000:@\d+:1")
        self.assertRegex(svc, r"--gidmap \+1000:@\d+:1")

    def test_nonexistent_extra_group_skipped_in_maps(self):
        # get_group_gid returns None for an unknown group; the +GID map is skipped
        # but the workload's own auto-map still lands and --userns is omitted.
        svc = self._gen('extra_groups = ["definitely_no_such_group_zzz"]')
        self.assertNotIn("--userns=", svc)
        self.assertIn("--group-add=keep-groups", svc)

    def test_extra_groups_maps_group_gid(self):
        import grp
        group = grp.getgrall()[0].gr_name
        gid = grp.getgrnam(group).gr_gid
        svc = self._gen(f'extra_groups = ["{group}"]')
        self.assertNotIn("--userns=", svc)
        self.assertIn("--group-add=keep-groups", svc)
        # gid 0 is already the mapped set seed; only assert the mapping when != workload gid
        self.assertRegex(svc, r"--gidmap \+\d+:@\d+:1")


class TestGeneratorMainEdgeCases(unittest.TestCase):
    """main()-level validation and cross-reference branches."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def test_name_dir_mismatch_refused(self):
        # bundle dir "realdir" but [workload].name "other" — split identity, refuse
        d = Path(self.config_dir) / "realdir"
        d.mkdir()
        (d / "workload.toml").write_text(textwrap.dedent("""\
            [workload]
            name = "other"

            [container]
            image = "myapp"
        """))
        (d / ".enabled").touch()
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0)
        self.assertIn("does not match bundle directory", result.stderr)
        self.assertFalse((Path(self.services_dir) / "workload-other.service").exists())

    def test_unknown_dependency_warns(self):
        write_config(self.config_dir, "dependent", """\
            [workload]
            name = "dependent"
            requires = ["ghost"]

            [container]
            image = "myapp"
        """)
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0)
        self.assertIn("references unknown workload 'ghost'", result.stderr)
        # the workload itself is still generated despite the dangling ref
        self.assertTrue((Path(self.services_dir) / "workload-dependent.service").exists())

    def test_pod_member_userns_ignored_with_warning(self):
        write_config(self.config_dir, "pns", """\
            [workload]
            name = "pns"
            mode = "pod"

            [[containers]]
            name = "a"
            [containers.container]
            image = "myapp"
            [containers.security]
            userns = "keep-id"
        """)
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("ignored in pod mode", result.stderr)

    def test_multi_container_invalid_systemd_skips_that_container(self):
        write_config(self.config_dir, "badmulti", """\
            [workload]
            name = "badmulti"
            mode = "pod"

            [[containers]]
            name = "good"
            [containers.container]
            image = "myapp"

            [[containers]]
            name = "bad"
            [containers.container]
            image = "myapp"
            systemd = "bogus"
        """)
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Skipping container bad due to config errors", result.stderr)
        self.assertTrue((Path(self.services_dir) / "workload-badmulti-good.service").exists())
        self.assertFalse((Path(self.services_dir) / "workload-badmulti-bad.service").exists())

    def test_bridge_workload_level_ports_ignored_with_warning(self):
        write_config(self.config_dir, "brw", """\
            [workload]
            name = "brw"
            mode = "bridge"

            [network]
            ports = ["8080:80"]

            [[containers]]
            name = "a"
            [containers.container]
            image = "myapp"
        """)
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("workload-level [network].ports is ignored in bridge mode", result.stderr)

    def test_rerun_replaces_existing_wants_symlink(self):
        # Second run must unlink the stale wants symlink before recreating it,
        # rather than crashing on an existing path.
        write_config(self.config_dir, "twice", """\
            [workload]
            name = "twice"

            [container]
            image = "myapp"
        """)
        r1 = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(r1.returncode, 0, msg=r1.stderr)
        link = Path(self.services_dir) / "multi-user.target.wants" / "workload-twice.service"
        self.assertTrue(link.is_symlink())
        r2 = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(r2.returncode, 0, msg=r2.stderr)
        self.assertTrue(link.is_symlink())

    def test_enabled_workload_with_invalid_toml_survives_boot(self):
        # Malformed TOML in an enabled bundle must be caught (both in the
        # dependency pre-scan and the main loop) and never abort generation.
        d = Path(self.config_dir) / "broken"
        d.mkdir()
        (d / "workload.toml").write_text('this is = = not valid toml [[[')
        (d / ".enabled").touch()
        # a healthy sibling still generates
        write_config(self.config_dir, "healthy", """\
            [workload]
            name = "healthy"

            [container]
            image = "myapp"
        """)
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0)
        self.assertTrue((Path(self.services_dir) / "workload-healthy.service").exists())

    def test_disabled_workload_not_in_dep_scan(self):
        write_config(self.config_dir, "consumer", """\
            [workload]
            name = "consumer"
            requires = ["producer"]

            [container]
            image = "myapp"
        """)
        # producer exists but is disabled → still counts as unknown for the ref check
        write_config(self.config_dir, "producer", """\
            [workload]
            name = "producer"

            [container]
            image = "myapp"
        """, enabled=False)
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0)
        self.assertIn("references unknown workload 'producer'", result.stderr)


class TestGeneratorVmResources(unittest.TestCase):
    """VM [resources] cgroup directives on the QEMU service unit."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def test_vm_resource_directives_emitted(self):
        write_config(self.config_dir, "resvm", """\
            [workload]
            name = "resvm"

            [vm]
            vcpus = 2
            memory = "2048M"
            cloud_image_url = "https://example.com/cloud.qcow2"
            cloud_image_checksum = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            user = "fedora"

            [resources]
            memory_max = "4G"
            cpu_quota = "200%"
            cpu_weight = 300
        """)
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        svc = (Path(self.services_dir) / "workload-resvm.service").read_text()
        self.assertIn("MemoryMax=4G", svc)
        self.assertIn("CPUQuota=200%", svc)
        self.assertIn("CPUWeight=300", svc)

    def test_vm_rerun_replaces_bridge_and_main_symlinks(self):
        write_config(self.config_dir, "revm", """\
            [workload]
            name = "revm"

            [vm]
            vcpus = 2
            memory = "2048M"
            cloud_image_url = "https://example.com/cloud.qcow2"
            cloud_image_checksum = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            user = "fedora"
        """)
        r1 = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(r1.returncode, 0, msg=r1.stderr)
        r2 = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(r2.returncode, 0, msg=r2.stderr)
        wants = Path(self.services_dir) / "multi-user.target.wants"
        self.assertTrue((wants / "workload-revm.service").is_symlink())
        self.assertTrue((wants / "workload-bridge.service").is_symlink())

    def test_vm_custom_subnet_derives_bridge_cidr(self):
        write_config(self.config_dir, "subnetvm", """\
            [workload]
            name = "subnetvm"

            [vm]
            vcpus = 2
            memory = "2048M"
            cloud_image_url = "https://example.com/cloud.qcow2"
            cloud_image_checksum = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            user = "fedora"

            [vm.network]
            subnet = "10.99.7.0/24"
        """)
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        bridge = (Path(self.services_dir) / "workload-bridge.service").read_text()
        # first host of the subnet becomes the bridge IP, /prefixlen preserved
        self.assertIn("10.99.7.1/24", bridge)

    def test_vm_sysusers_extra_groups(self):
        write_config(self.config_dir, "grpvm", """\
            [workload]
            name = "grpvm"

            [vm]
            vcpus = 2
            memory = "2048M"
            cloud_image_url = "https://example.com/cloud.qcow2"
            cloud_image_checksum = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            user = "fedora"

            [security]
            extra_groups = ["kvm", "render"]
        """)
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        sysusers = (Path(self.sysusers_dir) / "workload-grpvm.conf").read_text()
        # implicit kvm membership present exactly once (extra_groups kvm de-duped)
        self.assertEqual(sysusers.count("m _wl-grpvm kvm"), 1)
        self.assertIn("m _wl-grpvm render", sysusers)


if __name__ == "__main__":
    unittest.main()
