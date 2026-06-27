#!/usr/bin/env python3
"""Integration tests: generator + write-env pipeline and systemd syntax validation.

These tests verify that components work together correctly:
1. Pipeline tests: generator output feeds correctly into write-env
2. Syntax tests: generated service files pass systemd-analyze verify
"""

import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

GENERATOR = os.path.join(os.path.dirname(__file__), '..', 'generators', 'workload-generate')
WRITE_ENV = os.path.join(os.path.dirname(__file__), '..', 'libexec', 'workload-write-env')
LIB_DIR = os.path.join(os.path.dirname(__file__), '..', 'lib')


def run_generator(config_dir, services_dir, sysusers_dir):
    """Run the generator and return the CompletedProcess."""
    env = os.environ.copy()
    env["WORKLOAD_CONFIG_DIR"] = str(config_dir)
    env["SYSUSERS_DIR"] = str(sysusers_dir)
    env["PYTHONPATH"] = LIB_DIR
    return subprocess.run(
        [sys.executable, GENERATOR, str(services_dir)],
        capture_output=True, text=True, env=env,
    )


def run_write_env(name, config_dir, creds_dir, env_dir):
    """Run workload-write-env and return the CompletedProcess."""
    env = os.environ.copy()
    env["WORKLOAD_CONFIG_DIR"] = str(config_dir)
    env["CREDENTIALS_DIRECTORY"] = str(creds_dir)
    env["WORKLOAD_ENV_DIR"] = str(env_dir)
    env["PYTHONPATH"] = LIB_DIR
    return subprocess.run(
        [sys.executable, WRITE_ENV, name],
        capture_output=True, text=True, env=env,
    )


def write_config(config_dir, name, toml_content):
    (Path(config_dir) / name).mkdir(exist_ok=True)
    path = Path(config_dir) / name / "workload.toml"
    path.write_text(textwrap.dedent(toml_content))
    return path


def write_credential(creds_dir, name, value):
    Path(creds_dir, name).write_text(value)


def has_systemd_analyze():
    """Check if systemd-analyze is available."""
    try:
        subprocess.run(
            ["systemd-analyze", "--version"],
            capture_output=True, check=True,
        )
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


# ---------------------------------------------------------------------------
# Pipeline tests: generator → write-env consistency
# ---------------------------------------------------------------------------

class TestPipelineCredentialConsistency(unittest.TestCase):
    """Verify that credentials the generator declares via LoadCredentialEncrypted
    match exactly what write-env expects to find in $CREDENTIALS_DIRECTORY."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()
        self.creds_dir = tempfile.mkdtemp()
        self.env_dir = tempfile.mkdtemp()

    def tearDown(self):
        for d in (self.config_dir, self.services_dir, self.sysusers_dir,
                  self.creds_dir, self.env_dir):
            shutil.rmtree(d)

    def _extract_load_credentials(self, service_text):
        """Parse LoadCredentialEncrypted= lines, return set of credential names."""
        names = set()
        for line in service_text.splitlines():
            line = line.strip()
            if line.startswith("LoadCredentialEncrypted="):
                # Format: LoadCredentialEncrypted=name:/path
                rhs = line.split("=", 1)[1]
                cred_name = rhs.split(":")[0]
                names.add(cred_name)
        return names

    def _extract_env_file_path(self, service_text):
        """Extract the --env-file path from ExecStart, or None."""
        for line in service_text.splitlines():
            if "--env-file" in line:
                # Find the token after --env-file
                parts = line.split("--env-file")
                if len(parts) > 1:
                    # The path is the next whitespace-delimited token, possibly quoted
                    rest = parts[1].strip()
                    path = rest.split()[0].strip('"')
                    return path
        return None

    def _extract_write_env_name(self, service_text):
        """Extract workload name from ExecStartPre workload-write-env line."""
        for line in service_text.splitlines():
            if "workload-write-env" in line:
                # ExecStartPre=+/usr/libexec/workloadctl/workload-write-env <name>
                return line.strip().split()[-1]
        return None

    def test_secret_env_var_credentials_match(self):
        """Credentials from ${SECRET:name} in env vars appear in LoadCredentialEncrypted."""
        write_config(self.config_dir, "myapp", """\
            [workload]
            name = "myapp"
            enabled = true

            [container]
            image = "myapp:latest"

            [container.environment]
            API_KEY = "${SECRET:api-key}"
            DB_PASS = "${SECRET:db-pass}"
            PLAIN = "hello"
        """)

        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0)

        service = (Path(self.services_dir) / "workload-myapp.service").read_text()
        load_creds = self._extract_load_credentials(service)

        # Both secret names must be declared
        self.assertIn("api-key", load_creds)
        self.assertIn("db-pass", load_creds)

        # Now simulate runtime: create credential files and run write-env
        write_credential(self.creds_dir, "api-key", "sk-12345")
        write_credential(self.creds_dir, "db-pass", "hunter2")

        we_result = run_write_env("myapp", self.config_dir, self.creds_dir, self.env_dir)
        self.assertEqual(we_result.returncode, 0, we_result.stderr)

        secrets_file = Path(self.env_dir) / "workload-myapp.secrets"
        content = secrets_file.read_text()
        lines = sorted(content.strip().split('\n'))
        self.assertEqual(lines, ["API_KEY=sk-12345", "DB_PASS=hunter2"])

    def test_file_credential_in_load_but_not_env_file(self):
        """Secret file credentials appear in LoadCredentialEncrypted but not --env-file."""
        write_config(self.config_dir, "tls-app", """\
            [workload]
            name = "tls-app"
            enabled = true

            [container]
            image = "myapp:latest"

            [secrets]
            files = [
                { credential = "tls-cert", path = "/etc/ssl/cert.pem" },
                { credential = "tls-key", path = "/etc/ssl/key.pem" }
            ]
        """)

        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0)

        service = (Path(self.services_dir) / "workload-tls-app.service").read_text()
        load_creds = self._extract_load_credentials(service)

        self.assertIn("tls-cert", load_creds)
        self.assertIn("tls-key", load_creds)

        # No env-file needed (no secret env vars)
        self.assertIsNone(self._extract_env_file_path(service))
        # write-env not invoked
        self.assertIsNone(self._extract_write_env_name(service))

    def test_mixed_env_and_file_credentials(self):
        """Both env and file credentials detected; env-file only for env secrets."""
        write_config(self.config_dir, "full", """\
            [workload]
            name = "full"
            enabled = true

            [container]
            image = "myapp:latest"

            [container.environment]
            TOKEN = "${SECRET:auth-token}"
            MODE = "production"

            [secrets]
            files = [
                { credential = "ca-cert", path = "/etc/ssl/ca.pem" }
            ]
        """)

        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0)

        service = (Path(self.services_dir) / "workload-full.service").read_text()
        load_creds = self._extract_load_credentials(service)

        # Both credential types in LoadCredentialEncrypted
        self.assertIn("auth-token", load_creds)
        self.assertIn("ca-cert", load_creds)

        # env-file present (for TOKEN)
        env_file_path = self._extract_env_file_path(service)
        self.assertIsNotNone(env_file_path)
        self.assertIn("workload-full.secrets", env_file_path)

        # write-env invoked
        self.assertEqual(self._extract_write_env_name(service), "full")

        # Plain var passed as --env, secret var NOT passed as --env
        self.assertIn("--env MODE=", service)
        self.assertNotIn("--env TOKEN=", service)

        # Verify write-env produces the right output
        write_credential(self.creds_dir, "auth-token", "tok-abc")
        we_result = run_write_env("full", self.config_dir, self.creds_dir, self.env_dir)
        self.assertEqual(we_result.returncode, 0, we_result.stderr)

        content = (Path(self.env_dir) / "workload-full.secrets").read_text()
        self.assertEqual(content.strip(), "TOKEN=tok-abc")

    def test_env_file_path_matches_write_env_output(self):
        """The --env-file path in ExecStart matches the file write-env creates."""
        write_config(self.config_dir, "pathcheck", """\
            [workload]
            name = "pathcheck"
            enabled = true

            [container]
            image = "myapp:latest"

            [container.environment]
            SECRET = "${SECRET:key}"
        """)

        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0)

        service = (Path(self.services_dir) / "workload-pathcheck.service").read_text()
        env_file_path = self._extract_env_file_path(service)

        # The generator hardcodes /run/workload-env/workload-{name}.secrets
        self.assertEqual(env_file_path, "/run/workload-env/workload-pathcheck.secrets")

        # write-env (with overridden WORKLOAD_ENV_DIR) writes workload-{name}.secrets
        write_credential(self.creds_dir, "key", "val")
        run_write_env("pathcheck", self.config_dir, self.creds_dir, self.env_dir)

        # The filename component must match
        actual_file = Path(self.env_dir) / "workload-pathcheck.secrets"
        self.assertTrue(actual_file.exists())
        expected_basename = Path(env_file_path).name
        self.assertEqual(actual_file.name, expected_basename)

    def test_missing_credential_caught_by_write_env(self):
        """If generator declares a credential but it's missing at runtime, write-env fails."""
        write_config(self.config_dir, "missing", """\
            [workload]
            name = "missing"
            enabled = true

            [container]
            image = "myapp:latest"

            [container.environment]
            KEY = "${SECRET:oops}"
        """)

        # Generator succeeds (it doesn't check credential existence)
        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0)

        service = (Path(self.services_dir) / "workload-missing.service").read_text()
        self.assertIn("LoadCredentialEncrypted=oops:", service)

        # write-env fails because credential file doesn't exist
        we_result = run_write_env("missing", self.config_dir, self.creds_dir, self.env_dir)
        self.assertNotEqual(we_result.returncode, 0)
        self.assertIn("oops", we_result.stderr)

    def test_embedded_secret_in_value(self):
        """Secrets embedded in larger values (e.g., DSN strings) work end-to-end."""
        write_config(self.config_dir, "dsn", """\
            [workload]
            name = "dsn"
            enabled = true

            [container]
            image = "myapp:latest"

            [container.environment]
            DATABASE_URL = "postgres://user:${SECRET:db-pass}@db:5432/mydb"
        """)

        result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(result.returncode, 0)

        service = (Path(self.services_dir) / "workload-dsn.service").read_text()
        self.assertIn("LoadCredentialEncrypted=db-pass:", service)
        self.assertNotIn("--env DATABASE_URL=", service)

        write_credential(self.creds_dir, "db-pass", "s3cret!")
        we_result = run_write_env("dsn", self.config_dir, self.creds_dir, self.env_dir)
        self.assertEqual(we_result.returncode, 0, we_result.stderr)

        content = (Path(self.env_dir) / "workload-dsn.secrets").read_text()
        self.assertEqual(content.strip(), "DATABASE_URL=postgres://user:s3cret!@db:5432/mydb")


# ---------------------------------------------------------------------------
# systemd-analyze verify tests
# ---------------------------------------------------------------------------

@unittest.skipUnless(has_systemd_analyze(), "systemd-analyze not available")
class TestSystemdAnalyzeVerify(unittest.TestCase):
    """Run systemd-analyze verify on generated service files to catch syntax errors."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def _generate_and_verify(self, name, toml_content):
        """Generate a service file and run systemd-analyze verify on it.

        Patches ExecStartPre commands that reference /usr/libexec/ helpers
        (not present on dev machines) with /bin/true so systemd-analyze
        can validate the rest of the unit file syntax.

        Returns (verify_result, service_text).
        """
        write_config(self.config_dir, name, toml_content)
        gen_result = run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        self.assertEqual(gen_result.returncode, 0, gen_result.stderr)

        service_path = Path(self.services_dir) / f"workload-{name}.service"
        self.assertTrue(service_path.exists(), f"Service file not created for {name}")

        # Keep original for assertions, patch a copy for verify
        original = service_path.read_text()
        patched = original
        # Replace ExecStartPre commands pointing to helpers not on this host
        patched = patched.replace(
            "/usr/libexec/workloadctl/workload-ensure-user", "/bin/true")
        patched = patched.replace(
            "/usr/libexec/workloadctl/workload-write-env", "/bin/true")
        # Dev containers don't ship podman; systemd-analyze fails the unit on a
        # non-executable ExecStart. Patch only when actually absent so real
        # hosts keep strict verify.
        if not os.path.exists("/usr/bin/podman"):
            patched = patched.replace("/usr/bin/podman", "/bin/true")
        # sysusers conf is now in services_dir (generator output) — no patching needed
        # EnvironmentFile already has - prefix (optional) — no patching needed
        service_path.write_text(patched)

        verify_result = subprocess.run(
            ["systemd-analyze", "verify", str(service_path)],
            capture_output=True, text=True,
        )
        return verify_result, original

    def test_minimal_workload(self):
        result, _ = self._generate_and_verify("minimal", """\
            [workload]
            name = "minimal"
            enabled = true

            [container]
            image = "alpine:latest"
        """)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_workload_with_ports(self):
        result, _ = self._generate_and_verify("webserver", """\
            [workload]
            name = "webserver"
            enabled = true

            [container]
            image = "nginx:latest"

            [network]
            ports = ["8080:80", "8443:443"]
        """)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_workload_with_secrets(self):
        result, _ = self._generate_and_verify("secretsvc", """\
            [workload]
            name = "secretsvc"
            enabled = true

            [container]
            image = "myapp:latest"

            [container.environment]
            API_KEY = "${SECRET:api-key}"
            MODE = "prod"
        """)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_workload_with_volumes(self):
        result, _ = self._generate_and_verify("volsvc", """\
            [workload]
            name = "volsvc"
            enabled = true

            [container]
            image = "myapp:latest"

            [storage]
            volumes = ["./data:/app/data:rw", "/srv/shared:/shared:ro"]
        """)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_workload_with_resources(self):
        result, _ = self._generate_and_verify("limited", """\
            [workload]
            name = "limited"
            enabled = true

            [container]
            image = "myapp:latest"

            [resources]
            cpu_quota = "200%"
            memory_max = "4G"
            tasks_max = 100
        """)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_workload_with_devices(self):
        result, _ = self._generate_and_verify("gpusvc", """\
            [workload]
            name = "gpusvc"
            enabled = true

            [container]
            image = "rocm-app:latest"

            [devices]
            gpu = "amd"
            devices = ["/dev/ttyUSB0"]
        """)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_workload_with_secret_files(self):
        result, _ = self._generate_and_verify("tlssvc", """\
            [workload]
            name = "tlssvc"
            enabled = true

            [container]
            image = "myapp:latest"

            [secrets]
            files = [
                { credential = "tls-cert", path = "/etc/ssl/cert.pem" },
                { credential = "tls-key", path = "/etc/ssl/key.pem", mode = "ro" }
            ]
        """)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_workload_host_network(self):
        result, _ = self._generate_and_verify("hostnetsvc", """\
            [workload]
            name = "hostnetsvc"
            enabled = true

            [container]
            image = "myapp:latest"

            [network]
            mode = "host"
        """)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_workload_userns_host(self):
        result, _ = self._generate_and_verify("hostns", """\
            [workload]
            name = "hostns"
            enabled = true

            [container]
            image = "myapp:latest"

            [security]
            userns = "host"
        """)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_workload_userns_keep_id_with_uid_gid(self):
        result, _ = self._generate_and_verify("uidmap", """\
            [workload]
            name = "uidmap"
            enabled = true

            [container]
            image = "myapp:latest"

            [security]
            userns = "keep-id:uid=65534,gid=65534"
        """)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_workload_with_capabilities(self):
        result, _ = self._generate_and_verify("capsvc", """\
            [workload]
            name = "capsvc"
            enabled = true

            [container]
            image = "myapp:latest"

            [security]
            userns = "host"
            capabilities = ["NET_ADMIN", "NET_RAW"]
        """)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_workload_with_command(self):
        result, _ = self._generate_and_verify("cmdsvc", """\
            [workload]
            name = "cmdsvc"
            enabled = true

            [container]
            image = "alpine:latest"
            command = ["sh", "-c", "echo hello && sleep infinity"]
        """)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_workload_kitchen_sink(self):
        """A complex workload using most features at once."""
        result, _ = self._generate_and_verify("kitchen", """\
            [workload]
            name = "kitchen"
            enabled = true

            [container]
            image = "myapp:latest"
            command = "/usr/bin/start.sh"
            pull = "never"

            [container.environment]
            TOKEN = "${SECRET:auth-token}"
            DB = "postgres://${SECRET:db-user}:${SECRET:db-pass}@db:5432/app"
            LOG_LEVEL = "info"
            PORT = "8080"

            [network]
            mode = "pasta"
            ports = ["8080:8080", "9090:9090"]

            [storage]
            volumes = ["./data:/app/data:rw", "/srv/cache:/cache:ro"]

            [devices]
            gpu = "amd"

            [security]
            userns = "keep-id"
            capabilities = ["NET_ADMIN"]

            [secrets]
            files = [
                { credential = "tls-cert", path = "/etc/ssl/cert.pem" }
            ]

            [resources]
            cpu_quota = "400%"
            memory_max = "8G"
            memory_high = "6G"
            tasks_max = 200
            timeout_start_sec = 600
        """)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_no_unknown_directives_in_service_section(self):
        """Verify that generated service files don't produce 'Unknown key' warnings."""
        write_config(self.config_dir, "clean", """\
            [workload]
            name = "clean"
            enabled = true

            [container]
            image = "alpine:latest"

            [container.environment]
            KEY = "${SECRET:secret-key}"

            [resources]
            cpu_quota = "100%"
            memory_max = "1G"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service_path = Path(self.services_dir) / "workload-clean.service"

        result = subprocess.run(
            ["systemd-analyze", "verify", str(service_path)],
            capture_output=True, text=True,
        )
        # No "Unknown key" warnings
        self.assertNotIn("Unknown key", result.stderr,
                         f"Generated service has unknown directives:\n{result.stderr}")


if __name__ == "__main__":
    unittest.main()
