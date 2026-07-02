#!/usr/bin/env python3
"""Integration tests for the workload-write-env helper.

Runs the helper with temp directories for config, credentials, and output.
No root required — all paths are overridden via env vars.
"""

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

WRITE_ENV = os.path.join(os.path.dirname(__file__), '..', 'libexec', 'workload-write-env')
LIB_DIR = os.path.join(os.path.dirname(__file__), '..', 'lib')


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


def write_config(config_dir, name, toml_content, enabled=True):
    (Path(config_dir) / name).mkdir(exist_ok=True)
    path = Path(config_dir) / name / "workload.toml"
    body = textwrap.dedent(toml_content)
    path.write_text(body)
    if enabled:
        (Path(config_dir) / name / ".enabled").touch()
    return path


def write_credential(creds_dir, name, value):
    Path(creds_dir, name).write_text(value)


class TestWriteEnvBasic(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.creds_dir = tempfile.mkdtemp()
        self.env_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.creds_dir, self.env_dir):
            shutil.rmtree(d)

    def test_simple_secret(self):
        write_config(self.config_dir, "app", """\
            [workload]
            name = "app"

            [container]
            image = "myapp"

            [container.environment]
            API_KEY = "${SECRET:api-key}"
        """)
        write_credential(self.creds_dir, "api-key", "sk-12345")

        result = run_write_env("app", self.config_dir, self.creds_dir, self.env_dir)
        self.assertEqual(result.returncode, 0, result.stderr)

        env_file = Path(self.env_dir) / "workload-app.secrets"
        self.assertTrue(env_file.exists())
        content = env_file.read_text()
        self.assertEqual(content.strip(), "API_KEY=sk-12345")

    def test_mixed_value(self):
        write_config(self.config_dir, "db", """\
            [workload]
            name = "db"

            [container]
            image = "myapp"

            [container.environment]
            DSN = "host=db.local password=${SECRET:db-pass} port=5432"
        """)
        write_credential(self.creds_dir, "db-pass", "hunter2")

        result = run_write_env("db", self.config_dir, self.creds_dir, self.env_dir)
        self.assertEqual(result.returncode, 0, result.stderr)

        content = (Path(self.env_dir) / "workload-db.secrets").read_text()
        self.assertEqual(content.strip(), "DSN=host=db.local password=hunter2 port=5432")

    def test_multiple_secrets(self):
        write_config(self.config_dir, "multi", """\
            [workload]
            name = "multi"

            [container]
            image = "myapp"

            [container.environment]
            KEY_A = "${SECRET:secret-a}"
            KEY_B = "${SECRET:secret-b}"
        """)
        write_credential(self.creds_dir, "secret-a", "value-a")
        write_credential(self.creds_dir, "secret-b", "value-b")

        result = run_write_env("multi", self.config_dir, self.creds_dir, self.env_dir)
        self.assertEqual(result.returncode, 0, result.stderr)

        content = (Path(self.env_dir) / "workload-multi.secrets").read_text()
        lines = sorted(content.strip().split('\n'))
        self.assertEqual(lines, ["KEY_A=value-a", "KEY_B=value-b"])

    def test_plain_vars_excluded(self):
        write_config(self.config_dir, "mix", """\
            [workload]
            name = "mix"

            [container]
            image = "myapp"

            [container.environment]
            SECRET_VAR = "${SECRET:api-key}"
            PLAIN = "hello world"
        """)
        write_credential(self.creds_dir, "api-key", "sk-999")

        result = run_write_env("mix", self.config_dir, self.creds_dir, self.env_dir)
        self.assertEqual(result.returncode, 0, result.stderr)

        content = (Path(self.env_dir) / "workload-mix.secrets").read_text()
        self.assertIn("SECRET_VAR=sk-999", content)
        self.assertNotIn("PLAIN", content)

    def test_file_permissions(self):
        write_config(self.config_dir, "perms", """\
            [workload]
            name = "perms"

            [container]
            image = "myapp"

            [container.environment]
            K = "${SECRET:key}"
        """)
        write_credential(self.creds_dir, "key", "val")

        run_write_env("perms", self.config_dir, self.creds_dir, self.env_dir)

        env_file = Path(self.env_dir) / "workload-perms.secrets"
        mode = oct(env_file.stat().st_mode & 0o777)
        self.assertEqual(mode, "0o600")


class TestWriteEnvNoSecrets(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.creds_dir = tempfile.mkdtemp()
        self.env_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.creds_dir, self.env_dir):
            shutil.rmtree(d)

    def test_no_secrets_no_output(self):
        write_config(self.config_dir, "plain", """\
            [workload]
            name = "plain"

            [container]
            image = "myapp"

            [container.environment]
            FOO = "bar"
        """)

        result = run_write_env("plain", self.config_dir, self.creds_dir, self.env_dir)
        self.assertEqual(result.returncode, 0)

        # No secrets file should be created
        env_file = Path(self.env_dir) / "workload-plain.secrets"
        self.assertFalse(env_file.exists())

    def test_no_env_vars_at_all(self):
        write_config(self.config_dir, "empty", """\
            [workload]
            name = "empty"

            [container]
            image = "myapp"
        """)

        result = run_write_env("empty", self.config_dir, self.creds_dir, self.env_dir)
        self.assertEqual(result.returncode, 0)


class TestWriteEnvErrors(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.creds_dir = tempfile.mkdtemp()
        self.env_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.creds_dir, self.env_dir):
            shutil.rmtree(d)

    def test_missing_credential_fails(self):
        write_config(self.config_dir, "fail", """\
            [workload]
            name = "fail"

            [container]
            image = "myapp"

            [container.environment]
            K = "${SECRET:nonexistent}"
        """)

        result = run_write_env("fail", self.config_dir, self.creds_dir, self.env_dir)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nonexistent", result.stderr)

    def test_missing_credentials_directory(self):
        write_config(self.config_dir, "nocreds", """\
            [workload]
            name = "nocreds"

            [container]
            image = "myapp"

            [container.environment]
            K = "${SECRET:key}"
        """)

        # Run without CREDENTIALS_DIRECTORY set
        env = os.environ.copy()
        env["WORKLOAD_CONFIG_DIR"] = self.config_dir
        env["WORKLOAD_ENV_DIR"] = self.env_dir
        env["PYTHONPATH"] = LIB_DIR
        env.pop("CREDENTIALS_DIRECTORY", None)

        result = subprocess.run(
            [sys.executable, WRITE_ENV, "nocreds"],
            capture_output=True, text=True, env=env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CREDENTIALS_DIRECTORY", result.stderr)

    def test_no_args(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = LIB_DIR
        result = subprocess.run(
            [sys.executable, WRITE_ENV],
            capture_output=True, text=True, env=env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Usage", result.stderr)


class TestWriteEnvEdgeCases(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.creds_dir = tempfile.mkdtemp()
        self.env_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.creds_dir, self.env_dir):
            shutil.rmtree(d)

    def test_secret_with_special_chars(self):
        write_config(self.config_dir, "special", """\
            [workload]
            name = "special"

            [container]
            image = "myapp"

            [container.environment]
            PASS = "${SECRET:pass}"
        """)
        write_credential(self.creds_dir, "pass", 'p@ss"w0rd$with\\special')

        result = run_write_env("special", self.config_dir, self.creds_dir, self.env_dir)
        self.assertEqual(result.returncode, 0, result.stderr)

        content = (Path(self.env_dir) / "workload-special.secrets").read_text()
        self.assertEqual(content.strip(), 'PASS=p@ss"w0rd$with\\special')

    def test_newline_in_secret_warns(self):
        write_config(self.config_dir, "newline", """\
            [workload]
            name = "newline"

            [container]
            image = "myapp"

            [container.environment]
            CERT = "${SECRET:cert}"
        """)
        write_credential(self.creds_dir, "cert", "line1\nline2")

        result = run_write_env("newline", self.config_dir, self.creds_dir, self.env_dir)
        self.assertEqual(result.returncode, 1)
        self.assertIn("ERROR", result.stderr)
        self.assertIn("newlines", result.stderr)

    def test_multiple_secrets_in_one_value(self):
        write_config(self.config_dir, "combo", """\
            [workload]
            name = "combo"

            [container]
            image = "myapp"

            [container.environment]
            AUTH = "${SECRET:user}:${SECRET:pass}"
        """)
        write_credential(self.creds_dir, "user", "admin")
        write_credential(self.creds_dir, "pass", "s3cret")

        result = run_write_env("combo", self.config_dir, self.creds_dir, self.env_dir)
        self.assertEqual(result.returncode, 0, result.stderr)

        content = (Path(self.env_dir) / "workload-combo.secrets").read_text()
        self.assertEqual(content.strip(), "AUTH=admin:s3cret")


if __name__ == "__main__":
    unittest.main()
