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

from tests import script_env


WRITE_ENV = os.path.join(os.path.dirname(__file__), '..', 'libexec', 'workload-write-env')


def run_write_env(name, config_dir, creds_dir, env_dir, container=None):
    """Run workload-write-env and return the CompletedProcess."""
    env = script_env(
        WORKLOAD_CONFIG_DIR=config_dir,
        CREDENTIALS_DIRECTORY=creds_dir,
        WORKLOAD_ENV_DIR=env_dir,
    )
    argv = [sys.executable, WRITE_ENV, name]
    if container is not None:
        argv.append(container)
    return subprocess.run(
        argv,
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
        env = script_env(
            WORKLOAD_CONFIG_DIR=self.config_dir,
            WORKLOAD_ENV_DIR=self.env_dir,
        )
        env.pop("CREDENTIALS_DIRECTORY", None)

        result = subprocess.run(
            [sys.executable, WRITE_ENV, "nocreds"],
            capture_output=True, text=True, env=env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CREDENTIALS_DIRECTORY", result.stderr)

    def test_no_args(self):
        env = script_env()
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


class TestWriteEnvMultiContainer(unittest.TestCase):
    """Exercise the [[containers]] / <workload> <container> dispatch paths."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.creds_dir = tempfile.mkdtemp()
        self.env_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.creds_dir, self.env_dir):
            shutil.rmtree(d)

    POD_TOML = """\
        [workload]
        name = "pod"
        mode = "pod"

        [[containers]]
        name = "web"
        [containers.container]
        image = "web-img"
        [containers.container.environment]
        WEB_KEY = "${SECRET:web-secret}"

        [[containers]]
        name = "db"
        [containers.container]
        image = "db-img"
        [containers.container.environment]
        DB_KEY = "${SECRET:db-secret}"
    """

    def test_multi_container_without_container_arg_fails(self):
        """A multi-container workload called with no container name errors out."""
        write_config(self.config_dir, "pod", self.POD_TOML)
        write_credential(self.creds_dir, "web-secret", "w")
        write_credential(self.creds_dir, "db-secret", "d")

        result = run_write_env("pod", self.config_dir, self.creds_dir, self.env_dir)
        self.assertEqual(result.returncode, 1)
        self.assertIn("multiple containers", result.stderr)
        # Nothing should have been written.
        self.assertFalse(any(Path(self.env_dir).iterdir()))

    def test_container_not_found_fails(self):
        """Requesting a container that isn't in the workload errors out."""
        write_config(self.config_dir, "pod", self.POD_TOML)
        write_credential(self.creds_dir, "web-secret", "w")
        write_credential(self.creds_dir, "db-secret", "d")

        result = run_write_env(
            "pod", self.config_dir, self.creds_dir, self.env_dir, container="nope"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("nope", result.stderr)
        self.assertIn("not in workload", result.stderr)
        self.assertFalse(any(Path(self.env_dir).iterdir()))

    def test_container_arg_writes_per_container_file(self):
        """A valid container name writes only that container's secrets."""
        write_config(self.config_dir, "pod", self.POD_TOML)
        write_credential(self.creds_dir, "web-secret", "web-val")
        write_credential(self.creds_dir, "db-secret", "db-val")

        result = run_write_env(
            "pod", self.config_dir, self.creds_dir, self.env_dir, container="db"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        db_file = Path(self.env_dir) / "workload-pod-db.secrets"
        web_file = Path(self.env_dir) / "workload-pod-web.secrets"
        self.assertTrue(db_file.exists())
        # Only the requested container's file is written.
        self.assertFalse(web_file.exists())
        self.assertEqual(db_file.read_text().strip(), "DB_KEY=db-val")
        self.assertEqual(oct(db_file.stat().st_mode & 0o777), "0o600")


class TestWriteEnvKeyValidation(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.creds_dir = tempfile.mkdtemp()
        self.env_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.creds_dir, self.env_dir):
            shutil.rmtree(d)

    def test_invalid_env_key_rejected(self):
        """A key that isn't a valid POSIX name is rejected (guard must hold)."""
        write_config(self.config_dir, "badkey", """\
            [workload]
            name = "badkey"

            [container]
            image = "myapp"

            [container.environment]
            "1INVALID" = "${SECRET:k}"
        """)
        write_credential(self.creds_dir, "k", "v")

        result = run_write_env("badkey", self.config_dir, self.creds_dir, self.env_dir)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Invalid env var key", result.stderr)
        # The guard must fail closed: no secrets file left behind with a bad key.
        self.assertFalse(
            (Path(self.env_dir) / "workload-badkey.secrets").exists()
            and (Path(self.env_dir) / "workload-badkey.secrets").read_text()
        )


class TestWriteEnvDollarEscape(unittest.TestCase):
    """`$${SECRET:name}` is a literal, not a reference: it must be delivered
    verbatim and must NOT demand a credential — so an escaped-only workload has
    no LoadCredentialEncrypted (hence no CREDENTIALS_DIRECTORY) yet still boots.

    These exercise the full script (generator-equivalent credential decision +
    resolver + file write), not resolve_secret_env_vars in isolation, which is
    where the escape-aware and bare gates previously disagreed."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.creds_dir = tempfile.mkdtemp()
        self.env_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.creds_dir, self.env_dir):
            shutil.rmtree(d)

    def _run_without_creds_dir(self, name):
        """Run the helper with CREDENTIALS_DIRECTORY unset — mirrors a unit that
        emitted no LoadCredentialEncrypted (nothing to decrypt)."""
        env = script_env(
            WORKLOAD_CONFIG_DIR=self.config_dir,
            WORKLOAD_ENV_DIR=self.env_dir,
        )
        env.pop("CREDENTIALS_DIRECTORY", None)
        return subprocess.run(
            [sys.executable, WRITE_ENV, name],
            capture_output=True, text=True, env=env,
        )

    def test_escaped_only_boots_without_credentials_directory(self):
        # An env value whose ONLY secret syntax is escaped demands no credential.
        # Regression: the bare has_secret gate used to force this ExecStartPre to
        # fail with "CREDENTIALS_DIRECTORY not set", boot-blocking the workload.
        write_config(self.config_dir, "esconly", """\
            [workload]
            name = "esconly"

            [container]
            image = "myapp"

            [container.environment]
            LIT = "$${SECRET:phantom}"
        """)

        result = self._run_without_creds_dir("esconly")
        self.assertEqual(result.returncode, 0, result.stderr)

        content = (Path(self.env_dir) / "workload-esconly.secrets").read_text()
        # Collapses to the literal ${SECRET:phantom}; credential never read.
        self.assertEqual(content.strip(), "LIT=${SECRET:phantom}")

    def test_escaped_alongside_real_ref(self):
        # Escaped literal + a real ref on the same container: the real ref still
        # needs (and gets) the credstore; the escaped one stays literal.
        write_config(self.config_dir, "mixesc", """\
            [workload]
            name = "mixesc"

            [container]
            image = "myapp"

            [container.environment]
            LIT = "$${SECRET:phantom}"
            REAL = "${SECRET:used}"
        """)
        write_credential(self.creds_dir, "used", "realval")

        result = run_write_env("mixesc", self.config_dir, self.creds_dir, self.env_dir)
        self.assertEqual(result.returncode, 0, result.stderr)

        content = (Path(self.env_dir) / "workload-mixesc.secrets").read_text()
        lines = sorted(content.strip().split('\n'))
        self.assertEqual(lines, ["LIT=${SECRET:phantom}", "REAL=realval"])

    def test_escaped_only_never_reads_credstore(self):
        # Even with the credstore reachable, an escaped ref must not read a
        # same-named credential — the escape means "literal", full stop.
        write_config(self.config_dir, "escread", """\
            [workload]
            name = "escread"

            [container]
            image = "myapp"

            [container.environment]
            LIT = "$${SECRET:decoy}"
        """)
        write_credential(self.creds_dir, "decoy", "SHOULD-NOT-APPEAR")

        result = run_write_env("escread", self.config_dir, self.creds_dir, self.env_dir)
        self.assertEqual(result.returncode, 0, result.stderr)

        content = (Path(self.env_dir) / "workload-escread.secrets").read_text()
        self.assertEqual(content.strip(), "LIT=${SECRET:decoy}")
        self.assertNotIn("SHOULD-NOT-APPEAR", content)


if __name__ == "__main__":
    unittest.main()
