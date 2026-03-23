#!/usr/bin/env python3
"""Unit tests for the shared workload library."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add lib to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))

from workload_lib import (
    WORKLOADS_BASE, USERNAME_PREFIX, MAX_NAME_LENGTH, NAME_PATTERN,
    GENERATOR_OWNED_DIRECTIVES, SECRET_PATTERN,
    workload_username, workload_service_name, workload_container_name,
    workload_home_dir, validate_workload_name, expand_volume_path, dq,
    auto_detect_credentials, resolve_secret_env_vars,
)


class TestNaming(unittest.TestCase):
    def test_username(self):
        self.assertEqual(workload_username("foo"), "_wl-foo")
        self.assertEqual(workload_username("my-app"), "_wl-my-app")

    def test_service_name(self):
        self.assertEqual(workload_service_name("foo"), "workload-foo.service")

    def test_container_name(self):
        self.assertEqual(workload_container_name("foo"), "workload-foo")

    def test_home_dir(self):
        self.assertEqual(workload_home_dir("foo"), WORKLOADS_BASE / "foo")


class TestValidation(unittest.TestCase):
    def test_valid_names(self):
        for name in ["app", "my-app", "web1", "a", "a1b2c3"]:
            validate_workload_name(name)  # should not raise

    def test_uppercase_rejected(self):
        with self.assertRaises(ValueError):
            validate_workload_name("MyApp")

    def test_underscore_rejected(self):
        with self.assertRaises(ValueError):
            validate_workload_name("my_app")

    def test_starts_with_digit_rejected(self):
        with self.assertRaises(ValueError):
            validate_workload_name("1app")

    def test_starts_with_hyphen_rejected(self):
        with self.assertRaises(ValueError):
            validate_workload_name("-app")

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            validate_workload_name("")

    def test_too_long_rejected(self):
        with self.assertRaises(ValueError):
            validate_workload_name("a" * (MAX_NAME_LENGTH + 1))

    def test_max_length_accepted(self):
        validate_workload_name("a" * MAX_NAME_LENGTH)


class TestExpandVolumePath(unittest.TestCase):
    def test_relative_with_container_path(self):
        result = expand_volume_path("./data:/app/data", "/home/wl")
        self.assertEqual(result, "/home/wl/data:/app/data")

    def test_relative_with_options(self):
        result = expand_volume_path("./conf:/etc/conf:ro", "/home/wl")
        self.assertEqual(result, "/home/wl/conf:/etc/conf:ro")

    def test_absolute_unchanged(self):
        result = expand_volume_path("/srv/data:/app/data", "/home/wl")
        self.assertEqual(result, "/srv/data:/app/data")

    def test_relative_no_container_path(self):
        result = expand_volume_path("./data", "/home/wl")
        self.assertEqual(result, "/home/wl/data")

    def test_absolute_no_container_path(self):
        result = expand_volume_path("/srv/data", "/home/wl")
        self.assertEqual(result, "/srv/data")


class TestDq(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(dq("hello"), '"hello"')

    def test_with_quotes(self):
        self.assertEqual(dq('say "hi"'), '"say \\"hi\\""')

    def test_with_backslash(self):
        self.assertEqual(dq("a\\b"), '"a\\\\b"')

    def test_empty(self):
        self.assertEqual(dq(""), '""')

    def test_with_spaces(self):
        self.assertEqual(dq("hello world"), '"hello world"')


class TestSecretPattern(unittest.TestCase):
    def test_matches_simple(self):
        m = SECRET_PATTERN.search("${SECRET:api-key}")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "api-key")

    def test_matches_underscore(self):
        m = SECRET_PATTERN.search("${SECRET:my_secret}")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "my_secret")

    def test_matches_embedded(self):
        m = SECRET_PATTERN.search("prefix${SECRET:key}suffix")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "key")

    def test_no_match_plain(self):
        m = SECRET_PATTERN.search("just a plain value")
        self.assertIsNone(m)

    def test_multiple_matches(self):
        matches = SECRET_PATTERN.findall("${SECRET:a} and ${SECRET:b}")
        self.assertEqual(matches, ["a", "b"])


class TestAutoDetectCredentials(unittest.TestCase):
    def test_env_vars(self):
        config = {
            "container": {
                "environment": {
                    "API_KEY": "${SECRET:api-key}",
                    "PLAIN": "hello",
                }
            }
        }
        self.assertEqual(auto_detect_credentials(config), {"api-key"})

    def test_files(self):
        config = {
            "secrets": {
                "files": [
                    {"credential": "tls-cert", "path": "/etc/ssl/cert.pem"}
                ]
            }
        }
        self.assertEqual(auto_detect_credentials(config), {"tls-cert"})

    def test_both(self):
        config = {
            "container": {
                "environment": {"K": "${SECRET:env-secret}"}
            },
            "secrets": {
                "files": [{"credential": "file-secret", "path": "/x"}]
            },
        }
        self.assertEqual(
            auto_detect_credentials(config), {"env-secret", "file-secret"}
        )

    def test_mixed_value(self):
        config = {
            "container": {
                "environment": {
                    "DSN": "host=db pw=${SECRET:db-pass} port=5432"
                }
            }
        }
        self.assertEqual(auto_detect_credentials(config), {"db-pass"})

    def test_empty_config(self):
        self.assertEqual(auto_detect_credentials({}), set())

    def test_no_secrets(self):
        config = {
            "container": {"environment": {"PLAIN": "value"}}
        }
        self.assertEqual(auto_detect_credentials(config), set())


class TestResolveSecretEnvVars(unittest.TestCase):
    def setUp(self):
        self.creds_dir = tempfile.mkdtemp()
        Path(self.creds_dir, "api-key").write_text("sk-12345")
        Path(self.creds_dir, "db-pass").write_text("hunter2")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.creds_dir)

    def test_simple_secret(self):
        config = {
            "container": {"environment": {"K": "${SECRET:api-key}"}}
        }
        resolved = resolve_secret_env_vars(config, self.creds_dir)
        self.assertEqual(resolved, {"K": "sk-12345"})

    def test_mixed_value(self):
        config = {
            "container": {
                "environment": {
                    "DSN": "host=db pw=${SECRET:db-pass} port=5432"
                }
            }
        }
        resolved = resolve_secret_env_vars(config, self.creds_dir)
        self.assertEqual(resolved, {"DSN": "host=db pw=hunter2 port=5432"})

    def test_multiple_secrets_in_one_value(self):
        config = {
            "container": {
                "environment": {
                    "COMBO": "${SECRET:api-key}:${SECRET:db-pass}"
                }
            }
        }
        resolved = resolve_secret_env_vars(config, self.creds_dir)
        self.assertEqual(resolved, {"COMBO": "sk-12345:hunter2"})

    def test_plain_vars_excluded(self):
        config = {
            "container": {
                "environment": {
                    "SECRET_VAR": "${SECRET:api-key}",
                    "PLAIN": "hello",
                }
            }
        }
        resolved = resolve_secret_env_vars(config, self.creds_dir)
        self.assertNotIn("PLAIN", resolved)
        self.assertIn("SECRET_VAR", resolved)

    def test_missing_credential_raises(self):
        config = {
            "container": {"environment": {"K": "${SECRET:nonexistent}"}}
        }
        with self.assertRaises(FileNotFoundError):
            resolve_secret_env_vars(config, self.creds_dir)

    def test_empty_env(self):
        config = {"container": {"environment": {}}}
        resolved = resolve_secret_env_vars(config, self.creds_dir)
        self.assertEqual(resolved, {})


class TestConstants(unittest.TestCase):
    def test_username_prefix(self):
        self.assertEqual(USERNAME_PREFIX, "_wl-")

    def test_max_name_length_fits_username(self):
        # _wl- (4 chars) + max name + null = 32 (LOGIN_NAME_MAX)
        self.assertEqual(len(USERNAME_PREFIX) + MAX_NAME_LENGTH + 1, 32)

    def test_generator_owned_directives_is_frozenset(self):
        self.assertIsInstance(GENERATOR_OWNED_DIRECTIVES, frozenset)
        self.assertIn("ExecStart", GENERATOR_OWNED_DIRECTIVES)


if __name__ == "__main__":
    unittest.main()
