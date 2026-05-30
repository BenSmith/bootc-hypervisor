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
    validate_workload_config, infer_workload_mode, normalize_containers,
)


class TestMultiContainerValidation(unittest.TestCase):
    def test_rejects_both_container_blocks(self):
        config = {
            "workload": {"name": "x"},
            "container": {"image": "a"},
            "containers": [{"name": "c1", "container": {"image": "b"}}],
        }
        errs = validate_workload_config(config)
        self.assertTrue(any("both [container] and [[containers]]" in e for e in errs))

    def test_requires_unique_container_names(self):
        config = {
            "workload": {"name": "x"},
            "containers": [
                {"name": "c1", "container": {"image": "a"}},
                {"name": "c1", "container": {"image": "b"}},
            ],
        }
        errs = validate_workload_config(config)
        self.assertTrue(any("duplicate container name" in e for e in errs))

    def test_requires_image(self):
        config = {
            "workload": {"name": "x"},
            "containers": [{"name": "c1"}],
        }
        errs = validate_workload_config(config)
        self.assertTrue(any("image is required" in e for e in errs))

    def test_infer_mode_default_pod_for_multi(self):
        self.assertEqual(
            infer_workload_mode({"workload": {"name": "x"}, "containers": [{}]}),
            "pod",
        )

    def test_infer_mode_default_single(self):
        self.assertEqual(
            infer_workload_mode({"workload": {"name": "x"}, "container": {}}),
            "single",
        )

    def test_infer_mode_rejects_invalid(self):
        with self.assertRaises(ValueError):
            infer_workload_mode({"workload": {"name": "x", "mode": "bogus"}})

    def test_rejects_env_in_both_forms(self):
        config = {
            "workload": {"name": "x"},
            "containers": [{
                "name": "a",
                "container": {"image": "i", "environment": {"K": "nested"}},
                "environment": {"K": "sibling"},
            }],
        }
        errs = validate_workload_config(config)
        self.assertTrue(any("'environment' set both" in e for e in errs))

    def test_rejects_health_in_both_forms(self):
        config = {
            "workload": {"name": "x"},
            "containers": [{
                "name": "a",
                "container": {"image": "i", "health": {"cmd": "nested"}},
                "health": {"cmd": "sibling"},
            }],
        }
        errs = validate_workload_config(config)
        self.assertTrue(any("'health' set both" in e for e in errs))


class TestNormalizeContainers(unittest.TestCase):
    def test_single_container_unchanged(self):
        config = {
            "workload": {"name": "myapp"},
            "container": {"image": "img", "environment": {"K": "v"}},
            "security": {"capabilities": ["NET_BIND_SERVICE"]},
            "storage": {"volumes": ["./d:/d"]},
        }
        result = normalize_containers(config)
        self.assertEqual(len(result), 1)
        entry = result[0]
        self.assertEqual(entry["name"], "myapp")
        self.assertEqual(entry["container"]["image"], "img")
        self.assertEqual(entry["container"]["environment"], {"K": "v"})
        self.assertEqual(entry["security"]["capabilities"], ["NET_BIND_SERVICE"])
        self.assertEqual(entry["storage"]["volumes"], ["./d:/d"])

    def test_multi_lifts_sibling_environment(self):
        """[containers.environment] (sibling) lifts into entry["container"]["environment"]
        so the generator sees the same shape as a single-container TOML."""
        config = {
            "workload": {"name": "x"},
            "containers": [{
                "name": "db",
                "container": {"image": "postgres"},
                "environment": {"PGUSER": "alice"},
            }],
        }
        result = normalize_containers(config)
        self.assertEqual(result[0]["container"]["environment"], {"PGUSER": "alice"})
        self.assertNotIn("environment", result[0])

    def test_multi_lifts_sibling_health(self):
        config = {
            "workload": {"name": "x"},
            "containers": [{
                "name": "web",
                "container": {"image": "nginx"},
                "health": {"cmd": "wget localhost", "interval": "10s"},
            }],
        }
        result = normalize_containers(config)
        self.assertEqual(
            result[0]["container"]["health"],
            {"cmd": "wget localhost", "interval": "10s"},
        )
        self.assertNotIn("health", result[0])

    def test_multi_preserves_nested_forms(self):
        """Nested forms ([containers.container.environment]) pass through
        unchanged."""
        config = {
            "workload": {"name": "x"},
            "containers": [{
                "name": "web",
                "container": {
                    "image": "nginx",
                    "environment": {"K": "v"},
                    "health": {"cmd": "ok"},
                },
            }],
        }
        result = normalize_containers(config)
        self.assertEqual(result[0]["container"]["environment"], {"K": "v"})
        self.assertEqual(result[0]["container"]["health"], {"cmd": "ok"})

    def test_multi_preserves_sibling_security_storage(self):
        """Fields that are *always* siblings (security, storage, etc.) stay
        sibling-shaped after normalization — only environment/health move."""
        config = {
            "workload": {"name": "x"},
            "containers": [{
                "name": "web",
                "container": {"image": "nginx"},
                "security": {"capabilities": ["NET_ADMIN"]},
                "storage": {"volumes": ["./d:/d"]},
                "network": {"ports": ["8080:80"]},
            }],
        }
        result = normalize_containers(config)
        self.assertEqual(result[0]["security"], {"capabilities": ["NET_ADMIN"]})
        self.assertEqual(result[0]["storage"], {"volumes": ["./d:/d"]})
        self.assertEqual(result[0]["network"], {"ports": ["8080:80"]})


class TestAutoDetectCredentialsMulti(unittest.TestCase):
    def test_multi_container_sibling_env(self):
        """${SECRET:} in [containers.environment] (sibling form) must be
        detected. This is the form the shipped example TOMLs use."""
        config = {
            "containers": [
                {"name": "db",
                 "container": {"image": "postgres"},
                 "environment": {"PW": "${SECRET:db-pw}"}},
                {"name": "web",
                 "container": {"image": "nginx"},
                 "environment": {"K": "${SECRET:api-key}"}},
            ]
        }
        self.assertEqual(
            auto_detect_credentials(config), {"db-pw", "api-key"}
        )

    def test_multi_container_nested_env(self):
        config = {
            "containers": [{
                "name": "web",
                "container": {
                    "image": "nginx",
                    "environment": {"K": "${SECRET:k}"},
                },
            }]
        }
        self.assertEqual(auto_detect_credentials(config), {"k"})

    def test_multi_container_per_container_secrets_files(self):
        config = {
            "containers": [{
                "name": "web",
                "container": {"image": "nginx"},
                "secrets": {"files": [
                    {"credential": "tls-cert", "path": "/etc/cert"}
                ]},
            }]
        }
        self.assertEqual(auto_detect_credentials(config), {"tls-cert"})


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
