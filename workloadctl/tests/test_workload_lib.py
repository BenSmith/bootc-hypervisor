#!/usr/bin/env python3
"""Unit tests for the shared workload library."""

import contextlib
import os
import shutil
import socket
import subprocess
import stat
import tempfile
import threading
import tomllib
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

# Add lib to path for imports

import config_parser
import workload_lib
import vm_network_config
from config_parser import (
    WORKLOADS_BASE, infer_workload_mode, parse_volume_spec,
    ContainerPolicyEntry, container_policy_entries, ContainerCredential,
    container_credential_entries, container_allowed_hosts, ContainerAllowEntry,
    container_allow_entries, container_runs_on_host_network,
    container_uses_inspect, container_allow_resolve,
)
from workload_lib import (
    USERNAME_PREFIX, MAX_NAME_LENGTH, GENERATOR_OWNED_DIRECTIVES,
    workload_username, workload_service_name, workload_container_name,
    workload_home_dir, workload_state_dir, expand_volume_path,
    expand_workload_tokens, dq,
    normalize_containers,
    virtiofs_tag, systemd_escape_path,
    selinux_module_name, selinux_type_name,
    container_tls_mode, container_tls_reason,
    container_ca_delivery, container_ca_mount_path,
    ContainerHostReasonEntry, container_internal_entries, container_splice_entries,
    container_effective_tls_mode, validate_container_network,
    container_allow_resolved,
    container_filter_elements, container_filter_commands,
    container_internal_resolve, container_inspect_policy,
    container_inspect_policy_text,
)
from vm_defs import parse_memory_mib, mac_address, mac_collisions
from validation import (
    validate_workload_name, validate_workload_config,
    valid_userns_mode, collect_config_warnings,
)
from qmp import QMPClient
from secrets_template import (
    SECRET_PATTERN, auto_detect_credentials, resolve_secret_env_vars,
    substitute_template,
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

    def test_rejects_pod_mode_with_single_container(self):
        config = {
            "workload": {"name": "x", "mode": "pod"},
            "container": {"image": "i"},
        }
        errs = validate_workload_config(config)
        self.assertTrue(any("requires [[containers]]" in e for e in errs))

    def test_rejects_bridge_mode_with_single_container(self):
        config = {
            "workload": {"name": "x", "mode": "bridge"},
            "container": {"image": "i"},
        }
        errs = validate_workload_config(config)
        self.assertTrue(any("requires [[containers]]" in e for e in errs))

    def test_rejects_single_mode_with_containers(self):
        config = {
            "workload": {"name": "x", "mode": "single"},
            "containers": [{"name": "a", "container": {"image": "i"}}],
        }
        errs = validate_workload_config(config)
        self.assertTrue(any("incompatible with [[containers]]" in e for e in errs))

    def test_accepts_consistent_explicit_modes(self):
        pod = {
            "workload": {"name": "x", "mode": "pod"},
            "containers": [{"name": "a", "container": {"image": "i"}}],
        }
        self.assertEqual(validate_workload_config(pod), [])
        single = {
            "workload": {"name": "x", "mode": "single"},
            "container": {"image": "i"},
        }
        self.assertEqual(validate_workload_config(single), [])


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


class TestLoadWorkloadConfig(unittest.TestCase):
    """The one loader every boot-time helper now shares.

    Was TestLoadConfig in tests/test_ensure_user.py, back when
    workload-ensure-user had a copy of its own -- moved with the function
    rather than deleted, because the property is the same one.
    """

    def test_parses_the_instance_toml_for_a_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "myapp").mkdir()
            (Path(tmp) / "myapp" / "workload.toml").write_text(
                '[workload]\nname = "myapp"\n')
            with patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", Path(tmp)):
                cfg = workload_lib.load_workload_config("myapp")
        self.assertEqual(cfg["workload"]["name"], "myapp")

    def test_a_config_that_will_not_parse_raises(self):
        # Not caught here on purpose: a helper that cannot read its config has
        # nothing to do but fail, and the two callers that survive a bad config
        # each want their own handling. Swallowing it here would take that
        # choice away from both.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "myapp").mkdir()
            (Path(tmp) / "myapp" / "workload.toml").write_text("not = = toml")
            with patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", Path(tmp)):
                with self.assertRaises(tomllib.TOMLDecodeError):
                    workload_lib.load_workload_config("myapp")

    def test_a_missing_config_raises_oserror(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", Path(tmp)):
                with self.assertRaises(OSError):
                    workload_lib.load_workload_config("absent")


class TestNaming(unittest.TestCase):
    def test_username(self):
        self.assertEqual(workload_username("foo"), "_wl-foo")
        self.assertEqual(workload_username("my-app"), "_wl-my-app")

    def test_service_name(self):
        self.assertEqual(workload_service_name("foo"), "workload-foo.service")

    def test_container_name(self):
        self.assertEqual(workload_container_name("foo"), "workload-foo")

    def test_home_dir(self):
        self.assertEqual(workload_home_dir("foo"), WORKLOADS_BASE / "foo" / "state")


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


class TestVmNetworkValidation(unittest.TestCase):
    """The managed bridge's subnet/DNS are host-level (ADR 002), no longer
    per-VM: [vm.network].subnet/.dns are removed and rejected."""

    def _cfg(self, **network):
        return {"workload": {"name": "v"},
                "vm": {"image": "example/x:latest", "network": network}}

    def _net_errors(self, **network):
        return [e for e in
                vm_network_config.validate_vm_config(self._cfg(**network))
                if "network" in e]

    def test_absent_network_needs_an_egress_decision(self):
        # `egress` defaults to "filtered" and there is no proxy yet to supply
        # the implicit allow, so silence is no longer a complete answer.
        errs = self._net_errors()
        self.assertTrue(any("could reach nothing at all" in e for e in errs))

    def test_bridge_only_still_ok(self):
        # The escape hatch is unfiltered by definition, so it needs no egress
        # decision — there is no host socket carrying the workload uid.
        self.assertEqual(self._net_errors(bridge="br0"), [])

    def test_managed_bridge_subnet_rejected(self):
        # Went with the bridge (ADR 006). Rejected rather than ignored, so an
        # operator carrying an old config learns why it stopped meaning
        # anything instead of finding it silently dropped.
        errs = self._net_errors(subnet="10.100.0.0/24", egress="open")
        self.assertTrue(any("ADR 006" in e for e in errs), errs)

    def test_managed_bridge_dns_rejected(self):
        errs = self._net_errors(dns=["1.1.1.1"], egress="open")
        self.assertTrue(any("ADR 006" in e for e in errs), errs)


class TestSelinuxIdentifiers(unittest.TestCase):
    def test_simple_name(self):
        self.assertEqual(selinux_module_name("alloy"), "wl_alloy")
        # Type is the CIL-namespaced process domain (wl_<name>.process).
        self.assertEqual(selinux_type_name("alloy"), "wl_alloy.process")

    def test_hyphens_become_underscores(self):
        self.assertEqual(selinux_module_name("wayfire-bob"), "wl_wayfire_bob")
        self.assertEqual(selinux_type_name("vncdesktop-wayfire"),
                         "wl_vncdesktop_wayfire.process")

    def test_identifiers_are_selinux_safe(self):
        # The module/block name is a plain identifier; the type adds the CIL
        # namespace separator '.' before the inherited 'process' domain.
        for name in ["alloy", "wayfire-bob", "vncdesktop-labwc", "a1-b2-c3"]:
            self.assertRegex(selinux_module_name(name), r"^[a-zA-Z0-9_]+$")
            self.assertRegex(selinux_type_name(name), r"^[a-zA-Z0-9_]+\.process$")

    def test_sanitize_is_injective(self):
        # NAME_PATTERN forbids underscores, so hyphen->underscore never collides:
        # distinct valid names always map to distinct types.
        names = ["a-b", "ab", "a-b-c", "abc", "x-y", "xy"]
        types = [selinux_type_name(n) for n in names]
        self.assertEqual(len(types), len(set(types)))


class TestExpandVolumePath(unittest.TestCase):
    def setUp(self):
        self.home = str(workload_state_dir("foo"))  # /var/lib/workloads/foo/state

    def test_relative_with_container_path(self):
        result = expand_volume_path("./data:/app/data", self.home)
        self.assertEqual(result, "/var/lib/workloads/foo/data/data:/app/data")

    def test_relative_with_options(self):
        result = expand_volume_path("./conf:/etc/conf:ro", self.home)
        self.assertEqual(result, "/var/lib/workloads/foo/data/conf:/etc/conf:ro")

    def test_absolute_unchanged(self):
        result = expand_volume_path("/srv/data:/app/data", self.home)
        self.assertEqual(result, "/srv/data:/app/data")

    def test_relative_no_container_path(self):
        result = expand_volume_path("./data", self.home)
        self.assertEqual(result, "/var/lib/workloads/foo/data/data")

    def test_absolute_no_container_path(self):
        result = expand_volume_path("/srv/data", self.home)
        self.assertEqual(result, "/srv/data")

    def test_opts_with_colon_preserved(self):
        # opts may itself contain a colon; expansion must keep the full opts
        # field intact (regression: parse used to split unbounded and drop it).
        result = expand_volume_path("./d:/g:ro:context=x", self.home)
        self.assertEqual(result, "/var/lib/workloads/foo/data/d:/g:ro:context=x")

    def test_at_anchor(self):
        result = expand_volume_path("@/cache:/c", self.home)
        self.assertEqual(result, "/var/lib/workloads/foo/state/volumes/cache:/c")

    def test_data_anchor(self):
        result = expand_volume_path("data/x:/x", self.home)
        self.assertEqual(result, "/var/lib/workloads/foo/data/x:/x")

    def test_state_anchor(self):
        result = expand_volume_path("state/x:/x", self.home)
        self.assertEqual(result, "/var/lib/workloads/foo/state/volumes/x:/x")

    def test_traversal_rejected(self):
        with self.assertRaises(ValueError):
            expand_volume_path("./../escape:/x", self.home)


class TestExpandWorkloadTokens(unittest.TestCase):
    def test_instance_dir(self):
        self.assertEqual(
            expand_workload_tokens("seccomp=${WORKLOAD_INSTANCE_DIR}/seccomp.json", "games"),
            "seccomp=/etc/workloads.d/games/seccomp.json")

    def test_all_tokens(self):
        self.assertEqual(
            expand_workload_tokens(
                "${WORKLOAD_NAME}|${WORKLOAD_ROOT_DIR}|"
                "${WORKLOAD_STATE_DIR}|${WORKLOAD_DATA_DIR}", "games"),
            "games|/var/lib/workloads/games|"
            "/var/lib/workloads/games/state|/var/lib/workloads/games/data")

    def test_multiple_occurrences(self):
        self.assertEqual(expand_workload_tokens("${WORKLOAD_NAME}-${WORKLOAD_NAME}", "w"),
                         "w-w")

    def test_value_without_tokens_untouched(self):
        self.assertEqual(expand_workload_tokens("label=disable", "games"), "label=disable")

    def test_non_workload_dollar_braces_untouched(self):
        """Only WORKLOAD_-prefixed names are ours; leave anything else alone."""
        self.assertEqual(expand_workload_tokens("${HOME}/x", "games"), "${HOME}/x")

    def test_unknown_token_raises(self):
        with self.assertRaises(ValueError) as cm:
            expand_workload_tokens("${WORKLOAD_HOME_DIR}/x", "games")
        self.assertIn("WORKLOAD_HOME_DIR", str(cm.exception))

    def test_expands_to_instance_not_bundle(self):
        """The whole point: a bundle instantiated under another name must
        resolve to the instance's paths, never the bundle's."""
        out = expand_workload_tokens("${WORKLOAD_INSTANCE_DIR}/seccomp.json", "games")
        self.assertNotIn("sunshine-streaming", out)


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

    def test_dollar_is_doubled(self):
        # systemd expands $VAR/${VAR} in Exec args after quote removal, so a
        # literal $ must be $$ (B2).
        self.assertEqual(dq("$HOME"), '"$$HOME"')
        self.assertEqual(dq("${FOO}/x"), '"$${FOO}/x"')
        self.assertEqual(dq("price$5"), '"price$$5"')

    def test_percent_is_doubled(self):
        # systemd expands % specifiers at unit load, before quote parsing (B2).
        self.assertEqual(dq("100%"), '"100%%"')
        self.assertEqual(dq("%H/path"), '"%%H/path"')

    def test_single_quote_needs_no_escape_inside_double_quotes(self):
        # The old shlex.quote path emitted shell '"'"' for this; inside systemd
        # double quotes a single quote is literal.
        self.assertEqual(dq("it's"), '"it\'s"')

    def test_combined_specials_all_escaped(self):
        self.assertEqual(dq('a"b\\c$d%e'), '"a\\"b\\\\c$$d%%e"')


class TestSecretPattern(unittest.TestCase):
    def test_matches_simple(self):
        m = SECRET_PATTERN.search("${SECRET:api-key}")
        self.assertIsNotNone(m)
        assert m is not None
        self.assertEqual(m.group(1), "api-key")

    def test_matches_underscore(self):
        m = SECRET_PATTERN.search("${SECRET:my_secret}")
        self.assertIsNotNone(m)
        assert m is not None
        self.assertEqual(m.group(1), "my_secret")

    def test_matches_embedded(self):
        m = SECRET_PATTERN.search("prefix${SECRET:key}suffix")
        self.assertIsNotNone(m)
        assert m is not None
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
        config: dict = {
            "container": {"environment": {"K": "${SECRET:nonexistent}"}}
        }
        with self.assertRaises(FileNotFoundError):
            resolve_secret_env_vars(config, self.creds_dir)

    def test_empty_env(self):
        config: dict = {"container": {"environment": {}}}
        resolved = resolve_secret_env_vars(config, self.creds_dir)
        self.assertEqual(resolved, {})


class TestParseMemoryMib(unittest.TestCase):
    def test_int_passthrough(self):
        self.assertEqual(parse_memory_mib(2048), 2048)

    def test_bare_string(self):
        self.assertEqual(parse_memory_mib("2048"), 2048)

    def test_m_suffix(self):
        self.assertEqual(parse_memory_mib("2048M"), 2048)

    def test_g_suffix(self):
        self.assertEqual(parse_memory_mib("4G"), 4096)

    def test_lowercase_suffix(self):
        # Suffix matching is case-insensitive (upper() is applied internally).
        self.assertEqual(parse_memory_mib("2g"), 2048)

    def test_k_suffix_rounds(self):
        self.assertEqual(parse_memory_mib("2048K"), 2)

    def test_k_suffix_small_value_floors_to_one(self):
        # Sub-MiB values still produce a positive integer so the QEMU memfd
        # backend doesn't get "size=0M".
        self.assertEqual(parse_memory_mib("100K"), 1)

    def test_unknown_suffix_raises(self):
        with self.assertRaises(ValueError):
            parse_memory_mib("2048T")

    def test_empty_string_raises(self):
        with self.assertRaises(ValueError):
            parse_memory_mib("")


class TestVirtiofsTag(unittest.TestCase):
    def test_strips_leading_slash_and_replaces_inner(self):
        self.assertEqual(virtiofs_tag("/mnt/data"), "mnt-data")

    def test_empty_path_falls_back_to_index(self):
        self.assertEqual(virtiofs_tag("", 7), "vol7")
        self.assertEqual(virtiofs_tag("/", 0), "vol0")

    def test_invalid_chars_replaced(self):
        self.assertEqual(virtiofs_tag("/has spaces/and$weird"), "has-spaces-and-weird")

    def test_clipped_to_36_chars(self):
        long_path = "/" + "a" * 50
        tag = virtiofs_tag(long_path)
        self.assertEqual(len(tag), 36)

    def test_stable_across_call_sites(self):
        # The generator and the cloud-init builder must derive identical tags
        # from the same guest path or virtiofs mounts won't match.
        for guest in ("/data", "/var/lib/x", "/srv/share-one"):
            self.assertEqual(virtiofs_tag(guest), virtiofs_tag(guest, 99))


class TestVirtiofsTags(unittest.TestCase):
    """virtiofs_tags() disambiguates tags that collide after sanitize+truncate
    so each volume gets a distinct sidecar unit / chardev tag (B3)."""

    def test_distinct_paths_keep_base_tags(self):
        self.assertEqual(
            workload_lib.virtiofs_tags(["/data:/data", "/logs:/logs"]),
            ["data", "logs"])

    def test_sanitize_collision_is_disambiguated(self):
        # "/a b" and "/a$b" both sanitize to "a-b" — must not collide.
        tags = workload_lib.virtiofs_tags(["/host0:/a b", "/host1:/a$b"])
        self.assertEqual(tags, ["a-b-0", "a-b-1"])
        self.assertEqual(len(set(tags)), 2)

    def test_truncation_collision_is_disambiguated(self):
        # Two long guest paths sharing the first 36 chars collapse to the same
        # truncated tag; the index suffix keeps them unique and within 36 chars.
        base = "/" + "x" * 40
        tags = workload_lib.virtiofs_tags([f"/h0:{base}/one", f"/h1:{base}/two"])
        self.assertEqual(len(set(tags)), 2)
        self.assertTrue(all(len(t) <= 36 for t in tags))

    def test_order_preserved(self):
        tags = workload_lib.virtiofs_tags(["/z:/z", "/a:/a"])
        self.assertEqual(tags, ["z", "a"])

    def test_suffixed_tag_cannot_recollide_with_natural_tag(self):
        # Disambiguating the two "/data" volumes yields "data-1", which must
        # not collide with the third volume's natural "data-1" tag (from
        # "/data/1") — uniqueness is enforced against the final set, not just
        # the base counts.
        tags = workload_lib.virtiofs_tags(
            ["/h1:/data", "/h2:/data", "/h3:/data/1"])
        self.assertEqual(len(set(tags)), 3)
        self.assertEqual(tags[:2], ["data-0", "data-1"])
        self.assertTrue(all(len(t) <= 36 for t in tags))


class TestParseVolumeSpec(unittest.TestCase):
    def test_single_path_defaults_both_sides(self):
        host, guest, opts = parse_volume_spec("/data")
        self.assertEqual((host, guest, opts), ("/data", "/data", "rw"))

    def test_host_and_guest(self):
        host, guest, opts = parse_volume_spec("/host:/guest")
        self.assertEqual((host, guest, opts), ("/host", "/guest", "rw"))

    def test_host_guest_opts(self):
        host, guest, opts = parse_volume_spec("/host:/guest:ro")
        self.assertEqual((host, guest, opts), ("/host", "/guest", "ro"))

    def test_relative_host_path_preserved(self):
        # ./ expansion is the caller's responsibility; the parser leaves it
        # alone so callers can decide what to root it against.
        host, guest, _ = parse_volume_spec("./local:/g")
        self.assertEqual(host, "./local")
        self.assertEqual(guest, "/g")

    def test_opts_may_contain_colon(self):
        # Only the first two ':' delimit fields, so a colon inside opts stays.
        host, guest, opts = parse_volume_spec("/host:/guest:ro:context=foo")
        self.assertEqual((host, guest, opts), ("/host", "/guest", "ro:context=foo"))


class TestSystemdEscapePath(unittest.TestCase):
    """The transform has to match systemd's exactly: an ordering edge on a
    mis-escaped unit name is accepted in silence and orders nothing."""

    def test_plain_path(self):
        self.assertEqual(
            systemd_escape_path("/var/lib/workloads/aj/data/home/netmnt"),
            "var-lib-workloads-aj-data-home-netmnt")

    def test_literal_dash_is_escaped(self):
        # "-" is the separator, so a dash in the path must not survive as one.
        # This is the case that looks right and matches nothing if missed.
        self.assertEqual(systemd_escape_path("/srv/foo-bar"), "srv-foo\\x2dbar")

    def test_trailing_and_leading_slashes_ignored(self):
        self.assertEqual(systemd_escape_path("/srv/data/"),
                         systemd_escape_path("srv/data"))

    def test_root_is_a_single_dash(self):
        self.assertEqual(systemd_escape_path("/"), "-")

    def test_allowed_punctuation_survives(self):
        self.assertEqual(systemd_escape_path("/srv/a.b_c:d"), "srv-a.b_c:d")

    def test_leading_dot_is_escaped(self):
        # Otherwise the unit file name would be hidden.
        self.assertEqual(systemd_escape_path("/.hidden"), "\\x2ehidden")

    def test_other_characters_hex_escape(self):
        self.assertEqual(systemd_escape_path("/srv/a b"), "srv-a\\x20b")

    @unittest.skipIf(shutil.which("systemd-escape") is None,
                     "systemd-escape not available")
    def test_agrees_with_systemd_escape(self):
        for path in ("/var/lib/workloads/aj/data/home/netmnt",
                     "/srv/foo-bar", "/srv/a.b_c:d", "/srv/a b", "/.hidden",
                     "/"):
            with self.subTest(path=path):
                expected = subprocess.run(
                    ["systemd-escape", "--path", path],
                    capture_output=True, text=True, check=True).stdout.strip()
                self.assertEqual(systemd_escape_path(path), expected)


class TestVmMacAddress(unittest.TestCase):
    def test_locally_administered_unicast(self):
        # Bit 1 of the first byte = locally administered; bit 0 = unicast (0).
        mac = mac_address("fedora-vm")
        first = int(mac.split(":")[0], 16)
        self.assertEqual(first & 0x03, 0x02)

    def test_stable_for_same_name(self):
        self.assertEqual(mac_address("a"), mac_address("a"))

    def test_differs_by_name(self):
        self.assertNotEqual(mac_address("a"), mac_address("b"))


class TestValidateVmConfig(unittest.TestCase):
    def _base(self, **vm_overrides):
        vm = {
            "vcpus": 2,
            "memory": "2048M",
            "cloud_image_url": "https://example.com/x.qcow2",
            "cloud_image_checksum": "sha256:" + "a" * 64,
            # Spelled out so these tests assert about images, memory and
            # cloud-init rather than re-testing the egress default; that has
            # its own coverage in TestVmNetworkValidation.
            "network": {"egress": "open"},
        }
        vm.update(vm_overrides)
        return {"workload": {"name": "fedora-vm"}, "vm": vm}

    def test_minimal_valid(self):
        self.assertEqual(validate_workload_config(self._base()), [])

    def test_shipped_example_validates(self):
        # Mirrors docs/examples/example-fedora-vm.toml so a regression in the
        # validator that rejects the example will fail loudly here.
        cfg = {
            "workload": {"name": "example-fedora-vm"},
            "vm": {
                "vcpus": 2,
                "memory": "2048M",
                "cloud_image_url": "https://example.com/Fedora.qcow2",
                "cloud_image_checksum": "sha256:" + "d" * 64,
                "data_disk_size": "50G",
                "user": "fedora",
                "network": {"egress": "open"},
            },
        }
        self.assertEqual(validate_workload_config(cfg), [])

    def test_after_mounts_accepts_absolute_and_anchored_paths(self):
        cfg = self._base(volumes=["./home:/home/ben"],
                         after_mounts=["./home/netmnt", "/srv/nfs", "data/x",
                                       "state/y", "@/z"])
        self.assertEqual(validate_workload_config(cfg), [])

    def test_after_mounts_rejects_a_bare_relative_path(self):
        # It would be expanded against the workload home and yield an ordering
        # edge on a plausible unit name that names no mount -- which systemd
        # accepts silently, so the operator gets no ordering and no error.
        errs = validate_workload_config(self._base(after_mounts=["home/netmnt"]))
        self.assertTrue(any("after_mounts" in e for e in errs), errs)

    def test_after_mounts_must_be_a_list_of_non_empty_strings(self):
        for bad in ("/srv/nfs", [""], [7]):
            with self.subTest(bad=bad):
                errs = validate_workload_config(self._base(after_mounts=bad))
                self.assertTrue(any("after_mounts" in e for e in errs), errs)

    def test_announce_submounts_must_be_boolean(self):
        self.assertEqual(
            validate_workload_config(self._base(announce_submounts=True)), [])
        errs = validate_workload_config(self._base(announce_submounts="yes"))
        self.assertTrue(any("announce_submounts" in e for e in errs), errs)

    def test_memory_in_qemu_notation_accepted(self):
        for mem in ("2048", "2048M", "4G", 2048):
            cfg = self._base(memory=mem)
            self.assertEqual(validate_workload_config(cfg), [],
                             msg=f"memory={mem!r} should validate")

    def test_memory_too_small_rejected(self):
        errs = validate_workload_config(self._base(memory="64M"))
        self.assertTrue(any("at least 256" in e for e in errs), errs)

    def test_memory_garbage_rejected(self):
        errs = validate_workload_config(self._base(memory="lots"))
        self.assertTrue(any("QEMU notation" in e for e in errs), errs)

    def test_mutually_exclusive_with_container(self):
        cfg = self._base()
        cfg["container"] = {"image": "nginx"}
        errs = validate_workload_config(cfg)
        self.assertTrue(any("mutually exclusive" in e for e in errs), errs)

    def test_requires_an_image_source(self):
        cfg = {"workload": {"name": "x"}, "vm": {"vcpus": 1, "memory": "512M"}}
        errs = validate_workload_config(cfg)
        self.assertTrue(any("exactly one image source" in e for e in errs), errs)

    def test_rejects_multiple_image_sources(self):
        cfg = self._base(local_image="/path/x.qcow2")
        errs = validate_workload_config(cfg)
        self.assertTrue(any("exactly one image source" in e for e in errs), errs)

    def test_cloud_image_url_requires_checksum(self):
        cfg = self._base()
        del cfg["vm"]["cloud_image_checksum"]
        errs = validate_workload_config(cfg)
        self.assertTrue(any("cloud_image_checksum is required" in e for e in errs), errs)

    def test_checksum_must_be_sha256(self):
        errs = validate_workload_config(self._base(cloud_image_checksum="md5:abcd"))
        self.assertTrue(any("sha256:" in e for e in errs), errs)

    def test_vcpus_must_be_positive_int(self):
        for bad in (0, -1, 1.5, "two"):
            errs = validate_workload_config(self._base(vcpus=bad))
            self.assertTrue(any("vcpus" in e for e in errs),
                            msg=f"vcpus={bad!r} should be rejected, got {errs}")

    def test_rollback_keep_must_be_positive_int(self):
        for bad in (0, -1, "two"):
            errs = validate_workload_config(self._base(rollback_keep=bad))
            self.assertTrue(any("rollback_keep" in e for e in errs),
                            msg=f"rollback_keep={bad!r} should be rejected")

    def test_local_image_alone_is_valid(self):
        cfg = {
            "workload": {"name": "x"},
            "vm": {"vcpus": 1, "memory": "512M", "local_image": "/srv/i.qcow2",
                   "network": {"egress": "open"}},
        }
        self.assertEqual(validate_workload_config(cfg), [])

    def test_restart_rejects_unknown_value(self):
        errs = validate_workload_config(self._base(restart="sometimes"))
        self.assertTrue(any("restart" in e for e in errs), errs)

    def test_restart_accepts_known_values(self):
        for val in ("always", "on-failure", "on-reboot"):
            errs = validate_workload_config(self._base(restart=val))
            self.assertFalse(any("restart" in e for e in errs),
                             msg=f"restart={val!r} should be accepted, got {errs}")


class TestVmNetworkBridge(unittest.TestCase):
    def _base(self, **network):
        return {
            "workload": {"name": "fedora-vm"},
            "vm": {
                "vcpus": 1,
                "memory": "512M",
                "local_image": "/srv/x.qcow2",
                "network": network,
            },
        }

    def test_default_bridge_when_section_omitted(self):
        cfg = {
            "workload": {"name": "fedora-vm"},
            "vm": {"vcpus": 1, "memory": "512M", "local_image": "/srv/x.qcow2",
                   "network": {"egress": "open"}},
        }
        self.assertEqual(validate_workload_config(cfg), [])

    def test_custom_bridge_accepted(self):
        self.assertEqual(validate_workload_config(self._base(bridge="br0")), [])

    def test_bridge_must_be_non_empty_string(self):
        for bad in ("", None, 42):
            errs = validate_workload_config(self._base(bridge=bad))
            self.assertTrue(any("bridge" in e for e in errs),
                            msg=f"bridge={bad!r} should be rejected, got {errs}")

    def test_bridge_too_long_rejected(self):
        errs = validate_workload_config(self._base(bridge="x" * 16))
        self.assertTrue(any("valid interface name" in e for e in errs), errs)

    def test_bridge_invalid_charset_rejected(self):
        for bad in ("br0!", "br 0", "br0/x", "br0.lan"):
            errs = validate_workload_config(self._base(bridge=bad))
            self.assertTrue(any("valid interface name" in e for e in errs),
                            msg=f"bridge={bad!r} should be rejected")


class TestVmCloudInit(unittest.TestCase):
    def _base(self, **cloud_init):
        return {
            "workload": {"name": "fedora-vm"},
            "vm": {
                "vcpus": 1,
                "memory": "512M",
                "local_image": "/srv/x.qcow2",
                "network": {"egress": "open"},
                "cloud_init": cloud_init,
            },
        }

    def test_empty_cloud_init_accepted(self):
        self.assertEqual(validate_workload_config(self._base()), [])

    def test_user_data_file_string_accepted(self):
        cfg = self._base(user_data_file="./cloud-init/user-data")
        self.assertEqual(validate_workload_config(cfg), [])

    def test_user_data_file_non_string_rejected(self):
        errs = validate_workload_config(self._base(user_data_file=42))
        self.assertTrue(any("user_data_file" in e for e in errs), errs)

    def test_template_vars_must_be_table(self):
        errs = validate_workload_config(self._base(template_vars="not a table"))
        self.assertTrue(any("template_vars must be a table" in e for e in errs), errs)

    def test_template_vars_scalars_accepted(self):
        cfg = self._base(template_vars={"REPO": "x", "PORT": 8080, "DEBUG": True, "RATIO": 1.5})
        self.assertEqual(validate_workload_config(cfg), [])

    def test_template_vars_non_scalar_rejected(self):
        errs = validate_workload_config(self._base(template_vars={"NESTED": {"a": 1}}))
        self.assertTrue(any("must be a scalar" in e for e in errs), errs)

    def test_template_vars_list_rejected(self):
        errs = validate_workload_config(self._base(template_vars={"LIST": [1, 2, 3]}))
        self.assertTrue(any("must be a scalar" in e for e in errs), errs)

    def test_seed_provides_known_values_accepted(self):
        cfg = self._base(seed_provides=["ca", "mounts"])
        self.assertEqual(validate_workload_config(cfg), [])

    def test_seed_provides_proxy_is_refused_and_names_its_replacement(self):
        """The retired entry is not merely dropped from the accepted set.

        A seed that still declares it DOES provide something -- the concern it
        provides was renamed under the operator -- so the generic
        "unknown entries" message would send them hunting a typo they did not
        make. The message has to name the replacement, or a custom seed declines
        a CA it was never offered.
        """
        errs = validate_workload_config(self._base(seed_provides=["proxy"]))
        self.assertEqual(len(errs), 1, errs)
        self.assertIn("proxy", errs[0])
        self.assertIn("'ca'", errs[0])
        # And not ALSO reported as unknown: one entry, one error.
        self.assertNotIn("unknown entries", errs[0])

    def test_seed_provides_unknown_value_rejected(self):
        """A typo'd opt-out would silently disable a seed-completeness check —
        the exact silence the check exists to prevent — so it is a hard error
        rather than an ignored key."""
        errs = validate_workload_config(self._base(seed_provides=["proxies"]))
        self.assertTrue(any("seed_provides" in e and "proxies" in e
                            for e in errs), errs)

    def test_seed_provides_must_be_list_of_strings(self):
        errs = validate_workload_config(self._base(seed_provides="proxy"))
        self.assertTrue(any("seed_provides must be a list" in e for e in errs), errs)


class TestSubstituteTemplate(unittest.TestCase):
    def test_substitutes_template_var(self):
        out = substitute_template("hello ${NAME}", template_vars={"NAME": "world"})
        self.assertEqual(out, "hello world")

    def test_template_var_coerces_to_string(self):
        out = substitute_template("port=${PORT}", template_vars={"PORT": 8080})
        self.assertEqual(out, "port=8080")

    def test_template_vars_take_precedence_over_env(self):
        out = substitute_template(
            "${X}",
            template_vars={"X": "from-template"},
            env={"X": "from-env"},
        )
        self.assertEqual(out, "from-template")

    def test_falls_back_to_env(self):
        out = substitute_template("${HOME}", env={"HOME": "/srv"})
        self.assertEqual(out, "/srv")

    def test_missing_var_raises_keyerror(self):
        with self.assertRaises(KeyError):
            substitute_template("hi ${MISSING}")

    def test_secret_uses_resolver(self):
        seen = []
        def resolver(name):
            seen.append(name)
            return "s3cr3t"
        out = substitute_template("token=${SECRET:api-token}", secret_resolver=resolver)
        self.assertEqual(out, "token=s3cr3t")
        self.assertEqual(seen, ["api-token"])

    def test_secret_without_resolver_raises(self):
        with self.assertRaises(KeyError):
            substitute_template("token=${SECRET:foo}")

    def test_dollar_dollar_collapses(self):
        # Escape mechanism so user-data can contain a literal `${shellvar}`.
        out = substitute_template("price is $$5", template_vars={})
        self.assertEqual(out, "price is $5")

    def test_dollar_dollar_escapes_var_pattern(self):
        # `$${HOME}` should not be substituted; it becomes the literal `${HOME}`.
        out = substitute_template("$${HOME}", env={"HOME": "/nope"})
        self.assertEqual(out, "${HOME}")

    def test_dollar_dollar_escapes_required_secret(self):
        # Regression: `$${SECRET:name}` must escape to a literal, NOT trigger a
        # secret lookup. Before the SECRET branches gained the (?<!\$) lookbehind,
        # this matched and resolved "name" — aborting on a missing credential
        # (the bug the scratch-VM cloud-init comment tripped at enable time).
        called = []
        def resolver(name):
            called.append(name)
            return "LEAK"
        out = substitute_template(
            "$${SECRET:name}", secret_resolver=resolver,
        )
        self.assertEqual(out, "${SECRET:name}")
        self.assertEqual(called, [])  # resolver must never run for an escaped ref

    def test_dollar_dollar_escapes_optional_secret(self):
        # `$${SECRET?name}` must escape to a literal too, not be swallowed to "".
        called = []
        def resolver(name):
            called.append(name)
            return "LEAK"
        out = substitute_template(
            "$${SECRET?name}", secret_resolver=resolver,
        )
        self.assertEqual(out, "${SECRET?name}")
        self.assertEqual(called, [])

    def test_dollar_dollar_escapes_secret_without_resolver(self):
        # The escaped required form must not raise even with no resolver — it's
        # a literal, so the missing-resolver KeyError path is never reached.
        out = substitute_template("$${SECRET:name}")
        self.assertEqual(out, "${SECRET:name}")

    def test_multiple_vars_and_secrets(self):
        out = substitute_template(
            "user=${USER} pw=${SECRET:pw} home=${HOME}",
            template_vars={"USER": "alice"},
            env={"HOME": "/h/alice"},
            secret_resolver=lambda n: "hunter2",
        )
        self.assertEqual(out, "user=alice pw=hunter2 home=/h/alice")

    def test_empty_input_passthrough(self):
        self.assertEqual(substitute_template(""), "")

    def test_no_placeholders_passthrough(self):
        self.assertEqual(substitute_template("plain text"), "plain text")

    def test_optional_secret_resolved(self):
        out = substitute_template(
            "tok='${SECRET?api}'",
            secret_resolver=lambda n: "REALVALUE",
        )
        self.assertEqual(out, "tok='REALVALUE'")

    def test_optional_secret_missing_returns_empty(self):
        def resolver(name):
            raise FileNotFoundError(name)
        out = substitute_template(
            "tok='${SECRET?api}'",
            secret_resolver=resolver,
        )
        self.assertEqual(out, "tok=''")

    def test_optional_secret_missing_keyerror_returns_empty(self):
        def resolver(name):
            raise KeyError(name)
        out = substitute_template(
            "tok='${SECRET?api}'",
            secret_resolver=resolver,
        )
        self.assertEqual(out, "tok=''")

    def test_optional_secret_without_resolver_returns_empty(self):
        # No resolver configured at all — the optional form must NOT raise
        # (that's the whole point); it just substitutes empty.
        out = substitute_template("tok='${SECRET?api}'")
        self.assertEqual(out, "tok=''")

    def test_optional_and_required_secret_coexist(self):
        seen = []
        def resolver(name):
            seen.append(name)
            if name == "missing":
                raise FileNotFoundError(name)
            return f"VAL-{name}"
        out = substitute_template(
            "req=${SECRET:present} opt=${SECRET?missing}",
            secret_resolver=resolver,
        )
        self.assertEqual(out, "req=VAL-present opt=")
        self.assertEqual(sorted(seen), ["missing", "present"])

    def test_optional_secret_does_not_match_required_form(self):
        # ${SECRET:name} must still go through the required path even when
        # ${SECRET?...} is also present in the same template.
        with self.assertRaises(KeyError):
            substitute_template("req=${SECRET:x} opt=${SECRET?y}")


class TestConstants(unittest.TestCase):
    def test_username_prefix(self):
        self.assertEqual(USERNAME_PREFIX, "_wl-")

    def test_max_name_length_fits_username(self):
        # _wl- (4 chars) + max name + null = 32 (LOGIN_NAME_MAX)
        self.assertEqual(len(USERNAME_PREFIX) + MAX_NAME_LENGTH + 1, 32)

    def test_generator_owned_directives_is_frozenset(self):
        self.assertIsInstance(GENERATOR_OWNED_DIRECTIVES, frozenset)
        self.assertIn("ExecStart", GENERATOR_OWNED_DIRECTIVES)


class TestQMPClient(unittest.TestCase):
    """Exercise the shared QMP client against a fake QEMU monitor socket."""

    def _serve_once(self, sock_path, reply_frames):
        """Accept one client: send greeting, ack qmp_capabilities, then send
        `reply_frames` (raw bytes) after reading the command. Returns the thread.
        """
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(sock_path))
        srv.listen(1)
        self.addCleanup(srv.close)

        def serve():
            conn, _ = srv.accept()
            with conn:
                conn.sendall(b'{"QMP": {"version": {}, "capabilities": []}}\n')
                conn.recv(4096)  # qmp_capabilities
                conn.sendall(b'{"return": {}}\n')
                conn.recv(4096)  # the command
                conn.sendall(reply_frames)
                conn.recv(4096)  # wait for client to close

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        return t

    def test_execute_skips_async_events_before_reply(self):
        # A QMP async event arriving before the command's reply must be drained,
        # not mistaken for the reply (the property all four call sites rely on).
        tmp = Path(tempfile.mkdtemp())
        sock_path = tmp / "qmp.sock"
        self._serve_once(
            sock_path,
            b'{"event": "RESUME"}\n'
            b'{"return": {"status": "running", "running": true}}\n',
        )
        qmp = QMPClient()
        try:
            qmp.connect(sock_path, timeout=2.0, recv_timeout=2.0)
            qmp.negotiate()
            reply = qmp.execute("query-status")
        finally:
            qmp.close()
        self.assertEqual(reply["return"]["status"], "running")
        self.assertTrue(reply["return"]["running"])

    def test_connect_times_out_when_socket_absent(self):
        missing = Path(tempfile.mkdtemp()) / "nope.sock"
        qmp = QMPClient()
        # Each retry must close its socket: a leaked fd raises ResourceWarning
        # (promoted to an error here) when GC'd.
        with warnings.catch_warnings():
            warnings.simplefilter("error", ResourceWarning)
            with self.assertRaises(TimeoutError):
                qmp.connect(missing, timeout=0.3, recv_timeout=0.3)

    def test_readline_raises_connectionerror_when_peer_closes(self):
        # If the monitor dies mid-negotiate (closes without acking
        # qmp_capabilities), the reader must not loop forever on an empty
        # recv() — it must surface a clear ConnectionError.
        tmp = Path(tempfile.mkdtemp())
        sock_path = tmp / "qmp.sock"
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(sock_path))
        srv.listen(1)
        self.addCleanup(srv.close)

        def serve():
            conn, _ = srv.accept()
            with conn:
                conn.sendall(b'{"QMP": {"version": {}, "capabilities": []}}\n')
                conn.recv(4096)  # qmp_capabilities
                # Close without sending the ack.

        t = threading.Thread(target=serve, daemon=True)
        t.start()

        qmp = QMPClient()
        try:
            qmp.connect(sock_path, timeout=2.0, recv_timeout=2.0)
            with self.assertRaises(ConnectionError):
                qmp.negotiate()
        finally:
            qmp.close()

    def test_execute_raises_connectionerror_after_max_events(self):
        # A reply that never arrives (or arrives after more async events than
        # max_events allows) must not hang execute() forever.
        tmp = Path(tempfile.mkdtemp())
        sock_path = tmp / "qmp.sock"
        self._serve_once(
            sock_path,
            b'{"event": "A"}\n{"event": "B"}\n{"event": "C"}\n',
        )
        qmp = QMPClient()
        try:
            qmp.connect(sock_path, timeout=2.0, recv_timeout=2.0)
            qmp.negotiate()
            with self.assertRaises(ConnectionError) as ctx:
                qmp.execute("query-status", max_events=3)
        finally:
            qmp.close()
        self.assertIn("no QMP reply", str(ctx.exception))

    def test_context_manager_closes_socket_on_exit(self):
        tmp = Path(tempfile.mkdtemp())
        sock_path = tmp / "qmp.sock"
        self._serve_once(sock_path, b'{"return": {}}\n')
        with QMPClient() as qmp:
            qmp.connect(sock_path, timeout=2.0, recv_timeout=2.0)
            qmp.negotiate()
            qmp.execute("query-status")
            self.assertIsNotNone(qmp._sock)
        self.assertIsNone(qmp._sock)


class TestGetNextUid(unittest.TestCase):
    """get_next_uid() assigns each workload's dedicated system UID — a
    collision here breaks the per-workload isolation model, so the scan and
    exhaustion logic (never exercised elsewhere; callers always mock this
    function outright) needs direct coverage."""

    def setUp(self):
        # get_next_uid() now flocks SUBID_LOCK (/run/lock, root-only); stub the
        # lock so these tests exercise only the UID-scan math. Real reentrant
        # locking is covered by TestSubidLock.
        self.enterContext(
            patch.object(workload_lib, "subid_lock", contextlib.nullcontext)
        )
        # It also unions in UIDs pinned in /run sysusers configs; stub that to
        # empty so the passwd/allocated math is tested in isolation (the scan
        # itself is covered by TestReservedUidsInPendingSysusers).
        self.enterContext(
            patch.object(
                workload_lib, "_reserved_uids_in_pending_sysusers",
                return_value=set(),
            )
        )

    def _pw(self, uid):
        import types
        return types.SimpleNamespace(pw_uid=uid)

    def test_returns_uid_min_when_nothing_allocated(self):
        with patch.object(workload_lib, '_allocated_uids', set()), \
             patch.object(workload_lib.pwd, 'getpwall', return_value=[]):
            uid = workload_lib.get_next_uid()
        self.assertEqual(uid, workload_lib.UID_MIN)

    def test_skips_uids_in_live_passwd_and_already_allocated(self):
        live = [self._pw(workload_lib.UID_MIN)]
        with patch.object(workload_lib, '_allocated_uids', {workload_lib.UID_MIN + 1}), \
             patch.object(workload_lib.pwd, 'getpwall', return_value=live):
            uid = workload_lib.get_next_uid()
        self.assertEqual(uid, workload_lib.UID_MIN + 2)

    def test_second_call_does_not_reuse_uid_from_first(self):
        # Two calls within the same process (no /etc/passwd entry written
        # yet in between) must not hand out the same slot twice.
        with patch.object(workload_lib, '_allocated_uids', set()), \
             patch.object(workload_lib.pwd, 'getpwall', return_value=[]):
            first = workload_lib.get_next_uid()
            second = workload_lib.get_next_uid()
        self.assertNotEqual(first, second)

    def test_getpwall_failure_falls_back_to_allocated_set_only(self):
        with patch.object(workload_lib, '_allocated_uids', set()), \
             patch.object(workload_lib.pwd, 'getpwall', side_effect=OSError("boom")):
            uid = workload_lib.get_next_uid()
        self.assertEqual(uid, workload_lib.UID_MIN)

    def test_raises_runtime_error_when_range_exhausted(self):
        with patch.object(workload_lib, 'UID_MIN', 10000), \
             patch.object(workload_lib, 'UID_MAX', 10000), \
             patch.object(workload_lib, '_allocated_uids', set()), \
             patch.object(workload_lib.pwd, 'getpwall', return_value=[self._pw(10000)]):
            with self.assertRaises(RuntimeError) as ctx:
                workload_lib.get_next_uid()
        self.assertIn("No free UIDs", str(ctx.exception))


class TestClaimUid(unittest.TestCase):
    """claim_uid() adopts the UID that owns a workload's pre-existing /var tree.

    The case this exists for: boot an older bootc deployment and _wl-<name> is
    gone from /etc/passwd while /var/lib/workloads/<name> survives, owned by the
    old UID. Because the subordinate range is *derived* from the UID, a fresh
    allocation re-points it onto a tree owned by the old one — and ensure-user
    chowns only the tops of state/ and data/, so the workload comes up unable to
    read its own data. Silent at enable time, which is what makes it worth a
    dedicated allocator rather than a doctor check.
    """

    def setUp(self):
        self.enterContext(
            patch.object(workload_lib, "subid_lock", contextlib.nullcontext)
        )
        self.enterContext(
            patch.object(
                workload_lib, "_reserved_uids_in_pending_sysusers",
                return_value=set(),
            )
        )
        self.enterContext(patch.object(workload_lib, "_allocated_uids", set()))
        self.enterContext(
            patch.object(workload_lib.pwd, "getpwall", return_value=[])
        )
        self.base = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(
            patch.object(config_parser, "WORKLOADS_BASE", self.base)
        )

    def _pw(self, uid):
        import types
        return types.SimpleNamespace(pw_uid=uid)

    def _make_state(self, name, uid, subdir="data"):
        """Create <base>/<name>/<subdir> reporting `uid` as its owner.

        st_uid is faked rather than chowned: these run unprivileged, and the only
        thing under test is what claim_uid does with the number.
        """
        d = self.base / name / subdir
        d.mkdir(parents=True)
        real_stat = Path.stat

        def fake_stat(self, *a, **kw):
            st = real_stat(self, *a, **kw)
            if self == d:
                return os.stat_result(
                    (st.st_mode, st.st_ino, st.st_dev, st.st_nlink, uid,
                     st.st_gid, st.st_size, int(st.st_atime), int(st.st_mtime),
                     int(st.st_ctime)))
            return st

        self.enterContext(patch.object(Path, "stat", fake_stat))

    def test_no_state_dir_allocates_fresh(self):
        uid, why = workload_lib.claim_uid("newbie")
        self.assertEqual((uid, why), (workload_lib.UID_MIN, "fresh"))

    def test_adopts_the_uid_owning_an_existing_data_dir(self):
        # The whole point: not UID_MIN, which is what a fresh allocation gives.
        self._make_state("rolled-back", workload_lib.UID_MIN + 5)
        uid, why = workload_lib.claim_uid("rolled-back")
        self.assertEqual((uid, why), (workload_lib.UID_MIN + 5, "adopted"))

    def test_adopts_from_state_dir_when_data_dir_is_absent(self):
        self._make_state("vmish", workload_lib.UID_MIN + 7, subdir="state")
        uid, why = workload_lib.claim_uid("vmish")
        self.assertEqual((uid, why), (workload_lib.UID_MIN + 7, "adopted"))

    def test_root_owned_state_is_not_adoptable(self):
        # The root above data/ and state/ may legitimately stay root-owned, and
        # a root-owned data/ is not a workload's UID to adopt.
        self._make_state("freshly-made", 0)
        uid, why = workload_lib.claim_uid("freshly-made")
        self.assertEqual((uid, why), (workload_lib.UID_MIN, "fresh"))

    def test_reports_collision_when_the_old_uid_now_belongs_to_someone_else(self):
        """The one case nothing here can repair: the derived range is gone, so
        the tree is stranded and the caller has to say so out loud."""
        taken = workload_lib.UID_MIN + 3
        self._make_state("stranded", taken)
        with patch.object(workload_lib.pwd, "getpwall",
                          return_value=[self._pw(taken)]):
            uid, why = workload_lib.claim_uid("stranded")
        self.assertEqual(why, "collision")
        self.assertNotEqual(uid, taken)

    def test_an_adopted_uid_is_not_handed_out_again_in_the_same_run(self):
        """An out-of-sequence adoption has to enter the allocated set, or the
        next workload in the same generator pass gets the same slot."""
        self._make_state("adopter", workload_lib.UID_MIN)
        adopted, why = workload_lib.claim_uid("adopter")
        self.assertEqual(why, "adopted")
        self.assertNotEqual(workload_lib.claim_uid("other")[0], adopted)

    def test_unreadable_var_is_treated_as_absent(self):
        with patch.object(Path, "stat", side_effect=PermissionError("nope")):
            self.assertIsNone(workload_lib.state_owner_uid("whatever"))


class TestReservedUidsInPendingSysusers(unittest.TestCase):
    """Pending sysusers configs are the only record of a UID that's been handed
    out but not yet written to /etc/passwd (generator defers user creation to
    the workload's setup service). get_next_uid() must treat those as taken, or
    a concurrent allocator re-hands-out the slot — collapsing per-workload
    isolation onto a shared UID."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.run_systemd = self.tmp / "systemd-system"
        self.sysusers_d = self.tmp / "sysusers.d"
        self.run_systemd.mkdir()
        self.sysusers_d.mkdir()
        self.enterContext(
            patch.object(workload_lib, "RUN_SYSTEMD_SYSTEM", self.run_systemd)
        )
        self.enterContext(
            patch.object(workload_lib, "RUN_SYSUSERS_D", self.sysusers_d)
        )

    def _write(self, d, name, body):
        (d / name).write_text(body)

    def test_parses_uid_from_both_dirs(self):
        self._write(
            self.run_systemd, "workload-alpha.conf",
            'u _wl-alpha 10005 "alpha workload" /var/lib/x\n',
        )
        self._write(
            self.sysusers_d, "workload-beta.conf",
            'u _wl-beta 10007 "beta workload" /var/lib/y\nm _wl-beta kvm\n',
        )
        self.assertEqual(
            workload_lib._reserved_uids_in_pending_sysusers(), {10005, 10007}
        )

    def test_ignores_non_user_lines_and_junk(self):
        self._write(
            self.run_systemd, "workload-gamma.conf",
            "# comment\nm _wl-gamma render\nu _wl-gamma notanint /home\n",
        )
        self.assertEqual(
            workload_lib._reserved_uids_in_pending_sysusers(), set()
        )

    def test_missing_dir_is_tolerated(self):
        import shutil
        shutil.rmtree(self.sysusers_d)
        self._write(
            self.run_systemd, "workload-delta.conf",
            'u _wl-delta 10009 "d" /home\n',
        )
        self.assertEqual(
            workload_lib._reserved_uids_in_pending_sysusers(), {10009}
        )

    def test_get_next_uid_skips_pinned_but_uncreated_uid(self):
        # UID_MIN is pinned in a pending conf but absent from passwd — the exact
        # allocate-then-create window. get_next_uid must skip it.
        self._write(
            self.run_systemd, "workload-eps.conf",
            f'u _wl-eps {workload_lib.UID_MIN} "e" /home\n',
        )
        with patch.object(workload_lib, "subid_lock", contextlib.nullcontext), \
             patch.object(workload_lib, "_allocated_uids", set()), \
             patch.object(workload_lib.pwd, "getpwall", return_value=[]):
            uid = workload_lib.get_next_uid()
        self.assertEqual(uid, workload_lib.UID_MIN + 1)


class TestSubidLock(unittest.TestCase):
    """subid_lock() serializes UID/subid allocation across processes and is
    reentrant within one so the enable path (which holds it across the sysusers
    write) can call get_next_uid() — itself now locked — without deadlocking."""

    def setUp(self):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        # Point the flock at a writable path so the test runs unprivileged.
        self.enterContext(
            patch.object(workload_lib, "SUBID_LOCK", tmp / "subid.lock")
        )
        # Reset reentrancy globals in case a prior test left them dirty.
        self.enterContext(patch.object(workload_lib, "_subid_lock_fd", None))
        self.enterContext(patch.object(workload_lib, "_subid_lock_depth", 0))

    def test_reentrant_acquire_does_not_deadlock(self):
        with workload_lib.subid_lock():
            self.assertEqual(workload_lib._subid_lock_depth, 1)
            with workload_lib.subid_lock():  # nested acquire, same process
                self.assertEqual(workload_lib._subid_lock_depth, 2)
            # inner release must NOT drop the underlying flock yet
            self.assertEqual(workload_lib._subid_lock_depth, 1)
            self.assertIsNotNone(workload_lib._subid_lock_fd)
        self.assertEqual(workload_lib._subid_lock_depth, 0)
        self.assertIsNone(workload_lib._subid_lock_fd)

    def test_held_lock_blocks_a_separate_fd(self):
        # A distinct open file description competes with the held lock (the
        # exact same-process collision that forces reentrancy on one cached
        # fd): a non-blocking grab on a second fd must fail while it's held,
        # and succeed once released — proving the flock actually mutexes.
        import fcntl

        with workload_lib.subid_lock():
            other = open(workload_lib.SUBID_LOCK, "w")
            try:
                with self.assertRaises(OSError):
                    fcntl.flock(other.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                other.close()

        released = open(workload_lib.SUBID_LOCK, "w")
        try:
            fcntl.flock(released.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(released.fileno(), fcntl.LOCK_UN)
        finally:
            released.close()

    def test_permission_error_degrades_to_unlocked(self):
        # An unprivileged caller can't open the root-owned lock; the body must
        # still run (fd stays None = unlocked) with reentrancy state balanced.
        with patch("builtins.open", side_effect=PermissionError("denied")):
            with workload_lib.subid_lock():
                self.assertEqual(workload_lib._subid_lock_depth, 1)
                self.assertIsNone(workload_lib._subid_lock_fd)
        self.assertEqual(workload_lib._subid_lock_depth, 0)
        self.assertIsNone(workload_lib._subid_lock_fd)

    def test_non_permission_oserror_propagates_and_cleans_up(self):
        # A real fault (not a permission denial) must NOT silently degrade to an
        # unlocked allocation — it propagates, and leaves no leaked fd or dirty
        # reentrancy depth behind.
        with patch("builtins.open", side_effect=OSError("I/O error")):
            with self.assertRaises(OSError):
                with workload_lib.subid_lock():
                    self.fail("body must not run when acquire raises")
        self.assertEqual(workload_lib._subid_lock_depth, 0)
        self.assertIsNone(workload_lib._subid_lock_fd)


class TestUnitsOutdated(unittest.TestCase):
    """units_outdated(): config-edited-since-enable mtime heads-up (gotcha #3)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.cfgdir = root / "etc"
        self.rundir = root / "run"
        (self.cfgdir / "foo").mkdir(parents=True)
        self.rundir.mkdir(parents=True)
        self._patches = [
            patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.cfgdir),
            patch.object(workload_lib, "RUN_SYSTEMD_SYSTEM", self.rundir),
        ]
        for p in self._patches:
            p.start()
        self.cfg = self.cfgdir / "foo" / "workload.toml"
        self.unit = self.rundir / "workload-foo.service"

    def tearDown(self):
        for p in self._patches:
            p.stop()
        self._tmp.cleanup()

    def test_false_when_unit_missing(self):
        self.cfg.write_text("x")
        self.assertFalse(workload_lib.units_outdated("foo"))

    def test_false_when_config_missing(self):
        self.unit.write_text("x")
        self.assertFalse(workload_lib.units_outdated("foo"))

    def test_false_when_unit_newer(self):
        self.cfg.write_text("x")
        os.utime(self.cfg, (1000, 1000))
        self.unit.write_text("x")
        os.utime(self.unit, (2000, 2000))
        self.assertFalse(workload_lib.units_outdated("foo"))

    def test_true_when_config_newer(self):
        self.unit.write_text("x")
        os.utime(self.unit, (1000, 1000))
        self.cfg.write_text("x")
        os.utime(self.cfg, (2000, 2000))
        self.assertTrue(workload_lib.units_outdated("foo"))

    def test_slack_swallows_same_second_enable(self):
        # enable writes both within the same second — must not flag stale.
        self.unit.write_text("x")
        os.utime(self.unit, (1000.0, 1000.0))
        self.cfg.write_text("x")
        os.utime(self.cfg, (1000.4, 1000.4))
        self.assertFalse(workload_lib.units_outdated("foo"))


class TestUnitsFromOtherBuild(unittest.TestCase):
    """units_from_other_build(): the *software* moved under the units.

    The companion to units_outdated(). An RPM upgrade rewrites the generator
    without touching either the TOML's or the unit's mtime, so the mtime check
    cannot see it; only the stamp the generator writes into the unit can.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.rundir = Path(self._tmp.name) / "run"
        self.rundir.mkdir(parents=True)
        p = patch.object(workload_lib, "RUN_SYSTEMD_SYSTEM", self.rundir)
        p.start()
        self.addCleanup(p.stop)
        self.unit = self.rundir / "workload-foo.service"

    def _write(self, stamp_line):
        self.unit.write_text(
            f"# foo rootless workload\n{stamp_line}\n\n[Unit]\nDescription=foo\n"
        )

    def test_same_build_is_not_reported(self):
        self._write(f"# Generated by workload-generate ({workload_lib.WORKLOADCTL_VERSION})")
        self.assertIsNone(workload_lib.units_from_other_build("foo"))

    def test_other_build_returns_the_stamped_version(self):
        self._write("# Generated by workload-generate (0.1.0-1.20250101000000)")
        self.assertEqual(
            workload_lib.units_from_other_build("foo"), "0.1.0-1.20250101000000"
        )

    def test_unstamped_unit_is_reported(self):
        # Written by a workloadctl older than the stamp itself — the one upgrade
        # every existing host makes exactly once, so it must not read as "fine".
        self._write("# Generated by workload-generate")
        self.assertEqual(
            workload_lib.units_from_other_build("foo"), workload_lib.UNSTAMPED_BUILD
        )

    def test_missing_unit_says_nothing(self):
        self.assertIsNone(workload_lib.units_from_other_build("foo"))

    def test_file_the_generator_did_not_write_says_nothing(self):
        self.unit.write_text("[Unit]\nDescription=hand-rolled\n")
        self.assertIsNone(workload_lib.units_from_other_build("foo"))

    def test_stamp_is_found_past_a_workload_specific_first_line(self):
        # The cgroup drop-in leads with a workload-specific comment, so the
        # stamp is not always line 1.
        self.unit.write_text(
            "# Workload foo: redirect user@10000 into workloads.slice\n"
            "# Generated by workload-generate (9.9.9-1.20990101000000)\n"
        )
        self.assertEqual(
            workload_lib.units_from_other_build("foo"), "9.9.9-1.20990101000000"
        )


class TestHostUsernsGate(unittest.TestCase):
    """S5: userns=host is refused unless explicitly acknowledged."""

    def _cfg(self, security):
        return {"workload": {"name": "app"}, "container": {"image": "x:latest"},
                "security": security}

    def test_uses_host_userns_detection(self):
        from validation import uses_host_userns
        self.assertTrue(uses_host_userns(self._cfg({"userns": "host"})))
        self.assertFalse(uses_host_userns(self._cfg({"userns": "keep-id"})))
        self.assertFalse(uses_host_userns(
            self._cfg({"userns": "keep-id:uid=0,gid=0"})))
        # VMs never use userns.
        self.assertFalse(uses_host_userns(
            {"workload": {"name": "v"}, "vm": {"cloud_image_url": "x"},
             "security": {"userns": "host"}}))

    def test_bridge_reads_per_container_userns(self):
        from validation import uses_host_userns
        cfg = {"workload": {"name": "app", "mode": "bridge"},
               "containers": [
                   {"name": "web", "container": {"image": "x:latest"}},
                   {"name": "vpn", "container": {"image": "y:latest"},
                    "security": {"userns": "host"}},
               ]}
        self.assertTrue(uses_host_userns(cfg))

    def test_validate_rejects_unacked_host_userns(self):
        errors = validate_workload_config(self._cfg({"userns": "host"}))
        self.assertTrue(any("unsafe_host_userns" in e for e in errors))

    def test_validate_accepts_acked_host_userns(self):
        errors = validate_workload_config(
            self._cfg({"userns": "host", "unsafe_host_userns": True}))
        self.assertFalse(any("unsafe_host_userns" in e for e in errors))

    def test_validate_accepts_container_root_keep_id(self):
        errors = validate_workload_config(
            self._cfg({"userns": "keep-id:uid=0,gid=0"}))
        self.assertEqual(errors, [])


class TestVmMacCollisions(unittest.TestCase):
    def test_no_collision_for_distinct_names(self):
        # Real derived MACs differ for these names.
        self.assertEqual(mac_collisions("git", ["forge", "build"]), [])

    def test_excludes_self(self):
        self.assertEqual(mac_collisions("git", ["git"]), [])

    def test_detects_collision(self):
        # Force two names onto one MAC to exercise the detection path without
        # having to construct a real md5 collision.
        fixed = "02:00:00:00:00:01"
        collide = {"git", "forge"}
        # Patched on vm_defs, not on vm. vm re-exports the name, but
        # mac_collisions resolves it in the module that DEFINES it, so a
        # patch aimed at the re-export binds a copy nothing calls.
        with patch("vm_defs.mac_address",
                   side_effect=lambda n: fixed if n in collide else f"02:00:00:00:00:{ord(n[0]):02x}"):
            self.assertEqual(mac_collisions("git", ["forge", "other"]), ["forge"])


class TestValidUsernsMode(unittest.TestCase):
    def test_accepts_plain_forms(self):
        self.assertTrue(valid_userns_mode("keep-id"))
        self.assertTrue(valid_userns_mode("host"))

    def test_accepts_keep_id_params(self):
        self.assertTrue(valid_userns_mode("keep-id:uid=1000"))
        self.assertTrue(valid_userns_mode("keep-id:uid=0,gid=0"))

    def test_rejects_bad_forms(self):
        for bad in ("private", "keep-id:", "keep-id:uid=x", "keep-id:foo=1",
                    "keep-id:uid=1,uid=2", "keep-id:uid"):
            self.assertFalse(valid_userns_mode(bad), bad)


class TestCollectConfigWarnings(unittest.TestCase):
    """collect_config_warnings mirrors the boot generator's kmsg-only warnings
    so `validate` can surface them at edit/deploy time."""

    def test_clean_single_config_has_no_warnings(self):
        cfg = {"workload": {"name": "app"}, "container": {"image": "x:latest"}}
        self.assertEqual(collect_config_warnings(cfg), [])

    def test_invalid_userns_flagged(self):
        cfg = {"workload": {"name": "app"}, "container": {"image": "x:latest"},
               "security": {"userns": "private"}}
        warnings = collect_config_warnings(cfg)
        self.assertTrue(any("invalid userns" in w and "private" in w for w in warnings))

    def test_valid_userns_not_flagged(self):
        cfg = {"workload": {"name": "app"}, "container": {"image": "x:latest"},
               "security": {"userns": "keep-id:uid=0,gid=0"}}
        self.assertEqual(collect_config_warnings(cfg), [])

    def test_bridge_userns_read_per_container(self):
        cfg = {"workload": {"name": "app", "mode": "bridge"},
               "containers": [
                   {"name": "web", "container": {"image": "x:latest"},
                    "security": {"userns": "bogus"}},
                   {"name": "db", "container": {"image": "y:latest"}},
               ]}
        warnings = collect_config_warnings(cfg)
        self.assertTrue(any("invalid userns" in w and "'web'" in w for w in warnings))

    def test_pet_in_multi_flagged(self):
        cfg = {"workload": {"name": "app", "mode": "pod", "lifecycle": "pet"},
               "containers": [
                   {"name": "web", "container": {"image": "x:latest"}},
                   {"name": "db", "container": {"image": "y:latest"}},
               ]}
        warnings = collect_config_warnings(cfg)
        self.assertTrue(any("lifecycle=pet" in w for w in warnings))

    def test_pet_in_single_not_flagged(self):
        cfg = {"workload": {"name": "app", "lifecycle": "pet"},
               "container": {"image": "x:latest"}}
        self.assertFalse(any("lifecycle=pet" in w
                             for w in collect_config_warnings(cfg)))

    def test_bridge_ports_ignored_flagged(self):
        cfg = {"workload": {"name": "app", "mode": "bridge"},
               "network": {"ports": ["8080:80"]},
               "containers": [
                   {"name": "web", "container": {"image": "x:latest"}},
                   {"name": "db", "container": {"image": "y:latest"}},
               ]}
        warnings = collect_config_warnings(cfg)
        self.assertTrue(any("[network].ports is ignored in bridge mode" in w
                            for w in warnings))

    def test_requires_after_cross_reference(self):
        cfg = {"workload": {"name": "app", "requires": ["db"], "after": ["cache"]},
               "container": {"image": "x:latest"}}
        # Without the fleet view, the cross-reference is skipped.
        self.assertEqual(collect_config_warnings(cfg), [])
        # db exists, cache does not.
        warnings = collect_config_warnings(cfg, known_workload_names={"app", "db"})
        self.assertTrue(any("after" in w and "cache" in w for w in warnings))
        self.assertFalse(any("db" in w for w in warnings))

    def test_vm_config_skips_container_checks(self):
        cfg = {"workload": {"name": "gitvm", "lifecycle": "pet"},
               "vm": {"cloud_image_url": "https://x/y.qcow2"},
               "security": {"userns": "private"}}
        # VMs don't use userns/lifecycle-in-mode; those must not fire.
        self.assertEqual(collect_config_warnings(cfg), [])


class TestSubidFileHelpers(unittest.TestCase):
    """R6: one parser and one mutator for /etc/subuid + /etc/subgid.

    These are the most security-relevant files the tool writes — a lost or
    mangled range silently removes a workload's isolation — so the format
    parsing and the rewrite mechanics are pinned here rather than left to the
    command modules that call them.
    """

    def setUp(self):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.dir = tmp
        self.subuid = tmp / "subuid"
        self.subgid = tmp / "subgid"
        self.enterContext(patch.object(workload_lib, "SUBUID_FILE", self.subuid))
        self.enterContext(patch.object(workload_lib, "SUBGID_FILE", self.subgid))
        self.enterContext(patch.object(workload_lib, "SUBID_LOCK", tmp / "subid.lock"))

    def test_accessors_follow_a_redirected_constant(self):
        # The whole reason these are functions: an importing module must not
        # capture a stale copy (same contract as workload_config_dir()).
        self.assertEqual(workload_lib.subuid_file(), self.subuid)
        self.assertEqual(workload_lib.subgid_file(), self.subgid)
        self.assertEqual(workload_lib.subid_files(), (self.subuid, self.subgid))

    def test_read_entry_parses_start_and_count(self):
        self.subuid.write_text("_wl-a:600100000:65536\n")
        self.assertEqual(
            workload_lib.read_subid_entry("_wl-a", self.subuid), (600100000, 65536)
        )

    def test_read_entry_returns_none_when_absent_or_missing_file(self):
        self.subuid.write_text("_wl-other:600100000:65536\n")
        self.assertIsNone(workload_lib.read_subid_entry("_wl-a", self.subuid))
        self.assertIsNone(
            workload_lib.read_subid_entry("_wl-a", self.dir / "nope")
        )

    def test_read_entry_returns_none_on_malformed_line(self):
        # Callers (info, diagnose) are read-only reporters; a corrupt file must
        # not raise out of them.
        self.subuid.write_text("_wl-a:notanumber:alsobad\n")
        self.assertIsNone(workload_lib.read_subid_entry("_wl-a", self.subuid))

    def test_read_entry_takes_only_the_main_range(self):
        # extra_groups add supplementary `user:GID:1` lines beside the main
        # range; only the main range is the mapping that matters.
        self.subuid.write_text("_wl-a:600100000:65536\n_wl-a:989:1\n")
        self.assertEqual(
            workload_lib.read_subid_entry("_wl-a", self.subuid), (600100000, 65536)
        )

    def test_read_entry_finds_the_main_range_after_supplementary_entries(self):
        """The ordering this used to get wrong. Nothing has ever guaranteed the
        main range is written first — it came out of a set — so on a host where
        it landed last, diagnose read `105:1` as the mapping and failed both
        subid checks for a workload whose range was present and correct."""
        self.subuid.write_text(
            "_wl-a:105:1\n_wl-a:966:1\n_wl-a:600100000:65536\n"
        )
        self.assertEqual(
            workload_lib.read_subid_entry("_wl-a", self.subuid), (600100000, 65536)
        )

    def test_read_entry_returns_a_drifted_main_range_not_a_supplementary_one(self):
        """Selecting by count != 1 rather than count == SUBID_COUNT, so a
        pre-derivation range with the wrong width still reaches
        subid_derived_check instead of being mistaken for a group entry and
        dropped — silently passing the check that exists to catch it."""
        self.subuid.write_text("_wl-a:989:1\n_wl-a:100000:10000\n")
        self.assertEqual(
            workload_lib.read_subid_entry("_wl-a", self.subuid), (100000, 10000)
        )

    def test_read_entry_falls_back_when_only_supplementary_entries_exist(self):
        """No main range at all: report the first entry rather than None, so the
        derived check fails loudly. None would omit the check entirely while
        subid_files_with_entries still called the user configured."""
        self.subuid.write_text("_wl-a:105:1\n_wl-a:966:1\n")
        self.assertEqual(
            workload_lib.read_subid_entry("_wl-a", self.subuid), (105, 1)
        )

    def test_prefix_match_does_not_catch_a_longer_username(self):
        """`_wl-app` must not match `_wl-app2` — the bug class that would strip
        a different, still-running workload's mapping."""
        self.subuid.write_text("_wl-app2:600200000:65536\n")
        self.subgid.write_text("_wl-app2:600200000:65536\n")
        self.assertIsNone(workload_lib.read_subid_entry("_wl-app", self.subuid))
        self.assertEqual(workload_lib.subid_files_with_entries("_wl-app"), [])
        self.assertEqual(workload_lib.remove_subid_entries("_wl-app"), [])
        self.assertIn("_wl-app2", self.subuid.read_text())

    def test_remove_strips_only_the_named_user(self):
        self.subuid.write_text("_wl-a:1:2\n_wl-b:3:4\n")
        self.subgid.write_text("_wl-a:1:2\n_wl-b:3:4\n_wl-a:989:1\n")
        changed = workload_lib.remove_subid_entries("_wl-a")
        self.assertEqual(changed, [self.subuid, self.subgid])
        self.assertEqual(self.subuid.read_text(), "_wl-b:3:4\n")
        self.assertEqual(self.subgid.read_text(), "_wl-b:3:4\n")

    def test_remove_reports_only_files_it_changed(self):
        self.subuid.write_text("_wl-a:1:2\n")
        self.subgid.write_text("_wl-b:3:4\n")
        self.assertEqual(
            workload_lib.remove_subid_entries("_wl-a"), [self.subuid]
        )

    def test_remove_of_last_entry_leaves_an_empty_file_not_a_stray_newline(self):
        self.subuid.write_text("_wl-a:1:2\n")
        workload_lib.remove_subid_entries("_wl-a")
        self.assertEqual(self.subuid.read_text(), "")

    def test_remove_is_atomic_and_preserves_mode(self):
        """The rewrite must land via rename, not truncate-in-place: podman and
        newuidmap read these files without taking SUBID_LOCK, so a partial
        write is observable by a reader that cannot detect it."""
        self.subuid.write_text("_wl-a:1:2\n_wl-b:3:4\n")
        os.chmod(self.subuid, 0o640)
        self.subgid.write_text("_wl-b:3:4\n")

        seen = []
        real_replace = os.replace

        def spy_replace(src, dst):
            # At the moment of the rename the destination still holds the OLD
            # content — never a truncated or partial version.
            seen.append(Path(dst).read_text())
            return real_replace(src, dst)

        with patch.object(workload_lib.os, "replace", spy_replace):
            workload_lib.remove_subid_entries("_wl-a")

        self.assertEqual(seen, ["_wl-a:1:2\n_wl-b:3:4\n"])
        self.assertEqual(self.subuid.read_text(), "_wl-b:3:4\n")
        self.assertEqual(stat.S_IMODE(self.subuid.stat().st_mode), 0o640)
        self.assertEqual(list(self.dir.glob(".*.tmp")), [])

    def test_remove_leaves_no_temp_file_when_nothing_matches(self):
        self.subuid.write_text("_wl-b:3:4\n")
        workload_lib.remove_subid_entries("_wl-a")
        self.assertEqual(list(self.dir.glob(".*.tmp")), [])

    def test_append_adds_lines_and_creates_nothing_for_empty(self):
        self.subuid.write_text("_wl-a:1:2\n")
        workload_lib.append_subid_entries(self.subuid, ["_wl-b:3:4"])
        self.assertEqual(self.subuid.read_text(), "_wl-a:1:2\n_wl-b:3:4\n")
        workload_lib.append_subid_entries(self.subuid, [])
        self.assertEqual(self.subuid.read_text(), "_wl-a:1:2\n_wl-b:3:4\n")

    def test_append_is_reentrant_under_an_outer_lock(self):
        """workload-ensure-user appends while already holding subid_lock(); the
        inner acquire must be a no-op, not a same-process deadlock."""
        self.subuid.write_text("")
        with workload_lib.subid_lock():
            workload_lib.append_subid_entries(self.subuid, ["_wl-a:1:2"])
        self.assertEqual(self.subuid.read_text(), "_wl-a:1:2\n")

    def test_files_with_entries_skips_absent_files(self):
        self.subuid.write_text("_wl-a:1:2\n")
        # subgid intentionally not created
        self.assertEqual(
            workload_lib.subid_files_with_entries("_wl-a"), [self.subuid]
        )


class TestReplaceFileAtomically(unittest.TestCase):
    """The general whole-file replacement used anywhere a reader could observe
    the write or a crash could outlive it. The subid rewrite is one caller; the
    others are `edit`'s restore-on-validation-failure and the VM host-key pin.
    """

    def setUp(self):
        self.dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.dir / "target"

    def test_replaces_content_and_leaves_no_temp(self):
        self.path.write_text("old\n")
        workload_lib.replace_file_atomically(self.path, "new\n")
        self.assertEqual(self.path.read_text(), "new\n")
        self.assertEqual(list(self.dir.glob(".*")), [])

    def test_destination_holds_old_content_until_the_rename(self):
        """The whole point: a concurrent reader sees the old file or the new
        one, never a half-written one."""
        self.path.write_text("old\n")
        seen = []
        real_replace = os.replace

        def spy_replace(src, dst):
            seen.append(Path(dst).read_text())
            return real_replace(src, dst)

        with patch.object(workload_lib.os, "replace", spy_replace):
            workload_lib.replace_file_atomically(self.path, "new\n")
        self.assertEqual(seen, ["old\n"])

    def test_temp_is_a_sibling_so_the_rename_stays_on_one_filesystem(self):
        self.path.write_text("old\n")
        seen = []
        with patch.object(workload_lib.os, "replace",
                          lambda src, dst: seen.append(Path(src).parent)):
            workload_lib.replace_file_atomically(self.path, "new\n")
        self.assertEqual(seen, [self.path.parent])
        (self.dir / ("." + self.path.name + ".tmp")).unlink()

    def test_existing_mode_survives_the_replace(self):
        self.path.write_text("old\n")
        os.chmod(self.path, 0o600)
        workload_lib.replace_file_atomically(self.path, "new\n", default_mode=0o644)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_default_mode_applies_only_when_creating(self):
        workload_lib.replace_file_atomically(self.path, "new\n", default_mode=0o600)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_accepts_bytes(self):
        workload_lib.replace_file_atomically(self.path, b"\x00binary\n")
        self.assertEqual(self.path.read_bytes(), b"\x00binary\n")

    def test_unwritable_owner_is_not_fatal(self):
        """chown fails for a non-root caller; the write must still land, since
        every caller that depends on ownership already requires root."""
        self.path.write_text("old\n")
        with patch.object(workload_lib.os, "chown",
                          side_effect=PermissionError("not root")):
            workload_lib.replace_file_atomically(self.path, "new\n", owner=(1, 1))
        self.assertEqual(self.path.read_text(), "new\n")


class TestContainerNetworkPolicyCredentialParsing(unittest.TestCase):
    """Shape-tolerant parsing -- validation is a separate, not-yet-written
    function; these tests only lock the parse."""

    def test_policy_entry_defaults(self):
        entries = container_policy_entries({"policy": [{"host": "api.example.com"}]})
        self.assertEqual(entries, [ContainerPolicyEntry(
            host="api.example.com", methods=None, paths=None, credential=None)])

    def test_policy_methods_uppercased_paths_not(self):
        entries = container_policy_entries({"policy": [{
            "host": "api.example.com", "methods": ["post"], "paths": ["/v1/Messages"],
            "credential": "anthropic",
        }]})
        self.assertEqual(entries[0].methods, ("POST",))
        self.assertEqual(entries[0].paths, ("/v1/Messages",))
        self.assertEqual(entries[0].credential, "anthropic")

    def test_policy_entry_missing_host_is_skipped(self):
        self.assertEqual(container_policy_entries({"policy": [{"methods": ["GET"]}]}), [])

    def test_policy_non_list_is_empty(self):
        self.assertEqual(container_policy_entries({"policy": "oops"}), [])
        self.assertEqual(container_policy_entries({}), [])

    def test_credential_entry_round_trips_optional_auth_fields(self):
        creds = container_credential_entries({"credential": [{
            "name": "anthropic", "placeholder": "sk-ant-placeholder",
            "env": "ANTHROPIC_API_KEY", "auth_header": "Authorization",
            "auth_format": "Bearer {secret}",
        }]})
        self.assertEqual(creds, [ContainerCredential(
            name="anthropic", placeholder="sk-ant-placeholder", env="ANTHROPIC_API_KEY",
            auth_header="Authorization", auth_format="Bearer {secret}")])

    def test_credential_entry_missing_required_field_is_skipped(self):
        self.assertEqual(container_credential_entries({"credential": [{"name": "x"}]}), [])


class TestContainerNetworkScalarParsing(unittest.TestCase):
    def test_hosts_filters_non_strings_and_defaults_empty(self):
        self.assertEqual(container_allowed_hosts({"hosts": ["*.pypi.org", 5, ""]}),
                          ["*.pypi.org"])
        self.assertEqual(container_allowed_hosts({}), [])

    def test_tls_is_not_defaulted(self):
        """Effective tls is computed by validate_container_network(), not here."""
        self.assertIsNone(container_tls_mode({}))
        self.assertEqual(container_tls_mode({"tls": "splice"}), "splice")

    def test_tls_reason_ca_delivery_ca_mount_path(self):
        net = {"tls_reason": " pinned cert ", "ca_delivery": "env",
               "ca_mount_path": "/etc/ssl/wl-ca.pem"}
        self.assertEqual(container_tls_reason(net), "pinned cert")
        self.assertEqual(container_ca_delivery(net), "env")
        self.assertEqual(container_ca_mount_path(net), "/etc/ssl/wl-ca.pem")
        self.assertIsNone(container_tls_reason({}))
        self.assertIsNone(container_ca_delivery({}))
        self.assertIsNone(container_ca_mount_path({}))


class TestContainerNetworkArrayParsing(unittest.TestCase):
    def test_allow_entry_by_host(self):
        entries = container_allow_entries({"allow": [
            {"host": "smtp.example.com", "port": 587, "reason": "mail relay"},
        ]})
        self.assertEqual(entries, [ContainerAllowEntry(
            host="smtp.example.com", address=None, port=587, reason="mail relay")])

    def test_allow_entry_by_address(self):
        entries = container_allow_entries({"allow": [
            {"address": "10.0.0.5", "port": 22, "reason": "backup host"},
        ]})
        self.assertEqual(entries[0].host, None)
        self.assertEqual(entries[0].address, "10.0.0.5")

    def test_allow_entry_without_host_or_address_is_skipped(self):
        self.assertEqual(container_allow_entries({"allow": [{"port": 22, "reason": "x"}]}), [])

    def test_allow_entry_bool_port_is_not_an_int_port(self):
        """isinstance(True, int) is True in Python -- must not leak through."""
        entries = container_allow_entries({"allow": [
            {"host": "x.example.com", "port": True, "reason": "x"},
        ]})
        self.assertIsNone(entries[0].port)

    def test_internal_and_splice_entries_keep_reason(self):
        net = {
            "internal": [{"host": "nas.lan", "reason": "backup share"}],
            "splice": [{"host": "pinned.example.com", "reason": "cert pinning"}],
        }
        self.assertEqual(container_internal_entries(net),
                          [ContainerHostReasonEntry(host="nas.lan", reason="backup share")])
        self.assertEqual(container_splice_entries(net),
                          [ContainerHostReasonEntry(host="pinned.example.com",
                                                     reason="cert pinning")])

    def test_internal_entry_missing_host_is_skipped(self):
        self.assertEqual(container_internal_entries({"internal": [{"reason": "x"}]}), [])

    def test_arrays_non_list_is_empty(self):
        self.assertEqual(container_allow_entries({"allow": "oops"}), [])
        self.assertEqual(container_internal_entries({"internal": "oops"}), [])
        self.assertEqual(container_splice_entries({"splice": "oops"}), [])


class TestContainerEffectiveTlsMode(unittest.TestCase):
    def test_no_policy_is_splice(self):
        self.assertEqual(container_effective_tls_mode({"hosts": ["a.com"]}), "splice")

    def test_policy_present_is_inspect(self):
        net = {"hosts": ["a.com"], "policy": [{"host": "a.com"}]}
        self.assertEqual(container_effective_tls_mode(net), "inspect")

    def test_explicit_tls_wins_either_direction(self):
        net = {"hosts": ["a.com"], "policy": [{"host": "a.com"}], "tls": "splice"}
        self.assertEqual(container_effective_tls_mode(net), "splice")
        net = {"hosts": ["a.com"], "tls": "inspect"}
        self.assertEqual(container_effective_tls_mode(net), "inspect")


class TestValidateContainerNetwork(unittest.TestCase):
    """One assertion per V-rule from the container egress-parity build spec's
    validation section, in numeric order. Not-a-dict and no-trigger inputs
    bookend the class since they are the two cases every rule below assumes
    past."""

    def test_not_a_dict_is_one_error(self):
        self.assertEqual(validate_container_network([]), ["[network] must be a table"])

    def test_no_trigger_is_clean(self):
        self.assertEqual(validate_container_network({}), [])

    def test_hosts_only_needs_no_ca_delivery(self):
        self.assertEqual(validate_container_network({"hosts": ["*.pypi.org"]}), [])

    # --- the mode = "host" delta (build spec §6 delta 2), settled by P0-1 ---
    #
    # Measured on hardware: under the default `userns = "keep-id"` only ONE
    # in-container uid maps to the workload uid; `[container] user = "0"` and
    # `user = "1000"` both leave as subuids. Every egress rule selects on the
    # single uid, so a host-mode policy would cover only bundles that happen
    # to run as the keep-id uid. The combination is refused rather than
    # honoured-for-some-containers.

    def test_host_mode_with_an_egress_key_is_refused(self):
        errors = validate_container_network(
            {"mode": "host", "hosts": ["*.pypi.org"]})
        self.assertTrue(any('mode = "host"' in e for e in errors), errors)
        self.assertTrue(any("[network].hosts" in e for e in errors), errors)

    def test_host_mode_without_any_egress_key_is_clean(self):
        """Host networking on its own is untouched -- the rule is about the
        combination, not about host mode."""
        self.assertEqual(validate_container_network({"mode": "host"}), [])

    def test_host_mode_refusal_names_every_key_the_workload_set(self):
        """The message has to be actionable for a bundle that set several;
        naming only the first would send the operator round the loop."""
        errors = validate_container_network({
            "mode": "host",
            "hosts": ["a.example.com"],
            "policy": [{"host": "a.example.com"}],
            "allow": [{"address": "10.0.0.1", "port": 22, "reason": "r"}],
            "internal": [{"host": "a.example.com", "reason": "r"}],
        })
        self.assertEqual(len(errors), 1, errors)
        for key in ("hosts", "policy", "allow", "internal"):
            self.assertIn(f"[network].{key}", errors[0])

    def test_host_mode_refusal_states_the_remedy(self):
        errors = validate_container_network(
            {"mode": "host", "hosts": ["a.example.com"]})
        self.assertTrue(any("Remove" in e for e in errors), errors)

    def test_host_mode_suppresses_the_rest_of_the_policy_shape_errors(self):
        """Under host mode no policy can be armed, so reporting how a policy
        that will never exist is misspelled is noise. One error, not six."""
        errors = validate_container_network({
            "mode": "host",
            "policy": [{"host": "a.example.com"}],   # would demand ca_delivery
            "allow": [{"host": "b.example.com", "port": 443}],  # 443 + no reason
        })
        self.assertEqual(len(errors), 1, errors)

    def test_non_host_modes_are_not_caught_by_the_host_rule(self):
        """pasta/bridge re-originate through a host process owned by the
        workload uid -- measured `exact-uid` on all three in-container uids,
        so their single-uid selectors are sound."""
        for mode in ("pasta", "bridge", None):
            net = {"hosts": ["*.pypi.org"]}
            if mode is not None:
                net["mode"] = mode
            self.assertEqual(validate_container_network(net), [], mode)

    def test_bridge_topology_never_reads_network_mode_so_host_is_inert(self):
        """`mode = "host"` in a BRIDGE-mode workload is a key nobody reads.

        The refusal exists because a host-netns container's processes span the
        workload's whole subuid window rather than its single uid (P0-1). That
        is a statement about `podman run --network=host` / `podman pod create
        --network=host`, and bridge mode issues neither -- every member joins
        `workload-<name>-net` instead, exactly as workload-level
        [network].ports is ignored there. Refusing was refusing a workload for
        a key the generator never reads, and it fails closed, so the workload
        did not run at all.
        """
        config = {
            "workload": {"name": "br", "mode": "bridge"},
            "network": {"mode": "host", "hosts": ["*.pypi.org"]},
            "containers": [{"name": "web", "container": {"image": "i"}}],
        }
        self.assertFalse(container_runs_on_host_network(config))
        self.assertEqual(validate_container_network(config["network"], config), [])
        self.assertTrue(container_uses_inspect(config))

    def test_pod_and_single_topologies_do_read_it_and_are_still_refused(self):
        """The other half: both pass the key straight to podman, so the
        measurement that produced the refusal applies to them unchanged."""
        for mode, extra in (("pod", {"containers": [
                                {"name": "web", "container": {"image": "i"}}]}),
                            ("single", {"container": {"image": "i"}})):
            config = {"workload": {"name": "w", "mode": mode},
                      "network": {"mode": "host", "hosts": ["*.pypi.org"]},
                      **extra}
            self.assertTrue(container_runs_on_host_network(config), mode)
            errors = validate_container_network(config["network"], config)
            self.assertTrue(any('mode = "host"' in e for e in errors),
                            (mode, errors))
            self.assertFalse(container_uses_inspect(config), mode)

    def test_without_a_config_the_key_is_assumed_honoured(self):
        """The table alone cannot answer a topology question, and the safe
        reading of "I do not know the topology" is the refusing one."""
        self.assertEqual(
            len(validate_container_network(
                {"mode": "host", "hosts": ["*.pypi.org"]})), 1)

    def test_v3_overlapping_entries_must_both_state_methods_and_paths(self):
        net = {
            "hosts": ["api.example.com"],
            "policy": [
                {"host": "api.example.com", "methods": ["GET"], "paths": ["/a"]},
                {"host": "*.example.com"},
            ],
            "ca_delivery": "env",
        }
        errors = validate_container_network(net)
        self.assertTrue(any("shares a host with" in e for e in errors), errors)

    def test_v4_apex_not_covered_by_wildcard_policy_entry(self):
        net = {
            "hosts": ["example.com"],
            "policy": [{"host": "*.example.com"}],
            "ca_delivery": "env",
        }
        errors = validate_container_network(net)
        self.assertTrue(any("does not cover the apex" in e for e in errors), errors)

    def test_v4_apex_covered_is_clean(self):
        net = {
            "hosts": ["example.com"],
            "policy": [{"host": "*.example.com"}, {"host": "example.com"}],
            "ca_delivery": "env",
        }
        self.assertEqual(validate_container_network(net), [])

    def test_v5_unregistered_method_is_error(self):
        net = {"hosts": ["a.com"], "policy": [{"host": "a.com", "methods": ["FETCH"]}],
               "ca_delivery": "env"}
        errors = validate_container_network(net)
        self.assertTrue(any("not a registered HTTP method" in e for e in errors), errors)

    def test_v5_connect_is_refused_by_name(self):
        net = {"hosts": ["a.com"], "policy": [{"host": "a.com", "methods": ["CONNECT"]}],
               "ca_delivery": "env"}
        errors = validate_container_network(net)
        self.assertTrue(any("never sees" in e for e in errors), errors)

    def test_v6_path_with_query_string_is_error(self):
        net = {"hosts": ["a.com"], "policy": [{"host": "a.com", "paths": ["/x?y=1"]}],
               "ca_delivery": "env"}
        errors = validate_container_network(net)
        self.assertTrue(any("query or fragment" in e for e in errors), errors)

    def test_v7_credential_must_be_declared(self):
        net = {"hosts": ["a.com"], "policy": [{"host": "a.com", "credential": "nope"}],
               "ca_delivery": "env"}
        errors = validate_container_network(net)
        self.assertTrue(any("no [[network.credential]] block declares" in e for e in errors), errors)

    def test_v8_wildcard_host_with_credential_is_error(self):
        net = {
            "hosts": ["example.com"],
            "policy": [{"host": "*.example.com", "credential": "c"}],
            "credential": [{"name": "c", "placeholder": "x", "env": "MY_KEY"}],
            "ca_delivery": "env",
        }
        errors = validate_container_network(net)
        self.assertTrue(any("attached per exact host" in e for e in errors), errors)

    def test_v9_tls_splice_with_policy_is_error(self):
        net = {"hosts": ["a.com"], "tls": "splice", "policy": [{"host": "a.com"}]}
        errors = validate_container_network(net)
        self.assertTrue(any("tls = 'splice'" in e for e in errors), errors)

    def test_v10_credential_env_cannot_shadow_ca_var(self):
        net = {
            "hosts": ["a.com"],
            "policy": [{"host": "a.com", "credential": "c"}],
            "credential": [{"name": "c", "placeholder": "x", "env": "PIP_CERT"}],
            "ca_delivery": "env",
        }
        errors = validate_container_network(net)
        self.assertTrue(any("CA trust-store variables" in e for e in errors), errors)

    # --- The rules the container port had dropped ---
    #
    # Every one of these existed on the VM side and on no other. They are the
    # reason the two validators are now one function: each of these six went
    # missing by being a rule nobody re-typed, and a missing rule is invisible
    # in a suite that only ever asks whether the rules present still fire.
    # They all fail the same way at runtime -- the broker attaches the wrong
    # header or none, the provider answers 401, and nothing on this host
    # considers the request anything but authorised.

    def test_an_unknown_credential_key_is_named(self):
        """A typo, not a feature: `auth_hedaer` was accepted and dropped, so
        the workload got the broker's default header on every request and the
        file said otherwise."""
        net = {"hosts": ["a.com"], "ca_delivery": "env",
               "policy": [{"host": "a.com", "credential": "c"}],
               "credential": [{"name": "c", "placeholder": "x", "env": "K",
                               "auth_hedaer": "Authorization"}]}
        errors = validate_container_network(net)
        self.assertTrue(any("unknown key(s) auth_hedaer" in e for e in errors),
                        errors)

    def test_a_credential_name_that_is_not_a_credstore_name_is_refused(self):
        net = {"hosts": ["a.com"], "ca_delivery": "env",
               "policy": [{"host": "a.com", "credential": "a/b"}],
               "credential": [{"name": "a/b", "placeholder": "x",
                               "env": "K"}]}
        errors = validate_container_network(net)
        self.assertTrue(any("usable credstore name" in e for e in errors),
                        errors)

    def test_a_credential_env_that_is_not_a_shell_name_is_refused(self):
        net = {"hosts": ["a.com"], "ca_delivery": "env",
               "policy": [{"host": "a.com", "credential": "c"}],
               "credential": [{"name": "c", "placeholder": "x",
                               "env": "MY KEY"}]}
        errors = validate_container_network(net)
        self.assertTrue(any("not a shell variable name" in e for e in errors),
                        errors)

    def test_an_empty_auth_header_is_refused_not_defaulted(self):
        """Refused rather than coerced to None. Coercion is what the port did,
        and it turns a stated intent into the broker's default silently."""
        net = {"hosts": ["a.com"], "ca_delivery": "env",
               "policy": [{"host": "a.com", "credential": "c"}],
               "credential": [{"name": "c", "placeholder": "x", "env": "K",
                               "auth_header": "  "}]}
        errors = validate_container_network(net)
        self.assertTrue(any("auth_header" in e for e in errors), errors)

    def test_an_auth_header_that_cannot_carry_a_credential_is_refused(self):
        net = {"hosts": ["a.com"], "ca_delivery": "env",
               "policy": [{"host": "a.com", "credential": "c"}],
               "credential": [{"name": "c", "placeholder": "x", "env": "K",
                               "auth_header": "connection"}]}
        errors = validate_container_network(net)
        self.assertTrue(any("cannot carry a credential" in e for e in errors),
                        errors)

    def test_an_auth_format_naming_the_wrong_field_is_refused(self):
        """The broker renders this with str.format at startup and exits on a
        bad one, so the only symptom on a generated unit is a restart loop."""
        net = {"hosts": ["a.com"], "ca_delivery": "env",
               "policy": [{"host": "a.com", "credential": "c"}],
               "credential": [{"name": "c", "placeholder": "x", "env": "K",
                               "auth_format": "Bearer {token}"}]}
        errors = validate_container_network(net)
        self.assertTrue(any("auth_format" in e for e in errors), errors)

    def test_an_unknown_policy_key_is_named(self):
        net = {"hosts": ["a.com"], "ca_delivery": "env",
               "policy": [{"host": "a.com", "pathes": ["/v1"]}]}
        errors = validate_container_network(net)
        self.assertTrue(any("unknown key(s) pathes" in e for e in errors),
                        errors)

    def test_a_well_formed_credential_block_still_validates_clean(self):
        """The six rows above are only meaningful beside this one: the port's
        gaps are closed without the shared body having tightened onto the
        ordinary shape."""
        net = {"hosts": ["a.com"], "ca_delivery": "env",
               "policy": [{"host": "a.com", "credential": "c"}],
               "credential": [{"name": "c", "placeholder": "sk-placeholder",
                               "env": "API_KEY",
                               "auth_header": "Authorization",
                               "auth_format": "Bearer {secret}"}]}
        self.assertEqual(validate_container_network(net), [])

    def test_v12_internal_entry_not_on_any_list_is_error(self):
        net = {"hosts": ["a.com"], "internal": [{"host": "nas.lan", "reason": "backup"}]}
        errors = validate_container_network(net)
        self.assertTrue(any("[network].internal: 'nas.lan' is on no list" in e for e in errors), errors)

    def test_v12_internal_entry_justified_by_policy_host_is_clean(self):
        net = {
            "policy": [{"host": "nas.lan"}],
            "internal": [{"host": "nas.lan", "reason": "backup"}],
            "ca_delivery": "env",
        }
        self.assertEqual(validate_container_network(net), [])

    def test_v14_splice_entry_missing_reason_is_error(self):
        net = {"hosts": ["a.com"], "splice": [{"host": "a.com"}]}
        errors = validate_container_network(net)
        self.assertTrue(any("has no `reason`" in e for e in errors), errors)

    def test_v14_internal_entry_missing_reason_is_error(self):
        net = {"policy": [{"host": "nas.lan"}], "internal": [{"host": "nas.lan"}],
               "ca_delivery": "env"}
        errors = validate_container_network(net)
        self.assertTrue(any("has no `reason`" in e for e in errors), errors)

    def test_v12_splice_entry_not_allowlisted_is_error(self):
        net = {"hosts": ["a.com"], "splice": [{"host": "b.com", "reason": "cert pinning"}]}
        errors = validate_container_network(net)
        self.assertTrue(any("matches no allowlisted name" in e for e in errors), errors)

    def test_v16_policy_without_ca_delivery_is_error(self):
        net = {"hosts": ["a.com"], "policy": [{"host": "a.com"}]}
        errors = validate_container_network(net)
        self.assertTrue(any("ca_delivery is required" in e for e in errors), errors)

    def test_v16_explicit_tls_inspect_also_requires_ca_delivery(self):
        net = {"hosts": ["a.com"], "tls": "inspect"}
        errors = validate_container_network(net)
        self.assertTrue(any("ca_delivery is required" in e for e in errors), errors)

    def test_v16_ca_delivery_mount_requires_mount_path(self):
        net = {"hosts": ["a.com"], "policy": [{"host": "a.com"}], "ca_delivery": "mount"}
        errors = validate_container_network(net)
        self.assertTrue(any("requires ca_mount_path" in e for e in errors), errors)

    def test_ca_mount_path_without_mount_delivery_is_error(self):
        net = {"hosts": ["a.com"], "ca_delivery": "env", "ca_mount_path": "/etc/x.crt"}
        errors = validate_container_network(net)
        self.assertTrue(any("ca_mount_path is set but ca_delivery" in e for e in errors), errors)

    def test_v18_splice_entry_on_already_spliced_workload_is_error(self):
        net = {"hosts": ["a.com"], "splice": [{"host": "a.com", "reason": "pinning"}]}
        errors = validate_container_network(net)
        self.assertTrue(any("is redundant" in e for e in errors), errors)

    def test_credential_declared_but_unselected_is_error(self):
        net = {
            "hosts": ["a.com"],
            "credential": [{"name": "c", "placeholder": "x", "env": "MY_KEY"}],
        }
        errors = validate_container_network(net)
        self.assertTrue(any("attached to nothing" in e for e in errors), errors)

    def test_full_rung3_example_is_clean(self):
        net = {
            "hosts": ["*.pypi.org", "files.pythonhosted.org"],
            "ca_delivery": "env",
            "policy": [{"host": "api.anthropic.com", "methods": ["POST"],
                       "paths": ["/v1/messages"], "credential": "anthropic"}],
            "credential": [{"name": "anthropic", "placeholder": "sk-ant-x",
                           "env": "ANTHROPIC_API_KEY", "auth_header": "Authorization",
                           "auth_format": "Bearer {secret}"}],
        }
        self.assertEqual(validate_container_network(net), [])


class TestValidateContainerNetworkAllowAndHostPatterns(unittest.TestCase):
    """P1-14: the half of validate_container_network() the V-rule class above
    does not reach.

    Every rule here is one the VM schema also has, which is exactly why it went
    untested -- a rule that reads like a port of a proven one looks covered.
    They were separate implementations, and a port that dropped a clause failed
    on the container side alone where no VM test could see it. They share one
    body now, so what these rows still measure is the part that is NOT shared:
    the two sentences the container schema owns, which the shared body takes as
    arguments and cannot check for itself."""

    # --- `hosts` pattern shape (_validate_container_host_pattern) ---

    def test_a_url_is_refused_with_the_scheme_named(self):
        errors = validate_container_network({"hosts": ["https://example.com"]})
        self.assertTrue(any("drop the scheme" in e for e in errors), errors)

    def test_a_path_is_refused_because_it_can_never_match(self):
        errors = validate_container_network({"hosts": ["example.com/v2/"]})
        self.assertTrue(any("contains a path" in e for e in errors), errors)

    def test_a_port_is_refused_and_points_at_the_allow_array(self):
        """The remedy matters as much as the refusal: hostname policy governs
        the two redirected ports only, and the operator who wrote a port meant
        a destination [[network.allow]] carries."""
        errors = validate_container_network({"hosts": ["example.com:8443"]})
        self.assertTrue(any("contains a port" in e for e in errors), errors)
        self.assertTrue(any("[[network.allow]]" in e for e in errors), errors)

    def test_bare_star_is_refused_as_filtering_nothing(self):
        """Not an error about syntax -- '*' parses fine and matches every host.
        It is refused because it reads as configured and enforces nothing, and
        the message has to say so or the operator just writes it again."""
        errors = validate_container_network({"hosts": ["*"]})
        self.assertTrue(any("filters nothing" in e for e in errors), errors)

    def test_an_empty_pattern_is_refused(self):
        errors = validate_container_network({"hosts": ["   "]})
        self.assertTrue(any("must not be empty" in e for e in errors), errors)

    def test_hosts_must_be_an_array(self):
        errors = validate_container_network({"hosts": "example.com"})
        self.assertTrue(any("must be an array" in e for e in errors), errors)

    def test_a_wildcard_pattern_is_accepted(self):
        """The negative cases above are only meaningful beside this one: the
        pattern rules must not have tightened into rejecting the ordinary
        shape."""
        self.assertEqual(
            validate_container_network({"hosts": ["*.example.com", "example.com"]}),
            [])

    # --- [[network.allow]] ---

    def _allow(self, entry, **net):
        return validate_container_network({"allow": [entry], **net})

    def test_an_allow_entry_with_neither_host_nor_address_is_refused(self):
        errors = self._allow({"port": 22, "reason": "r"})
        self.assertTrue(any("neither `host` nor `address`" in e for e in errors),
                        errors)

    def test_an_allow_entry_with_both_is_refused(self):
        """One destination, named one way. Accepting both would leave which of
        the two is armed decided by parse order and reported by nothing."""
        errors = self._allow({"host": "git.local", "address": "10.0.0.1",
                              "port": 22, "reason": "r"})
        self.assertTrue(any("names one destination one way" in e for e in errors),
                        errors)

    def test_port_80_is_refused_and_the_message_says_why(self):
        """R5. 80 and 443 are redirected into the inspector before the filter
        chain consults this list, so an element here is armed and never
        matched -- while the config reads as if the destination were exempt
        from inspection. That is the misreport, not the wasted element."""
        errors = self._allow({"address": "10.0.0.1", "port": 80, "reason": "r"})
        self.assertTrue(any("always redirected" in e for e in errors), errors)

    def test_port_443_is_refused_the_same_way(self):
        errors = self._allow({"host": "example.com", "port": 443, "reason": "r"})
        self.assertTrue(any("always redirected" in e for e in errors), errors)

    def test_a_missing_port_is_refused(self):
        errors = self._allow({"address": "10.0.0.1", "reason": "r"})
        self.assertTrue(any("`port` must be an integer" in e for e in errors),
                        errors)

    def test_a_boolean_is_not_a_port(self):
        """bool is an int in Python, so `port = true` would otherwise pass the
        isinstance check and arm element 1."""
        errors = self._allow({"address": "10.0.0.1", "port": True, "reason": "r"})
        self.assertTrue(any("`port` must be an integer" in e for e in errors),
                        errors)

    def test_an_out_of_range_port_is_refused(self):
        errors = self._allow({"address": "10.0.0.1", "port": 70000, "reason": "r"})
        self.assertTrue(any("`port` must be an integer" in e for e in errors),
                        errors)

    def test_v14_an_allow_entry_needs_a_reason(self):
        errors = self._allow({"address": "10.0.0.1", "port": 22})
        self.assertTrue(any("has no `reason`" in e for e in errors), errors)

    def test_allow_must_be_an_array(self):
        errors = validate_container_network({"allow": {"host": "x"}})
        self.assertTrue(any("must be an array" in e for e in errors), errors)

    def test_a_well_formed_allow_entry_is_clean(self):
        """And it is a trigger on its own -- no `hosts`, no policy, and this
        must still validate rather than being refused for having nothing to
        inspect."""
        self.assertEqual(
            self._allow({"host": "git.local", "port": 2222,
                         "reason": "git over SSH"}),
            [])

    def test_an_allow_entry_alone_does_not_pull_in_the_ca_requirement(self):
        """V16 keys on the EFFECTIVE tls mode, and an allow-only workload has
        no policy entries, so it is rung 2 and needs no trust delivery. A
        version that keyed on `is_triggered` instead would demand ca_delivery
        from a workload whose traffic is never terminated."""
        errors = self._allow({"address": "10.0.0.1", "port": 22, "reason": "r"})
        self.assertFalse([e for e in errors if "ca_delivery" in e], errors)

    # --- the `tls` scalar and its tls_reason interlock ---
    #
    # Found by writing this class: both rules exist on the VM side and neither
    # had been ported, because `tls` is computed for almost every workload and
    # the hand-written branch is the one nothing constrained.

    def test_an_unrecognised_tls_value_is_refused(self):
        """The dangerous one. container_effective_tls_mode() returns the
        literal verbatim, so a typo is an effective mode that is neither
        'inspect' (V16 never asks for ca_delivery) nor 'splice' (V18 never
        fires) -- it validates clean and runs with a mode the inspector does
        not implement."""
        errors = validate_container_network({"hosts": ["a.example.com"],
                                             "tls": "inspct"})
        self.assertTrue(any("must be 'inspect' or 'splice'" in e for e in errors),
                        errors)

    def test_case_matters_because_nothing_downstream_normalises_it(self):
        errors = validate_container_network({"hosts": ["a.example.com"],
                                             "tls": "Splice"})
        self.assertTrue(any("must be 'inspect' or 'splice'" in e for e in errors),
                        errors)

    def test_explicit_splice_requires_a_reason(self):
        errors = validate_container_network({"hosts": ["a.example.com"],
                                             "tls": "splice"})
        self.assertTrue(any("requires tls_reason" in e for e in errors), errors)

    def test_splice_by_omission_requires_no_reason(self):
        """The container-only half, and the reason this is not a straight copy
        of the VM rule: a workload with no policy entries is spliced because
        that is rung 2, not because anything narrower was given up. Demanding a
        justification there would make the minimum filtered workload two keys,
        one of them an apology."""
        self.assertEqual(
            validate_container_network({"hosts": ["a.example.com"]}), [])

    def test_a_reason_without_an_explicit_splice_is_refused(self):
        errors = validate_container_network({"hosts": ["a.example.com"],
                                             "tls_reason": "vendor image"})
        self.assertTrue(any("was never chosen" in e for e in errors), errors)

    def test_explicit_splice_with_a_reason_is_clean(self):
        self.assertEqual(
            validate_container_network({"hosts": ["a.example.com"],
                                        "tls": "splice",
                                        "tls_reason": "vendor image"}),
            [])

    # --- V15 ---

    def test_v15_internal_is_not_refused_under_explicit_splice(self):
        """The delta from V9, and the one that is easy to fold in by mistake.
        The internal-destination check lives on the inspector's UPSTREAM leg,
        which a spliced connection still has -- so a spliced host can still
        resolve into private space and still needs the exemption."""
        net = {
            "hosts": ["git.local"],
            "tls": "splice",
            "tls_reason": "appliance image",
            "internal": [{"host": "git.local", "reason": "homelab forge"}],
        }
        self.assertEqual(validate_container_network(net), [])


class TestContainerFilterElements(unittest.TestCase):
    """P1-7/P1-8: the nft element/command builders container_uses_inspect's
    triggers feed into workload-container-filter."""

    def test_address_entry_needs_no_resolution(self):
        entry = ContainerAllowEntry(host=None, address="10.0.0.5", port=8080,
                                    reason="db")
        self.assertEqual(container_allow_resolve(entry),
                         [__import__("ipaddress").ip_address("10.0.0.5")])

    def test_host_entry_resolves_and_raises_on_failure(self):
        entry = ContainerAllowEntry(
            host="definitely-not-a-real-host.invalid", address=None, port=443,
            reason="x")
        with self.assertRaises(ValueError) as cm:
            container_allow_resolve(entry)
        self.assertIn("does not resolve", str(cm.exception))

    def test_filter_elements_splits_by_family_and_carries_uid(self):
        allow = [ContainerAllowEntry(host=None, address="10.0.0.5", port=8080,
                                     reason="db")]
        elements = container_filter_elements(1234, allow)
        self.assertEqual(elements["wl_filtered"], ["1234"])
        self.assertEqual(elements["wl_allow4"], ["1234 . 10.0.0.5 . 8080"])
        self.assertNotIn("wl_allow6", elements)

    def test_filter_elements_refuses_listener_range(self):
        # 198.18.0.0/16 is INSPECT_NETWORK -- another workload's listener
        # plane, never a legitimate allow destination (mirrors
        # vm_allow_reserved_reason's VM-side refusal).
        allow = [ContainerAllowEntry(host=None, address="198.18.1.5", port=443,
                                     reason="oops")]
        with self.assertRaises(ValueError) as cm:
            container_filter_elements(1234, allow)
        self.assertIn("listener range", str(cm.exception))

    def test_filter_commands_are_add_or_delete(self):
        allow = [ContainerAllowEntry(host=None, address="10.0.0.5", port=8080,
                                     reason="db")]
        add_cmds = container_filter_commands(1234, allow, "add")
        self.assertTrue(any("add" in c for c in add_cmds[0]))
        with self.assertRaises(ValueError):
            container_filter_commands(1234, allow, "bogus")

    def test_internal_resolve_raises_naming_host(self):
        with self.assertRaises(ValueError) as cm:
            container_internal_resolve("definitely-not-a-real-host.invalid")
        self.assertIn("does not resolve", str(cm.exception))


class TestContainerInspectPolicy(unittest.TestCase):
    """P1-9: the JSON document workload-container-inspect writes for the
    (substrate-generic) listener to read -- same shape vm_inspect_policy
    produces, per D6."""

    def test_shape_matches_listener_expectations(self):
        net = {
            "hosts": ["*.pypi.org"],
            "internal": [{"host": "db.lan", "reason": "internal service"}],
            "splice": [{"host": "pinned.example.com", "reason": "mTLS"}],
            "policy": [{"host": "api.example.com", "methods": ["POST"],
                       "credential": "anthropic"}],
        }
        doc = container_inspect_policy(net)
        self.assertEqual(doc["tls"], "inspect")  # a policy entry is present
        self.assertEqual(doc["hosts"], ["*.pypi.org"])
        self.assertEqual(doc["internal"], ["db.lan"])
        self.assertEqual(doc["splice"], ["pinned.example.com"])
        self.assertEqual(doc["http2"], [])
        self.assertEqual(doc["policy"], [
            {"host": "api.example.com", "methods": ["POST"], "paths": None,
             "credential": "anthropic"},
        ])

    def test_no_policy_entries_is_splice_mode(self):
        doc = container_inspect_policy({"hosts": ["*.pypi.org"]})
        self.assertEqual(doc["tls"], "splice")

    def test_text_is_deterministic_and_sorted(self):
        net = {"hosts": ["b.com", "a.com"]}
        first = container_inspect_policy_text(net)
        second = container_inspect_policy_text(net)
        self.assertEqual(first, second)
        self.assertTrue(first.endswith("\n"))

    def test_the_document_says_there_is_no_guest_agent(self):
        """The one key this renderer emits and the VM's does not.

        A container has no QEMU guest agent, and the listener's mint-time
        clock remedy works by asking one. Unsaid, that remedy ran here anyway
        -- dialling a socket this substrate has never had, once per mint miss,
        and counting each attempt into a figure published as meaning the
        remedy is INERT IN THIS GUEST. Guaranteed on a container, so it
        reported a broken remedy where there is none to break, with nothing
        red anywhere.
        """
        self.assertIs(container_inspect_policy({"hosts": ["a.com"]})
                      ["guest_agent"], False)

    def test_the_vm_renderer_stays_silent_about_it(self):
        """Absence is what keeps every VM document byte-identical.

        The document is byte-compared for drift, so a key added on both sides
        would report every inspected VM as drifted until it was re-armed --
        for a value that did not change. Containers pay that once because
        their document really did change; VMs must not pay it at all.
        """
        import egress_policy
        self.assertNotIn("guest_agent",
                         egress_policy.vm_inspect_policy({"hosts": ["a.com"]}))


if __name__ == "__main__":
    unittest.main()
