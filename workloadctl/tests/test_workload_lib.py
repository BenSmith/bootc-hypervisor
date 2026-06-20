#!/usr/bin/env python3
"""Unit tests for the shared workload library."""

import os
import socket
import sys
import tempfile
import threading
import unittest
import warnings
from pathlib import Path

# Add lib to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))

from workload_lib import (
    WORKLOADS_BASE, USERNAME_PREFIX, MAX_NAME_LENGTH, NAME_PATTERN,
    GENERATOR_OWNED_DIRECTIVES, SECRET_PATTERN,
    workload_username, workload_service_name, workload_container_name,
    workload_home_dir, workload_state_dir, validate_workload_name, expand_volume_path, dq,
    auto_detect_credentials, resolve_secret_env_vars,
    validate_workload_config, infer_workload_mode, normalize_containers,
    parse_memory_mib, virtiofs_tag, parse_volume_spec, vm_mac_address,
    substitute_template, QMPClient,
    selinux_module_name, selinux_type_name,
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


class TestVmMacAddress(unittest.TestCase):
    def test_locally_administered_unicast(self):
        # Bit 1 of the first byte = locally administered; bit 0 = unicast (0).
        mac = vm_mac_address("fedora-vm")
        first = int(mac.split(":")[0], 16)
        self.assertEqual(first & 0x03, 0x02)

    def test_stable_for_same_name(self):
        self.assertEqual(vm_mac_address("a"), vm_mac_address("a"))

    def test_differs_by_name(self):
        self.assertNotEqual(vm_mac_address("a"), vm_mac_address("b"))


class TestValidateVmConfig(unittest.TestCase):
    def _base(self, **vm_overrides):
        vm = {
            "vcpus": 2,
            "memory": "2048M",
            "cloud_image_url": "https://example.com/x.qcow2",
            "cloud_image_checksum": "sha256:" + "a" * 64,
        }
        vm.update(vm_overrides)
        return {"workload": {"name": "fedora-vm"}, "vm": vm}

    def test_minimal_valid(self):
        self.assertEqual(validate_workload_config(self._base()), [])

    def test_shipped_example_validates(self):
        # Mirrors docs/examples/example-vm-fedora.toml so a regression in the
        # validator that rejects the example will fail loudly here.
        cfg = {
            "workload": {"name": "fedora-vm"},
            "vm": {
                "vcpus": 2,
                "memory": "2048M",
                "cloud_image_url": "https://example.com/Fedora.qcow2",
                "cloud_image_checksum": "sha256:" + "d" * 64,
                "data_disk_size": "50G",
                "user": "fedora",
            },
        }
        self.assertEqual(validate_workload_config(cfg), [])

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
            "vm": {"vcpus": 1, "memory": "512M", "local_image": "/srv/i.qcow2"},
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
            "vm": {"vcpus": 1, "memory": "512M", "local_image": "/srv/x.qcow2"},
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


if __name__ == "__main__":
    unittest.main()
