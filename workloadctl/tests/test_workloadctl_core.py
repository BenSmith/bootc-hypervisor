#!/usr/bin/env python3
"""Unit tests for workloadctl_core: helpers, WorkloadConfig, WorkloadManager.

Uses a temp WORKLOAD_CONFIG_DIR/WORKLOAD_BUNDLES_DIR (like
test_control_file_resolution.py) so WorkloadConfig can be constructed for
real against on-disk TOML, plus direct unit tests of the pure helper
functions with no filesystem involvement.
"""

import io
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import workload_lib               # noqa: E402
import workloadctl_core as core  # noqa: E402


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

class ParseWorkloadRefTest(unittest.TestCase):
    def test_no_slash(self):
        self.assertEqual(core.parse_workload_ref("foo"), ("foo", None))

    def test_with_slash(self):
        self.assertEqual(core.parse_workload_ref("foo/bar"), ("foo", "bar"))

    def test_multiple_slashes_splits_once(self):
        self.assertEqual(core.parse_workload_ref("foo/bar/baz"), ("foo", "bar/baz"))


class FormatSizeTest(unittest.TestCase):
    def test_bytes(self):
        self.assertEqual(core.format_size(500), "500.0 B")

    def test_kb(self):
        self.assertEqual(core.format_size(2048), "2.0 KB")

    def test_gb(self):
        self.assertEqual(core.format_size(3 * 1024**3), "3.0 GB")

    def test_caps_at_tb(self):
        huge = 5 * 1024**5
        self.assertTrue(core.format_size(huge).endswith("TB"))


class FormatCreatedTest(unittest.TestCase):
    def test_none_is_unknown(self):
        self.assertEqual(core.format_created(None), "unknown")

    def test_empty_string_is_unknown(self):
        self.assertEqual(core.format_created(""), "unknown")

    def test_unix_int_days_ago(self):
        import datetime
        ts = int((datetime.datetime.now() - datetime.timedelta(days=3)).timestamp())
        self.assertEqual(core.format_created(ts), "3 days ago")

    def test_iso_string_hours_ago(self):
        import datetime
        dt = datetime.datetime.now() - datetime.timedelta(hours=2)
        self.assertEqual(core.format_created(dt.isoformat()), "2 hours ago")

    def test_iso_string_with_z_and_fraction(self):
        import datetime
        dt = datetime.datetime.now() - datetime.timedelta(minutes=5)
        s = dt.strftime("%Y-%m-%dT%H:%M:%S.123456Z")
        result = core.format_created(s)
        self.assertTrue(result.endswith("ago"))

    def test_unparseable_is_unknown(self):
        self.assertEqual(core.format_created("not-a-date-at-all!!"), "unknown")

    def test_minute_ago_floor(self):
        import datetime
        dt = datetime.datetime.now() - datetime.timedelta(seconds=5)
        result = core.format_created(dt.isoformat())
        self.assertEqual(result, "1 minute ago")


class CreatedUnixTest(unittest.TestCase):
    def test_none(self):
        self.assertIsNone(core.created_unix(None))

    def test_empty(self):
        self.assertIsNone(core.created_unix(""))

    def test_int_passthrough(self):
        self.assertEqual(core.created_unix(1700000000), 1700000000)

    def test_iso_string(self):
        self.assertEqual(core.created_unix("2023-11-14T22:13:20"), 1700000000)

    def test_float_string_fallback(self):
        # Not valid isoformat -> falls back to float() parse.
        self.assertEqual(core.created_unix("1700000000.5"), 1700000000)

    def test_unparseable_returns_none(self):
        self.assertIsNone(core.created_unix("garbage!!"))


class ParseSizeBytesTest(unittest.TestCase):
    def test_int_passthrough(self):
        self.assertEqual(core.parse_size_bytes(42), 42)

    def test_plain_bytes(self):
        self.assertEqual(core.parse_size_bytes("100B"), 100)

    def test_kb_decimal(self):
        self.assertEqual(core.parse_size_bytes("1.5kB"), int(1.5 * 10**3))

    def test_gib_binary(self):
        self.assertEqual(core.parse_size_bytes("2GiB"), 2 * 1024**3)

    def test_zero_b(self):
        self.assertEqual(core.parse_size_bytes("0 B"), 0)

    def test_bare_number_string(self):
        self.assertEqual(core.parse_size_bytes("123"), 123)

    def test_unparseable_returns_zero(self):
        self.assertEqual(core.parse_size_bytes("nonsense"), 0)

    def test_malformed_suffix_number_returns_zero(self):
        # Ends in "b" (matches the bare "b" suffix) but prefix isn't a float.
        self.assertEqual(core.parse_size_bytes("xyzb"), 0)


class TomlStringTest(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(core.toml_string("hello"), '"hello"')

    def test_escapes_backslash_and_quote(self):
        self.assertEqual(core.toml_string('a\\b"c'), '"a\\\\b\\"c"')

    def test_escapes_newline_tab_cr(self):
        self.assertEqual(core.toml_string("a\nb\tc\rd"), '"a\\nb\\tc\\rd"')

    def test_escapes_control_chars(self):
        self.assertEqual(core.toml_string("a\x01b"), '"a\\u0001b"')


class RequireRootTest(unittest.TestCase):
    def test_root_passes(self):
        with mock.patch("os.geteuid", return_value=0):
            core.require_root()  # should not raise/exit

    def test_non_root_exits_1(self):
        with mock.patch("os.geteuid", return_value=1000):
            buf = io.StringIO()
            with redirect_stderr(buf):
                with self.assertRaises(SystemExit) as cm:
                    core.require_root()
            self.assertEqual(cm.exception.code, 1)
            self.assertIn("must be run as root", buf.getvalue())


class ExceptionsTest(unittest.TestCase):
    def test_workload_masked_message(self):
        exc = core.WorkloadMasked("foo")
        self.assertEqual(exc.name, "foo")
        self.assertIn("foo", str(exc))
        self.assertIn("masked", str(exc))

    def test_workload_user_not_found_message(self):
        exc = core.WorkloadUserNotFound("bar")
        self.assertEqual(exc.name, "bar")
        self.assertIn("bar", str(exc))
        self.assertIn("enable bar", str(exc))


# ---------------------------------------------------------------------------
# WorkloadConfig, backed by real temp TOML files
# ---------------------------------------------------------------------------

class WorkloadConfigTestBase(unittest.TestCase):
    def setUp(self):
        self.etc = Path(tempfile.mkdtemp())
        self.usr = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.etc, ignore_errors=True))
        self.addCleanup(lambda: shutil.rmtree(self.usr, ignore_errors=True))
        self._p1 = mock.patch.object(core, "WORKLOAD_BUNDLES_DIR", self.usr)
        self._p2 = mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.etc)
        self._p1.start()
        self._p2.start()
        self.addCleanup(self._p1.stop)
        self.addCleanup(self._p2.stop)

    def _write(self, name: str, body: str):
        (self.etc / name).mkdir(exist_ok=True, parents=True)
        (self.etc / name / "workload.toml").write_text(body)

    def _config(self, name: str, body: str) -> "core.WorkloadConfig":
        self._write(name, body)
        return core.WorkloadConfig(name)


class WorkloadConfigConstructionTest(WorkloadConfigTestBase):
    def test_missing_config_raises_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            core.WorkloadConfig("nope")

    def test_masked_symlink_raises_workload_masked(self):
        (self.etc / "ghost").mkdir()
        (self.etc / "ghost" / "workload.toml").symlink_to("/dev/null")
        with self.assertRaises(core.WorkloadMasked):
            core.WorkloadConfig("ghost")

    def test_name_mismatch_raises_value_error(self):
        self._write("realname", '[workload]\nname = "othername"\n\n'
                                 '[container]\nimage = "x"\n')
        with self.assertRaises(ValueError):
            core.WorkloadConfig("realname")

    def test_invalid_name_rejected(self):
        self._write("Bad_Name", '[workload]\nname = "Bad_Name"\n\n'
                                 '[container]\nimage = "x"\n')
        with self.assertRaises(ValueError):
            core.WorkloadConfig("Bad_Name")

    def test_valid_config_loads(self):
        cfg = self._config("ok", '[workload]\nname = "ok"\n\n'
                                  '[container]\nimage = "localhost/x:latest"\n')
        self.assertEqual(cfg.name, "ok")
        self.assertEqual(cfg.kind, "container")
        self.assertFalse(cfg.is_vm)
        self.assertEqual(cfg.image, "localhost/x:latest")

    def test_no_filename_alias(self):
        # `name` is the single identity attribute; the old `.filename` alias
        # (which duplicated `.name`) is gone. Guard against reintroducing it.
        cfg = self._config("ok", '[workload]\nname = "ok"\n\n'
                                  '[container]\nimage = "x"\n')
        self.assertFalse(hasattr(cfg, "filename"))


class WorkloadConfigVmImageTest(WorkloadConfigTestBase):
    def test_vm_image_field(self):
        cfg = self._config("vm1", '[workload]\nname = "vm1"\n\n'
                                   '[vm]\nimage = "vmimg"\n')
        self.assertTrue(cfg.is_vm)
        self.assertEqual(cfg.image, "vmimg")

    def test_vm_cloud_image_url_fallback(self):
        cfg = self._config("vm2", '[workload]\nname = "vm2"\n\n'
                                   '[vm]\ncloud_image_url = "http://x/img.qcow2"\n')
        self.assertEqual(cfg.image, "http://x/img.qcow2")

    def test_vm_local_image_fallback(self):
        cfg = self._config("vm3", '[workload]\nname = "vm3"\n\n'
                                   '[vm]\nlocal_image = "/path/img.qcow2"\n')
        self.assertEqual(cfg.image, "/path/img.qcow2")

    def test_vm_no_image_returns_placeholder(self):
        cfg = self._config("vm4", '[workload]\nname = "vm4"\n\n[vm]\n')
        self.assertEqual(cfg.image, "(vm)")


class WorkloadConfigLifecycleTest(WorkloadConfigTestBase):
    def test_default_lifecycle_cattle(self):
        cfg = self._config("c1", '[workload]\nname = "c1"\n\n'
                                  '[container]\nimage = "x"\n')
        self.assertEqual(cfg.lifecycle, "cattle")

    def test_pet_lifecycle(self):
        cfg = self._config("p1", '[workload]\nname = "p1"\nlifecycle = "pet"\n\n'
                                  '[container]\nimage = "x"\n')
        self.assertEqual(cfg.lifecycle, "pet")

    def test_default_snapshot_keep(self):
        cfg = self._config("s1", '[workload]\nname = "s1"\n\n'
                                  '[container]\nimage = "x"\n')
        self.assertEqual(cfg.snapshot_keep, 3)

    def test_explicit_snapshot_keep(self):
        cfg = self._config("s2", '[workload]\nname = "s2"\nsnapshot_keep = 7\n\n'
                                  '[container]\nimage = "x"\n')
        self.assertEqual(cfg.snapshot_keep, 7)

    def test_invalid_snapshot_keep_falls_back_to_default(self):
        cfg = self._config("s3", '[workload]\nname = "s3"\nsnapshot_keep = 0\n\n'
                                  '[container]\nimage = "x"\n')
        self.assertEqual(cfg.snapshot_keep, 3)

    def test_bool_snapshot_keep_falls_back_to_default(self):
        cfg = self._config("s4", '[workload]\nname = "s4"\nsnapshot_keep = true\n\n'
                                  '[container]\nimage = "x"\n')
        self.assertEqual(cfg.snapshot_keep, 3)


class WorkloadConfigBundleTest(WorkloadConfigTestBase):
    def test_selinux_policy_default_false(self):
        cfg = self._config("n1", '[workload]\nname = "n1"\n\n'
                                  '[container]\nimage = "x"\n')
        self.assertFalse(cfg.selinux_policy)
        self.assertIsNone(cfg.selinux_bundle)

    def test_selinux_policy_true_uses_bundle(self):
        cfg = self._config("n2", '[workload]\nname = "n2"\nbundle = "b2"\n\n'
                                  '[security]\nselinux_policy = true\n\n'
                                  '[container]\nimage = "x"\n')
        self.assertTrue(cfg.selinux_policy)
        self.assertEqual(cfg.selinux_bundle, "b2")

    def test_resolve_control_file_rejects_dotdot(self):
        cfg = self._config("n3", '[workload]\nname = "n3"\n\n'
                                  '[container]\nimage = "x"\n')
        with self.assertRaises(ValueError):
            cfg.resolve_control_file("../evil")

    def test_resolve_control_file_absolute_path(self):
        cfg = self._config("n4", '[workload]\nname = "n4"\n\n'
                                  '[container]\nimage = "x"\n')
        path, source = cfg.resolve_control_file_with_source("/abs/path")
        self.assertEqual(source, "abs")
        self.assertEqual(path, Path("/abs/path"))

    def test_resolve_control_file_usr_default(self):
        cfg = self._config("n5", '[workload]\nname = "n5"\n\n'
                                  '[container]\nimage = "x"\n')
        path, source = cfg.resolve_control_file_with_source("build.sh")
        self.assertEqual(source, "usr")
        self.assertEqual(path, self.usr / "n5" / "build.sh")

    def test_resolve_control_file_etc_override_wins(self):
        cfg = self._config("n6", '[workload]\nname = "n6"\n\n'
                                  '[container]\nimage = "x"\n')
        override = self.etc / "n6" / "build.sh"
        override.write_text("override")
        path, source = cfg.resolve_control_file_with_source("build.sh")
        self.assertEqual(source, "etc")
        self.assertEqual(path, override)


class WorkloadConfigBuildTest(WorkloadConfigTestBase):
    def test_build_defaults(self):
        cfg = self._config("bd1", '[workload]\nname = "bd1"\n\n'
                                   '[container]\nimage = "localhost/bd1:latest"\n'
                                   'pull = "never"\n')
        self.assertIsNone(cfg.build_script)
        self.assertEqual(cfg.build_containerfile, "Containerfile")
        self.assertEqual(cfg.build_args, {})
        self.assertEqual(cfg.build_arg_env, [])
        self.assertIsNone(cfg.build_target)
        self.assertEqual(cfg.build_images(), ["localhost/bd1:latest"])

    def test_has_build_context_false_without_containerfile(self):
        cfg = self._config("bd2", '[workload]\nname = "bd2"\n\n'
                                   '[container]\nimage = "localhost/bd2:latest"\n'
                                   'pull = "never"\n')
        self.assertFalse(cfg.has_build_context())

    def test_has_build_context_true_with_containerfile(self):
        (self.usr / "bd3").mkdir(parents=True)
        (self.usr / "bd3" / "Containerfile").write_text("FROM scratch\n")
        cfg = self._config("bd3", '[workload]\nname = "bd3"\n\n'
                                   '[container]\nimage = "localhost/bd3:latest"\n'
                                   'pull = "never"\n')
        self.assertTrue(cfg.has_build_context())

    def test_build_script_and_target_and_args(self):
        cfg = self._config(
            "bd4",
            '[workload]\nname = "bd4"\n\n'
            '[build]\nscript = "custom.sh"\ntarget = "final"\n'
            'args = { FOO = "bar" }\narg_env = ["BAZ"]\n\n'
            '[container]\nimage = "x"\n',
        )
        self.assertEqual(cfg.build_script, "custom.sh")
        self.assertEqual(cfg.build_target, "final")
        self.assertEqual(cfg.build_args, {"FOO": "bar"})
        self.assertEqual(cfg.build_arg_env, ["BAZ"])


class WorkloadConfigUidGidTest(WorkloadConfigTestBase):
    def test_uid_raises_workload_user_not_found(self):
        cfg = self._config("u1", '[workload]\nname = "u1"\n\n'
                                  '[container]\nimage = "x"\n')
        with mock.patch("pwd.getpwnam", side_effect=KeyError("no such user")):
            with self.assertRaises(core.WorkloadUserNotFound):
                _ = cfg.uid

    def test_gid_raises_workload_user_not_found(self):
        cfg = self._config("u2", '[workload]\nname = "u2"\n\n'
                                  '[container]\nimage = "x"\n')
        with mock.patch("pwd.getpwnam", side_effect=KeyError("no such user")):
            with self.assertRaises(core.WorkloadUserNotFound):
                _ = cfg.gid

    def test_uid_gid_resolve_via_pwd(self):
        cfg = self._config("u3", '[workload]\nname = "u3"\n\n'
                                  '[container]\nimage = "x"\n')
        fake_pw = mock.Mock(pw_uid=10123, pw_gid=10123)
        with mock.patch("pwd.getpwnam", return_value=fake_pw):
            self.assertEqual(cfg.uid, 10123)
            self.assertEqual(cfg.gid, 10123)


class WorkloadConfigMultiContainerTest(WorkloadConfigTestBase):
    def _multi(self):
        return self._config(
            "multi",
            '[workload]\nname = "multi"\n\n'
            '[[containers]]\nname = "web"\n'
            '[containers.container]\nimage = "web:latest"\n'
            'pull = "always"\n'
            '[containers.storage]\nvolumes = ["./web-data:/data"]\n\n'
            '[[containers]]\nname = "db"\n'
            '[containers.container]\nimage = "db:latest"\n'
            '[containers.container.health]\ncmd = ["pg_isready"]\n',
        )

    def test_is_multi_true(self):
        cfg = self._multi()
        self.assertTrue(cfg.is_multi)
        self.assertEqual(cfg.container_names(), ["web", "db"])

    def test_container_image_lookup(self):
        cfg = self._multi()
        self.assertEqual(cfg.container_image("web"), "web:latest")
        self.assertEqual(cfg.container_image("db"), "db:latest")

    def test_container_image_missing_raises_keyerror(self):
        cfg = self._multi()
        with self.assertRaises(KeyError):
            cfg.container_image("nope")

    def test_container_images(self):
        cfg = self._multi()
        self.assertEqual(cfg.container_images(),
                          [("web", "web:latest"), ("db", "db:latest")])

    def test_container_specs(self):
        cfg = self._multi()
        self.assertEqual(
            cfg.container_specs(),
            [("web", "web:latest", "always"), ("db", "db:latest", "missing")],
        )

    def test_all_volumes_multi(self):
        cfg = self._multi()
        self.assertEqual(cfg.all_volumes(), ["./web-data:/data"])

    def test_sub_service_names_multi(self):
        cfg = self._multi()
        self.assertEqual(
            cfg.sub_service_names(),
            ["workload-multi-web.service", "workload-multi-db.service"],
        )

    def test_podman_container_name_multi(self):
        cfg = self._multi()
        self.assertEqual(cfg.podman_container_name("web"), "workload-multi-web")

    def test_has_health_check_true_and_blocks(self):
        cfg = self._multi()
        self.assertTrue(cfg.has_health_check())
        blocks = cfg.container_health_blocks()
        self.assertEqual(len(blocks), 1)
        local, podman_name, health = blocks[0]
        self.assertEqual(local, "db")
        self.assertEqual(podman_name, "workload-multi-db")
        self.assertEqual(health["cmd"], ["pg_isready"])


class WorkloadConfigSingleContainerTest(WorkloadConfigTestBase):
    def _single(self, extra=""):
        return self._config(
            "single",
            '[workload]\nname = "single"\n\n'
            '[container]\nimage = "x:latest"\n' + extra,
        )

    def test_is_multi_false(self):
        cfg = self._single()
        self.assertFalse(cfg.is_multi)
        self.assertEqual(cfg.container_names(), ["single"])

    def test_container_image_single(self):
        cfg = self._single()
        self.assertEqual(cfg.container_image("single"), "x:latest")

    def test_container_specs_single(self):
        cfg = self._single('pull = "never"\n')
        self.assertEqual(cfg.container_specs(), [("single", "x:latest", "never")])

    def test_sub_service_names_single(self):
        cfg = self._single()
        self.assertEqual(cfg.sub_service_names(), [cfg.service_name])

    def test_podman_container_name_single(self):
        cfg = self._single()
        self.assertEqual(cfg.podman_container_name("anything"), cfg.container_name)

    def test_no_health_check_by_default(self):
        cfg = self._single()
        self.assertFalse(cfg.has_health_check())
        self.assertEqual(cfg.container_health_blocks(), [])

    def test_get_network_ports_volumes_groups(self):
        cfg = self._config(
            "netcfg",
            '[workload]\nname = "netcfg"\n\n'
            '[container]\nimage = "x"\n\n'
            '[network]\nmode = "bridge"\nports = ["8080:80"]\n\n'
            '[storage]\nvolumes = ["./d:/data"]\n\n'
            '[security]\nextra_groups = ["video"]\n',
        )
        self.assertEqual(cfg.get_network_mode(), "bridge")
        self.assertEqual(cfg.get_ports(), ["8080:80"])
        self.assertEqual(cfg.get_volumes(), ["./d:/data"])
        self.assertEqual(cfg.all_volumes(), ["./d:/data"])
        self.assertEqual(cfg.get_extra_groups(), ["video"])

    def test_default_network_mode_pasta(self):
        cfg = self._single()
        self.assertEqual(cfg.get_network_mode(), "pasta")
        self.assertEqual(cfg.get_ports(), [])
        self.assertEqual(cfg.get_extra_groups(), [])

    def test_required_files_skips_missing_path_and_expands_anchor(self):
        cfg = self._config(
            "reqf",
            '[workload]\nname = "reqf"\n\n'
            '[container]\nimage = "x"\n\n'
            '[[setup.required_files]]\npath = "./secret.env"\nhint = "put it here"\n\n'
            '[[setup.required_files]]\nhint = "no path, skipped"\n',
        )
        result = cfg.get_required_files()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["hint"], "put it here")
        self.assertTrue(result[0]["path"].endswith("secret.env"))
        self.assertEqual(result[0]["path"], str(cfg.data_dir / "secret.env"))


class WorkloadConfigPodmanTargetsTest(WorkloadConfigTestBase):
    """Table test over single/pod/bridge/multi modes for podman_targets()."""

    def test_podman_targets_by_mode(self):
        cases = [
            ("single", '[workload]\nname = "single"\n\n'
                       '[container]\nimage = "x:latest"\n',
             ["workload-single"]),
            ("podmode", '[workload]\nname = "podmode"\nmode = "pod"\n\n'
                        '[[containers]]\nname = "web"\n'
                        '[containers.container]\nimage = "web:latest"\n\n'
                        '[[containers]]\nname = "db"\n'
                        '[containers.container]\nimage = "db:latest"\n',
             ["workload-podmode-web", "workload-podmode-db"]),
            ("bridgemode", '[workload]\nname = "bridgemode"\nmode = "bridge"\n\n'
                           '[[containers]]\nname = "web"\n'
                           '[containers.container]\nimage = "web:latest"\n\n'
                           '[[containers]]\nname = "db"\n'
                           '[containers.container]\nimage = "db:latest"\n',
             ["workload-bridgemode-web", "workload-bridgemode-db"]),
            ("multi", '[workload]\nname = "multi"\n\n'
                      '[[containers]]\nname = "web"\n'
                      '[containers.container]\nimage = "web:latest"\n\n'
                      '[[containers]]\nname = "db"\n'
                      '[containers.container]\nimage = "db:latest"\n',
             ["workload-multi-web", "workload-multi-db"]),
        ]
        for name, body, expected in cases:
            with self.subTest(name=name):
                cfg = self._config(name, body)
                self.assertEqual(cfg.podman_targets(), expected)


class WorkloadConfigMiscPropsTest(WorkloadConfigTestBase):
    def test_vm_bridge_default(self):
        cfg = self._config("vmb1", '[workload]\nname = "vmb1"\n\n[vm]\n')
        self.assertEqual(cfg.vm_bridge, workload_lib.VM_BRIDGE_NAME)

    def test_vm_bridge_custom(self):
        cfg = self._config(
            "vmb2",
            '[workload]\nname = "vmb2"\n\n[vm]\n[vm.network]\nbridge = "br-custom"\n',
        )
        self.assertEqual(cfg.vm_bridge, "br-custom")

    def test_enabled_reflects_marker_file(self):
        cfg = self._config("en1", '[workload]\nname = "en1"\n\n'
                                   '[container]\nimage = "x"\n')
        self.assertFalse(cfg.enabled)
        (self.etc / "en1" / ".enabled").touch()
        self.assertTrue(cfg.enabled)

    def test_username_service_container_home_state_data(self):
        cfg = self._config("paths1", '[workload]\nname = "paths1"\n\n'
                                      '[container]\nimage = "x"\n')
        self.assertEqual(cfg.username, workload_lib.workload_username("paths1"))
        self.assertEqual(cfg.service_name,
                          workload_lib.workload_service_name("paths1"))
        self.assertEqual(cfg.container_name,
                          workload_lib.workload_container_name("paths1"))
        self.assertEqual(cfg.home_dir, workload_lib.workload_home_dir("paths1"))
        self.assertEqual(cfg.state_dir, workload_lib.workload_state_dir("paths1"))
        self.assertEqual(cfg.data_dir, workload_lib.workload_data_dir("paths1"))

    def test_mode_property(self):
        cfg = self._config("modecfg", '[workload]\nname = "modecfg"\n\n'
                                       '[container]\nimage = "x"\n')
        self.assertEqual(cfg.mode, workload_lib.infer_workload_mode(cfg.config))


# ---------------------------------------------------------------------------
# resolve_container_target
# ---------------------------------------------------------------------------

class ResolveContainerTargetTest(unittest.TestCase):
    def _fake_config(self, is_multi, names=None, podman_name=None,
                      container_name=None):
        cfg = mock.Mock()
        cfg.is_multi = is_multi
        cfg.container_name = container_name
        if names is not None:
            cfg.container_names.return_value = names
        if podman_name is not None:
            cfg.podman_container_name.return_value = podman_name
        return cfg

    def test_single_container_no_suffix(self):
        cfg = self._fake_config(False, container_name="workload-foo")
        result = core.resolve_container_target(cfg, None, "foo")
        self.assertEqual(result, "workload-foo")

    def test_single_container_with_suffix_errors(self):
        cfg = self._fake_config(False, container_name="workload-foo")
        buf = io.StringIO()
        with redirect_stderr(buf):
            with self.assertRaises(core.UsageError):
                core.resolve_container_target(cfg, "extra", "foo")
        self.assertIn("single-container", buf.getvalue())

    def test_multi_container_missing_suffix_errors(self):
        cfg = self._fake_config(True, names=["web", "db"])
        buf = io.StringIO()
        with redirect_stderr(buf):
            with self.assertRaises(core.UsageError):
                core.resolve_container_target(cfg, None, "multi")
        self.assertIn("multiple containers", buf.getvalue())
        self.assertIn("web, db", buf.getvalue())

    def test_multi_container_bad_name_errors(self):
        cfg = self._fake_config(True, names=["web", "db"])
        buf = io.StringIO()
        with redirect_stderr(buf):
            with self.assertRaises(core.UsageError):
                core.resolve_container_target(cfg, "cache", "multi")
        self.assertIn("not in workload", buf.getvalue())

    def test_multi_container_valid_name_resolves(self):
        cfg = self._fake_config(True, names=["web", "db"],
                                 podman_name="workload-multi-web")
        result = core.resolve_container_target(cfg, "web", "multi")
        self.assertEqual(result, "workload-multi-web")
        cfg.podman_container_name.assert_called_once_with("web")


# ---------------------------------------------------------------------------
# WorkloadManager
# ---------------------------------------------------------------------------

class WorkloadManagerTest(WorkloadConfigTestBase):
    def setUp(self):
        super().setUp()
        self._pwl = mock.patch.object(core, "workload_config_dir",
                                       return_value=self.etc)
        self._pwl.start()
        self.addCleanup(self._pwl.stop)

    def test_get_all_configs_skips_masked_and_broken(self):
        # Good workload.
        self._write("good", '[workload]\nname = "good"\n\n'
                             '[container]\nimage = "x"\n')
        # Masked workload (symlink to /dev/null).
        (self.etc / "masked").mkdir()
        (self.etc / "masked" / "workload.toml").symlink_to("/dev/null")
        # Broken workload (bad TOML content -> load error).
        self._write("broken", "not = [valid toml")

        mgr = core.WorkloadManager()
        buf = io.StringIO()
        with redirect_stderr(buf):
            configs = mgr.get_all_configs()
        names = [c.name for c in configs]
        self.assertEqual(names, ["good"])
        self.assertIn("Warning: Failed to load", buf.getvalue())
        self.assertNotIn("masked", buf.getvalue())

    def test_get_all_configs_enabled_only(self):
        self._write("en", '[workload]\nname = "en"\n\n[container]\nimage = "x"\n')
        self._write("dis", '[workload]\nname = "dis"\n\n[container]\nimage = "x"\n')
        (self.etc / "en" / ".enabled").touch()

        mgr = core.WorkloadManager()
        configs = mgr.get_all_configs(enabled_only=True)
        self.assertEqual([c.name for c in configs], ["en"])

    def test_user_exists_true_false(self):
        cfg = self._config("ue", '[workload]\nname = "ue"\n\n'
                                  '[container]\nimage = "x"\n')
        mgr = core.WorkloadManager()
        with mock.patch("pwd.getpwnam", return_value=mock.Mock()):
            self.assertTrue(mgr.user_exists(cfg))
        with mock.patch("pwd.getpwnam", side_effect=KeyError()):
            self.assertFalse(mgr.user_exists(cfg))

    def test_podman_memoizes_per_uid(self):
        cfg = self._config("pm1", '[workload]\nname = "pm1"\n\n'
                                   '[container]\nimage = "x"\n')
        mgr = core.WorkloadManager()
        fake_pw = mock.Mock(pw_uid=10500, pw_gid=10500)
        fake_client = mock.Mock()
        with mock.patch("pwd.getpwnam", return_value=fake_pw), \
             mock.patch.object(core.Podman, "for_user",
                                return_value=fake_client) as for_user:
            client1 = mgr.podman(cfg)
            client2 = mgr.podman(cfg)
        self.assertIs(client1, fake_client)
        self.assertIs(client2, fake_client)
        for_user.assert_called_once_with(mock.ANY, 10500, cfg.home_dir)
        self.assertEqual(for_user.call_count, 1)

    def test_get_image_id_delegates_to_podman(self):
        cfg = self._config("gi1", '[workload]\nname = "gi1"\n\n'
                                   '[container]\nimage = "localhost/gi1:latest"\n')
        mgr = core.WorkloadManager()
        fake_pw = mock.Mock(pw_uid=10600, pw_gid=10600)
        fake_client = mock.Mock()
        fake_client.image_id.return_value = "sha256:abc"
        with mock.patch("pwd.getpwnam", return_value=fake_pw), \
             mock.patch.object(core.Podman, "for_user", return_value=fake_client):
            result = mgr.get_image_id(cfg)
        self.assertEqual(result, "sha256:abc")
        fake_client.image_id.assert_called_once_with("localhost/gi1:latest")

    def test_run_podman_exec_and_run_podman_delegate(self):
        cfg = self._config("rp1", '[workload]\nname = "rp1"\n\n'
                                   '[container]\nimage = "x"\n')
        mgr = core.WorkloadManager()
        fake_pw = mock.Mock(pw_uid=10700, pw_gid=10700)
        fake_client = mock.Mock()
        fake_client.run.return_value = "ok"
        with mock.patch("pwd.getpwnam", return_value=fake_pw), \
             mock.patch.object(core.Podman, "for_user", return_value=fake_client):
            r1 = mgr.run_podman_exec(cfg, ["echo", "hi"], check=True)
            r2 = mgr.run_podman(cfg, "ps", "-a", capture_output=True)
        self.assertEqual(r1, "ok")
        self.assertEqual(r2, "ok")
        fake_client.run.assert_any_call("exec", "echo", "hi",
                                         check=True, capture_output=False)
        fake_client.run.assert_any_call("ps", "-a",
                                         check=False, capture_output=True)


if __name__ == "__main__":
    unittest.main()
