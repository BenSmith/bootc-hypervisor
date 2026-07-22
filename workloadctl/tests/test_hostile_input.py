#!/usr/bin/env python3
"""Consolidated trust-boundary ("hostile input") regression guard.

One module pinning workloadctl's behavior at five untrusted-input seams. Each
class exercises the REAL shipped guard (imported and called directly), not a
re-implementation:

1. Malicious backup archive  -> cmd_backup._extract_archive (tarfile data
   filter) + cmd_backup._assert_no_escaping_symlinks + validate_workload_name
   on the archive's self-declared name.
2. [host].setup with ".."    -> WorkloadConfig.resolve_control_file_with_source
   (the single control-file chokepoint; rejects "..", takes absolute verbatim).
3. Bad bundle/workload names -> validation.validate_workload_name (NAME_PATTERN).
4. $${SECRET:x} escaping     -> secrets_template.substitute_template AND
   resolve_secret_env_vars (both honor the $$-escape via a single-pass resolver);
   auto_detect_credentials skips the escape so it can't demand a phantom credential.
5. Volume source escaping    -> workload_lib.expand_volume_path /
   _safe_anchor_subpath (anchored subpaths may not be absolute or contain "..").

These are unit-rung tests (plain `just test`); no runtime marker, no host state.
"""
import io
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


import cmd_backup                      # noqa: E402
import workload_lib                    # noqa: E402
import workloadctl_core as core        # noqa: E402
from workload_lib import (             # noqa: E402
    expand_volume_path,
    workload_state_dir,
    _safe_anchor_subpath,
)
from validation import validate_workload_name  # noqa: E402
from secrets_template import (          # noqa: E402
    substitute_template,
    resolve_secret_env_vars,
    auto_detect_credentials,
)


def _make_tar_zst(members: list, dest: Path) -> None:
    """Write a `.tar.zst` archive to `dest` from a list of member specs.

    Each spec is a dict with 'name' plus one of:
      'data'    -> a regular file member with those bytes.
      'symlink' -> a symlink member pointing at that (verbatim) target.
    Members are written with whatever hostile name is given (absolute, "..",
    etc.) so the extraction guard is what's under test, not tarfile's writer.
    """
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for m in members:
            if "symlink" in m:
                ti = tarfile.TarInfo(m["name"])
                ti.type = tarfile.SYMTYPE
                ti.linkname = m["symlink"]
                tf.addfile(ti)
            else:
                payload = m["data"]
                ti = tarfile.TarInfo(m["name"])
                ti.size = len(payload)
                tf.addfile(ti, io.BytesIO(payload))
    raw.seek(0)
    # _extract_archive shells out to the `zstd` binary, so compress with it too.
    proc = subprocess.run(
        ["zstd", "-q", "-o", str(dest), "-"],
        input=raw.getvalue(), capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"zstd failed: {proc.stderr.decode(errors='replace')}")


class TestMaliciousBackupArchive(unittest.TestCase):
    """Boundary 1: restore of a crafted archive must stay inside its sandbox.

    Exercises cmd_backup._extract_archive (untrusted tar read through the
    stdlib `data` filter) and cmd_backup._assert_no_escaping_symlinks. Restore
    lays an archive authored on a possibly-hostile host into root-owned paths,
    so member names / symlink targets are a trust boundary.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.staging = self.tmp / "staging"
        self.staging.mkdir()

    def test_absolute_member_path_is_contained_not_written_outside(self):
        # An absolute member `/etc/workloadctl-pwn` must not land at the real
        # host path; the data filter strips the leading slash so it stays under
        # staging.
        sentinel = Path("/etc/workloadctl-pwn-test")
        self.assertFalse(sentinel.exists(), "precondition: sentinel absent")
        arc = self.tmp / "abs.tar.zst"
        _make_tar_zst([{"name": "/etc/workloadctl-pwn-test", "data": b"x"}], arc)
        try:
            cmd_backup._extract_archive(arc, self.staging)
        except tarfile.TarError:
            pass  # rejecting outright is also acceptable containment
        self.assertFalse(sentinel.exists(),
                         "absolute member escaped to the real /etc")
        # It is contained under staging if extracted at all.
        self.assertTrue((self.staging / "etc" / "workloadctl-pwn-test").exists()
                        or not any(self.staging.iterdir()))

    def test_parent_traversal_member_is_rejected(self):
        # A `../escape` regular member must be refused by the data filter, not
        # written into staging's parent.
        arc = self.tmp / "trav.tar.zst"
        _make_tar_zst([{"name": "../escape", "data": b"x"}], arc)
        with self.assertRaises(tarfile.TarError):
            cmd_backup._extract_archive(arc, self.staging)
        self.assertFalse((self.tmp / "escape").exists(),
                         "traversal member escaped staging")

    def test_absolute_escaping_symlink_rejected(self):
        # The dedicated symlink guard rejects a member symlink whose target
        # resolves outside the extracted tree.
        (self.staging / "bad").symlink_to("/etc")
        with self.assertRaises(ValueError):
            cmd_backup._assert_no_escaping_symlinks(self.staging)

    def test_relative_escaping_symlink_rejected(self):
        (self.staging / "bad").symlink_to("../../etc")
        with self.assertRaises(ValueError):
            cmd_backup._assert_no_escaping_symlinks(self.staging)

    def test_in_tree_symlink_allowed(self):
        (self.staging / "real").write_text("ok")
        (self.staging / "link").symlink_to("real")
        cmd_backup._assert_no_escaping_symlinks(self.staging)  # no raise

    def test_archive_declared_name_traversal_rejected(self):
        # restore reads the workload name from the archive's own workload.toml
        # (raw tomllib, no WorkloadConfig) then builds root-owned dest paths
        # from it, so the name is validated with validate_workload_name.
        for bad in ("../../etc/cron.d/pwn", "../escape", "a/b", "_wl-x", ""):
            with self.assertRaises(ValueError):
                validate_workload_name(bad)


class TestHostSetupTraversal(unittest.TestCase):
    """Boundary 2: a [host].setup path that escapes its bundle/override tree.

    [host].setup resolves through WorkloadConfig.resolve_control_file_with_source
    and is then read+executed as root, so a `..`-laden relpath must be rejected
    there. An absolute path is the documented escape hatch (taken verbatim).
    """

    def setUp(self):
        self.etc = Path(tempfile.mkdtemp())
        self.usr = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.etc, ignore_errors=True))
        self.addCleanup(lambda: shutil.rmtree(self.usr, ignore_errors=True))
        p1 = mock.patch.object(core, "WORKLOAD_BUNDLES_DIR", self.usr)
        p2 = mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.etc)
        p1.start()
        p2.start()
        self.addCleanup(p1.stop)
        self.addCleanup(p2.stop)

    def _config(self, name="app", setup=None):
        body = f'[workload]\nname = "{name}"\n\n[container]\nimage = "localhost/x:latest"\n'
        if setup is not None:
            body += f'\n[host]\nsetup = "{setup}"\n'
        (self.etc / name).mkdir(exist_ok=True)
        (self.etc / name / "workload.toml").write_text(body)
        return core.WorkloadConfig(name)

    def test_setup_parent_traversal_rejected(self):
        cfg = self._config(setup="../../etc/cron.d/pwn")
        with self.assertRaises(ValueError):
            cfg.resolve_control_file_with_source("../../etc/cron.d/pwn")

    def test_setup_single_dotdot_rejected(self):
        cfg = self._config(setup="../evil.sh")
        with self.assertRaises(ValueError):
            cfg.resolve_control_file(cfg.config["host"]["setup"])

    def test_relative_setup_resolves_under_bundle_tree(self):
        cfg = self._config(setup="setup.sh")
        path, source = cfg.resolve_control_file_with_source("setup.sh")
        # Resolves to the shipped-bundle default (no override present).
        self.assertEqual(source, "usr")
        self.assertTrue(path.is_relative_to(self.usr))

    def test_absolute_setup_taken_verbatim(self):
        # Documented escape hatch: an absolute setup path bypasses the chain.
        cfg = self._config(setup="/opt/hooks/setup.sh")
        path, source = cfg.resolve_control_file_with_source("/opt/hooks/setup.sh")
        self.assertEqual(source, "abs")
        self.assertEqual(path, Path("/opt/hooks/setup.sh"))


class TestBadBundleNames(unittest.TestCase):
    """Boundary 3: a workload/bundle name that would break out of
    /etc/workloads.d/<name>/ or the _wl-<name> user.

    validate_workload_name (NAME_PATTERN ^[a-z][a-z0-9-]*$, max 27) is the guard
    every mutating path funnels the name through.
    """

    def test_breakout_and_metachar_names_rejected(self):
        hostile = [
            "",                 # empty
            "/",                # absolute
            "..",               # parent
            "../evil",          # traversal
            "a/b",              # path separator
            "foo bar",          # whitespace
            "foo;rm -rf /",     # shell metachars
            "foo$(id)",         # command substitution
            "foo`id`",          # backticks
            "foo|bar",          # pipe
            "foo\nbar",         # newline
            "-app",             # leading hyphen
            "1app",             # leading digit
            "_wl-x",            # leading underscore (collides with user prefix)
            "MyApp",            # uppercase
            "a" * 28,           # over MAX_NAME_LENGTH (27)
        ]
        for name in hostile:
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_workload_name(name)

    def test_legitimate_names_accepted(self):
        for name in ("app", "my-app", "web1", "a", "a" * 27):
            with self.subTest(name=name):
                validate_workload_name(name)  # no raise


class TestControlCharInjection(unittest.TestCase):
    """Boundary: a container-config string with an embedded newline must not
    reach the generator, or it could inject a following systemd directive.

    validate_workload_config walks the whole container config and rejects any
    string carrying a C0 control char (except tab) or DEL — covering every
    ExecStart token and the raw-spliced [resources.custom_directives] values,
    regardless of whether that particular site is dq()'d.
    """

    def _base(self):
        return {
            "workload": {"name": "app"},
            "container": {"image": "localhost/x:latest"},
        }

    def test_newline_in_env_value_rejected(self):
        from validation import validate_workload_config
        cfg = self._base()
        cfg["container"]["environment"] = {"K": "foo\nExecStartPost=/bin/evil"}
        errors = validate_workload_config(cfg)
        self.assertTrue(
            any("control character" in e for e in errors),
            f"newline env value not rejected: {errors}",
        )

    def test_newline_in_custom_directive_rejected(self):
        from validation import validate_workload_config
        cfg = self._base()
        cfg["resources"] = {"custom_directives": {"Environment": "a\nExecStop=x"}}
        errors = validate_workload_config(cfg)
        self.assertTrue(any("control character" in e for e in errors))

    def test_control_chars_in_various_sites_rejected(self):
        from validation import validate_workload_config
        for mutate in (
            lambda c: c["container"].__setitem__("image", "img\nx"),
            lambda c: c["container"].__setitem__("command", "run\r0"),
            lambda c: c["container"].__setitem__(
                "storage", {"volumes": ["/a:/b\n:ro"]}),
            lambda c: c.__setitem__(
                "security", {"capabilities": ["NET_ADMIN\nfoo"]}),
            lambda c: c.__setitem__("devices", {"devices": ["/dev/x\x00"]}),
        ):
            cfg = self._base()
            mutate(cfg)
            with self.subTest(cfg=cfg):
                errors = validate_workload_config(cfg)
                self.assertTrue(
                    any("control character" in e for e in errors),
                    f"control char not rejected: {errors}",
                )

    def test_tab_and_clean_values_accepted(self):
        from validation import validate_workload_config
        cfg = self._base()
        # tab is allowed; ordinary values must not trip the check
        cfg["container"]["environment"] = {"ARGS": "a\tb", "URL": "https://x/y"}
        errors = validate_workload_config(cfg)
        self.assertFalse(
            any("control character" in e for e in errors),
            f"clean/tab values wrongly rejected: {errors}",
        )


class TestWorkloadTokenValidation(unittest.TestCase):
    """Boundary: a ${WORKLOAD_*} token that will not be expanded must be
    rejected at validate time rather than reaching podman as a literal path.

    Only security_opt expands these. The two ways to get it wrong — a typo in a
    field that does expand, and a correct token in a field that doesn't — both
    otherwise fail late: the first as a dropped option warned about in the boot
    journal, the second as a container that won't start.
    """

    def _base(self):
        return {
            "workload": {"name": "app"},
            "container": {"image": "localhost/x:latest"},
        }

    def _errors(self, cfg):
        from validation import validate_workload_config
        return validate_workload_config(cfg)

    def test_valid_token_in_security_opt_accepted(self):
        cfg = self._base()
        cfg["security"] = {"security_opt": ["seccomp=${WORKLOAD_INSTANCE_DIR}/s.json"]}
        self.assertEqual(self._errors(cfg), [])

    def test_unknown_token_rejected(self):
        cfg = self._base()
        cfg["security"] = {"security_opt": ["seccomp=${WORKLOAD_HOME_DIR}/s.json"]}
        errors = self._errors(cfg)
        self.assertTrue(any("unknown token" in e and "WORKLOAD_HOME_DIR" in e
                            for e in errors), errors)

    def test_valid_token_in_non_expanding_field_rejected(self):
        for mutate in (
            lambda c: c.__setitem__("storage", {"volumes": ["${WORKLOAD_DATA_DIR}/x:/x"]}),
            lambda c: c.__setitem__("devices", {"devices": ["${WORKLOAD_ROOT_DIR}/dev"]}),
            lambda c: c["container"].__setitem__(
                "environment", {"K": "${WORKLOAD_NAME}"}),
        ):
            cfg = self._base()
            mutate(cfg)
            errors = self._errors(cfg)
            self.assertTrue(any("not expanded here" in e for e in errors),
                            f"unexpanded token not rejected: {errors}")

    def test_multi_container_security_opt_accepted(self):
        cfg = {
            "workload": {"name": "app", "mode": "pod"},
            "containers": [{
                "name": "a",
                "container": {"image": "localhost/x:latest"},
                "security": {"security_opt": ["seccomp=${WORKLOAD_INSTANCE_DIR}/s.json"]},
            }],
        }
        self.assertEqual(self._errors(cfg), [])

    def test_no_tokens_is_clean(self):
        cfg = self._base()
        cfg["security"] = {"security_opt": ["label=disable"]}
        self.assertEqual(self._errors(cfg), [])

    def test_vm_config_tokens_rejected(self):
        """No VM field expands tokens, so any of them there is a mistake."""
        cfg = {
            "workload": {"name": "vm1"},
            "vm": {"image": "x.qcow2", "volumes": ["${WORKLOAD_DATA_DIR}/v:/v"]},
        }
        self.assertTrue(any("not expanded here" in e for e in self._errors(cfg)),
                        self._errors(cfg))


class TestVmControlCharInjection(unittest.TestCase):
    """A VM config reaches root units too, and gets the same guard.

    [resources].slice lands in the VM service's Slice=; a [vm].volumes host path
    lands in the virtiofsd ExecStart. Both are emitted verbatim, so a newline
    there would terminate the directive and let the tail parse as a following
    one. The single exemption is [vm.cloud_init].template_vars, which is
    substituted into YAML rather than a unit.
    """

    def _base(self):
        return {
            "workload": {"name": "guest"},
            "vm": {
                "cloud_image_url": "https://example.com/cloud.qcow2",
                "cloud_image_checksum": "sha256:" + "d" * 64,
            },
        }

    def test_newline_in_slice_rejected(self):
        from validation import validate_workload_config
        cfg = self._base()
        cfg["resources"] = {"slice": "workloads.slice\nExecStartPre=/bin/evil"}
        errors = validate_workload_config(cfg)
        self.assertTrue(
            any("control character" in e for e in errors),
            f"newline in [resources].slice not rejected: {errors}",
        )

    def test_newline_in_volume_host_path_rejected(self):
        from validation import validate_workload_config
        cfg = self._base()
        cfg["vm"]["volumes"] = ["/srv/data\nExecStartPost=/bin/evil:/mnt/data"]
        errors = validate_workload_config(cfg)
        self.assertTrue(
            any("control character" in e for e in errors),
            f"newline in [vm].volumes not rejected: {errors}",
        )

    def test_multiline_template_var_accepted(self):
        from validation import validate_workload_config
        cfg = self._base()
        cfg["vm"]["cloud_init"] = {
            "user_data_file": "cloud-init.yaml",
            "template_vars": {"SETUP": "#!/bin/bash\nset -euo pipefail\ndnf -y update\n"},
        }
        errors = validate_workload_config(cfg)
        self.assertFalse(
            any("control character" in e for e in errors),
            f"multi-line template_var wrongly rejected: {errors}",
        )

    def test_control_char_outside_template_vars_still_rejected(self):
        # Pruning template_vars must not blind the guard to the rest of the
        # [vm.cloud_init] table — user_data_file is a path, not YAML.
        from validation import validate_workload_config
        cfg = self._base()
        cfg["vm"]["cloud_init"] = {
            "user_data_file": "cloud-init.yaml\nx",
            "template_vars": {"SETUP": "a\nb"},
        }
        errors = validate_workload_config(cfg)
        self.assertTrue(
            any("control character" in e for e in errors),
            f"newline in user_data_file not rejected: {errors}",
        )


class TestSecretDollarEscape(unittest.TestCase):
    """Boundary 4: the $${SECRET:x} literal-dollar escape must NOT resolve.

    Both resolvers honor it: substitute_template (cloud-init / template rendering)
    and resolve_secret_env_vars ([container.environment]) each run a single
    left-to-right pass where the $$-escaped form collapses to a literal ${SECRET:x}
    and the credential is never read, so no secret leaks. A bare ${SECRET:x} still
    resolves through the respective resolver.
    """

    def test_escaped_secret_is_literal_and_resolver_not_called(self):
        called = []
        out = substitute_template(
            "token=$${SECRET:api-key}",
            secret_resolver=lambda n: called.append(n) or "LEAKED",
        )
        self.assertEqual(out, "token=${SECRET:api-key}")
        self.assertEqual(called, [], "resolver ran for an escaped ref")

    def test_escaped_secret_needs_no_resolver(self):
        # A literal must not reach the missing-resolver KeyError path.
        self.assertEqual(
            substitute_template("$${SECRET:x}"), "${SECRET:x}"
        )

    def test_template_preserves_double_dollar_in_resolved_secret(self):
        # A decrypted secret whose plaintext contains `$$` must be emitted
        # verbatim: the $$-escape collapse applies only to the template author's
        # text, never to substituted-in content (re.sub does not re-scan its
        # replacements). A trailing global collapse would corrupt `a$$b` -> `a$b`.
        out = substitute_template("pw=${SECRET:x}", secret_resolver=lambda n: "a$$b")
        self.assertEqual(out, "pw=a$$b")

    def test_bare_secret_resolves(self):
        out = substitute_template(
            "token=${SECRET:api-key}",
            secret_resolver=lambda n: "resolved-value",
        )
        self.assertEqual(out, "token=resolved-value")

    def test_container_env_path_honors_dollar_escape(self):
        # The container-env resolver honors the same $$ escape as the cloud-init
        # path: `$${SECRET:x}` collapses to a literal `${SECRET:x}` and the
        # credential is NEVER read (no leak). A bare `${SECRET:x}` still resolves.
        creds = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(creds, ignore_errors=True))
        (creds / "x").write_text("SECRETVAL")
        cfg = {
            "container": {
                "environment": {"ESC": "$${SECRET:x}", "REF": "v=${SECRET:x}"}
            }
        }
        resolved = resolve_secret_env_vars(cfg, str(creds))
        self.assertEqual(resolved["ESC"], "${SECRET:x}")
        self.assertNotIn("SECRETVAL", resolved["ESC"])  # no leak through the escape
        self.assertEqual(resolved["REF"], "v=SECRETVAL")  # bare ref resolves

    def test_container_env_escape_never_reads_missing_credential(self):
        # A purely-escaped ref must not touch the credstore at all — even when the
        # named credential is absent it resolves to the literal, not FileNotFound.
        creds = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(creds, ignore_errors=True))
        cfg = {"container": {"environment": {"K": "$${SECRET:absent}"}}}
        resolved = resolve_secret_env_vars(cfg, str(creds))
        self.assertEqual(resolved["K"], "${SECRET:absent}")

    def test_env_and_template_agree_on_odd_dollar_run(self):
        # Regression: `$$${SECRET:x}` must be an inert literal on BOTH paths. A
        # greedy `$$`-pair collapse would re-expose the ${SECRET:x} and leak the
        # secret on the env path while the cloud-init path treats it as literal.
        creds = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(creds, ignore_errors=True))
        (creds / "x").write_text("TOPSECRET")
        env = resolve_secret_env_vars(
            {"container": {"environment": {"K": "$$${SECRET:x}"}}}, str(creds)
        )["K"]
        tpl = substitute_template("$$${SECRET:x}", secret_resolver=lambda n: "TOPSECRET")
        self.assertNotIn("TOPSECRET", env, "env path leaked a secret the template treats as literal")
        self.assertNotIn("TOPSECRET", tpl)
        self.assertEqual(auto_detect_credentials(
            {"container": {"environment": {"K": "$$${SECRET:x}"}}}), set())

    def test_standalone_double_dollar_is_not_collapsed(self):
        # Only the `$${SECRET:` escape is special; an unrelated `$$` in the same
        # value (e.g. a literal in a password) must survive intact, not collapse.
        creds = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(creds, ignore_errors=True))
        (creds / "x").write_text("SV")
        env = resolve_secret_env_vars(
            {"container": {"environment": {"K": "a$$b-${SECRET:x}"}}}, str(creds)
        )["K"]
        self.assertEqual(env, "a$$b-SV")

    def test_auto_detect_skips_escaped_ref(self):
        # The escape must not demand a credential: auto_detect_credentials drives
        # the generator's *mandatory* LoadCredentialEncrypted=, so flagging an
        # escaped `$${SECRET:x}` would fail the unit at boot when no such
        # credential exists. Escaped refs are skipped; real refs still detected.
        cfg = {"container": {"environment": {
            "ESC": "$${SECRET:phantom}",       # escaped -> not needed
            "REF": "${SECRET:real}",           # bare    -> needed
            "MIX": "$${SECRET:lit}-${SECRET:also}",  # only the bare one needed
        }}}
        self.assertEqual(auto_detect_credentials(cfg), {"real", "also"})


class TestVolumeSourceEscapesRoot(unittest.TestCase):
    """Boundary 5: a volume host anchor resolving outside the workload root.

    expand_volume_path -> _expand_anchor -> _safe_anchor_subpath rejects an
    anchored subpath that is absolute or contains "..", so ./ @/ data/ state/
    anchors can never resolve outside <root>/{data,state}. Unanchored absolute
    host paths are the documented pass-through (returned verbatim).
    """

    def setUp(self):
        self.home = str(workload_state_dir("foo"))  # /var/lib/workloads/foo/state
        self.root = "/var/lib/workloads/foo"

    def test_dot_slash_traversal_rejected(self):
        with self.assertRaises(ValueError):
            expand_volume_path("./../escape:/x", self.home)

    def test_data_anchor_deep_traversal_rejected(self):
        with self.assertRaises(ValueError):
            expand_volume_path("data/../../etc/passwd:/x", self.home)

    def test_absolute_anchored_subpath_rejected(self):
        # A double-slash makes the anchored subpath absolute (/etc/passwd).
        with self.assertRaises(ValueError):
            _safe_anchor_subpath("/etc/passwd")
        with self.assertRaises(ValueError):
            expand_volume_path("data//etc/passwd:/x", self.home)

    def test_state_anchor_traversal_rejected(self):
        with self.assertRaises(ValueError):
            expand_volume_path("@/../../../etc:/x", self.home)

    def test_valid_anchor_stays_under_root(self):
        out = expand_volume_path("./conf:/etc/conf:ro", self.home)
        host = out.split(":", 1)[0]
        self.assertTrue(Path(host).is_relative_to(self.root))
        self.assertEqual(host, f"{self.root}/data/conf")

    def test_unanchored_absolute_host_path_passes_through(self):
        # Documented behavior: a non-anchored absolute host source is a verbatim
        # bind mount (operator's responsibility), returned unchanged.
        out = expand_volume_path("/srv/data:/data:ro", self.home)
        self.assertEqual(out, "/srv/data:/data:ro")


if __name__ == "__main__":
    unittest.main()
