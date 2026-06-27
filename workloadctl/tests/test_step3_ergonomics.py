#!/usr/bin/env python3
"""Step 3 management ergonomics: info --files, edit <name> <file>, build <name>.

These exercise the lazy-override surface that makes control files livable:
- `info --files` (cmd_inspect._collect_control_files) — the merged view reporting
  whether each control file wins from /etc (override) or /usr (shipped).
- `edit <name> <file>` (cmd_admin._edit_control_file) — copy-on-write seed of an
  /etc override, with systemctl-edit-style discard when the result matches the
  shipped default (or is an untouched empty new file).
- `build <name>` (cmd_lifecycle.cmd_build) — resolve+run the bundle's build.sh,
  override-aware.

Pattern mirrors test_control_file_resolution: temp /usr (bundles) + temp /etc
(configs + overrides), patched into the core namespace so resolution is honored.
"""
import argparse
import io
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import workload_lib               # noqa: E402
import workloadctl_core as core   # noqa: E402
import cmd_admin                  # noqa: E402
import cmd_inspect                # noqa: E402
import cmd_lifecycle              # noqa: E402
from workloadctl_core import WorkloadConfig, WorkloadManager  # noqa: E402


def _ns(**kw):
    return argparse.Namespace(**kw)


def _script_editor(body: str) -> str:
    """Write an executable shell 'editor' that runs `body` with $1 = the file."""
    fd, path = tempfile.mkstemp(suffix=".sh")
    os.write(fd, ("#!/bin/sh\n" + body + "\n").encode())
    os.close(fd)
    os.chmod(path, 0o755)
    return path


class Step3Base(unittest.TestCase):
    def setUp(self):
        self.etc = Path(tempfile.mkdtemp())
        self.usr = Path(tempfile.mkdtemp())
        import shutil
        self.addCleanup(lambda: shutil.rmtree(self.etc, ignore_errors=True))
        self.addCleanup(lambda: shutil.rmtree(self.usr, ignore_errors=True))
        for p in (
            mock.patch.object(core, "WORKLOAD_BUNDLES_DIR", self.usr),
            mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.etc),
            mock.patch.object(cmd_admin, "require_root", lambda: None),
            mock.patch.object(cmd_lifecycle, "require_root", lambda: None),
        ):
            p.start()
            self.addCleanup(p.stop)
        self.manager = WorkloadManager()
        self._editors = []
        self.addCleanup(self._cleanup_editors)

    def _cleanup_editors(self):
        for e in self._editors:
            try:
                os.unlink(e)
            except FileNotFoundError:
                pass

    def _editor(self, body):
        path = _script_editor(body)
        self._editors.append(path)
        return path

    def _config(self, name, bundle=None, *, extra=""):
        body = f'[workload]\nname = "{name}"\nenabled = false\n'
        if bundle is not None:
            body += f'bundle = "{bundle}"\n'
        body += '\n[container]\nimage = "localhost/x:latest"\n' + extra
        (self.etc / name).mkdir(exist_ok=True)
        (self.etc / name / "workload.toml").write_text(body)
        return WorkloadConfig(name)

    def _ship(self, bundle, fname, content="shipped\n"):
        d = self.usr / bundle
        d.mkdir(parents=True, exist_ok=True)
        (d / fname).write_text(content)
        return d / fname

    def _override_file(self, name, fname, content="override\n"):
        d = self.etc / name
        d.mkdir(parents=True, exist_ok=True)
        (d / fname).write_text(content)
        return d / fname


# ---------------------------------------------------------------------------
# Stage B — info --files merged view
# ---------------------------------------------------------------------------

class TestControlFilesView(Step3Base):
    def test_unions_present_files_with_winning_source(self):
        self._ship("solo", "build.sh")
        self._ship("solo", "Containerfile")
        self._ship("solo", "policy.cil")
        self._override_file("solo", "policy.cil")  # override wins for this one
        cfg = self._config("solo")
        files = {f["file"]: f for f in cmd_inspect._collect_control_files(cfg)}
        self.assertEqual(set(files), {"build.sh", "Containerfile", "policy.cil"})
        self.assertEqual(files["build.sh"]["source"], "usr")
        self.assertTrue(files["build.sh"]["exists"])
        self.assertEqual(files["policy.cil"]["source"], "etc")
        self.assertTrue(files["policy.cil"]["path"].startswith(str(self.etc)))

    def test_excludes_workload_toml(self):
        self._ship("solo", "workload.toml", 'name="solo"')
        self._ship("solo", "build.sh")
        cfg = self._config("solo")
        names = {f["file"] for f in cmd_inspect._collect_control_files(cfg)}
        self.assertEqual(names, {"build.sh"})

    def test_declared_but_missing_setup_surfaced(self):
        cfg = self._config("solo", extra='\n[host]\nsetup = "setup.sh"\n')
        files = {f["file"]: f for f in cmd_inspect._collect_control_files(cfg)}
        self.assertIn("setup.sh", files)
        self.assertEqual(files["setup.sh"]["source"], "usr")
        self.assertFalse(files["setup.sh"]["exists"])

    def test_absolute_setup_not_listed(self):
        cfg = self._config("solo", extra='\n[host]\nsetup = "/opt/x/setup.sh"\n')
        names = {f["file"] for f in cmd_inspect._collect_control_files(cfg)}
        self.assertEqual(names, set())

    def test_copy_resolves_against_source_bundle(self):
        self._ship("src-bundle", "build.sh")
        cfg = self._config("copy", bundle="src-bundle")
        files = {f["file"]: f for f in cmd_inspect._collect_control_files(cfg)}
        self.assertEqual(files["build.sh"]["source"], "usr")
        self.assertTrue(files["build.sh"]["path"].startswith(str(self.usr / "src-bundle")))

    def test_nested_control_files_listed(self):
        # edit accepts nested relpaths and the build context can carry subdirs,
        # so a nested file must show in the merged view (not silently shadow).
        d = self.usr / "solo" / "rootfs"
        d.mkdir(parents=True)
        (d / "extra.conf").write_text("x\n")
        cfg = self._config("solo")
        files = {f["file"]: f for f in cmd_inspect._collect_control_files(cfg)}
        self.assertIn("rootfs/extra.conf", files)
        self.assertEqual(files["rootfs/extra.conf"]["source"], "usr")
        self.assertTrue(files["rootfs/extra.conf"]["exists"])

    def test_print_no_control_files(self):
        cfg = self._config("solo")
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_inspect._print_control_files(cfg, json_mode=False)
        self.assertIn("No control files", buf.getvalue())

    def test_json_shape(self):
        self._ship("solo", "build.sh")
        cfg = self._config("solo")
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_inspect._print_control_files(cfg, json_mode=True)
        import json
        data = json.loads(buf.getvalue())
        self.assertEqual(data["workload"], "solo")
        self.assertEqual(data["bundle"], "solo")
        self.assertEqual(data["control_files"][0]["file"], "build.sh")


# ---------------------------------------------------------------------------
# Stage C — edit <name> <file>
# ---------------------------------------------------------------------------

class TestEditControlFile(Step3Base):
    def _edit(self, name, fname, editor_body):
        with mock.patch.dict(os.environ, {"EDITOR": self._editor(editor_body)}):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cmd_admin.cmd_edit(_ns(workload=name, file=fname, yes=False),
                                   self.manager)
            return buf.getvalue()

    def test_seed_from_shipped_then_modify(self):
        self._ship("solo", "build.sh", "ORIGINAL\n")
        self._config("solo")
        self._edit("solo", "build.sh", 'printf "CHANGED\\n" > "$1"')
        override = self.etc / "solo" / "build.sh"
        self.assertTrue(override.exists())
        self.assertEqual(override.read_text(), "CHANGED\n")
        # And it now wins resolution.
        path, source = WorkloadConfig("solo").resolve_control_file_with_source("build.sh")
        self.assertEqual(source, "etc")
        self.assertEqual(path, override)

    def test_identical_to_default_is_discarded(self):
        default = self._ship("solo", "build.sh", "SAME\n")
        self._config("solo")
        # Editor "writes" the exact shipped bytes back (a no-op edit).
        out = self._edit("solo", "build.sh", f'cp "{default}" "$1"')
        self.assertFalse((self.etc / "solo" / "build.sh").exists())
        # override dir survives: it holds workload.toml (subdir layout)
        self.assertTrue((self.etc / "solo").exists())
        self.assertIn("still tracks", out)

    def test_new_file_left_empty_is_discarded(self):
        self._config("solo")  # bundle ships no build.sh
        out = self._edit("solo", "extra.sh", "true")  # no-op editor, file stays empty
        self.assertFalse((self.etc / "solo" / "extra.sh").exists())
        self.assertIn("Empty file", out)

    def test_new_file_with_content_kept_and_executable(self):
        self._config("solo")
        self._edit("solo", "extra.sh", 'printf "echo hi\\n" > "$1"')
        override = self.etc / "solo" / "extra.sh"
        self.assertTrue(override.exists())
        self.assertEqual(override.read_text(), "echo hi\n")
        self.assertTrue(override.stat().st_mode & stat.S_IXUSR)

    def test_seeded_copy_preserves_default_content_before_edit(self):
        # If the editor makes a real change, the pre-edit seed must have come
        # from the shipped default (not an empty file).
        self._ship("solo", "policy.cil", "(allow foo bar)\n")
        self._config("solo")
        # Append a line; final content must contain the original.
        self._edit("solo", "policy.cil", 'printf "(allow baz qux)\\n" >> "$1"')
        override = self.etc / "solo" / "policy.cil"
        self.assertIn("(allow foo bar)", override.read_text())
        self.assertIn("(allow baz qux)", override.read_text())

    def test_traversal_rejected(self):
        self._config("solo")
        with mock.patch.dict(os.environ, {"EDITOR": self._editor("true")}):
            with self.assertRaises(SystemExit):
                with redirect_stdout(io.StringIO()):
                    cmd_admin.cmd_edit(_ns(workload="solo", file="../evil", yes=False),
                                       self.manager)

    def test_symlink_escape_rejected(self):
        # `..` is blocked, but a pre-planted symlinked component must not let a
        # write follow the link out of the override tree.
        import shutil
        self._config("solo")
        outside = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(outside, ignore_errors=True))
        odir = self.etc / "solo"
        odir.mkdir(parents=True, exist_ok=True)
        (odir / "sub").symlink_to(outside)
        with mock.patch.dict(os.environ, {"EDITOR": self._editor('printf x > "$1"')}):
            with self.assertRaises(SystemExit):
                with redirect_stdout(io.StringIO()):
                    cmd_admin.cmd_edit(_ns(workload="solo", file="sub/evil", yes=False),
                                       self.manager)
        self.assertFalse((outside / "evil").exists())  # nothing written through link

    def test_shebang_makes_nonsh_file_executable(self):
        # A freshly authored hook with a shebang but no .sh suffix still gets +x.
        self._config("solo")
        self._edit("solo", "hook", 'printf "#!/bin/sh\\necho hi\\n" > "$1"')
        override = self.etc / "solo" / "hook"
        self.assertTrue(override.exists())
        self.assertTrue(override.stat().st_mode & stat.S_IXUSR)

    def test_custom_containerfile_rebuild_hint(self):
        # A declared [build].containerfile gets the rebuild next-step, not the
        # generic recreate hint.
        self._config("solo", extra='\n[build]\ncontainerfile = "Containerfile.gpu"\n')
        out = self._edit("solo", "Containerfile.gpu", 'printf "FROM x\\n" > "$1"')
        self.assertIn("Rebuild image", out)

    def test_missing_workload_rejected(self):
        with mock.patch.dict(os.environ, {"EDITOR": self._editor("true")}):
            with self.assertRaises(SystemExit):
                with redirect_stdout(io.StringIO()):
                    cmd_admin.cmd_edit(_ns(workload="ghost", file="build.sh", yes=False),
                                       self.manager)

    def test_no_file_arg_takes_toml_path(self):
        # Sanity: omitting the file arg must NOT hit the control-file branch.
        # (We can't run the full TOML editor flow here, but the branch guard is
        # what we assert — getattr(args, "file", None) falsy → TOML path, which
        # errors out on a missing config rather than seeding an override.)
        with self.assertRaises(SystemExit):
            with redirect_stdout(io.StringIO()):
                cmd_admin.cmd_edit(_ns(workload="ghost", file=None, yes=False),
                                   self.manager)
        self.assertFalse((self.etc / "ghost").exists())


# ---------------------------------------------------------------------------
# Stage D — build <name>  (end-to-end escape hatch; built-in builder is mocked
# in test_imagebuild). A bare build.sh is NOT auto-run anymore — it only runs
# when declared via [build].script.
# ---------------------------------------------------------------------------

class TestBuild(Step3Base):
    _ESC = '\n[build]\nscript = "build.sh"\n'

    def _build(self, name):
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_lifecycle.cmd_build(_ns(workload=name), self.manager)
        return buf.getvalue()

    def test_escape_hatch_runs_declared_script(self):
        sentinel = self.etc / "built-usr"
        self._ship("solo", "build.sh", f'#!/bin/sh\ntouch "{sentinel}"\n').chmod(0o755)
        self._config("solo", extra=self._ESC)
        self._build("solo")
        self.assertTrue(sentinel.exists())

    def test_override_script_wins(self):
        usr_sentinel = self.etc / "built-usr"
        etc_sentinel = self.etc / "built-etc"
        self._ship("solo", "build.sh", f'#!/bin/sh\ntouch "{usr_sentinel}"\n').chmod(0o755)
        self._override_file("solo", "build.sh", f'#!/bin/sh\ntouch "{etc_sentinel}"\n').chmod(0o755)
        self._config("solo", extra=self._ESC)
        self._build("solo")
        self.assertTrue(etc_sentinel.exists())
        self.assertFalse(usr_sentinel.exists())

    def test_bare_build_sh_not_run_without_declaration(self):
        # Stray build.sh, no [build].script and no Containerfile → nothing to build.
        sentinel = self.etc / "should-not-exist"
        self._ship("solo", "build.sh", f'#!/bin/sh\ntouch "{sentinel}"\n').chmod(0o755)
        self._config("solo")
        with self.assertRaises(SystemExit) as cm:
            with redirect_stdout(io.StringIO()):
                cmd_lifecycle.cmd_build(_ns(workload="solo"), self.manager)
        self.assertEqual(cm.exception.code, 1)
        self.assertFalse(sentinel.exists())

    def test_failed_script_propagates_exit_code(self):
        self._ship("solo", "build.sh", "#!/bin/sh\nexit 7\n").chmod(0o755)
        self._config("solo", extra=self._ESC)
        with self.assertRaises(SystemExit) as cm:
            with redirect_stdout(io.StringIO()):
                cmd_lifecycle.cmd_build(_ns(workload="solo"), self.manager)
        self.assertEqual(cm.exception.code, 7)


if __name__ == "__main__":
    unittest.main()
