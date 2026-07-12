#!/usr/bin/env python3
"""Built-in image builder + [build] section (the declarative replacement for the
per-bundle build.sh scripts).

Covers:
- WorkloadConfig [build] accessors + build_images()/has_build_context().
- imagebuild.materialize_build_context — the merged /usr+/etc overlay (the bit
  that makes overriding a Containerfile/COPY-ed asset actually take effect),
  control-file stripping, cleanup.
- imagebuild.assemble_build_args — args defaults, arg_env override, proxy.
- imagebuild.build_image / run_build_script — podman argv + escape-hatch
  invocation (podman is mocked; no real build).
- cmd_lifecycle._run_build precedence + cmd_build VM rejection / exit codes.

Temp /usr (bundles) + /etc (configs+overrides) patched into the core namespace,
mirroring test_step3_ergonomics.
"""
import argparse
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


import workload_lib               # noqa: E402
import workloadctl_core as core   # noqa: E402
import imagebuild                 # noqa: E402
import cmd_lifecycle              # noqa: E402
from workloadctl_core import WorkloadConfig, WorkloadManager  # noqa: E402


def _ns(**kw):
    return argparse.Namespace(**kw)


class BuildBase(unittest.TestCase):
    def setUp(self):
        import shutil
        self.etc = Path(tempfile.mkdtemp())
        self.usr = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.etc, ignore_errors=True))
        self.addCleanup(lambda: shutil.rmtree(self.usr, ignore_errors=True))
        for p in (
            mock.patch.object(core, "WORKLOAD_BUNDLES_DIR", self.usr),
            mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.etc),
            mock.patch.object(cmd_lifecycle, "require_root", lambda: None),
        ):
            p.start()
            self.addCleanup(p.stop)
        self.manager = WorkloadManager()

    def _config(self, name, *, bundle=None, pull="never", build=None,
                host_setup=None, extra=""):
        body = f'[workload]\nname = "{name}"\n'
        if bundle is not None:
            body += f'bundle = "{bundle}"\n'
        body += f'\n[container]\nimage = "localhost/{name}:latest"\npull = "{pull}"\n'
        if host_setup is not None:
            body += f'\n[host]\nsetup = "{host_setup}"\n'
        if build is not None:
            body += "\n[build]\n" + build
        body += extra
        (self.etc / name).mkdir(exist_ok=True)
        (self.etc / name / "workload.toml").write_text(body)
        return WorkloadConfig(name)

    def _ship(self, bundle, fname, content="x\n"):
        d = self.usr / bundle
        d.mkdir(parents=True, exist_ok=True)
        (d / fname).write_text(content)
        return d / fname

    def _override(self, name, fname, content="x\n"):
        d = self.etc / name
        d.mkdir(parents=True, exist_ok=True)
        (d / fname).write_text(content)
        return d / fname


# ---------------------------------------------------------------------------
# Accessors
# ---------------------------------------------------------------------------

class TestAccessors(BuildBase):
    def test_defaults(self):
        cfg = self._config("solo")
        self.assertIsNone(cfg.build_script)
        self.assertEqual(cfg.build_containerfile, "Containerfile")
        self.assertEqual(cfg.build_args, {})
        self.assertEqual(cfg.build_arg_env, [])
        self.assertIsNone(cfg.build_target)

    def test_build_section_parsed(self):
        cfg = self._config("solo", build=(
            'containerfile = "Containerfile.web"\n'
            'args = { GPU_TYPE = "amd" }\n'
            'arg_env = ["GPU_TYPE"]\n'
            'target = "runtime"\n'
        ))
        self.assertEqual(cfg.build_containerfile, "Containerfile.web")
        self.assertEqual(cfg.build_args, {"GPU_TYPE": "amd"})
        self.assertEqual(cfg.build_arg_env, ["GPU_TYPE"])
        self.assertEqual(cfg.build_target, "runtime")

    def test_build_images_only_pull_never(self):
        self.assertEqual(self._config("a", pull="never").build_images(),
                         ["localhost/a:latest"])
        self.assertEqual(self._config("b", pull="missing").build_images(), [])

    def test_has_build_context(self):
        cfg = self._config("solo", pull="never")
        self.assertFalse(cfg.has_build_context())   # no Containerfile yet
        self._ship("solo", "Containerfile", "FROM scratch\n")
        self.assertTrue(WorkloadConfig("solo").has_build_context())

    def test_has_build_context_false_when_pull_missing(self):
        self._ship("solo", "Containerfile", "FROM scratch\n")
        self.assertFalse(self._config("solo", pull="missing").has_build_context())


# ---------------------------------------------------------------------------
# Merged build context
# ---------------------------------------------------------------------------

class TestMergedContext(BuildBase):
    def test_usr_only(self):
        self._ship("solo", "Containerfile", "FROM usr\n")
        self._ship("solo", "config.json", "usr-cfg\n")
        cfg = self._config("solo")
        ctx = imagebuild.materialize_build_context(cfg)
        try:
            self.assertEqual((ctx / "Containerfile").read_text(), "FROM usr\n")
            self.assertEqual((ctx / "config.json").read_text(), "usr-cfg\n")
        finally:
            __import__("shutil").rmtree(ctx, ignore_errors=True)

    def test_etc_override_wins_per_file(self):
        self._ship("solo", "Containerfile", "FROM usr\n")
        self._ship("solo", "config.json", "usr-cfg\n")
        self._override("solo", "Containerfile", "FROM etc\n")  # only this one
        cfg = self._config("solo")
        ctx = imagebuild.materialize_build_context(cfg)
        try:
            self.assertEqual((ctx / "Containerfile").read_text(), "FROM etc\n")
            self.assertEqual((ctx / "config.json").read_text(), "usr-cfg\n")  # untouched
        finally:
            __import__("shutil").rmtree(ctx, ignore_errors=True)

    def test_copied_asset_override_wins(self):
        # The case the old self-locating build.sh got wrong: overriding a
        # COPY-ed asset must win, not just the Containerfile.
        self._ship("solo", "Containerfile", "FROM usr\n")
        self._ship("solo", "app.conf", "usr\n")
        self._override("solo", "app.conf", "etc\n")
        cfg = self._config("solo")
        ctx = imagebuild.materialize_build_context(cfg)
        try:
            self.assertEqual((ctx / "app.conf").read_text(), "etc\n")
        finally:
            __import__("shutil").rmtree(ctx, ignore_errors=True)

    def test_control_files_stripped(self):
        self._ship("solo", "Containerfile", "FROM usr\n")
        self._ship("solo", "workload.toml", "x")
        self._ship("solo", "build.sh", "x")
        self._ship("solo", "policy.cil", "x")
        self._ship("solo", "setup.sh", "x")
        cfg = self._config("solo", host_setup="setup.sh")
        ctx = imagebuild.materialize_build_context(cfg)
        try:
            self.assertFalse((ctx / "workload.toml").exists())
            self.assertFalse((ctx / "build.sh").exists())
            self.assertFalse((ctx / "policy.cil").exists())
            self.assertFalse((ctx / "setup.sh").exists())
            self.assertTrue((ctx / "Containerfile").exists())
        finally:
            __import__("shutil").rmtree(ctx, ignore_errors=True)


# ---------------------------------------------------------------------------
# Build args
# ---------------------------------------------------------------------------

class TestBuildArgs(BuildBase):
    def test_static_args(self):
        cfg = self._config("solo", build='args = { GPU_TYPE = "amd" }\n')
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(imagebuild.assemble_build_args(cfg),
                             ["--build-arg", "GPU_TYPE=amd"])

    def test_arg_env_overrides_default(self):
        cfg = self._config("solo", build=(
            'args = { GPU_TYPE = "amd" }\narg_env = ["GPU_TYPE"]\n'))
        with mock.patch.dict(os.environ, {"GPU_TYPE": "nvidia"}, clear=True):
            self.assertEqual(imagebuild.assemble_build_args(cfg),
                             ["--build-arg", "GPU_TYPE=nvidia"])

    def test_arg_env_absent_uses_default(self):
        cfg = self._config("solo", build=(
            'args = { GPU_TYPE = "amd" }\narg_env = ["GPU_TYPE"]\n'))
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(imagebuild.assemble_build_args(cfg),
                             ["--build-arg", "GPU_TYPE=amd"])

    def test_proxy_forwarded(self):
        cfg = self._config("solo")
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://p:3128"}, clear=True):
            self.assertEqual(imagebuild.assemble_build_args(cfg),
                             ["--build-arg", "https_proxy=http://p:3128"])


# ---------------------------------------------------------------------------
# build_image / run_build_script (podman mocked)
# ---------------------------------------------------------------------------

class TestBuildImage(BuildBase):
    def test_podman_argv_and_cleanup(self):
        self._ship("solo", "Containerfile", "FROM scratch\n")
        cfg = self._config("solo", build='args = { K = "v" }\n')
        captured = {}

        def fake_run(cmd, *a, **k):
            captured["cmd"] = cmd
            captured["ctx_existed"] = Path(cmd[-1]).is_dir()
            return mock.Mock(returncode=0)

        with mock.patch.object(imagebuild.subprocess, "run", side_effect=fake_run), \
             mock.patch.dict(os.environ, {}, clear=True):
            with redirect_stdout(io.StringIO()):
                rc = imagebuild.build_image(cfg)
        self.assertEqual(rc, 0)
        cmd = captured["cmd"]
        self.assertEqual(cmd[:2], ["podman", "build"])
        self.assertIn("-t", cmd)
        self.assertIn("localhost/solo:latest", cmd)
        self.assertIn("--build-arg", cmd)
        self.assertIn("K=v", cmd)
        # -f points at the Containerfile inside the materialized context.
        self.assertEqual(cmd[cmd.index("-f") + 1], str(Path(cmd[-1]) / "Containerfile"))
        self.assertTrue(captured["ctx_existed"])
        # Temp context is cleaned up afterward.
        self.assertFalse(Path(cmd[-1]).exists())

    def test_build_failure_propagates(self):
        self._ship("solo", "Containerfile", "FROM scratch\n")
        cfg = self._config("solo")
        with mock.patch.object(imagebuild.subprocess, "run",
                               return_value=mock.Mock(returncode=5)):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(imagebuild.build_image(cfg), 5)

    def test_no_image_to_build(self):
        cfg = self._config("solo", pull="missing")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(imagebuild.build_image(cfg), 1)

    def test_run_build_script_gets_context_and_tag(self):
        self._ship("solo", "Containerfile", "FROM scratch\n")
        self._ship("solo", "build.sh", "#!/bin/sh\n")
        cfg = self._config("solo", build='script = "build.sh"\n')
        captured = {}

        def fake_run(cmd, *a, **k):
            captured["cmd"] = cmd
            captured["env"] = k.get("env", {})
            return mock.Mock(returncode=0)

        with mock.patch.object(imagebuild.subprocess, "run", side_effect=fake_run):
            with redirect_stdout(io.StringIO()):
                rc = imagebuild.run_build_script(cfg)
        self.assertEqual(rc, 0)
        cmd = captured["cmd"]
        self.assertTrue(cmd[0].endswith("build.sh"))
        self.assertEqual(cmd[2], "localhost/solo:latest")    # tag arg
        self.assertEqual(captured["env"]["WL_TAG"], "localhost/solo:latest")
        self.assertEqual(captured["env"]["WL_BUILD_CONTEXT"], cmd[1])


# ---------------------------------------------------------------------------
# Precedence + cmd_build
# ---------------------------------------------------------------------------

class TestDispatch(BuildBase):
    def test_script_takes_precedence(self):
        self._ship("solo", "Containerfile", "FROM scratch\n")
        cfg = self._config("solo", build='script = "build.sh"\n')
        with mock.patch.object(imagebuild, "run_build_script", return_value=0) as rs, \
             mock.patch.object(imagebuild, "build_image") as bi:
            self.assertEqual(cmd_lifecycle._run_build(cfg), 0)
        rs.assert_called_once()
        bi.assert_not_called()

    def test_builtin_when_no_script(self):
        self._ship("solo", "Containerfile", "FROM scratch\n")
        cfg = self._config("solo")
        with mock.patch.object(imagebuild, "build_image", return_value=0) as bi, \
             mock.patch.object(imagebuild, "run_build_script") as rs:
            self.assertEqual(cmd_lifecycle._run_build(cfg), 0)
        bi.assert_called_once()
        rs.assert_not_called()

    def test_nothing_to_build(self):
        cfg = self._config("solo", pull="missing")
        with redirect_stdout(io.StringIO()), redirect_stdout(io.StringIO()):
            rc = cmd_lifecycle._run_build(cfg)
        self.assertEqual(rc, 1)

    def test_cmd_build_rejects_vm(self):
        (self.etc / "vm").mkdir(exist_ok=True)
        (self.etc / "vm" / "workload.toml").write_text(
            '[workload]\nname = "vm"\n\n[vm]\nmemory = "1024M"\n')
        with self.assertRaises(SystemExit) as cm:
            with redirect_stdout(io.StringIO()):
                cmd_lifecycle.cmd_build(_ns(workload="vm"), self.manager)
        self.assertEqual(cm.exception.code, 1)

    def test_cmd_build_success(self):
        self._ship("solo", "Containerfile", "FROM scratch\n")
        self._config("solo")
        with mock.patch.object(imagebuild, "build_image", return_value=0):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cmd_lifecycle.cmd_build(_ns(workload="solo"), self.manager)
        self.assertIn("Built image", buf.getvalue())

    def test_cmd_build_propagates_failure(self):
        self._ship("solo", "Containerfile", "FROM scratch\n")
        self._config("solo")
        with mock.patch.object(imagebuild, "build_image", return_value=3):
            with self.assertRaises(SystemExit) as cm:
                with redirect_stdout(io.StringIO()):
                    cmd_lifecycle.cmd_build(_ns(workload="solo"), self.manager)
        self.assertEqual(cm.exception.code, 3)


if __name__ == "__main__":
    unittest.main()
