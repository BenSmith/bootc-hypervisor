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
# Per-container image builds ([containers.build])
# ---------------------------------------------------------------------------

class MultiBuildBase(BuildBase):
    def _multi(self, name, containers, *, build=None):
        """containers: list of (cname, image, pull, per_container_build_toml)."""
        body = f'[workload]\nname = "{name}"\nmode = "pod"\n'
        if build is not None:
            body += "\n[build]\n" + build
        for cname, image, pull, cbuild in containers:
            body += f'\n[[containers]]\nname = "{cname}"\n'
            body += f'[containers.container]\nimage = "{image}"\npull = "{pull}"\n'
            if cbuild:
                body += f"[containers.build]\n{cbuild}"
        (self.etc / name).mkdir(exist_ok=True)
        (self.etc / name / "workload.toml").write_text(body)
        return WorkloadConfig(name)


class TestBuildJobs(MultiBuildBase):
    def test_per_container_containerfile_and_target(self):
        cfg = self._multi("stack", [
            ("vpn", "localhost/stack-vpn:latest", "never",
             'containerfile = "Containerfile.vpn"\n'),
            ("app", "localhost/stack-app:latest", "never",
             'containerfile = "Containerfile.app"\ntarget = "runtime"\n'),
        ])
        jobs = cfg.build_jobs()
        self.assertEqual([(j.image, j.containerfile, j.target) for j in jobs], [
            ("localhost/stack-vpn:latest", "Containerfile.vpn", None),
            ("localhost/stack-app:latest", "Containerfile.app", "runtime"),
        ])
        self.assertEqual(cfg.build_images(),
                         ["localhost/stack-vpn:latest", "localhost/stack-app:latest"])

    def test_resolution_is_all_or_nothing(self):
        # A [containers.build] block is self-describing: it does NOT merge with
        # the workload-level [build]. So a per-container Containerfile that omits
        # `target` gets NO target (not the workload's) — a workload target is
        # only meaningful against the default Containerfile. A container with no
        # [containers.build] at all inherits the workload [build] wholesale.
        cfg = self._multi("stack", [
            ("vpn", "localhost/stack-vpn:latest", "never",
             'containerfile = "Containerfile.vpn"\n'),      # sets cf, not target
            ("app", "localhost/stack-app:latest", "never", ""),
        ], build='containerfile = "Containerfile.default"\ntarget = "base"\n')
        jobs = {j.image: j for j in cfg.build_jobs()}
        self.assertEqual(jobs["localhost/stack-vpn:latest"].containerfile,
                         "Containerfile.vpn")               # per-ctr block
        self.assertIsNone(jobs["localhost/stack-vpn:latest"].target)  # NOT inherited
        self.assertEqual(jobs["localhost/stack-app:latest"].containerfile,
                         "Containerfile.default")           # wholesale inherit
        self.assertEqual(jobs["localhost/stack-app:latest"].target, "base")

    def test_block_without_containerfile_defaults_to_Containerfile(self):
        # A [containers.build] that sets only args still self-describes: its
        # containerfile is the built-in "Containerfile" default, NOT the
        # workload-level [build].containerfile.
        cfg = self._multi("stack", [
            ("app", "localhost/stack-app:latest", "never", 'args = { B = "2" }\n'),
        ], build='containerfile = "Containerfile.default"\n')
        job = cfg.build_jobs()[0]
        self.assertEqual(job.containerfile, "Containerfile")
        self.assertEqual(job.args, {"B": "2"})

    def test_buildable_gate_single_build_block_without_pull_never(self):
        # The zot-consuming shape: registry ref, pull=missing, [build] present.
        cfg = self._config("app", pull="missing", build="")
        self.assertEqual(cfg.build_images(), ["localhost/app:latest"])
        self.assertTrue(cfg.is_buildable("app", "missing"))

    def test_buildable_gate_single_no_build_block_not_buildable(self):
        cfg = self._config("app", pull="missing")
        self.assertEqual(cfg.build_jobs(), [])
        self.assertFalse(cfg.is_buildable("app", "missing"))

    def test_buildable_gate_pull_never_is_legacy_signal(self):
        cfg = self._config("app", pull="never")
        self.assertEqual(cfg.build_images(), ["localhost/app:latest"])

    def test_buildable_gate_multi_requires_per_container_block(self):
        # In multi mode the workload-level [build] supplies inherited inputs
        # only; a container without pull=never or its own [containers.build]
        # is not buildable even when the workload table exists.
        cfg = self._multi("stack", [
            ("app", "registry.local/workload-stack:latest", "missing",
             '# empty block\n'),
            ("db", "docker.io/library/postgres:16", "missing", ""),
        ], build='containerfile = "Containerfile.default"\n')
        self.assertEqual(cfg.build_images(),
                         ["registry.local/workload-stack:latest"])
        self.assertFalse(cfg.is_buildable("db", "missing"))

    def test_empty_block_still_self_describes(self):
        # Presence, not content, selects per-container resolution: an EMPTY
        # [containers.build] means "default Containerfile, no target/args" —
        # it does not fall back to the workload-level [build].
        cfg = self._multi("stack", [
            ("app", "localhost/stack-app:latest", "never",
             '# empty block\n'),
        ], build='containerfile = "Containerfile.other"\ntarget = "base"\n')
        job = cfg.build_jobs()[0]
        self.assertEqual(job.containerfile, "Containerfile")
        self.assertIsNone(job.target)
        self.assertEqual(job.args, {})

    def test_shared_image_with_conflicting_builds_raises(self):
        # Two pull=never containers may share an image tag only if they resolve
        # identical build inputs; anything else would silently build the first
        # container's recipe for both.
        cfg = self._multi("stack", [
            ("a", "localhost/shared:latest", "never",
             'containerfile = "Containerfile.a"\n'),
            ("b", "localhost/shared:latest", "never", ""),   # inherits [build]
        ], build='containerfile = "Containerfile.b"\n')
        with self.assertRaisesRegex(ValueError, "shared"):
            cfg.build_jobs()

    def test_shared_image_with_identical_builds_dedupes(self):
        cfg = self._multi("stack", [
            ("a", "localhost/shared:latest", "never",
             'containerfile = "Containerfile.x"\n'),
            ("b", "localhost/shared:latest", "never",
             'containerfile = "Containerfile.x"\n'),
        ])
        self.assertEqual(len(cfg.build_jobs()), 1)

    def test_pull_missing_and_dupes_skipped(self):
        cfg = self._multi("stack", [
            ("a", "localhost/shared:latest", "never", ""),
            ("b", "localhost/shared:latest", "never", ""),   # same image → deduped
            ("c", "docker.io/library/x:1", "missing", ""),   # pulled → not built
        ])
        self.assertEqual(cfg.build_images(), ["localhost/shared:latest"])

    def test_block_args_replace_workload_args_wholesale(self):
        # All-or-nothing: a [containers.build] with its own args does NOT inherit
        # the workload-level [build].args (no {A} here, only the block's {B}).
        cfg = self._multi("stack", [
            ("app", "localhost/stack-app:latest", "never",
             'args = { B = "2" }\n'),
        ], build='args = { A = "1", B = "1" }\n')
        job = cfg.build_jobs()[0]
        self.assertEqual(job.args, {"B": "2"})


class TestMultiBuildImage(MultiBuildBase):
    def test_one_podman_build_per_image(self):
        self._ship("stack", "Containerfile.vpn", "FROM scratch\n")
        self._ship("stack", "Containerfile.app", "FROM scratch\n")
        cfg = self._multi("stack", [
            ("vpn", "localhost/stack-vpn:latest", "never",
             'containerfile = "Containerfile.vpn"\n'),
            ("app", "localhost/stack-app:latest", "never",
             'containerfile = "Containerfile.app"\n'),
        ])
        calls = []

        def fake_run(cmd, *a, **k):
            calls.append(cmd)
            return mock.Mock(returncode=0)

        with mock.patch.object(imagebuild.subprocess, "run", side_effect=fake_run), \
             mock.patch.dict(os.environ, {}, clear=True):
            with redirect_stdout(io.StringIO()):
                rc = imagebuild.build_image(cfg)
        self.assertEqual(rc, 0)
        self.assertEqual(len(calls), 2)
        # Each image built with its own -f, same materialized context dir.
        by_tag = {c[c.index("-t") + 1]: c for c in calls}
        vpn = by_tag["localhost/stack-vpn:latest"]
        app = by_tag["localhost/stack-app:latest"]
        self.assertEqual(vpn[vpn.index("-f") + 1],
                         str(Path(vpn[-1]) / "Containerfile.vpn"))
        self.assertEqual(app[app.index("-f") + 1],
                         str(Path(app[-1]) / "Containerfile.app"))
        self.assertEqual(vpn[-1], app[-1])   # shared context
        self.assertFalse(Path(vpn[-1]).exists())   # cleaned up

    def test_missing_per_container_containerfile_fails(self):
        self._ship("stack", "Containerfile.vpn", "FROM scratch\n")
        # Containerfile.app deliberately not shipped.
        cfg = self._multi("stack", [
            ("vpn", "localhost/stack-vpn:latest", "never",
             'containerfile = "Containerfile.vpn"\n'),
            ("app", "localhost/stack-app:latest", "never",
             'containerfile = "Containerfile.app"\n'),
        ])
        with mock.patch.object(imagebuild.subprocess, "run",
                               return_value=mock.Mock(returncode=0)):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = imagebuild.build_image(cfg)
        self.assertEqual(rc, 1)
        self.assertIn("Containerfile.app", buf.getvalue())

    def test_has_build_context_requires_all_containerfiles(self):
        self._ship("stack", "Containerfile.vpn", "FROM scratch\n")
        cfg = self._multi("stack", [
            ("vpn", "localhost/stack-vpn:latest", "never",
             'containerfile = "Containerfile.vpn"\n'),
            ("app", "localhost/stack-app:latest", "never",
             'containerfile = "Containerfile.app"\n'),
        ])
        self.assertFalse(cfg.has_build_context())   # app's is missing
        self._ship("stack", "Containerfile.app", "FROM scratch\n")
        self.assertTrue(WorkloadConfig("stack").has_build_context())


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
