#!/usr/bin/env python3
"""`ci-workload-images.py` — the multi-variant publishing path.

Run it directly; it is deliberately NOT under `workloadctl/tests/`:

    python3 -m unittest .forgejo/scripts/test_ci_workload_images.py
    python3 .forgejo/scripts/test_ci_workload_images.py

The CI helper had no coverage, and `[[build.variants]]` added real logic to it:
ref-tag rewriting, an arg_env cross-check, and a temporary environment
override. Those are pure functions, so they need neither podman nor a registry
— which is why they were factored out that way.

WHY NOT IN workloadctl/tests/: importing this script is destructive to a shared
test process. At module scope it exports WORKLOAD_CONFIG_DIR /
WORKLOAD_BUNDLES_DIR pointing at the REAL repo tree and imports
workloadctl_core, which reads them at import time. `unittest discover` would
run this file first alphabetically, so the rest of the suite then resolved
bundles from the real tree instead of its own temp /usr + /etc — 67 failures,
690 errors, and it wrote 15 fixture bundles (coolapp, withfiles, myvm, ...)
into workloadctl/workloads/ as untracked junk. The teardown below undoes the
import, but keeping this out of the discovery path is the actual fix; the
teardown is belt and braces for anyone who moves it back.

The load-bearing case is `test_rejects_args_not_declared_in_arg_env`. A variant
arg that `[build].arg_env` does not declare is silently dropped by
`assemble_build_args`, so the build still succeeds and CI publishes a variant
tag holding a byte-identical copy of the default image. That failure is
invisible at build time and misleads every consumer of the tag, so the helper
refuses it up front.
"""
import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

_SCRIPT = Path(__file__).resolve().parent / "ci-workload-images.py"


def _load_ci_module():
    """Import the hyphenated script by path (not a legal module name).

    Importing it is DESTRUCTIVE to a shared test process and must be undone.
    The script is a CI entrypoint, so at module scope it exports
    WORKLOAD_CONFIG_DIR / WORKLOAD_BUNDLES_DIR pointing at the real repo tree,
    prepends lib/ to sys.path, and imports workloadctl_core — which reads those
    vars at import time and caches them in sys.modules.

    `unittest discover` runs this file before the rest alphabetically, so
    leaving any of that behind makes every later test resolve bundles from the
    real tree instead of its own temp /usr + /etc. That is not hypothetical: it
    produced 67 failures and 690 errors across the suite before this teardown
    existed. Restore the environment, sys.path, and sys.modules to exactly what
    we found.
    """
    saved_env = dict(os.environ)
    saved_path = list(sys.path)
    preexisting = set(sys.modules)
    try:
        spec = importlib.util.spec_from_file_location("ci_workload_images", _SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        os.environ.clear()
        os.environ.update(saved_env)
        sys.path[:] = saved_path
        # Drop only modules this import introduced; anything already loaded
        # belongs to another test and must be left alone.
        for name in set(sys.modules) - preexisting:
            del sys.modules[name]


ci = _load_ci_module()


class _Cfg:
    """Minimal stand-in for WorkloadConfig: only what the helpers read."""

    def __init__(self, arg_env=(), variants=None):
        self.build_arg_env = list(arg_env)
        self.build_config = {"variants": list(variants)} if variants is not None else {}


class SplitRefTests(unittest.TestCase):
    def test_plain_repo_and_tag(self):
        self.assertEqual(
            ci._split_ref("registry.local/workloads/llama-swap:latest"),
            ("registry.local/workloads/llama-swap", "latest"),
        )

    def test_registry_port_is_not_a_tag(self):
        # The reason rsplit(":") is wrong: the colon is a port, not a tag.
        self.assertEqual(
            ci._split_ref("registry.local:5000/workloads/x"),
            ("registry.local:5000/workloads/x", ""),
        )

    def test_registry_port_with_tag(self):
        self.assertEqual(
            ci._split_ref("registry.local:5000/workloads/x:cuda"),
            ("registry.local:5000/workloads/x", "cuda"),
        )

    def test_untagged(self):
        self.assertEqual(ci._split_ref("localhost/x"), ("localhost/x", ""))


class VariantRefTests(unittest.TestCase):
    def test_replaces_tag(self):
        self.assertEqual(
            ci._variant_ref("registry.local/workloads/llama-swap:latest", "cuda"),
            "registry.local/workloads/llama-swap:cuda",
        )

    def test_survives_registry_port(self):
        self.assertEqual(
            ci._variant_ref("registry.local:5000/workloads/x:latest", "cuda"),
            "registry.local:5000/workloads/x:cuda",
        )


class VariantsTableTests(unittest.TestCase):
    def test_absent_table_is_empty(self):
        self.assertEqual(ci._variants(_Cfg()), [])

    def test_reads_entries(self):
        cfg = _Cfg(variants=[{"suffix": "cuda", "args": {"BASE_TAG": "cuda"}}])
        self.assertEqual(len(ci._variants(cfg)), 1)


class ValidateVariantsTests(unittest.TestCase):
    def test_valid(self):
        cfg = _Cfg(arg_env=["SD_TAG", "BASE_TAG"])
        variants = [{"suffix": "cuda", "args": {"SD_TAG": "master-cuda", "BASE_TAG": "cuda"}}]
        self.assertIsNone(ci._validate_variants(cfg, variants))

    def test_rejects_args_not_declared_in_arg_env(self):
        cfg = _Cfg(arg_env=["SD_TAG"])
        variants = [{"suffix": "cuda", "args": {"SD_TAG": "master-cuda", "BASE_TAG": "cuda"}}]
        err = ci._validate_variants(cfg, variants)
        self.assertIsNotNone(err)
        self.assertIn("BASE_TAG", err)
        self.assertIn("arg_env", err)

    def test_rejects_missing_suffix(self):
        cfg = _Cfg(arg_env=["SD_TAG"])
        err = ci._validate_variants(cfg, [{"args": {"SD_TAG": "x"}}])
        self.assertIn("suffix", err)

    def test_rejects_latest_suffix(self):
        cfg = _Cfg(arg_env=["SD_TAG"])
        err = ci._validate_variants(cfg, [{"suffix": "latest", "args": {"SD_TAG": "x"}}])
        self.assertIn("latest", err)

    def test_rejects_duplicate_suffix(self):
        cfg = _Cfg(arg_env=["SD_TAG"])
        variants = [
            {"suffix": "cuda", "args": {"SD_TAG": "a"}},
            {"suffix": "cuda", "args": {"SD_TAG": "b"}},
        ]
        self.assertIn("duplicate", ci._validate_variants(cfg, variants))

    def test_rejects_empty_args(self):
        cfg = _Cfg(arg_env=["SD_TAG"])
        err = ci._validate_variants(cfg, [{"suffix": "cuda"}])
        self.assertIn("args", err)

    def test_rejects_suffix_with_separator(self):
        cfg = _Cfg(arg_env=["SD_TAG"])
        for bad in ("a/b", "a:b"):
            with self.subTest(suffix=bad):
                err = ci._validate_variants(cfg, [{"suffix": bad, "args": {"SD_TAG": "x"}}])
                self.assertIsNotNone(err)


class EnvOverrideTests(unittest.TestCase):
    def test_sets_then_restores_existing(self):
        with mock.patch.dict(os.environ, {"SD_TAG": "original"}, clear=False):
            with ci._env_overrides({"SD_TAG": "master-cuda"}):
                self.assertEqual(os.environ["SD_TAG"], "master-cuda")
            self.assertEqual(os.environ["SD_TAG"], "original")

    def test_removes_previously_unset(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SD_TAG_UNSET_PROBE", None)
            with ci._env_overrides({"SD_TAG_UNSET_PROBE": "x"}):
                self.assertEqual(os.environ["SD_TAG_UNSET_PROBE"], "x")
            self.assertNotIn("SD_TAG_UNSET_PROBE", os.environ)

    def test_restores_on_exception(self):
        with mock.patch.dict(os.environ, {"SD_TAG": "original"}, clear=False):
            with self.assertRaises(RuntimeError):
                with ci._env_overrides({"SD_TAG": "master-cuda"}):
                    raise RuntimeError("build blew up")
            self.assertEqual(os.environ["SD_TAG"], "original")

    def test_values_are_stringified(self):
        # TOML can hold non-strings; os.environ only accepts str.
        with ci._env_overrides({"SOME_NUMERIC_ARG": 8}):
            self.assertEqual(os.environ["SOME_NUMERIC_ARG"], "8")


class TagTests(unittest.TestCase):
    def test_noop_when_already_tagged(self):
        # Bundles whose [container].image names the registry are built pre-tagged;
        # `podman tag x x` is pointless, so it must not be invoked at all.
        with mock.patch.object(ci.subprocess, "run") as run:
            self.assertEqual(ci._tag("registry.local/w/x:latest", "registry.local/w/x:latest"), 0)
            run.assert_not_called()

    def test_tags_when_different(self):
        with mock.patch.object(ci.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=0)
            self.assertEqual(ci._tag("localhost/x:latest", "registry.local/workloads/x:cuda"), 0)
            run.assert_called_once_with(
                ["podman", "tag", "localhost/x:latest", "registry.local/workloads/x:cuda"]
            )


class CmdBuildOrderingTests(unittest.TestCase):
    """Build order is load-bearing, so it gets a test rather than just a comment.

    Every build tags its output as [container].image, so the LAST build owns
    that tag. Hosts consume it as :latest, so the default must run last. If the
    order inverts, CI still succeeds and still publishes both tags — but
    :latest quietly holds the final variant's image. Nothing downstream would
    notice until a host ran the wrong backend.
    """

    def _cfg(self, variants):
        cfg = _Cfg(arg_env=["SD_TAG", "BASE_TAG"], variants=variants)
        cfg.is_vm = False
        cfg.has_build_context = lambda: True
        cfg.build_images = lambda: ["registry.local/workloads/llama-swap:latest"]
        return cfg

    def _run(self, variants):
        """Run cmd_build with podman/imagebuild mocked; return (build_env_log, refs)."""
        cfg = self._cfg(variants)
        seen = []

        def fake_build(_cfg):
            seen.append(
                {k: os.environ.get(k) for k in ("SD_TAG", "BASE_TAG")}
            )
            return 0

        with mock.patch.object(ci, "_load", return_value=cfg), \
             mock.patch.object(ci.imagebuild, "build_image", side_effect=fake_build), \
             mock.patch.object(ci, "_tag", return_value=0), \
             mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("REFS_OUT", None)
            rc = ci.cmd_build("llama-swap")
        self.assertEqual(rc, 0)
        return seen

    def test_default_builds_last_so_it_owns_latest(self):
        seen = self._run([{"suffix": "cuda", "args": {"SD_TAG": "master-cuda", "BASE_TAG": "cuda"}}])
        self.assertEqual(len(seen), 2)
        # variant first, with its args exported...
        self.assertEqual(seen[0], {"SD_TAG": "master-cuda", "BASE_TAG": "cuda"})
        # ...then the default, with the overrides removed again.
        self.assertEqual(seen[1], {"SD_TAG": None, "BASE_TAG": None})

    def test_no_variants_builds_once(self):
        self.assertEqual(len(self._run([])), 1)

    def test_invalid_variant_fails_before_building(self):
        cfg = self._cfg([{"suffix": "cuda", "args": {"UNDECLARED": "x"}}])
        with mock.patch.object(ci, "_load", return_value=cfg), \
             mock.patch.object(ci.imagebuild, "build_image") as build:
            rc = ci.cmd_build("llama-swap")
        self.assertEqual(rc, 1)
        build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
