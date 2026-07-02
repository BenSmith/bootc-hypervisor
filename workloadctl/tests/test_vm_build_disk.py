#!/usr/bin/env python3
"""Unit tests for workload-vm-build-disk helpers.

The script lives in libexec/ and has a __main__ guard; load it as a module
with importlib so we can exercise the disk-rotation logic without running
the full build (which downloads/copies real qcow2 files).
"""

import importlib.machinery
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

LIB_DIR = os.path.join(os.path.dirname(__file__), '..', 'lib')
SCRIPT = os.path.join(os.path.dirname(__file__), '..', 'libexec', 'workload-vm-build-disk')


def _load_script():
    if LIB_DIR not in sys.path:
        sys.path.insert(0, LIB_DIR)
    loader = importlib.machinery.SourceFileLoader("workload_vm_build_disk", SCRIPT)
    spec = importlib.util.spec_from_loader("workload_vm_build_disk", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class TestRotateGenerations(unittest.TestCase):
    def setUp(self):
        self.mod = _load_script()
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def _make(self, name: str, content: bytes = b"x"):
        (self.home / name).write_bytes(content)

    def _gens(self):
        return sorted(
            int(p.suffix[5:])
            for p in self.home.glob("system.qcow2.gen-*")
            if p.suffix[5:].isdigit()
        )

    def test_no_system_disk_is_noop(self):
        result = self.mod.rotate_generations(self.home, keep=2)
        self.assertIsNone(result)
        self.assertEqual(self._gens(), [])

    def test_first_rotation_creates_gen_1(self):
        self._make("system.qcow2", b"v1")
        result = self.mod.rotate_generations(self.home, keep=2)
        self.assertEqual(result, self.home / "system.qcow2.gen-1")
        self.assertEqual(self._gens(), [1])
        self.assertFalse((self.home / "system.qcow2").exists())
        self.assertEqual((self.home / "system.qcow2.gen-1").read_bytes(), b"v1")

    def test_rotation_picks_next_free_number(self):
        # Pre-existing gens 1 and 2; rotating system.qcow2 should produce gen-3.
        self._make("system.qcow2.gen-1")
        self._make("system.qcow2.gen-2")
        self._make("system.qcow2")
        result = self.mod.rotate_generations(self.home, keep=10)
        self.assertEqual(result, self.home / "system.qcow2.gen-3")
        self.assertEqual(self._gens(), [1, 2, 3])

    def test_pruning_respects_keep(self):
        # Three pre-existing gens, keep=2 → after rotating, the oldest of
        # the *pre-existing* gens should be pruned, but the just-rotated
        # gen must survive.
        for n in (1, 2, 3):
            self._make(f"system.qcow2.gen-{n}", f"old-{n}".encode())
        self._make("system.qcow2", b"current")
        result = self.mod.rotate_generations(self.home, keep=2)
        self.assertEqual(result, self.home / "system.qcow2.gen-4")
        gens = self._gens()
        # Must include the new one (4) and not have grown beyond keep+1
        # (we keep `keep` historical generations + the brand-new one as the
        # only restore point).
        self.assertIn(4, gens)
        self.assertNotIn(1, gens, "oldest gen-1 should have been pruned")

    def test_just_rotated_gen_never_pruned_even_when_keep_is_one(self):
        # Regression for the off-by-one we fixed: with keep=1 and an existing
        # gen, the newly created gen would be the only restore point if the
        # next build fails, so it must not be pruned.
        self._make("system.qcow2.gen-1", b"old")
        self._make("system.qcow2", b"current")
        result = self.mod.rotate_generations(self.home, keep=1)
        self.assertEqual(result, self.home / "system.qcow2.gen-2")
        self.assertTrue(result.exists(), "freshly rotated gen must survive pruning")

    def test_non_numeric_suffix_ignored(self):
        # A stray file like system.qcow2.gen-keep should not crash the int
        # parsing or get pruned by it.
        (self.home / "system.qcow2.gen-keep").write_bytes(b"unrelated")
        self._make("system.qcow2", b"v1")
        result = self.mod.rotate_generations(self.home, keep=2)
        self.assertEqual(result, self.home / "system.qcow2.gen-1")
        self.assertTrue((self.home / "system.qcow2.gen-keep").exists())


if __name__ == "__main__":
    unittest.main()
