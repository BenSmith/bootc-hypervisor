#!/usr/bin/env python3
"""Every lib module imports on its own, in a fresh interpreter.

`lib/` is a flat set of top-level modules, not a package, and on a host every
entrypoint finds them through its own `sys.path[0]`. That arrangement has no
import-order authority in it: nothing declares which module is allowed to
depend on which, so a cycle is legal right up until the first process that
happens to enter it from the wrong side.

Nothing else in the suite would catch one. `just lint` is `py_compile`, which
compiles a module without executing its imports. `test_stdlib_only.py` walks
lib/ by AST and never imports anything. And the ordinary test run imports the
modules in whatever order unittest discovery reaches them -- an order in which
a cycle can resolve fine, because by the time the second module is imported
the first is already in `sys.modules`, half-initialised but far enough along
to satisfy the attribute being read. The failure then appears on a host, in
whichever entrypoint happens to import the pair from the other end, as an
ImportError or an AttributeError on a module that plainly defines the name.

So each module is imported in a SUBPROCESS, alone, as the first thing that
interpreter does. That is the one condition the test suite never reproduces
and every libexec helper creates on every run.

This matters most when a large module is SPLIT: splitting it and
re-exporting the moved names from the original -- the pattern 582948a
established for vm_normalise_hostname -- is exactly the shape that produces a
cycle, because the new module needs something from the old one and the old one
now imports the new.

The second class below holds the OTHER half of that pattern. A split keeps
every caller working by re-exporting the moved names, and the re-export is a
hand-written list: a name left out of it disappears from the original module's
surface, and nothing in the suite notices. Measured, not reasoned -- dropping
VM_UID_MGMT from vm.py's re-export passed all 4,867 tests, and would have
failed on a host at the first entrypoint importing it by name.
"""

import importlib
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LIB = REPO_ROOT / "lib"

# module that was split -> the modules split out of it. The contract is that
# the original still answers for every public name in each of them, because
# that is the promise the split made to callers it did not touch.
RE_EXPORTS = {
    "vm": ("vm_addr", "vm_selinux"),
}


def _lib_modules():
    return sorted(p.stem for p in LIB.glob("*.py") if p.stem != "_version")


class TestEveryLibModuleImportsAlone(unittest.TestCase):

    def test_modules_were_found(self):
        """Guards the guard: a glob that matches nothing passes silently.

        Without this, a moved lib/ directory or a renamed extension turns the
        whole class below into zero assertions reading green.
        """
        self.assertGreater(len(_lib_modules()), 30, _lib_modules())

    def test_each_module_imports_in_a_fresh_interpreter(self):
        failures = []
        for name in _lib_modules():
            result = subprocess.run(
                [sys.executable, "-c", f"import {name}"],
                cwd=LIB, capture_output=True, text=True)
            if result.returncode != 0:
                last = result.stderr.strip().splitlines()[-1:] or ["(no output)"]
                failures.append(f"{name}: {last[0]}")
        self.assertEqual(failures, [], "\n".join(failures))


class TestASplitModuleStillAnswersForItsParts(unittest.TestCase):
    """Every public name in a split-out module is reachable from the original.

    Not a style preference. The split's whole claim is that no caller changed,
    and there are fifteen extensionless entrypoints plus fifty-odd lib modules
    importing names from vm by name; a name missing from the re-export fails
    exactly one of them, at import, on a host.
    """

    def test_the_table_names_modules_that_exist(self):
        """Guards the guard: a renamed module turns every check below into
        zero assertions rather than a failure."""
        for original, parts in RE_EXPORTS.items():
            self.assertTrue((LIB / f"{original}.py").exists(), original)
            for part in parts:
                self.assertTrue((LIB / f"{part}.py").exists(), part)

    def test_every_public_name_is_re_exported(self):
        for original, parts in RE_EXPORTS.items():
            parent = importlib.import_module(original)
            for part in parts:
                module = importlib.import_module(part)
                public = sorted(
                    name for name, value in vars(module).items()
                    if not name.startswith("__")
                    and getattr(value, "__module__", part) == part)
                missing = [n for n in public if not hasattr(parent, n)]
                with self.subTest(original=original, part=part):
                    self.assertEqual(
                        missing, [],
                        f"{part} defines these and {original} does not "
                        f"re-export them: {missing}")

    def test_the_sweep_finds_names_to_check(self):
        """The other half of the guard, on the FILTER rather than the table:
        a `__module__` test that stopped matching would sweep zero names, in
        every part at once, and the check above would pass over nothing."""
        for parts in RE_EXPORTS.values():
            for part in parts:
                module = importlib.import_module(part)
                public = [n for n, v in vars(module).items()
                          if not n.startswith("__")
                          and getattr(v, "__module__", part) == part]
                with self.subTest(part=part):
                    self.assertGreater(len(public), 5, public)
        self.assertIn("VM_UID_MGMT", dir(importlib.import_module("vm_addr")))


if __name__ == "__main__":
    unittest.main()
