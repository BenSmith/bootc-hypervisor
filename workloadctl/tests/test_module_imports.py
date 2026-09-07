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

This matters most for the file splits in docs/wip/simplification-survey.md
(§1, §4, §5): splitting a module and re-exporting the moved names from the
original -- the pattern 582948a established for vm_normalise_hostname -- is
exactly the shape that produces a cycle, because the new module needs
something from the old one and the old one now imports the new.
"""

import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LIB = REPO_ROOT / "lib"


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


if __name__ == "__main__":
    unittest.main()
