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
re-exporting the moved names from the original is exactly the shape that
produces a cycle, because the new module needs something from the old one and
the old one now imports the new.

The second class below holds the OTHER half of that pattern -- the half the
re-export itself costs, once the split is done and the callers have moved.
"""

import ast
import importlib
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LIB = REPO_ROOT / "lib"

# Modules that must publish only what they define. `lib/` is flat, so there is
# no such thing as a private import here: every `from X import name` in one of
# these is a name its own callers can then read off it.
NO_RE_EXPORTS = ("vm",)


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


class TestAFacadeReExportsNothing(unittest.TestCase):
    """These modules import nothing they do not use, so they publish nothing
    they do not define.

    `lib/` is flat, so an import IS a re-export: `from egress_ca import
    CA_BACKDATE_SECONDS` inside vm.py does not merely make that name
    available to vm.py, it makes `vm.CA_BACKDATE_SECONDS` answer forever
    after. vm.py published 299 names it did not define, drawn from eleven
    modules, and the line count was the least of it. A reader who found `vm.X`
    had no way to tell which module owned X. `mock.patch("vm.X")` rebound a
    copy and left the module that actually reads X holding the original --
    which fails loudly when the patch feeds an assertion and goes silently
    inert when it was installed to SUPPRESS something. And every subsequent
    split had to either grow the hand-written list or drop a name from vm's
    surface, where nothing in the suite would notice: dropping UID_MGMT
    from it passed all 4,867 tests and would have failed on a host, at the
    first entrypoint importing it by name.

    So the rule is now mechanical -- a name is imported from the module that
    defines it -- and what makes the rule keepable is that a re-export is
    exactly an import the file does not use. What makes it worth checking is
    that adding one back is a single line which breaks nothing, passes every
    other test here, and is invisible until the surface has grown again.
    """

    @staticmethod
    def _unused_imports(name):
        """Names `from`-imported by a module and referenced nowhere in it.

        `import x` is left out on purpose: binding a module is not publishing
        a name, and a dead one is a lint finding rather than a facade. So is
        `__future__`, whose whole effect is on the compiler.
        """
        tree = ast.parse((LIB / f"{name}.py").read_text())
        imported = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) \
                    and node.module != "__future__":
                for alias in node.names:
                    imported[alias.asname or alias.name] = node.lineno
        used = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used.add(node.id)
            elif isinstance(node, ast.Attribute):
                used.add(node.attr)
            elif isinstance(node, ast.Constant) and \
                    isinstance(node.value, str):
                # __all__ entries and string annotations both read as strings.
                used.add(node.value)
        return {n: line for n, line in imported.items() if n not in used}

    def test_the_modules_exist(self):
        """Guards the guard: a renamed module makes the check below parse
        nothing and pass."""
        for name in NO_RE_EXPORTS:
            self.assertTrue((LIB / f"{name}.py").exists(), name)

    def test_the_sweep_sees_the_imports(self):
        """The other half of the guard, on the SCAN rather than the file: an
        AST shape that stopped matching would find zero imports, and zero
        imports are trivially all used."""
        for name in NO_RE_EXPORTS:
            tree = ast.parse((LIB / f"{name}.py").read_text())
            names = [a.asname or a.name for node in ast.walk(tree)
                     if isinstance(node, ast.ImportFrom)
                     for a in node.names]
            with self.subTest(module=name):
                self.assertGreater(len(names), 5, names)

    def test_no_imported_name_is_unused(self):
        offenders = []
        for name in NO_RE_EXPORTS:
            for unused, line in sorted(self._unused_imports(name).items()):
                offenders.append(
                    f"lib/{name}.py:{line} imports {unused} and never uses "
                    f"it, so {name}.{unused} is a re-export; import it from "
                    f"the module that defines it instead")
        self.assertEqual(offenders, [], "\n".join(offenders))

    def test_the_check_would_see_a_re_export(self):
        """Measured, not reasoned. The scan counts a name used if it appears
        anywhere -- including in a string, for __all__ and for annotations --
        so it is loose by construction, and a loose scan that has nothing to
        find reads exactly like a strict one."""
        tree = ast.parse("from egress_ca import CA_BACKDATE_SECONDS\n"
                         "x = 1\n")
        imported = {a.asname or a.name
                    for node in ast.walk(tree)
                    if isinstance(node, ast.ImportFrom) for a in node.names}
        used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        self.assertEqual(imported - used, {"CA_BACKDATE_SECONDS"})


class TestASharedModuleIsNotShadowedByItsCaller(unittest.TestCase):
    """No entrypoint redefines a name it imports from a shared lib module.

    The other end of the split hazard. generators/workload-generate does
    `from gen_common import log_msg, generate_setup_service, ...`; if someone
    later adds a `def log_msg` back into the generator -- restoring a helper
    from a stale branch, or writing one without noticing the import forty lines
    up -- Python takes the local definition and the import becomes dead. The
    generator then uses one implementation and gen_common's own internals use
    the other, and the two drift apart with every edit to either.

    Nothing else sees it. `just lint` is py_compile, which does not diagnose a
    redefinition. The unit suite drives the generator end to end, so both
    copies are exercised and both are usually right -- until they are not, and
    then the failure reads as the shared helper being wrong rather than as
    there being two of it.

    Checked by AST on the entrypoint alone: the extensionless entrypoints are
    invisible to `_lib_modules()` and importing one runs its argv parsing.
    """

    # file (repo-relative) -> lib modules it imports names from
    SHARED_IMPORTS = {
        "generators/workload-generate": ("gen_common", "gen_vm",
                                        "gen_container"),
        "lib/gen_vm.py": ("gen_common",),
        "lib/gen_container.py": ("gen_common",),
        "libexec/workload-ensure-user": ("ensure_common", "ensure_vm",
                                        "ensure_container"),
        "lib/ensure_vm.py": ("ensure_common",),
        "lib/ensure_container.py": ("ensure_common",),
    }

    @staticmethod
    def _top_level_names(path):
        tree = ast.parse(path.read_text())
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        names.add(t.id)
        return names

    def test_the_files_exist_and_define_names(self):
        """Guards the guard: a renamed file, or an AST walk that stopped
        matching, turns the check below into zero comparisons reading green."""
        for entry in self.SHARED_IMPORTS:
            path = REPO_ROOT / entry
            self.assertTrue(path.exists(), entry)
            self.assertGreater(len(self._top_level_names(path)), 5, entry)

    def test_no_file_shadows_a_shared_name(self):
        collisions = []
        for entry, modules in self.SHARED_IMPORTS.items():
            local = self._top_level_names(REPO_ROOT / entry)
            for name in modules:
                module = importlib.import_module(name)
                shared = {n for n, v in vars(module).items()
                          if not n.startswith("__")
                          and getattr(v, "__module__", name) == name}
                self.assertGreater(len(shared), 5, name)
                for clash in sorted(local & shared):
                    collisions.append(
                        f"{entry} defines {clash}, which it also imports from "
                        f"{name}; the import is dead and the two copies drift")
        self.assertEqual(collisions, [], "\n".join(collisions))


if __name__ == "__main__":
    unittest.main()
