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

import ast
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
    "vm": ("vm_addr", "vm_selinux", "vm_ptp",
            "netfilter_state", "vm_defs",
            "vm_network_config",
            "vm_broker_config"),
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


class TestNoTestPatchesAReExportedName(unittest.TestCase):
    """No test aims a patch at a name its target module only re-exports.

    Found by the split, not reasoned about. `mock.patch("vm.vm_mac_address")`
    and `mock.patch.object(vm, "VM_TLS_UNBUILT")` both stopped working the
    moment those names moved down, because `from x import name` copies the
    binding: rebinding it on the re-exporting module leaves the module that
    actually reads it holding the original. Both failed loudly here, which is
    luck -- they patch something the assertion depends on. A patch installed to
    SUPPRESS something (a network call, a sleep, a subprocess) fails the other
    way: it goes inert, the real thing runs, and the test still passes.

    So the rule is mechanical: patch the module that defines the name, or the
    module that reads it -- never the one that re-exports it.
    """

    @staticmethod
    def _patch_targets():
        """(file, line, module, attribute) for every patch of a `<mod>.<attr>`."""
        found = []
        for path in sorted((REPO_ROOT / "tests").glob("*.py")):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else (
                    func.id if isinstance(func, ast.Name) else None)
                if name == "patch" and node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        mod, _, attr = arg.value.rpartition(".")
                        if mod and "." not in mod:
                            found.append((path.name, node.lineno, mod, attr))
                elif name == "object" and isinstance(func, ast.Attribute) \
                        and len(node.args) >= 2:
                    target, attr = node.args[0], node.args[1]
                    if isinstance(target, ast.Name) and isinstance(attr, ast.Constant) \
                            and isinstance(attr.value, str):
                        found.append((path.name, node.lineno, target.id, attr.value))
        return found

    def test_the_scan_finds_patches(self):
        """Guards the guard: an AST shape that stopped matching passes silently."""
        self.assertGreater(len(self._patch_targets()), 20)

    def test_no_patch_targets_a_re_exported_name(self):
        offenders = []
        for original, parts in RE_EXPORTS.items():
            owned = set()
            for part in parts:
                owned |= {n for n, v in vars(importlib.import_module(part)).items()
                          if not n.startswith("__")
                          and getattr(v, "__module__", part) == part}
            for filename, lineno, mod, attr in self._patch_targets():
                if mod == original and attr in owned:
                    where = [p for p in parts
                             if hasattr(importlib.import_module(p), attr)]
                    offenders.append(
                        f"{filename}:{lineno} patches {mod}.{attr}, which {mod} "
                        f"only re-exports; patch {where[0]}.{attr} or the module "
                        f"that reads it")
        self.assertEqual(offenders, [], "\n".join(offenders))


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
        "libexec/workload-ensure-user": ("ensure_common",),
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
