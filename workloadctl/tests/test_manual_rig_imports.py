#!/usr/bin/env python3
"""Imports the rigs write INSIDE STRINGS still resolve against lib/.

WHY THIS EXISTS

A rig row that needs to read shipped code from inside a netns, or as another
uid, or against the installed RPM rather than the checkout, builds a small
Python program as a string and hands it to `python3 -c`. The import in that
program is not code to any tool that reads the rig: it is a string constant.

So every check the tree has looks straight past it. `just lint` is
py_compile, which compiles the literal and never its contents. An AST sweep
for callers -- the kind used to prove a module split moved every consumer --
walks `ast.Constant` and stops. The unit suite never runs the rigs at all,
and the rigs themselves only run on a KVM host, by hand, months apart.

That is exactly how one broke: `self_dial_rig` read `from vm import
nft_element_counter` in a `python3 -c` payload, the function moved to
netfilter_state.py, and the rig kept passing every gate in the repo while
being guaranteed to die with an ImportError on its next hardware run. It
would have presented as the SELF-DIAL MEASUREMENT failing, not as a stale
import -- a rig defect wearing a product defect's face, which is the whole
hazard `tests/manual/README.md` is written around.

WHAT IT DOES NOT DO

It resolves NAMES, not signatures. A function that still exists under a new
arity resolves here and fails on hardware just the same. And it only sees
imports spelled literally in a string; a rig that assembled a module name
from parts would be invisible to it. Neither is worth chasing -- the failure
this catches is the one that actually happened, and it is the cheap half.
"""

import ast
import importlib
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LIB = REPO_ROOT / "lib"
MANUAL = REPO_ROOT / "tests" / "manual"

# The snippets are one-liners joined with `;` as often as they are real
# multi-line programs, so both separators count as a statement boundary.
# They also arrive holding %-placeholders (`sys.path.insert(0, "%s")`), which
# is why this is a regex and not ast.parse of the string: the payload is
# frequently not valid Python until it has been interpolated.
FROM_IMPORT = re.compile(
    r"(?:^|;)[ \t]*from[ \t]+([A-Za-z_]\w*)[ \t]+import[ \t]+([\w, ]+)", re.M)
PLAIN_IMPORT = re.compile(
    r"(?:^|;)[ \t]*import[ \t]+([\w, ]+)", re.M)


def _lib_modules():
    return {p.stem for p in LIB.glob("*.py") if p.stem != "_version"}


def _embedded_strings():
    """(rig name, line, string) for every string constant in every rig."""
    out = []
    for path in sorted(MANUAL.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and \
                    isinstance(node.value, str):
                out.append((path.name, node.lineno, node.value))
    return out


def _string_imports():
    """What the rigs import from lib/ inside a string.

    Returns (from_imports, plain_imports):
      from_imports  -- (rig, line, module, [names])
      plain_imports -- (rig, line, module, [attributes read off it])

    The attribute half matters because `import cmd_diagnose` followed by
    `cmd_diagnose.inspect_check(...)` is the same decay with the name on
    the other side of the dot, and resolving only the module would pass
    against a module that had lost the function entirely.
    """
    lib = _lib_modules()
    froms, plains = [], []
    for rig, line, text in _embedded_strings():
        for match in FROM_IMPORT.finditer(text):
            module = match.group(1)
            if module in lib:
                names = [n.strip() for n in match.group(2).split(",")
                         if n.strip()]
                froms.append((rig, line, module, names))
        for match in PLAIN_IMPORT.finditer(text):
            for module in (m.strip() for m in match.group(1).split(",")):
                if module in lib:
                    attrs = sorted(set(re.findall(
                        r"\b%s\.(\w+)" % re.escape(module), text)))
                    plains.append((rig, line, module, attrs))
    return froms, plains


class TestTheSweepSeesTheStrings(unittest.TestCase):
    """Guards the guard. Every failure mode of this file is silent: a moved
    rigs directory, a regex that stopped matching, a glob that matches
    nothing. All of them find zero imports, and zero imports all resolve.
    """

    def test_the_rigs_are_where_this_thinks_they_are(self):
        self.assertTrue(MANUAL.is_dir(), MANUAL)
        self.assertGreater(len(list(MANUAL.glob("*.py"))), 5)

    def test_the_lib_modules_were_found(self):
        self.assertGreater(len(_lib_modules()), 30)

    def test_the_extractor_reads_inside_strings(self):
        """Asserted over ALL imports the rigs embed, stdlib included, not
        over the lib ones. The lib count is legitimately small and would
        drop to zero if a rig were rewritten; the total is what proves the
        scan is still reading string contents at all."""
        embedded = 0
        for _, _, text in _embedded_strings():
            embedded += len(FROM_IMPORT.findall(text))
            embedded += len(PLAIN_IMPORT.findall(text))
        self.assertGreater(embedded, 5, embedded)

    def test_it_finds_the_lib_imports_that_are_there(self):
        froms, plains = _string_imports()
        self.assertGreaterEqual(len(froms) + len(plains), 2,
                                f"{froms} {plains}")

    def test_the_check_would_see_a_stale_import(self):
        """Measured, not reasoned: the same extractor run over a snippet in
        the exact shape that broke -- adjacent literals, `;` separators,
        %-placeholders -- against a name lib/ does not define."""
        stale = ("import json,sys;sys.path.insert(0,%r);"
                 "from netfilter_state import no_such_function;"
                 "print(no_such_function(%d))")
        found = FROM_IMPORT.findall(stale)
        self.assertEqual(found, [("netfilter_state", "no_such_function")])
        module = importlib.import_module("netfilter_state")
        self.assertFalse(hasattr(module, "no_such_function"))


class TestEveryEmbeddedImportResolves(unittest.TestCase):

    def test_from_imported_names_exist(self):
        broken = []
        for rig, line, module, names in _string_imports()[0]:
            imported = importlib.import_module(module)
            for name in names:
                if not hasattr(imported, name):
                    broken.append(
                        f"tests/manual/{rig}:{line} embeds "
                        f"'from {module} import {name}' in a python3 -c "
                        f"payload, and lib/{module}.py no longer defines "
                        f"{name}; the rig will fail at import on hardware")
        self.assertEqual(broken, [], "\n".join(broken))

    def test_attributes_read_off_an_imported_module_exist(self):
        broken = []
        for rig, line, module, attrs in _string_imports()[1]:
            imported = importlib.import_module(module)
            for attr in attrs:
                if not hasattr(imported, attr):
                    broken.append(
                        f"tests/manual/{rig}:{line} embeds "
                        f"'{module}.{attr}' in a python3 -c payload, and "
                        f"lib/{module}.py no longer defines {attr}")
        self.assertEqual(broken, [], "\n".join(broken))


if __name__ == "__main__":
    unittest.main()
