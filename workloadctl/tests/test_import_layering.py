#!/usr/bin/env python3
"""The shared plane does not reach upward -- including from inside a function.

`lib/` is flat, so nothing about the file layout says which module may depend
on which. The intended direction is

    config_parser -> shared plane -> workload_lib -> substrate modules -> CLI

and the plane is the half that has to stay clean: a module below the line that
imports something above it is a cycle, and a cycle here is not hypothetical --
`workload_lib` reaches `vm` from inside four function bodies right now, which
is exactly how it stayed invisible.

**A deferred import is invisible to every other gate in this suite.**
`test_module_imports.py` imports each module alone in a fresh interpreter,
which is the strongest check available for a *module-level* cycle and
structurally blind to this one: the import never runs, because the function is
never called. `just lint` is `py_compile`, which does not execute imports at
all. `test_stdlib_only.py` walks the AST but asks a different question. So the
cycle survived every gate, indefinitely, while reading green -- and it survives
a green suite today, because deferred imports *work*. They resolve at call
time, by which point `sys.modules` is fully populated. Nothing breaks. That is
the problem: the cost is not a failure, it is that the layering claim is false
and no one can tell.

Hence this test walks function and class bodies too, and asserts on the edges
rather than on whether anything blows up.

The known violations are listed in `UPWARD_EDGES` with exact counts, and the
assertion is set equality, not "no new modules". Two consequences, both
intended: a fifth `workload_lib` -> `vm` import fails here even though that
pair is already listed, and REMOVING one fails too. The second is the point --
this table is a countdown. B3 of the shared-plane extraction is finished when
`UPWARD_EDGES` is empty, and every entry that disappears has to be deleted
from this table by the commit that fixed it, so the table cannot quietly
describe a tree that has moved on.
"""

import ast
import unittest
from collections import Counter
from pathlib import Path

from tests import REPO_ROOT

LIB = Path(REPO_ROOT) / "lib"

# The shared plane: modules that must not depend on anything above them.
# Three do not exist yet -- B2 creates them -- and are listed so that the
# first commit to add one inherits the rule instead of having to remember it.
PLANE = frozenset({
    "workload_addr", "egress_selinux", "egress_status", "egress_mint",
    "broker_config",
    "config_parser", "nft_constants", "egress_ca", "egress_policy",
})

# Everything the plane may not import. `cmd_*` is matched by prefix below.
ABOVE_THE_PLANE = frozenset({"vm", "workload_lib"})

# What the tree does today, and nothing more. Empty is the goal; see B3.
UPWARD_EDGES = {
    # The cycle itself: workload_lib is above the plane and reaches back into
    # the substrate facade from four function bodies.
    ("workload_lib", "vm"): 4,
    # Four parsing constants that belong in workload_addr and currently live
    # in workload_lib; this edge dies when they move.
    ("workload_addr", "workload_lib"): 1,
    # CREDSTORE_DIR (module level and again lazily) plus the credential path
    # helper, which lives in the CLI layer.
    ("broker_config", "workload_lib"): 2,
    ("broker_config", "cmd_secret"): 1,
    # egress_mint reaches the facade for the names it mints against.
    ("egress_mint", "vm"): 1,
}


def _lib_module_names():
    return {p.stem for p in LIB.glob("*.py")}


def _imports_in(tree, known):
    """Every (imported_module, deferred) an AST names, at any nesting depth.

    `deferred` is True when the import is not a direct child of the module
    body -- inside a function, a class, a `try`, an `if`. That flag is the
    whole reason this module exists, so it is computed here rather than
    inferred from indentation.
    """
    top_level = {id(node) for node in tree.body}
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            # A relative import cannot name a flat lib module.
            names = [node.module] if node.level == 0 and node.module else []
        elif isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        else:
            continue
        for name in names:
            if name in known:
                found.append((name, id(node) not in top_level))
    return found


def _upward_edges():
    """(importer, imported) -> count, for every plane module reaching up."""
    known = _lib_module_names() | PLANE
    counts = Counter()
    for path in sorted(LIB.glob("*.py")):
        if path.stem not in PLANE and path.stem != "workload_lib":
            continue
        tree = ast.parse(path.read_text())
        for imported, _deferred in _imports_in(tree, known):
            above = imported in ABOVE_THE_PLANE or imported.startswith("cmd_")
            if path.stem == "workload_lib":
                # workload_lib is above the plane, so only the substrate
                # facade is upward for it. It legitimately imports vm_defs,
                # vm_network_config and broker_config.
                above = imported == "vm"
            if above and imported != path.stem:
                counts[(path.stem, imported)] += 1
    return counts


class TestTheScannerSeesADeferredImport(unittest.TestCase):
    """Guards the guard. Every assertion below is a claim about what the walk
    FOUND, so a walk that quietly found nothing reads green -- and the thing it
    most plausibly stops finding is the nested import, which is the only kind
    the rest of the suite already covers.
    """

    def test_a_deferred_import_is_flagged_and_a_top_level_one_is_not(self):
        tree = ast.parse(
            "from vm import A\n"
            "def f():\n"
            "    from workload_lib import B\n"
            "class C:\n"
            "    import vm_defs\n")
        found = dict(_imports_in(tree, {"vm", "workload_lib", "vm_defs"}))
        self.assertEqual(found["vm"], False)
        self.assertEqual(found["workload_lib"], True, "function body missed")
        self.assertEqual(found["vm_defs"], True, "class body missed")

    def test_the_plane_modules_exist(self):
        """A rename that outran this table would empty PLANE of real files and
        turn the rule below into zero assertions."""
        present = _lib_module_names() & PLANE
        self.assertGreaterEqual(
            len(present), 5, f"PLANE names no existing module but {present}")

    def test_the_walk_reaches_real_source(self):
        known = _lib_module_names()
        total = sum(
            len(_imports_in(ast.parse(p.read_text()), known))
            for p in LIB.glob("*.py"))
        self.assertGreater(total, 50, total)


class TestTheSharedPlaneDoesNotReachUpward(unittest.TestCase):

    def test_upward_edges_match_the_table_exactly(self):
        actual = _upward_edges()
        expected = Counter(UPWARD_EDGES)
        new = {edge: n for edge, n in actual.items()
               if n > expected.get(edge, 0)}
        gone = {edge: n for edge, n in expected.items()
                if n > actual.get(edge, 0)}
        self.assertEqual(
            new, {},
            "new upward import(s) from the shared plane -- a module below the "
            f"line is reaching above it: {sorted(new)}")
        self.assertEqual(
            gone, {},
            "an upward import in UPWARD_EDGES is gone (good) -- delete it from "
            f"the table in the same commit: {sorted(gone)}")

    def test_the_cycle_is_still_the_one_this_table_describes(self):
        """B3's exit condition, written so that reaching it fails loudly.

        When `workload_lib` no longer imports `vm` from anywhere, this test
        fails and is deleted along with the entry -- rather than the suite
        going quiet about a milestone.
        """
        self.assertIn(("workload_lib", "vm"), UPWARD_EDGES,
                      "the workload_lib -> vm cycle is broken: delete this "
                      "test and the UPWARD_EDGES entry")


if __name__ == "__main__":
    unittest.main()
