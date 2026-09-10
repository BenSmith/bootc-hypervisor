#!/usr/bin/env python3
"""The vm_ prefix is a claim about who a symbol serves, and it is auditable.

WHAT THIS GUARDS

Most of the egress stack is named for the VM and is not the VM's: the CA,
hostname policy, inspection records, nft constants and uid addressing are all
reached by the container path too. A reader who trusts the prefix concludes a
shared thing is VM-specific, and edits it on that belief.

An earlier pass renamed the shared plane's FILES and left 199 of its SYMBOLS
prefixed, and nothing noticed -- because every gate on that work was
structural (imports resolve, the layering is a DAG, the facade re-exports
nothing) and all of them are blind to what a name says. So the work stalled
with a green suite and no way to tell how far it had got short of re-running
an AST pass by hand.

This file is that instrument, made permanent.

WHY IT IS A SET EQUALITY AND NOT A COUNT

A per-module budget would be a hand-written table with the same blind spot as
any hand-written table: it cannot see what nobody added, and it cannot tell a
symbol that was RENAMED from one that was DELETED. Equality can.

  * rename a symbol -> it leaves discovery -> its line must be deleted in the
    same commit, or this fails;
  * add a vm-prefixed symbol -> it enters discovery -> it must be classified
    before the suite is green again.

So RENAME shrinks monotonically without anyone maintaining a counter, and the
file's diff is the record of the work.

WHAT IT DOES NOT DO

Nothing mechanical stops a line being moved from RENAME to KEEP instead of
the work being done -- the classification rule is stated in the data file's
header and enforced by review, not here. And it says nothing about whether a
NEW name is better than the old one; it only insists the old one stopped being
claimed.

Discovery is top-level public definitions in lib/ only. The extension-less
entrypoints under libexec/ define their own names, but nothing imports them,
so a prefix there misleads nobody.
"""

import ast
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LIB = REPO_ROOT / "lib"
TABLE = Path(__file__).resolve().parent / "vm_prefixed_symbols.txt"

PREFIXES = ("vm_", "VM_")


def _defined():
    """{"module.NAME"} for every vm-prefixed public top-level definition.

    Top-level only, and public only. A name nested in a function is not part
    of any module's vocabulary, and an underscore name is already spelled as
    something no other module should be reading.
    """
    found = set()
    for path in sorted(LIB.glob("*.py")):
        for node in ast.parse(path.read_text()).body:
            names = []
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
                names = [node.name]
            elif isinstance(node, ast.Assign):
                names = [t.id for t in node.targets
                         if isinstance(t, ast.Name)]
            elif isinstance(node, ast.AnnAssign) and \
                    isinstance(node.target, ast.Name):
                names = [node.target.id]
            for name in names:
                if not name.startswith("_") and name.startswith(PREFIXES):
                    found.add(f"{path.stem}.{name}")
    return found


def _table():
    """(keep, rename) as sets of "module.NAME"."""
    keep, rename = set(), set()
    for line in TABLE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        verdict, _, symbol = line.partition("\t")
        {"KEEP": keep, "RENAME": rename}[verdict].add(symbol.strip())
    return keep, rename


class TestTheTableIsReadable(unittest.TestCase):
    """Guards the guard. Every failure mode here is silent: a moved file, a
    parser that returns nothing, a discovery sweep that matches nothing. All
    of them produce two empty sets, and two empty sets are equal.
    """

    def test_the_table_is_where_this_thinks_it_is(self):
        self.assertTrue(TABLE.is_file(), TABLE)

    def test_both_verdicts_are_populated(self):
        keep, rename = _table()
        self.assertGreater(len(keep), 10, keep)
        self.assertGreater(len(rename), 10, rename)

    def test_discovery_finds_symbols(self):
        self.assertGreater(len(_defined()), 100)

    def test_no_symbol_is_classified_twice(self):
        keep, rename = _table()
        self.assertEqual(keep & rename, set())

    def test_every_line_is_qualified_by_its_module(self):
        """An unqualified name cannot distinguish two modules defining it,
        and would go on matching after the symbol moved."""
        keep, rename = _table()
        for symbol in keep | rename:
            with self.subTest(symbol=symbol):
                self.assertIn(".", symbol)

    def test_discovery_reads_each_kind_of_definition(self):
        """Measured, not reasoned: a sweep that quietly stopped seeing
        assignments would drop every constant while still reading green on
        the functions."""
        found = _defined()
        self.assertIn("vm_defs.VM_SOCKET_DIR", found)          # Assign
        self.assertIn("workload_addr.vm_inspect_address", found)  # FunctionDef


class TestTheClassificationIsComplete(unittest.TestCase):

    def test_every_defined_symbol_is_classified(self):
        """A new vm-prefixed symbol has to be called shared or not.

        This is the half that stops the backlog growing while nobody is
        looking, which is how it reached 226 in the first place.
        """
        keep, rename = _table()
        unclassified = sorted(_defined() - (keep | rename))
        self.assertEqual(
            unclassified, [],
            "vm-prefixed symbols missing from tests/vm_prefixed_symbols.txt; "
            "classify each as KEEP or RENAME by CONSUMER, per that file's "
            f"header: {unclassified}")

    def test_every_classified_symbol_still_exists(self):
        """The other direction, and the one that makes this a ratchet.

        A renamed symbol leaves discovery, so its line has to go in the same
        commit. Without this the table would keep listing work already done
        and RENAME would never fall.
        """
        keep, rename = _table()
        stale = sorted((keep | rename) - _defined())
        self.assertEqual(
            stale, [],
            "tests/vm_prefixed_symbols.txt lists symbols lib/ no longer "
            f"defines; delete the lines for anything renamed: {stale}")


class TestTheValuePinnedConstants(unittest.TestCase):
    """These two may be renamed; what they hold may not.

    Real hosts already have these paths, and the units, the SELinux filecon
    and the runtime directory all name them independently of Python. A rename
    that carried the value along would be invisible here and fatal there.
    """

    def test_the_socket_dir_value_is_unchanged(self):
        import vm_defs
        self.assertEqual(str(vm_defs.VM_SOCKET_DIR), "/run/workload-vm")

    def test_the_listener_path_is_unchanged(self):
        import workload_addr
        self.assertEqual(
            workload_addr.VM_INSPECT_LISTENER_BIN,
            "/usr/libexec/workloadctl/workload-vm-inspect-listener")


if __name__ == "__main__":
    unittest.main()
