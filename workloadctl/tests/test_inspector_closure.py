#!/usr/bin/env python3
"""The inspector knows nothing about workloads: its import closure says so.

The egress inspector (lib/inspect_listener.py and everything it imports) is
started by workloadctl, on a host workloadctl laid out, from a document
workloadctl rendered -- and none of that is the inspector's to know. It takes
a policy document, a state directory, a broker endpoint and an optional
clock hook, all as values, and its closure contains no module that reads a
workload's config, no module that knows where a workload keeps its state,
and no module that turns a uid into an address. The entrypoint
(libexec/workload-inspect-listener) is the one place those facts are
derived, and it is a LAUNCHER: it imports the workloadctl side to compute
the values and the inspector side to hand them over.

WHY A CLOSURE AND NOT A LIST OF IMPORTS

The line was crossed by depth, not by a direct import: inspect_listener
never imported a config module, but it imported vm_clock for the guest-clock
remedy, and vm_clock imports qmp and vm_defs, and vm_defs imports the
config grammar -- so a TLS listener's closure held 32 modules, among them the
`[vm]` schema and a QMP client. Each edge was reasonable on its own. Only the
closure shows that the inspector could not be started without the whole of
workloadctl beside it, which is the property this file exists to hold.

test_import_layering.py asks a different question (does the shared plane
reach UP), and passed throughout: vm_defs and workload_lib are legitimately
above the plane, and the inspector is not a plane module. This asks whether
one specific program's closure stays inside one specific set.
"""

import ast
import unittest
from pathlib import Path

from tests import REPO_ROOT

LIB = Path(REPO_ROOT) / "lib"
LAUNCHER = Path(REPO_ROOT) / "libexec" / "workload-inspect-listener"

# The inspector's roots: the module the launcher hands values to, and the
# reader that turns the document into the Policy it is handed.
INSPECTOR_ROOTS = ("inspect_listener", "inspect_policy")

# Modules the inspector's closure must not contain. Each is named for what it
# knows: the config grammar, a workload's layout, a substrate, an address
# derivation. The list is explicit rather than "everything not in an allowed
# set" so that a new inspector-side module needs no registration -- but a
# new module that knows about workloads DOES need adding here, and a
# reviewer of a module that imports tomllib or workload_lib should ask
# whether it belongs in this table.
WORKLOAD_SIDE = frozenset({
    # The config grammar and its readers.
    "config_parser", "container_network_config", "vm_network_config",
    "credential_entries", "workloadctl_core", "workload_lib",
    # The renderers that produce the documents the inspector reads.
    "egress_policy", "broker_config", "broker_profiles",
    # Where a workload's things live, and what a uid becomes.
    "workload_addr", "workload_uid", "run_files", "secrets_template",
    # Substrates and the machinery only a substrate has.
    "vm_defs", "vm_clock", "qmp", "substrate", "substrate_vm",
    "substrate_container", "podman",
    # Arming and generation are the launcher's world, not the listener's.
    "inspect_arm", "filter_arm", "nft", "nft_elements", "nft_constants",
    "gen_egress", "gen_vm", "gen_container",
})

# What the launcher may import from the workload side, exactly. Set equality
# rather than a subset, so that a new derivation is a deliberate edit here
# and a derivation that moved into the inspector (leaving this list short)
# fails too.
LAUNCHER_WORKLOAD_IMPORTS = frozenset({
    "egress_policy",   # where the policy, status and record files are
    "workload_lib",    # where the state directory is
    "workload_addr",   # what the uid becomes, and the broker's port
    "vm_clock",        # the guest-clock remedy, a VM's to offer
})


def _lib_modules():
    return {p.stem: p for p in LIB.glob("*.py")}


def _direct_imports(path, known):
    """Every lib module a file imports, at any depth of nesting.

    Nested imports count, for the reason test_import_layering gives: a
    deferred import resolves at call time and is invisible to a fresh-
    interpreter import test, so a closure computed from top-level imports
    alone would miss exactly the edge most likely to be hidden.
    """
    tree = ast.parse(path.read_text())
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module in known:
                found.add(node.module)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in known:
                    found.add(alias.name)
    return found


def _closure(roots, mods):
    seen = set()
    todo = list(roots)
    while todo:
        name = todo.pop()
        if name in seen or name not in mods:
            continue
        seen.add(name)
        todo.extend(_direct_imports(mods[name], mods))
    return seen


def _imports_tomllib(path):
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(a.name == "tomllib" for a in node.names):
                return True
        elif isinstance(node, ast.ImportFrom) and node.module == "tomllib":
            return True
    return False


class TestTheScannerSeesTheTree(unittest.TestCase):
    """Guards the guard: every assertion below is about what the walk FOUND."""

    def test_the_roots_and_the_launcher_exist(self):
        mods = _lib_modules()
        for root in INSPECTOR_ROOTS:
            self.assertIn(root, mods)
        self.assertTrue(LAUNCHER.exists())

    def test_the_closure_is_not_trivial(self):
        """The inspector is a TLS-terminating HTTP relay with a minter and a
        record; a closure of three modules means the walk stopped early."""
        closure = _closure(INSPECTOR_ROOTS, _lib_modules())
        self.assertGreater(len(closure), 10, sorted(closure))
        for expected in ("inspect_tls", "inspect_http", "egress_upstream",
                         "egress_mint", "egress_ca", "inspect_document"):
            self.assertIn(expected, closure)

    def test_the_workload_side_names_real_modules(self):
        """A rename that outran this table would silently shrink the rule."""
        missing = WORKLOAD_SIDE - set(_lib_modules())
        self.assertEqual(missing, set(), sorted(missing))

    def test_the_walk_sees_a_nested_import(self):
        tree_path = LIB / "run_files.py"
        # run_files defers `from workloadctl_core import ...` inside a
        # function (test_import_layering documents why); the walk must see it.
        self.assertIn("workloadctl_core",
                      _direct_imports(tree_path, set(_lib_modules())))


class TestTheInspectorKnowsNothingAboutWorkloads(unittest.TestCase):

    def test_the_closure_contains_no_workload_side_module(self):
        closure = _closure(INSPECTOR_ROOTS, _lib_modules())
        crossed = sorted(closure & WORKLOAD_SIDE)
        self.assertEqual(
            crossed, [],
            "the inspector's import closure reaches the workload side; the "
            "value it needs from there belongs in the launcher, handed in as "
            f"an argument: {crossed}")

    def test_the_closure_reads_no_toml(self):
        """The rule's plainest reading, checked independently of the table:
        nothing the inspector imports parses TOML. A module that did would
        be one the table should have named."""
        mods = _lib_modules()
        closure = _closure(INSPECTOR_ROOTS, mods)
        readers = sorted(m for m in closure if _imports_tomllib(mods[m]))
        self.assertEqual(readers, [], readers)

    def test_the_inspector_derives_no_path_address_or_state_dir(self):
        """The three values the launcher hands over, asserted by absence of
        the functions that would derive them. A closure test would catch the
        import; this catches a copy."""
        mods = _lib_modules()
        closure = _closure(INSPECTOR_ROOTS, mods)
        for name in ("broker_listen_address", "workload_state_dir",
                     "workload_root_dir", "inspect_policy_path",
                     "resync_guest_clock_if_skewed"):
            holders = sorted(m for m in closure
                             if name in mods[m].read_text())
            self.assertEqual(holders, [], f"{name} named in {holders}")


class TestTheLauncherIsTheOnlyPlaceTheTwoMeet(unittest.TestCase):

    def test_the_launcher_imports_exactly_the_derivations(self):
        mods = _lib_modules()
        direct = _direct_imports(LAUNCHER, set(mods))
        self.assertEqual(direct & WORKLOAD_SIDE, LAUNCHER_WORKLOAD_IMPORTS)

    def test_the_launcher_hands_every_value_across(self):
        """Each derivation the launcher makes has to reach the inspector as
        an argument, or the launcher derived something the inspector then
        re-derived for itself. Read the source rather than run it: main()
        needs inherited sockets."""
        text = LAUNCHER.read_text()
        for handed in ("workload_state_dir(name)", "remedy=",
                       "broker_endpoint=", "status_path=", "record_path="):
            self.assertIn(handed, text, handed)


if __name__ == "__main__":
    unittest.main()
