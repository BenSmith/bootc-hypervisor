#!/usr/bin/env python3
"""The inspector knows nothing about workloads: its import closure says so.

The egress inspector (libexec/workload-inspect-listener, lib/inspect_listener.py
and everything they import) is started by workloadctl, on a host workloadctl
laid out, from a document workloadctl rendered -- and none of that is the
inspector's to know. It takes a policy document, a state directory, a
status file, a record file and a broker endpoint, all as flags on its
command line, and its closure contains no module that reads a workload's
config, no module that knows where a workload keeps its state, no module
that turns a uid into an address, and no module that can speak to a guest.
The GENERATOR (gen_egress.inspect_listener_command) is the one place those
facts are derived: it imports the workloadctl side to compute the values
and writes them into the unit's ExecStart=.

The entrypoint was a LAUNCHER until the flags -- it took a workload name and
imported egress_policy, workload_lib and workload_addr to compute the rest,
so it was the one file importing both sides. This file then held the
launcher's workload-side imports to an exact set. Now it holds them to
none, and holds the generator to naming every value.

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

# The inspector's roots: the module the entrypoint hands values to, and the
# reader that turns the document into the Policy it is handed. The
# entrypoint itself is walked too (see _closure); it is not a lib module.
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
    # The renderers that produce the documents the inspector reads, and
    # the broker's command line. (broker_profiles was here while it read
    # broker.toml; it reads flags now and knows no workload, so it is fenced
    # by test_broker_closure rather than named here.)
    "egress_policy", "broker_config",
    # Where a workload's things live, and what a uid becomes.
    "workload_addr", "workload_uid", "run_files", "secrets_template",
    # Substrates and the machinery only a substrate has.
    "vm_defs", "vm_clock", "qmp", "substrate", "substrate_vm",
    "substrate_container", "podman",
    # Arming and generation are the generator's world, not the listener's.
    "inspect_arm", "filter_arm", "nft", "nft_elements", "nft_constants",
    "gen_egress", "gen_vm", "gen_container",
})

# The flags the generator hands the entrypoint, exactly: one per value the
# inspector must be told and cannot derive. Set equality rather than a
# subset, so that a new derivation is a deliberate edit here and a value
# that stopped being handed over (because the inspector started deriving it
# for itself) fails too.
HANDED_FLAGS = frozenset({
    "--name",       # a label: the CA subject and the log lines
    "--policy",     # where the policy document is
    "--state-dir",  # where the CA and the leaf caches are
    "--status",     # where the counters go
    "--record",     # where the per-request record goes
    "--broker",     # what the uid became, and the broker's port
})
# NOT a clock hook, and there was one: the launcher once handed the
# inspector a guest-clock resync to run before every fresh mint. The clock
# keeper (workload-<name>-clock.timer) owns that on every VM now, so nothing
# about the guest is handed over and the inspector's closure holds no QMP
# client. A vm_clock import reappearing anywhere below is the seam coming
# back.


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


def _closure(roots, mods, *, launcher=None):
    """The lib modules reachable from `roots`, plus, when given, from the
    entrypoint file -- which has no `.py` and so is not in `mods`."""
    seen = set()
    todo = list(roots)
    if launcher is not None:
        todo.extend(_direct_imports(launcher, set(mods)))
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

    def test_the_roots_and_the_entrypoint_exist(self):
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
        closure = _closure(INSPECTOR_ROOTS, _lib_modules(), launcher=LAUNCHER)
        crossed = sorted(closure & WORKLOAD_SIDE)
        self.assertEqual(
            crossed, [],
            "the inspector's import closure reaches the workload side; the "
            "value it needs from there belongs in the generator, handed in "
            f"as a flag: {crossed}")

    def test_the_closure_reads_no_toml(self):
        """The rule's plainest reading, checked independently of the table:
        nothing the inspector imports parses TOML. A module that did would
        be one the table should have named."""
        mods = _lib_modules()
        closure = _closure(INSPECTOR_ROOTS, mods, launcher=LAUNCHER)
        readers = sorted(m for m in closure if _imports_tomllib(mods[m]))
        self.assertEqual(readers, [], readers)
        self.assertFalse(_imports_tomllib(LAUNCHER))

    def test_the_inspector_derives_no_path_address_or_state_dir(self):
        """The values the generator hands over, asserted by absence of the
        functions that would derive them -- in the closure and in the
        entrypoint. A closure test would catch the import; this catches a
        copy."""
        mods = _lib_modules()
        closure = _closure(INSPECTOR_ROOTS, mods, launcher=LAUNCHER)
        sources = {m: mods[m].read_text() for m in closure}
        sources["workload-inspect-listener"] = LAUNCHER.read_text()
        # Call-shaped, so that a docstring pointing a reader at where the
        # path IS defined (egress_record's does) is not a finding; a call is.
        for name in ("broker_listen_address", "workload_state_dir",
                     "workload_root_dir", "inspect_policy_path",
                     "inspect_status_path", "inspect_record_path",
                     "resync_guest_clock_if_skewed"):
            holders = sorted(m for m, text in sources.items()
                             if f"{name}(" in text)
            self.assertEqual(holders, [], f"{name} called in {holders}")


class TestTheGeneratorIsTheOnlyPlaceTheTwoMeet(unittest.TestCase):
    """The entrypoint imports nothing from the workload side, and the
    generator's ExecStart= names every value it needs."""

    def test_the_entrypoint_imports_nothing_from_the_workload_side(self):
        """This set was {egress_policy, workload_lib, workload_addr} while
        the entrypoint was a launcher. A module reappearing here is the
        derivation coming back into the inspector's process."""
        mods = _lib_modules()
        direct = _direct_imports(LAUNCHER, set(mods))
        self.assertEqual(sorted(direct & WORKLOAD_SIDE), [])

    def test_the_generator_hands_every_value_across(self):
        """Each flag the entrypoint requires appears on the rendered
        ExecStart=, with the value the workload side derives for it -- or the
        generator dropped one and the listener fails its start on the
        guest's first dial, long after the generator ran."""
        from egress_policy import (
            inspect_policy_path, inspect_record_path, inspect_status_path,
        )
        from gen_egress import inspect_listener_command
        from workload_addr import BROKER_INSTANCE_PORT, broker_listen_address
        from workload_lib import workload_state_dir
        cmd = inspect_listener_command("web", 10004)
        flags = {cmd[i]: cmd[i + 1] for i in range(1, len(cmd), 2)}
        self.assertEqual(set(flags), HANDED_FLAGS)
        self.assertEqual(flags, {
            "--name": "web",
            "--policy": inspect_policy_path("web"),
            "--state-dir": str(workload_state_dir("web")),
            "--status": inspect_status_path("web"),
            "--record": str(inspect_record_path("web")),
            "--broker": f"{broker_listen_address(10004)}:{BROKER_INSTANCE_PORT}",
        })

    def test_the_entrypoint_requires_every_handed_flag(self):
        """The other direction: a flag the generator emits that the
        entrypoint does not take is an argparse error at start, and a flag
        the entrypoint takes that the generator does not emit is a required
        argument missing -- both fail the start, but only on the guest's
        first dial. Read from the source: the parser is built inside a
        function so the module can be loaded without running it."""
        text = LAUNCHER.read_text()
        for flag in HANDED_FLAGS:
            self.assertIn(f'"{flag}"', text, flag)


if __name__ == "__main__":
    unittest.main()
