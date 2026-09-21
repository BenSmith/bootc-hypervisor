#!/usr/bin/env python3
"""The broker knows nothing about workloads: its import closure says so.

The credential broker (libexec/agent-broker, lib/broker_profiles.py,
lib/broker_server.py and everything they import) is started by workloadctl,
for a workload workloadctl created, on an address workloadctl derived -- and
none of that is the broker's to know. It takes a name, a listen endpoint, a
caller uid and a set of credential ids, all as flags on its command line,
and its closure contains no module that reads a workload's config, no module
that knows where a workload keeps its things, no module that turns a uid
into an address or a name, and nothing that parses TOML. The GENERATOR
(broker_config.broker_command, written to the unit by
gen_egress.generate_broker_service) is the one place those facts are
derived: it imports the workloadctl side to compute the values and writes
them into the unit's ExecStart=.

The broker was closer to this than the inspector was, and further in one
way. It never derived a path: it took a document, broker.toml, rendered by
an ExecStartPre from the workload TOML. But the document was keyed by
WORKLOAD NAME, so the broker resolved each caller's uid to a `_wl-<name>`
user through passwd to look it up -- the naming convention was in the
broker's process, and peer_identity carried the prefix. Now the uid is a
flag, the comparison is uid to uid, and the prefix is gone from both
daemons. This file holds that, the way test_inspector_closure holds the
inspector's.

WHY A CLOSURE AND NOT A LIST OF IMPORTS

test_inspector_closure gives the reason and it applies unchanged: the line
is crossed by depth. broker_config imported broker_profiles for one
exception class, so the reader and the renderer were one import apart, and
the ExecStartPre that ran the renderer had the whole workload side in its
closure -- correctly, since it read the TOML, but on a unit whose other
half was the daemon. Only the closure of the program that runs shows what
it could be started without.
"""

import unittest
from pathlib import Path

from tests import REPO_ROOT
from tests.test_inspector_closure import (
    WORKLOAD_SIDE,
    _closure,
    _direct_imports,
    _imports_tomllib,
    _lib_modules,
)

LIB = Path(REPO_ROOT) / "lib"
ENTRYPOINT = Path(REPO_ROOT) / "libexec" / "agent-broker"

# The broker's roots: the reader that turns the flags into the profile
# table, and the server that serves it. The entrypoint itself is walked too
# (see _closure); it is not a lib module.
BROKER_ROOTS = ("broker_profiles", "broker_server")

# The flags the generator hands the entrypoint. The required four are one
# per value the broker must be told and cannot derive; the optional three
# describe a credential and are emitted only when the block states one.
# Set equality on the union, so that a new derivation is a deliberate edit
# here and a value that stopped being handed over (because the broker
# started deriving it for itself) fails too.
REQUIRED_FLAGS = frozenset({
    "--name",        # a label: the log lines
    "--listen",      # what the uid became, and the instance port
    "--caller-uid",  # the one uid this instance serves
    "--host",        # a Host, and the credential id the unit loaded for it
})
PER_CREDENTIAL_FLAGS = frozenset({
    "--placeholder",  # the fiction the guest holds, checked against the key
    "--auth-header",  # the provider's header
    "--auth-format",  # the provider's value shape
})
HANDED_FLAGS = REQUIRED_FLAGS | PER_CREDENTIAL_FLAGS
# NOT --upstream: the upstream is https://<host> on port 443 and the broker
# supplies both, so there is nothing to vary and nothing to hand over. A
# flag reappearing for it is a base path coming back (ADR 007 decision 10).


def _imports_module(path, name):
    """Whether a file imports the stdlib module `name` -- the pwd analogue
    of _imports_tomllib."""
    import ast
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(a.name == name for a in node.names):
                return True
        elif isinstance(node, ast.ImportFrom) and node.module == name:
            return True
    return False


class TestTheScannerSeesTheTree(unittest.TestCase):
    """Guards the guard: every assertion below is about what the walk FOUND."""

    def test_the_roots_and_the_entrypoint_exist(self):
        mods = _lib_modules()
        for root in BROKER_ROOTS:
            self.assertIn(root, mods)
        self.assertTrue(ENTRYPOINT.exists())

    def test_the_closure_is_the_four_broker_modules(self):
        """A reader, a server, a request path and the caller identification,
        and nothing else -- exact, because the broker is small enough that
        its closure IS its manifest, and a fifth module is either a new
        broker module (edit this) or the seam coming back (do not)."""
        closure = _closure(BROKER_ROOTS, _lib_modules(), launcher=ENTRYPOINT)
        self.assertEqual(sorted(closure), ["broker_profiles", "broker_request",
                                           "broker_server", "peer_identity"])


class TestTheBrokerKnowsNothingAboutWorkloads(unittest.TestCase):

    def test_the_closure_contains_no_workload_side_module(self):
        closure = _closure(BROKER_ROOTS, _lib_modules(), launcher=ENTRYPOINT)
        crossed = sorted(closure & WORKLOAD_SIDE)
        self.assertEqual(
            crossed, [],
            "the broker's import closure reaches the workload side; the "
            "value it needs from there belongs in the generator, handed in "
            f"as a flag: {crossed}")

    def test_the_closure_reads_no_toml(self):
        """The rule's plainest reading: nothing the broker imports parses
        TOML. It did -- broker_profiles.load_config read broker.toml -- and
        that reader is the thing this branch deleted."""
        mods = _lib_modules()
        closure = _closure(BROKER_ROOTS, mods, launcher=ENTRYPOINT)
        readers = sorted(m for m in closure if _imports_tomllib(mods[m]))
        self.assertEqual(readers, [], readers)
        self.assertFalse(_imports_tomllib(ENTRYPOINT))

    def test_the_closure_looks_no_user_up(self):
        """The broker's own crossing, which no path derivation test would
        see: peer_identity resolved a caller's uid through passwd to a
        `_wl-<name>` user and matched the name against the document. A pwd
        import anywhere in the closure is that lookup coming back."""
        mods = _lib_modules()
        closure = _closure(BROKER_ROOTS, mods, launcher=ENTRYPOINT)
        lookups = sorted(m for m in closure if _imports_module(mods[m], "pwd"))
        self.assertEqual(lookups, [], lookups)
        self.assertFalse(_imports_module(ENTRYPOINT, "pwd"))
        sources = {m: mods[m].read_text() for m in closure}
        sources["agent-broker"] = ENTRYPOINT.read_text()
        holders = sorted(m for m, text in sources.items() if "_wl-" in text)
        self.assertEqual(holders, [], f"the workload user prefix in {holders}")

    def test_the_broker_derives_no_address_or_name(self):
        """The values the generator hands over, asserted by absence of the
        functions that would derive them -- in the closure and in the
        entrypoint. A closure test would catch the import; this catches a
        copy."""
        mods = _lib_modules()
        closure = _closure(BROKER_ROOTS, mods, launcher=ENTRYPOINT)
        sources = {m: mods[m].read_text() for m in closure}
        sources["agent-broker"] = ENTRYPOINT.read_text()
        for name in ("broker_listen_address", "broker_credential",
                     "workload_name", "getpwuid", "getpwnam",
                     "load_workload_config", "broker_config_path"):
            holders = sorted(m for m, text in sources.items()
                             if f"{name}(" in text)
            self.assertEqual(holders, [], f"{name} called in {holders}")


class TestTheGeneratorIsTheOnlyPlaceTheTwoMeet(unittest.TestCase):
    """The entrypoint imports nothing from the workload side, and the
    generator's ExecStart= names every value it needs."""

    def test_the_entrypoint_imports_nothing_from_the_workload_side(self):
        mods = _lib_modules()
        direct = _direct_imports(ENTRYPOINT, set(mods))
        self.assertEqual(sorted(direct & WORKLOAD_SIDE), [])

    def test_the_generator_hands_every_value_across(self):
        """Each required flag appears on the command, with the value the
        workload side derives for it; each optional one appears exactly
        when the credential block states it; and nothing else does -- a
        flag the entrypoint does not take fails the start, and the start is
        the first brokered request, long after the generator ran."""
        from broker_config import broker_command, broker_credential
        from workload_addr import BROKER_INSTANCE_PORT, broker_listen_address

        from tests.test_broker import flags_of

        class Cred:
            def __init__(self, **kw):
                self.__dict__.update({"auth_header": None, "auth_format": None},
                                     **kw)

        _path, cred_id = broker_credential("web", "tok")
        # A block saying nothing optional: the four required flags only.
        cmd = broker_command("web", 10004, [("api.x.test", "tok")],
                             [Cred(name="tok", placeholder="P")])
        flags = flags_of(cmd)
        self.assertEqual(set(flags), REQUIRED_FLAGS | {"--placeholder"})
        self.assertEqual(flags, {
            "--name": ["web"],
            "--listen": [f"{broker_listen_address(10004)}:{BROKER_INSTANCE_PORT}"],
            "--caller-uid": ["10004"],
            "--host": [f"api.x.test={cred_id}"],
            "--placeholder": [f"{cred_id}=P"],
        })
        # A block saying everything: the union, and nothing outside it.
        cmd = broker_command("web", 10004, [("api.x.test", "tok")],
                             [Cred(name="tok", placeholder="P",
                                   auth_header="Authorization",
                                   auth_format="Bearer {secret}")])
        self.assertEqual(set(flags_of(cmd)), HANDED_FLAGS)

    def test_the_entrypoint_takes_every_handed_flag_and_requires_the_required(self):
        """The other direction: a flag the generator emits that the
        entrypoint does not take is an argparse error at start. Read from
        the source: the parser is built inside a function so the module can
        be loaded without running it -- and the required ones are asserted
        required, because a defaulted --listen is 127.0.0.1 (ADR 007's
        first detail that will bite) and a defaulted --caller-uid serves
        nobody or everybody."""
        text = ENTRYPOINT.read_text()
        for flag in HANDED_FLAGS:
            self.assertIn(f'"{flag}"', text, flag)
        for flag in REQUIRED_FLAGS - {"--host"}:
            self.assertIn(f'"{flag}", required=True', text, flag)
        # --host is required by the reader rather than the parser
        # (`nargs="+"` would allow one empty), asserted in test_broker_config.


if __name__ == "__main__":
    unittest.main()
