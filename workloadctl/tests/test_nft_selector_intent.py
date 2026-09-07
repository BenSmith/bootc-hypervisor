#!/usr/bin/env python3
"""Every rule in workload-filter.nft, pinned to the selector its purpose needs.

WHY THIS EXISTS

The output chain carries TWO different notions of "this workload" and every
rule has to pick the right one:

  meta skuid @wl_filtered                  the guest AND the inspector, which
                                           share a uid
  socket cgroupv2 level 2 @wl_egress_cg    the inspector only

Picking the wrong one is a silent hole or a silent outage, never an error. That
is not hypothetical. The cross-workload live guard was first written
`meta skuid @wl_filtered` where the intent was "exempt the host's own tooling":
@wl_filtered is a strictly narrower set, so every UNFILTERED workload and every
ordinary shell on the box walked through it, reached a filtered workload's
listener, and had its dials written into that workload's egress records. The
repair was `meta skuid != 0`.

Nothing asserted that a rule used the selector its purpose required, so nothing
could have caught it. The rule's own justification lives in sixty lines of
comment above it, which is exactly what an editor changing one token does not
read.

WHAT IT PINS

One entry per rule, in EXPECTED, naming the selector and the reason. Two
directions, and both are needed:

  * a rule whose selector changed no longer matches its entry, so it is
    reported as unaccounted-for;
  * a rule ADDED to the chain has no entry at all, and fails until someone
    states what its selector is for. That is the half that catches the next
    one, rather than the four that prompted the file.

The key is the rule with its SELECTOR REMOVED, so ordinary edits (a counter
added, a comment rewritten, whitespace) do not fail it while a selector swap
lands on the entry that explains what that selector was for. It is the residual
rule rather than a summary of it, because a coarser key lets a newly added rule
collide with an existing entry, find its selector acceptable, and pass.

WHAT IT DOES NOT DO

It does not run nft, so it cannot say the ruleset LOADS or that the rules are
in the right order — tests/test_vm_egress.py holds the ordering properties and
the manual rigs prove the behaviour on a host. This is the intent layer only:
whether each rule selects who it means to.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKELETON = ROOT / "nftables" / "workload-filter.nft"

# --- the selector vocabulary ---
#
# A rule may carry more than one: the internal-destination exceptions are
# cgroup-selected AND uid-keyed, and the two do different jobs (see EXPECTED).
SELECTORS = {
    # `meta skuid 10000-52948` -- the whole allocated uid range, filtered or
    # not, because inbound capture attribution is not a policy question.
    "skuid-range": r"meta skuid \d+-\d+",
    # `meta skuid != 0` -- everyone except the host's own root tooling.
    "skuid-nonroot": r"meta skuid != 0",
    # `meta skuid . <family> daddr [. th dport] @set` -- one element per
    # workload, so the uid inside the key is what scopes it.
    "skuid-tuple": r"meta skuid \. ip6? daddr",
    # `meta skuid @set` -- bare uid membership: guest and inspector alike.
    "skuid-set": r"meta skuid @\w+",
    # `socket cgroupv2 level 2 @wl_egress_cg` -- the inspector's own socket,
    # and the ONLY thing that can tell it from the guest it fronts.
    "cgroup": r"socket cgroupv2 level 2 @\w+",
    # No source selector at all: the input path has no uid to match on.
    "destination-only": None,
}

# residual rule text -> (the selectors it must carry, why those and not
# another)
EXPECTED = {
    "ct mark set meta skuid or 0x40000000": (
        {"skuid-range"},
        "Attribution, not policy: the mark is what gives `pcap -Q in` a "
        "handle on the reply leg, and it must cover every workload rather "
        "than only the filtered ones -- keyed on @wl_filtered it left "
        "`-Q in` silently empty for everything else."),

    "ct direction reply accept": (
        {"skuid-set"},
        "The reply leg of every connection a filtered uid has. Bare uid "
        "membership is right: a reply is a reply whether the guest or the "
        "inspector opened the connection."),

    "meta skuid . ip daddr . th dport @wl_allow4 accept": (
        {"skuid-tuple"},
        "The operator's explicit grants, scoped to one workload by the uid "
        "in the set key."),
    "meta skuid . ip6 daddr . th dport @wl_allow6 accept": (
        {"skuid-tuple"},
        "The v6 twin. `ip daddr` matches v4 only, so the split is forced by "
        "nftables, not by us."),

    "meta skuid . ip daddr . th dport @wl_inspect_dst accept": (
        {"skuid-tuple"},
        "Redirected connections, admitted by their TRANSLATED tuple. Scoped "
        "per workload so one workload's redirect is not another's."),
    "meta skuid . ip6 daddr . th dport @wl_inspect_dst6 accept": (
        {"skuid-tuple"},
        "The v6 twin."),

    "meta skuid . ip daddr @wl_inspect_self ct direction original drop": (
        {"skuid-tuple"},
        "The self-dial guard, and the per-workload counter is the whole "
        "point: `diagnose` must be able to say THIS guest dialled its own "
        "listener on a port nothing serves, which a shared counter cannot."),
    "meta skuid . ip6 daddr @wl_inspect_self6 ct direction original drop": (
        {"skuid-tuple"},
        "The v6 twin."),

    "ct direction original ip daddr @wl_inspect_live drop": (
        {"skuid-nonroot"},
        "THE RULE THE HOLE WAS IN. The exemption is for the HOST'S OWN "
        "TOOLING, and @wl_filtered expressed it as 'workloads already under "
        "policy' -- a strictly narrower set that let every unfiltered "
        "workload and every ordinary shell reach a filtered workload's "
        "listener. `diagnose` and `doctor` both require_root(), so root is "
        "the whole of the legitimate probing population."),
    "ct direction original ip6 daddr @wl_inspect_live6 drop": (
        {"skuid-nonroot"},
        "The v6 twin. A v4-only guard leaves the hole open on the plane "
        "clients try first."),

    "th dport 53 accept": (
        {"cgroup"},
        "Host-side name resolution is the INSPECTOR's, not guest-chosen "
        "egress. On the uid this would be an all-ports-to-anywhere DNS grant "
        "for the guest too."),

    "meta skuid . ip daddr @wl_internal_ok4 ct direction original accept": (
        {"cgroup", "skuid-tuple"},
        "Both, doing different jobs: cgroup for WHO OPENED IT, uid for WHOSE "
        "ELEMENT IT IS. The set key holds no port -- the exemption is about "
        "where a name resolves to -- so without the cgroup match the very "
        "same element becomes an all-ports grant from the GUEST to a LAN "
        "address."),
    "meta skuid . ip6 daddr @wl_internal_ok6 ct direction original accept": (
        {"cgroup", "skuid-tuple"},
        "The v6 twin."),

    "ct direction original ip daddr @wl_internal4 drop": (
        {"cgroup"},
        "The inspector must not reach the LAN on the guest's behalf. Keyed "
        "on the cgroup because the uid is shared with the guest, whose own "
        "path to an internal address is the operator's `allow` to grant."),
    "ct direction original ip6 daddr @wl_internal6 drop": (
        {"cgroup"},
        "The v6 twin."),

    "oif lo accept": (
        {"skuid-set"},
        "Loopback is the workload's own control plane, not egress -- passt's "
        "replies on the management socket and the DNS forward are both "
        "output traffic owned by the workload uid. Bare membership, because "
        "it is true of the guest and the inspector alike."),

    "accept": (
        {"cgroup"},
        "The re-originator's own egress. On the uid this would accept "
        "everything the GUEST sends and the chain would enforce nothing."),

    "udp dport 443 drop": (
        {"skuid-set"},
        "HTTP/3, dropped and counted rather than dropped silently. A pure "
        "attribution split immediately ahead of the default deny, so it "
        "covers exactly what that rule already covered: the whole uid."),

    "drop": (
        {"skuid-set"},
        "The default deny. Set-guarded, so a workload not in @wl_filtered "
        "never reaches it and an unarmed host has an inert table."),
}

def _rules(chain):
    """The `add rule` lines of one chain, comments and whitespace normalised."""
    prefix = f"add rule inet workload_filter {chain} "
    out = []
    for line in SKELETON.read_text().splitlines():
        line = line.strip()
        if not line.startswith(prefix):
            continue
        out.append(re.sub(r"\s+", " ", line[len(prefix):]).strip())
    return out


# The source selector is REMOVED before the key is computed, and that is the
# point: swapping `meta skuid != 0` for `meta skuid @wl_filtered` -- the exact
# historical defect -- leaves the key intact, so the rule still finds its entry
# and fails with the reason attached rather than as an anonymous new rule.
#
# The tuple form (`meta skuid . ip daddr @set`) is not stripped, because there
# the selector and the match are one expression and cannot be told apart.
_SELECTOR_PREFIXES = (
    r"meta skuid != 0",
    r"meta skuid \d+-\d+",
    r"meta skuid @\w+",              # bare membership, NOT the `. ip daddr` tuple
    r"socket cgroupv2 level \d+ @\w+",
)


def _key(expr):
    """What is left of a rule once its source selector is removed.

    The residual, not a summary of it: a coarser key lets a NEWLY ADDED rule
    collide with an existing entry, find its selector acceptable, and pass --
    which is the one failure this file exists to prevent. `counter` is dropped
    because adding one is not a change of intent.
    """
    for pattern in _SELECTOR_PREFIXES:
        expr = re.sub(pattern, "", expr)
    expr = re.sub(r"\bcounter\b", "", expr)
    return re.sub(r"\s+", " ", expr).strip()


def _selectors(expr):
    found = {name for name, pattern in SELECTORS.items()
             if pattern and re.search(pattern, expr)}
    # A tuple match is also a bare `meta skuid @set` textually; the tuple form
    # is the specific one and the two are different intents.
    if "skuid-tuple" in found:
        found.discard("skuid-set")
    return found or {"destination-only"}


class TestOutputChainSelectors(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rules = _rules("output")

    def test_the_chain_was_actually_parsed(self):
        """Guards the guard: a prefix that stopped matching would make every
        assertion below vacuously true."""
        self.assertGreater(len(self.rules), 15, self.rules)

    def test_every_rule_has_a_stated_intent(self):
        """A rule added to the chain fails here until someone says what its
        selector is for. This is the half that catches the NEXT one."""
        unaccounted = [expr for expr in self.rules if _key(expr) not in EXPECTED]
        self.assertEqual(
            unaccounted, [],
            "output-chain rules with no entry in EXPECTED. A new rule needs "
            "one; an existing rule reaching here means its selector, sets or "
            "verdict changed and the reason on record no longer describes "
            "it:\n  " + "\n  ".join(unaccounted))

    def test_no_stated_intent_describes_a_rule_that_is_gone(self):
        """The other direction: an entry nothing matches is a reason kept for
        a rule that no longer exists, and it reads as coverage."""
        keys = {_key(expr) for expr in self.rules}
        orphans = sorted(k for k in EXPECTED if k not in keys)
        self.assertEqual(orphans, [], "\n  ".join(orphans))

    def test_each_rule_carries_the_selector_its_purpose_requires(self):
        wrong = []
        for expr in self.rules:
            key = _key(expr)
            if key not in EXPECTED:
                continue
            expected, why = EXPECTED[key]
            actual = _selectors(expr)
            if actual != expected:
                wrong.append(f"{expr}\n    selects: {sorted(actual)}\n"
                             f"    must be: {sorted(expected)}\n    why: {why}")
        self.assertEqual(wrong, [], "\n  ".join(wrong))

    def test_the_two_notions_of_this_workload_are_both_in_use(self):
        """If one disappeared the table would still pass, and the distinction
        this whole file exists to hold would be gone."""
        kinds = set().union(*(_selectors(e) for e in self.rules))
        self.assertIn("skuid-set", kinds)
        self.assertIn("cgroup", kinds)
        self.assertIn("skuid-nonroot", kinds)

    def test_no_rule_selecting_the_inspector_falls_back_to_the_bare_uid(self):
        """The cgroup rules are the ones where the uid is NOT a substitute:
        the inspector runs as the workload's own user, so `meta skuid` cannot
        tell its traffic from the guest's."""
        for expr in self.rules:
            if "wl_egress_cg" not in expr:
                continue
            self.assertRegex(
                expr, r"socket cgroupv2 level 2 @wl_egress_cg",
                f"a rule naming wl_egress_cg without the cgroup match means "
                f"something else entirely: {expr}")

    def test_the_classifier_can_tell_the_selectors_apart(self):
        """Guards the guard again: a classifier that returned the same answer
        for everything would pass every row above."""
        self.assertEqual(_selectors("meta skuid != 0 ip daddr @s drop"),
                         {"skuid-nonroot"})
        self.assertEqual(_selectors("meta skuid @wl_filtered oif lo accept"),
                         {"skuid-set"})
        self.assertEqual(_selectors("meta skuid . ip daddr @s drop"),
                         {"skuid-tuple"})
        self.assertEqual(
            _selectors("socket cgroupv2 level 2 @wl_egress_cg meta skuid . "
                       "ip daddr @wl_internal_ok4 accept"),
            {"cgroup", "skuid-tuple"})


class TestInputChainSelectors(unittest.TestCase):
    """The input half, where the absence of a uid is the fact worth pinning."""

    @classmethod
    def setUpClass(cls):
        cls.rules = _rules("input")

    def test_the_chain_was_actually_parsed(self):
        self.assertGreater(len(self.rules), 1, self.rules)

    def test_every_rule_is_destination_keyed_and_exempts_loopback(self):
        for expr in self.rules:
            self.assertEqual(_selectors(expr), {"destination-only"},
                             f"the input path has no uid to match on: {expr}")
            self.assertIn("iif != lo", expr,
                          f"without the exemption every inspected connection "
                          f"dies, and it presents as the design being "
                          f"inert: {expr}")

    def test_both_families_are_guarded(self):
        """A v4-only input chain leaves the plane clients reach first wide
        open, and nothing about the v4 half's behaviour would say so."""
        self.assertTrue(any("ip daddr" in e and "ip6" not in e
                            for e in self.rules))
        self.assertTrue(any("ip6 daddr" in e for e in self.rules))


if __name__ == "__main__":
    unittest.main()
