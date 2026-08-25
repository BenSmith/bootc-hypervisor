#!/usr/bin/env python3
"""The uid-keyed egress layer: skeleton, element model, and unit wiring.

Named test_vm_egress rather than test_..._workload_filter to stay clear of
tests/test_generator_workload_filter.py, which is about the generator's
`--workload` narrowing flag and has nothing to do with nftables.
"""

import os
import shutil
import tempfile
import ipaddress
import json
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from vm import (
    NFT_MAP_INSPECT4, NFT_MAP_INSPECT6, NFT_SET_ALLOW4, NFT_SET_ALLOW6,
    NFT_SET_FILTERED, NFT_SET_INSPECT_CG, NFT_SET_INSPECT_DST,
    NFT_SET_INSPECT_DST6, NFT_SET_INSPECT_SELF, NFT_SET_INSPECT_SELF6,
    NFT_SET_INTERNAL4, NFT_SET_INTERNAL6, NFT_SET_EGRESS_CG, NFT_SKELETON,
    VM_INSPECT_ADDR6_PREFIX, VM_INSPECT_NETWORK,
    VM_INSPECT_PORT_CLEARTEXT, VM_INSPECT_PORT_TLS,
    CONNTRACK_PRESSURE, conntrack_occupancy,
    nft_drop_counter, nft_element_counter, nft_set_elements,
    parse_vm_allow, vm_allow_reserved_reason, vm_filter_commands,
    vm_filter_delete_command, vm_inspect_address, vm_owned_elements,
)
from workload_lib import UID_MAX, UID_MIN


def allow_entry(address, reason="a test bypass, written down"):
    """One [[vm.network.allow]] table.

    A helper rather than a literal at each site because `reason` is required
    and carries no meaning in these tests -- what they are about is the
    address. The tests that ARE about the reason build the dict themselves.
    """
    return {"address": address, "reason": reason}


def only(case, matches, what):
    """The single line matching a filter, asserting that there is exactly one.

    Taking `[0]` off a filtered list is total coverage only while the thing
    filtered for is unique. When a second one arrives the test keeps checking
    the first and nothing reports it. The skeleton holds exactly the kind of
    collection that happens to: one `add element` line per set today, freely
    splittable across two tomorrow because nft accepts both spellings.

    The direction it fails in is what makes it worth a helper rather than a
    convention. An `assertIn` narrowed this way weakens; an `assertNotIn`
    starts passing while the thing it forbids is present on the line it no
    longer reads.
    """
    case.assertEqual(len(matches), 1,
                     f"expected exactly one {what}, got {len(matches)}: {matches}")
    return matches[0]


SKELETON = Path(__file__).resolve().parent.parent / "nftables" / "workload-filter.nft"
PROXY_SKELETON = Path(__file__).resolve().parent.parent / "nftables" / "workload-proxy.nft"


class TestSkeleton(unittest.TestCase):
    """Properties of the .nft file itself, checkable without nft installed."""

    @classmethod
    def setUpClass(cls):
        cls.text = SKELETON.read_text()
        cls.directives = [ln.strip() for ln in cls.text.splitlines()
                          if ln.strip() and not ln.strip().startswith("#")]

    def test_the_chain_is_flushed_before_rules_are_added(self):
        """The one property that makes re-application safe.

        `add rule` appends, so a file applied at every VM start would grow the
        chain without the flush. `flush chain` empties only the chain -- set
        elements live on the table, which is what stops a second VM's start
        from disarming the first.
        """
        order = [i for i, d in enumerate(self.directives)
                 if d.startswith(("flush chain", "add rule"))]
        kinds = [self.directives[i].split()[0] for i in order]
        self.assertIn("flush", kinds, "skeleton never flushes the chain")
        self.assertLess(
            kinds.index("flush"), kinds.index("add"),
            "the flush must precede every add rule, or re-applying the file "
            "duplicates the ruleset")

    def test_sets_are_created_before_the_rules_that_reference_them(self):
        add_sets = max(i for i, d in enumerate(self.directives)
                       if d.startswith("add set"))
        first_rule = min(i for i, d in enumerate(self.directives)
                         if d.startswith("add rule"))
        self.assertLess(add_sets, first_rule)

    def test_the_drop_is_guarded_by_set_membership(self):
        """An unguarded drop would take the whole host off the network.

        The qualifying sets hold only per-workload state. `wl_filtered` holds
        workload uids; `wl_egress_cg` holds the cgroup paths of hostname-proxy
        units, which only exist for filtered VMs; `wl_inspect_self`/`self6`
        hold one element per armed workload. All are empty on a host running
        no filtered workload, which is what makes an abandoned table inert.
        """
        guards = (f"@{NFT_SET_FILTERED}", f"@{NFT_SET_EGRESS_CG}",
                  f"@{NFT_SET_INSPECT_SELF}", f"@{NFT_SET_INSPECT_SELF6}")
        # The output chain only. The input chain's drops are deliberately
        # unguarded on any set — there is no uid on the input path — and are
        # bounded by destination plus `iif != lo` instead (§7.2.6).
        drops = [d for d in self.directives
                 if d.endswith("drop")
                 and d.startswith("add rule inet workload_filter output")]
        self.assertTrue(drops, "no drop rule in the skeleton")
        for rule in drops:
            self.assertTrue(any(g in rule for g in guards),
                            f"unguarded drop rule: {rule}")

    def test_chain_policy_is_accept(self):
        """So an abandoned table is inert rather than a host-wide outage.

        The asymmetry is the point, and it is why this is EVERY chain in the
        skeleton rather than the first: an abandoned OUTPUT chain is inert —
        accept policy, a set-guarded drop, and an empty wl_filtered match
        nothing. A default-deny INPUT chain is a host-wide outage: the input
        chain runs at priority 0, ahead of firewalld's filter_INPUT at
        filter+10, so it would silently take over input policy for every
        service on the machine, and nothing would be reported — just every
        service unreachable. §7.2.6 records it as the one direction where
        getting it wrong is unrecoverable.
        """
        chains = [d for d in self.directives if d.startswith("add chain")]
        self.assertTrue(chains, "no chain declared in the skeleton")
        for chain in chains:
            self.assertIn("policy accept", chain)

    def test_ct_mark_rule_is_present_and_non_terminating(self):
        """Design 13 step 2 calls this out: nothing reads the mark until step
        5, so it is written-but-unexercised and has to be covered here.

        It must (a) exist in the always-on skeleton -- a rule added when a
        capture starts could only mark connections opened later, and the
        connection an operator is chasing is already established -- and (b)
        carry no verdict, or it would terminate evaluation and the allow/drop
        rules below would never run.
        """
        marks = [d for d in self.directives if "ct mark set" in d]
        self.assertEqual(len(marks), 1, f"expected exactly one mark rule: {marks}")
        rule = marks[0]
        for verdict in ("accept", "drop", "reject", "return", "goto", "jump"):
            self.assertNotIn(
                f" {verdict}", rule,
                f"the mark rule carries a {verdict} verdict, which would stop "
                f"evaluation before the allow and drop rules")

    def test_the_mark_covers_every_workload_not_only_filtered_ones(self):
        """The mark is ATTRIBUTION, not policy.

        Guarding it on @wl_filtered like the drop is the obvious-looking thing
        and it is wrong: `pcap -Q in` selects packets by this mark, so a mark
        that only fires for filtered workloads makes inbound capture silently
        empty for every container and every `egress = "open"` VM -- while
        `-Q out` kept working, so each workload class had exactly one working
        direction and neither reported an error.

        The range must be the whole of what lib/workload_lib.py allocates, or
        workloads at one end of it are unattributable.
        """
        rule = only(self, [d for d in self.directives if "ct mark set" in d],
                    "ct mark set rule")
        self.assertNotIn(
            f"@{NFT_SET_FILTERED}", rule,
            "the mark is guarded on set membership, so unfiltered workloads "
            "carry no mark and inbound capture cannot attribute them")
        self.assertIn(f"meta skuid {UID_MIN}-{UID_MAX}", rule,
                      f"the skeleton's uid range must match "
                      f"UID_MIN..UID_MAX ({UID_MIN}-{UID_MAX})")

    def test_mark_precedes_the_terminating_rules(self):
        idx = [i for i, d in enumerate(self.directives) if d.startswith("add rule")]
        rules = [self.directives[i] for i in idx]
        self.assertIn("ct mark set", rules[0],
                      "the mark must run before anything that can accept or "
                      "drop the packet")

    def test_loopback_is_accepted_before_the_drop(self):
        """Without this a filtered VM is cut off from its own control plane.

        Found on a live VM, not in review: passt binds the management address
        as the workload user, so `workloadctl exec`'s replies are output
        traffic owned by that uid and hit this chain — the TCP connection is
        accepted and then dies. The same rule covers DNS, which passt forwards
        to `dns-host` (127.0.0.53 under systemd-resolved) as the same uid.
        """
        loopback = [d for d in self.directives
                    if "oif lo" in d and d.startswith("add rule")]
        self.assertEqual(len(loopback), 1,
                         f"expected one loopback accept rule: {loopback}")
        self.assertIn(f"@{NFT_SET_FILTERED}", loopback[0],
                      "the loopback accept must be guarded on membership")
        self.assertIn("accept", loopback[0])

        rules = [d for d in self.directives if d.startswith("add rule")]
        self.assertLess(
            rules.index(loopback[0]),
            max(i for i, r in enumerate(rules) if r.endswith("drop")),
            "the loopback accept must precede the drop")

    def test_each_family_has_its_own_allow_set(self):
        """`ip daddr` matches v4 only and `ip6 daddr` v6 only, so one set
        cannot serve both -- and an entry in the wrong set never matches,
        which fails silently."""
        for set_name, keyword in ((NFT_SET_ALLOW4, "ip daddr"),
                                  (NFT_SET_ALLOW6, "ip6 daddr")):
            decl = [d for d in self.directives
                    if d.startswith("add set") and set_name in d]
            self.assertEqual(len(decl), 1, set_name)
            self.assertIn(keyword, decl[0])

    def test_membership_set_is_family_agnostic(self):
        decl = only(self, [d for d in self.directives
                           if d.startswith("add set") and NFT_SET_FILTERED in d],
                    f"declaration of {NFT_SET_FILTERED}")
        self.assertNotIn("ip daddr", decl)
        self.assertNotIn("ip6 daddr", decl)

    def test_the_inspect_sets_are_declared_with_their_constant_names(self):
        """The skeleton spells these names literally so it stays applicable
        with a bare `nft -f`; a rename on either side is a set no rule ever
        reads, which looks like the guard being off rather than a bug. Both
        families or neither, for the same reason the allow sets split.

        The shapes are checked by their own tokens because they differ in the
        one way that matters: the self sets carry the per-element `counter`
        (diagnose attributes a wrong-port self-dial to its workload off it,
        which the range guard's shared number cannot), and the dst sets do not
        — a counter on the dst sets would count connections, not self-dials,
        and a counterless self set would render back as the wrong shape.
        """
        for name in (NFT_SET_INSPECT_DST, NFT_SET_INSPECT_DST6,
                     NFT_SET_INSPECT_SELF, NFT_SET_INSPECT_SELF6):
            decls = [d for d in self.directives
                     if d.startswith("add set") and d.split()[4] == name]
            self.assertEqual(len(decls), 1, name)
            self.assertIn("typeof meta skuid", decls[0], name)
        for name in (NFT_SET_INSPECT_DST, NFT_SET_INSPECT_DST6):
            decl = only(self, [d for d in self.directives
                               if d.startswith("add set")
                               and d.split()[4] == name],
                        f"declaration of {name}")
            self.assertIn("th dport", decl)
            self.assertNotIn("counter", decl)
        for name in (NFT_SET_INSPECT_SELF, NFT_SET_INSPECT_SELF6):
            decl = only(self, [d for d in self.directives
                               if d.startswith("add set")
                               and d.split()[4] == name],
                        f"declaration of {name}")
            self.assertIn("counter", decl)
            self.assertNotIn("th dport", decl)

    def test_the_inspect_rules_reference_the_sets_by_their_constants(self):
        """A declaration a rule never reads is a guard that is off while the
        ruleset reads correctly."""
        for name in (NFT_SET_INSPECT_DST, NFT_SET_INSPECT_DST6,
                     NFT_SET_INSPECT_SELF, NFT_SET_INSPECT_SELF6):
            self.assertIn(f"@{name}", self.text)


class TestInternalDestinationGuard(unittest.TestCase):
    """The re-originators' cgroup exemption is not destination-blind.

    The inspector matches the name it read out of a Host header or an SNI,
    resolves it with the host resolver, and connects to whatever comes back.
    Without these rules an allowlisted name resolving into RFC 1918, loopback
    or link-local space is reachable from a VM that reports itself confined --
    and the guest never controls the resolution, so nothing about it looks like
    an attack in a log.
    """

    @classmethod
    def setUpClass(cls):
        cls.rules = [ln.strip() for ln in SKELETON.read_text().splitlines()
                     if ln.strip().startswith("add rule")]
        cls.text = SKELETON.read_text()

    def _drops(self):
        return [r for r in self.rules
                if r.endswith("drop") and NFT_SET_EGRESS_CG in r]

    def test_one_drop_per_address_family(self):
        """`ip daddr` matches v4 only and `ip6 daddr` v6 only, so a single
        rule cannot cover both -- and the missing family fails open."""
        drops = self._drops()
        self.assertEqual(len(drops), 2, drops)
        self.assertTrue(any(f"ip daddr @{NFT_SET_INTERNAL4}" in r for r in drops))
        self.assertTrue(any(f"ip6 daddr @{NFT_SET_INTERNAL6}" in r for r in drops))

    def test_both_sets_are_interval_sets_with_elements(self):
        """Declared without `flags interval` a prefix is a parse error, so
        this would fail loudly -- but only on a host, at the first VM start."""
        for name in (NFT_SET_INTERNAL4, NFT_SET_INTERNAL6):
            decl = [ln for ln in self.text.splitlines()
                    if ln.startswith("add set") and name in ln]
            self.assertEqual(len(decl), 1, name)
            self.assertIn("flags interval", decl[0])
            self.assertTrue(
                any(ln.startswith("add element") and name in ln
                    for ln in self.text.splitlines()),
                f"{name} is declared but never populated")

    def test_the_ranges_that_matter_are_covered(self):
        """169.254.0.0/16 carries the cloud metadata endpoint; the RFC 1918
        blocks are the LAN the host sits on; 127/8 is every service the host
        runs for itself."""
        elems = only(self, [ln for ln in self.text.splitlines()
                            if ln.startswith("add element")
                            and NFT_SET_INTERNAL4 in ln],
                     f"element line for {NFT_SET_INTERNAL4}")
        for prefix in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                       "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10"):
            self.assertIn(prefix, elems)
        v6 = only(self, [ln for ln in self.text.splitlines()
                         if ln.startswith("add element")
                         and NFT_SET_INTERNAL6 in ln],
                  f"element line for {NFT_SET_INTERNAL6}")
        for prefix in ("::1/128", "fc00::/7", "fe80::/10"):
            self.assertIn(prefix, v6)

    def test_v6_covers_the_prefixes_that_encode_a_v4_destination(self):
        """A v6 destination can name a v4 one. With NAT64 or 6to4 in the path,
        64:ff9b::a00:5 reaches 10.0.0.5 without any element of the v4 set being
        consulted, so listing only the direct v6 forms leaves the guard
        family-blind in exactly the way it exists to prevent."""
        v6 = only(self, [ln for ln in self.text.splitlines()
                         if ln.startswith("add element")
                         and NFT_SET_INTERNAL6 in ln],
                  f"element line for {NFT_SET_INTERNAL6}")
        for prefix in ("::ffff:0.0.0.0/96",   # v4-mapped
                       "64:ff9b::/96",        # NAT64, well-known (RFC 6052)
                       "64:ff9b:1::/48",      # NAT64, local-use (RFC 8215)
                       "2002::/16"):          # 6to4 (RFC 3056)
            self.assertIn(prefix, v6)

    def test_teredo_is_not_blocked(self):
        """2001::/32 encodes the client's own public address, not a destination
        inside the host's network, so blocking it would deny traffic the guard
        has no claim on."""
        v6 = only(self, [ln for ln in self.text.splitlines()
                         if ln.startswith("add element")
                         and NFT_SET_INTERNAL6 in ln],
                  f"element line for {NFT_SET_INTERNAL6}")
        self.assertNotIn("2001::/32", v6)

    def test_the_advertised_address_is_not_blocked(self):
        """The guest's flow reaches the credential broker FROM 192.0.2.1, so
        the broker's replies are addressed to it. Listing that prefix takes the
        broker down completely -- every request hangs and nothing logs. It did
        the same to the retired proxy, which shared the address."""
        elems = " ".join(ln for ln in self.text.splitlines()
                         if ln.startswith("add element"))
        self.assertNotIn("192.0.2.", elems)

    def test_the_drop_only_covers_connections_the_exempt_processes_open(self):
        """Without `ct direction original` this drops the reply direction of
        connections made TO an exempt process whenever the client's source
        address falls in one of these ranges -- 127.0.0.1 being the obvious
        one."""
        for rule in self._drops():
            self.assertIn("ct direction original", rule, rule)

    def test_name_resolution_is_exempted_before_the_drop(self):
        """The inspector resolves through the host's configured resolver, which
        may be a stub on 127.0.0.53 or a box on the LAN -- both inside these
        ranges. Without the carve-out every lookup fails and the listener
        returns 502 while looking healthy.

        This carve-out was written for tinyproxy and OUTLIVED it deliberately:
        the inspector resolves host-side on every connection it authorises,
        permanently, so deleting it with the service it was named for would
        have taken hostname policy down on the rung that replaced it."""
        dns = [i for i, r in enumerate(self.rules)
               if NFT_SET_EGRESS_CG in r and "th dport 53" in r
               and r.endswith("accept")]
        self.assertEqual(len(dns), 1, "expected one DNS carve-out rule")
        first_drop = min(i for i, r in enumerate(self.rules)
                         if r.endswith("drop") and NFT_SET_EGRESS_CG in r)
        self.assertLess(dns[0], first_drop,
                        "the DNS carve-out must precede the drop")

    def test_the_operator_escape_hatch_is_evaluated_first(self):
        """`allow` is the documented way to grant an internal destination, so
        the allow rules must sit ahead of the drops. They used to sit behind
        the proxy's blanket accept, where moving them changes nothing: every
        rule they passed on the way up is also an accept."""
        first_drop = min(i for i, r in enumerate(self.rules)
                         if r.endswith("drop") and NFT_SET_EGRESS_CG in r)
        for name in (NFT_SET_ALLOW4, NFT_SET_ALLOW6):
            idx = next(i for i, r in enumerate(self.rules) if f"@{name}" in r)
            self.assertLess(idx, first_drop,
                            f"@{name} is evaluated after the internal drop, "
                            f"so `allow` cannot override it")

    def test_the_blanket_proxy_accept_still_comes_last(self):
        """The exemption that makes hostname policy work at all is unchanged;
        these rules only carve destinations out of it, so they must precede
        it or they never run."""
        # By shape, and the shape is "cgroup and nothing else": the chain now
        # also carries two internal EXEMPTIONS that are cgroup accepts with a
        # set key, and matching one of those would test the wrong rule.
        blanket = next(i for i, r in enumerate(self.rules)
                       if NFT_SET_EGRESS_CG in r and r.endswith("accept")
                       and "dport" not in r and "daddr" not in r)
        for i, r in enumerate(self.rules):
            if r.endswith("drop") and NFT_SET_EGRESS_CG in r:
                self.assertLess(i, blanket)



class TestRuleOrderIsPinned(unittest.TestCase):
    """The output chain's rule ORDER is the enforcement, so it is pinned as a
    sequence rather than probed rule by rule.

    Every other test here asserts that some rule exists and precedes some other
    rule. That catches a deletion and misses an insertion: a new rule dropped
    into the wrong position satisfies every pairwise check while changing what
    the chain does. This test fails on any change to the sequence, so extending
    the chain means updating EXPECTED deliberately and saying why in the commit.

    It exists because of two findings measured on a live host that no functional
    test can see. Both are recorded in
    docs/adr/008-transparent-egress-inspection.md:

      - the guard for the inspector's listener range must sit between the
        per-workload accept and the loopback accept, or one workload reaches
        another's inspector -- admitted by the loopback accept, which is safe
        only while every host-local address a filtered uid can reach is in
        127/8;
      - the drops around it must carry `ct direction original`, or they also
        drop the inspector's own REPLY traffic, which takes every inspected
        connection down while the ruleset still reads correctly.

    Neither is visible in a packet trace of a passing test, and the second was
    credited to the wrong qualifier for three days because the rig that measured
    it ran its listener as root rather than as the workload uid.
    """

    # (label, required substrings) in the order they must appear — the
    # output chain of §7.2.5 with rules 12 and 13 not yet shipped. Rule 18, the
    # counted HTTP/3 drop, IS shipped: it is attribution only — it counts
    # packets the default deny below it would have dropped anyway — and its
    # position in the pin is the point: in place between the proxy egress
    # accept and the default drop, it reads as attribution; anywhere else it
    # reads as policy, and this test is what keeps it there.
    EXPECTED = [
        ("ct mark attribution",     ("ct mark set", "meta skuid 10000-52948")),
        ("inspector reply accept",  ("@wl_filtered", "ct direction reply", "accept")),
        ("operator allow v4",       ("@wl_allow4", "accept")),
        ("operator allow v6",       ("@wl_allow6", "accept")),
        ("inspector redirect accept v4", ("@wl_inspect_dst", "accept")),
        ("inspector redirect accept v6", ("@wl_inspect_dst6", "accept")),
        ("inspector self drop v4",  ("@wl_inspect_self", "ct direction original", "drop")),
        ("inspector self drop v6",  ("@wl_inspect_self6", "ct direction original", "drop")),
        ("inspector range guard v4", ("@wl_filtered", "ct direction original", "198.18.0.0/16", "drop")),
        ("inspector range guard v6", ("@wl_filtered", "ct direction original", "2001:2::/48", "drop")),
        ("host-side name resolution", ("@wl_egress_cg", "th dport 53", "accept")),
        ("internal exemption v4",   ("@wl_egress_cg", "@wl_internal_ok4",
                                    "ct direction original", "accept")),
        ("internal exemption v6",   ("@wl_egress_cg", "@wl_internal_ok6",
                                    "ct direction original", "accept")),
        ("re-originator internal drop v4", ("@wl_egress_cg", "ct direction original",
                                    "@wl_internal4", "drop")),
        ("re-originator internal drop v6", ("@wl_egress_cg", "ct direction original",
                                    "@wl_internal6", "drop")),
        ("loopback accept",         ("@wl_filtered", "oif lo", "accept")),
        ("re-originator egress",    ("@wl_egress_cg", "accept")),
        ("HTTP/3 counted drop",     ("@wl_filtered", "udp dport 443", "counter drop")),
        ("default drop",            ("@wl_filtered", "counter drop")),
    ]

    @classmethod
    def setUpClass(cls):
        cls.rules = [ln.strip() for ln in SKELETON.read_text().splitlines()
                     if ln.strip().startswith("add rule inet workload_filter output")]

    def test_the_chain_matches_the_pinned_sequence(self):
        self.assertEqual(
            len(self.rules), len(self.EXPECTED),
            "the output chain gained or lost a rule. Rule order is the "
            "enforcement here, so update EXPECTED with the new rule in its "
            "intended position rather than appending it:\n  "
            + "\n  ".join(self.rules))
        for rule, (label, required) in zip(self.rules, self.EXPECTED):
            for token in required:
                self.assertIn(token, rule, f"rule {label!r} lost {token!r}: {rule}")

    def test_every_destination_drop_is_qualified_to_the_original_direction(self):
        """A drop that does not say `ct direction original` also drops replies.

        The internal-destination drops carry it today for the reason the file
        states -- the reply direction of a connection made TO the proxy must
        never be dropped. The same applies to every future drop keyed on a
        DESTINATION, and it is the property whose absence takes the whole
        workload down rather than opening a hole. Drops keyed on membership
        alone (the default drop) are exempt: they are the fallthrough, and a
        reply that reaches them was already refused by everything above.
        """
        for rule in self.rules:
            if not rule.endswith("drop"):
                continue
            if "daddr" not in rule:
                continue          # membership-only fallthrough
            self.assertIn(
                "ct direction original", rule,
                "a destination-keyed drop without `ct direction original` "
                f"also drops the reply leg of established connections: {rule}")


class TestInputChain(unittest.TestCase):
    """The input chain of §7.2.6, asserted by PROPERTIES rather than pinned as
    a sequence, and that distinction is the point.

    The output chain is pinned as an ordered sequence because order IS the
    enforcement there: an inserted rule satisfies every pairwise check while
    changing what the chain does. This chain has two rules and no ordering to
    get wrong — neither rule's meaning depends on the other, and there is no
    accept below a drop that an insert could slip in front of. What it can
    get wrong is its SHAPE, and §7.2.6 names four independent ways a
    plausible-looking version of it is wrong. Each of the four is a test here,
    plus one negative test for the absence of a qualifier no plausible-looking
    version should carry, and one for the `counter` §11 reads the off-box
    arrivals figure off.
    """

    @classmethod
    def setUpClass(cls):
        cls.directives = [ln.strip() for ln in SKELETON.read_text().splitlines()
                          if ln.strip() and not ln.strip().startswith("#")]
        cls.input_rules = [d for d in cls.directives
                           if d.startswith("add rule inet workload_filter input")]

    def test_the_chain_exists_and_is_hooked_at_input_priority_0(self):
        """Presence. §7.2.6's first named failure is a version of this design
        with no input chain at all: the output rules above assume it, and its
        absence fails open on both planes."""
        decls = [d for d in self.directives
                 if d.startswith("add chain")
                 and " inet workload_filter input " in d]
        self.assertEqual(len(decls), 1, f"expected exactly one input chain: {decls}")
        decl = decls[0]
        self.assertIn("hook input", decl)
        self.assertIn("priority 0", decl)

    def test_both_families_are_dropped(self):
        """Both families, or neither.

        A v4-only input chain leaves the plane clients try FIRST wide open —
        happy-eyeballs dials the v6 address before the v4 one — and nothing
        about the v4 half's behaviour would say so. The failure is silent in
        the direction that matters, which is why the split is asserted rather
        than inferred from the v4 rule's existence.
        """
        self.assertEqual(len(self.input_rules), 2, self.input_rules)
        self.assertTrue(
            any("ip  daddr 198.18.0.0/16" in r and r.endswith("drop")
                for r in self.input_rules),
            "no v4 drop covering 198.18.0.0/16")
        self.assertTrue(
            any("ip6 daddr 2001:2::/48" in r and r.endswith("drop")
                for r in self.input_rules),
            "no v6 drop covering 2001:2::/48")

    def test_the_policy_is_accept_and_the_chain_holds_only_drops(self):
        """The one direction where getting it wrong is unrecoverable.

        This is not a host firewall and must never grow into one. firewalld
        runs filter_INPUT at filter+10 and this chain at priority 0 runs
        AHEAD of it, so a default-deny input chain of ours silently takes
        over policy for every service on the machine — a far larger blast
        radius than the thing being fixed, with nothing reported, just every
        service unreachable. The chain removes one class of destination and
        does nothing else; it holds only drops, and none of them accepts.
        """
        decl = only(self, [d for d in self.directives
                           if d.startswith("add chain")
                           and " inet workload_filter input " in d],
                    "input chain declaration")
        self.assertIn("policy accept", decl)
        self.assertTrue(self.input_rules, "the input chain is empty")
        for rule in self.input_rules:
            self.assertIn("drop", rule)
            for verdict in ("accept", "reject", "return", "goto", "jump"):
                self.assertNotIn(f" {verdict}", rule,
                                 f"the input chain holds only drops: {rule}")

    def test_the_loopback_exemption_is_on_both_drops(self):
        """`iif != lo` is the entire exemption, and it is the load-bearing
        detail.

        Everything legitimate on these planes is host-local: the guest's
        redirected connection is re-originated by passt as a host socket, so
        it arrives on lo; so does the inspector's reply; so does `diagnose`
        probing a listener as root. A drop missing the exemption takes every
        inspected connection down rather than opening anything — the safe
        direction, and it presents as the whole design being inert. Both
        drops must carry it, because a single missing one is the whole
        failure.
        """
        for rule in self.input_rules:
            self.assertIn("iif != lo", rule,
                          f"a drop without the loopback exemption breaks "
                          f"host-local traffic on these planes: {rule}")

    def test_both_drops_are_counted(self):
        """§11's off-box-arrivals figure IS these two counters, and it is the
        one figure in that list with no benign reading: the listener planes
        are reachable from off the host only because the weak host model
        delivers them, so a non-zero value is an attack or a misrouted
        network. Drop the `counter` and the rule still drops -- the evidence
        is simply gone, and nothing anywhere else in the ruleset records that
        the packet ever arrived."""
        for line in self.input_rules:
            self.assertIn("counter", line, line)

    def test_the_drops_carry_no_ct_direction_qualifier(self):
        """The absence is asserted, and it is a test, because the temptation
        to add one is cargo-culted from the output chain.

        Every drop in the output chain carries `ct direction original`
        because the inspector's replies are OUTPUT traffic from a filtered
        uid, and a drop without the qualifier takes every inspected
        connection down. On the input path there is no such thing: a packet
        arriving FROM the inspector is on lo and is already exempted by
        interface. Adding the qualifier there would WEAKEN the rule rather
        than tighten it — an attacker's packet is original-direction on its
        own connection and would still be caught, but a packet that merely
        LOOKED like a reply would no longer be.
        """
        for rule in self.input_rules:
            self.assertNotIn("ct direction", rule,
                             f"a ct direction qualifier on an input drop "
                             f"would let a forged reply through: {rule}")


class TestElementModel(unittest.TestCase):
    def test_uid_alone_goes_in_the_membership_set(self):
        cmds = vm_filter_commands(10001, [], "add")
        self.assertEqual(len(cmds), 1)
        self.assertIn(NFT_SET_FILTERED, cmds[0])
        self.assertIn("{ 10001 }", cmds[0])

    def test_entries_are_split_by_family(self):
        cmds = vm_filter_commands(
            10001, [allow_entry("192.168.0.10:22"),
                    allow_entry("[2001:db8::1]:8443")], "add")
        by_set = {c[5]: c[-1] for c in cmds}
        self.assertIn("192.168.0.10", by_set[NFT_SET_ALLOW4])
        self.assertNotIn("192.168.0.10", by_set[NFT_SET_ALLOW6])
        self.assertIn("2001:db8::1", by_set[NFT_SET_ALLOW6])

    def test_empty_family_produces_no_command(self):
        cmds = vm_filter_commands(10001, [allow_entry("192.168.0.10:22")], "add")
        self.assertNotIn(NFT_SET_ALLOW6, [c[5] for c in cmds])

    def test_all_entries_for_a_set_go_in_one_transaction(self):
        """One nft invocation is one atomic transaction, so a VM is never
        left in wl_filtered holding only part of its allowlist."""
        cmds = vm_filter_commands(
            10001, [allow_entry(f"10.0.0.{n}:22") for n in (1, 2, 3)], "add")
        allow4 = [c for c in cmds if c[5] == NFT_SET_ALLOW4]
        self.assertEqual(len(allow4), 1, "one command per set, not per entry")
        for addr in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
            self.assertIn(addr, allow4[0][-1])

    def test_delete_mirrors_add(self):
        args = (10001, [allow_entry("10.0.0.1:22"),
                        allow_entry("[2001:db8::1]:8443")])
        add = vm_filter_commands(*args, "add")
        delete = vm_filter_commands(*args, "delete")
        self.assertEqual([c[5] for c in add], [c[5] for c in delete])
        self.assertEqual([c[-1] for c in add], [c[-1] for c in delete])
        self.assertTrue(all(c[1] == "delete" for c in delete))

    def test_unknown_action_rejected(self):
        with self.assertRaises(ValueError):
            vm_filter_commands(10001, [], "flush")


class TestOwnedElements(unittest.TestCase):
    """Parsing `nft -j list set` output to find one workload's elements.

    This is what makes a purge possible: nft has no "delete every element
    whose first field is N", so the elements have to be enumerated and
    deleted by exact value.
    """

    def test_membership_set_holds_bare_uids(self):
        self.assertEqual(vm_owned_elements(10001, [10001, 10002]), ["10001"])

    def test_allow_set_holds_concatenations(self):
        elems = [{"concat": [10001, "192.168.0.10", 22]},
                 {"concat": [10002, "192.168.0.11", 22]}]
        self.assertEqual(vm_owned_elements(10001, elems),
                         ["10001 . 192.168.0.10 . 22"])

    def test_a_sibling_workloads_elements_are_never_touched(self):
        """The failure this guards is a purge taking another VM offline."""
        elems = [{"concat": [10002, "10.0.0.1", 22]}]
        self.assertEqual(vm_owned_elements(10001, elems), [])

    def test_empty_and_missing_sets(self):
        self.assertEqual(vm_owned_elements(10001, None), [])
        self.assertEqual(vm_owned_elements(10001, []), [])

    def test_delete_command_batches_entries(self):
        argv = vm_filter_delete_command(
            NFT_SET_ALLOW4, ["10001 . 1.1.1.1 . 22", "10001 . 2.2.2.2 . 443"])
        self.assertEqual(argv[1:3], ["delete", "element"])
        self.assertEqual(
            argv[-1], "{ 10001 . 1.1.1.1 . 22, 10001 . 2.2.2.2 . 443 }")


class TestInspectorAddresses(unittest.TestCase):
    """The inspector's listening addresses, derived from the uid.

    Like the management address and nflog group, these are tested against
    spelled-out values rather than the formula: the DNAT map carries them, so a
    silent drift points every redirected connection at the wrong workload.
    """

    def test_v4_addresses_are_spelled_out(self):
        self.assertEqual(vm_inspect_address(10000).v4, "198.18.1.0")
        self.assertEqual(vm_inspect_address(10004).v4, "198.18.1.4")
        self.assertEqual(vm_inspect_address(10005).v4, "198.18.1.5")
        self.assertEqual(vm_inspect_address(UID_MAX).v4, "198.18.168.196")

    def test_v6_twin_embeds_the_v4(self):
        # 2001:2::198.18.1.4 is a legal literal spelling the same address
        # 2001:2::c612:104; the kernel prints the canonical form, so the value
        # is asserted against that, and the readability is a property of what
        # we write, not of the output.
        self.assertEqual(vm_inspect_address(10000).v6, "2001:2::c612:100")
        self.assertEqual(vm_inspect_address(10004).v6, "2001:2::c612:104")
        self.assertEqual(
            str(ipaddress.IPv6Address("2001:2::198.18.1.4")),
            vm_inspect_address(10004).v6)

    def test_the_first_workload_is_not_on_the_range_network_address(self):
        # A bare offset would put the first workload allocated on any host on
        # 198.18.0.0, the range's own network address — the value everything
        # else defaults to. The base is 198.18.1.0 so it is not.
        self.assertNotEqual(vm_inspect_address(UID_MIN).v4, "198.18.0.0")

    def test_the_whole_uid_range_fits_its_targets(self):
        v4, v6 = vm_inspect_address(UID_MAX)
        self.assertIn(ipaddress.ip_address(v4), VM_INSPECT_NETWORK)
        self.assertIn(ipaddress.ip_address(v6), VM_INSPECT_ADDR6_PREFIX)

    def test_out_of_range_uids_raise_rather_than_wrap(self):
        for uid in (0, 999, UID_MIN - 1, UID_MAX + 1):
            with self.assertRaises(ValueError):
                vm_inspect_address(uid)

    def test_listener_ports_are_unprivileged(self):
        # The inspector binds as the workload user, not root, so both ports
        # have to stay above net.ipv4.ip_unprivileged_port_start (1024).
        self.assertGreater(VM_INSPECT_PORT_CLEARTEXT, 1024)
        self.assertGreater(VM_INSPECT_PORT_TLS, 1024)


class TestProxySkeletonNamesAgree(unittest.TestCase):
    """The transparent redirect's objects and the constants that name them.

    workload-proxy.nft spells wl_inspect4 / wl_inspect6 / wl_inspect_cg
    literally so the file stays applicable with a bare `nft -f`; the DNAT map
    and the cgroup `return` carry those same names. A rename on either side
    leaves the other pointing at a set or map that does not exist — which looks
    exactly like the redirect being off rather than a bug, so the file is read
    and checked against the constants rather than trusted, the way
    test_vm_broker.py does for VM_BROKER_LISTEN_ADDR.
    """

    def test_the_skeleton_declares_each_object_with_its_constant_name(self):
        text = PROXY_SKELETON.read_text()
        self.assertIn(f"add map inet workload_proxy {NFT_MAP_INSPECT4}", text)
        self.assertIn(f"add map inet workload_proxy {NFT_MAP_INSPECT6}", text)
        self.assertIn(
            f"add set inet workload_proxy {NFT_SET_INSPECT_CG}", text)

    def test_the_rules_reference_each_object_by_its_constant_name(self):
        """The declaration is not enough: a rule must reach the object by the
        same name, and a drift between the two is a map or set that no rule
        ever reads."""
        text = PROXY_SKELETON.read_text()
        self.assertIn(f"@{NFT_SET_INSPECT_CG} return", text)
        self.assertIn(f"map @{NFT_MAP_INSPECT4}", text)
        self.assertIn(f"map @{NFT_MAP_INSPECT6}", text)


class TestUnitWiring(unittest.TestCase):
    """The VM unit's arm/disarm hooks, rendered by the real generator."""

    @classmethod
    def setUpClass(cls):
        from tests.test_generator_snapshot import render_matrix
        cls.units = {n: t for n, t in render_matrix().items()
                     if n.startswith("vm-") and "qemu-system" in t}

    def _hooks(self, text):
        return [ln for ln in text.splitlines() if "workload-vm-filter" in ln]

    def test_every_passt_vm_arms_and_disarms(self):
        self.assertTrue(self.units, "no VM units rendered")
        for name, text in self.units.items():
            if "-netdev passt" not in text:
                continue      # bridged: no host socket carries the uid
            hooks = self._hooks(text)
            self.assertTrue(
                any(h.startswith("ExecStartPre=") and " up " in h
                    for h in hooks), f"{name} never arms: {hooks}")
            self.assertTrue(
                any(h.startswith("ExecStopPost=") and " down " in h
                    for h in hooks), f"{name} never disarms: {hooks}")

    def test_disarm_runs_on_stop_post_not_stop(self):
        """ExecStop does not run when a unit is killed or fails; ExecStopPost
        does. A crashed VM must not leave its uid armed."""
        for name, text in self.units.items():
            for hook in self._hooks(text):
                if " down " in hook:
                    self.assertTrue(hook.startswith("ExecStopPost="), hook)

    def test_arm_is_privileged_and_intolerant_disarm_is_tolerant(self):
        """`+` because the workload user cannot write nft state. The arm must
        NOT be `-` prefixed: a filtered VM that failed to arm would run wide
        open while its config claims confinement."""
        for name, text in self.units.items():
            for hook in self._hooks(text):
                value = hook.split("=", 1)[1]
                if " up " in hook:
                    self.assertTrue(value.startswith("+"), hook)
                    self.assertFalse(value.startswith("-"), hook)
                else:
                    self.assertTrue(value.startswith("-+"), hook)

    def test_bridged_vms_are_not_wired_to_the_filter(self):
        for name, text in self.units.items():
            if "-netdev passt" in text:
                continue
            self.assertEqual(self._hooks(text), [], name)


class TestFilterHelper(unittest.TestCase):
    """libexec/workload-vm-filter -- arming and disarming one workload."""

    @classmethod
    def setUpClass(cls):
        from tests import load_script
        cls.mod = load_script("libexec/workload-vm-filter")

    def setUp(self):
        self.calls = []
        # Default: every nft call succeeds and every set lists as empty.
        self.listing = {}
        self.rc = {}

        def fake_run(argv, capture_output=True, text=True, check=False,
                     timeout=None):
            self.calls.append(argv)
            rc = self.rc.get(tuple(argv[:3]), 0)
            stdout = ""
            if "-j" in argv and "list" in argv:
                set_name = argv[-1]
                stdout = json.dumps({"nftables": [
                    {"metainfo": {}},
                    {"set": {"name": set_name,
                             "elem": self.listing.get(set_name, [])}}]})
            result = SimpleNamespace(returncode=rc, stdout=stdout, stderr="")
            if check and rc != 0:
                raise subprocess.CalledProcessError(rc, argv)
            return result

        patcher = mock.patch.object(self.mod.subprocess, "run", fake_run)
        patcher.start()
        self.addCleanup(patcher.stop)
        self._patch("workload_uid", lambda name: 10001)

        # The responder's answer document is written by this helper, from the
        # same resolution the elements were armed from. Redirected into a
        # tmpdir rather than stubbed out: the write is part of `up`, and a
        # stub here would make every assertion below true of a helper that
        # never wrote one. The ownership call is what actually needs root, so
        # only that is faked.
        import tempfile
        self.policy_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.policy_dir, True)
        self.policy_path = os.path.join(self.policy_dir, "resolve.json")
        self._patch("vm_resolve_policy_path", lambda name: self.policy_path)
        self._patch("pwd", SimpleNamespace(
            getpwnam=lambda n: SimpleNamespace(pw_uid=10001, pw_gid=10001)))
        self.chowned = []
        self._patch("os", SimpleNamespace(
            chown=lambda p, u, g: self.chowned.append((p, u, g)),
            chmod=os.chmod, replace=os.replace))

    def _resolve_document(self):
        with open(self.policy_path) as f:
            return json.load(f)

    def _patch(self, attr, value):
        p = mock.patch.object(self.mod, attr, value)
        p.start()
        self.addCleanup(p.stop)

    def _net(self, **cfg):
        self._patch("network_config", lambda name: cfg)

    def _adds(self):
        return [c for c in self.calls if len(c) > 1 and c[1] == "add"]

    # --- the responder's answer document, written here ---

    def test_up_writes_the_responder_document(self):
        """The responder is socket-activated by a guest query, and the guest
        cannot query before the VM it comes from is running -- which is after
        this ExecStartPre. Ordering is inherited rather than declared, so the
        thing to assert is that the write happens at all."""
        from vm import VM_RESOLVE_TTL, vm_inspect_address
        self._net(egress="filtered", allow=[])
        self.mod.up("vm1")
        doc = self._resolve_document()
        self.assertEqual(doc["address"], vm_inspect_address(10001).v4)
        self.assertEqual(doc["address6"], vm_inspect_address(10001).v6)
        self.assertEqual(doc["ttl"], VM_RESOLVE_TTL)

    def test_the_document_is_readable_only_by_the_workload(self):
        """0640 with the workload's group, like the inspector's policy: the
        responder runs as _wl-<name> and must read it, and one workload's
        answers are not another's to enumerate."""
        self._net(egress="filtered", allow=[])
        self.mod.up("vm1")
        self.assertEqual(os.stat(self.policy_path).st_mode & 0o777, 0o640)
        self.assertEqual(self.chowned, [(self.policy_path + ".tmp", 0, 10001)])

    def test_a_named_allow_entry_reaches_the_document(self):
        """And it reaches it from the SAME resolution the elements were armed
        from -- here one stub answers once, and both consumers read it."""
        entry = SimpleNamespace(address=None, host="git.local", port=2222,
                                reason="forge")
        resolved = [(entry, [ipaddress.IPv4Address("192.0.2.9")])]
        self._patch("vm_allow_resolved", lambda allow: resolved)
        self._net(egress="filtered",
                  allow=[{"address": "git.local:2222", "reason": "forge"}])
        self.mod.up("vm1")
        self.assertEqual(self._resolve_document()["static"],
                         {"git.local": ["192.0.2.9"]})
        armed = [c for c in self._adds() if c[-2] == "wl_allow4"]
        self.assertIn("192.0.2.9", armed[0][-1])

    def test_resolver_none_writes_no_document(self):
        """One knob, one meaning. A guest told to ask nobody gets no
        responder unit, so a document for one would be a file nothing reads
        holding a policy nobody applied."""
        self._net(egress="filtered", allow=[], resolver="none")
        self.mod.up("vm1")
        self.assertFalse(os.path.exists(self.policy_path))

    def test_open_egress_writes_no_document(self):
        self._net(egress="open", allow=[])
        self.mod.up("vm1")
        self.assertFalse(os.path.exists(self.policy_path))

    def test_a_bridged_vm_writes_no_document(self):
        self._net(bridge="br0", allow=[])
        self.mod.up("vm1")
        self.assertFalse(os.path.exists(self.policy_path))

    def _deletes(self):
        return [c for c in self.calls if len(c) > 1 and c[1] == "delete"]

    def test_up_applies_the_skeleton_before_touching_elements(self):
        self._net(egress="filtered", allow=[allow_entry("10.0.0.1:22")])
        self.mod.up("vm1")
        self.assertIn("-f", self.calls[0])
        self.assertIn(NFT_SKELETON, self.calls[0])

    def test_up_arms_the_uid_and_its_allowlist(self):
        self._net(egress="filtered", allow=[allow_entry("10.0.0.1:22")])
        self.mod.up("vm1")
        armed = " ".join(" ".join(c) for c in self._adds())
        self.assertIn(NFT_SET_FILTERED, armed)
        self.assertIn("10.0.0.1", armed)

    def test_open_egress_applies_the_skeleton_but_arms_nothing(self):
        self._net(egress="open")
        self.mod.up("vm1")
        self.assertEqual(self._adds(), [])

    def test_bridged_vm_does_not_even_apply_the_skeleton(self):
        self._net(bridge="br0")
        self.mod.up("vm1")
        self.assertEqual(self.calls, [])

    def test_up_clears_stale_elements_from_a_previous_allowlist(self):
        """The reason this is a script and not a few Exec lines.

        An operator removing an entry from `allow` and re-enabling would
        otherwise leave the dropped address permitted: ExecStopPost only
        deletes what the *current* unit names. Verified against nftables
        1.1.6 -- arming {A, B} then deleting {B} leaves A behind.
        """
        self.listing = {
            NFT_SET_FILTERED: [10001],
            NFT_SET_ALLOW4: [{"concat": [10001, "1.1.1.1", 22]},
                             {"concat": [10001, "2.2.2.2", 443]}],
        }
        self._net(egress="filtered", allow=[allow_entry("2.2.2.2:8443")])
        self.mod.up("vm1")
        cleared = " ".join(" ".join(c) for c in self._deletes())
        self.assertIn("1.1.1.1", cleared,
                      "the dropped entry was left permitted")

    def test_up_never_clears_a_sibling_workloads_elements(self):
        self.listing = {NFT_SET_ALLOW4: [{"concat": [10002, "9.9.9.9", 22]}]}
        self._net(egress="filtered", allow=[allow_entry("10.0.0.1:22")])
        self.mod.up("vm1")
        self.assertNotIn("9.9.9.9",
                         " ".join(" ".join(c) for c in self._deletes()))

    def test_up_fails_when_the_skeleton_cannot_be_applied(self):
        """A filtered VM that failed to arm must not start: it would run wide
        open while its config claims confinement."""
        self.rc[("/usr/sbin/nft", "-f", NFT_SKELETON)] = 1
        self._net(egress="filtered", allow=[allow_entry("10.0.0.1:22")])
        with self.assertRaises(subprocess.CalledProcessError):
            self.mod.up("vm1")

    def test_up_fails_when_an_element_cannot_be_added(self):
        self.rc[("/usr/sbin/nft", "add", "element")] = 1
        self._net(egress="filtered", allow=[allow_entry("10.0.0.1:22")])
        with self.assertRaises(subprocess.CalledProcessError):
            self.mod.up("vm1")

    def test_down_removes_this_workloads_elements(self):
        self.listing = {NFT_SET_FILTERED: [10001, 10002]}
        self._net(egress="filtered")
        self.mod.down("vm1")
        deleted = " ".join(" ".join(c) for c in self._deletes())
        self.assertIn("10001", deleted)
        self.assertNotIn("10002", deleted)

    def test_down_is_quiet_when_nothing_is_armed(self):
        self._net(egress="filtered")
        self.assertEqual(self.mod.down("vm1"), 0)
        self.assertEqual(self._deletes(), [])

    def test_down_survives_a_missing_workload_user(self):
        """Purge deletes the user; the stop hook may run after."""
        self._patch("workload_uid",
                    mock.Mock(side_effect=KeyError("_wl-vm1")))
        self.assertEqual(self.mod.down("vm1"), 0)

    def test_down_survives_a_missing_table(self):
        """After the break-glass `nft delete table`, listing fails."""
        self.rc[("/usr/sbin/nft", "-j", "list")] = 1
        self._net(egress="filtered")
        self.assertEqual(self.mod.down("vm1"), 0)

    def test_usage(self):
        self.assertEqual(self.mod.main(["x"]), 2)
        self.assertEqual(self.mod.main(["x", "sideways", "vm1"]), 2)


    def test_up_clears_the_previous_instances_resolver_status(self):
        """Same lifecycle trap as the inspector's: the run dir is preserved
        across a restart and the responder is socket-activated, so until the
        guest's first query the file on disk is the last boot's query counts.
        Cleared beside the policy write, which is the other thing this helper
        does to that directory on every arm."""
        source = (Path(__file__).resolve().parent.parent
                  / "libexec" / "workload-vm-filter").read_text()
        up = source[source.index("def up("):source.index("def down(")]
        self.assertIn("clear_status(vm_resolve_status_path(name))", up)
        # Inside the resolver branch: a workload with no synthesising responder
        # has no such file, and clearing one unconditionally would claim a
        # producer that this workload does not run.
        self.assertLess(up.index("vm_uses_resolve"),
                        up.index("clear_status"))

class TestEgressDiagnose(unittest.TestCase):
    """`diagnose`'s egress check.

    Its reason for existing is the one failure no other signal catches: a
    config that says "filtered" while the uid is absent from the set. That VM
    is wide open, and the unit is active, the guest has network, and `status`
    is green.
    """

    def setUp(self):
        import cmd_diagnose
        self.mod = cmd_diagnose

    def _config(self, egress="filtered", bridge=None, uid=10001, hosts=None):
        net = {} if egress is None else {"egress": egress}
        if hosts:
            net["hosts"] = hosts
        return SimpleNamespace(
            name="vm1", uid=uid, vm_bridge=bridge, vm_network=net)

    def _nft(self, *, table=True, armed=True, allow=(), dropped=None,
             guard=True):
        """Stub _nft_json: model the host's nft state as data."""
        def fake(*args):
            if not table:
                return None
            if args[0] == "list" and args[1] == "set":
                name = args[-1]
                if name == NFT_SET_FILTERED:
                    return {"nftables": [{"set": {"elem": [10001] if armed else []}}]}
                if name == NFT_SET_ALLOW4:
                    return {"nftables": [{"set": {"elem": [
                        {"concat": [10001, a, p]} for a, p in allow]}}]}
                if name in (NFT_SET_INTERNAL4, NFT_SET_INTERNAL6):
                    return {"nftables": [{"set": {
                        "elem": ["10.0.0.0/8"] if guard else []}}]}
                return {"nftables": [{"set": {"elem": []}}]}
            rule = {"expr": [{"counter": {"packets": dropped or 0, "bytes": 0}},
                             {"drop": None}]}
            return {"nftables": [{"rule": rule}]} if dropped is not None else {"nftables": []}
        return mock.patch.object(self.mod, "_nft_json", fake)

    def test_filtered_and_armed_passes_and_counts_entries(self):
        with self._nft(allow=[("10.0.0.1", 22)], dropped=7):
            name, passed, msg = self.mod.vm_egress_check(self._config())
        self.assertEqual(name, "vm_egress")
        self.assertTrue(passed)
        self.assertIn("1 allow entry", msg)

    def test_the_conntrack_figure_is_reported_on_a_healthy_host(self):
        """Always a number, so it is there when someone looks."""
        with self._nft(dropped=0), mock.patch.object(
                self.mod, "conntrack_occupancy", lambda: (34, 262144)):
            _, passed, msg = self.mod.vm_egress_check(self._config())
        self.assertTrue(passed)
        self.assertIn("conntrack 34/262144", msg)
        self.assertNotIn("near capacity", msg)

    def test_conntrack_near_capacity_carries_its_interpretation(self):
        """The number alone is not the finding -- the sentence is.

        An exhausted table reclassifies established replies as `direction
        original` and the guard drops them mid-transfer, which inside the
        guest is a download dying part-way with nothing else moving: the
        accept counters are unchanged and the guard counter climbs for what
        looks exactly like the cross-workload case. This line is the only path
        from that symptom to the cause.

        The threshold constant and the reader were both tested; that
        vm_egress_check ever appends the sentence was not, so raising the
        multiplier so it could never fire left the whole suite green.
        """
        with self._nft(dropped=0), mock.patch.object(
                self.mod, "conntrack_occupancy", lambda: (250000, 262144)):
            _, passed, msg = self.mod.vm_egress_check(self._config())
        self.assertTrue(passed, msg)
        self.assertIn("conntrack 250000/262144", msg)
        self.assertIn("near capacity", msg)
        self.assertIn("part-way", msg)

    def test_an_unreadable_conntrack_figure_is_simply_absent(self):
        """The module is not loaded until something uses it, so None is a
        normal reading and must not become a traceback or a zero."""
        with self._nft(dropped=0), mock.patch.object(
                self.mod, "conntrack_occupancy", lambda: None):
            _, passed, msg = self.mod.vm_egress_check(self._config())
        self.assertTrue(passed)
        self.assertNotIn("conntrack", msg)

    def test_filtered_but_not_armed_fails_loudly(self):
        with self._nft(armed=False):
            _, passed, msg = self.mod.vm_egress_check(self._config())
        self.assertFalse(passed)
        self.assertIn("UNFILTERED", msg)

    def test_filtered_with_no_table_fails(self):
        with self._nft(table=False):
            _, passed, msg = self.mod.vm_egress_check(self._config())
        self.assertFalse(passed)
        self.assertIn("absent", msg)

    def test_open_with_no_table_is_consistent(self):
        with self._nft(table=False):
            _, passed, _ = self.mod.vm_egress_check(self._config(egress="open"))
        self.assertTrue(passed)

    def test_open_but_still_armed_fails(self):
        """A stale element from an earlier config silently filters a VM the
        operator has since opened up."""
        with self._nft(armed=True):
            _, passed, msg = self.mod.vm_egress_check(self._config(egress="open"))
        self.assertFalse(passed)
        self.assertIn("stale", msg)

    def test_open_and_not_armed_passes(self):
        with self._nft(armed=False):
            _, passed, _ = self.mod.vm_egress_check(self._config(egress="open"))
        self.assertTrue(passed)

    def test_hostname_policy_without_the_guard_fails(self):
        """The table outlives the RPM. A VM started before an upgrade keeps the
        older chain, so its proxy is still destination-blind while every other
        signal -- unit active, uid armed, allow entries present -- is green."""
        with self._nft(guard=False):
            _, passed, msg = self.mod.vm_egress_check(
                self._config(hosts=["api.example.com"]))
        self.assertFalse(passed)
        self.assertIn(NFT_SET_INTERNAL4, msg)
        self.assertIn("restart", msg)

    def test_hostname_policy_with_the_guard_passes(self):
        with self._nft(guard=True, dropped=0):
            _, passed, msg = self.mod.vm_egress_check(
                self._config(hosts=["api.example.com"]))
        self.assertTrue(passed)
        self.assertIn("egress filtered", msg)

    def test_no_hostname_policy_does_not_require_the_guard(self):
        """The guard only qualifies the proxy's exemption. A VM with no `hosts`
        has no proxy, so an older table is not a finding for it -- reporting one
        would send an operator after an irrelevant restart."""
        with self._nft(guard=False, allow=[("10.0.0.1", 22)], dropped=0):
            _, passed, _ = self.mod.vm_egress_check(self._config())
        self.assertTrue(passed)

    def test_bridged_vm_is_skipped_entirely(self):
        self.assertIsNone(self.mod.vm_egress_check(self._config(bridge="br0")))

    def test_drop_count_is_reported_as_shared_not_per_workload(self):
        """One drop rule guarded on set membership serves every filtered
        workload, so the counter aggregates them. Presenting it as this VM's
        would misattribute a sibling's traffic."""
        with self._nft(dropped=42):
            _, _, msg = self.mod.vm_egress_check(self._config())
        self.assertIn("42", msg)
        self.assertIn("shared", msg)

    def test_missing_user_is_not_reported_here(self):
        """The user-exists check already says so; repeating it as an egress
        failure would give one cause two unrelated-looking symptoms."""
        class NoUser:
            name, vm_bridge, vm_network = "vm1", None, {"egress": "filtered"}

            @property
            def uid(self):
                raise KeyError("_wl-vm1")

        self.assertIsNone(self.mod.vm_egress_check(NoUser()))


class TestDropCounterParsing(unittest.TestCase):
    def test_finds_the_counter_on_the_drop_rule(self):
        doc = {"nftables": [
            {"rule": {"expr": [{"counter": {"packets": 1, "bytes": 2}},
                               {"accept": None}]}},
            {"rule": {"expr": [{"counter": {"packets": 9, "bytes": 8}},
                               {"drop": None}]}}]}
        self.assertEqual(nft_drop_counter(doc), (9, 8))

    def test_none_when_no_drop_rule(self):
        self.assertIsNone(nft_drop_counter({"nftables": []}))
        self.assertIsNone(nft_drop_counter(None))

    def test_set_elements_extraction(self):
        doc = {"nftables": [{"metainfo": {}}, {"set": {"elem": [1, 2]}}]}
        self.assertEqual(nft_set_elements(doc), [1, 2])
        self.assertEqual(nft_set_elements({"nftables": []}), [])
        self.assertEqual(nft_set_elements(None), [])


if __name__ == "__main__":
    unittest.main()


class TestConntrackOccupancy(unittest.TestCase):
    """§11's conntrack figure. It is not the inspector's to report and it is
    read here anyway, because the egress guard's correctness depends on
    conntrack state: a reply is only distinguishable from a fresh connection
    because an entry exists, so an exhausted table reclassifies the
    inspector's replies as `direction original` and drops them mid-connection.

    The reason it needs a producer at all is that nothing else moves when it
    happens. The accept counters are unchanged and the guard counter climbs
    for a reason that looks exactly like the cross-workload case it was
    written for, so without this number an operator has no path from
    "downloads keep dying" to the cause.
    """

    def _paths(self, count, maximum):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        c, m = os.path.join(d, "count"), os.path.join(d, "max")
        with open(c, "w") as f:
            f.write(f"{count}\n")
        with open(m, "w") as f:
            f.write(f"{maximum}\n")
        return c, m

    def test_reads_both_figures(self):
        c, m = self._paths(1234, 262144)
        self.assertEqual(conntrack_occupancy(c, m), (1234, 262144))

    def test_an_unloaded_module_is_none_not_an_exception(self):
        """The conntrack module is not loaded until something uses it, so the
        files are legitimately absent. A missing figure must never turn a
        diagnose line into a traceback."""
        self.assertIsNone(
            conntrack_occupancy("/nonexistent/count", "/nonexistent/max"))

    def test_garbage_is_none_not_a_crash(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        c, m = os.path.join(d, "c"), os.path.join(d, "m")
        with open(c, "w") as f:
            f.write("not a number\n")
        with open(m, "w") as f:
            f.write("262144\n")
        self.assertIsNone(conntrack_occupancy(c, m))

    def test_a_zero_maximum_is_none_rather_than_a_division_by_zero(self):
        """The pressure test divides by it. Zero is not a real kernel value,
        which is exactly why nothing downstream would guard against it."""
        c, m = self._paths(0, 0)
        self.assertIsNone(conntrack_occupancy(c, m))

    def test_the_pressure_threshold_leaves_a_healthy_host_unremarked(self):
        """A number, not a warning, is what a healthy host gets: the figure is
        reported always so that it is there when someone looks, and the
        interpretation is added only when it is the answer."""
        self.assertLess(34 / 262144, CONNTRACK_PRESSURE)
        self.assertGreaterEqual(250000 / 262144, CONNTRACK_PRESSURE)


class TestInspectDiagnose(unittest.TestCase):
    """`diagnose`'s inspector check.

    The failure it exists for is the mirror of the egress check's, and harder
    to see: inspection is default-on, so nothing in the config declares it and
    there is no stated intent for an operator to compare reality against. A
    guest missing from the inspect maps reaches the internet directly with the
    unit active, `status` green, and `vm_egress` correctly reporting the VM
    filtered — because it is filtered. It is just not being looked at.
    """

    def setUp(self):
        import cmd_diagnose
        self.mod = cmd_diagnose

    def _config(self, egress="filtered", bridge=None, uid=10001, is_vm=True):
        net = {} if egress is None else {"egress": egress}
        cfg = {"vm": {}} if is_vm else {"container": {}}
        if is_vm:
            cfg["vm"]["network"] = dict(net)
            if bridge:
                cfg["vm"]["network"]["bridge"] = bridge
        return SimpleNamespace(name="vm1", uid=uid, vm_bridge=bridge,
                               vm_network=net, config=cfg)

    def _elem(self, uid, port):
        """One map element in the shape nft 1.1.6 actually renders."""
        return [{"concat": [uid, port]},
                {"concat": ["198.18.1.1", 8080]}]

    def _run(self, **kw):
        kw.setdefault("socket_active", True)
        kw.setdefault("v6_route", True)
        # Injected rather than probed so no test shells out to nft. None is
        # the reading on a host where the set cannot be read, which is what
        # every test that is not about this counter should see.
        kw.setdefault("self_dials", None)
        return self.mod.vm_inspect_check(self._config(), **kw)

    # --- applicability ---

    def test_a_container_gets_no_line(self):
        cfg = self._config(is_vm=False)
        self.assertIsNone(self.mod.vm_inspect_check(cfg))

    def test_a_bridged_vm_gets_no_line(self):
        # No host socket in the data path, so there is no uid to key on.
        cfg = self._config(bridge="br0")
        self.assertIsNone(self.mod.vm_inspect_check(cfg))

    def test_an_unfiltered_vm_gets_no_line(self):
        cfg = self._config(egress="unfiltered")
        self.assertIsNone(self.mod.vm_inspect_check(cfg))

    # --- verdicts ---

    def test_an_absent_table_fails_and_says_traffic_is_leaving_uninspected(self):
        ok, passed, msg = self._run(elements4=None, elements6=None)
        self.assertEqual(ok, "vm_inspect")
        self.assertFalse(passed)
        self.assertIn("reaching the internet directly", msg)

    def test_a_uid_in_neither_map_fails(self):
        _, passed, msg = self._run(elements4=[self._elem(10002, 80)],
                                   elements6=[self._elem(10002, 80)])
        self.assertFalse(passed)
        self.assertIn("uninspected", msg)
        self.assertIn("workload-vm1-inspect.socket", msg)

    def test_half_armed_is_a_failure_naming_the_missing_family(self):
        # The half that works is the half an operator probes: a v4 check passes
        # and the journal fills with lines while v6 leaves unseen.
        _, passed, msg = self._run(elements4=[self._elem(10001, 80)],
                                   elements6=[])
        self.assertFalse(passed)
        self.assertIn("IPv6", msg)
        self.assertIn(NFT_MAP_INSPECT6, msg)

    def test_half_armed_the_other_way_names_ipv4(self):
        _, passed, msg = self._run(elements4=[],
                                   elements6=[self._elem(10001, 80)])
        self.assertFalse(passed)
        self.assertIn("IPv4", msg)
        self.assertIn(NFT_MAP_INSPECT4, msg)

    def test_armed_maps_with_a_dead_socket_fail_and_name_the_symptom(self):
        # The opposite failure direction from missing maps, and it must not be
        # confused with it: here the guest breaks rather than leaks.
        _, passed, msg = self._run(elements4=[self._elem(10001, 80)],
                                   elements6=[self._elem(10001, 80)],
                                   socket_active=False)
        self.assertFalse(passed)
        self.assertIn("nothing accepts", msg)
        self.assertIn("DNS and SSH", msg)

    def test_fully_armed_passes(self):
        _, passed, msg = self._run(elements4=[self._elem(10001, 80)],
                                   elements6=[self._elem(10001, 80)])
        self.assertTrue(passed)
        self.assertIn("both families", msg)

    def test_a_host_with_no_v6_route_still_passes_but_says_so(self):
        # A correctly armed v6 redirect logs nothing on such a host: the packet
        # loses its routing lookup before the nat hook. Silence there is not a
        # fault, and reporting it as one sends the operator after a working
        # ruleset.
        _, passed, msg = self._run(elements4=[self._elem(10001, 80)],
                                   elements6=[self._elem(10001, 80)],
                                   v6_route=False)
        self.assertTrue(passed)
        self.assertIn("no IPv6 default route", msg)
        self.assertIn("before nftables", msg)

    def test_no_user_yet_gets_no_line(self):
        # Generation precedes user creation, so a first `enable` reaches this
        # before _wl-vm1 exists. Check 1 already reports that; a second line
        # saying the redirect is missing would be noise blaming the wrong step.
        class NoUser:
            name = "vm1"
            vm_bridge = None
            vm_network = {"egress": "filtered"}
            config = {"vm": {"network": {"egress": "filtered"}}}

            @property
            def uid(self):
                raise KeyError("_wl-vm1")

        self.assertIsNone(self.mod.vm_inspect_check(NoUser()))


class TestInspectMapKeyShapes(unittest.TestCase):
    """The map-element reader accepts every shape nft renders.

    This is not defensive padding. A map element is a two-item [key, value]
    list, not a dict with "concat" at the top, so reading the inspect maps with
    the *set* helper (vm_owned_elements) returns nothing and reports every
    inspected VM as uninspected — a false alarm on every host. That exact
    mismatch already shipped once against the proxy map.
    """

    def setUp(self):
        import cmd_diagnose
        self.uid_of = cmd_diagnose._map_key_uid

    def test_the_nft_list_shape(self):
        self.assertEqual(
            self.uid_of([{"concat": [10001, 80]},
                         {"concat": ["198.18.1.1", 8080]}]), "10001")

    def test_the_counted_elem_shape(self):
        self.assertEqual(
            self.uid_of({"elem": {"key": {"concat": [10001, 443]}}}), "10001")

    def test_the_flat_fixture_string(self):
        self.assertEqual(
            self.uid_of("10001 . 80 : 198.18.1.1 . 8080"), "10001")

    def test_a_shape_it_cannot_read_returns_none_rather_than_guessing(self):
        self.assertIsNone(self.uid_of({"unexpected": True}))

    def test_the_set_helper_would_have_missed_the_real_shape(self):
        # Pins the reason this helper exists at all: if this ever starts
        # returning the uid, the two readers have converged and the extra
        # helper can go.
        from vm import vm_owned_elements
        self.assertEqual(
            vm_owned_elements(10001, [[{"concat": [10001, 80]},
                                       {"concat": ["198.18.1.1", 8080]}]]), [])


class TestAllowMayNotNameTheListenerRange(unittest.TestCase):
    """An `allow` entry inside the inspector's planes is refused (HLD §3).

    `allow` is matched ahead of the guard that stops one workload reaching
    another's inspector, so nothing downstream catches such an entry: it is
    accepted, lands on a policy point enforcing a different workload's
    allowlist, and re-originates as a different workload's uid. The refusal is
    the only thing standing between that config line and cross-workload
    inspection, which is why it is tested on both the schema path an operator
    meets and the arming path a live start takes.
    """

    def test_a_v4_listener_address_is_refused(self):
        addr = vm_inspect_address(10000)
        with self.assertRaises(ValueError) as caught:
            parse_vm_allow(allow_entry(f"{addr.v4}:8080"))
        self.assertIn("listener range", str(caught.exception))

    def test_a_v6_listener_address_is_refused(self):
        addr = vm_inspect_address(10000)
        with self.assertRaises(ValueError) as caught:
            parse_vm_allow(allow_entry(f"[{addr.v6}]:8443"))
        self.assertIn("listener range", str(caught.exception))

    def test_any_address_in_the_range_is_refused_not_just_an_allocated_one(self):
        """The whole reservation, not the addresses uids happen to map to.

        A guard that refused only allocated addresses would accept
        198.18.200.1 today and refuse it the day a workload is created that
        maps to it -- a validation rule whose answer depends on which other
        workloads exist.
        """
        with self.assertRaises(ValueError):
            parse_vm_allow(allow_entry("198.18.200.1:8443"))
        with self.assertRaises(ValueError):
            parse_vm_allow(allow_entry("[2001:2::dead:beef]:8443"))

    def test_the_refusal_names_the_range_and_a_remedy(self):
        with self.assertRaises(ValueError) as caught:
            parse_vm_allow(allow_entry("198.18.1.0:9999"))
        message = str(caught.exception)
        self.assertIn("198.18.0.0/16", message)
        self.assertIn("inspector", message)

    def test_ordinary_addresses_still_parse(self):
        for spec in ("192.168.0.10:22", "10.0.0.1:5432", "[2001:db8::1]:8443"):
            with self.subTest(spec=spec):
                parse_vm_allow(allow_entry(spec))

    def test_the_neighbouring_benchmark_half_is_not_refused(self):
        """198.18.0.0/15 is the benchmark reservation; only our /16 is ours.

        Refusing the whole /15 would take addresses this design never claimed,
        and the boundary is one bit -- exactly the kind of range a later edit
        widens by accident.
        """
        parse_vm_allow(allow_entry("198.19.0.1:8443"))

    def test_the_reason_helper_answers_none_for_a_public_address(self):
        self.assertIsNone(
            vm_allow_reserved_reason(ipaddress.ip_address("93.184.216.34")))
        self.assertIsNone(
            vm_allow_reserved_reason(ipaddress.ip_address("2606:2800::1")))

    def test_a_v4_plane_address_does_not_refuse_the_v6_family_and_back(self):
        """Each family is judged against its own plane.

        The planes are derived from one number, so a check that compared an
        address against the wrong family's network would answer False for
        everything and read as a passing test.
        """
        self.assertIsNone(
            vm_allow_reserved_reason(ipaddress.ip_address("2001:db8::1")))
        self.assertIsNotNone(
            vm_allow_reserved_reason(ipaddress.ip_address("198.18.1.0")))


class TestListenerRangeRefusalReachesBothPaths(unittest.TestCase):
    """The schema path and the arming path both refuse (HLD §3: "in the
    helper as well as the schema").

    They are separate tests because they fail separately: validation runs when
    an operator writes the file, and the arming path runs on every start
    including one whose config predates the rule.
    """

    def test_validation_reports_it_as_an_allow_error(self):
        from vm import _validate_egress
        errors = _validate_egress({"egress": "filtered",
                                   "allow": [allow_entry("198.18.1.0:8080")]})
        self.assertTrue(any("listener range" in e for e in errors), errors)
        self.assertTrue(any("[vm.network].allow" in e for e in errors), errors)

    def test_the_arming_path_refuses_rather_than_installing_the_element(self):
        with self.assertRaises(ValueError):
            vm_filter_commands(10001, [allow_entry("198.18.1.0:8080")], "add")

    def test_a_valid_entry_beside_a_refused_one_does_not_rescue_it(self):
        """One bad entry fails the whole arm rather than arming the rest.

        A partial arm is the worst outcome available: the workload starts,
        `diagnose` shows allow entries, and the refused one is missing with
        nothing saying so.
        """
        with self.assertRaises(ValueError):
            vm_filter_commands(10001, [allow_entry("10.0.0.1:22"),
                                      allow_entry("198.18.1.0:8080")], "add")


class TestElementCounterParsing(unittest.TestCase):
    """nft_element_counter -- the per-element shape a counted set renders.

    The shape differs from an uncounted set's, and reading the uncounted shape
    against a counted set silently yields nothing. Fixtures are the literal
    output of nft 1.1.6, not a guess at it.
    """

    def _counted(self, uid, addr, packets, byte_count):
        return {"nftables": [
            {"metainfo": {}},
            {"set": {"name": NFT_SET_INSPECT_SELF,
                     "elem": [{"elem": {
                         "val": {"concat": [uid, addr]},
                         "counter": {"packets": packets,
                                     "bytes": byte_count}}}]}}]}

    def test_it_reads_the_wrapped_element_shape(self):
        doc = self._counted(10000, "198.18.1.0", 12, 720)
        self.assertEqual(nft_element_counter(doc, 10000), (12, 720))

    def test_another_workloads_element_is_not_this_workloads_count(self):
        """The attribution is the whole point of a per-element counter.

        Matching on anything but the first component would report a sibling's
        self-dials as this guest's, which is precisely what the host-wide drop
        counter already does and what this exists to improve on.
        """
        doc = self._counted(10002, "198.18.3.0", 12, 720)
        self.assertIsNone(nft_element_counter(doc, 10000))

    def test_absent_is_none_and_zero_is_zero(self):
        """None and (0, 0) are different findings and must not collapse.

        Zero is armed and never hit -- the healthy reading. None on a workload
        that claims inspection means the guard was never armed, which is a
        missing drop rather than an unused one.
        """
        self.assertEqual(
            nft_element_counter(self._counted(10000, "198.18.1.0", 0, 0), 10000),
            (0, 0))
        self.assertIsNone(nft_element_counter(
            {"nftables": [{"set": {"name": NFT_SET_INSPECT_SELF, "elem": []}}]},
            10000))

    def test_an_uncounted_element_yields_none_rather_than_a_wrong_number(self):
        """A set that lost its `counter` flag renders the unwrapped shape."""
        doc = {"nftables": [
            {"set": {"name": NFT_SET_INSPECT_SELF,
                     "elem": [{"concat": [10000, "198.18.1.0"]}]}}]}
        self.assertIsNone(nft_element_counter(doc, 10000))

    def test_the_skeleton_still_declares_the_counter_flag(self):
        """Without the flag every reading above is None on a live host.

        The parser cannot tell a set that was never hit from one that cannot
        count, so the flag is asserted where it is declared.
        """
        text = SKELETON.read_text()
        for set_name in (NFT_SET_INSPECT_SELF, NFT_SET_INSPECT_SELF6):
            # `set_name in line` would match wl_inspect_self against the
            # wl_inspect_self6 declaration too: one name is a prefix of the
            # other, and the substring test picks up both.
            line = only(self, [l for l in text.splitlines()
                               if l.split()[:1] == ["add"]
                               and f" {set_name} " in l],
                        f"declaration of {set_name}")
            self.assertIn("counter", line)


class TestV6RouteProbeFailsQuiet(unittest.TestCase):
    """_host_has_v6_route answers "unknown" as True, and that direction matters.

    The note it gates says the v6 redirect will log nothing because the host
    has no IPv6 default route -- a statement about the HOST, offered so an
    operator does not read the silence as a broken redirect. If the probe
    cannot run at all, the honest position is to say nothing: a note claiming
    the host has no v6 route, printed because `ip` was missing, sends the
    reader to investigate a routing table that may be perfectly fine.

    Inverting the fallback to False left the whole suite green, so the comment
    saying "unknown: do not manufacture a warning" was the only thing holding
    the direction.
    """

    def setUp(self):
        import cmd_diagnose
        self.mod = cmd_diagnose

    def test_a_probe_that_cannot_run_reads_as_having_a_route(self):
        with mock.patch.object(self.mod.subprocess, "run",
                               side_effect=OSError("no ip binary")):
            self.assertTrue(self.mod._host_has_v6_route())

    def test_a_probe_that_times_out_reads_as_having_a_route(self):
        import subprocess as _sp
        with mock.patch.object(self.mod.subprocess, "run",
                               side_effect=_sp.TimeoutExpired("ip", 5)):
            self.assertTrue(self.mod._host_has_v6_route())

    def test_an_empty_routing_table_reads_as_having_none(self):
        """The real finding still has to register, or the fallback above would
        be indistinguishable from the probe never working."""
        with mock.patch.object(self.mod.subprocess, "run",
                               return_value=SimpleNamespace(returncode=0, stdout="")):
            self.assertFalse(self.mod._host_has_v6_route())

    def test_a_default_route_reads_as_having_one(self):
        with mock.patch.object(
                self.mod.subprocess, "run",
                return_value=SimpleNamespace(
                    returncode=0, stdout="default via fe80::1 dev eth0\n")):
            self.assertTrue(self.mod._host_has_v6_route())


class TestSelfDialCounterIsReported(unittest.TestCase):
    """`diagnose` names the wrong-port self-dial drops (HLD §11).

    The guard drops two different things on two different counters, and this
    is the one that will actually happen: a guest dialling its own listener
    address on a port the inspector does not serve. Inside the guest that is a
    hang, not an error, and every other line of `diagnose` passes — so the
    counter is the only path from the symptom to the cause.
    """

    def setUp(self):
        import cmd_diagnose
        self.mod = cmd_diagnose

    def _line(self, self_dials):
        cfg = SimpleNamespace(
            name="vm1", uid=10001, vm_bridge=None,
            vm_network={"egress": "filtered"},
            config={"vm": {"network": {"egress": "filtered"}}})
        elems = [{"concat": [10001, 80]}, {"concat": [10001, 443]}]
        return self.mod.vm_inspect_check(
            cfg, elements4=elems, elements6=elems, socket_active=True,
            v6_route=True, self_dials=self_dials)

    def test_a_nonzero_count_is_named_with_its_remedy(self):
        name, ok, detail = self._line((12, 720))
        self.assertTrue(ok, detail)
        self.assertIn("12 packet(s)", detail)
        self.assertIn("allow", detail)

    def test_zero_says_nothing(self):
        """The healthy reading is silence, unlike the conntrack figure.

        Conntrack's number is itself the answer to "why do transfers die
        part-way", so it is printed always. A zero here answers nothing and
        would only add noise to every passing line on the host.
        """
        _name, ok, detail = self._line((0, 0))
        self.assertTrue(ok)
        self.assertNotIn("packet(s) dropped dialling", detail)

    def test_the_counter_sums_both_address_families(self):
        """A v6-only self-dial is the same mistake as a v4-only one.

        _inspect_self_counter reads NFT_SET_INSPECT_SELF and its v6 twin and
        adds them, because which family the guest happened to pick is not the
        operator's question -- reporting them separately would ask the reader
        to add two numbers to learn one thing. Dropping the v6 set from that
        loop left the whole suite green, so the summing was asserted by
        nothing: every existing test here injects `self_dials` already summed
        and so runs entirely past the function that does the adding.
        """
        def payload(packets):
            return {"nftables": [{"set": {"elem": [
                {"elem": {"val": {"concat": [10001, "198.18.1.1"]},
                          "counter": {"packets": packets, "bytes": packets * 60}}}
            ]}}]}

        seen = []

        def fake(*args):
            seen.append(args[-1])
            # v4 set silent, v6 set carrying the drops: the arrangement that a
            # v4-only reader reports as a healthy zero.
            return payload(0 if args[-1] == NFT_SET_INSPECT_SELF else 9)

        with mock.patch.object(self.mod, "_nft_json", fake):
            total = self.mod._inspect_self_counter(10001)
        self.assertEqual(total, (9, 540))
        self.assertIn(NFT_SET_INSPECT_SELF6, seen)

    def test_a_family_whose_set_is_unreadable_does_not_zero_the_other(self):
        """One unreadable set is a partial reading, not a contradiction of the
        other -- so it is skipped, and the family that did read still counts."""
        def fake(*args):
            if args[-1] == NFT_SET_INSPECT_SELF:
                return None
            return {"nftables": [{"set": {"elem": [
                {"elem": {"val": {"concat": [10001, "198.18.1.1"]},
                          "counter": {"packets": 4, "bytes": 240}}}]}}]}

        with mock.patch.object(self.mod, "_nft_json", fake):
            self.assertEqual(self.mod._inspect_self_counter(10001), (4, 240))

    def test_an_unreadable_counter_says_nothing_rather_than_zero(self):
        """None must not be rendered as a count.

        A set that could not be read is not a workload with no self-dials, and
        printing "0 packets dropped" for it would state a measurement that was
        never taken.
        """
        _name, ok, detail = self._line(None)
        self.assertTrue(ok)
        self.assertNotIn("packet(s) dropped dialling", detail)

    def test_it_does_not_turn_a_healthy_workload_into_a_failure(self):
        """Advisory, not a verdict.

        A self-dial is an operator's misconfiguration one `allow` line from
        working, not a broken inspector, and failing the check would make
        `diagnose` red on a host whose confinement is doing exactly its job.
        """
        _name, ok, _detail = self._line((4000, 240000))
        self.assertTrue(ok)



class TestRung2Schema(unittest.TestCase):
    """The rung 2 schema: `tls`, `internal`, and `allow` as a reasoned table.

    Nothing here changes runtime behaviour -- T3 arms what `internal` means and
    the inspector is what reads `tls`. What these pin is the set of configs the
    host will accept, which is the only thing standing between an operator's
    stated intent and a system that quietly does something else.
    """

    def _egress(self, net):
        from vm import _validate_egress
        return _validate_egress(net)

    # --- tls ---

    def test_tls_inspect_names_the_rung_rather_than_listing_valid_values(self):
        """The refusal has to say WHEN, not just "no".

        `inspect` is the word for a property -- the connection is decrypted and
        the request is read. A key that accepted it and spliced would be a
        config claiming a property it does not have, and an "unknown value"
        error would read as a typo rather than as work that has not landed.
        """
        errors = self._egress({"hosts": ["github.com"], "tls": "inspect"})
        self.assertTrue(errors)
        message = " ".join(errors)
        self.assertIn("rung 3", message)
        self.assertNotIn("must be one of", message)

    def test_an_unknown_tls_value_still_lists_what_is_valid(self):
        errors = self._egress({"hosts": ["github.com"], "tls": "terminate"})
        self.assertTrue(any("must be one of" in e for e in errors), errors)

    def test_tls_splice_is_accepted_and_is_the_default(self):
        from vm import VM_TLS_DEFAULT, VM_TLS_MODES
        self.assertEqual(VM_TLS_DEFAULT, "splice")
        self.assertIn(VM_TLS_DEFAULT, VM_TLS_MODES)
        self.assertEqual(self._egress({"hosts": ["github.com"],
                                       "tls": "splice"}), [])
        self.assertEqual(self._egress({"hosts": ["github.com"]}), [])

    def test_tls_is_refused_under_open_rather_than_ignored(self):
        errors = self._egress({"egress": "open", "tls": "splice"})
        self.assertTrue(any("no effect" in e and "tls" in e for e in errors),
                        errors)

    def test_tls_is_refused_alongside_a_bridge(self):
        errors = self._egress({"bridge": "br0", "tls": "splice"})
        self.assertTrue(any("no effect with .bridge" in e for e in errors),
                        errors)

    # --- internal ---

    def test_an_internal_host_on_no_list_is_refused(self):
        """The dead entry fails in the direction nobody notices in time.

        An ignored `internal` line produces `403 <host> resolves to an internal
        address` on the one host the entry existed to permit -- which is the
        failure the key was added to remove, arrived at by writing the key.
        """
        errors = self._egress({
            "hosts": ["github.com"],
            "internal": [{"host": "git.local", "reason": "the forge"}]})
        self.assertTrue(any("on no list" in e for e in errors), errors)

    def test_an_internal_host_the_allowlist_covers_is_accepted(self):
        self.assertEqual(self._egress({
            "hosts": ["git.local"],
            "internal": [{"host": "git.local", "reason": "the forge"}]}), [])

    def test_a_wildcard_in_hosts_covers_an_internal_entry(self):
        self.assertEqual(self._egress({
            "hosts": ["*.local"],
            "internal": [{"host": "git.local", "reason": "the forge"}]}), [])

    def test_internal_requires_a_reason(self):
        errors = self._egress({"hosts": ["git.local"],
                               "internal": [{"host": "git.local"}]})
        self.assertTrue(any("reason" in e for e in errors), errors)

    def test_internal_is_refused_under_open(self):
        errors = self._egress({
            "egress": "open",
            "internal": [{"host": "git.local", "reason": "the forge"}]})
        self.assertTrue(any("no effect" in e and "internal" in e
                            for e in errors), errors)

    def test_internal_is_NOT_refused_under_splice(self):
        """The asymmetry a later tidy for symmetry would delete.

        The internal-destination check lives on the inspector's UPSTREAM leg,
        which a spliced connection still has -- so a spliced host can resolve
        into private space and still needs the exemption. If this test ever
        fails because someone made `internal` behave like `policy` will, the
        exemption was taken away from exactly the workloads that need it.
        """
        self.assertEqual(self._egress({
            "hosts": ["git.local"],
            "tls": "splice",
            "internal": [{"host": "git.local", "reason": "the forge"}]}), [])

    # --- allow ---

    def test_a_bare_string_allow_is_refused_by_shape(self):
        """Refused, not accepted for compatibility.

        Premise 3 leaves nothing deployed to migrate, so a second accepted
        shape would exist only to let the two drift. The message names what to
        type, because this is the one error reachable by having written a
        correct config for the previous release.
        """
        errors = self._egress({"allow": ["192.168.0.10:22"]})
        self.assertTrue(errors)
        message = " ".join(errors)
        self.assertIn("[[vm.network.allow]]", message)
        self.assertIn("reason", message)

    def test_allow_requires_a_reason(self):
        errors = self._egress({"allow": [{"address": "192.168.0.10:22"}]})
        self.assertTrue(any("reason" in e for e in errors), errors)

    def test_allow_refuses_a_key_it_does_not_know(self):
        errors = self._egress({"allow": [{"address": "192.168.0.10:22",
                                          "reason": "r", "host": "x"}]})
        self.assertTrue(any("unknown key" in e for e in errors), errors)

    def test_a_network_scalar_below_the_allow_table_names_its_cause(self):
        """The misordering the schema reference's own reading order invites.

        The annotated section documents [[vm.network.allow]] above `hosts`, so
        an operator working down the file writes `hosts` after the allow table
        -- where TOML reads it as part of the allow ENTRY. The key is not
        missing and not misspelled; it belongs to the wrong table, and the file
        looks entirely reasonable. "unknown key" alone sends the reader
        hunting for a typo that is not there.
        """
        errors = self._egress({"allow": [{"address": "192.168.0.10:22",
                                          "reason": "r",
                                          "hosts": ["example.com"]}]})
        message = " ".join(errors)
        self.assertIn("unknown key", message)
        self.assertIn("[vm.network]", message)
        # The remedy has to be "move it up": re-declaring the table lower down
        # is a TOML error, so a reader who guesses that way gets a second
        # failure with a message that names no workloadctl concept at all.
        self.assertIn("ABOVE", message)

    def test_a_genuine_typo_gets_no_misordering_hint(self):
        """The hint is for a key that exists somewhere else, not for any
        unknown key -- otherwise it is noise on every real typo."""
        errors = self._egress({"allow": [{"address": "192.168.0.10:22",
                                          "reason": "r", "adress": "x"}]})
        message = " ".join(errors)
        self.assertIn("unknown key", message)
        self.assertNotIn("ABOVE", message)

    def test_an_allow_on_443_is_refused_with_tls_absent(self):
        """The case the design's own wording would have let through.

        §3 words this as an error "under tls = 'inspect'". The redirect keys on
        the workload uid and the ORIGINAL port and reads nothing else -- not
        `tls`, not the destination -- so the element is intercepted whatever
        `tls` says, and `egress = "filtered"` is the real condition.
        """
        for port in (80, 443):
            with self.subTest(port=port):
                errors = self._egress({
                    "hosts": ["github.com"],
                    "allow": [allow_entry(f"192.168.0.10:{port}")]})
                self.assertTrue(any("redirected" in e for e in errors), errors)

    def test_the_80_443_refusal_reaches_the_name_form_too(self):
        errors = self._egress({"hosts": ["github.com"],
                               "allow": [allow_entry("git.local:443")]})
        self.assertTrue(any("redirected" in e for e in errors), errors)

    def test_an_allow_on_443_is_not_refused_when_nothing_redirects(self):
        # Under 'open' there is no redirect keyed on this uid, so the entry is
        # simply an address and a port.
        self.assertEqual(self._egress({
            "egress": "open",
            "allow": [allow_entry("192.168.0.10:443")]}), [])

    def test_a_name_is_legal_and_is_not_resolved_by_validation(self):
        """Validation runs where the name may not resolve at all.

        An operator edits a config on one host and deploys it to another; a
        resolution failure at edit time would be a refusal that has nothing to
        do with whether the config is right. The arming path resolves.
        """
        self.assertEqual(self._egress({
            "allow": [allow_entry("git.local:2222")]}), [])

    def test_a_name_that_also_appears_in_hosts_is_legal(self):
        """The natural thing to guess wrong.

        Forbidding it would forbid the combination the shipped forge needs:
        HTTPS to the forge through the inspector, git-over-SSH to the same name
        on 2222 through the filter chain. It costs nothing, because the
        redirect is keyed on uid and port alone.
        """
        self.assertEqual(self._egress({
            "hosts": ["git.local"],
            "internal": [{"host": "git.local", "reason": "the forge"}],
            "allow": [allow_entry("git.local:2222")]}), [])

    # --- resolver = "none" ---

    def test_resolver_none_beside_a_host_list_is_an_error(self):
        for net in ({"hosts": ["github.com"]},
                    {"hosts": ["git.local"],
                     "internal": [{"host": "git.local", "reason": "r"}]},
                    {"allow": [allow_entry("git.local:2222")]}):
            with self.subTest(net=sorted(net)):
                errors = self._egress({**net, "resolver": "none"})
                self.assertTrue(any("resolver = 'none'" in e for e in errors),
                                errors)

    def test_resolver_none_with_address_only_allow_is_valid(self):
        """The one coherent configuration, which is why it is not an error.

        A workload whose destinations are all address-keyed reaches them
        through the filter chain without touching the inspector and needs no
        DNS at all. It gets the warning below instead.
        """
        self.assertEqual(self._egress({
            "resolver": "none",
            "allow": [allow_entry("192.168.0.10:22")]}), [])


class TestRung2Warnings(unittest.TestCase):
    """Warnings, not errors -- each is a coherent thing to have meant.

    Which is exactly why silence would be wrong: nothing else in the tool would
    ever report any of them.
    """

    def _warn(self, net):
        from vm import vm_network_warnings
        return vm_network_warnings(net)

    def test_a_registration_domain_wildcard_warns_wherever_it_appears(self):
        for net in ({"hosts": ["*.github.io"]},
                    {"internal": [{"host": "*.pages.dev", "reason": "r"}]}):
            with self.subTest(net=sorted(net)):
                self.assertTrue(any("register a label" in w
                                    for w in self._warn(net)), net)

    def test_it_is_never_an_error(self):
        """The list cannot be exhaustive.

        A stale copy shipped in an RPM that hard-fails a valid config is worse
        than a line of output -- the operator cannot edit the RPM.
        """
        from vm import _validate_egress
        self.assertEqual(_validate_egress({"hosts": ["*.github.io"]}), [])

    def test_a_named_host_under_such_a_parent_does_not_warn(self):
        # `pages.github.io` names one site; only a wildcard lets the guest pick.
        self.assertEqual(self._warn({"hosts": ["pages.github.io"]}), [])

    def test_resolver_none_warns_on_the_configuration_that_is_valid(self):
        warnings = self._warn({"resolver": "none",
                               "allow": [allow_entry("192.168.0.10:22")]})
        self.assertTrue(any("only .allow entries written by address" in w
                            for w in warnings), warnings)

    def test_an_allow_on_53_warns_that_synthesis_is_bypassed(self):
        warnings = self._warn({"allow": [allow_entry("192.168.0.53:53")]})
        self.assertTrue(any("ECHConfig" in w for w in warnings), warnings)

    def test_a_bridged_vm_gets_none_of_them(self):
        # Nothing of ours is in that guest's path; none of these apply.
        self.assertEqual(self._warn({"bridge": "br0",
                                     "hosts": ["*.github.io"]}), [])

    def test_validate_surfaces_them_for_a_vm(self):
        """The channel, not just the function.

        collect_config_warnings returned early for every VM before this rung,
        so a warning that existed and was never reached would look identical to
        one that never fired.
        """
        from validation import collect_config_warnings
        warnings = collect_config_warnings({
            "workload": {"name": "vm1"},
            "vm": {"image": "x", "network": {"hosts": ["*.github.io"]}}})
        self.assertTrue(any("register a label" in w for w in warnings),
                        warnings)


class TestAllowNameResolution(unittest.TestCase):
    """The arming path resolves an `allow` name, once, at start."""

    def _resolve(self, answers):
        return mock.patch(
            "socket.getaddrinfo",
            return_value=[(0, 0, 0, "", (a, 0)) for a in answers])

    def test_every_address_a_name_answers_with_is_armed(self):
        """Not just the first.

        A dual-stack forge answers with both families; arming half of it is the
        works-until-it-doesn't failure the both-families-or-neither rule exists
        to stop -- and the half that survives is the one clients try first.
        """
        with self._resolve(["192.168.0.10", "2001:db8::10"]):
            cmds = vm_filter_commands(
                10001, [allow_entry("git.local:2222")], "add")
        by_set = {c[5]: c[-1] for c in cmds}
        self.assertIn("192.168.0.10 . 2222", by_set[NFT_SET_ALLOW4])
        self.assertIn("2001:db8::10 . 2222", by_set[NFT_SET_ALLOW6])

    def test_a_name_that_does_not_resolve_is_an_error_not_an_empty_arm(self):
        """`allow` is the only path to a named service on an unredirected port.

        An element that failed to arm does not present as a refusal -- it
        presents as the guest hanging against the default-deny drop, with the
        workload started and `diagnose` clean.
        """
        with mock.patch("socket.getaddrinfo", side_effect=OSError("no such host")):
            with self.assertRaises(ValueError) as caught:
                vm_filter_commands(10001, [allow_entry("git.local:2222")], "add")
        self.assertIn("git.local", str(caught.exception))

    def test_a_name_resolving_into_the_listener_plane_is_refused(self):
        """The refusal parse_vm_allow cannot make, because it does not resolve.

        Without this the name form reaches around the address form's refusal
        and arms an accept for another workload's inspector -- which then
        applies that workload's allowlist and re-originates as its uid.
        """
        with self._resolve(["198.18.1.0"]):
            with self.assertRaises(ValueError) as caught:
                vm_filter_commands(10001, [allow_entry("evil.local:2222")], "add")
        self.assertIn("listener range", str(caught.exception))


class TestReservedPlanes(unittest.TestCase):
    """`ports` may not bind any plane this design owns (T2).

    The check was one `in VM_MGMT_NETWORK` with a docstring committing to v4,
    written when there was one plane and it was v4. Two listener planes arrived
    and one of them is v6, so `198.18.1.4:8443:22` validated and 2001:2::/48
    was not checked at all -- and either gap produces a cross-workload denial
    of service on a security control, or one workload receiving another's
    intercepted traffic, with nothing logged for either.
    """

    def _ports(self, spec):
        from vm import validate_vm_network
        return [e for e in validate_vm_network({"egress": "open",
                                                "ports": [spec]})
                if "ports" in e]

    def test_the_list_holds_every_plane_and_both_families(self):
        """Pins the LIST, not its first entry.

        A test naming one plane passes unchanged while a second is added and
        left unenforced, which is exactly how the v6 listener plane went
        unchecked -- so what is asserted here is the membership of the
        collection the check reads.
        """
        from vm import (VM_INSPECT_ADDR6_PREFIX, VM_INSPECT_NETWORK,
                        VM_MGMT_NETWORK, VM_RESERVED_PLANES)
        networks = [p.network for p in VM_RESERVED_PLANES]
        self.assertIn(VM_MGMT_NETWORK, networks)
        self.assertIn(VM_INSPECT_NETWORK, networks)
        self.assertIn(VM_INSPECT_ADDR6_PREFIX, networks)
        self.assertTrue(any(n.version == 6 for n in networks),
                        "a v6 plane exists and must be one of these")

    def test_the_broker_plane_is_the_broker_s_own_listener(self):
        """Cross-file, like tests/test_vm_broker.py and for the same reason.

        The broker is not a range: it is one socket on an address operators
        publish on freely. If the plane and the listener ever disagree, the
        reservation protects an address nothing listens on while the real
        listener is bindable from a config key.
        """
        from vm import (VM_BROKER_LISTEN_ADDR, VM_BROKER_LISTEN_PORT,
                        VM_RESERVED_PLANES)
        scoped = [p for p in VM_RESERVED_PLANES if p.port is not None]
        self.assertEqual(len(scoped), 1, "one port-scoped plane, the broker")
        self.assertEqual(str(scoped[0].network.network_address),
                         VM_BROKER_LISTEN_ADDR)
        self.assertEqual(scoped[0].port, VM_BROKER_LISTEN_PORT)

    def test_each_plane_is_refused(self):
        for spec in ("127.128.0.3:2222:22",
                     "198.18.1.4:8443:22",
                     "[2001:2::c612:100]:8443:22",
                     "127.0.0.1:8081:80"):
            with self.subTest(spec=spec):
                self.assertTrue(self._ports(spec), spec)

    def test_the_v6_listener_plane_is_refused(self):
        """Called out on its own because it was unreachable by construction.

        The address is parsed and compared against a v4 network, which answers
        False for every v6 address -- a check that reads as passing while
        testing nothing.
        """
        errors = self._ports("[2001:2::c612:100]:8443:22")
        self.assertTrue(any("2001:2::/48" in e for e in errors), errors)

    def test_the_message_names_what_would_collide_not_just_the_range(self):
        """Four planes, four sentences.

        A collision with a management address, an inspector, a broker and (from
        T5a) a responder are four different problems with four different
        remedies. One recited range for all of them tells an operator the rule
        and not what they broke.
        """
        mgmt = " ".join(self._ports("127.128.0.3:2222:22"))
        inspect = " ".join(self._ports("198.18.1.4:8443:22"))
        broker = " ".join(self._ports("127.0.0.1:8081:80"))
        self.assertIn("workloadctl exec", mgmt)
        self.assertIn("inspector", inspect)
        self.assertIn("credential", broker)
        self.assertNotEqual(mgmt, inspect)
        self.assertNotEqual(inspect, broker)

    def test_the_broker_refusal_is_scoped_to_its_port(self):
        """127.0.0.1 stays a normal thing to publish on.

        A plane that took the whole address would refuse most of what `ports`
        is for, which is how a reservation gets narrowed back out again.
        """
        self.assertEqual(self._ports("127.0.0.1:8080:80"), [])
        self.assertEqual(self._ports("127.0.0.1:9000:9000"), [])

    def test_ordinary_addresses_are_untouched(self):
        for spec in ("192.168.0.5:8080:80", "[2001:db8::1]:8080:80",
                     "198.19.0.1:8080:80"):
            with self.subTest(spec=spec):
                self.assertEqual(self._ports(spec), [])

    def test_the_helper_answers_none_off_plane_and_the_plane_on_it(self):
        from vm import VM_MGMT_NETWORK, vm_reserved_plane
        self.assertIsNone(vm_reserved_plane("192.168.0.5", 8080))
        self.assertIsNone(vm_reserved_plane("not-an-address", 8080))
        self.assertEqual(vm_reserved_plane("127.128.0.3", 2222).network,
                         VM_MGMT_NETWORK)

    def test_a_v4_plane_never_matches_a_v6_address_and_back(self):
        """Each family is judged against its own plane.

        A comparison that crossed families would raise, or worse, answer False
        for everything and read as a passing test.
        """
        from vm import vm_reserved_plane
        self.assertIsNone(vm_reserved_plane("2001:db8::1", 8443))
        self.assertIsNotNone(vm_reserved_plane("2001:2::c612:100", 8443))
        self.assertIsNotNone(vm_reserved_plane("198.18.1.4", 8443))


class TestInternalOkAccept(unittest.TestCase):
    """The `internal` exemption: the accept ahead of the internal drop (T3).

    A per-workload accept keyed on (uid, address) and carrying NO PORT. The
    missing port is safe only because of the cgroup match on the rule, and the
    ordering is only useful because the accept precedes the drop it excepts --
    so both are asserted, and both would otherwise fail silently.
    """

    @classmethod
    def setUpClass(cls):
        cls.rules = [ln.strip() for ln in SKELETON.read_text().splitlines()
                     if ln.strip().startswith("add rule inet workload_filter "
                                              "output")]

    def _index(self, needle):
        matches = [i for i, r in enumerate(self.rules) if needle in r]
        self.assertEqual(len(matches), 1, f"expected one rule with {needle!r}, "
                                          f"got {len(matches)}")
        return matches[0]

    def test_the_sets_are_declared(self):
        from vm import NFT_SET_INTERNAL_OK4, NFT_SET_INTERNAL_OK6
        text = SKELETON.read_text()
        for name in (NFT_SET_INTERNAL_OK4, NFT_SET_INTERNAL_OK6):
            self.assertIn(f"add set inet workload_filter {name} ", text)

    def test_a_rule_reaches_each_set_by_name(self):
        """Declaration is not wiring.

        A set declared and referenced by nothing is indistinguishable from one
        whose rule drifted to a different name: the skeleton loads, the helper
        arms elements, and the accept never fires.
        """
        from vm import NFT_SET_INTERNAL_OK4, NFT_SET_INTERNAL_OK6
        for name in (NFT_SET_INTERNAL_OK4, NFT_SET_INTERNAL_OK6):
            self.assertTrue(any(f"@{name}" in r for r in self.rules),
                            f"no rule consults @{name}")

    def test_the_accept_carries_the_inspector_cgroup_match(self):
        """The whole of what makes a portless accept safe.

        The set key holds a uid and an address and no port. The uid is shared
        between the guest and the inspector -- which is why the drops here are
        keyed on the cgroup in the first place -- so without this match the
        very same element is an all-ports grant from the GUEST to a LAN
        address. Dropping the match leaves a rule that still parses, still
        matches, and means something else entirely.
        """
        from vm import NFT_SET_INTERNAL_OK4, NFT_SET_INTERNAL_OK6, NFT_SET_EGRESS_CG
        for name in (NFT_SET_INTERNAL_OK4, NFT_SET_INTERNAL_OK6):
            rule = self.rules[self._index(f"@{name}")]
            self.assertIn(f"socket cgroupv2 level 2 @{NFT_SET_EGRESS_CG}", rule)
            self.assertIn("ct direction original", rule)

    def test_the_accept_precedes_the_drop_it_excepts(self):
        """Sequence position, not mere presence.

        An accept after the drop it excepts is a rule that never fires, and
        every other signal -- the set exists, the element is armed, the rule is
        in the chain -- reads exactly as it does when it works.
        """
        from vm import (NFT_SET_INTERNAL4, NFT_SET_INTERNAL6,
                        NFT_SET_INTERNAL_OK4, NFT_SET_INTERNAL_OK6)
        for ok, drop in ((NFT_SET_INTERNAL_OK4, NFT_SET_INTERNAL4),
                         (NFT_SET_INTERNAL_OK6, NFT_SET_INTERNAL6)):
            self.assertLess(self._index(f"@{ok}"), self._index(f"@{drop}"),
                            f"@{ok} must be consulted before @{drop}")

    def test_the_prefixes_match_what_the_skeleton_actually_arms(self):
        """The duplication this refusal rests on.

        VM_INTERNAL_PREFIXES* exist so the arming path can refuse an address
        the drop would never have caught. A range added to the .nft and not
        here makes that refusal wrong in the permissive direction, and nothing
        else would notice.
        """
        from vm import (NFT_SET_INTERNAL4, NFT_SET_INTERNAL6,
                        VM_INTERNAL_PREFIXES4, VM_INTERNAL_PREFIXES6)
        text = SKELETON.read_text()
        for set_name, prefixes in ((NFT_SET_INTERNAL4, VM_INTERNAL_PREFIXES4),
                                   (NFT_SET_INTERNAL6, VM_INTERNAL_PREFIXES6)):
            line = only(self, [ln for ln in text.splitlines()
                               if ln.startswith(f"add element inet "
                                                f"workload_filter {set_name}")],
                        f"{set_name} element line")
            armed = {p.strip() for p in
                     line.split("{", 1)[1].rsplit("}", 1)[0].split(",")}
            self.assertEqual(armed, set(prefixes))


class TestInternalOkElements(unittest.TestCase):
    """The element model and the refusal on the arming path."""

    def _addrs(self, *specs):
        return [ipaddress.ip_address(s) for s in specs]

    def test_elements_split_by_family_and_carry_no_port(self):
        from vm import (NFT_SET_INTERNAL_OK4, NFT_SET_INTERNAL_OK6,
                        vm_internal_ok_elements)
        elements = vm_internal_ok_elements(
            10001, self._addrs("192.168.0.10", "fd00::10"))
        self.assertEqual(elements[NFT_SET_INTERNAL_OK4], ["10001 . 192.168.0.10"])
        self.assertEqual(elements[NFT_SET_INTERNAL_OK6], ["10001 . fd00::10"])

    def test_an_empty_family_produces_no_command(self):
        from vm import NFT_SET_INTERNAL_OK6, vm_internal_ok_commands
        cmds = vm_internal_ok_commands(10001, self._addrs("192.168.0.10"), "add")
        self.assertEqual(len(cmds), 1)
        self.assertNotIn(NFT_SET_INTERNAL_OK6, cmds[0])

    def test_delete_mirrors_add(self):
        from vm import vm_internal_ok_commands
        addrs = self._addrs("192.168.0.10", "fd00::10")
        add = vm_internal_ok_commands(10001, addrs, "add")
        delete = vm_internal_ok_commands(10001, addrs, "delete")
        self.assertEqual([c[-1] for c in add], [c[-1] for c in delete])
        self.assertTrue(all(c[1] == "delete" for c in delete))

    def test_a_public_address_is_refused(self):
        """The mirror of the `allow` listener-range refusal.

        An exemption for an address the drop would never have caught excepts
        nothing and only widens what the inspector may open -- an operator's
        belief about where a name points, written down and wrong.
        """
        from vm import vm_internal_ok_elements
        for spec in ("93.184.216.34", "2606:2800::1"):
            with self.subTest(spec=spec):
                with self.assertRaises(ValueError) as caught:
                    vm_internal_ok_elements(10001, self._addrs(spec))
                self.assertIn("never have fired", str(caught.exception))

    def test_every_private_family_is_accepted(self):
        from vm import vm_internal_ok_elements
        for spec in ("10.0.0.5", "192.168.0.10", "172.16.0.1", "169.254.169.254",
                     "fd00::10", "fe80::1"):
            with self.subTest(spec=spec):
                self.assertTrue(vm_internal_ok_elements(10001, self._addrs(spec)))

    def test_hosts_are_read_shape_tolerantly(self):
        """Validation already refused a malformed entry.

        This runs at VM start, where raising on a typo turns it into a workload
        that does not boot -- long after the error was reportable.
        """
        from vm import vm_internal_hosts
        self.assertEqual(
            vm_internal_hosts({"internal": [{"host": "git.local", "reason": "r"},
                                            {"reason": "no host"},
                                            "a bare string",
                                            {"host": "  "}]}),
            ["git.local"])
        self.assertEqual(vm_internal_hosts({}), [])
        self.assertEqual(vm_internal_hosts({"internal": "not a list"}), [])

    def test_an_unresolvable_internal_name_raises_naming_the_failure(self):
        from vm import vm_internal_resolve
        with mock.patch("socket.getaddrinfo", side_effect=OSError("nope")):
            with self.assertRaises(ValueError) as caught:
                vm_internal_resolve("git.local")
        message = str(caught.exception)
        self.assertIn("git.local", message)
        # It must name the failure the operator will actually see, which is a
        # refusal on the allowlisted host -- not "an element is missing".
        self.assertIn("internal-destination drop", message)
