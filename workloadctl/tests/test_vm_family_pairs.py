#!/usr/bin/env python3
"""Every address-bearing nftables object exists twice, and Python writes it once.

In the inet family `ip daddr` matches v4 only and `ip6 daddr` v6 only, so each
of these sets and maps is really two. The RULES must be written twice. The
builders must not be, and when they were, the v6 half went missing in both of
the ways it can:

  * omitted entirely -- the reserved-range check was `in MGMT_NETWORK` with
    a docstring committing to v4, so 2001:2::/48 was not checked at all and
    `ports = ["198.18.1.4:8443:22"]` validated (TestReservedRanges);
  * or present and wrong -- an element in the other family's set matches
    nothing, and a set nothing ever matches looks exactly like a set nothing
    dialled. There is no error and no counter to read.

So the two names are one FamilyPair value and the builders fill both halves
from it. This file asserts the property that shape is supposed to buy, rather
than the shape: that no v6 object is orphaned, that the uid-derived builders
emit both families, and that each family's elements carry that family's
address.

WHAT IT DOES NOT DO

It does not check the .nft skeleton's rules -- those genuinely are written
twice, and test_vm_egress.py is what holds them to each other. This file is
about the Python that arms them.
"""

import ast
import ipaddress
import unittest
from pathlib import Path

import nft_constants
import vm
import vm_network_config
import workload_addr
from nft_constants import (FamilyPair, NFT_PAIR_ALLOW, NFT_PAIR_INSPECT_DST,
                           NFT_PAIR_INSPECT_LIVE, NFT_PAIR_INSPECT_MAP,
                           NFT_PAIR_INSPECT_SELF, NFT_PAIR_INTERNAL,
                           NFT_PAIR_INTERNAL_OK, NFT_SET_FILTERED)

UID = 10004


def _derived():
    """The objects derived from a uid alone, DISCOVERED rather than listed.

    Not operator input: there is no such thing as a workload with a v4
    inspector and no v6 one, so unlike the allowlist these must fill BOTH
    halves unconditionally.

    This was a hand-written tuple, and that was the one gap in a file built to
    close exactly this class of gap. Every assertion below iterates it, so a
    builder added tomorrow and forgotten here would be guarded by none of
    them -- and what it would be unguarded against is the silent failure in
    the module docstring: an element in the other family's set matches
    nothing, and nothing reports a set that never matched. A list of the
    things to check, maintained by hand, cannot see the thing nobody added.

    So the table IS the call sites: every function in vm.py that calls
    both_families, paired with the FamilyPair it hands over. Adding a builder
    enrolls it; it cannot be added and forgotten.
    """
    source = ast.parse(Path(vm.__file__).read_text())
    found = []
    for node in ast.walk(source):
        if not isinstance(node, ast.FunctionDef):
            continue
        for call in ast.walk(node):
            if not (isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name)
                    and call.func.id == "both_families"):
                continue
            pair = call.args[0]
            # A builder that computed its pair instead of naming a constant
            # would defeat the pairing here, so refuse it rather than skip it.
            assert isinstance(pair, ast.Name), (
                f"{node.name} does not name its pair directly")
            found.append((getattr(nft_constants, pair.id),
                          getattr(vm, node.name)))
    return tuple(found)


DERIVED = _derived()


def _entry(port):
    return vm_network_config.VmAllowEntry(address=None, host=None, port=port,
                                          reason="test")


def _pairs():
    return [v for v in vars(vm).values() if isinstance(v, FamilyPair)]


class TestThePairTable(unittest.TestCase):

    def test_pairs_were_found(self):
        """Guards the guard: an empty sweep passes every test below."""
        self.assertGreaterEqual(len(_pairs()), 6, _pairs())

    def test_every_v6_object_is_half_of_a_pair(self):
        """The orphan is the whole failure mode.

        A v6 set constant that no pair names is a v6 object some builder
        either fills by hand or does not fill at all, and neither shows up as
        an error at runtime.
        """
        v6_halves = {p.v6 for p in _pairs()}
        orphans = sorted(
            name for name, value in vars(vm).items()
            if name.startswith(("NFT_SET_", "NFT_MAP_"))
            and isinstance(value, str) and value.endswith("6")
            and value not in v6_halves)
        self.assertEqual(orphans, [], f"v6 objects in no FamilyPair: {orphans}")

    def test_every_v4_half_is_the_v6_half_without_the_six(self):
        """Catches a pair built from two unrelated objects.

        A transposed pair -- v4 of one object with v6 of another -- arms one
        family of each and reads as fully armed.
        """
        for pair in _pairs():
            with self.subTest(pair=pair):
                self.assertTrue(pair.v6.endswith("6"), pair)
                self.assertEqual(pair.v6.rstrip("6").rstrip("4"),
                                 pair.v4.rstrip("4"), pair)

    def test_no_object_appears_in_two_pairs(self):
        halves = [n for p in _pairs() for n in (p.v4, p.v6)]
        self.assertEqual(sorted(halves), sorted(set(halves)), halves)

    def test_of_selects_by_version(self):
        pair = FamilyPair("a4", "a6")
        self.assertEqual(pair.of(4), "a4")
        self.assertEqual(pair.of(6), "a6")


class TestTheDerivedBuildersFillBothHalves(unittest.TestCase):

    def test_the_table_is_every_call_site(self):
        """The guard on the guard: discovery actually found them.

        An empty or short table makes every other test in this class vacuous
        while they all report green -- the failure mode a hand-written list
        has permanently and a bad discovery has once.
        """
        self.assertTrue(DERIVED, "no uid-derived builders discovered")
        calls = Path(vm.__file__).read_text().count("both_families(")
        self.assertEqual(len(DERIVED), calls)
        self.assertEqual(len({build for _, build in DERIVED}), len(DERIVED))
        for pair, _ in DERIVED:
            self.assertIsInstance(pair, FamilyPair)

    def test_each_builder_returns_exactly_its_pair(self):
        for pair, build in DERIVED:
            with self.subTest(build=build.__name__):
                self.assertEqual(set(build(UID)), {pair.v4, pair.v6})

    def test_neither_half_is_empty(self):
        """An empty half is not a smaller ruleset, it is an unarmed family.

        `nft add element ... { }` is an error, so the arming path fails the
        start -- but a builder that returned an empty half would fail it for
        every workload, which is why this is asserted here rather than left to
        be discovered on a host.
        """
        for pair, build in DERIVED:
            for name, entries in build(UID).items():
                with self.subTest(build=build.__name__, set=name):
                    self.assertTrue(entries)

    def test_each_half_carries_its_own_family_s_address(self):
        """The silent failure: right element, wrong set.

        An element in the other family's set never matches, and nothing
        anywhere reports a set that is never matched.
        """
        addr = workload_addr.inspect_address(UID)
        for pair, build in DERIVED:
            elements = build(UID)
            with self.subTest(build=build.__name__):
                v4 = " ".join(elements[pair.v4])
                v6 = " ".join(elements[pair.v6])
                self.assertIn(str(addr.v4), v4)
                self.assertNotIn(str(addr.v6), v4)
                self.assertIn(str(addr.v6), v6)
                # The v4 address is a substring of nothing in the v6 form:
                # 2001:2::c612:104 is the same number, written differently.
                self.assertNotIn(str(addr.v4), v6)

    def test_no_builder_names_a_family_of_its_own(self):
        """The shape, asserted structurally, because it is what makes the
        rest of this file hold for a builder written tomorrow.

        A builder that reads `.v4` off the address, or names a single-family
        constant, is back to writing the split by hand -- and the tests above
        would still pass for it while it stayed correct.
        """
        source = ast.parse(Path(vm.__file__).read_text())
        by_name = {n.name: n for n in ast.walk(source)
                   if isinstance(n, ast.FunctionDef)}
        for _, build in DERIVED:
            node = by_name[build.__name__]
            with self.subTest(build=build.__name__):
                attrs = sorted({n.attr for n in ast.walk(node)
                                if isinstance(n, ast.Attribute)
                                and n.attr in ("v4", "v6")})
                self.assertEqual(attrs, [], f"names a family directly: {attrs}")
                named = sorted({n.id for n in ast.walk(node)
                                if isinstance(n, ast.Name)
                                and n.id.startswith(("NFT_SET_", "NFT_MAP_"))})
                self.assertEqual(named, [],
                                 f"names a single-family object: {named}")


class TestSplitByFamily(unittest.TestCase):
    """The operator-input half: allow entries and internal exemptions."""

    def test_each_address_lands_in_its_own_family(self):
        v4 = ipaddress.ip_address("192.0.2.1")
        v6 = ipaddress.ip_address("2001:db8::1")
        got = nft_constants.split_by_family(FamilyPair("a4", "a6"),
                                  [(v4, "x"), (v6, "y"), (v4, "z")])
        self.assertEqual(got, {"a4": ["x", "z"], "a6": ["y"]})

    def test_an_empty_half_is_dropped_not_emitted(self):
        """`nft add element ... { }` is an error, not a no-op, so a half with
        nothing in it must not become a command."""
        v4 = ipaddress.ip_address("192.0.2.1")
        self.assertEqual(
            nft_constants.split_by_family(FamilyPair("a4", "a6"),
                                           [(v4, "x")]),
            {"a4": ["x"]})
        self.assertEqual(
            nft_constants.split_by_family(FamilyPair("a4", "a6"), []), {})

    def test_the_allowlist_splits_and_keeps_the_family_agnostic_set(self):
        """wl_filtered carries the bare uid and belongs to neither family:
        "is this workload under policy at all?" has one answer."""
        elements = vm.filter_elements(
            UID, [], resolved=[
                (_entry(443), [ipaddress.ip_address("93.184.216.34"),
                               ipaddress.ip_address("2606:2800::1")])])
        self.assertEqual(elements[NFT_SET_FILTERED], [str(UID)])
        self.assertIn("93.184.216.34", " ".join(elements[NFT_PAIR_ALLOW.v4]))
        self.assertIn("2606:2800::1", " ".join(elements[NFT_PAIR_ALLOW.v6]))

    def test_a_v4_only_allowlist_emits_no_v6_set(self):
        elements = vm.filter_elements(
            UID, [], resolved=[
                (_entry(443), [ipaddress.ip_address("93.184.216.34")])])
        self.assertNotIn(NFT_PAIR_ALLOW.v6, elements)

    def test_internal_exemptions_split_the_same_way(self):
        got = vm.internal_ok_elements(
            UID, [ipaddress.ip_address("192.168.0.5"),
                  ipaddress.ip_address("fd00::1")])
        self.assertEqual(set(got), {NFT_PAIR_INTERNAL_OK.v4,
                                    NFT_PAIR_INTERNAL_OK.v6})
        self.assertEqual(got[NFT_PAIR_INTERNAL_OK.v6], [f"{UID} . fd00::1"])

    def test_the_dump_reads_both_exemption_sets(self):
        """The teardown path is the one that reads them back, and a dump of
        one family purges one family."""
        named = [argv[-1] for argv in vm.internal_ok_list_commands()]
        self.assertEqual(named, [NFT_PAIR_INTERNAL_OK.v4,
                                 NFT_PAIR_INTERNAL_OK.v6])


class TestTheDropRangesArePaired(unittest.TestCase):

    def test_the_internal_drop_sets_are_a_pair(self):
        """Nothing in Python arms these -- the skeleton holds the elements --
        but diagnose reads both to tell a loaded guard from an older table,
        and reading one family answers for one family."""
        self.assertEqual(
            NFT_PAIR_INTERNAL,
            FamilyPair(nft_constants.NFT_SET_INTERNAL4,
                       nft_constants.NFT_SET_INTERNAL6))


if __name__ == "__main__":
    unittest.main()
