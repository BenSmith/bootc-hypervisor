#!/usr/bin/env python3
"""The uid planes: one derivation, and a reservation that cannot lag it.

WHY THIS EXISTS

Everything a workload gets of its own -- two loopback listeners, an inspector
address in both families, an nflog group -- is the same three lines:
bounds-check the uid, add its offset into the workload range to a base. Five
copies of that is five places for one of them to be subtly different, and the
copy that matters most is the bounds check: an unchecked offset does not fail,
it produces a plausible value on a plane that is not this workload's.

The reservation is the half that has actually gone wrong. `[vm.network].ports`
may name any bind address, and a plane no reservation covers is not checked at
all -- which is how `ports = ["198.18.1.4:8443:22"]` once validated and
2001:2::/48 was not checked at all by construction. Either gap produces a
cross-workload denial of service on a security control, or one workload
receiving another's intercepted traffic, with nothing logged for either.

So VM_RESERVED_PLANES is DERIVED from VM_UID_PLANES rather than written beside
it, and these are the properties that derivation is supposed to buy:

  * every plane that is an address names a reservation;
  * every plane's WHOLE allocated range is inside it, not just its base;
  * no two planes overlap;
  * no plane straddles a family;
  * and no UidPlane exists in the module that the table forgot.

Parametrised over the table, so a plane added tomorrow is checked by every row
here without anyone remembering to add one.

WHAT IT DOES NOT DO

It does not check that anything BINDS these addresses, or that the nft elements
name them -- tests/test_vm_egress.py and the manual rigs hold that. This is the
arithmetic and the reservation only.
"""

import ipaddress
import unittest

import vm
from vm import UID_MAX, UID_MIN, UidPlane, VM_RESERVED_PLANES, VM_UID_PLANES

SPAN = UID_MAX - UID_MIN


def _addresses(plane):
    """(reservation, first, last) per family this plane allocates in."""
    out = []
    if plane.reservation is not None:
        out.append((plane.reservation,
                    ipaddress.ip_address(plane.base),
                    ipaddress.ip_address(plane.base + SPAN)))
    if plane.reservation6 is not None:
        prefix = int(plane.reservation6.network.network_address)
        out.append((plane.reservation6,
                    ipaddress.ip_address(prefix | plane.base),
                    ipaddress.ip_address(prefix | (plane.base + SPAN))))
    return out


class TestTheTableIsComplete(unittest.TestCase):

    def test_the_table_was_found(self):
        """Guards the guard: an empty table passes every parametrised row
        below without running a single assertion."""
        self.assertGreaterEqual(len(VM_UID_PLANES), 5, VM_UID_PLANES)

    def test_no_plane_is_defined_and_left_out(self):
        """The rows sit beside the constants they derive from, so the tuple is
        assembled by hand and a plane can be written and never joined to it.
        A plane outside the table derives fine and is reserved by nothing.
        """
        defined = {v for v in vars(vm).values() if isinstance(v, UidPlane)}
        self.assertEqual(defined, set(VM_UID_PLANES),
                         "UidPlane(s) defined in lib/vm.py but absent from "
                         "VM_UID_PLANES: "
                         f"{sorted(p.noun for p in defined - set(VM_UID_PLANES))}")

    def test_every_plane_has_a_distinct_noun(self):
        """The noun is the whole of the out-of-range message, so two planes
        sharing one make the error name the wrong plane."""
        nouns = [p.noun for p in VM_UID_PLANES]
        self.assertEqual(sorted(nouns), sorted(set(nouns)))


class TestEveryPlaneIsReserved(unittest.TestCase):

    def test_every_address_plane_names_a_reservation(self):
        """The nflog group is the one plane that legitimately names none -- a
        group is not an address, so there is nothing `ports` could bind."""
        unreserved = [p.noun for p in VM_UID_PLANES
                      if p.reservation is None and p.reservation6 is None]
        self.assertEqual(unreserved, ["nflog group"], unreserved)

    def test_the_whole_allocated_range_is_inside_the_reservation(self):
        """Not just the base. A reservation that covers the first workload and
        not the 42,949th is a guard that passes on every host with few
        workloads and fails on the one that has many."""
        for plane in VM_UID_PLANES:
            for reservation, first, last in _addresses(plane):
                with self.subTest(plane=plane.noun, family=first.version):
                    self.assertIn(first, reservation.network)
                    self.assertIn(last, reservation.network)

    def test_no_two_planes_overlap(self):
        """Two planes sharing an address is one workload's broker answering
        where another workload's sshd belongs, decided by start order."""
        seen = []
        for plane in VM_UID_PLANES:
            for _, first, last in _addresses(plane):
                for other_noun, other_first, other_last in seen:
                    if first.version != other_first.version:
                        continue
                    with self.subTest(a=plane.noun, b=other_noun):
                        self.assertTrue(
                            last < other_first or first > other_last,
                            f"{plane.noun} ({first}-{last}) overlaps "
                            f"{other_noun} ({other_first}-{other_last})")
                seen.append((plane.noun, first, last))

    def test_no_plane_straddles_a_family(self):
        for plane in VM_UID_PLANES:
            if plane.reservation is not None:
                self.assertEqual(plane.reservation.network.version, 4,
                                 plane.noun)
            if plane.reservation6 is not None:
                self.assertEqual(plane.reservation6.network.version, 6,
                                 plane.noun)

    def test_a_plane_in_both_families_carries_the_same_number(self):
        """The v6 address is the v4 OR-ed into the prefix, which is what makes
        an address in a log or an .nft element say which workload it is."""
        for plane in VM_UID_PLANES:
            if plane.reservation6 is None:
                continue
            v4, v6 = (a for _, a, _ in _addresses(plane))
            self.assertEqual(int(v6) & 0xFFFFFFFF, int(v4), plane.noun)


class TestTheReservedListIsDerived(unittest.TestCase):

    def test_it_holds_every_reservation_the_planes_name(self):
        named = {r for p in VM_UID_PLANES
                 for r in (p.reservation, p.reservation6) if r}
        self.assertEqual({p.network for p in VM_RESERVED_PLANES},
                         {r.network for r in named})

    def test_a_shared_reservation_appears_once(self):
        """Three planes hang off the /9. The management addresses state it;
        the broker and the responder inherit it."""
        networks = [p.network for p in VM_RESERVED_PLANES]
        self.assertEqual(len(networks), len(set(networks)), networks)

    def test_both_families_are_present(self):
        versions = {p.network.version for p in VM_RESERVED_PLANES}
        self.assertEqual(versions, {4, 6})

    def test_the_loopback_planes_are_covered_without_entries_of_their_own(self):
        """The property the /9 exists for, asserted through the lookup rather
        than the list: "the entry is gone" and "the reservation is gone" are
        the two things a list-reading test cannot tell apart.
        """
        for uid in (UID_MIN, UID_MIN + 3, UID_MAX):
            for address in (vm.vm_broker_listen_address(uid),
                            vm.vm_resolve_address(uid),
                            vm.vm_management_address(uid)):
                with self.subTest(address=address):
                    self.assertEqual(
                        vm.vm_reserved_plane(address, 8080).network,
                        vm.VM_MGMT_NETWORK)


class TestTheDerivation(unittest.TestCase):

    FUNCTIONS = {
        "management address": vm.vm_management_address,
        "broker listen address": vm.vm_broker_listen_address,
        "responder address": vm.vm_resolve_address,
        "nflog group": vm.vm_nflog_group,
    }

    def test_each_function_agrees_with_its_row(self):
        by_noun = {p.noun: p for p in VM_UID_PLANES}
        for noun, function in self.FUNCTIONS.items():
            plane = by_noun[noun]
            for uid in (UID_MIN, UID_MIN + 3, UID_MAX):
                with self.subTest(noun=noun, uid=uid):
                    expected = plane.base + (uid - UID_MIN)
                    got = function(uid)
                    if isinstance(got, str):
                        got = int(ipaddress.ip_address(got))
                    self.assertEqual(got, expected)

    def test_the_inspector_row_drives_both_families(self):
        plane = {p.noun: p for p in VM_UID_PLANES}["inspector address"]
        for uid in (UID_MIN, UID_MIN + 3, UID_MAX):
            address = vm.vm_inspect_address(uid)
            self.assertEqual(int(ipaddress.ip_address(address.v4)),
                             plane.base + (uid - UID_MIN))
            self.assertEqual(int(ipaddress.ip_address(address.v6))
                             & 0xFFFFFFFF,
                             plane.base + (uid - UID_MIN))

    def test_every_plane_refuses_a_uid_outside_the_range(self):
        """One raise for five planes, so this is the only place it is checked
        -- and an unchecked offset does not fail, it lands the caller on a
        plane belonging to nobody."""
        for plane in VM_UID_PLANES:
            for uid in (UID_MIN - 1, UID_MAX + 1, 0, -1):
                with self.subTest(plane=plane.noun, uid=uid):
                    with self.assertRaises(ValueError) as caught:
                        vm._uid_plane_value(plane, uid)
                    self.assertIn(plane.noun, str(caught.exception))
                    self.assertIn(str(uid), str(caught.exception))

    def test_the_bounds_are_inclusive_at_both_ends(self):
        """UID_MAX is allocatable, so a `>=` here would strand the last
        workload the allocator can hand out."""
        for plane in VM_UID_PLANES:
            with self.subTest(plane=plane.noun):
                self.assertEqual(vm._uid_plane_value(plane, UID_MIN),
                                 plane.base)
                self.assertEqual(vm._uid_plane_value(plane, UID_MAX),
                                 plane.base + SPAN)


if __name__ == "__main__":
    unittest.main()
