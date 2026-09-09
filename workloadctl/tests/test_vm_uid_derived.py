#!/usr/bin/env python3
"""The uid rows: one derivation, and a reservation that cannot lag it.

WHY THIS EXISTS

Everything a workload gets of its own -- two loopback listeners, an inspector
address in both families, an nflog group -- is the same three lines:
bounds-check the uid, add its offset into the workload range to a base. Five
copies of that is five places for one of them to be subtly different, and the
copy that matters most is the bounds check: an unchecked offset does not fail,
it produces a plausible value on a row that is not this workload's.

The reservation is the half that has actually gone wrong. `[vm.network].ports`
may name any bind address, and a row no reservation covers is not checked at
all -- which is how `ports = ["198.18.1.4:8443:22"]` once validated and
2001:2::/48 was not checked at all by construction. Either gap produces a
cross-workload denial of service on a security control, or one workload
receiving another's intercepted traffic, with nothing logged for either.

So VM_RESERVED_RANGES is DERIVED from VM_UID_DERIVED rather than written beside
it, and these are the properties that derivation is supposed to buy:

  * every row that is an address names a reservation;
  * every row's WHOLE allocated range is inside it, not just its base;
  * no two rows overlap;
  * no row straddles a family;
  * and no UidDerived exists in the module that the table forgot.

Parametrised over the table, so a row added tomorrow is checked by every
here without anyone remembering to add one.

WHAT IT DOES NOT DO

It does not check that anything BINDS these addresses, or that the nft elements
name them -- tests/test_vm_egress.py and the manual rigs hold that. This is the
arithmetic and the reservation only.
"""

import ast
import importlib
import ipaddress
import unittest
from pathlib import Path

import vm
import workload_addr
from workload_addr import (UID_MAX, UID_MIN, UidDerived, VM_RESERVED_RANGES,
                           VM_UID_DERIVED)

LIB = Path(vm.__file__).resolve().parent

SPAN = UID_MAX - UID_MIN


def _addresses(row):
    """(reservation, first, last) per family this row allocates in."""
    out = []
    if row.reservation is not None:
        out.append((row.reservation,
                    ipaddress.ip_address(row.base),
                    ipaddress.ip_address(row.base + SPAN)))
    if row.reservation6 is not None:
        prefix = int(row.reservation6.network.network_address)
        out.append((row.reservation6,
                    ipaddress.ip_address(prefix | row.base),
                    ipaddress.ip_address(prefix | (row.base + SPAN))))
    return out


class TestTheTableIsComplete(unittest.TestCase):

    def test_the_table_was_found(self):
        """Guards the guard: an empty table passes every parametrised row
        below without running a single assertion."""
        self.assertGreaterEqual(len(VM_UID_DERIVED), 5, VM_UID_DERIVED)

    def test_no_row_is_defined_and_left_out(self):
        """The rows sit beside the constants they derive from, so the tuple is
        assembled by hand and a row can be written and never joined to it.
        A row outside the table derives fine and is reserved by nothing.

        Swept over EVERY lib module, not over vm. This test read `vars(vm)`
        while the rows lived in vm.py, and the moment they moved to workload_addr.py
        it passed over an orphan row -- vars() sees what a module imported, so
        a row defined in the new module and re-exported from neither the table
        nor vm was invisible to it. Measured, not reasoned: a deliberate
        orphan was added to workload_addr.py and this class stayed green.
        """
        defined = {}
        for path in sorted(LIB.glob("*.py")):
            if path.stem == "_version":
                continue
            module = importlib.import_module(path.stem)
            for name, value in vars(module).items():
                if isinstance(value, UidDerived):
                    defined.setdefault(value, f"{path.name}:{name}")
        orphans = sorted(where for row, where in defined.items()
                         if row not in VM_UID_DERIVED)
        self.assertEqual(orphans, [],
                         f"UidDerived(s) defined in lib/ but absent from "
                         f"VM_UID_DERIVED: {orphans}")

    def test_the_sweep_reaches_more_than_one_module(self):
        """Guards the guard above, whose whole failure was reading one module.

        An import that raised, or a glob that stopped matching, would make it
        pass over nothing -- and a green run over zero modules looks exactly
        like a green run over all of them.
        """
        modules = [p.stem for p in LIB.glob("*.py")]
        self.assertIn("vm", modules)
        self.assertIn("workload_addr", modules)
        self.assertGreater(len(modules), 30, modules)

    def test_the_rows_are_defined_where_the_table_is_assembled_from(self):
        """Every row is defined in workload_addr.py, and none in vm.py.

        Not a style rule. vm re-exports them, so `vm.VM_UID_MGMT` resolves
        either way and no import would break -- what breaks is the reader's
        one place to look, and this file's first version proved that a row
        outside the reader's one place is a row outside the table too.
        """
        source = ast.parse((LIB / "workload_addr.py").read_text())
        assigned = {t.id for n in ast.walk(source)
                    if isinstance(n, ast.Assign)
                    for t in n.targets if isinstance(t, ast.Name)}
        for row in VM_UID_DERIVED:
            with self.subTest(row=row.noun):
                names = [n for n in assigned
                         if getattr(workload_addr, n, None) is row]
                self.assertTrue(names, f"{row.noun} is not defined in workload_addr.py")

    def test_every_row_has_a_distinct_noun(self):
        """The noun is the whole of the out-of-range message, so two rows
        sharing one make the error name the wrong row."""
        nouns = [p.noun for p in VM_UID_DERIVED]
        self.assertEqual(sorted(nouns), sorted(set(nouns)))


class TestEveryAddressIsReserved(unittest.TestCase):

    def test_every_address_row_names_a_reservation(self):
        """The nflog group is the one row that legitimately names none -- a
        group is not an address, so there is nothing `ports` could bind."""
        unreserved = [p.noun for p in VM_UID_DERIVED
                      if p.reservation is None and p.reservation6 is None]
        self.assertEqual(unreserved, ["nflog group"], unreserved)

    def test_the_whole_allocated_range_is_inside_the_reservation(self):
        """Not just the base. A reservation that covers the first workload and
        not the 42,949th is a guard that passes on every host with few
        workloads and fails on the one that has many."""
        for row in VM_UID_DERIVED:
            for reservation, first, last in _addresses(row):
                with self.subTest(row=row.noun, family=first.version):
                    self.assertIn(first, reservation.network)
                    self.assertIn(last, reservation.network)

    def test_no_two_rows_overlap(self):
        """Two rows sharing an address is one workload's broker answering
        where another workload's sshd belongs, decided by start order."""
        seen = []
        for row in VM_UID_DERIVED:
            for _, first, last in _addresses(row):
                for other_noun, other_first, other_last in seen:
                    if first.version != other_first.version:
                        continue
                    with self.subTest(a=row.noun, b=other_noun):
                        self.assertTrue(
                            last < other_first or first > other_last,
                            f"{row.noun} ({first}-{last}) overlaps "
                            f"{other_noun} ({other_first}-{other_last})")
                seen.append((row.noun, first, last))

    def test_no_row_straddles_a_family(self):
        for row in VM_UID_DERIVED:
            if row.reservation is not None:
                self.assertEqual(row.reservation.network.version, 4,
                                 row.noun)
            if row.reservation6 is not None:
                self.assertEqual(row.reservation6.network.version, 6,
                                 row.noun)

    def test_a_row_in_both_families_carries_the_same_number(self):
        """The v6 address is the v4 OR-ed into the prefix, which is what makes
        an address in a log or an .nft element say which workload it is."""
        for row in VM_UID_DERIVED:
            if row.reservation6 is None:
                continue
            v4, v6 = (a for _, a, _ in _addresses(row))
            self.assertEqual(int(v6) & 0xFFFFFFFF, int(v4), row.noun)


class TestTheReservedListIsDerived(unittest.TestCase):

    def test_it_holds_every_reservation_the_rows_name(self):
        named = {r for p in VM_UID_DERIVED
                 for r in (p.reservation, p.reservation6) if r}
        self.assertEqual({p.network for p in VM_RESERVED_RANGES},
                         {r.network for r in named})

    def test_a_shared_reservation_appears_once(self):
        """Three rows hang off the /9. The management addresses state it;
        the broker and the responder inherit it."""
        networks = [p.network for p in VM_RESERVED_RANGES]
        self.assertEqual(len(networks), len(set(networks)), networks)

    def test_both_families_are_present(self):
        versions = {p.network.version for p in VM_RESERVED_RANGES}
        self.assertEqual(versions, {4, 6})

    def test_the_loopback_rows_are_covered_without_entries_of_their_own(self):
        """The property the /9 exists for, asserted through the lookup rather
        than the list: "the entry is gone" and "the reservation is gone" are
        the two things a list-reading test cannot tell apart.
        """
        for uid in (UID_MIN, UID_MIN + 3, UID_MAX):
            for address in (workload_addr.vm_broker_listen_address(uid),
                            workload_addr.vm_resolve_address(uid),
                            workload_addr.vm_management_address(uid)):
                with self.subTest(address=address):
                    self.assertEqual(
                        workload_addr.vm_reserved_range(address, 8080).network,
                        workload_addr.VM_MGMT_NETWORK)


class TestTheDerivation(unittest.TestCase):

    FUNCTIONS = {
        "management address": workload_addr.vm_management_address,
        "broker listen address": workload_addr.vm_broker_listen_address,
        "responder address": workload_addr.vm_resolve_address,
        "nflog group": workload_addr.vm_nflog_group,
    }

    def test_each_function_agrees_with_its_row(self):
        by_noun = {p.noun: p for p in VM_UID_DERIVED}
        for noun, function in self.FUNCTIONS.items():
            row = by_noun[noun]
            for uid in (UID_MIN, UID_MIN + 3, UID_MAX):
                with self.subTest(noun=noun, uid=uid):
                    expected = row.base + (uid - UID_MIN)
                    got = function(uid)
                    if isinstance(got, str):
                        got = int(ipaddress.ip_address(got))
                    self.assertEqual(got, expected)

    def test_the_inspector_row_drives_both_families(self):
        row = {p.noun: p for p in VM_UID_DERIVED}["inspector address"]
        for uid in (UID_MIN, UID_MIN + 3, UID_MAX):
            address = workload_addr.vm_inspect_address(uid)
            self.assertEqual(int(ipaddress.ip_address(address.v4)),
                             row.base + (uid - UID_MIN))
            self.assertEqual(int(ipaddress.ip_address(address.v6))
                             & 0xFFFFFFFF,
                             row.base + (uid - UID_MIN))

    def test_every_row_refuses_a_uid_outside_the_range(self):
        """One raise for five rows, so this is the only place it is checked
        -- and an unchecked offset does not fail, it lands the caller on a
        row belonging to nobody."""
        for row in VM_UID_DERIVED:
            for uid in (UID_MIN - 1, UID_MAX + 1, 0, -1):
                with self.subTest(row=row.noun, uid=uid):
                    with self.assertRaises(ValueError) as caught:
                        workload_addr._uid_derived_value(row, uid)
                    self.assertIn(row.noun, str(caught.exception))
                    self.assertIn(str(uid), str(caught.exception))

    def test_the_bounds_are_inclusive_at_both_ends(self):
        """UID_MAX is allocatable, so a `>=` here would strand the last
        workload the allocator can hand out."""
        for row in VM_UID_DERIVED:
            with self.subTest(row=row.noun):
                self.assertEqual(
                    workload_addr._uid_derived_value(row, UID_MIN),
                    row.base)
                self.assertEqual(
                    workload_addr._uid_derived_value(row, UID_MAX),
                    row.base + SPAN)


if __name__ == "__main__":
    unittest.main()
