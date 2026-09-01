#!/usr/bin/env python3
"""`diagnose`'s reading of the four inspect elements nothing read until rung 5.

`vm_inspect_element_commands` arms SIX objects across two tables. Until this
tier `vm_inspect_check` read two of them -- the DNAT maps -- and a workload
missing an accept element rendered as `egress inspected on both families`,
green, while the guest's HTTP and HTTPS died and its DNS and SSH kept working.
The docstring on the arming helper already named that state; nothing asserted
it was visible.

Two things are held here. The set names this reads must be the ones the arming
helper writes, because a name that stopped matching produces a check that
reports every workload as correctly armed -- there is no runtime signal for a
presence test that never finds anything. And the two KINDS of set must keep
their different verdicts: a missing accept element breaks the guest, a missing
self element only stops a counter being attributable, and one sentence for both
sends an operator to reboot a VM over a lost statistic.
"""

import unittest
import unittest.mock
from types import SimpleNamespace

import cmd_diagnose
from cmd_diagnose import INSPECT_ACCEPT_SETS, INSPECT_SELF_SETS
from vm import (
    NFT_SET_INSPECT_DST, NFT_SET_INSPECT_DST6,
    NFT_SET_INSPECT_SELF, NFT_SET_INSPECT_SELF6,
    NFT_TABLE, vm_inspect_dst_elements, vm_inspect_element_commands,
    vm_inspect_self_elements,
)

UID = 10001


class TestTheSetNamesAreTheOnesArmed(unittest.TestCase):
    """A presence check reading a name nothing arms says "armed" forever.

    There is no counter behind this and no runtime tell: `vm_owned_elements`
    over a set that does not exist and over a set the uid is missing from are
    both empty, and the reader has already turned an unreadable set into
    silence one line earlier. So the only thing that can catch a drifted name
    is this.
    """

    def test_the_accept_sets_are_the_ones_the_arming_helper_writes(self):
        self.assertEqual(set(INSPECT_ACCEPT_SETS),
                         set(vm_inspect_dst_elements(UID)))

    def test_the_self_sets_are_the_ones_the_arming_helper_writes(self):
        self.assertEqual(set(INSPECT_SELF_SETS),
                         set(vm_inspect_self_elements(UID)))

    def test_all_four_live_in_the_filter_table(self):
        """Read out of one `nft list table <NFT_TABLE>`. The two DNAT maps
        live in the proxy table and are read separately; a set that moved
        tables would be looked for in a document that cannot contain it and
        read as unreadable, which this check treats as silence."""
        filter_sets = {
            argv[argv.index("element") + 1 + len(NFT_TABLE.split())]
            for argv in vm_inspect_element_commands(UID, "add")
            if NFT_TABLE.split() == argv[argv.index("element") + 1:
                                         argv.index("element") + 1
                                         + len(NFT_TABLE.split())]}
        self.assertEqual(filter_sets,
                         set(INSPECT_ACCEPT_SETS) | set(INSPECT_SELF_SETS))

    def test_the_four_are_disjoint(self):
        """The two kinds get different verdicts, so a set in both lists would
        produce a failing line and a passing fragment about the same fact."""
        self.assertEqual(set(INSPECT_ACCEPT_SETS) & set(INSPECT_SELF_SETS),
                         set())


class TestTheVerdicts(unittest.TestCase):

    def _line(self, filter_sets):
        cfg = SimpleNamespace(
            name="vm1", uid=UID, vm_bridge=None,
            vm_network={"egress": "filtered"},
            config={"vm": {"network": {"egress": "filtered"}}})
        elems = [{"concat": [UID, 80]}, {"concat": [UID, 443]}]
        return cmd_diagnose.vm_inspect_check(
            cfg, elements4=elems, elements6=elems, socket_active=True,
            v6_route=True, self_dials=None, status=None,
            filter_sets=filter_sets)

    def _armed(self, **overrides):
        sets = {name: True for name in INSPECT_ACCEPT_SETS + INSPECT_SELF_SETS}
        sets.update(overrides)
        return sets

    def test_all_four_armed_passes(self):
        _name, ok, detail = self._line(self._armed())
        self.assertTrue(ok, detail)
        self.assertNotIn("DROPPED", detail)
        self.assertNotIn("not counted against it", detail)

    def test_a_missing_accept_element_fails_the_line(self):
        _name, ok, detail = self._line(
            self._armed(**{NFT_SET_INSPECT_DST: False}))
        self.assertFalse(ok)
        self.assertIn(NFT_SET_INSPECT_DST, detail)

    def test_the_accept_message_says_the_socket_is_not_the_problem(self):
        """The symptom inside the guest is identical to the inspector being
        down. An operator handed the socket's sentence restarts a unit that was
        already listening and watches nothing change."""
        _name, _ok, detail = self._line(
            self._armed(**{NFT_SET_INSPECT_DST6: False}))
        self.assertIn("socket is fine", detail)
        self.assertIn("DROPPED", detail)

    def test_both_missing_accept_sets_are_named(self):
        _name, _ok, detail = self._line(
            self._armed(**{NFT_SET_INSPECT_DST: False,
                           NFT_SET_INSPECT_DST6: False}))
        self.assertIn(NFT_SET_INSPECT_DST, detail)
        self.assertIn(NFT_SET_INSPECT_DST6, detail)

    def test_a_missing_self_element_is_a_fragment_not_a_verdict(self):
        """Nothing the guest does breaks: the drop rule is in the skeleton
        either way. What is lost is the attribution, so the counter's zero
        stops meaning "it never happened"."""
        _name, ok, detail = self._line(
            self._armed(**{NFT_SET_INSPECT_SELF: False}))
        self.assertTrue(ok, detail)
        self.assertIn(NFT_SET_INSPECT_SELF, detail)
        self.assertIn("reads 0", detail)

    def test_an_unreadable_set_says_nothing(self):
        """None is not False. The table's absence is already this check's first
        branch, so a None here is one `nft list set` failing on a table that
        answered a moment ago -- and a diagnostic must not invent a failure out
        of a missing diagnostic."""
        sets = {name: None
                for name in INSPECT_ACCEPT_SETS + INSPECT_SELF_SETS}
        _name, ok, detail = self._line(sets)
        self.assertTrue(ok, detail)
        self.assertNotIn("DROPPED", detail)
        self.assertNotIn("not counted against it", detail)

    def test_an_absent_observation_says_nothing(self):
        """The mapping a real host produces always has all four keys, but a
        caller that passed a partial one must land in the silent branch rather
        than report every unnamed set as missing."""
        _name, ok, detail = self._line({})
        self.assertTrue(ok, detail)
        self.assertNotIn("DROPPED", detail)

    def test_the_accept_verdict_wins_over_the_self_fragment(self):
        """Both wrong at once is one event -- the arming helper runs all six
        argvs or fails the start -- and the accept failure is the one that
        stops the guest working."""
        _name, ok, detail = self._line(
            {name: False
             for name in INSPECT_ACCEPT_SETS + INSPECT_SELF_SETS})
        self.assertFalse(ok)
        self.assertNotIn("reads 0", detail)


class TestTheReadCostsOneExec(unittest.TestCase):
    """Four `nft list set` calls for an answer one `list table` carries.

    This runs on the HEALTHY path of every inspected VM -- before the socket
    check, because a missing accept element and a dead socket look the same
    from inside the guest -- and `doctor` multiplies it by every workload on
    the host. Four execs each was four times the cost of the same answer.

    The two states the caller distinguishes have to survive that change, and
    they are not the same state: a set object the table does not contain is
    unreadable, and stays silence, while a set that exists without this uid in
    it is the failure the check exists to report. Collapsing them would make a
    host whose skeleton never got built report every workload as misarmed.
    """

    def _table(self, *, names, uid=UID):
        sets = [{"set": {"name": name,
                         "elem": [{"concat": [uid, 80]}]}} for name in names]
        return {"nftables": [{"metainfo": {}}] + sets}

    def _read(self, payload):
        calls = []

        def fake(*argv):
            calls.append(argv)
            return payload

        with unittest.mock.patch.object(cmd_diagnose, "_nft_json", fake):
            return cmd_diagnose._inspect_filter_sets(UID), calls

    def test_all_four_come_from_a_single_nft_call(self):
        result, calls = self._read(
            self._table(names=INSPECT_ACCEPT_SETS + INSPECT_SELF_SETS))
        self.assertEqual(len(calls), 1, calls)
        self.assertEqual(calls[0][:2], ("list", "table"))
        self.assertEqual(set(result), set(INSPECT_ACCEPT_SETS
                                          + INSPECT_SELF_SETS))
        self.assertTrue(all(result.values()), result)

    def test_each_name_reads_its_own_set_and_not_the_first_one(self):
        """The whole hazard of reading a table instead of a set: a lookup that
        returned the first set in the document would give all four names the
        membership of one of them, and three checks would be answering about
        somebody else."""
        armed = INSPECT_ACCEPT_SETS[0]
        result, _calls = self._read(self._table(names=[armed]))
        self.assertIs(result[armed], True)
        for name in INSPECT_ACCEPT_SETS[1:] + INSPECT_SELF_SETS:
            self.assertIsNone(result[name], name)

    def test_a_set_present_without_this_uid_is_the_failure_not_silence(self):
        payload = self._table(names=INSPECT_ACCEPT_SETS + INSPECT_SELF_SETS,
                              uid=UID + 7)
        result, _calls = self._read(payload)
        self.assertEqual(set(result.values()), {False})

    def test_an_unreadable_table_says_nothing_about_any_of_them(self):
        """nft absent, or a table under an upgrade. The absence of the table
        itself is already the first branch of vm_inspect_check; inventing four
        failures out of it here would fire on a host mid-upgrade."""
        result, calls = self._read(None)
        self.assertEqual(len(calls), 1)
        self.assertEqual(set(result.values()), {None})

    def test_a_map_is_matched_as_well_as_a_set(self):
        """nft renders a map under "map", not "set". A reader matching only on
        "set" reports a name that moved to a map as unreadable forever."""
        name = INSPECT_ACCEPT_SETS[0]
        found, elements = cmd_diagnose._named_set_elements(
            {"nftables": [{"map": {"name": name, "elem": [1]}}]}, name)
        self.assertTrue(found)
        self.assertEqual(elements, [1])


if __name__ == "__main__":
    unittest.main()
