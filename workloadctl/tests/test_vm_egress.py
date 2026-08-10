#!/usr/bin/env python3
"""The uid-keyed egress layer: skeleton, element model, and unit wiring.

Named test_vm_egress rather than test_..._workload_filter to stay clear of
tests/test_generator_workload_filter.py, which is about the generator's
`--workload` narrowing flag and has nothing to do with nftables.
"""

import json
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from vm import (
    NFT_SET_ALLOW4, NFT_SET_ALLOW6, NFT_SET_FILTERED, NFT_SKELETON,
    nft_drop_counter, nft_set_elements, vm_filter_commands,
    vm_filter_delete_command, vm_owned_elements,
)

SKELETON = Path(__file__).resolve().parent.parent / "nftables" / "workload-filter.nft"


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
        """An unguarded drop would take the whole host off the network."""
        drops = [d for d in self.directives if d.endswith("drop")]
        self.assertTrue(drops, "no drop rule in the skeleton")
        for rule in drops:
            self.assertIn(f"@{NFT_SET_FILTERED}", rule,
                          f"unguarded drop rule: {rule}")

    def test_chain_policy_is_accept(self):
        """So an abandoned table is inert rather than a host-wide outage."""
        chain = [d for d in self.directives if d.startswith("add chain")][0]
        self.assertIn("policy accept", chain)

    def test_ct_mark_rule_is_present_and_non_terminating(self):
        """Design 13 step 2 calls this out: nothing reads the mark until step
        5, so it is written-but-unexercised and has to be covered here.

        It must (a) exist in the always-on skeleton -- a rule added when a
        capture starts could only mark connections opened later, and the
        connection an operator is chasing is already established -- (b) be
        guarded on membership like the drop, and (c) carry no verdict, or it
        would terminate evaluation and the allow/drop rules below would never
        run.
        """
        marks = [d for d in self.directives if "ct mark set" in d]
        self.assertEqual(len(marks), 1, f"expected exactly one mark rule: {marks}")
        rule = marks[0]
        self.assertIn(f"@{NFT_SET_FILTERED}", rule)
        for verdict in ("accept", "drop", "reject", "return", "goto", "jump"):
            self.assertNotIn(
                f" {verdict}", rule,
                f"the mark rule carries a {verdict} verdict, which would stop "
                f"evaluation before the allow and drop rules")

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
        decl = [d for d in self.directives
                if d.startswith("add set") and NFT_SET_FILTERED in d][0]
        self.assertNotIn("ip daddr", decl)
        self.assertNotIn("ip6 daddr", decl)


class TestElementModel(unittest.TestCase):
    def test_uid_alone_goes_in_the_membership_set(self):
        cmds = vm_filter_commands(10001, [], "add")
        self.assertEqual(len(cmds), 1)
        self.assertIn(NFT_SET_FILTERED, cmds[0])
        self.assertIn("{ 10001 }", cmds[0])

    def test_entries_are_split_by_family(self):
        cmds = vm_filter_commands(
            10001, ["192.168.0.10:22", "[2001:db8::1]:443"], "add")
        by_set = {c[5]: c[-1] for c in cmds}
        self.assertIn("192.168.0.10", by_set[NFT_SET_ALLOW4])
        self.assertNotIn("192.168.0.10", by_set[NFT_SET_ALLOW6])
        self.assertIn("2001:db8::1", by_set[NFT_SET_ALLOW6])

    def test_empty_family_produces_no_command(self):
        cmds = vm_filter_commands(10001, ["192.168.0.10:22"], "add")
        self.assertNotIn(NFT_SET_ALLOW6, [c[5] for c in cmds])

    def test_all_entries_for_a_set_go_in_one_transaction(self):
        """One nft invocation is one atomic transaction, so a VM is never
        left in wl_filtered holding only part of its allowlist."""
        cmds = vm_filter_commands(
            10001, ["10.0.0.1:22", "10.0.0.2:22", "10.0.0.3:22"], "add")
        allow4 = [c for c in cmds if c[5] == NFT_SET_ALLOW4]
        self.assertEqual(len(allow4), 1, "one command per set, not per entry")
        for addr in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
            self.assertIn(addr, allow4[0][-1])

    def test_delete_mirrors_add(self):
        args = (10001, ["10.0.0.1:22", "[2001:db8::1]:443"])
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

    def _patch(self, attr, value):
        p = mock.patch.object(self.mod, attr, value)
        p.start()
        self.addCleanup(p.stop)

    def _net(self, **cfg):
        self._patch("network_config", lambda name: cfg)

    def _adds(self):
        return [c for c in self.calls if len(c) > 1 and c[1] == "add"]

    def _deletes(self):
        return [c for c in self.calls if len(c) > 1 and c[1] == "delete"]

    def test_up_applies_the_skeleton_before_touching_elements(self):
        self._net(egress="filtered", allow=["10.0.0.1:22"])
        self.mod.up("vm1")
        self.assertIn("-f", self.calls[0])
        self.assertIn(NFT_SKELETON, self.calls[0])

    def test_up_arms_the_uid_and_its_allowlist(self):
        self._net(egress="filtered", allow=["10.0.0.1:22"])
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
        self._net(egress="filtered", allow=["2.2.2.2:443"])
        self.mod.up("vm1")
        cleared = " ".join(" ".join(c) for c in self._deletes())
        self.assertIn("1.1.1.1", cleared,
                      "the dropped entry was left permitted")

    def test_up_never_clears_a_sibling_workloads_elements(self):
        self.listing = {NFT_SET_ALLOW4: [{"concat": [10002, "9.9.9.9", 22]}]}
        self._net(egress="filtered", allow=["10.0.0.1:22"])
        self.mod.up("vm1")
        self.assertNotIn("9.9.9.9",
                         " ".join(" ".join(c) for c in self._deletes()))

    def test_up_fails_when_the_skeleton_cannot_be_applied(self):
        """A filtered VM that failed to arm must not start: it would run wide
        open while its config claims confinement."""
        self.rc[("/usr/sbin/nft", "-f", NFT_SKELETON)] = 1
        self._net(egress="filtered", allow=["10.0.0.1:22"])
        with self.assertRaises(subprocess.CalledProcessError):
            self.mod.up("vm1")

    def test_up_fails_when_an_element_cannot_be_added(self):
        self.rc[("/usr/sbin/nft", "add", "element")] = 1
        self._net(egress="filtered", allow=["10.0.0.1:22"])
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

    def _config(self, egress="filtered", bridge=None, uid=10001):
        return SimpleNamespace(
            name="vm1", uid=uid, vm_bridge=bridge,
            vm_network={} if egress is None else {"egress": egress})

    def _nft(self, *, table=True, armed=True, allow=(), dropped=None):
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
