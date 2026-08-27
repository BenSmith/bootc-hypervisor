"""`diagnose`'s reading of the two figures rung 4's policy work landed.

The inspector counts a name-to-`Host` binding rejection and a host that turned
out not to speak HTTP, and until this tier nothing printed either. A figure
nobody prints is a figure nobody has: the whole value of both is an operator's
next move, and in the non-HTTP case the count is the ONLY place that list of
splice candidates exists, since whether a host speaks HTTP over 443 is not
knowable from the file.

Two things are held here. The keys `lib/vm.py` restates must be the listener's
own strings -- `lib/` cannot import an extension-less entrypoint, so the reader
restates them and this is what keeps the restatement honest. And each figure's
message must carry the split it exists for, because both splits are prefix
pairs: merged by a careless reader, every coalescing client reads as an
intrusion and every dead policy entry reads as a host one line from working.
"""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cmd_diagnose import (
    _binding_fragments, _named_hosts, _not_http_fragments,
)
from vm import (
    VM_DROP_MISDIRECTED, VM_DROP_MISDIRECTED_LISTED,
    VM_DROP_NOT_HTTP, VM_DROP_NOT_HTTP_POLICY,
)
from vm_status import OTHER_KEY

from tests.test_vm_inspect_listener import _mod


class TestTheKeysAgreeWithTheListener(unittest.TestCase):
    """A rename in the listener has to fail here rather than turn a figure
    into a permanent zero. Zero is a legal value for every one of these, so
    nothing at runtime distinguishes a key that stopped matching from a
    refusal that never fired."""

    def test_each_key_is_the_listeners_own_string(self):
        mod = _mod()
        for ours, theirs in (
                (VM_DROP_MISDIRECTED, "DROP_MISDIRECTED"),
                (VM_DROP_MISDIRECTED_LISTED, "DROP_MISDIRECTED_LISTED"),
                (VM_DROP_NOT_HTTP, "DROP_NOT_HTTP"),
                (VM_DROP_NOT_HTTP_POLICY, "DROP_NOT_HTTP_POLICY")):
            self.assertEqual(ours, getattr(mod, theirs), theirs)

    def test_every_key_read_here_is_one_the_listener_reports(self):
        """Restating a string the listener never writes is the same permanent
        zero one step earlier, and it survives the equality test above if the
        constant it was copied from is itself unused."""
        mod = _mod()
        for key in (VM_DROP_MISDIRECTED, VM_DROP_MISDIRECTED_LISTED,
                    VM_DROP_NOT_HTTP, VM_DROP_NOT_HTTP_POLICY):
            self.assertIn(key, mod.DROP_REASONS)

    def test_the_two_per_host_figures_are_actually_per_host(self):
        """Both messages name hosts. A reason with no per-host map would leave
        `_named_hosts` reading an absent key forever, and the message would
        render an empty parenthesis rather than the list it promises."""
        mod = _mod()
        for key in (VM_DROP_MISDIRECTED_LISTED, VM_DROP_NOT_HTTP,
                    VM_DROP_NOT_HTTP_POLICY):
            self.assertIn(key, mod.PER_HOST_REASONS)

    def test_the_unlisted_binding_half_has_no_per_host_map(self):
        """Its keys are guest-chosen and unbounded, which is why it is absent
        -- so the message for it must not promise a list. Pinned so that
        adding one later forces this message to be revisited."""
        self.assertNotIn(VM_DROP_MISDIRECTED, _mod().PER_HOST_REASONS)


class TestNamedHosts(unittest.TestCase):

    def test_busiest_first(self):
        out = _named_hosts({"a.example": 1, "b.example": 9})
        self.assertEqual(out, "b.example (9), a.example (1)")

    def test_the_overflow_bucket_is_not_rendered_as_a_hostname(self):
        """`(other)` counts events from hosts past the cap, not a host called
        `(other)`. An operator who reads it as a name goes looking for a VM
        that dialled it."""
        out = _named_hosts({"a.example": 1, OTHER_KEY: 4})
        self.assertNotIn("(other)", out)
        self.assertIn("4 more", out)

    def test_a_zero_overflow_says_nothing(self):
        self.assertEqual(_named_hosts({"a.example": 1, OTHER_KEY: 0}),
                         "a.example (1)")

    def test_a_missing_map_is_empty_rather_than_an_error(self):
        self.assertEqual(_named_hosts(None), "")


class TestTheBindingFigureIsTwoReadings(unittest.TestCase):

    def test_a_quiet_workload_says_nothing(self):
        self.assertEqual(_binding_fragments({"drop_reasons": {
            VM_DROP_MISDIRECTED: 0, VM_DROP_MISDIRECTED_LISTED: 0}}), [])

    def test_the_unlisted_half_is_named_as_evidence_not_a_setting(self):
        (line,) = _binding_fragments(
            {"drop_reasons": {VM_DROP_MISDIRECTED: 3}})
        self.assertIn("3 request(s)", line)
        self.assertIn("NO list", line)
        self.assertIn("evidence", line)
        self.assertNotIn("coalesc", line)

    def test_the_allowlisted_half_names_the_hosts_and_calls_it_benign(self):
        (line,) = _binding_fragments({
            "drop_reasons": {VM_DROP_MISDIRECTED_LISTED: 2},
            "per_host": {VM_DROP_MISDIRECTED_LISTED: {"cdn.example": 2}},
        })
        self.assertIn("coalescing", line)
        self.assertIn("cdn.example (2)", line)
        self.assertIn("Benign", line)

    def test_both_halves_produce_two_sentences_not_one(self):
        """The whole point of the split. One figure for both reads every
        coalescing client as an intrusion, and an alarm that fires on ordinary
        traffic stops being read."""
        lines = _binding_fragments({
            "drop_reasons": {VM_DROP_MISDIRECTED: 1,
                             VM_DROP_MISDIRECTED_LISTED: 1},
            "per_host": {VM_DROP_MISDIRECTED_LISTED: {"cdn.example": 1}},
        })
        self.assertEqual(len(lines), 2)
        self.assertIn("evidence", lines[0])
        self.assertIn("coalescing", lines[1])

    def test_the_allowlisted_half_survives_a_missing_per_host_map(self):
        """The count is exact and the map is best-effort; a report that
        crashed without one would lose the figure to protect the detail."""
        (line,) = _binding_fragments(
            {"drop_reasons": {VM_DROP_MISDIRECTED_LISTED: 2}})
        self.assertIn("2 request(s)", line)
        self.assertNotIn("()", line)


class TestTheNonHttpFigureIsTheSpliceList(unittest.TestCase):

    def test_a_quiet_workload_says_nothing(self):
        self.assertEqual(_not_http_fragments({"per_host_totals": {
            VM_DROP_NOT_HTTP: 0, VM_DROP_NOT_HTTP_POLICY: 0}}), [])

    def test_a_total_with_no_map_behind_it_drops_the_list_not_the_line(self):
        """Both halves render the hosts in parentheses, and an absent map made
        one of them print `()` -- an empty parenthesis exactly where the
        operator is looking for the name. The sibling figure already guarded
        this; the two disagreed, which is the whole reason it is pinned.

        It takes a document whose two halves disagree to get here, so the
        honest output is the sentence without the list rather than a blank
        where the list was promised.
        """
        for reason in (VM_DROP_NOT_HTTP, VM_DROP_NOT_HTTP_POLICY):
            with self.subTest(reason=reason):
                (line,) = _not_http_fragments({"per_host_totals": {reason: 3}})
                self.assertNotIn("()", line)
                self.assertIn("3 connection(s)", line)

    def test_the_plain_half_names_splice_and_the_host(self):
        (line,) = _not_http_fragments({
            "per_host_totals": {VM_DROP_NOT_HTTP: 4},
            "per_host": {VM_DROP_NOT_HTTP: {"smtp.example": 4}},
        })
        self.assertIn("smtp.example (4)", line)
        self.assertIn("[[vm.network.splice]]", line)
        self.assertNotIn("policy", line)

    def test_the_policy_half_says_the_entry_has_to_go_too(self):
        """Splicing a host that has a policy entry is TWO moves and the second
        is a deletion -- `validate` refuses a host in both. A message naming
        only `splice` would send an operator to type something validate
        rejects."""
        (line,) = _not_http_fragments({
            "per_host_totals": {VM_DROP_NOT_HTTP_POLICY: 1},
            "per_host": {VM_DROP_NOT_HTTP_POLICY: {"api.example": 1}},
        })
        self.assertIn("api.example (1)", line)
        self.assertIn("[[vm.network.policy]]", line)
        self.assertIn("deleting", line)
        self.assertIn("NEVER RUN", line)

    def test_the_two_halves_are_two_sentences(self):
        lines = _not_http_fragments({
            "per_host_totals": {VM_DROP_NOT_HTTP: 1,
                                VM_DROP_NOT_HTTP_POLICY: 1},
            "per_host": {VM_DROP_NOT_HTTP: {"smtp.example": 1},
                         VM_DROP_NOT_HTTP_POLICY: {"api.example": 1}},
        })
        self.assertEqual(len(lines), 2)
        self.assertIn("smtp.example", lines[0])
        self.assertIn("api.example", lines[1])

    def test_the_count_includes_the_hosts_past_the_cap(self):
        """`per_host` is capped at top-N and `per_host_totals` is exact, but
        the two reconcile: the snapshot carries `(other)`, so summing the map
        gives the total back. What does NOT reconcile is summing the NAMED
        keys, which is the natural way to write it from a map you are already
        iterating to render -- and it understates the figure by exactly the
        traffic a guest pushed into `(other)`, which is the traffic a guest
        filling the map with cheap names is trying to hide."""
        (line,) = _not_http_fragments({
            "per_host_totals": {VM_DROP_NOT_HTTP: 50},
            "per_host": {VM_DROP_NOT_HTTP: {"a.example": 1, OTHER_KEY: 49}},
        })
        self.assertIn("50 connection(s)", line)
        self.assertIn("49 more", line)


class TestTheFiguresReachTheLine(unittest.TestCase):
    """The seam. Both fragment builders can be perfect and `vm_inspect_check`
    never call them: the figures would then be computed, correct, and printed
    nowhere, which is indistinguishable from a workload with nothing to report.
    """

    def setUp(self):
        import cmd_diagnose
        self.mod = cmd_diagnose

    def _line(self, status):
        cfg = SimpleNamespace(
            name="vm1", uid=10001, vm_bridge=None,
            vm_network={"egress": "filtered"},
            config={"vm": {"network": {"egress": "filtered"}}})
        elems = [{"concat": [10001, 80]}, {"concat": [10001, 443]}]
        return self.mod.vm_inspect_check(
            cfg, elements4=elems, elements6=elems, socket_active=True,
            v6_route=True, self_dials=None, status=status)

    def test_both_figures_are_on_the_line(self):
        name, ok, detail = self._line({
            "drop_reasons": {VM_DROP_MISDIRECTED: 1,
                             VM_DROP_MISDIRECTED_LISTED: 1},
            "per_host": {VM_DROP_MISDIRECTED_LISTED: {"cdn.example": 1},
                         VM_DROP_NOT_HTTP: {"smtp.example": 2}},
            "per_host_totals": {VM_DROP_NOT_HTTP: 2},
        })
        self.assertEqual(name, "vm_inspect")
        self.assertIn("NO list", detail)
        self.assertIn("coalescing", detail)
        self.assertIn("smtp.example (2)", detail)

    def test_the_line_still_passes(self):
        """However loud the wording. Every one of these refusals is the
        inspector working, and nothing about this workload's configuration is
        broken by a guest behaving badly -- a red line would send an operator
        hunting for a setting that already did its job."""
        _, ok, detail = self._line(
            {"drop_reasons": {VM_DROP_MISDIRECTED: 99}})
        self.assertTrue(ok, detail)

    def test_a_quiet_workload_gets_the_ordinary_line(self):
        _, ok, detail = self._line({"drop_reasons": {}, "per_host": {}})
        self.assertTrue(ok)
        self.assertNotIn("421", detail)
        self.assertNotIn("splice", detail)

    def test_no_status_document_is_not_a_fault(self):
        """Socket-activated: a VM whose guest has dialled nothing has never
        written the file, which is the normal state of a healthy workload
        between boot and its first connection."""
        _, ok, detail = self._line(None)
        self.assertTrue(ok)
        self.assertIn("egress inspected on both families", detail)

    def test_the_document_is_read_from_the_path_the_listener_writes(self):
        """Probed rather than injected on a real run, and a reader pointed at
        a path nothing writes reports silence forever."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "inspect-status.json"
            path.write_text(json.dumps(
                {"drop_reasons": {VM_DROP_MISDIRECTED: 7}}))
            with mock.patch.object(self.mod, "vm_inspect_status_path",
                                   return_value=str(path)) as spy:
                _, _, detail = self._line(self.mod.PROBE)
        spy.assert_called_once_with("vm1")
        self.assertIn("7 request(s)", detail)

    def test_an_unreadable_document_says_nothing_rather_than_raising(self):
        """A malformed file means a bug in the writer. The honest report for
        that is silence on this line, not a traceback over the twenty other
        checks that were about to run."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "inspect-status.json"
            path.write_text("{not json")
            with mock.patch.object(self.mod, "vm_inspect_status_path",
                                   return_value=str(path)):
                _, ok, detail = self._line(self.mod.PROBE)
        self.assertTrue(ok)
        self.assertIn("egress inspected on both families", detail)


if __name__ == "__main__":
    unittest.main()
