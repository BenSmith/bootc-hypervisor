#!/usr/bin/env python3
"""Contracts for the inspector's figures — the one producer, and its two renderers.

Rung 5 T8/T9. Decision 9 is the property under test and it is not a property of
either renderer on its own: `doctor` prints these figures for a person and the
exporter publishes them for Prometheus, and the failure this file exists to
catch is the two of them disagreeing about what a figure MEANS. That cannot be
seen by testing either in isolation, which is why OneProducerTest reads both
against the same document and compares them to each other rather than to a
literal.

The second half is the table itself. FIGURES is a mechanism, not a list: both
renderers walk it, so a malformed row (a duplicate metric name, a counter
without `_total`, a figure that is both stored and derived) is a defect in
output neither renderer's own tests would look at.
"""

import argparse
import io
import json
import re
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

import cmd_doctor
import vm_inspect_figures as fig

from tests import load_script

REPO = Path(__file__).resolve().parent.parent


def _exporter():
    return load_script("libexec/workload-exporter", "exporter_figures")


FULL_STATUS = {
    "dispositions": {"spliced": 2, "terminated": 5, "forwarded": 1,
                     "dropped": 3},
    "drop_reasons": {"not allowlisted": 3, "timed out": 0, "not HTTP": 0},
    "concurrency": {"open": 1, "refused": 0},
    "internal_refusals_total": 4,
    "record_failures": 0, "h2_unrecorded": 1, "bumped": 5,
    "ech": {"seen": 0, "alarm": 0},
    "policy_digest": "a" * 64,
    "mint": {"mints": 4, "hits": 11, "denied_mints": 1, "denied_hits": 0,
             "throttled": 0, "failed": 0, "working_set": 4, "denials": 1,
             "clock_resyncs": 0, "clock_unavailable": 2, "clock_failed": 0},
}

FULL_RESOLVE = {
    "queries": {"synthesised": 7, "static": 1, "nodata": 0, "malformed": 0},
    "unlisted": 2,
}


class TableTest(unittest.TestCase):
    """FIGURES is walked by both renderers, so a malformed row is a defect in
    output that neither renderer's own tests inspect."""

    def test_keys_are_unique(self):
        keys = [f.key for f in fig.FIGURES]
        self.assertEqual(len(keys), len(set(keys)))

    def test_exported_metric_names_are_unique(self):
        """Two rows sharing a metric name publish two values under one series,
        and Prometheus keeps whichever it parsed last."""
        names = [f.metric for f in fig.FIGURES if f.metric]
        self.assertEqual(len(names), len(set(names)))

    def test_every_figure_is_stored_or_derived_and_never_both(self):
        for f in fig.FIGURES:
            with self.subTest(f.key):
                self.assertNotEqual(bool(f.path), bool(f.derive),
                                    "exactly one of path/derive")

    def test_counters_end_in_total_and_gauges_do_not(self):
        """Prometheus convention, and it is load-bearing rather than cosmetic:
        `rate()` over a name without `_total` is the shape reviewers stop
        catching once one series has broken the rule."""
        for f in fig.FIGURES:
            if not f.metric:
                continue
            with self.subTest(f.metric):
                if f.kind == "counter":
                    self.assertTrue(f.metric.endswith("_total"))
                else:
                    self.assertFalse(f.metric.endswith("_total"))

    def test_every_group_is_one_the_renderers_know(self):
        for f in fig.FIGURES:
            self.assertIn(f.group, fig.GROUP_LABELS)

    def test_only_the_two_sums_are_withheld_from_prometheus(self):
        """An empty `metric` is a deliberate, argued exception (a sum belongs
        to the query language). A third one added silently is a figure an
        operator's dashboard will never see, with nothing to say so."""
        self.assertEqual({f.key for f in fig.FIGURES if not f.metric},
                         {"connections_total", "drops_total"})


class GroupPresenceTest(unittest.TestCase):
    """Absent groups are omitted, not zeroed. `mint_mints 0` on a workload with
    no minter asserts a minter exists and is idle — a different, false claim."""

    def test_a_spliced_workload_reports_no_mint_figures(self):
        figs = fig.figures({"dispositions": {"spliced": 1}})
        self.assertNotIn("mints", figs)
        self.assertIn("spliced", figs)

    def test_a_terminating_workload_does_report_them(self):
        self.assertIn("mints", fig.figures(FULL_STATUS))

    def test_names_need_the_resolver_document(self):
        self.assertNotIn("synthesised", fig.figures(FULL_STATUS))
        self.assertIn("synthesised", fig.figures(FULL_STATUS, FULL_RESOLVE))

    def test_no_status_document_reports_nothing_at_all(self):
        self.assertEqual(fig.figures(None), {})

    def test_the_resolver_alone_still_reports_names(self):
        """The two documents have separate writers: the responder can have run
        while a socket-activated inspector has not."""
        self.assertEqual(set(fig.figures(None, FULL_RESOLVE)),
                         {f.key for f in fig.FIGURES if f.group == fig.NAMES})


class FigureValueTest(unittest.TestCase):

    def test_the_sums_add_their_own_parts(self):
        figs = fig.figures(FULL_STATUS)
        self.assertEqual(figs["connections_total"], 11)
        self.assertEqual(figs["drops_total"], 3)

    def test_a_missing_key_inside_a_present_group_reads_zero(self):
        figs = fig.figures({"dispositions": {"spliced": 1}})
        self.assertEqual(figs["terminated"], 0)

    def test_a_bool_is_not_a_count(self):
        """`isinstance(True, int)` is True in Python, so an unguarded reader
        turns a flag that was never a counter into the value 1."""
        self.assertEqual(fig.figures({"bumped": True})["bumped"], 0)

    def test_a_path_through_a_non_mapping_reads_zero(self):
        self.assertEqual(fig.figures({"ech": 5})["ech_seen"], 0)

    def test_drop_reasons_are_passed_through_not_summed(self):
        self.assertEqual(fig.drop_reasons(FULL_STATUS),
                         {"not allowlisted": 3, "timed out": 0, "not HTTP": 0})

    def test_drop_reasons_of_a_missing_document(self):
        self.assertEqual(fig.drop_reasons(None), {})


class ReaderTest(unittest.TestCase):
    """One parse of each document, and silence for every reason it cannot be
    read — the inspector is socket-activated, so absence is the ordinary state
    of a healthy workload between boot and its guest's first connection."""

    def test_a_missing_file_is_none(self):
        with mock.patch.object(fig, "vm_inspect_status_path",
                               return_value="/nonexistent/x.json"):
            self.assertIsNone(fig.read_inspect_status("vm1"))

    def test_a_malformed_file_is_none_rather_than_a_traceback(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "s.json"
            path.write_text("{not json")
            with mock.patch.object(fig, "vm_inspect_status_path",
                                   return_value=str(path)):
                self.assertIsNone(fig.read_inspect_status("vm1"))

    def test_a_document_that_is_not_an_object_is_none(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "s.json"
            path.write_text("[1, 2]")
            with mock.patch.object(fig, "vm_resolve_status_path",
                                   return_value=str(path)):
                self.assertIsNone(fig.read_resolve_status("vm1"))


class RenderTest(unittest.TestCase):
    """The human rendering: zeros shown, absent groups silent."""

    def _text(self, status=FULL_STATUS, resolve=None):
        return "\n".join(fig.figure_lines(fig.figures(status, resolve),
                                          fig.drop_reasons(status)))

    def test_a_zero_is_printed_rather_than_skipped(self):
        """"The guest dialled nothing" and "the inspector is not seeing this
        guest's traffic" are the two readings an operator is choosing between,
        and an absent line makes them look alike."""
        self.assertIn("0  turned away at the connection ceiling", self._text())

    def test_an_absent_group_prints_no_header(self):
        text = "\n".join(fig.figure_lines(
            fig.figures({"dispositions": {"spliced": 1}})))
        self.assertNotIn(fig.GROUP_LABELS[fig.CERTIFICATES], text)
        self.assertNotIn(fig.GROUP_LABELS[fig.NAMES], text)

    def test_present_groups_print_their_header(self):
        text = self._text(resolve=FULL_RESOLVE)
        for group in (fig.CONNECTIONS, fig.CERTIFICATES, fig.NAMES,
                      fig.EVIDENCE):
            self.assertIn(fig.GROUP_LABELS[group], text)

    def test_drop_reasons_are_busiest_first_and_zeros_are_counted_not_listed(self):
        text = self._text()
        self.assertIn("3  not allowlisted", text)
        self.assertIn("(2 other reasons measured, all zero)", text)
        self.assertNotIn("0  timed out", text)

    def test_all_reasons_zero_says_how_many_were_measured(self):
        """A document from an older listener carrying six reasons and a current
        one carrying eighteen render identically when every one is zero, so the
        count is what separates "never measured" from "never fired"."""
        status = {"dispositions": {}, "drop_reasons": {"a": 0, "b": 0}}
        text = "\n".join(fig.figure_lines(fig.figures(status),
                                          fig.drop_reasons(status)))
        self.assertIn("(2 drop reasons measured, all zero)", text)

    def test_the_labels_are_the_tables(self):
        """Rendered from FIGURES, never restated — a label written twice is the
        second definition in the smallest possible form."""
        text = self._text(resolve=FULL_RESOLVE)
        for f in fig.FIGURES:
            with self.subTest(f.key):
                self.assertIn(f.label, text)


class OneProducerTest(unittest.TestCase):
    """Decision 9, and the only test that can see it: both renderers, one
    document, compared to EACH OTHER rather than to a literal."""

    def _exported(self):
        payload = {"status_present": 1,
                   "figures": fig.figures(FULL_STATUS, FULL_RESOLVE),
                   "drop_reasons": fig.drop_reasons(FULL_STATUS)}
        return _exporter()._inspect_metric_lines([("vm1", payload)])

    def test_every_published_value_is_the_producers_value(self):
        figs = fig.figures(FULL_STATUS, FULL_RESOLVE)
        published = {}
        for line in self._exported():
            m = re.match(r'(\w+)\{workload="vm1"\} (\d+)$', line)
            if m:
                published[m.group(1)] = int(m.group(2))
        by_metric = {f.metric: f.key for f in fig.FIGURES if f.metric}
        checked = 0
        for metric, value in published.items():
            if metric not in by_metric:
                continue          # status_present, which is not a figure
            self.assertEqual(value, figs[by_metric[metric]], metric)
            checked += 1
        self.assertEqual(checked, len(by_metric),
                         "a figure in the table reached no series")

    def test_the_sums_are_not_published(self):
        """Prometheus computes them from the parts. A published total is a
        second definition free to disagree the moment a disposition is added to
        one and not the other."""
        text = "\n".join(self._exported())
        self.assertNotIn("connections_total", text)
        self.assertNotIn("drops_total", text)

    def test_the_human_rendering_shows_the_sums_that_prometheus_does_not(self):
        """The exception is argued, not accidental: a person reading `doctor`
        cannot run a query."""
        text = "\n".join(fig.figure_lines(fig.figures(FULL_STATUS)))
        self.assertIn("11  connections seen", text)


class ExporterTest(unittest.TestCase):

    def setUp(self):
        self.mod = _exporter()

    def _lines(self, payloads):
        return self.mod._inspect_metric_lines(payloads)

    def test_no_inspected_workloads_emits_nothing(self):
        self.assertEqual(self._lines([]), [])

    def test_a_filtered_workload_that_has_not_been_dialled_emits_zeros(self):
        """The series has to exist from the first scrape: `record_failures == 0`
        is only alertable if no-data and zero are distinguishable, and
        status_present is what distinguishes them."""
        payload = {"status_present": 0, "figures": fig.figures({}),
                   "drop_reasons": {}}
        text = "\n".join(self._lines([("vm1", payload)]))
        self.assertIn('workload_vm_inspect_status_present{workload="vm1"} 0',
                      text)
        self.assertIn(
            'workload_vm_inspect_record_failures_total{workload="vm1"} 0', text)

    def test_help_and_type_precede_every_family(self):
        payload = {"status_present": 1, "figures": fig.figures(FULL_STATUS),
                   "drop_reasons": fig.drop_reasons(FULL_STATUS)}
        lines = self._lines([("vm1", payload)])
        seen = set()
        for i, line in enumerate(lines):
            m = re.match(r"(\w+)\{", line)
            if not m or m.group(1) in seen:
                continue
            seen.add(m.group(1))
            header = "\n".join(lines[max(0, i - 2):i])
            self.assertIn(f"# HELP {m.group(1)} ", header)
            self.assertIn(f"# TYPE {m.group(1)} ", header)

    def test_samples_of_one_family_are_contiguous(self):
        """Prometheus rejects an exposition file that interleaves families, so
        a per-workload loop wrapped around the metric loop breaks the whole
        drop rather than one series."""
        payload = {"status_present": 1, "figures": fig.figures(FULL_STATUS),
                   "drop_reasons": {}}
        lines = self._lines([("vm1", payload), ("vm2", payload)])
        order = [m.group(1) for m in
                 (re.match(r"(\w+)\{", line) for line in lines) if m]
        first_seen = []
        for name in order:
            if name not in first_seen:
                first_seen.append(name)
        self.assertEqual(len(first_seen), len(set(order)))
        runs = [name for i, name in enumerate(order)
                if i == 0 or order[i - 1] != name]
        self.assertEqual(len(runs), len(set(order)))

    def test_a_reason_label_is_escaped(self):
        payload = {"status_present": 1, "figures": {},
                   "drop_reasons": {'says "no"': 1}}
        text = "\n".join(self._lines([("vm1", payload)]))
        self.assertIn(r'reason="says \"no\""', text)

    def test_an_absent_group_publishes_no_empty_family(self):
        """A HELP/TYPE header with no samples is legal and useless: it
        advertises a series that will never have one."""
        payload = {"status_present": 1,
                   "figures": fig.figures({"dispositions": {"spliced": 1}}),
                   "drop_reasons": {}}
        text = "\n".join(self._lines([("vm1", payload)]))
        self.assertNotIn("workload_vm_inspect_mints_total", text)

    def test_an_unfiltered_workload_is_not_collected(self):
        """Nothing, not zeros: a series for an unfiltered workload asserts a
        filter exists and is idle."""
        with mock.patch.object(self.mod, "get_enabled_workloads",
                               return_value=[("app", [], False, False),
                                             ("vm1", [], True, False)]):
            self.assertEqual(self.mod.collect_inspect(), [])

    def test_a_filtered_workload_is(self):
        with mock.patch.object(self.mod, "get_enabled_workloads",
                               return_value=[("vm1", [], True, True)]), \
             mock.patch.object(self.mod, "read_inspect_status",
                               return_value=FULL_STATUS), \
             mock.patch.object(self.mod, "read_resolve_status",
                               return_value=None):
            collected = self.mod.collect_inspect()
        self.assertEqual([name for name, _ in collected], ["vm1"])
        self.assertEqual(collected[0][1]["status_present"], 1)

    def test_the_uses_inspect_flag_comes_from_the_config(self):
        """Derived where the TOML is already parsed. Deciding from the runtime
        directory instead cannot tell a filtered VM that has not started this
        boot from an unfiltered one, and those owe opposite output."""
        self.assertIn("vm_uses_inspect",
                      (REPO / "libexec" / "workload-exporter").read_text())


class DoctorSectionTest(unittest.TestCase):
    """`doctor`'s egress section: evidence, and never a verdict."""

    CHECKS = ([{"check": "user_exists", "passed": True, "message": "ok"}], True)
    LIVENESS = {"service_active": True, "service_state": "active",
                "container_running": True, "container_status": "Up",
                "healthy": True}

    def setUp(self):
        cfg = SimpleNamespace(name="vm1", kind="vm", mode="single",
                              lifecycle="pet", enabled=True, config={})
        for name, value in (("require_root", lambda: None),
                            ("units_outdated", lambda n: False),
                            ("units_from_other_build", lambda n: None),
                            ("workload_config_path", lambda n: "/etc/x.toml"),
                            ("_generator_lines", lambda n: []),
                            ("_unit_rows", lambda c: []),
                            ("collect_drift", lambda n: []),
                            ("collect_policy_drift", lambda n: []),
                            ("WorkloadConfig", lambda n: cfg)):
            self.enterContext(mock.patch.object(cmd_doctor, name, value))
        self.enterContext(mock.patch.object(
            cmd_doctor, "collect_diagnose_checks",
            lambda config, manager: self.CHECKS))
        substrate = mock.Mock()
        substrate.liveness.return_value = dict(self.LIVENESS)
        self.enterContext(mock.patch.object(
            cmd_doctor, "get_substrate", lambda config, manager: substrate))

    def _run(self, *, filtered=True, status=FULL_STATUS, json_mode=False):
        out = io.StringIO()
        with mock.patch.object(cmd_doctor, "vm_uses_inspect",
                               return_value=filtered), \
             mock.patch.object(cmd_doctor, "read_inspect_status",
                               return_value=status), \
             mock.patch.object(cmd_doctor, "read_resolve_status",
                               return_value=None):
            try:
                with redirect_stdout(out):
                    cmd_doctor.cmd_doctor(
                        argparse.Namespace(workload="vm1", json=json_mode),
                        mock.Mock())
            except SystemExit as e:
                return e.code, out.getvalue()
        return None, out.getvalue()

    def test_the_section_is_rendered_for_a_filtered_workload(self):
        code, text = self._run()
        self.assertIn("Egress (inspected)", text)
        self.assertIn("3  dropped", text)

    def test_denials_do_not_make_the_workload_unhealthy(self):
        """A guest being denied is the filter WORKING. A doctor that reported
        UNHEALTHY over a drop count would teach an operator that the feature
        doing its job is a fault, which is how a report stops being read."""
        code, text = self._run()
        self.assertEqual(code, 0)
        self.assertIn("Overall: HEALTHY", text)

    def test_the_section_says_it_carries_no_verdict(self):
        _, text = self._run()
        self.assertIn("evidence, not a verdict", text)

    def test_an_unfiltered_workload_has_no_section(self):
        _, text = self._run(filtered=False)
        self.assertNotIn("Egress (inspected)", text)

    def test_a_workload_never_dialled_says_so_rather_than_printing_zeros(self):
        _, text = self._run(status=None)
        self.assertIn("socket-activated", text)
        self.assertNotIn("0  dropped", text)

    def test_the_enforced_digest_is_named(self):
        _, text = self._run()
        self.assertIn("enforcing policy", text)

    def test_json_carries_the_figures(self):
        _, text = self._run(json_mode=True)
        egress = json.loads(text)["egress"]
        self.assertEqual(egress["figures"]["dropped"], 3)
        self.assertTrue(egress["status_present"])

    def test_json_egress_is_null_for_an_unfiltered_workload(self):
        _, text = self._run(filtered=False, json_mode=True)
        self.assertIsNone(json.loads(text)["egress"])


class DocumentedMetricTest(unittest.TestCase):
    """Every metric name a tracked doc prints must be one that exists.

    ONE DIRECTION ONLY, like test_completions' flag check and for the same
    reason: omitting a series from a doc is an editorial choice — the
    walkthrough's table says out loud that it is a selection — while NAMING one
    that does not exist is always a bug, and the worst kind, because a
    dashboard built on it silently graphs nothing forever. Nothing else in the
    tree parses a metric name out of prose, so a rename lands, the suite stays
    green, and the doc points at a series that no longer exists.
    """

    # The two series the exporter emits that are not FIGURES rows: a gauge
    # about the document rather than from it, and the labelled family whose
    # samples are the drop breakdown.
    NON_FIGURE_SERIES = {"workload_vm_inspect_status_present",
                         "workload_vm_inspect_drop_events_total"}

    def _named(self):
        """Full metric names in every tracked doc, `_`-suffix shorthand aside.

        The digit in `h2_unrecorded` is why the character class is not [a-z_]:
        a name-shaped regex that stops at a digit reports a real metric as
        fictional, which is how this check first accused the docs it was
        written to guard.
        """
        found = {}
        for path in sorted(REPO.glob("docs/**/*.md")):
            if "wip" in path.parts:      # gitignored; nothing tracked cites it
                continue
            for name in re.findall(r"workload_vm_(?:inspect|resolve)_[a-z0-9_]+",
                                   path.read_text()):
                found.setdefault(name, path.name)
        return found

    def test_every_documented_metric_exists(self):
        real = {f.metric for f in fig.FIGURES if f.metric} | self.NON_FIGURE_SERIES
        bad = {name: where for name, where in self._named().items()
               if name not in real}
        self.assertEqual(bad, {}, f"documented metrics that do not exist: {bad}")

    def test_the_check_can_see_the_docs_at_all(self):
        """A glob that matches nothing passes vacuously — the failure this
        whole file's TableTest exists to make impossible, one level up."""
        self.assertGreater(len(self._named()), 5)

    def test_the_non_figure_exceptions_are_still_not_figures(self):
        """If either becomes a FIGURES row, this set shrinks rather than
        quietly excusing a name the table now owns."""
        self.assertEqual(
            self.NON_FIGURE_SERIES & {f.metric for f in fig.FIGURES}, set())


if __name__ == "__main__":
    unittest.main()
