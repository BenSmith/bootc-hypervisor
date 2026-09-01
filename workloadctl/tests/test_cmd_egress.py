"""`workloadctl egress` — the reader over the per-request record. Rung 5 T2.

Named test_cmd_egress rather than test_egress to stay clear of
tests/test_vm_egress.py, which is the uid-keyed nftables layer and has nothing
to do with the record.

Three kinds of thing are held here.

**The pins.** The reader restates two of the listener's vocabularies —
`VM_INSPECT_RECORD_REASONS` and the `id=`/`req=` field names — because nothing
in `lib/` can import an extension-less entrypoint. Both directions are checked:
a reason the listener writes and `lib/vm.py` omits is a filter that cannot
select a real refusal, and one `lib/vm.py` carries that the listener never
writes is a filter that always returns nothing. Neither failure is visible in
the output, which is what makes the pin the only place they can be caught.

**The filters.** Every one has to both select and reject. A filter that
accepted everything would look exactly like a workload with nothing to hide,
and a filter that accepted nothing would look exactly like a guest that never
did the thing being asked about — the second is why `--reason` validates
against a closed set rather than matching free text.

**The gaps.** Rotation, a connection that straddles one, a group whose earlier
records fell off the retention horizon, and a torn line. Each is a case where
the honest answer differs from the convenient one.
"""

import datetime
import gzip
import io
import json
import os
import unittest
import unittest.mock
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from tempfile import TemporaryDirectory

import cmd_egress
from cmd_egress import (
    EgressUsage, build_filters, filters_active, format_record, generations,
    group_by_connection, group_is_partial, parse_when, read_records,
    resolve_id, resolve_reason, resolve_status, select,
)
from vm import (
    VM_INSPECT_LOG_ID_FIELD, VM_INSPECT_LOG_REQ_FIELD,
    VM_INSPECT_RECORD_DECISIONS, VM_INSPECT_RECORD_FIELDS,
    VM_INSPECT_RECORD_MODES, VM_INSPECT_RECORD_PLANES,
    VM_INSPECT_RECORD_REASONS,
)

from tests.test_vm_inspect_listener import _mod


def _rec(**overrides):
    """A record with every field present, so a test overrides only what it means.

    Every field on every line is T1's rule — a key that is absent and a key
    that is null are different facts — so a fixture that omitted them would be
    testing a shape the listener never emits.
    """
    record = dict.fromkeys(VM_INSPECT_RECORD_FIELDS)
    record.update({
        VM_INSPECT_LOG_ID_FIELD: "a1b2c3d4e5f6",
        VM_INSPECT_LOG_REQ_FIELD: 1,
        "ts": "2026-08-31T12:00:00.000Z",
        "plane": "tls",
        "mode": "terminate",
        "host": "api.example.com",
        "method": "GET",
        "path": "/v1/models",
        "http": "HTTP/1.1",
        "decision": "forward",
        "status": 200,
        "upstream": "203.0.113.10:443",
        "duration_ms": 12.5,
    })
    record.update(overrides)
    return record


def _args(**overrides):
    defaults = dict(workload="wl", lines=cmd_egress.LINES_DEFAULT, group=False,
                    json=False, id=None, decision=None, mode=None, plane=None,
                    reason=None, host=None, method=None, status=None,
                    since=None, until=None)
    defaults.update(overrides)
    return unittest.mock.Mock(**defaults)


def _write(path: Path, records, *, gz=False):
    body = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)
    if gz:
        path.write_bytes(gzip.compress(body.encode()))
    else:
        path.write_text(body)


# --- the pins ---------------------------------------------------------------

class TestReasonPin(unittest.TestCase):
    """lib/vm.py's reason set against the listener's own, both directions."""

    def test_every_reason_the_listener_writes_is_selectable(self):
        """A missing one is a refusal no --reason value can ask about."""
        for reason in _mod().DROP_REASONS:
            self.assertIn(reason, VM_INSPECT_RECORD_REASONS)

    def test_no_reason_here_is_one_the_listener_never_writes(self):
        """A stale one is a filter that always returns nothing, silently."""
        for reason in VM_INSPECT_RECORD_REASONS:
            self.assertIn(reason, _mod().DROP_REASONS)

    def test_the_vocabularies_match_the_listeners(self):
        mod = _mod()
        self.assertEqual(tuple(VM_INSPECT_RECORD_DECISIONS),
                         tuple(mod.RECORD_DECISIONS))
        self.assertEqual(tuple(VM_INSPECT_RECORD_MODES),
                         tuple(mod.RECORD_MODES))

    def test_planes_are_the_two_the_listener_labels(self):
        """Derived from plane_for_port, not restated beside it.

        This asserted `{"tls", "cleartext"}` against a literal, which is a
        third spelling of the same two strings and pins nothing: the listener
        has no named plane vocabulary — the values are bare returns inside
        plane_for_port() — so a rename there left `--plane cleartext` a legal
        argparse choice that matches every record never, and `No records
        matched.` is indistinguishable from a guest that never used that plane.
        That is the silent-filter failure resolve_reason() is built to prevent,
        arriving through the one vocabulary that was not derived.
        """
        mod = _mod()
        self.assertEqual(
            set(VM_INSPECT_RECORD_PLANES),
            {mod.plane_for_port(mod.VM_INSPECT_PORT_TLS),
             mod.plane_for_port(mod.VM_INSPECT_PORT_CLEARTEXT)})

    def test_every_plane_is_a_port_the_socket_unit_binds(self):
        """And nothing else is a plane: an unrecognised port is None, which is
        not a value any record can carry."""
        self.assertIsNone(_mod().plane_for_port(9999))
        self.assertNotIn(None, VM_INSPECT_RECORD_PLANES)


class TestIdPatternIsBuiltFromTheConstant(unittest.TestCase):
    """The join key's spelling has exactly one definition.

    An operator pastes `id=<hex>` off a journal line. If the reader hard-coded
    `id=` and the listener's field were renamed, every paste would be rejected
    as malformed — a failure that looks like the operator mistyping.
    """

    def test_the_pasted_token_and_the_bare_hex_are_the_same_id(self):
        self.assertEqual(resolve_id(f"{VM_INSPECT_LOG_ID_FIELD}=A1B2C3"),
                         "a1b2c3")
        self.assertEqual(resolve_id("a1b2c3"), "a1b2c3")

    def test_a_renamed_field_moves_the_pattern_with_it(self):
        with unittest.mock.patch.object(cmd_egress, "VM_INSPECT_LOG_ID_FIELD",
                                        "conn"):
            pattern = cmd_egress.re.compile(
                rf"\A(?:{cmd_egress.re.escape(cmd_egress.VM_INSPECT_LOG_ID_FIELD)}=)?"
                r"([0-9a-fA-F]+)\Z")
            self.assertTrue(pattern.match("conn=a1b2c3"))

    def test_a_non_hex_token_is_a_sentence_not_a_traceback(self):
        with self.assertRaises(EgressUsage):
            resolve_id("id=not-a-connection")


# --- filter values ----------------------------------------------------------

class TestReasonResolution(unittest.TestCase):

    def test_an_unambiguous_substring_resolves(self):
        self.assertEqual(resolve_reason("ceiling"),
                         "connection ceiling reached")

    def test_a_substring_shared_by_two_reasons_is_ambiguous(self):
        """`allowlisted` is in `not allowlisted` and in the binding-rejection
        pair's listed half, and those need different operator responses."""
        with self.assertRaises(EgressUsage):
            resolve_reason("allowlisted")

    def test_case_does_not_matter(self):
        self.assertEqual(resolve_reason("MINT RATIONED"), "mint rationed")

    def test_an_exact_match_beats_its_own_prefix_relationship(self):
        """`not HTTP` is a prefix of `not HTTP (policy entry)`.

        The two exist as separate reasons because they need different operator
        responses, so the more common of the pair must stay selectable.
        """
        self.assertEqual(resolve_reason("not HTTP"), "not HTTP")
        self.assertEqual(resolve_reason("not HTTP (policy entry)"),
                         "not HTTP (policy entry)")

    def test_an_ambiguous_substring_names_the_candidates(self):
        with self.assertRaises(EgressUsage) as caught:
            resolve_reason("server name")
        self.assertIn("allowlisted", str(caught.exception))

    def test_an_unknown_reason_errors_rather_than_returning_empty(self):
        """The whole argument for the closed set.

        `--reason "not allowed"` free-text would print an empty report, and an
        operator would conclude the denial never happened.
        """
        with self.assertRaises(EgressUsage) as caught:
            resolve_reason("not allowed")
        self.assertIn("not allowlisted", str(caught.exception))


class TestStatusAndTime(unittest.TestCase):

    def test_an_exact_status_and_a_class(self):
        self.assertEqual(resolve_status("403"), ("exact", 403))
        self.assertEqual(resolve_status("4xx"), ("class", 4))

    def test_a_bad_status_is_a_sentence(self):
        with self.assertRaises(EgressUsage):
            resolve_status("forbidden")

    def test_relative_spellings_agree(self):
        a = parse_when("2h")
        b = parse_when("-2h")
        c = parse_when("2h ago")
        self.assertLess(abs((a - b).total_seconds()), 2)
        self.assertLess(abs((a - c).total_seconds()), 2)

    def test_an_iso_value_with_an_offset_is_taken_as_given(self):
        self.assertEqual(parse_when("2026-08-31T12:00:00+00:00").hour, 12)

    def test_a_bad_time_is_a_sentence(self):
        with self.assertRaises(EgressUsage):
            parse_when("last tuesday")


# --- selection --------------------------------------------------------------

class TestFiltersSelectAndReject(unittest.TestCase):
    """Every filter has to do both. One that only selects is not a filter."""

    def setUp(self):
        self.records = [
            _rec(),
            _rec(**{VM_INSPECT_LOG_ID_FIELD: "ffffffffffff",
                    "decision": "drop", "mode": "splice", "plane": "cleartext",
                    "host": "files.internal.test", "method": "POST",
                    "reason": "not allowlisted", "status": None,
                    "path": None, VM_INSPECT_LOG_REQ_FIELD: None}),
            _rec(**{VM_INSPECT_LOG_REQ_FIELD: 2, "decision": "drop",
                    "status": 403, "reason": "not permitted by policy",
                    "path": "/v1/admin"}),
        ]

    def _select(self, **flags):
        return select(self.records, build_filters(_args(**flags)))

    def test_no_filter_selects_everything(self):
        self.assertEqual(len(self._select()), 3)

    def test_decision(self):
        self.assertEqual(len(self._select(decision=["drop"])), 2)
        self.assertEqual(len(self._select(decision=["forward"])), 1)

    def test_mode(self):
        self.assertEqual(len(self._select(mode=["splice"])), 1)
        self.assertEqual(len(self._select(mode=["h2"])), 0)

    def test_plane(self):
        self.assertEqual(len(self._select(plane=["cleartext"])), 1)
        self.assertEqual(len(self._select(plane=["tls"])), 2)

    def test_reason(self):
        self.assertEqual(len(self._select(reason=["not permitted"])), 1)
        self.assertEqual(len(self._select(reason=["timed out"])), 0)

    def test_id_takes_the_pasted_token(self):
        picked = self._select(id=[f"{VM_INSPECT_LOG_ID_FIELD}=ffffffffffff"])
        self.assertEqual(len(picked), 1)
        self.assertEqual(picked[0]["mode"], "splice")

    def test_host_is_a_pattern(self):
        self.assertEqual(len(self._select(host=["*.example.com"])), 2)
        self.assertEqual(len(self._select(host=["*.internal.test"])), 1)

    def test_a_record_with_no_host_never_matches_a_host_pattern(self):
        """A hello that gave no name did not visit `*`, and must not be claimed
        to have."""
        records = [_rec(host=None)]
        self.assertEqual(
            select(records, build_filters(_args(host=["*"]))), [])

    def test_method(self):
        self.assertEqual(len(self._select(method=["post"])), 1)

    def test_status_exact_and_class(self):
        self.assertEqual(len(self._select(status=["403"])), 1)
        self.assertEqual(len(self._select(status=["4xx"])), 1)
        self.assertEqual(len(self._select(status=["2xx"])), 1)

    def test_a_null_status_is_not_in_any_class(self):
        self.assertEqual(len(self._select(status=["5xx"])), 0)

    def test_repeated_flags_or_within_a_field(self):
        self.assertEqual(len(self._select(mode=["splice", "terminate"])), 3)

    def test_fields_and_across(self):
        self.assertEqual(len(self._select(decision=["drop"], plane=["tls"])), 1)

    def test_since_and_until(self):
        records = [_rec(ts="2026-08-30T12:00:00.000Z"),
                   _rec(ts="2026-08-31T12:00:00.000Z")]
        picked = select(records, build_filters(
            _args(since="2026-08-31T00:00:00+00:00")))
        self.assertEqual(len(picked), 1)
        picked = select(records, build_filters(
            _args(until="2026-08-31T00:00:00+00:00")))
        self.assertEqual(len(picked), 1)

    def test_filters_active_distinguishes_the_two_kinds_of_gap(self):
        self.assertFalse(filters_active(build_filters(_args())))
        self.assertTrue(filters_active(build_filters(_args(decision=["drop"]))))


# --- generations ------------------------------------------------------------

class TestGenerations(unittest.TestCase):

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.path = self.dir / "requests.log"
        self.addCleanup(self._tmp.cleanup)

    def test_oldest_first_across_plain_and_gz(self):
        """logrotate leaves .1 uncompressed (delaycompress) and .N.gz behind it."""
        _write(self.path, [_rec(path="/live")])
        _write(self.dir / "requests.log.1", [_rec(path="/one")])
        _write(self.dir / "requests.log.2.gz", [_rec(path="/two")], gz=True)
        self.assertEqual([p.name for p in generations(self.path)],
                         ["requests.log.2.gz", "requests.log.1", "requests.log"])

    def test_unrelated_neighbours_are_not_generations(self):
        _write(self.path, [_rec()])
        (self.dir / "requests.log.swp").write_text("x")
        (self.dir / "other.log.1").write_text("x")
        self.assertEqual([p.name for p in generations(self.path)],
                         ["requests.log"])

    def test_records_arrive_oldest_first(self):
        _write(self.path, [_rec(path="/live")])
        _write(self.dir / "requests.log.1", [_rec(path="/one")])
        _write(self.dir / "requests.log.2.gz", [_rec(path="/two")], gz=True)
        records, malformed, read = read_records(self.path)
        self.assertEqual([r["path"] for r in records], ["/two", "/one", "/live"])
        self.assertEqual(malformed, 0)
        self.assertEqual(len(read), 3)

    def test_a_missing_file_is_not_an_error(self):
        records, malformed, read = read_records(self.path)
        self.assertEqual((records, malformed, read), ([], 0, []))

    def test_a_torn_line_is_counted_and_the_rest_still_reads(self):
        """One bad line must not make the whole retained history unreadable."""
        self.path.write_text(
            json.dumps(_rec(path="/first")) + "\n"
            + '{"id": "abc", "trunc\n'
            + json.dumps(_rec(path="/second")) + "\n")
        records, malformed, _ = read_records(self.path)
        self.assertEqual([r["path"] for r in records], ["/first", "/second"])
        self.assertEqual(malformed, 1)

    def test_a_json_scalar_is_malformed_not_a_record(self):
        self.path.write_text('"just a string"\n')
        records, malformed, _ = read_records(self.path)
        self.assertEqual((records, malformed), ([], 1))

    def test_since_prunes_a_generation_by_mtime_without_reading_it(self):
        old = self.dir / "requests.log.1"
        _write(old, [_rec(path="/old")])
        os.utime(old, (1_000_000, 1_000_000))
        _write(self.path, [_rec(path="/live")])
        records, _, read = read_records(self.path, since=parse_when("1h"))
        self.assertEqual([r["path"] for r in records], ["/live"])
        self.assertNotIn(old, read)

    def test_until_prunes_on_the_first_record_alone(self):
        _write(self.dir / "requests.log.1",
               [_rec(ts="2026-08-30T12:00:00.000Z", path="/old")])
        _write(self.path, [_rec(ts="2026-08-31T12:00:00.000Z", path="/live")])
        _, _, read = read_records(
            self.path, until=parse_when("2026-08-30T18:00:00+00:00"))
        self.assertEqual([p.name for p in read], ["requests.log.1"])


# --- grouping ---------------------------------------------------------------

class TestGrouping(unittest.TestCase):

    def test_a_connection_spanning_two_generations_groups_as_one(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "requests.log"
            _write(Path(tmp) / "requests.log.1",
                   [_rec(**{VM_INSPECT_LOG_REQ_FIELD: 1, "path": "/a"})])
            _write(path, [_rec(**{VM_INSPECT_LOG_REQ_FIELD: 2, "path": "/b"})])
            records, _, _ = read_records(path)
            groups = group_by_connection(records)
            self.assertEqual(len(groups), 1)
            self.assertEqual([r["path"] for r in groups[0][1]], ["/a", "/b"])

    def test_the_connection_level_record_heads_its_group(self):
        """It describes a decision taken before any request existed."""
        records = [_rec(**{VM_INSPECT_LOG_REQ_FIELD: 1}),
                   _rec(**{VM_INSPECT_LOG_REQ_FIELD: None, "mode": "splice"})]
        _, items = group_by_connection(records)[0]
        self.assertIsNone(items[0][VM_INSPECT_LOG_REQ_FIELD])

    def test_a_group_missing_its_first_request_is_partial(self):
        self.assertTrue(group_is_partial(
            [_rec(**{VM_INSPECT_LOG_REQ_FIELD: 3})]))
        self.assertFalse(group_is_partial(
            [_rec(**{VM_INSPECT_LOG_REQ_FIELD: 1})]))

    def test_a_connection_level_record_makes_a_group_complete(self):
        """That record IS the front of the connection, so nothing is missing."""
        self.assertFalse(group_is_partial(
            [_rec(**{VM_INSPECT_LOG_REQ_FIELD: None, "mode": "h2"})]))

    def test_the_marker_says_retained_or_filtered_and_not_the_other(self):
        """Calling a filtered view a retention gap is a false claim about the
        record; calling a retention gap a filtered view hides a real one."""
        records = [_rec(**{VM_INSPECT_LOG_REQ_FIELD: 3})]
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_egress._print_grouped(records, filtered=False)
        self.assertIn("not retained", buf.getvalue())
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_egress._print_grouped(records, filtered=True)
        self.assertIn("not shown", buf.getvalue())


# --- rendering and the command ----------------------------------------------

class TestRendering(unittest.TestCase):

    def test_a_null_field_renders_as_a_dash_not_as_none(self):
        line = format_record(_rec(host=None, status=None))
        self.assertNotIn("None", line)

    def test_the_query_is_off_the_default_line_and_on_the_grouped_one(self):
        record = _rec(query="key=sekrit")
        self.assertNotIn("sekrit", format_record(record))
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_egress._print_grouped([record], filtered=False)
        self.assertIn("sekrit", buf.getvalue())


class TestCommand(unittest.TestCase):

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.dir = Path(self._tmp.name) / "wl"
        self.dir.mkdir()
        self.path = self.dir / "requests.log"
        self.addCleanup(self._tmp.cleanup)
        config = unittest.mock.Mock()
        config.config = {"vm": {"network": {"egress": "filtered"}}}
        self._patches = [
            unittest.mock.patch.object(cmd_egress, "load_config_or_exit",
                                       return_value=config),
            unittest.mock.patch.object(cmd_egress, "vm_inspect_record_dir",
                                       return_value=self.dir),
            unittest.mock.patch.object(cmd_egress, "vm_inspect_record_path",
                                       return_value=self.path),
        ]
        for patch in self._patches:
            patch.start()
            self.addCleanup(patch.stop)

    def _run(self, **flags):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cmd_egress.cmd_egress(_args(**flags), None)
        return rc, out.getvalue(), err.getvalue()

    def test_an_uninspected_workload_is_a_sentence_not_an_empty_report(self):
        with unittest.mock.patch.object(cmd_egress, "vm_uses_inspect",
                                        return_value=False):
            rc, _, err = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("egress", err)

    def test_json_is_a_wrapper_so_no_records_differs_from_nothing_read(self):
        _write(self.path, [_rec()])
        _, out, _ = self._run(json=True)
        payload = json.loads(out)
        self.assertEqual(len(payload["records"]), 1)
        self.assertEqual(payload["malformed"], 0)
        self.assertEqual(len(payload["generations"]), 1)

        self.path.unlink()
        _, out, _ = self._run(json=True)
        self.assertEqual(json.loads(out)["generations"], [])

    def test_json_round_trips_a_field_this_reader_does_not_know(self):
        """A later rung's field has to reach a machine reader with no change
        here."""
        _write(self.path, [_rec(future_field="whatever")])
        _, out, _ = self._run(json=True)
        self.assertEqual(json.loads(out)["records"][0]["future_field"],
                         "whatever")

    def test_a_bad_filter_value_exits_two_and_names_the_valid_set(self):
        _write(self.path, [_rec()])
        rc, out, err = self._run(reason=["not allowed"])
        self.assertEqual(rc, 2)
        self.assertIn("not allowlisted", err)
        self.assertEqual(out, "")

    def test_no_records_and_no_match_read_differently(self):
        _write(self.path, [_rec()])
        _, out, _ = self._run(decision=["drop"])
        self.assertIn("No records matched", out)
        _write(self.path, [])
        _, out, _ = self._run()
        self.assertIn("No records in", out)

    def test_a_missing_record_says_so_rather_than_reporting_silence(self):
        rc, out, _ = self._run()
        self.assertEqual(rc, 0)
        self.assertIn("does not exist", out)

    def test_lines_takes_the_last_n_and_zero_takes_all(self):
        _write(self.path, [_rec(path=f"/{n}") for n in range(5)])
        _, out, _ = self._run(lines=2)
        self.assertNotIn("/0", out)
        self.assertIn("/4", out)
        _, out, _ = self._run(lines=0)
        self.assertIn("/0", out)

    def test_a_torn_line_is_reported_on_stderr_not_swallowed(self):
        self.path.write_text(json.dumps(_rec()) + "\n" + "{oops\n")
        rc, _, err = self._run()
        self.assertEqual(rc, 0)
        self.assertIn("unreadable line", err)

    def test_an_unreadable_directory_is_a_sentence_not_a_traceback(self):
        with unittest.mock.patch.object(cmd_egress, "_readable",
                                        return_value=False):
            rc, out, err = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("root", err)
        self.assertEqual(out, "")


class TestTheSubsetMarkerCountsMinusN(unittest.TestCase):
    """`-n` is a subset too, and the marker had no way to know it.

    A group whose earliest record is not request 1 is reported one of two
    ways: "not retained", meaning the record itself no longer holds them, or
    "not shown", meaning you asked for less than everything. `-n` DEFAULTS TO
    50 -- so before this, any workload with more than fifty records had its
    oldest group cut by the limit and then reported as a retention gap. That
    is a false claim about the guest's history, made by default, on exactly
    the workloads busy enough for somebody to be reading this.
    """

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.dir = Path(self._tmp.name) / "wl"
        self.dir.mkdir()
        self.path = self.dir / "requests.log"
        self.addCleanup(self._tmp.cleanup)
        config = unittest.mock.Mock()
        config.config = {"vm": {"network": {"egress": "filtered"}}}
        for patch in (
                unittest.mock.patch.object(cmd_egress, "load_config_or_exit",
                                           return_value=config),
                unittest.mock.patch.object(cmd_egress, "vm_inspect_record_dir",
                                           return_value=self.dir),
                unittest.mock.patch.object(cmd_egress, "vm_inspect_record_path",
                                           return_value=self.path)):
            patch.start()
            self.addCleanup(patch.stop)

    def _run(self, **flags):
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            cmd_egress.cmd_egress(_args(**flags), None)
        return out.getvalue()

    def _one_long_connection(self, count):
        _write(self.path, [_rec(**{VM_INSPECT_LOG_ID_FIELD: "aa",
                                   VM_INSPECT_LOG_REQ_FIELD: n})
                           for n in range(1, count + 1)])

    def test_a_group_cut_by_the_limit_is_not_called_a_retention_gap(self):
        self._one_long_connection(5)
        out = self._run(group=True, lines=3)
        self.assertNotIn("not retained", out)
        self.assertIn("not shown", out)

    def test_the_default_limit_counts_the_same_as_an_explicit_one(self):
        """Nobody types `-n 50`; it is what they get. A fix that only worked
        when the flag was given would leave the default -- the only value most
        of these reports are read at -- still lying."""
        self._one_long_connection(cmd_egress.LINES_DEFAULT + 5)
        out = self._run(group=True)
        self.assertNotIn("not retained", out)

    def test_a_real_retention_gap_still_reads_as_one(self):
        """The other direction, which is the one that matters: rendering a
        rotated-away history as a filtered view hides a real loss."""
        _write(self.path, [_rec(**{VM_INSPECT_LOG_ID_FIELD: "aa",
                                   VM_INSPECT_LOG_REQ_FIELD: n})
                           for n in (7, 8)])
        out = self._run(group=True)
        self.assertIn("not retained", out)


class TestAnUnreadableDirectoryIsNotReportedAsAbsent(unittest.TestCase):
    """The permission sentence was unreachable in the case it was written for.

    The record is 0600 under a 0700 directory under a 0700 `egress/`, so a
    non-root reader fails at a parent component. `Path.exists()` swallows that
    EACCES and answers False -- so the readability branch never ran, the read
    found nothing, and the operator was told the record `does not exist`. A
    false statement about the guest's history, handed to the person least able
    to check it.
    """

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.parent = Path(self._tmp.name) / "egress"
        self.parent.mkdir()
        self.dir = self.parent / "wl"
        self.dir.mkdir()

    def test_an_unsearchable_parent_reads_as_denied_not_missing(self):
        if os.geteuid() == 0:
            self.skipTest("root searches a 0700 directory regardless")
        self.parent.chmod(0o000)
        self.addCleanup(self.parent.chmod, 0o700)
        self.assertEqual(cmd_egress._record_dir_state(self.dir), "denied")

    def test_a_directory_that_is_simply_absent_reads_as_missing(self):
        """A VM that has never run must still get the quiet answer, not a
        permission error naming a fault that does not exist."""
        self.assertEqual(
            cmd_egress._record_dir_state(self.parent / "never-ran"), "missing")

    def test_a_readable_directory_reads_as_ok(self):
        self.assertEqual(cmd_egress._record_dir_state(self.dir), "ok")

    def test_an_unreadable_directory_that_exists_reads_as_denied(self):
        if os.geteuid() == 0:
            self.skipTest("root reads a 0000 directory regardless")
        self.dir.chmod(0o000)
        self.addCleanup(self.dir.chmod, 0o700)
        self.assertEqual(cmd_egress._record_dir_state(self.dir), "denied")


class TestRecordsWithNoIdDoNotMerge(unittest.TestCase):
    """Grouping is by connection; a record naming none belongs to none.

    Keying them all on the same missing value collapsed unrelated records --
    potentially from different connections entirely -- into one block rendered
    `id=-`, which reads as a single connection that did all of it.
    """

    def test_two_id_less_records_are_two_groups(self):
        groups = cmd_egress.group_by_connection(
            [_rec(**{VM_INSPECT_LOG_ID_FIELD: None, "host": "a.example"}),
             _rec(**{VM_INSPECT_LOG_ID_FIELD: None, "host": "b.example"})])
        self.assertEqual(len(groups), 2)
        self.assertEqual([key for key, _ in groups], [None, None])

    def test_records_that_do_have_an_id_still_group(self):
        groups = cmd_egress.group_by_connection(
            [_rec(**{VM_INSPECT_LOG_ID_FIELD: "aa"}),
             _rec(**{VM_INSPECT_LOG_ID_FIELD: None}),
             _rec(**{VM_INSPECT_LOG_ID_FIELD: "aa"})])
        self.assertEqual(len(groups), 2)
        by_key = {key: items for key, items in groups}
        self.assertEqual(len(by_key["aa"]), 2)
        self.assertEqual(len(by_key[None]), 1)


class TestAPrunedWindowIsNotAnAbsentRecord(unittest.TestCase):
    """`--since` older than every generation must not say the file is missing.

    `read_records` returns the generations it actually OPENED, and
    `_skip_generation` prunes on mtime before any of them are -- so keying the
    absence sentence on that list told an operator whose guest went quiet three
    days ago that the record `does not exist`, over a populated file sitting
    right there. Same shape as the permission finding: a false statement about
    the guest's history, offered to the person asking precisely because they
    cannot see it themselves.
    """

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.dir = root / "wl"
        self.dir.mkdir()
        self.path = self.dir / "requests.log"
        config = unittest.mock.Mock()
        config.config = {"vm": {"network": {"egress": "filtered"}}}
        for patch in (
                unittest.mock.patch.object(cmd_egress, "load_config_or_exit",
                                           return_value=config),
                unittest.mock.patch.object(cmd_egress, "vm_inspect_record_dir",
                                           return_value=self.dir),
                unittest.mock.patch.object(cmd_egress, "vm_inspect_record_path",
                                           return_value=self.path)):
            patch.start()
            self.addCleanup(patch.stop)

    def _run(self, **flags):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cmd_egress.cmd_egress(_args(**flags), None)
        return rc, out.getvalue(), err.getvalue()

    def _write_old(self):
        """One record three days old, in a file whose mtime matches it."""
        stamp = (datetime.datetime.now(datetime.UTC)
                 - datetime.timedelta(days=3))
        _write(self.path, [_rec(ts=stamp.isoformat().replace("+00:00", "Z"))])
        old = stamp.timestamp()
        os.utime(self.path, (old, old))

    def test_a_window_with_nothing_in_it_is_not_a_missing_file(self):
        self._write_old()
        rc, out, _ = self._run(since="2h")
        self.assertEqual(rc, 0)
        self.assertNotIn("does not exist", out)
        self.assertIn("No records matched", out)

    def test_a_genuinely_absent_record_still_says_so(self):
        rc, out, _ = self._run()
        self.assertEqual(rc, 0)
        self.assertIn("does not exist", out)

    def test_an_absent_record_asked_about_a_window_still_says_so(self):
        """The two causes of an empty read, told apart in the direction that
        matters as well: nothing on disk stays `does not exist` even when a
        time filter is what would have pruned it."""
        rc, out, _ = self._run(since="2h")
        self.assertIn("does not exist", out)

    def test_a_rotated_generation_outside_the_window_counts_as_existing(self):
        """The live file gone, only a rotated one left, and it is older than
        the window -- the state a workload that stopped days ago actually
        reaches."""
        self._write_old()
        self.path.rename(self.path.with_name(self.path.name + ".1"))
        old = (datetime.datetime.now() - datetime.timedelta(days=3)).timestamp()
        os.utime(self.path.with_name(self.path.name + ".1"), (old, old))
        _, out, _ = self._run(since="2h")
        self.assertNotIn("does not exist", out)


class TestTheJsonWrapperDisclosesTheLimit(unittest.TestCase):
    """`-n` applies to `--json` too, and defaults to 50.

    Without a key saying so, a machine reader asking for a busy workload's
    history receives fifty records and nothing at all indicating there were
    four thousand -- and concludes the guest made fifty requests. The grouped
    view says so in a sentence; this is the same disclosure in the shape a
    program reads.
    """

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.dir = root / "wl"
        self.dir.mkdir()
        self.path = self.dir / "requests.log"
        config = unittest.mock.Mock()
        config.config = {"vm": {"network": {"egress": "filtered"}}}
        for patch in (
                unittest.mock.patch.object(cmd_egress, "load_config_or_exit",
                                           return_value=config),
                unittest.mock.patch.object(cmd_egress, "vm_inspect_record_dir",
                                           return_value=self.dir),
                unittest.mock.patch.object(cmd_egress, "vm_inspect_record_path",
                                           return_value=self.path)):
            patch.start()
            self.addCleanup(patch.stop)

    def _payload(self, **flags):
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            cmd_egress.cmd_egress(_args(json=True, **flags), None)
        return json.loads(out.getvalue())

    def test_a_truncated_read_says_it_was_truncated(self):
        _write(self.path, [_rec(path=f"/{n}")
                           for n in range(cmd_egress.LINES_DEFAULT + 5)])
        payload = self._payload()
        self.assertTrue(payload["truncated"])
        self.assertEqual(payload["limit"], cmd_egress.LINES_DEFAULT)
        self.assertEqual(len(payload["records"]), cmd_egress.LINES_DEFAULT)

    def test_a_complete_read_says_it_was_complete(self):
        _write(self.path, [_rec(path=f"/{n}") for n in range(3)])
        payload = self._payload()
        self.assertFalse(payload["truncated"])
        self.assertEqual(len(payload["records"]), 3)

    def test_n_zero_reports_no_limit_at_all(self):
        _write(self.path, [_rec(path=f"/{n}")
                           for n in range(cmd_egress.LINES_DEFAULT + 5)])
        payload = self._payload(lines=0)
        self.assertIsNone(payload["limit"])
        self.assertFalse(payload["truncated"])
        self.assertEqual(len(payload["records"]),
                         cmd_egress.LINES_DEFAULT + 5)

    def test_the_flag_is_not_inferable_from_the_count(self):
        """Exactly `-n` records read is not evidence of truncation, and the
        wrapper must not make a reader guess from the length."""
        _write(self.path, [_rec(path=f"/{n}") for n in range(4)])
        payload = self._payload(lines=4)
        self.assertEqual(len(payload["records"]), 4)
        self.assertFalse(payload["truncated"])


class TestANegativeLineCountIsRefused(unittest.TestCase):
    """`selected[-limit:]` on a negative limit drops the OLDEST records.

    It is the opposite end of the record from the one `-n`'s help promises,
    and it hides them without a word. A value that cannot mean what it says is
    an error, like any other filter value that can select nothing.
    """

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.dir = root / "wl"
        self.dir.mkdir()
        self.path = self.dir / "requests.log"
        _write(self.path, [_rec(path=f"/{n}") for n in range(5)])
        config = unittest.mock.Mock()
        config.config = {"vm": {"network": {"egress": "filtered"}}}
        for patch in (
                unittest.mock.patch.object(cmd_egress, "load_config_or_exit",
                                           return_value=config),
                unittest.mock.patch.object(cmd_egress, "vm_inspect_record_dir",
                                           return_value=self.dir),
                unittest.mock.patch.object(cmd_egress, "vm_inspect_record_path",
                                           return_value=self.path)):
            patch.start()
            self.addCleanup(patch.stop)

    def _run(self, **flags):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cmd_egress.cmd_egress(_args(**flags), None)
        return rc, out.getvalue(), err.getvalue()

    def test_it_exits_two_rather_than_silently_dropping_the_oldest(self):
        rc, out, err = self._run(lines=-2)
        self.assertEqual(rc, 2)
        self.assertEqual(out, "")
        self.assertIn("-n -2", err)

    def test_a_positive_count_still_takes_the_last_n(self):
        rc, out, _ = self._run(lines=2)
        self.assertEqual(rc, 0)
        self.assertIn("/4", out)
        self.assertNotIn("/0", out)


if __name__ == "__main__":
    unittest.main()
