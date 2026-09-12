"""
cmd_egress — read back the per-request record the inspector writes.

Rung 5 T2. The record itself is T1's: one JSON object per line in
`/var/log/workloadctl/egress/<name>/requests.log`, `0600` under a `0700`
directory, written by `libexec/workload-inspect-listener`. The selection over
it -- times, filter values, generations, grouping -- is egress_record_query;
this module is the refusal for a workload with no inspector, the rendering,
and the exit code. The refusal is the only substrate-shaped thing here, since
the two trigger spellings genuinely differ and the reader is keyed by
workload name alone.

A TOP-LEVEL VERB, not a subcommand of `inspect`. There is no `workloadctl
inspect` to hang one on — `lib/cmd_inspect.py` is the module behind `list` and
`status`, named for podman-style introspection and predating egress filtering
entirely — so a subcommand there would make one module name mean two things.
`egress` sits beside `logs` and `pcap` instead, which is the right
neighbourhood: all three answer "what did this workload do", from three
vantages, and this is the one that answers what `pcap` cannot, because the
bytes on the wire are ciphertext and the decision was taken here.
"""

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

import cli_log
from cmd_validate import load_config_or_exit
from substrate import get_substrate
from egress_record import (
    LOG_ID_FIELD,
    LOG_REQ_FIELD,
    RECORD_DECISIONS,
    RECORD_MODES,
)
from egress_plane import PLANES
from egress_policy import inspect_record_dir, inspect_record_path
from egress_record_query import (
    EgressUsage,
    build_filters,
    filters_active,
    generations,
    group_by_connection,
    group_is_partial,
    read_records,
    select,
)

LINES_DEFAULT = 50


# --- rendering --------------------------------------------------------------

def _cell(value, dash="-") -> str:
    if value is None or value == "":
        return dash
    return str(value)


def format_record(record: dict) -> str:
    """One line. The query is not a column — it is in `--json` and `--group`.

    Not elided for secrecy: the sink is private and the query is recorded on
    purpose, because "what did this agent send" is not answerable without it.
    It is off the default line because a query is frequently longer than a
    terminal and would push every other column off the screen.
    """
    ident = _cell(record.get(LOG_ID_FIELD))
    seq = record.get(LOG_REQ_FIELD)
    ident = f"{ident}/{seq}" if seq is not None else f"{ident}/-"
    target = " ".join(x for x in (record.get("method"), record.get("path")) if x)
    duration = record.get("duration_ms")
    return "  ".join((
        _cell(record.get("ts")),
        f"{ident:<15}",
        f"{_cell(record.get('decision')):<7}",
        f"{_cell(record.get('mode')):<9}",
        f"{_cell(record.get('host')):<30}",
        f"{_cell(target):<40}",
        f"{_cell(record.get('status')):>5}",
        f"{duration:.0f}ms" if isinstance(duration, (int, float)) else "-",
    ))


def _print_clipped(line: str) -> None:
    width = shutil.get_terminal_size(fallback=(200, 24)).columns
    print(line if len(line) <= width else line[:width - 1] + "…")


def _print_flat(records) -> None:
    for record in records:
        _print_clipped(format_record(record))


def _print_grouped(records, *, filtered: bool) -> None:
    first = True
    for ident, items in group_by_connection(records):
        if not first:
            print()
        first = False
        print(f"{LOG_ID_FIELD}={_cell(ident)}"
              f"  ({len(items)} record{'s' if len(items) != 1 else ''})")
        if group_is_partial(items):
            print("  (earlier records not shown — filtered or limited by -n)"
                  if filtered
                  else "  (earlier records not retained)")
        for record in items:
            _print_clipped("  " + format_record(record))
            query = record.get("query")
            if query:
                _print_clipped(f"    ?{query}")
            reason = record.get("reason")
            if reason:
                _print_clipped(f"    reason: {reason}")
            upstream = record.get("upstream")
            if upstream:
                _print_clipped(f"    upstream: {upstream}")


# --- the command ------------------------------------------------------------

def _readable(directory: Path) -> bool:
    """Whether this uid can even look inside the per-workload directory.

    The record is 0600 under a 0700 directory under a 0700 `egress/`, so a
    non-root operator fails at the DIRECTORY on the way in. Checked rather than
    caught so the failure is a sentence: uncaught, it is a traceback out of
    iterdir() two frames deep, and a traceback is indistinguishable from the
    feature being broken.

    Not require_root(): that guard is for verbs that mutate, and this one only
    reads. The workload's own uid can read its record and is not root.
    """
    return os.access(directory, os.R_OK | os.X_OK)


def _record_dir_state(directory: Path) -> str:
    """`ok`, `missing`, or `denied` for the per-workload record directory.

    STAT, NOT `Path.exists()`. `exists()` swallows every OSError and answers
    False, so for the case this whole guard exists for -- a non-root operator,
    where `egress/` is 0700 and not searchable -- it reported the directory as
    absent, the readability branch never ran, and the operator was told the
    record `does not exist`. That is a false statement about the workload's
    history offered to the person least able to check it, and the sentence
    written for them was unreachable in exactly their case.

    os.stat raises the two apart: EACCES anywhere along the path is
    PermissionError, a genuinely absent directory is FileNotFoundError. A
    workload that has simply never run still reads `missing` and still gets
    the quiet answer.
    """
    try:
        os.stat(directory)
    except PermissionError:
        return "denied"
    except OSError:
        return "missing"
    return "ok" if _readable(directory) else "denied"


def cmd_egress(args, manager):
    """Read back one workload's per-request egress record."""
    json_mode = bool(getattr(args, "json", False))
    workload, _, _container = str(args.workload).partition("/")
    config = load_config_or_exit(workload, json_mode=json_mode)

    # Routed through the substrate predicate (G4 in the container
    # egress-parity build spec): everything below keys purely on workload
    # name (inspect_record_dir/_path), nothing VM-specific, so this
    # already generalises to a container once one is actually inspected.
    if not get_substrate(config, manager).uses_inspect():
        cli_log.error(
            f"{workload} has no inspected egress, so there is no request "
            "record. Egress filtering is a [network] trigger on a "
            "container, or [vm.network].egress = \"filtered\" on a VM "
            "without a bridge.")
        return 1

    directory = inspect_record_dir(workload)
    path = inspect_record_path(workload)

    if _record_dir_state(directory) == "denied":
        cli_log.error(
            f"cannot read {directory} as uid {os.geteuid()} — the request "
            "record is readable by root and the workload user only. Re-run "
            "as root.")
        return 1

    try:
        filters = build_filters(args)
    except EgressUsage as exc:
        cli_log.error(str(exc))
        return 2

    # A NEGATIVE `-n` IS REFUSED, not interpreted. `selected[-limit:]` on a
    # negative limit is `selected[N:]` — it drops the N OLDEST records and
    # shows everything after them, which is the opposite end of the record from
    # the one the flag's own help promises, and it does it silently. Hiding
    # records without saying so is the failure this whole reader is careful
    # about; a value that cannot mean what it says is an error, exactly like a
    # filter value that can select nothing.
    limit = getattr(args, "lines", LINES_DEFAULT)
    if isinstance(limit, int) and limit < 0:
        cli_log.error(
            f"-n {limit} is not a count — use a positive number of records, "
            "or 0 for all")
        return 2

    try:
        records, malformed, read = read_records(
            path, since=filters["since"], until=filters["until"])
    except PermissionError:
        cli_log.error(
            f"cannot read {path} as uid {os.geteuid()} — the request record "
            "is readable by root and the workload user only. Re-run as root.")
        return 1

    selected = select(records, filters)
    # `-n` IS A SUBSET, and the grouped view has to be told so. The marker on a
    # group missing its first request says "not retained" when nothing was
    # asked for and "not shown" when something was, and `-n` defaults to 50 --
    # so without this, any workload with more than fifty records had its oldest
    # group cut here and then reported as a retention gap. That is the false
    # claim about the record filters_active() was written to prevent, arriving
    # through the one filter it did not count.
    truncated = bool(limit) and len(selected) > limit
    if limit:
        selected = selected[-limit:]

    if json_mode:
        # A WRAPPER, not a bare array, for T3's reason: a machine reader has to
        # be able to tell "this workload made no requests" from "nothing was
        # read", and an empty list says both.
        # `limit` AND `truncated` ARE PART OF THE WRAPPER, for the reason the
        # wrapper exists at all. `-n` defaults to 50 and applies here exactly
        # as it does to the printed views, so without these two keys a machine
        # reader asking for a busy workload's history receives fifty records
        # and nothing at all saying there were four thousand — and concludes
        # the workload made fifty requests. The grouped view says so in a
        # sentence; this is the same disclosure in the shape a program reads.
        # Stated rather than inferable: `len(records) == limit` is a coincidence
        # a reader should not have to gamble on.
        print(json.dumps({
            "workload": workload,
            "generations": [str(p) for p in read],
            "limit": limit or None,
            "truncated": truncated,
            "records": selected,
            "malformed": malformed,
        }, indent=2))
        return 0

    # `read` IS NOT `exists`. It is the generations this call actually opened,
    # and _skip_generation prunes on `--since`/`--until` before any of them are
    # — so keying the absence sentence on it told an operator whose workload went
    # quiet three days ago that the record `does not exist`, over a populated
    # file they could have read with `cat`. The existence question is answered
    # by the generation list itself, evaluated only once `read` is already
    # empty. A record that exists but held nothing in the window falls through
    # to `No records matched.` below, which is true: pruning cannot happen
    # unless a time filter was given, so filters_active() is set by
    # construction on exactly this path.
    if not read and not generations(path):
        print(f"No request record for {workload} yet ({path} does not exist).")
        return 0
    if not selected:
        print("No records matched." if filters_active(filters)
              else f"No records in {path}.")
    elif getattr(args, "group", False):
        _print_grouped(selected,
                       filtered=filters_active(filters) or truncated)
    else:
        _print_flat(selected)

    if malformed:
        print(f"\n{malformed} unreadable line(s) skipped.", file=sys.stderr)
    return 0


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """`egress`'s flags. Declared here so the vocabularies stay beside the reader."""
    parser.add_argument("-n", "--lines", type=int, metavar="N",
                        default=LINES_DEFAULT,
                        help=f"Show last N records, 0 for all "
                             f"(default: {LINES_DEFAULT})")
    parser.add_argument("-g", "--group", action="store_true",
                        help="Group by connection, with query and reason")
    parser.add_argument("--json", action="store_true",
                        help="Print the record objects verbatim")
    parser.add_argument("--id", action="append", metavar="ID",
                        help="Connection id, as pasted from a journal line. "
                             "Repeatable")
    parser.add_argument("--decision", action="append",
                        choices=list(RECORD_DECISIONS),
                        help="Repeatable")
    parser.add_argument("--mode", action="append",
                        choices=list(RECORD_MODES),
                        help="Repeatable")
    parser.add_argument("--plane", action="append",
                        choices=[p.label for p in PLANES],
                        help="Repeatable")
    parser.add_argument("--reason", action="append", metavar="REASON",
                        help="Drop reason, or an unambiguous part of one. "
                             "Repeatable")
    parser.add_argument("--host", action="append", metavar="PATTERN",
                        help="Host, fnmatch pattern. Repeatable")
    parser.add_argument("--method", action="append", metavar="METHOD",
                        help="HTTP method. Repeatable")
    parser.add_argument("--status", action="append", metavar="STATUS",
                        help="403, or 4xx for the class. Repeatable")
    parser.add_argument("--since", metavar="TIME",
                        help="2h, 30m ago, YYYY-MM-DDTHH:MM (naive is local)")
    parser.add_argument("--until", metavar="TIME", help="Same spellings")
    parser.add_argument("workload", metavar="WORKLOAD", help="Workload name")
