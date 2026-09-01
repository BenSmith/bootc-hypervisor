"""
cmd_egress — read back the per-request record the inspector writes.

Rung 5 T2. The record itself is T1's: one JSON object per line in
`/var/log/workloadctl/egress/<name>/requests.log`, `0600` under a `0700`
directory, written by `libexec/workload-vm-inspect-listener`. This is the only
reader of it.

A TOP-LEVEL VERB, not a subcommand of `inspect`. There is no `workloadctl
inspect` to hang one on — `lib/cmd_inspect.py` is the module behind `list` and
`status`, named for podman-style introspection and predating egress filtering
entirely — so a subcommand there would make one module name mean two things.
`egress` sits beside `logs` and `pcap` instead, which is the right
neighbourhood: all three answer "what did this workload do", from three
vantages, and this is the one that answers what `pcap` cannot, because the
bytes on the wire are ciphertext and the decision was taken here.

THE JOIN RUNS JOURNAL -> RECORD. An operator reads a refusal in `workloadctl
logs`, copies the `id=` token off it, and asks for that connection. So `--id`
takes the bare hex or the whole pasted token, and its pattern is built from
`VM_INSPECT_LOG_ID_FIELD` rather than from a literal `id=` — the standing
constraint against a second definition of a listener string, satisfied by
construction. The reverse direction is deliberately absent: the record already
carries what the journal line carries, and shelling out to journalctl from here
would make this a second renderer of the inspector's decisions.
"""

import argparse
import datetime
import gzip
import json
import os
import re
import shutil
import sys
from pathlib import Path

import cli_log
from cmd_validate import load_config_or_exit
from vm import (
    VM_INSPECT_LOG_ID_FIELD,
    VM_INSPECT_LOG_REQ_FIELD,
    VM_INSPECT_RECORD_DECISIONS,
    VM_INSPECT_RECORD_MODES,
    VM_INSPECT_RECORD_PLANES,
    VM_INSPECT_RECORD_REASONS,
    vm_hostname_match,
    vm_inspect_record_dir,
    vm_inspect_record_path,
    vm_uses_inspect,
)

LINES_DEFAULT = 50

# `id=<hex>` as a journal line spells it, or the bare hex on its own. Built
# from the constant rather than from a literal, so a rename of the listener's
# field name fails the pin in tests/test_cmd_egress.py instead of quietly
# refusing every token an operator pastes.
_ID_TOKEN_RE = re.compile(
    rf"\A(?:{re.escape(VM_INSPECT_LOG_ID_FIELD)}=)?([0-9a-fA-F]+)\Z")

_STATUS_CLASS_RE = re.compile(r"\A([1-5])xx\Z", re.IGNORECASE)

_RELATIVE_RE = re.compile(r"\A-?(\d+)\s*([smhdw])(?:\s+ago)?\Z", re.IGNORECASE)
_RELATIVE_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


# --- errors -----------------------------------------------------------------

class EgressUsage(Exception):
    """A filter value that cannot select anything. Reported, never raised out."""


# --- time -------------------------------------------------------------------

def parse_when(text: str) -> datetime.datetime:
    """`--since` / `--until`: a relative offset or an ISO timestamp.

    `2h`, `-2h` and `2h ago` are the same thing, and are what an operator
    actually types. An absolute value is ISO-8601: a date, or a date and a
    time, with or without an offset.

    A NAIVE VALUE IS LOCAL, and converted here. The record's `ts` is UTC —
    T1 chose that deliberately, since a record read on a host whose timezone
    changed has to stay comparable — but nobody remembers an incident in UTC.
    journalctl's `--since` reads naive input as local for the same reason, and
    an operator moving between the two commands must not have to change how
    they write a time.
    """
    raw = str(text).strip()
    now = datetime.datetime.now(datetime.UTC)
    if raw.lower() in ("now", "today"):
        return (now if raw.lower() == "now"
                else now.astimezone().replace(hour=0, minute=0, second=0,
                                              microsecond=0))
    match = _RELATIVE_RE.match(raw)
    if match:
        seconds = int(match.group(1)) * _RELATIVE_UNITS[match.group(2).lower()]
        return now - datetime.timedelta(seconds=seconds)
    try:
        parsed = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        raise EgressUsage(
            f"{text!r} is not a time — use 2h, 30m ago, 2026-08-31, "
            "2026-08-31T14:00, or an ISO timestamp") from None
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    return parsed.astimezone(datetime.UTC)


def record_time(record: dict) -> datetime.datetime | None:
    """One record's `ts` as an aware UTC datetime, or None if unreadable."""
    raw = record.get("ts")
    if not isinstance(raw, str):
        return None
    try:
        parsed = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.UTC)
    return parsed.astimezone(datetime.UTC)


# --- filter values ----------------------------------------------------------

def resolve_reason(value: str) -> str:
    """One `--reason` value against the closed set, exact or unambiguous.

    The reasons are sentences (`host does not match the server name
    (allowlisted)`), which nobody types, so a bare `choices=` would be a filter
    an operator cannot use. A unique case-insensitive substring resolves to the
    reason it names, and anything matching zero or more than one is an error
    listing the candidates — which is the property that matters. A filter value
    matching nothing renders identically to a guest that never hit that
    refusal, so `--reason "not allowed"` would print an empty report and an
    operator would conclude the denial never happened.

    AN EXACT MATCH ALWAYS WINS, and that is not a tidiness rule: `not HTTP` is
    a prefix of `not HTTP (policy entry)`, and those two exist as separate
    reasons precisely because they need different operator responses. Without
    this branch the more common of the pair would be unselectable.
    """
    raw = str(value).strip()
    for reason in VM_INSPECT_RECORD_REASONS:
        if raw == reason:
            return reason
    lowered = raw.casefold()
    hits = [r for r in VM_INSPECT_RECORD_REASONS if lowered in r.casefold()]
    if len(hits) == 1:
        return hits[0]
    if not hits:
        raise EgressUsage(
            f"{value!r} is not a drop reason. Valid values:\n  "
            + "\n  ".join(VM_INSPECT_RECORD_REASONS))
    raise EgressUsage(
        f"{value!r} matches {len(hits)} drop reasons:\n  " + "\n  ".join(hits))


def resolve_id(value: str) -> str:
    """`id=a1b2c3d4e5f6` as pasted from a journal line, or the bare hex."""
    match = _ID_TOKEN_RE.match(str(value).strip())
    if not match:
        raise EgressUsage(
            f"{value!r} is not a connection id — paste the "
            f"{VM_INSPECT_LOG_ID_FIELD}= token from a journal line, or its "
            "hex alone")
    return match.group(1).lower()


def resolve_status(value: str):
    """An exact status, or a `4xx`-style class. Returns an int or a class int."""
    raw = str(value).strip()
    match = _STATUS_CLASS_RE.match(raw)
    if match:
        return ("class", int(match.group(1)))
    try:
        return ("exact", int(raw))
    except ValueError:
        raise EgressUsage(
            f"{value!r} is not a status — use 403, or 4xx for the class"
        ) from None


# --- the generations --------------------------------------------------------

def generations(path: Path) -> list[Path]:
    """The record's rotated files and the live one, OLDEST FIRST.

    logrotate leaves `requests.log`, `requests.log.1` (uncompressed, because
    the snippet sets `delaycompress` so the listener's still-open fd is not
    compressed out from under it) and `requests.log.N.gz` behind it. Reading
    only the live file would make "no records" the answer to anything older
    than the last rotation — which is the whole window this record exists to
    cover, since the question it answers is usually asked days after the fact.
    """
    rotated = []
    parent = path.parent
    try:
        names = list(parent.iterdir())
    except OSError:
        names = []
    for candidate in names:
        if not candidate.name.startswith(path.name + "."):
            continue
        suffix = candidate.name[len(path.name) + 1:]
        if suffix.endswith(".gz"):
            suffix = suffix[:-3]
        if not suffix.isdigit():
            continue
        rotated.append((int(suffix), candidate))
    # Descending generation number is ascending age -> oldest first.
    ordered = [p for _, p in sorted(rotated, key=lambda item: -item[0])]
    if path.exists():
        ordered.append(path)
    return ordered


def _open_generation(path: Path):
    if path.name.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _skip_generation(path: Path, since, until) -> bool:
    """Whether a generation can be dropped without reading it.

    `--since` prunes on MTIME, which needs no decompression: a rotated file
    stops being appended to at the moment it is rotated, so a generation whose
    mtime precedes `--since` cannot hold a record after it. `compress` rewrites
    the `.gz` afterwards and only moves that mtime forward, so the test stays
    conservative in the safe direction — it may read a generation it did not
    need to, never skip one it did.

    `--until` costs one line: the first record in a generation is its earliest,
    and gzip streams, so this decompresses a few bytes rather than a day.
    """
    if since is not None:
        try:
            mtime = datetime.datetime.fromtimestamp(
                path.stat().st_mtime, datetime.UTC)
        except OSError:
            mtime = None
        if mtime is not None and mtime < since:
            return True
    if until is not None:
        first = _first_record_time(path)
        if first is not None and first > until:
            return True
    return False


def _first_record_time(path: Path):
    try:
        with _open_generation(path) as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    return None
                if isinstance(record, dict):
                    return record_time(record)
                return None
    except OSError:
        return None
    return None


def read_records(path: Path, *, since=None, until=None):
    """Every record across every generation, oldest first, plus a torn count.

    A TORN LINE IS COUNTED, NOT FATAL. The listener writes each line with one
    `os.write` under a lock, so a partial line means the host lost power
    mid-write or something outside this project truncated the file. A reader
    that raised on it would make the whole retained history unreadable over one
    bad line; a reader that skipped it silently would under-report the guest,
    which is worse than either. So it is counted and the count is printed.
    """
    records = []
    malformed = 0
    read = []
    for generation in generations(path):
        if _skip_generation(generation, since, until):
            continue
        read.append(generation)
        try:
            with _open_generation(generation) as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except ValueError:
                        malformed += 1
                        continue
                    if not isinstance(record, dict):
                        malformed += 1
                        continue
                    records.append(record)
        except (OSError, EOFError, gzip.BadGzipFile):
            # A generation being rotated out from under us, or a `.gz` still
            # being written. What was already read stands.
            continue
    return records, malformed, read


# --- filtering --------------------------------------------------------------

def _matches_status(record, wanted) -> bool:
    status = record.get("status")
    if not isinstance(status, int):
        return False
    for kind, value in wanted:
        if kind == "exact" and status == value:
            return True
        if kind == "class" and status // 100 == value:
            return True
    return False


def build_filters(args) -> dict:
    """The parsed, validated filter set. Raises EgressUsage on a bad value."""
    return {
        "decision": set(args.decision or ()),
        "mode": set(args.mode or ()),
        "plane": set(args.plane or ()),
        "reason": {resolve_reason(v) for v in (args.reason or ())},
        "id": {resolve_id(v) for v in (args.id or ())},
        "host": list(args.host or ()),
        "status": [resolve_status(v) for v in (args.status or ())],
        "method": {str(v).upper() for v in (args.method or ())},
        "since": parse_when(args.since) if args.since else None,
        "until": parse_when(args.until) if args.until else None,
    }


def filters_active(filters: dict) -> bool:
    """Whether anything was asked for. Distinguishes two kinds of gap.

    A group missing its first request means "the earlier records were rotated
    away" when nothing was filtered, and "you asked for a subset" when
    something was. Rendering one as the other makes a false claim about
    retention, so the marker's wording is chosen from this.

    NOT THE WHOLE ANSWER: `-n` is a subset too, and it is not in here because
    it is not a filter over records -- see cmd_egress(), which ORs this with
    its own truncation before handing the answer to the grouped view.
    """
    return any(v for v in filters.values())


def select(records, filters):
    """AND across fields, OR within one — the shape `pcap`'s repeatable `-i` set."""
    out = []
    for record in records:
        if filters["decision"] and record.get("decision") not in filters["decision"]:
            continue
        if filters["mode"] and record.get("mode") not in filters["mode"]:
            continue
        if filters["plane"] and record.get("plane") not in filters["plane"]:
            continue
        if filters["reason"] and record.get("reason") not in filters["reason"]:
            continue
        if filters["id"] and str(
                record.get(VM_INSPECT_LOG_ID_FIELD) or "").lower() not in filters["id"]:
            continue
        if filters["method"] and str(
                record.get("method") or "").upper() not in filters["method"]:
            continue
        if filters["status"] and not _matches_status(record, filters["status"]):
            continue
        if filters["host"]:
            host = record.get("host")
            # vm_hostname_match is the shipped matcher, and both sides are
            # normalised inside it. A record with no host — a hello that never
            # gave one — cannot match a host pattern, and must not be included
            # by accident.
            if not isinstance(host, str) or not vm_hostname_match(
                    host, filters["host"]):
                continue
        if filters["since"] or filters["until"]:
            when = record_time(record)
            if when is None:
                continue
            if filters["since"] and when < filters["since"]:
                continue
            if filters["until"] and when > filters["until"]:
                continue
        out.append(record)
    return out


def group_by_connection(records):
    """[(id, [records])], connections in first-appearance order.

    Within a connection the connection-level record comes first — it has no
    `req`, because it describes a decision taken before any request existed
    (a bump, an unreadable hello, a splice, an h2 session), and it is the
    group's header rather than a peer of the requests it precedes.

    A RECORD WITH NO ID IS ITS OWN GROUP. Grouping is by connection, and a
    record that names no connection belongs to none -- keying them all on None
    would collapse unrelated records from unrelated guests' connections into
    one block under `id=-`, which reads as a single connection that did all of
    it. Only a writer bug produces one, and a writer bug is when this is read.
    """
    groups = {}
    for index, record in enumerate(records):
        key = record.get(VM_INSPECT_LOG_ID_FIELD)
        groups.setdefault(key if key else ("", index), []).append(record)
    ordered = []
    for key, items in groups.items():
        if isinstance(key, tuple):
            key = None
        items.sort(key=lambda r: (r.get(VM_INSPECT_LOG_REQ_FIELD) is not None,
                                  r.get(VM_INSPECT_LOG_REQ_FIELD) or 0))
        ordered.append((key, items))
    return ordered


def group_is_partial(items) -> bool:
    """Whether this connection's earlier records are missing.

    A group whose lowest request ordinal is not 1 began before what we read.
    A group with a connection-level record is complete by construction: that
    record IS the front of the connection.
    """
    seqs = [r.get(VM_INSPECT_LOG_REQ_FIELD) for r in items]
    if any(s is None for s in seqs):
        return False
    numbers = [s for s in seqs if isinstance(s, int)]
    return bool(numbers) and min(numbers) != 1


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
    ident = _cell(record.get(VM_INSPECT_LOG_ID_FIELD))
    seq = record.get(VM_INSPECT_LOG_REQ_FIELD)
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
        print(f"{VM_INSPECT_LOG_ID_FIELD}={_cell(ident)}"
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
    record `does not exist`. That is a false statement about the guest's
    history offered to the person least able to check it, and the sentence
    written for them was unreachable in exactly their case.

    os.stat raises the two apart: EACCES anywhere along the path is
    PermissionError, a genuinely absent directory is FileNotFoundError. A VM
    that has simply never run still reads `missing` and still gets the quiet
    answer.
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

    if not vm_uses_inspect(config.config):
        cli_log.error(
            f"{workload} has no inspected egress, so there is no request "
            "record. Egress filtering is [vm.network].egress = \"filtered\" "
            "on a VM workload without a bridge.")
        return 1

    directory = vm_inspect_record_dir(workload)
    path = vm_inspect_record_path(workload)

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
        # the guest made fifty requests. The grouped view says so in a
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
    # — so keying the absence sentence on it told an operator whose guest went
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
                        choices=list(VM_INSPECT_RECORD_DECISIONS),
                        help="Repeatable")
    parser.add_argument("--mode", action="append",
                        choices=list(VM_INSPECT_RECORD_MODES),
                        help="Repeatable")
    parser.add_argument("--plane", action="append",
                        choices=list(VM_INSPECT_RECORD_PLANES),
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
                        help="2h, 30m ago, 2026-08-31T14:00 (naive is local)")
    parser.add_argument("--until", metavar="TIME", help="Same spellings")
    parser.add_argument("workload", metavar="WORKLOAD", help="Workload name")
