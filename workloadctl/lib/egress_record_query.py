"""The per-request record, read back: what `workloadctl egress` selects from.

The record is one JSON object per line in
`/var/log/workloadctl/egress/<name>/requests.log`, written by
`libexec/workload-inspect-listener` and rotated into gzipped generations
beside it. This module turns an operator's filters into a selection over
those lines -- parsing the times, resolving the filter values against the
closed vocabularies in egress_record, walking the generations, and grouping
by connection -- and raises EgressUsage for a value that could not select
anything. It prints nothing and never exits; cmd_egress renders what it
returns and owns the exit code.

BOTH SUBSTRATES, one tree. The listener is the same binary for a filtered
container as for a filtered VM, and the record path is keyed by workload name
and nothing else, so everything below is substrate-blind by construction.

THE RECORD IS PER WORKLOAD, NOT PER CONTAINER, and for a `pod`- or
`bridge`-mode workload that is a real limit rather than a wording choice. Every
container in such a workload runs under the one `_wl-<name>` uid and shares one
netns (`pod`) or one network (`bridge`), so the listener has no identity to
tell them apart with -- the uid IS the workload. A line here therefore says
"this workload asked for that", and a reader who takes it as naming a
particular container will attribute a request to the wrong one.

What an operator has instead: `host`, `path` and the connection `id` usually
separate the members in practice, since two containers in one pod rarely dial
the same host for the same path. When the distinction has to be structural --
one member is sandboxed and another is trusted -- the answer is to make the
sandboxed one its own workload, which gives it its own uid, its own policy and
its own record. That is the same reasoning the broker uses for its
one-instance-per-workload rule.

THE JOIN RUNS JOURNAL -> RECORD. An operator reads a refusal in `workloadctl
logs`, copies the `id=` token off it, and asks for that connection. So `--id`
takes the bare hex or the whole pasted token, and its pattern is built from
`LOG_ID_FIELD` rather than from a literal `id=` -- the standing constraint
against a second definition of a listener string, satisfied by construction.
The reverse direction is deliberately absent: the record already carries what
the journal line carries, and shelling out to journalctl from here would make
this a second renderer of the inspector's decisions.
"""

import datetime
import gzip
import json
import re
from pathlib import Path

from inspect_document import hostname_match
from egress_record import DROP_REASONS, LOG_ID_FIELD, LOG_REQ_FIELD

# `id=<hex>` as a journal line spells it, or the bare hex on its own. Built
# from the constant rather than from a literal, so a rename of the listener's
# field name fails the pin in tests/test_cmd_egress.py instead of quietly
# refusing every token an operator pastes.
_ID_TOKEN_RE = re.compile(
    rf"\A(?:{re.escape(LOG_ID_FIELD)}=)?([0-9a-fA-F]+)\Z")

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
            f"{text!r} is not a time — use 2h, 30m ago, YYYY-MM-DD, "
            "YYYY-MM-DDTHH:MM, or an ISO timestamp") from None
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
    matching nothing renders identically to a workload that never hit that
    refusal, so `--reason "not allowed"` would print an empty report and an
    operator would conclude the denial never happened.

    AN EXACT MATCH ALWAYS WINS, and that is not a tidiness rule: `not HTTP` is
    a prefix of `not HTTP (policy entry)`, and those two exist as separate
    reasons precisely because they need different operator responses. Without
    this branch the more common of the pair would be unselectable.
    """
    raw = str(value).strip()
    for reason in DROP_REASONS:
        if raw == reason:
            return reason
    lowered = raw.casefold()
    hits = [r for r in DROP_REASONS if lowered in r.casefold()]
    if len(hits) == 1:
        return hits[0]
    if not hits:
        raise EgressUsage(
            f"{value!r} is not a drop reason. Valid values:\n  "
            + "\n  ".join(DROP_REASONS))
    raise EgressUsage(
        f"{value!r} matches {len(hits)} drop reasons:\n  " + "\n  ".join(hits))


def resolve_id(value: str) -> str:
    """`id=a1b2c3d4e5f6` as pasted from a journal line, or the bare hex."""
    match = _ID_TOKEN_RE.match(str(value).strip())
    if not match:
        raise EgressUsage(
            f"{value!r} is not a connection id — paste the "
            f"{LOG_ID_FIELD}= token from a journal line, or its "
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
    bad line; a reader that skipped it silently would under-report the workload,
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
                record.get(LOG_ID_FIELD) or "").lower() not in filters["id"]:
            continue
        if filters["method"] and str(
                record.get("method") or "").upper() not in filters["method"]:
            continue
        if filters["status"] and not _matches_status(record, filters["status"]):
            continue
        if filters["host"]:
            host = record.get("host")
            # hostname_match is the shipped matcher, and both sides are
            # normalised inside it. A record with no host — a hello that never
            # gave one — cannot match a host pattern, and must not be included
            # by accident.
            if not isinstance(host, str) or not hostname_match(
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
    would collapse unrelated records from unrelated workloads' connections into
    one block under `id=-`, which reads as a single connection that did all of
    it. Only a writer bug produces one, and a writer bug is when this is read.
    """
    groups = {}
    for index, record in enumerate(records):
        key = record.get(LOG_ID_FIELD)
        groups.setdefault(key if key else ("", index), []).append(record)
    ordered = []
    for key, items in groups.items():
        if isinstance(key, tuple):
            key = None
        items.sort(key=lambda r: (r.get(LOG_REQ_FIELD) is not None,
                                  r.get(LOG_REQ_FIELD) or 0))
        ordered.append((key, items))
    return ordered


def group_is_partial(items) -> bool:
    """Whether this connection's earlier records are missing.

    A group whose lowest request ordinal is not 1 began before what we read.
    A group with a connection-level record is complete by construction: that
    record IS the front of the connection.
    """
    seqs = [r.get(LOG_REQ_FIELD) for r in items]
    if any(s is None for s in seqs):
        return False
    numbers = [s for s in seqs if isinstance(s, int)]
    return bool(numbers) and min(numbers) != 1
