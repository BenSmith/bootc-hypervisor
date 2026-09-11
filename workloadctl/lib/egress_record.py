#!/usr/bin/env python3
"""The egress inspector's record: what it refuses, what it writes, and the
file it writes to.

The vocabulary of one refusal (`DROP_*`, `DROP_REASONS`, the per-host subset),
the shape of one line of the per-request record (`RECORD_FIELDS` and the
closed sets three of its fields draw from), and the writer (`Record`,
`RequestLog`). Defined once, here, and read by everything on both sides of
the file: the listener writes it, `workloadctl egress` renders and filters
it, `diagnose` reads the counters keyed by the same strings.

They used to be spelled twice -- once in the listener, once in
egress_policy for the readers -- because the listener is an extension-less
entrypoint nothing in lib/ can import, and each pair was held together by a
pin test. A drift turned a real refusal into a figure that read zero, which
is indistinguishable from a refusal that never fired; the pins were the
guard, and moving the definitions to where both sides can import them is
what makes the pins unnecessary.

Where the record file lives (`INSPECT_RECORD_ROOT`, `inspect_record_path`)
stays in egress_policy beside the rest of the inspector's paths.

Installed to /usr/libexec/workloadctl/egress_record.py.
"""

import datetime
import json
import os
import threading
import time


# The two field names that tie one of the inspector's journal lines to the
# per-request record written beside it. `id` is per CONNECTION and `req` is
# the ordinal within it, so a reader selecting on `id` alone gets every
# decision taken on one connection in order. Neither can be replaced by
# `peer=`, which the listener also logs: a source port repeats across the
# requests on one keep-alive connection and is reused by the kernel after
# close, so it groups the wrong lines together and splits the right ones
# apart.
LOG_ID_FIELD = "id"
LOG_REQ_FIELD = "req"


def format_endpoint(addr):
    """host:port, bracketing the host for the IPv6 listeners."""
    host, port = addr[0], addr[1]
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


# Every reason a connection or a request is refused, named once. The listener's
# call sites index into these rather than passing a literal, because
# `Counters.record_drop` counts a drop it cannot classify in `dispositions`
# either way: a reason string that reached a call site without reaching this
# tuple would leave the two maps disagreeing with nothing to say so, which is
# the exact failure the pre-seeded `drop_reasons` exists to prevent. Adding a
# reason means adding it here.
#
# DROP_REASONS IS THE WHOLE SET, and `workloadctl egress --reason` validates
# against it. A closed set is the point: a reason value that matches nothing
# renders identically to a guest that never hit that refusal, so `--reason
# "not allowed"` for `not allowlisted` would print an empty report and an
# operator would conclude the denial never happened. Validated, it is an
# argparse error naming the valid values instead. This matters more since the
# guest-facing refusal body was made generic: the guest is told nothing about
# WHY, so `reason` in the record is the only place a not-allowlisted denial is
# distinguishable from a not-permitted one.
DROP_NOT_ALLOWLISTED = "not allowlisted"
DROP_NO_NAME = "no readable name"
DROP_UNREADABLE_REQUEST = "unreadable request"
DROP_UNREACHABLE = "upstream unreachable"
DROP_INTERNAL = "internal destination"
DROP_CEILING = "connection ceiling reached"
# Connection-level like DROP_CEILING, and refused for the same reason: decided
# before any byte is read, so it never reaches a plane or a policy. The
# caller's uid is not this workload's; the listener identifies callers through
# peer_identity, `workload_filter` is the primary control and this is the
# layer behind it.
DROP_FOREIGN_CALLER = "caller is not this workload"
DROP_RELAY_FAILED = "relay failed"
DROP_TIMED_OUT = "timed out"
DROP_UNVERIFIED = "upstream certificate unverified"
DROP_CLIENT_CERT = "upstream wants a client certificate"
DROP_MISDIRECTED = "host does not match the server name"
# The same binding rejection where the name inside the session IS on this
# workload's allowlist, and the split is the whole value of the figure.
#
# §4 gives the count one job: a non-zero value is either an attack or a broken
# assumption in §4, and an operator has to tell which AT A GLANCE. Merged, they
# cannot. A guest reusing an authorised session to reach a name it was never
# given is the attack the binding exists to close, and the name it picks is on
# no list. A client reusing one connection across two names that resolve to the
# same address -- ordinary connection coalescing, which no client asks
# permission for -- produces the identical mismatch with both names allowlisted
# and nothing adversarial happening. One figure for both reads every coalescing
# client as an intrusion, which is how an alarm stops being read.
#
# Both strings begin "host does not match the server name" so a grep for the
# reason still finds both, the convention `not HTTP` set one tier earlier.
#
# The guest is told the same thing either way -- a 421 naming the session's
# name -- because the split is FOR THE OPERATOR and changing the body would
# only tell the guest which of its guesses were on the list.
DROP_MISDIRECTED_LISTED = "host does not match the server name (allowlisted)"
DROP_THROTTLED = "mint rationed"
DROP_MINT_FAILED = "could not mint a leaf"
DROP_NOT_HTTP = "not HTTP"
# The same refusal on a host a [[vm.network.policy]] entry names, kept apart
# because the operator's next move differs. Plain `not HTTP` is one line away
# from working -- add the host to [[vm.network.splice]]. This one is two, and
# the second is a DELETION: `validate` refuses a host that is in both `splice`
# and `policy`, so the entry whose `methods` and `paths` can never run has to
# go with it. An operator reading a single merged figure cannot tell which of
# their hosts is in which situation, and the two-line one is the one whose
# config states an intention the wire has already contradicted.
#
# Both strings begin "not HTTP" so a grep for the reason still finds both.
DROP_NOT_HTTP_POLICY = "not HTTP (policy entry)"
DROP_NOT_PERMITTED = "not permitted by policy"
DROP_NOT_H2 = "not HTTP/2"

# The dial to this workload's own credential broker failed, and it is NOT
# DROP_UNREACHABLE. "The provider is down" and "this workload's credential
# broker is down" need different operator responses -- the first is somebody
# else's outage, the second is a unit on this host that failed to start, or an
# SELinux rule missing from security/workload-inspect.cil, which is the
# failure the listener's "THE UPSTREAM DIAL" block records as "a policy gap
# wearing a network error's clothes": an OSError caught by the relay and
# counted as a dead upstream. Merged into the generic reason, such an AVC is
# indistinguishable from a provider outage, and `workloadctl egress --reason`
# -- which validates against DROP_REASONS -- would have no filter that
# selects it. `upstream unreachable` says "the provider is down, wait"; this
# says "a unit on this host is not answering, look at
# workload-<name>-broker.service and at audit.log".
DROP_BROKER_UNREACHABLE = "credential broker unreachable"

DROP_REASONS = (
    DROP_NOT_ALLOWLISTED,
    DROP_NO_NAME,
    DROP_UNREADABLE_REQUEST,
    DROP_UNREACHABLE,
    DROP_INTERNAL,
    DROP_CEILING,
    DROP_FOREIGN_CALLER,
    DROP_RELAY_FAILED,
    DROP_TIMED_OUT,
    DROP_UNVERIFIED,
    DROP_CLIENT_CERT,
    DROP_MISDIRECTED,
    DROP_MISDIRECTED_LISTED,
    DROP_THROTTLED,
    DROP_MINT_FAILED,
    DROP_NOT_HTTP,
    DROP_NOT_HTTP_POLICY,
    DROP_NOT_H2,
    DROP_NOT_PERMITTED,
    DROP_BROKER_UNREACHABLE,
)

# The reasons that also get a PER-HOST figure, and the only ones that do.
#
# Each is a refusal an operator acts on by NAME: the host to add an
# [[vm.network.internal]] entry for, the host whose private root has to go into
# this host's anchors, the host that needs client certificates and therefore
# `tls = "splice"`, and the host that is not speaking HTTP and therefore needs
# the same. `not HTTP/2` joins them and is read the same way with one word
# changed: the operator put that host in [[vm.network.http2]] and it did not
# speak h2, so either the entry is wrong or the host needs splicing.
#
# `not HTTP` appears TWICE, and the split is the whole value of the pair. The
# figures answer two different questions -- which hosts want splicing, and
# which hosts have method and path rules that can never run. The second has no
# other way of being learnt: nothing at startup could have told the operator,
# because whether a host speaks HTTP is not knowable from the file, which is
# exactly why §8 made it a runtime report rather than a validation rule.
#
# A per-host figure for `not allowlisted` is deliberately absent --
# the guest picks those names, there is no bound on how many it invents, and
# the answer is already the allowlist itself rather than a list to read. The
# un-allowlisted half of the binding rejection is absent for the same reason
# and the ALLOWLISTED half is present for its inverse: those names came off
# this workload's own lists, so the key space is bounded by the file, and WHICH
# PAIR of names a client is coalescing is the entire question that figure
# answers. A count alone says a mismatch happened; §4 needs to know between
# what.
#
# `not permitted by policy` is absent too, and unlike the two above that is a
# decision rather than a consequence. Its keys look bounded by the file -- a
# `policy` entry allowlists its own host -- but a WILDCARD entry bounds nothing,
# and a guest under `*.example.com` invents subdomains as freely as it invents
# anything else. That alone would settle it. What settles it twice is that the
# figure would not help if it were free: an operator whose request was refused
# needs the METHOD and the PATH to know which of their `methods`/`paths` lines
# to change, and a per-host count carries neither. That question belongs to the
# per-request record, which has all three, and half-answering it here would put
# the more findable of the two answers in the operator's way.
#
# Every one of these is a BOUNDED top-N with a counted overflow, because the
# keys are guest-chosen: unbounded, a guest inflating the report damages the
# host's Prometheus label cardinality rather than its own workload.
PER_HOST_REASONS = (
    DROP_INTERNAL,
    DROP_MISDIRECTED_LISTED,
    DROP_UNVERIFIED,
    DROP_CLIENT_CERT,
    DROP_NOT_HTTP,
    DROP_NOT_HTTP_POLICY,
    DROP_NOT_H2,
)

# Where a drop whose reason is not in DROP_REASONS is counted. Emitted only when
# it is non-zero, for the reason `(other)` is: a bucket reading zero on every
# healthy workload trains an operator to skip the line, and this is the line
# that matters when it is not zero. Its presence means the listener has a bug,
# not that the guest did anything -- but the totals still reconcile while it
# does.
DROP_UNCLASSIFIED = "(unclassified)"


# The record's field names, and the vocabularies of three of them.
#
# `credential` is the NAME of the credstore material the request was brokered
# with, or null on a request that was not brokered -- never the material, and
# never an address. It is here because `upstream` is honestly the broker's
# address on a brokered request: `upstream` is documented as the address
# actually dialled, and recording the origin there instead would put a second,
# false definition of "what this request touched" into the one document that
# exists to be evidence. What makes the honest value readable is this field
# naming which credential rode along, so `host` says where the request went
# and `credential` says why `upstream` is a loopback address.
RECORD_FIELDS = (
    LOG_ID_FIELD, LOG_REQ_FIELD, "ts", "plane", "mode", "host", "method",
    "path", "query", "http", "decision", "reason", "status", "upstream",
    "credential", "duration_ms",
)

# `forward` and `drop` ARE THE JOURNAL'S OWN VERBS, and there is deliberately
# no third value for "refused with an answer". Whether the guest was told is
# already carried, exactly and without a second representation, by `status`
# being non-null: a `drop` with a status is a refusal the guest can read, a
# `drop` without one is a connection that died saying nothing. A `refuse`
# value beside them would be a second spelling of that same fact, free to
# disagree with it -- which is the failure the listener argues against wherever
# one number is derived twice.
RECORD_DECISIONS = ("forward", "drop")

# What the listener was doing with the connection, which is not the same
# question as which port it arrived on (`plane`). `forward` is a cleartext
# request relayed, `terminate` a request inside a session this process
# completed, `splice` and `h2` the two connection-level records -- the paths
# that carry requests this process never decoded.
RECORD_MODES = ("forward", "terminate", "splice", "h2")


def record_timestamp():
    """Wall clock, ISO-8601 UTC to milliseconds.

    WALL CLOCK AND NOT monotonic(): a record exists to be joined against a
    journal line, an audit log and a person's memory of when something
    happened, and a monotonic reading joins to none of the three. `duration_ms`
    is the one figure taken from monotonic(), because an interval is the one
    thing a wall clock measures badly.
    """
    return (datetime.datetime.now(datetime.UTC)
            .isoformat(timespec="milliseconds").replace("+00:00", "Z"))


class Where(str):
    """The journal's connection key, carrying the record's fields as data.

    A str subclass so that every `f"drop {where} ..."` in the listener keeps
    working untouched while the record builder gets the id, the plane and the
    request ordinal without re-parsing the line it just composed.

    The alternative is a second parameter threaded through
    inspect_tls.serve_tls, _serve_tls_inspect, _serve_h2, serve_terminated and
    inspect_http.serve_one_request -- five signatures, and a sixth path added
    later that forgets it produces a record with no id while its journal line
    still looks perfectly right.

    `t0` is when this context began: the connection for a connection-level
    record, the request for a per-request one. That is what `duration_ms` is
    measured from, so each kind of record measures its own kind of interval.
    """

    __slots__ = ("cid", "plane", "seq", "t0")

    def __new__(cls, text, *, cid, plane, seq=None):
        where = super().__new__(cls, text)
        where.cid = cid
        where.plane = plane
        where.seq = seq
        where.t0 = time.monotonic()
        return where

    def request(self, seq):
        """This connection's key with one request's ordinal appended."""
        return Where(f"{self} {LOG_REQ_FIELD}={seq}",
                      cid=self.cid, plane=self.plane, seq=seq)


class Record:
    """One line of the private record, filled in as the exchange runs.

    Built at the top of a pass and written once at the bottom, so that a pass
    which never got a parseable head still leaves a line -- the record's
    coverage is the COUNTERS' coverage, which is what makes the two joinable
    in the rung that renders them. A pass with no decision wrote nothing to
    count and writes nothing here either: an idle kept-alive connection
    reaching its bound, and a guest that closed between requests, are not
    requests and must not be invented as ones.

    NO HEADERS AND NO BODIES, EVER. There is no redaction step because there is
    nothing here to redact -- the standing constraint is met at construction,
    which is the only place it can be met without being one `--verbose` away
    from not being met at all.
    """

    def __init__(self, log, where, mode, *, host=None):
        self._log = log
        self._t0 = where.t0
        # SEEDED FROM RECORD_FIELDS, so the constant the readers import is the
        # one this actually emits. Every field is present on every line and null
        # where it was not measured: a key that is absent and a key that is
        # null are different facts, and a reader cannot tell "not measured"
        # from "measured as nothing" if the writer drops the Nones.
        self.fields = dict.fromkeys(RECORD_FIELDS)
        self.fields.update({
            LOG_ID_FIELD: where.cid,
            LOG_REQ_FIELD: where.seq,
            "ts": record_timestamp(),
            "plane": where.plane,
            "mode": mode,
            "host": host,
        })

    def set(self, **fields):
        self.fields.update(fields)

    def started(self):
        """Re-stamp, now that a head has actually arrived.

        On a kept-alive connection the pass begins when the previous response
        finished and may wait out the whole idle timeout before a byte of this
        request exists. Stamping only at construction would date every second
        request on a connection to the end of the first. The timeout arms
        deliberately do NOT call this: there the interval being measured IS the
        wait, and the pass's own start is when it began.
        """
        self.fields["ts"] = record_timestamp()
        self._t0 = time.monotonic()

    def request(self, req):
        """The fields a parsed head supplies, and only those.

        `path` and `query` are the split req.path already makes, kept apart
        because they are different evidence: a path is what was asked for and a
        query can carry a credential outright. Both are recorded -- the sink is
        private, and eliding the query to protect a credential in a URL only
        moves that credential somewhere with less protection.
        """
        path, _, query = req.target.partition("?")
        self.set(host=req.host, method=req.method, path=path,
                 query=query or None, http=req.version)

    def dialled(self, sock):
        """The address actually reached -- §11's other half of the join.

        The name was resolved here, by this process, so it is the only party
        that knows which address a policy name became. Best effort: a socket
        that has already gone away answers nothing, and a record missing one
        field is better than a request that failed for a diagnostic.
        """
        try:
            peer = sock.getpeername()
            if not isinstance(peer, (tuple, list)) or len(peer) < 2:
                # A unix socket, or anything that is not an address pair. The
                # shape is checked rather than assumed because THE DIAGNOSTIC
                # MAY NOT KILL THE REQUEST -- the standing rule for every
                # diagnostic in the listener, and the except below is as wide
                # as that claim for the same reason.
                return
            self.set(upstream=format_endpoint(peer))
        except Exception:
            return

    def emit(self):
        if self.fields["decision"] is None:
            return
        self.fields["duration_ms"] = round(
            (time.monotonic() - self._t0) * 1000, 3)
        self._log.write(self.fields)


class RequestLog:
    """The per-request record's file: append, reopen on SIGHUP, never raise.

    A SEPARATE SINK FROM THE JOURNAL, deliberately. The decision lines stay
    where they are -- they exist to tell an operator what to fix, and the
    journal is the right place for that. This carries the per-request detail
    for allowed and denied alike, which is evidence of what a sandboxed agent
    was doing, and lands in a file readable by root and the workload uid only.
    egress_policy's INSPECT_RECORD_ROOT comment carries the whole argument, including
    why a LogNamespace= was not enough.

    NEVER RAISES, and the except clauses have to be as wide as that claim -- the
    standing rule for every diagnostic in the listener, and it binds harder
    here than in write_status: this runs on the CONNECTION threads, so an exception
    escaping would take one guest request down per failure rather than the
    accept loop once.

    The first failure is logged and the rest are not. A sink that cannot be
    written is unwritable for every request, and a line per request would put
    exactly the volume the private sink exists to keep out of the journal back
    into it. The permanent reading is the counter -- see Counters.record_write
    -- because a warning nobody re-reads is not a signal an operator has.
    """

    def __init__(self, path, out=None, on_failure=None):
        self._path = None if path is None else str(path)
        self._out = out
        self._on_failure = on_failure
        self._fd = None
        self._lock = threading.Lock()
        # Set by the signal handler, acted on by the next write. NOT reopened
        # in the handler itself: a signal is delivered on whichever thread the
        # kernel picks, and taking this lock there deadlocks against a thread
        # already inside write(). The cost is that an idle workload holds the
        # rotated fd until its next request, which is exactly what the
        # logrotate snippet's `delaycompress` is for -- the two are a pair.
        self._reopen = False
        self._warned = False

    def reopen(self):
        """Ask for a reopen. Async-signal-safe: one assignment, no I/O."""
        self._reopen = True

    def write(self, record: dict) -> None:
        if self._path is None:
            return
        try:
            line = json.dumps(record, sort_keys=True) + "\n"
        except (TypeError, ValueError) as exc:
            # A field a later rung added that json cannot serialise. Degrade to
            # a missing record, never to a failed request.
            self._fail(f"could not serialise a record: {exc}")
            return
        try:
            with self._lock:
                if self._reopen or self._fd is None:
                    self._open_locked()
                # ONE write of the whole line. O_APPEND fixes the offset so two
                # threads cannot overwrite each other, but it does not make a
                # partial write atomic -- the lock is what keeps one record on
                # one line, and it is needed for the reopen regardless.
                os.write(self._fd, line.encode())
        except OSError as exc:
            self._fail(f"could not write {self._path}: {exc}")

    def _open_locked(self):
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
        self._reopen = False
        fd = os.open(self._path,
                     os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        # The open mode is a REQUEST, filtered by the umask this process
        # inherited from its socket unit. fchmod is what makes 0600 a fact --
        # and the mode is the access decision here, not a nicety.
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            os.close(fd)
            raise
        self._fd = fd

    def _fail(self, message):
        if self._on_failure is not None:
            self._on_failure()
        if self._warned or self._out is None:
            return
        self._warned = True
        print(f"WARNING: the per-request record is not being written: "
              f"{message}", file=self._out, flush=True)

    def close(self):
        with self._lock:
            if self._fd is not None:
                try:
                    os.close(self._fd)
                except OSError:
                    pass
                self._fd = None
