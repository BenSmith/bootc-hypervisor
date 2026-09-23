"""
inspect_scope: what every connection decision is made against.

One workload's inspector holds five things that a connection decision reads
and never replaces: the policy, the counters, the per-request record, the
upstream pool and the minter. The accept loop, the ceiling and the status
file are not among them -- those belong to the process (lib/inspect_listener.py)
and no decision consults them. Bundling the five here is what lets the TLS
plane and the request loop be functions with one named dependency instead
of methods on the object that also owns the sockets.

The two behaviours the bundle has are the two every path needs: a log line,
and a record for a whole connection where there are no requests.
"""

import json
import sys

from egress_record import Record, RequestLog
from egress_upstream import Upstream
from inspect_counters import Counters
from inspect_policy import Policy


class Inspection:
    """One workload's policy, counters, record, upstream pool and minter."""

    def __init__(self, policy=None, *, out=None, minter=None,
                 record_path=None, broker_endpoint=None):
        self.out = out if out is not None else sys.stdout
        # An empty policy is a legal configuration and NOT a default: the
        # entrypoint will not construct a Listener without one. The fallback
        # exists so the tests that only exercise the shape need not invent a
        # policy.
        # `splice`, NOT TLS_DEFAULT. This fallback is a test convenience,
        # and the product default terminates -- which needs a CA, a minter and a
        # state directory none of the shape tests have. Naming the weaker mode
        # here is the honest version of that: a Listener built with no policy is
        # explicitly not exercising the default, rather than exercising it with
        # half its machinery missing.
        self.policy = policy if policy is not None else Policy(
            tls="splice", hosts=())
        # The counters exist whether or not a status file is ever written: a
        # figure that only accumulates when someone is watching is a figure
        # nobody can trust.
        self.counters = Counters(self.policy)
        # None means "build no record", the same convention the status path
        # uses and for the same reason: the shape tests construct a Listener
        # with no workload name and no directory to write into, and a
        # diagnostic that made those impossible would be a diagnostic that
        # decides which tests can exist.
        self.record = RequestLog(
            record_path, out=self.out,
            on_failure=self.counters.record_write_failure)
        # None under `tls = "splice"`, and the entrypoint refuses to start
        # without one under `tls = "inspect"`. Not defaulted here: a Listener that
        # terminated with no minter would have no leaf to present and would
        # fail every guest handshake while reporting itself healthy.
        self.minter = minter
        self.upstream = Upstream(broker_endpoint)

    def log(self, line):
        # One write of the line WITH its newline. print() writes the two
        # separately, and a connection thread logging between them joins
        # two decisions into one journal line.
        self.out.write(line + "\n")
        self.out.flush()

    def drop(self, where, reason, detail=None, *, host=None, mode=None,
             rec=None, answered=None, verb="drop", **fields):
        """One refusal: counted, recorded, and logged.

        The record line is `rec`, the request's own, or else a line for the
        whole connection in `mode`; with neither, none is written, which is
        right only for a caller that is not this workload. `answered` is the
        status the guest was given, if any. The journal line's reason begins
        with the reason as counted, so a grep for one finds the other.
        """
        self.counters.record_drop(reason, host)
        if rec is not None:
            rec.set(decision="drop", reason=reason)
            if answered is not None:
                rec.set(status=answered)
        elif mode is not None:
            line = Record(self.record, where, mode, host=host)
            line.set(decision="drop", reason=reason, status=answered)
            line.emit()
        text = reason if detail is None else f"{reason}: {detail}"
        named = "".join(f" {k}={v}" for k, v in
                        ((("host", host),) + tuple(fields.items()))
                        if v is not None)
        self.log(f"{verb} {where}{named} reason={quoted(text)}")


def quoted(text):
    """`text` as one journal field: double-quoted, with the quote, the
    backslash and every control character escaped.

    Guest bytes reach these lines, through a name or an error that repeats
    what it could not read. Escaped, nothing in them can end the field and
    be read as a field of its own.
    """
    return json.dumps(str(text), ensure_ascii=False)
