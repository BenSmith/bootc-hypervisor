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
        print(line, file=self.out, flush=True)

    def connection_record(self, where, mode, *, host=None, decision,
                          reason=None, status=None):
        """One record for a whole connection, where there are no requests.

        THE RECORD'S COVERAGE IS THE COUNTERS' COVERAGE. Every path that calls
        record_drop, record_splice or record_termination writes a line, or the
        file answers "what did this guest do" with a subset and a reader has no
        way to know which subset. Two of these are the paths §11 names --
        `splice` and `h2` relay bytes this process never decodes -- and the
        rest are decisions taken at the front of a TLS connection, before there
        is a request to attach anything to.
        """
        rec = Record(self.record, where, mode, host=host)
        rec.set(decision=decision, reason=reason, status=status)
        rec.emit()
