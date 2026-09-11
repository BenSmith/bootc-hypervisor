"""
inspect_listener: the transparent egress inspector (the inspector design,
§7.7.1), one connection at a time.

The shape is the socket, the concurrency and the timeout discipline: accept
on the inherited listeners, admit up to a ceiling, name the plane, and hand
the connection to it with the workload's Inspection (lib/inspect_scope.py).
The planes are the rest. On 443 (lib/inspect_tls.py) a connection has its
ClientHello read, its server name matched against this workload's `hosts`,
and is then SPLICED byte-exact to that name's real host, TERMINATED and
authorised request by request, or closed. On 80 (lib/inspect_http.py) every
request on a connection is authorised by its Host header, through the same
matcher, and only the ones that pass are relayed -- a name on no list gets a
real 403 naming it, which is an answer 443 cannot give.

WHY THE PLANE COMES FROM getsockname, NOT LISTEN_FDNAMES

The socket unit runs with Accept=no, under which systemd names every
activated fd after the unit — all four carry the same LISTEN_FDNAMES entry, so
the name cannot tell the cleartext listener from the TLS one. The local port
of the inherited fd can, and it is the honest source of it: a guest dial to 80
is translated onto the cleartext plane's inspect port, one to 443 onto the
TLS plane's (lib/egress_plane.py), and the socket that accepted the
connection knows which it is. §7.1 uses exactly this property to justify never calling
SO_ORIGINAL_DST; a regression that started reading the port from anywhere
else quietly reintroduces the need for it.

CONCURRENCY AND TIMEOUTS (the shape, per §7.7.1)

One thread per connection, with a ceiling, and reject above it — do not queue.
An unbounded accept queue turns a guest's connection storm into memory growth
in a process that holds a CA key; a refused connection is a fast,
countable failure instead. The threads are daemons, as the broker's
ThreadingMixIn sets them, so a SIGTERM that stops the accept loop does not
wait on the connections it already took.

Every accepted socket gets an explicit timeout before it is touched, and the
two numbers it moves between -- one bounding every wait up to a decision, one
bounding every wait after -- are egress_relay's, which says why they cannot
be one number and which wait on the cleartext plane takes which.

Installed to /usr/libexec/workloadctl/inspect_listener.py.
"""

import os
import secrets
import selectors
import threading
import time

from egress_plane import TLS, plane_for_port
from egress_policy import INSPECT_DIGEST_KEY
from egress_ca import ca_cert_path, ca_key_path
from http_framing import RequestUnreadable
from egress_mint import Minter
from egress_record import (
    DROP_CEILING, DROP_FOREIGN_CALLER, LOG_ID_FIELD, Where, format_endpoint,
)
import egress_relay
from egress_status import write_status
import inspect_http
import inspect_tls
from inspect_scope import Inspection
from peer_identity import local_endpoints, peer_uid
from vm_clock import resync_guest_clock_if_skewed
from workload_lib import workload_state_dir



# The ceiling on simultaneously-handled connections. Sized well above a guest's
# legitimate concurrency (a browser is a handful of connections per origin,
# plus a few parallel downloads). The cost of being generous is bounded; the
# cost of being tight is a workload that reaches nothing. Past it a connection
# is refused, not queued.
MAX_CONNECTIONS = 128



# How often the accept loop wakes to look for a stop, in seconds. select() is a
# blocking call that a SIGTERM cannot make return (PEP 475 retries it), so the
# loop polls on a short interval and checks the stop flag.
_ACCEPT_POLL = 0.1




# How often the status file is replaced while the listener is serving. A low
# tick, deliberately: it is read by `diagnose` at a moment nobody chose, and a
# file minutes out of date reads as a stalled counter. Cheap enough to ignore
# -- a few hundred bytes of JSON against a process whose other work is relaying
# a tunnel.
STATUS_INTERVAL = 30.0


class Ceiling:
    """Bounded, per-process: admit up to `limit` live connections, refuse the
    rest. Refuse, not queue — a connection over the cap is turned away
    immediately rather than held in an unbounded accept queue, which is what
    turns a guest's connection storm into memory growth.
    """

    def __init__(self, limit):
        self._limit = limit
        self._lock = threading.Lock()
        self._held = 0
        self.rejected = 0

    @property
    def held(self) -> int:
        """Connections live right now.

        Reported beside `rejected` because the pair is what separates the two
        readings of a non-zero refusal count: a guest storming the listener
        shows refusals with the ceiling full, and a ceiling set too low for a
        real workload shows them with it full as well -- but the second sits at
        the limit steadily while the first spikes. One number cannot say which.
        """
        with self._lock:
            return self._held

    def admit(self):
        """Count a connection against the ceiling, or refuse it."""
        with self._lock:
            if self._held >= self._limit:
                self.rejected += 1
                return False
            self._held += 1
            return True

    def release(self, *, refused=False):
        """Give a slot back.

        `refused` marks the give-back as a connection that was admitted but
        never served, so the tally counts every turned-away connection and not
        only the ones the cap itself turned away. Both reach the guest the same
        way — a closed connection — so a total that counted just one of them
        would understate what the guest saw.
        """
        with self._lock:
            self._held -= 1
            if refused:
                self.rejected += 1


class Listener:
    """Accept on the inherited listeners and act on each connection by plane."""

    def __init__(self, sockets, out=None, limit=MAX_CONNECTIONS, policy=None,
                 status_path=None, minter=None, record_path=None,
                 broker_address=None):
        self._sockets = list(sockets)
        self._ceiling = Ceiling(limit)
        self._stop = threading.Event()
        # None means "count but never write", which is what the tests want and
        # also what a listener started without a workload name would do.
        self._status_path = status_path
        self.inspection = Inspection(
            policy, out=out, minter=minter, record_path=record_path,
            broker_address=broker_address)

    def stop(self):
        """Ask the accept loop to end; called from the SIGTERM handler."""
        self._stop.set()

    def close(self):
        for s in self._sockets:
            s.close()

    def accept_loop(self):
        sel = selectors.DefaultSelector()
        for s in self._sockets:
            sel.register(s, selectors.EVENT_READ)
        # Written once before the first connection, so the file exists from the
        # moment the listener is up. Absence then means "this inspector has
        # never STARTED" rather than the ambiguous "has never served a
        # connection" -- a distinction the reader cannot otherwise draw,
        # because a workload whose guest has dialled nothing is healthy and a
        # socket unit that hit its trigger limit is not.
        self.write_status()
        due = time.monotonic() + STATUS_INTERVAL
        try:
            while not self._stop.is_set():
                if time.monotonic() >= due:
                    self.write_status()
                    due = time.monotonic() + STATUS_INTERVAL
                try:
                    events = sel.select(timeout=_ACCEPT_POLL)
                except InterruptedError:
                    continue
                for key, _ in events:
                    try:
                        conn, peer = key.fileobj.accept()
                    except OSError:
                        continue
                    self._handle(conn, peer, key.fileobj)
        finally:
            sel.close()

    def _handle(self, conn, peer, listen_sock):
        # Set the timeout before doing anything with the accepted socket —
        # admitted or not, and before the ceiling is consulted. Both planes
        # read as their first act, so this is the number that bounds a guest
        # that connects and then says nothing.
        conn.settimeout(egress_relay.CONNECTION_TIMEOUT)
        # The accepting port, from getsockname() on the inherited fd — the fd
        # name cannot distinguish the planes under Accept=no (module docstring).
        local = listen_sock.getsockname()
        plane = plane_for_port(local[1])
        # HERE, not in _serve, and before the ceiling is consulted: _serve does
        # not run for a connection the ceiling rejects, and those two
        # `rejected` lines are exactly the ones an operator correlates when a
        # guest reports a stall it got no answer to.
        #
        # Random rather than a counter. The listener is socket-activated, so a
        # counter restarts at zero every time the socket re-triggers it, while
        # the record file this keys outlives that restart -- two unrelated
        # connections would share a key in the one file a reader joins on.
        cid = secrets.token_hex(6)
        if plane is None:
            # Not a port the socket unit binds, so not a listener of ours:
            # there is no plane to serve it on and none a record could name.
            self.inspection.log(
                f"rejected {LOG_ID_FIELD}={cid} local={format_endpoint(local)} "
                f"peer={format_endpoint(peer)} reason='not an inspect port'")
            conn.close()
            return
        # WHO IS CALLING. Before the ceiling, so a foreign caller cannot spend
        # a slot the workload needs, and before any byte is read.
        #
        # This is defence in depth, not the primary control: `workload_filter`
        # already drops a non-root packet aimed at any live inspector address
        # that is not the sender's own. It exists because that guard is one
        # rule in a table this program does not own and cannot verify, and
        # because of what leaked past it before it was fixed -- a dial from any
        # local uid reached this listener AND was written into this workload's
        # egress records, so the records described traffic the workload never
        # sent. A record an operator cannot trust is worse than no record.
        #
        # Root is refused here even though the nft guard exempts it. The
        # exemption exists so `diagnose` and `doctor` are not caught by a
        # host-wide drop, and neither dials this listener -- nothing in the
        # tree does. So the exemption is about packets, not about callers, and
        # root's manual probe landing in a workload's records was the second
        # half of the same defect.
        try:
            caller = peer_uid(local_endpoints(conn), peer[:2])
        except Exception:
            # A check that can throw is worse than one that fails soft: this is
            # the second layer, and taking the connection path down with it
            # would turn a hardening measure into an outage. Treated as
            # unresolved, which is handled below.
            caller = None
        if caller is not None and caller != os.getuid():
            self.inspection.log(
                f"rejected {LOG_ID_FIELD}={cid} plane={plane.label} "
                f"local={format_endpoint(local)} peer={format_endpoint(peer)} caller_uid={caller} "
                f"reason='{DROP_FOREIGN_CALLER}'")
            self.inspection.counters.record_drop(DROP_FOREIGN_CALLER)
            conn.close()
            return
        # `None` means the lookup could not name the owner -- a row that had
        # already left the table, or a /proc read that failed. Admitted, not
        # refused: the nft guard is the control that must hold, this layer
        # cannot distinguish "hostile" from "raced", and failing closed on an
        # unresolvable read would drop the workload's OWN traffic under exactly
        # the load that makes the table churn. Logged so the silence is
        # visible rather than assumed absent.
        if caller is None:
            # Counted, not logged. A line per connection would be noise for a
            # routine race -- the row can leave the table before we read it --
            # and it would carry a connection id, putting entries in the log an
            # operator joins on for connections that were served normally.
            self.inspection.counters.record_caller_unresolved()
        if not self._ceiling.admit():
            # Reject rather than queue: close now, count it, spawn no thread.
            self.inspection.log(
                f"rejected {LOG_ID_FIELD}={cid} plane={plane.label} local={format_endpoint(local)} "
                f"peer={format_endpoint(peer)} reason='connection ceiling reached'")
            # Counted as a drop as well as a rejection. The guest saw a closed
            # connection, which is the same thing every other drop reason gives
            # it, and a disposition total that omitted these would not add up
            # to the connections that were accepted.
            self.inspection.counters.record_drop(DROP_CEILING)
            conn.close()
            return
        # Daemon, as the broker's ThreadingMixIn: a SIGTERM that stops the
        # accept loop does not wait on the connections it already took.
        #
        # The slot is admitted before the thread exists, so the failure to
        # start one has to give it back here. Thread.start() raises RuntimeError
        # when the process cannot get another thread — exactly the condition a
        # connection storm produces, and exactly when the ceiling matters. A
        # leaked slot is never returned by anything: _serve's release only runs
        # for a thread that ran, so each failure lowers the effective ceiling
        # permanently and the listener degrades to refusing every connection
        # while still reporting itself active.
        try:
            threading.Thread(
                target=self._serve, args=(conn, peer, local, plane, cid),
                daemon=True).start()
        except RuntimeError as exc:
            self._ceiling.release(refused=True)
            self.inspection.log(
                f"rejected {LOG_ID_FIELD}={cid} plane={plane.label} local={format_endpoint(local)} "
                f"peer={format_endpoint(peer)} reason='cannot start thread: {exc}'")
            self.inspection.counters.record_drop(DROP_CEILING)
            conn.close()

    def _serve(self, conn, peer, local, plane, cid):
        # The id LEADS `where`, and `where` is interpolated by every decision
        # path in this file -- so one field here is what puts a join key on
        # `drop`, `splice`, `bump`, `terminate`, `forward`, `close` and
        # `upgrade` at once, rather than on the subset someone remembered.
        #
        # `peer=` cannot serve as that key and this does not replace it: a
        # port repeats across the requests on one keep-alive connection and is
        # reused by the kernel after close, so it groups the wrong things
        # together and separates the right ones.
        where = Where(f"{LOG_ID_FIELD}={cid} plane={plane.label} "
                       f"local={format_endpoint(local)} peer={format_endpoint(peer)}",
                       cid=cid, plane=plane.label)
        try:
            if plane is TLS:
                inspect_tls.serve_tls(self.inspection, conn, where)
            else:
                inspect_http.serve_cleartext(self.inspection, conn, where)
        except (OSError, RequestUnreadable):
            pass
        finally:
            conn.close()
            self._ceiling.release()

    @property
    def rejected(self) -> int:
        """How many connections this process turned away.

        A ceiling nobody can read is indistinguishable from one that never
        fires: the guest sees closed connections either way, and the operator
        has no way to tell a listener that refused 40,000 connections from one
        that was never reached. Reported on shutdown by `log_summary`.
        """
        return self._ceiling.rejected

    def status(self) -> dict:
        """This listener's counters, as they would be written right now."""
        snap = self.inspection.counters.snapshot(open_now=self._ceiling.held,
                                      refused=self.rejected)
        # The digest of the document THIS PROCESS loaded. It is not a
        # counter and it never moves, which is exactly why it belongs here:
        # the status file is the only channel from a running listener to the
        # host, and the question `diagnose` cannot otherwise answer is which
        # policy the process behind the socket is actually enforcing. Written
        # unconditionally, empty string included -- a key that appeared only
        # when non-empty would make "no digest" and "an older listener"
        # indistinguishable to the reader, and the reader treats one of those
        # as silence.
        snap[INSPECT_DIGEST_KEY] = self.inspection.policy.digest
        if self.inspection.minter is not None:
            # The minter's own figures, live sizes and CA identity included.
            # `hits` against `mints` says whether the working set is doing its
            # job; the `denied_*` subsets say which half of the traffic is
            # driving it; `throttled` is the only thing that names why a
            # workload under sustained abuse stopped getting readable 403s;
            # and `clock_unavailable` is the only thing that says the
            # mint-time clock remedy is inert in this guest.
            snap["mint"] = self.inspection.minter.snapshot()
        return snap

    def write_status(self):
        """Replace the status file, or log why it could not be replaced.

        Never raises, and the except clause has to be as wide as that claim.
        A listener that died because it could not write a diagnostic would be a
        worse outcome than the missing diagnostic, and this runs on the accept
        loop -- the thread whose death stops the guest reaching anything.

        OSError is the expected failure (a full or read-only /run). TypeError
        and ValueError are caught because json.dump raises them for a value it
        cannot serialise: every figure here is an int, a str or a dict of those
        today, so that is unreachable -- and a counter added in a later rung
        that is not must degrade to a missing status file, never to a workload
        whose guest cannot reach anything.
        """
        if self._status_path is None:
            return
        try:
            write_status(self._status_path, self.status())
        except (OSError, TypeError, ValueError) as exc:
            self.inspection.log(f"WARNING: could not write {self._status_path}: {exc}")

    def log_summary(self):
        """One line, at shutdown, naming what was refused.

        Emitted unconditionally — a zero is the useful reading most of the
        time, because it is what distinguishes "the ceiling never fired" from
        "nothing was logged about it".
        """
        self.inspection.log(f"stopped: {self.rejected} connection(s) rejected")


def build_minter(name, policy):
    """A Minter for a terminating workload, or None. Raises if it cannot.

    The CA is checked HERE rather than at the first mint. It is made by
    `workload-vm-inspect up` before the listener is ever socket-activated, so
    its absence is a provisioning failure, and a provisioning failure that
    surfaces as one refused connection an hour after boot is a provisioning
    failure nobody attributes.
    """
    if policy.tls != "inspect":
        return None
    state_dir = workload_state_dir(name)
    cert = ca_cert_path(state_dir)
    key = ca_key_path(state_dir)
    for path in (cert, key):
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"tls = 'inspect' terminates, which needs this workload's "
                f"egress CA, and {path} is not there")
    # The clock check is the guest-clock remedy, and it is passed explicitly
    # because Minter refuses to be built without one. It runs on a mint MISS only, so a
    # guest cannot make the guest agent be dialled more often than it can make
    # us mint.
    #
    # `lambda: None` WHERE THERE IS NO AGENT TO ASK, which is Minter's own
    # documented way of saying a caller decided against the remedy rather than
    # forgot it. A container has no QEMU guest agent, so the check could only
    # ever fail: it dialled a socket that has never existed on that substrate,
    # once per mint miss, and counted every attempt into `clock_unavailable` --
    # a figure whose published meaning is that the remedy is INERT IN THIS
    # GUEST. Structurally guaranteed on a container, so it reported a broken
    # remedy where there is simply no such remedy, and nothing went red.
    #
    # The substrate is read off the policy document rather than branched on
    # here, because this binary does not differ between substrates (ADR 009).
    # The document differs; the binary reads the same keys from either.
    clock_check = ((lambda: resync_guest_clock_if_skewed(name))
                   if policy.guest_agent else (lambda: None))
    return Minter(name, state_dir, clock_check=clock_check)
