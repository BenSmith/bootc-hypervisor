"""
inspect_listener: the transparent egress inspector (the inspector design,
§7.7.1), one connection at a time.

The shape is the socket, the concurrency and the timeout discipline; the TLS
plane is the rest: a connection on 443 has its
ClientHello read, its server name matched against this workload's `hosts`, and
is then SPLICED byte-exact to that name's real host, or closed. The cleartext
plane authorises EVERY REQUEST on a connection by its Host header, through the
same matcher, and relays only the ones that pass -- a name on no list gets a
real 403 naming it, which is an answer 443 cannot give. That per-request loop
is lib/inspect_http.py; a terminated TLS connection hands its decrypted
socket to the same loop.

TWO TLS MODES, AND THE PEEK IS THE SAME PEEK

`tls = "splice"` decrypts nothing: the bytes read to find the name are the bytes
replayed upstream, verbatim, headers included. A ClientHello reconstructed from
a parse is a different ClientHello — different extension order, different
GREASE, a different JA3 — so the raw buffer is what travels and the parse is
only ever consulted for a decision.

`tls = "inspect"` (the default) TERMINATES. The same peek takes the
same decision, and then this process completes the guest's handshake itself with
a leaf minted by the workload's own CA, opens a separately verified session to
the origin, and authorises every REQUEST inside on the same matcher the
cleartext plane uses. The allowlist means the same thing on both planes only
under termination: spliced, a name is checked once at the front of a connection
whose contents nothing can see.

The reader itself is `lib/tls_hello.py`, and so is why the inspect path
peeks with MSG_PEEK where the splice path consumes.

BUMP-THEN-ANSWER

Every refusal a terminated connection carries is delivered THROUGH a completed
handshake, denials included: mint, complete the guest's handshake, then answer
403 or 502 in plain HTTP. Failing the handshake instead gives the guest an
opaque certificate error indistinguishable from the host being down, and the one
place a reason can reach a guest inside a TLS session is a response body.

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
import socket
import ssl
import threading
import time

from config_parser import normalise_hostname
from egress_plane import TLS, plane_for_port
from egress_policy import INSPECT_DIGEST_KEY
from egress_ca import LeafRefused, ca_cert_path, ca_key_path
from tls_hello import HelloUnreadable, read_client_hello
from http_framing import (
    H2_PREFACE, H2Framing, NotH2, RequestUnreadable, _Stream, is_http_request_start, send_response,
)
from http_target import SCHEME_HTTPS
from egress_mint import MintFailed, MintThrottled, Minter
from egress_record import (
    DROP_CEILING, DROP_FOREIGN_CALLER,
    DROP_MINT_FAILED, DROP_NOT_ALLOWLISTED, DROP_NOT_H2, DROP_NOT_HTTP, DROP_NOT_HTTP_POLICY,
    DROP_NO_NAME, DROP_RELAY_FAILED, DROP_THROTTLED,
    LOG_ID_FIELD,
    Record, Where, format_endpoint,
)
from egress_relay import relay
import egress_relay
from egress_status import write_status
from egress_upstream import (
    ALPN_H2, UPSTREAM_ALPN, dial_failure_reason,
    tls_failure,
)
from inspect_http import POLICY_REFUSAL_BODY
import inspect_http
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
                self._serve_tls(conn, where)
            else:
                inspect_http.serve_cleartext(self.inspection, conn, where)
        except (OSError, RequestUnreadable):
            pass
        finally:
            conn.close()
            self._ceiling.release()

    def _serve_tls(self, conn, where):
        """Peek, match, and then act by mode.

        The peek and the decision are the same on both modes and are taken here,
        once. What differs is everything after: `splice` replays the guest's own
        bytes at the origin and never sees inside; `inspect` completes the
        guest's handshake itself and authorises each request in it.

        The outcomes are logged with DISTINCT reasons, never merged: a hello
        that could not be read, a name that is on no list, and an upstream that
        could not be reached fail the guest's connection identically, and an
        operator who cannot tell them apart cannot tell a policy decision from a
        broken resolver from something speaking a non-TLS protocol at the TLS
        port.
        """
        # Whether this LISTENER can terminate at all, which is the mode. Which
        # of its connections it actually terminates is a per-host question
        # taken below, once there is a name -- so the hello is PEEKED whenever
        # the mode allows termination, not only when this connection will get
        # it. A consuming read here would leave a spliced host's own hello
        # already off the socket, and the splice property is that the origin
        # completes its handshake with the guest's bytes.
        inspect = self.inspection.policy.tls == "inspect"
        if inspect and self.inspection.minter is None:
            # Unreachable through the entrypoint, which refuses to start in
            # this state.
            # Kept anyway and LOUD: a Listener that terminated without a minter
            # would fail every guest handshake with an opaque certificate error,
            # which is the one failure this whole path exists to avoid, and a
            # test that constructed one would otherwise get it silently.
            self.inspection.counters.record_drop(DROP_MINT_FAILED)
            self.inspection.connection_record(where, "terminate", decision="drop",
                                              reason=DROP_MINT_FAILED)
            self.inspection.log(f"drop {where} reason='could not mint a leaf: this "
                                f"listener has no minter'")
            return
        try:
            raw, hello = read_client_hello(conn, peek=inspect)
        except HelloUnreadable as exc:
            self.inspection.counters.record_unreadable_hello()
            self.inspection.counters.record_drop(DROP_NO_NAME)
            self.inspection.connection_record(where, "terminate", decision="drop",
                                              reason=DROP_NO_NAME)
            self.inspection.log(f"drop {where} reason='no readable name: {exc}'")
            return
        if not hello.server_name:
            # The tripwire runs BEFORE the drop and with on_a_list False: a
            # hello that withholds SNI matched nothing, and if it also carried
            # ECH that is the strongest form of the signal, not an absent one.
            self.inspection.counters.record_hello(hello, False)
            self.inspection.counters.record_drop(DROP_NO_NAME)
            self.inspection.connection_record(where, "terminate", decision="drop",
                                              reason=DROP_NO_NAME)
            self.inspection.log(f"drop {where} reason='no readable name: the "
                                f"ClientHello carries no server_name extension'")
            return
        host = normalise_hostname(hello.server_name)
        # `admits`, not a bare `hosts` match: a [[vm.network.policy]] entry
        # allowlists its own host, so a workload whose entire allowlist is
        # written as policy entries would otherwise lose every connection at
        # the front, before the request its rules were written about exists.
        allowed = self.inspection.policy.admits(host)
        self.inspection.counters.record_hello(hello, allowed)
        # THE ALLOWLIST DECISION COMES FIRST, and the parenthesisation is what
        # says so. A name on the splice list and on no allowlist is refused,
        # not spliced -- and on a terminating listener it is refused the way
        # every other denial is, bump-then-403, rather than by a close the
        # guest cannot read. The reverse order looks equivalent and is not: a
        # `splice` PATTERN can cover names `hosts` does not (`*.example.com`
        # spliced, one name of it allowlisted), and validation cannot catch
        # that because the pattern does match allowlisted names.
        if inspect and not (allowed and self.inspection.policy.splices(host)):
            self._serve_tls_inspect(conn, where, host, allowed)
            return
        if not allowed:
            self.inspection.counters.record_drop(DROP_NOT_ALLOWLISTED, host)
            self.inspection.connection_record(where, "splice", host=host,
                                              decision="drop",
                                              reason=DROP_NOT_ALLOWLISTED)
            self.inspection.log(f"drop {where} host={host} reason='not allowlisted'")
            return
        # Dial the NAME, never an address (§7.4). The address the guest aimed
        # at is this inspector's own listener anyway -- the redirect already
        # rewrote it -- so there is nothing to forward even if forwarding one
        # were wanted, and resolving here is what makes the destination the one
        # the policy authorised rather than one the guest chose.
        try:
            upstream = socket.create_connection(
                (host, TLS.guest_port), timeout=egress_relay.CONNECTION_TIMEOUT)
        except OSError as exc:
            reason = dial_failure_reason(host, self.inspection.policy.internal)
            self.inspection.counters.record_drop(reason, host)
            self.inspection.connection_record(where, "splice", host=host,
                                              decision="drop", reason=reason)
            self.inspection.log(f"drop {where} host={host} reason='{reason}: {exc}'")
            return
        try:
            # The buffered hello, unmodified and before anything else. This is
            # the splice property: the server sees the guest's own ClientHello,
            # so the handshake it completes is with the guest, and this process
            # never holds a key to it.
            #
            # Nothing to replay when the hello was PEEKED -- a per-host splice
            # on a terminating listener -- because the bytes are still on the
            # socket and the relay below reads them first. Sending `raw` there
            # too would deliver the hello TWICE and the origin would fail the
            # handshake on the duplicate, which presents as the spliced host
            # being broken by the exemption that was supposed to fix it.
            if not inspect:
                upstream.sendall(raw)
            self.inspection.counters.record_splice()
            self.inspection.log(f"splice {where} host={host}"
                                f"{' per-host' if inspect else ''}")
            rec = Record(self.inspection.record, where, "splice", host=host)
            rec.dialled(upstream)
            rec.set(decision="forward")
            try:
                relay(conn, upstream)
            finally:
                # A NAMED EXEMPTION SHOULD BE VISIBLE IN THE RECORD AS ONE.
                # There is no path, no method and no status here and there
                # never will be -- that is what splicing means -- so the line
                # says which host was exempted and for how long, and a reader
                # who finds no requests for that host has this to find instead.
                rec.emit()
        finally:
            upstream.close()

    def _serve_tls_inspect(self, conn, where, host, allowed):
        """Terminate one connection: decide, dial, mint, handshake, serve.

        THE ORDER IS THE DESIGN. The upstream leg is established BEFORE the
        guest's handshake completes, so nothing here ever sniffs the guest to
        learn what to say upstream -- the protocol offered on both legs comes
        from UPSTREAM_ALPN, which is configuration. And the mint comes after the
        dial, so a host that cannot be reached or cannot be verified costs a
        leaf only because the REFUSAL is delivered through one.

        A BROKERED HOST HAS NO LEG TO ESTABLISH, and that does not weaken the
        invariant: the offer is still configuration, it is just always
        `http/1.1`. The request goes to this workload's broker, which is dialled
        per request, so an origin connection opened here would be verified and
        never written to -- and would make the ORIGIN's reachability and
        certificate a prerequisite for a request that never reaches it. See the
        branch below.

        EVERY OUTCOME IS BUMPED, denials included. A guest told "no" by a failed
        handshake is told nothing it can distinguish from the host being down;
        told "no" by a 403 through a chain it trusts, it has the name, the
        reason, and something to put in a log. That is the whole argument for
        holding a CA at all, and it applies with more force to the refusals than
        to the successes.
        """
        upstream = None
        refusal = None            # (drop reason, status, phrase, body text)
        # THE OFFER IS CHOSEN FROM CONFIGURATION, BEFORE EITHER HANDSHAKE, and
        # §6 is why there is no alternative: the upstream leg must be up before
        # a leaf is minted, so nothing here can sniff the guest and then speak
        # whatever came back. With the non-HTTP fallback gone there is also
        # nothing to sniff -- the only thing that ever needed a protocol
        # discovered after the fact was the relay path §8 deleted.
        h2 = self.inspection.policy.speaks_h2(host)
        # A BROKERED HOST IS NOT DIALLED HERE AT ALL, and the §6 invariant above
        # survives that: the offer is still chosen from configuration, it is
        # simply always `http/1.1` -- the broker leg is cleartext HTTP/1.1, and
        # `credential` with `http2` on one host is a validation error, so there
        # is no h2 session to relay and never was.
        #
        # WHAT THE DIAL WAS DOING FOR A BROKERED HOST WAS NOTHING GOOD. The
        # request goes to the broker, so the origin connection was opened,
        # verified, put in the pool and never written to. Its three purposes all
        # belong to the origin: hold the upstream leg open before the mint (the
        # broker leg is opened per request and has its own reason), check that
        # the origin took an h2 offer (there is no h2 here), and fail early if
        # the origin is unreachable. That last one is the harm: it made the
        # ORIGIN's reachability and certificate a prerequisite for a request
        # that never goes there, and reported the failure against the origin's
        # name. A provider having an outage failed brokered requests that would
        # have reached the broker fine, and a private origin behind a CA this
        # host does not hold failed them permanently.
        #
        # The mint does not need it either: `self.inspection.minter.leaf(host, ...)` takes
        # the name and nothing else.
        brokered = allowed and self.inspection.policy.credential_for(host) is not None
        if brokered:
            h2 = False
        if not allowed:
            # Generic body, like every policy denial (POLICY_REFUSAL_BODY): the
            # reason is the operator's, carried by the record_drop this refusal
            # triggers, and is not handed to the guest.
            refusal = (DROP_NOT_ALLOWLISTED, 403, "Forbidden",
                       POLICY_REFUSAL_BODY)
        elif brokered:
            pass  # no upstream leg at connection time; see above
        else:
            try:
                upstream = self.inspection.upstream.dial_tls(
                    host, ALPN_H2 if h2 else UPSTREAM_ALPN)
            except ssl.SSLError as exc:
                reason, text = tls_failure(host, exc)
                refusal = (reason, 502, "Bad Gateway", text)
            except OSError as exc:
                reason = dial_failure_reason(host, self.inspection.policy.internal)
                refusal = (reason, 502, "Bad Gateway",
                           f"{host} could not be reached: {exc}")
            else:
                # AND THE ORIGIN HAS TO HAVE TAKEN THE OFFER. ALPN_H2 says at
                # length that an offer binds nobody: a server speaking only
                # HTTP/1.1 completes this handshake and selects NOTHING, with
                # no alert of any kind. Unchecked, the guest's connection
                # preface is relayed into an HTTP/1.1 server and the session
                # fails as unattributable garbage -- while DROP_NOT_H2 cannot
                # fire from the other side, because the guest is speaking h2
                # perfectly and it is the ENTRY that is wrong.
                #
                # The guest half of this key is checked exhaustively -- preface,
                # first frame, framing, alignment -- precisely so that
                # [[vm.network.http2]] means SPEAKS H2 rather than EXEMPT.
                # Leaving the origin half unchecked settles that question on one
                # side of a relay whose entire content is the other side's
                # protocol, and hands the operator a broken host with no figure
                # naming it. One call, and it is the same reason and the same
                # remedy as every other way this key can be wrong.
                if h2 and upstream.sock.selected_alpn_protocol() != "h2":
                    # Closed HERE rather than left to the refusal branch, which
                    # has never had an upstream to close: every other refusal
                    # above is taken before the dial or by its failure. Keeping
                    # that invariant true is cheaper than a second close on a
                    # path where a leak is one verified socket per connection,
                    # owned by the workload uid, in a process the guest dials
                    # at will.
                    upstream.sock.close()
                    upstream = None
                    refusal = (
                        DROP_NOT_H2, 502, "Bad Gateway",
                        f"{host} is in [[vm.network.http2]] but did not select "
                        f"h2 for this connection, so there is no HTTP/2 session "
                        f"to relay. Either it does not speak h2 -- drop the "
                        f"entry and let it be inspected as HTTP/1.1 -- or it "
                        f"cannot take this workload's CA, and belongs in "
                        f"[[vm.network.splice]]")
        leaf = None
        try:
            # `denied` picks the CACHE, not the disposition: an allowlisted host
            # that was merely unreachable keeps its leaf in the working set,
            # because the next connection to it is expected to succeed and
            # should not pay for a mint. Only a name policy refused goes in the
            # denial set, which is the set a flood can fill.
            leaf = self.inspection.minter.leaf(host, denied=not allowed)
        except MintThrottled:
            # Nothing legible can be delivered without a leaf, so this is the
            # one outcome that closes on the guest. It is reachable only after
            # the bucket has been emptied, which honest traffic does not do.
            self.inspection.counters.record_drop(DROP_THROTTLED, host)
            self.inspection.connection_record(where, "terminate", host=host,
                                              decision="drop", reason=DROP_THROTTLED)
            self.inspection.log(f"drop {where} host={host} reason='mint rationed: the "
                                f"leaf bucket is empty'")
            return
        except (LeafRefused, MintFailed) as exc:
            self.inspection.counters.record_drop(DROP_MINT_FAILED, host)
            self.inspection.connection_record(where, "terminate", host=host,
                                              decision="drop", reason=DROP_MINT_FAILED)
            self.inspection.log(f"drop {where} host={host} "
                                f"reason='could not mint a leaf: {exc}'")
            return
        finally:
            # The upstream leg is open by now on the allowed path -- except a
            # brokered one, which never opens it -- and every arm above
            # returns. Closed here rather than in each of them, or a mint
            # failure leaks a host socket owned by the workload uid.
            if leaf is None and upstream is not None:
                upstream.sock.close()
        if leaf is None:
            return
        try:
            # `http/1.1` WHENEVER THERE IS A REFUSAL TO DELIVER, even on an
            # http2 host. Every refusal below is an HTTP/1.1 response written
            # into this session, so offering h2 for it would advertise a
            # protocol the next thing we send is not -- and buy nothing, since
            # the connection ends with that answer. The offer costs a
            # cooperating h2 client one fallback and gets it a readable 502
            # instead of a protocol error.
            tls_conn = self._wrap_guest(
                conn, leaf,
                ALPN_H2 if (h2 and refusal is None) else UPSTREAM_ALPN)
        except (ssl.SSLError, OSError) as exc:
            # The guest rejected the leaf, or went away mid-handshake. The most
            # common real cause is a guest that never got the CA -- an existing
            # instance whose seed predates it, which cloud-init will not revisit.
            #
            # BUT NOT IF THE LEAF IS GONE, and that is worth a branch of its
            # own. A cache eviction unlinks the PEM, so a leaf handed over and
            # then evicted before load_cert_chain opens it fails right here --
            # with an OSError about a path, and the sentence below would send
            # an operator to re-provision a guest whose trust is perfectly
            # fine. The caches are sized so this cannot happen (see
            # DENIAL_CACHE_MAX on the invariant), which is exactly why it must
            # say so if it ever does: it means that sizing is wrong, and no
            # other line would ever tell anyone.
            if not leaf.path.exists():
                self.inspection.counters.record_drop(DROP_MINT_FAILED, host)
                self.inspection.connection_record(where, "terminate", host=host,
                                                  decision="drop",
                                                  reason=DROP_MINT_FAILED)
                self.inspection.log(f"drop {where} host={host} reason='the leaf minted "
                                    f"for this connection was evicted before it could be "
                                    f"presented: {exc}. This is a cache-sizing fault, "
                                    f"not a trust one -- the leaf cache must hold more "
                                    f"entries than there are connection slots'")
                if upstream is not None:
                    upstream.sock.close()
                return
            self.inspection.counters.record_drop(DROP_RELAY_FAILED, host)
            self.inspection.connection_record(where, "terminate", host=host,
                                              decision="drop", reason=DROP_RELAY_FAILED)
            # NAMES BOTH SHAPES. "A guest provisioned before this workload had
            # a CA does not trust it and must be re-seeded" is true for a VM
            # instance whose seed predates the CA, and actively misleading for
            # the other case, which has no seed to revisit and no CA route to
            # repair; a sentence naming only the first is wrong half the time.
            # A JVM image is the standing example: `ca_delivery = "env"` delivers all five variables, every
            # one readable inside the container, and the JVM still refuses the
            # leaf -- because its anchors are
            # `cacerts` INSIDE THE IMAGE and no environment variable adds to
            # them, so telling that operator to re-seed names a guest that does
            # not exist. Anything with an embedded store is in this class: a JVM,
            # anything built on rustls with webpki-roots, a statically linked
            # client that never consults the system store.
            #
            # The listener cannot tell the two apart -- it sees a handshake
            # that did not complete and nothing about how the client was built
            # -- so it names both and the remedy each one needs, rather than
            # guessing and being confidently wrong for one substrate.
            self.inspection.log(f"drop {where} host={host} reason='the client did not "
                                f"complete the handshake: {exc}. It did not trust the "
                                f"leaf this workload minted, which has two shapes and "
                                f"they need different remedies. (1) A client that COULD "
                                f"be given the CA and was not: a VM instance seeded "
                                f"before this workload had one, which cloud-init will "
                                f"not revisit and which must be re-seeded; or a "
                                f"container whose ca_delivery route is absent or wrong. "
                                f"(2) A client that CANNOT be given it at all because "
                                f"its trust store is embedded in the image and it reads "
                                f"none of the CA environment variables -- a JVM, or "
                                f"anything on rustls. For (2) there is no CA route to "
                                f"fix: add {host} to [[network.splice]] "
                                f"([[vm.network.splice]] for a VM) so the connection is "
                                f"spliced rather than terminated, or change the image'")
            if upstream is not None:
                upstream.sock.close()
            return
        # wrap_socket DETACHES the socket it was given: `conn` has no fd from
        # here, so _serve's own close is a no-op and this is the only thing that
        # closes the guest's connection. Missing it leaks one fd per terminated
        # connection in a process the guest can open connections to at will.
        try:
            if refusal is not None:
                reason, status, phrase, text = refusal
                self.inspection.counters.record_drop(reason, host)
                self.inspection.counters.record_bump()
                # THE MOST COMMON DENIAL ON THIS PLANE, and it never reaches
                # inspect_http.serve_request: the decision was taken from the server name
                # before the guest's handshake completed, so there is no
                # request to hang it on. Without this the record's terminated
                # plane holds every allowed request and no refused one.
                self.inspection.connection_record(where, "terminate", host=host,
                                                  decision="drop", reason=reason,
                                                  status=status)
                self.inspection.log(f"bump {where} host={host} status={status} "
                                    f"reason='{reason}: {text}'")
                self._bump_answer(tls_conn, status, phrase, text)
                return
            self.inspection.counters.record_termination()
            self.inspection.log(f"terminate {where} host={host}"
                                f"{' h2' if h2 else ''}")
            if h2:
                self._serve_h2(tls_conn, where, host, upstream)
            else:
                self._serve_terminated(tls_conn, where, host, upstream)
        finally:
            try:
                tls_conn.close()
            except OSError:
                pass

    def _bump_answer(self, tls_conn, status, phrase, text):
        """Deliver a refusal inside a handshake we just completed.

        The guest's request is read first and thrown away. Not for anything in
        it -- the decision was taken from the server name before this socket was
        ever wrapped -- but because a client that is mid-send when the answer
        arrives and the connection closes reports a broken pipe instead of
        showing the status, and the whole point of bumping was to be legible.
        Bounded by the socket's own timeout, and failure to read one changes
        nothing: the answer goes out either way.
        """
        try:
            _Stream(tls_conn).read_head()
        except (RequestUnreadable, OSError):
            pass
        send_response(tls_conn, status, phrase, text, close=True)

    def _wrap_guest(self, conn, leaf, alpn=UPSTREAM_ALPN):
        """Complete the guest's handshake as the origin it dialled.

        A context per connection rather than one cached per name: the expensive
        half of this is the mint, which the working set already avoids, and a
        cache of live SSLContexts keyed by name would have to be invalidated by
        the same renewal the leaf cache handles -- two evictions that must agree
        about one certificate.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(leaf.path))
        ctx.set_alpn_protocols(list(alpn))
        return ctx.wrap_socket(conn, server_side=True)

    def _serve_h2(self, tls_conn, where, host, upstream):
        """Relay one h2 session at the frame level, refusing what is not h2.

        THE POINT OF THE CHECK IS WHAT THE KEY MEANS. Without it
        [[vm.network.http2]] names a byte relay -- no Host binding, no `paths`,
        no `methods`, and nothing establishing that the bytes are h2 at all --
        so a guest reaches a full policy opt-out on any host somebody listed
        for performance. With it the key means what it says: this host speaks
        h2, and the cost is that `:authority` goes unread. That is still a
        bypass (true fronting stays open here), which is why validation makes
        it carry a written `reason` and refuses it beside a `policy` entry.

        NOTHING IS DECODED. The preface is checked, frame headers are counted,
        and every byte is passed through unaltered -- stream ids untouched, the
        HPACK dynamic table end to end. §16's decoder is an increment on this,
        not a rewrite of it, because frame-header parsing is the half of that
        decoder which lands here.

        THE REMEDY IS THE ONE THE NON-HTTP REFUSAL NAMES, deliberately, because
        it is the same situation one key along: a session this design cannot
        police. `splice` gives the host back its end-to-end TLS and needs no CA
        in the guest.
        """
        # The upstream leg is THIS function's to close from here, exactly as
        # it is _serve_terminated's on the other branch. Missing it leaks one
        # verified TLS socket owned by the workload uid per h2 connection, in a
        # process a guest can open connections to at will -- and every
        # assertion about frames and counters passes while it does, because
        # nothing in the exchange is wrong.
        # ONE RECORD FOR THE WHOLE SESSION, because nothing inside it is
        # decoded -- that is what [[vm.network.http2]] means, and §11 names it
        # rather than letting the file be silent about a connection that
        # carried requests. `h2_unrecorded` beside it is the count a reader
        # needs before concluding a guest made no requests.
        rec = Record(self.inspection.record, where, "h2", host=host)
        rec.dialled(upstream.sock)
        try:
            client = _Stream(tls_conn)
            tls_conn.settimeout(egress_relay.CONNECTION_TIMEOUT)
            try:
                preface = client.read_exactly(len(H2_PREFACE))
            except (RequestUnreadable, OSError) as exc:
                self.inspection.counters.record_drop(DROP_NOT_H2, host)
                rec.set(decision="drop", reason=DROP_NOT_H2)
                self.inspection.log(f"drop {where} host={host} reason='not HTTP/2: the "
                                    f"connection preface never arrived ({exc}); drop the "
                                    f"[[vm.network.http2]] entry for {host}, or move it "
                                    f"to [[vm.network.splice]]'")
                return
            if preface != H2_PREFACE:
                self.inspection.counters.record_drop(DROP_NOT_H2, host)
                rec.set(decision="drop", reason=DROP_NOT_H2)
                self.inspection.log(f"drop {where} host={host} reason='not HTTP/2: "
                                    f"{preface[:8]!r} is not the connection preface, and "
                                    f"{host} is in [[vm.network.http2]]. Either it does not "
                                    f"speak h2 -- drop the entry -- or it speaks something "
                                    f"this cannot police, and belongs in "
                                    f"[[vm.network.splice]] instead'")
                return
            framing = H2Framing()
            # Everything the preface read pulled in past its own 24 bytes. It is
            # already frames, so it is fed to the scanner and forwarded with the
            # preface -- dropping it would lose the guest's opening SETTINGS, which
            # is the frame the scanner exists to check.
            surplus = client.take_buffered()
            try:
                framing.feed(surplus)
            except NotH2 as exc:
                self._drop_not_h2(where, host, exc)
                rec.set(decision="drop", reason=DROP_NOT_H2)
                return
            try:
                upstream.sock.sendall(preface + surplus)
                # And anything the ORIGIN sent before we asked. On h2 a server
                # opens with its own SETTINGS immediately, so the client-certificate
                # probe in egress_upstream.early_bytes routinely catches it; stranded in
                # that buffer it would stall the session rather than break it,
                # which is the harder failure to read.
                early = upstream.take_buffered()
                if early:
                    tls_conn.sendall(early)
            except OSError as exc:
                self.inspection.counters.record_drop(DROP_RELAY_FAILED, host)
                rec.set(decision="drop", reason=DROP_RELAY_FAILED)
                self.inspection.log(f"drop {where} host={host} "
                                    f"reason='relay failed: {exc}'")
                return
            try:
                relay(tls_conn, upstream.sock,
                            on_client_bytes=framing.feed)
            except NotH2 as exc:
                self._drop_not_h2(where, host, exc)
                rec.set(decision="drop", reason=DROP_NOT_H2)
                return
            except OSError as exc:
                self.inspection.counters.record_drop(DROP_RELAY_FAILED, host)
                rec.set(decision="drop", reason=DROP_RELAY_FAILED)
                self.inspection.log(f"drop {where} host={host} "
                                    f"reason='relay failed: {exc}'")
                return
            # The session ran. Recorded as a forward and counted as a blind
            # spot in the same breath, because both are true of it.
            rec.set(decision="forward")
            self.inspection.counters.record_h2_unrecorded()
            if not framing.aligned:
                # Counted, and the session is over either way -- but silence
                # here would make a stream that stopped framing halfway
                # indistinguishable from one that ended, which is the case
                # worth seeing.
                self._drop_not_h2(
                    where, host,
                    NotH2("the connection ended part-way through a frame"))
                rec.set(decision="drop", reason=DROP_NOT_H2)
        finally:
            rec.emit()
            upstream.sock.close()

    def _drop_not_h2(self, where, host, exc):
        self.inspection.counters.record_drop(DROP_NOT_H2, host)
        self.inspection.log(f"drop {where} host={host} reason='not HTTP/2: {exc}. "
                            f"{host} is in [[vm.network.http2]] and this session did not "
                            f"speak h2; drop the entry, or move the host to "
                            f"[[vm.network.splice]]'")

    def _serve_terminated(self, tls_conn, where, host, upstream):
        """Authorise every request inside one terminated session.

        The same loop the cleartext plane runs, with the upstream already open
        -- except on a brokered host, where there is deliberately none and every
        request opens the broker leg itself -- and the name PINNED to the server
        name the handshake was completed for.
        Pinning is not belt-and-braces: this session's certificate was minted
        for one name, and a request inside it naming another is asking to be
        relayed down a connection its Host header did not authorise. It gets a
        421, which is the answer HTTP already has for exactly this and which
        every client knows to retry elsewhere.
        """
        client = _Stream(tls_conn)
        # `upstream` is None for a brokered host: nothing was dialled at
        # connection time, because the request goes to this workload's broker
        # and not to the origin (see _serve_tls_inspect). Seeding the pool with
        # None would hand the first request a non-socket; seeding it with the
        # origin is what made the broker unreachable in the first place.
        upstreams = {host: upstream} if upstream is not None else {}
        try:
            if not self._is_http(client, tls_conn, where, host):
                return
            first = True
            seq = 1
            while inspect_http.serve_one_request(
                    self.inspection, client, tls_conn, where.request(seq),
                    upstreams, first, scheme=SCHEME_HTTPS, pinned_host=host):
                first = False
                seq += 1
        finally:
            for up in upstreams.values():
                up.sock.close()

    def _is_http(self, client, conn, where, host):
        """Whether this terminated connection is speaking HTTP. Closed if not.

        Closed, and not answered. See is_http_request_start for why an HTTP
        response is the wrong thing to write into a protocol that is not HTTP,
        and note that the guest gets no reason either way -- it is inside a
        session we completed, so a close here is a close it can see and cannot
        interpret.

        THE COST IS REAL AND THIS LINE IS THE ONLY EVIDENCE. A host that
        speaks something other than HTTP over 443 stops working the moment a
        workload terminates, and nothing before the connection could have
        predicted it -- which is why the remedy is written into the line rather
        than left for a doc. The remedy is a per-host [[vm.network.splice]]
        entry (HLD §11 hatch 2): the host keeps end-to-end TLS while every
        other name on the workload stays inspected. Whole-workload
        `tls = "splice"` is hatch 3 and gives up far more than the one host
        asked for.

        AND THE TWO REFUSALS ARE COUNTED APART. A host a [[vm.network.policy]]
        entry names is the same wire failure with a different remedy: the
        entry's `methods` and `paths` never ran and never can, so splicing the
        host is only half of it -- the entry has to go too, because `validate`
        refuses a host that is in `splice` and `policy` both. Reporting one
        merged figure would leave that operator with a number they cannot act
        on, and the split is the entire reason §11 asked for this counter.
        """
        conn.settimeout(egress_relay.CONNECTION_TIMEOUT)
        start = client.peek_start(
            until=lambda buf: is_http_request_start(buf) is not None)
        if is_http_request_start(start) is not False:
            # True is HTTP and None is undecided, which includes the b"" of a
            # peer that said nothing at all. Both go on to the loop below,
            # which owns the ways they end -- a 400, a clean close, a timeout
            # -- with the dispositions they already have.
            return True
        # Asked of the policy, not of the request: there is no request. See
        # Policy.governs.
        if self.inspection.policy.governs(host):
            self.inspection.counters.record_drop(DROP_NOT_HTTP_POLICY, host)
            self.inspection.connection_record(where, "terminate", host=host,
                                              decision="drop",
                                              reason=DROP_NOT_HTTP_POLICY)
            self.inspection.log(
                f"drop {where} host={host} reason='not HTTP (policy entry): "
                f"this session was terminated and {start[:8]!r} does not begin "
                f"a request line, so the [[vm.network.policy]] entry for "
                f"{host} never ran and never will. Either the host does not "
                f"belong in policy at all, or it needs a [[vm.network.splice]] "
                f"entry AND that policy entry deleted -- validate refuses both "
                f"on one host'")
            return False
        self.inspection.counters.record_drop(DROP_NOT_HTTP, host)
        self.inspection.connection_record(where, "terminate", host=host,
                                          decision="drop", reason=DROP_NOT_HTTP)
        self.inspection.log(f"drop {where} host={host} reason='not HTTP: this session "
                            f"was terminated and {start[:8]!r} does not begin a request "
                            f"line. Add {host} to [[vm.network.splice]] if it needs to "
                            f"keep end-to-end TLS'")
        return False

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
