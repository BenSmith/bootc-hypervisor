"""The synthesising responder's serve loop, and what it reports.

Counters is the status document's source; serve is the accept loop over the
sockets systemd passed in, answering UDP inline and TCP on a bounded number of
threads. Nothing here creates a socket, and nothing here speaks upstream:
tests/test_vm_resolve.py TestNoUpstream parses this file to keep it that way.

Raises rather than exits: workload-vm-resolve is the process, this is not.
"""
import selectors
import socket
import struct
import threading
import time

from dns_wire import (
    RCODE_FORMERR,
    RCODE_SERVFAIL,
    TCP_MAX,
    UDP_BUDGET,
    Malformed,
    NotAQuery,
    build_answer,
    error_response,
    log,
)
from egress_status import STATUS_TOP_N, BoundedCounts, write_status
from sd_listen import inherited_listening_sockets as sd_inherited_listening_sockets

# How long a TCP peer may hold a connection open with nothing on it. Clients
# reuse connections (RFC 7766) so this is not one query per connection, but an
# idle one must not pin a slot forever.
TCP_IDLE_TIMEOUT = 10.0

# The total wall-clock a single TCP connection may live, in seconds. The idle
# timeout alone does not bound one: settimeout() applies per recv, so a peer
# that sends a byte every nine seconds, or that pipelines queries forever, is
# never idle and never ends. Answers come from memory, so a real client is done
# in milliseconds and this is only ever spent by something that is not one.
TCP_LIFETIME = 30.0

# How many TCP connections may be in flight at once. Past it a connection is
# closed at accept rather than queued: a DNS client that loses a TCP attempt
# retries, and UDP -- which is how essentially every lookup arrives -- is not
# affected either way.
TCP_MAX_CONNECTIONS = 16

# How long the accept loop blocks before checking the clock and the stop flag.
_SELECT_POLL = 0.5

# The tick on which the status file is replaced while the responder is idle.
# Matches the listener's, so an operator reading both files side by side is not
# comparing two different staleness budgets.
STATUS_INTERVAL = 30.0


class Counters:
    """What the synthesising responder reports.

    THE FIGURE THAT IS NOT A HEALTH METRIC

    `unlisted` counts queries for names no list would authorise. It is the
    tunnelling signature, and it is worth being precise about what it does and
    does not mean. Synthesis makes the channel ABSENT rather than filtered:
    every name is answered with the inspector's address, so a guest encoding
    data into a1.example.com ... aN.example.com exfiltrates nothing -- the
    queries never leave this process, and nothing resolves them onward.

    What the count gives is evidence that something in the guest is TRYING. A
    legitimate guest's lookups cluster on a short list; an encoder's do not.
    That makes a rising `unlisted` a reason to look at the workload, never on
    its own a reason to believe anything left.
    """

    def __init__(self, top_n: int = STATUS_TOP_N):
        # TCP connections are answered on their own threads (see serve_stream),
        # so every observation and the snapshot that reads them back are taken
        # under one lock. BoundedCounts documents that its callers owe it this;
        # the read is in here too, because a status file assembled from a
        # half-applied observation reports figures that do not add up and is
        # worse than one written a tick later.
        self._lock = threading.Lock()
        self.synthesised = 0
        self.static = 0
        self.nodata = 0
        self.unlisted = 0
        self.malformed = 0
        # Bounded for the reason every per-host map here is: the keys are names
        # the GUEST chose, and this is the map a name-encoding guest is
        # actively trying to fill.
        self.unlisted_names = BoundedCounts(top_n)

    def record_answer(self, name: str, source: str, count: int,
                      on_a_list: bool) -> None:
        with self._lock:
            if source == "static":
                self.static += 1
            elif count:
                self.synthesised += 1
            else:
                self.nodata += 1
            if not on_a_list:
                self.unlisted += 1
                self.unlisted_names.add(name or ".")

    def record_nodata(self) -> None:
        """A question that was never about an address.

        HTTPS, SVCB, TXT, PTR, MX, SRV and every other type land here, and none
        of them is classified against the lists. The name in an HTTPS query is
        usually one the guest is about to look up properly anyway, so counting
        it as unlisted too would double every ordinary miss and drown the
        signal the unlisted figure exists to carry.
        """
        with self._lock:
            self.nodata += 1

    def record_malformed(self) -> None:
        with self._lock:
            self.malformed += 1

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "queries": {
                    "synthesised": self.synthesised,
                    "static": self.static,
                    "nodata": self.nodata,
                    "malformed": self.malformed,
                },
                "unlisted": self.unlisted,
                "unlisted_names": self.unlisted_names.snapshot(),
            }




def inherited_listening_sockets():
    """Recover the sockets systemd passed in, or fail loudly.

    The mechanics are shared with workload-inspect-listener
    (lib/sd_listen.py); what is ours is the reason a fallback bind is refused.
    Port 53 is privileged and this process is not, so a fallback would not fail
    -- it would succeed on some other port that nothing forwards to.
    """
    return sd_inherited_listening_sockets(
        refusal=(" -- port 53 is privileged and this process is not, so a "
                 "fallback bind would be a listener on some other port that "
                 "nothing forwards to"))


# --- the serve loop ---


def serve_datagram(sock, policy, counters=None):
    try:
        query, peer = sock.recvfrom(UDP_BUDGET * 4)
    except OSError as exc:
        log(f"  WARNING: recvfrom failed: {exc}")
        return
    try:
        reply = build_answer(query, policy, budget=UDP_BUDGET,
                             counters=counters)
    except Malformed as exc:
        if counters is not None:
            counters.record_malformed()
        if len(query) < 2:
            return
        log(f"  malformed query from {peer}: {exc}")
        reply = error_response(query, RCODE_FORMERR)
    except NotAQuery:
        # Not logged either: the log would be what a loop fills.
        if counters is not None:
            counters.record_malformed()
        return
    except Exception as exc:  # noqa: BLE001
        # ANYTHING else is a bug in this program, and the width of this arm is
        # the point rather than a shortcut. Without it the exception unwinds
        # through serve() and main() to the top-level handler and the process
        # exits: Restart=on-failure brings it back, the socket re-triggers it,
        # the same query arrives again and it exits again. That is a crash loop
        # in the guest's ONLY nameserver, presenting as "DNS stopped working"
        # with the cause a stack trace deep in the journal.
        #
        # handle_stream has caught this since it was written -- its
        # `except (OSError, struct.error)` wraps the same build_answer call --
        # so the identical query drops one TCP connection and kills the process
        # over UDP, which is the transport essentially every lookup uses. The
        # asymmetry was the defect; this is the side that was wrong.
        #
        # The reachable trigger today is a hand-edited or corrupted answer
        # document: pack_address raises OSError on a bad literal and Policy
        # does not validate the static map. Policy already normalises names on
        # the premise that the document gets edited by hand, and emit_status's
        # equally wide arm already carries the principle -- nothing peripheral
        # may take down the responder.
        #
        # SERVFAIL, not FORMERR: the query was fine, we were not. Not counted
        # as malformed either, because that figure means "the guest sent
        # rubbish" and an operator reading a rising count would look at the
        # guest instead of at the journal line below, which is the evidence.
        if len(query) < 2:
            return
        log(f"  WARNING: could not answer a query from {peer}: "
            f"{type(exc).__name__}: {exc}")
        reply = error_response(query, RCODE_SERVFAIL)
    try:
        sock.sendto(reply, peer)
    except OSError as exc:
        log(f"  WARNING: sendto failed: {exc}")


class _TcpSlots:
    """How many TCP connections are being answered right now.

    A plain counter under a lock rather than a BoundedSemaphore, because the
    figure is wanted for the log line that reports a refusal as well as for the
    decision itself.
    """

    def __init__(self, limit=TCP_MAX_CONNECTIONS):
        self._limit = limit
        self._live = 0
        self._lock = threading.Lock()

    def take(self) -> bool:
        with self._lock:
            if self._live >= self._limit:
                return False
            self._live += 1
            return True

    def give_back(self) -> None:
        with self._lock:
            self._live -= 1


def serve_stream(listener, policy, counters=None, slots=None):
    """Accept one TCP connection and answer it off the accept loop.

    NOT inline, which is what this used to be. The argument for inline was that
    answers come from memory, so a query cannot block on anything -- true, and
    beside the point: the loop is held by the READ, not by the answer. This
    process is the guest's only nameserver and the same loop serves UDP, so
    every second one TCP peer holds it is a second in which nothing in the
    guest can resolve anything and the status file stops being written. And a
    peer holds it easily: settimeout() bounds a single recv, so a client
    dribbling one byte inside the idle timeout, or pipelining queries forever
    (RFC 7766 reuse is deliberately supported), never trips it. That is a
    guest-local wedge of the guest's own DNS, which is bad enough -- but it is
    also indistinguishable, from the host, from a responder that has died.

    So the accept loop does exactly one thing: it takes the connection and
    hands it to a thread. TCP_MAX_CONNECTIONS bounds how many exist, and
    TCP_LIFETIME bounds how long each lives -- the two bounds the inline
    version had no way to express.
    """
    try:
        conn, _peer = listener.accept()
    except OSError as exc:
        log(f"  WARNING: accept failed: {exc}")
        return
    if slots is None:
        slots = _TCP_SLOTS
    if not slots.take():
        # Closed, not queued. See TCP_MAX_CONNECTIONS.
        log("  WARNING: TCP connection refused: "
            f"more than {TCP_MAX_CONNECTIONS} already in flight")
        conn.close()
        return
    # Daemon: a SIGTERM that ends the accept loop does not wait on connections
    # it already took. The slot is taken before the thread exists, so a thread
    # that cannot be started has to give it back here -- a leaked slot is never
    # returned by anything, and each one lowers the effective ceiling for the
    # life of the process.
    try:
        threading.Thread(target=_answer_stream,
                         args=(conn, policy, counters, slots),
                         daemon=True).start()
    except RuntimeError as exc:
        slots.give_back()
        log(f"  WARNING: TCP connection refused: cannot start thread: {exc}")
        conn.close()


def _answer_stream(conn, policy, counters=None, slots=None):
    """Answer every query on one connection until it ends or runs out of time."""
    try:
        handle_stream(conn, policy, counters)
    finally:
        if slots is not None:
            slots.give_back()


def handle_stream(conn, policy, counters=None, deadline=None):
    """Answer queries on an accepted TCP connection, then close it.

    `deadline` is a monotonic instant, defaulting to TCP_LIFETIME from now. It
    is a LIFETIME, not an idle bound: the idle bound is per recv and a peer
    that keeps sending is never idle. Each recv gets whichever of the two is
    nearer, so an ordinary client is bounded by idleness and only a peer still
    talking at the deadline is cut off by it.
    """
    if deadline is None:
        deadline = time.monotonic() + TCP_LIFETIME
    with conn:
        try:
            while True:
                prefix = recv_exactly(conn, 2, deadline)
                if prefix is None:
                    return
                length = struct.unpack("!H", prefix)[0]
                if length > TCP_MAX:
                    return
                query = recv_exactly(conn, length, deadline)
                if query is None:
                    return
                if not _arm(conn, deadline):
                    return
                try:
                    # No budget: TCP is where a truncated UDP answer is retried,
                    # so bounding it here would be the same answer twice.
                    reply = build_answer(query, policy, counters=counters)
                except Malformed as exc:
                    if counters is not None:
                        counters.record_malformed()
                    if len(query) < 2:
                        return
                    log(f"  malformed TCP query: {exc}")
                    reply = error_response(query, RCODE_FORMERR)
                except NotAQuery:
                    if counters is not None:
                        counters.record_malformed()
                    continue
                conn.sendall(struct.pack("!H", len(reply)) + reply)
        except (OSError, struct.error):
            return


def _arm(conn, deadline):
    """Set the socket's timeout for the next read. False if time is up.

    The send is armed by the same number the read before it set, which is what
    keeps a peer that has stopped READING from holding the connection past the
    deadline too.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        log(f"  TCP connection closed after {TCP_LIFETIME:.0f}s")
        return False
    conn.settimeout(min(TCP_IDLE_TIMEOUT, remaining))
    return True


def recv_exactly(conn, count, deadline=None):
    """Read exactly `count` bytes, or None if the peer stopped sending.

    The deadline is checked before EVERY recv, not once per message. A recv
    that returns a single byte rearms the idle timeout, so a peer dribbling one
    byte per recv would otherwise spend TCP_IDLE_TIMEOUT per byte of a message
    it chose the length of -- hours, out of a bound that reads like ten
    seconds. None means no lifetime, which is what a caller reading from a
    socket it already bounded another way passes.
    """
    chunks = bytearray()
    while len(chunks) < count:
        if deadline is not None and not _arm(conn, deadline):
            return None
        chunk = conn.recv(count - len(chunks))
        if not chunk:
            return None
        chunks += chunk
    return bytes(chunks)


# One ceiling for the process, shared by every call into serve_stream. The
# tests pass their own; nothing else needs to.
_TCP_SLOTS = _TcpSlots()


def serve(sockets, policy, counters=None, status_path=None, stop=None):
    """The accept loop. Returns when `stop` says so, or never.

    `stop` is a callable rather than an Event so the tests can end the loop
    after a fixed number of turns without a thread. In the process it is the
    SIGTERM flag.
    """
    selector = selectors.DefaultSelector()
    for sock in sockets:
        sock.setblocking(True)
        selector.register(sock, selectors.EVENT_READ)
    emit = lambda: emit_status(status_path, counters)
    # Before the first query, so the file's absence means "never started"
    # rather than the ambiguous "never asked a question" -- a responder whose
    # guest has looked nothing up yet is healthy.
    emit()
    due = time.monotonic() + STATUS_INTERVAL
    while stop is None or not stop():
        # The timeout is what makes the tick happen on an idle responder. With
        # a blocking select, a workload that stopped asking questions would
        # freeze its own status file at whatever the last query left behind and
        # look, to a reader, exactly like a process that had died.
        for key, _events in selector.select(timeout=_SELECT_POLL):
            sock = key.fileobj
            if sock.type == socket.SOCK_DGRAM:
                serve_datagram(sock, policy, counters)
            else:
                serve_stream(sock, policy, counters)
        if time.monotonic() >= due:
            emit()
            due = time.monotonic() + STATUS_INTERVAL
    emit()


def emit_status(status_path, counters):
    """Replace the status file, or log why it could not be replaced.

    Never raises, and the except clause has to be as wide as that claim: a
    responder that died because it could not write a diagnostic would leave the
    guest unable to resolve anything, which is a far worse failure than the
    missing file.

    OSError is the expected failure (a full or read-only /run). TypeError and
    ValueError are caught because json.dump raises them for a value it cannot
    serialise -- unreachable for the figures here today, and a counter added
    later that is not must cost a status file, not the guest's DNS.
    """
    if status_path is None or counters is None:
        return
    try:
        write_status(status_path, counters.snapshot())
    except (OSError, TypeError, ValueError) as exc:
        log(f"  WARNING: could not write {status_path}: {exc}")
