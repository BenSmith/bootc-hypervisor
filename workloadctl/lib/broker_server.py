"""The broker's server: one handler thread per admitted connection.

Handler settles the caller's identity once per connection, looks its
(workload, Host) profile up, and forwards one buffered request at a time to
the fixed upstream with the credential attached -- the decisions themselves
are broker_request's. Server bounds the pool: a global ceiling, a per-caller
ceiling, and an in-flight body budget, each refusing fast rather than
queueing, because a sandbox that can make the broker hang can deny it to
every other sandbox. The two TLS contexts at the end are the program's:
verified TLS out to the provider, and optional TLS in from the guest.

Used by `libexec/agent-broker`. Installed to /usr/libexec/workloadctl/broker_server.py.
"""

import http.client
import http.server
import socketserver
import ssl
import sys
import threading
import time

from broker_config import normalise_host
from broker_request import forwarded_headers, request_framing, response_framing
from peer_identity import local_endpoints, peer_uid, workload_name

# At most this much request body summed over every connection at once. The
# request is buffered whole before it is forwarded, and broker_request's
# MAX_REQUEST_BYTES bounds only one of them: with MAX_CONCURRENT connections
# each sending a legal 64 MiB body, the
# broker reserved 2 GiB of host RAM. Neither the per-request nor the per-caller
# limit helps, because no single request and no single caller exceeds its own
# share -- the sum is the whole problem, and it is not a limit either of them
# expresses.
#
# It matters more here than it would elsewhere: this runs on a hypervisor, so
# the memory in question is memory the VMs are using, and a sandboxed agent
# inside one of those VMs is exactly who would be reaching for it.
#
# Past the budget a request is refused with 503 rather than queued, so a caller
# gets a fast error it can retry instead of a hang -- the same choice the
# per-caller connection ceiling makes.
MAX_INFLIGHT_BYTES = 256 * 1024 * 1024

CHUNK = 64 * 1024

# How long a connection may make no progress before it is dropped. Without one,
# a caller that opens a socket and sends nothing holds its handler thread for
# ever -- and with a bounded pool, enough of those deny the broker to every
# other sandbox. Measured: 32 silent connections were sufficient.
#
# It bounds each blocking operation, not the request, so a client trickling
# bytes is not caught by this; MAX_PER_CALLER is what stops one caller taking
# the pool that way. Idle keep-alive connections are also reaped by it, which is
# ordinary (nginx defaults to 75s) and costs a reconnect at worst.
CONNECTION_TIMEOUT = 60.0


def log(event, **fields):
    """One structured line per event, to stderr -> journal. Never logs bodies,
    headers, or anything derived from the credential."""
    parts = " ".join(f"{k}={v}" for k, v in fields.items())
    print(f"[{time.strftime('%H:%M:%S')}] {event} {parts}", file=sys.stderr, flush=True)


class Handler(http.server.BaseHTTPRequestHandler):
    # Set by main(). Class attributes so every request sees the same objects.
    config = None
    profiles = {}
    overflow = 65534
    upstream_context = None

    protocol_version = "HTTP/1.1"
    server_version = "agent-broker"
    sys_version = ""

    # Applied to the connection by StreamRequestHandler.setup(). See
    # CONNECTION_TIMEOUT.
    timeout = CONNECTION_TIMEOUT

    def setup(self):
        """Resolve the caller, take a slot against its ceiling, then hand off.

        Identity is settled here, once per connection rather than once per
        request: it is what the per-caller ceiling is applied to, and what
        _identify then uses without scanning the socket tables again.

        TLS to the guest is also completed here rather than on the listening
        socket. Wrapping the listener made accept() perform the handshake, so a
        caller that connected and then stalled it blocked the accept loop for
        every other sandbox -- a denial of service that MAX_CONCURRENT does not
        bound, because the connection never reaches a handler at all. In this
        thread the same stall costs one slot and expires on the timeout.
        """
        try:
            self.caller_uid = peer_uid(local_endpoints(self.request),
                                       self.client_address)
        except OSError:
            self.caller_uid = None  # peer vanished between accept and lookup
        if not self.server.admit_caller(self.request, self.caller_uid):
            raise CallerCeilingExceeded(self.server._bucket(self.caller_uid))

        guest_ctx = self.server.guest_tls_context
        if guest_ctx is not None:
            # Before wrapping: the handshake happens inside wrap_socket, and an
            # unarmed socket would let it hang for as long as the caller likes.
            self.request.settimeout(self.timeout)
            self.request = guest_ctx.wrap_socket(self.request, server_side=True)
        super().setup()

    def log_message(self, fmt, *args):
        pass  # replaced by explicit structured logging in _forward

    # Every method the provider APIs use lands in one place.
    def do_GET(self):
        self._forward("GET")

    def do_POST(self):
        self._forward("POST")

    def do_DELETE(self):
        self._forward("DELETE")

    def _identify(self):
        """(sandbox, label) for this caller; sandbox is None if it gets nothing.

        The uid on the far end is the identity, resolved once when the
        connection was admitted (Server.process_request) because the per-caller
        connection ceiling has to know who is calling before it grants a slot.
        The two failures that mean the *mechanism* is broken -- no peer socket,
        or a uid this namespace cannot map -- are refusals, because both make
        every caller look alike.

        This settles HALF the profile key. The other half is the `Host`, which
        is per request rather than per connection: one keep-alive connection
        from one inspector may carry requests for two credential-backed hosts,
        and resolving the profile once at setup would give the second request
        the first request's credential.
        """
        uid = self.caller_uid
        if uid is None:
            return None, "no-peer-socket"
        if uid == self.overflow:
            return None, "uid-unmapped"

        name = workload_name(uid)
        label = name or f"uid:{uid}"
        if name is not None and any(s == name for s, _ in self.profiles):
            return name, label
        return None, label

    def _fail(self, status, message):
        """Answer without forwarding, and end the connection.

        close_connection is set for every refusal, not just politeness in a
        header. A rejected request has left its body unread -- rejected because
        it was unreadable, in the chunked and bad-length cases -- so the next
        thing on the wire is body bytes where a request line should be. Reading
        on desynchronises the connection: measured as a following pipelined
        request that silently received no response at all.
        """
        body = message.encode()
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _forward(self, method):
        started = time.monotonic()
        # Per request, not per connection: a keep-alive connection runs this
        # handler many times and the second request must not inherit the
        # first's verdict about whether a response is already on the wire.
        self.response_started = False
        sandbox, label = self._identify()
        if sandbox is None:
            log("deny", reason="unidentified", caller=label)
            self._fail(403, "caller not registered with the broker\n")
            return

        # The second half of the key. Resolved from THIS BROKER'S OWN TABLE --
        # the header selects a row and supplies nothing. A Host with no row is
        # refused: there is no default profile in either dimension (ADR 007
        # decision 3), so a workload's second, unlisted destination cannot
        # silently receive its first destination's key.
        host = normalise_host(self.headers.get("Host"))
        profile = self.profiles.get((sandbox, host)) if host else None
        if profile is None:
            log("deny", reason="host-not-configured", sandbox=label,
                host=host or "")
            self._fail(403, "no credential is configured for that host\n")
            return
        sandbox = profile.name

        length, rejection = request_framing(self.path, self.headers)
        if rejection is not None:
            status, reason, message = rejection
            log("deny", reason=reason, sandbox=sandbox, bytes=length)
            self._fail(status, message)
            return
        if not self.server.reserve_body(length):
            log("deny", reason="inflight-body-limit", sandbox=sandbox,
                bytes=length)
            self._fail(503, "broker is at its in-flight request limit\n")
            return

        try:
            self._forward_body(method, length, profile, sandbox, started)
        finally:
            self.server.release_body(length)

    def _forward_body(self, method, length, profile, sandbox, started):
        """Read the body and relay one request. Split from _forward only so the
        budget reserved for `length` is released on every path out."""
        body = self.rfile.read(length) if length else None

        # Denylist rather than allowlist: provider SDKs send version and beta
        # headers that change faster than we would keep an allowlist current,
        # and dropping one silently breaks requests in ways that are painful to
        # debug. Everything genuinely dangerous is enumerated in
        # forwarded_headers.
        headers = forwarded_headers(self.headers, profile)
        if body is not None:
            headers["Content-Length"] = str(len(body))

        path = self.path
        conn = None
        try:
            conn = http.client.HTTPSConnection(
                profile.host,
                profile.port,
                context=self.upstream_context,
                timeout=self.config["connect_timeout"],
            )
            conn.request(method, path, body=body, headers=headers)
            # Streamed completions can idle between tokens for far longer than
            # a connect timeout should allow.
            conn.sock.settimeout(self.config["read_timeout"])
            resp = conn.getresponse()
            sent = self._relay(resp)
            log("ok", sandbox=sandbox, method=method, path=self.path,
                status=resp.status, bytes=sent,
                ms=int((time.monotonic() - started) * 1000))
        except (OSError, http.client.HTTPException) as exc:
            log("upstream-error", sandbox=sandbox, path=self.path,
                error=type(exc).__name__, streamed=self.response_started)
            if self.response_started:
                # A status line and headers -- and usually some body -- are
                # already on the wire. _fail() would send a *second* complete
                # response, which the client reads as body content of the
                # first: under Content-Length it either truncates or arrives as
                # trailing garbage, and under chunked its raw bytes are parsed
                # as a chunk header and kill the message. Both leave the caller
                # holding something that looks like an answer.
                #
                # Dropping the connection instead is the one signal every
                # client already understands. A Content-Length body short of
                # its declared length, or a chunked body with no terminating
                # 0-chunk, is a truncated message by definition -- so the
                # caller gets an error rather than a plausible answer, which is
                # the whole point when the response carries model output.
                self.close_connection = True
            else:
                try:
                    self._fail(502,
                               f"upstream request failed: {type(exc).__name__}\n")
                except OSError:
                    pass  # client already gone
        finally:
            if conn is not None:
                conn.close()

    def _relay(self, resp):
        """Stream the upstream response back without buffering it.

        read1() is the load-bearing call. A plain read(n) blocks until it has n
        bytes or EOF, which turns a token-by-token SSE stream into one silent
        pause followed by the whole answer at once — the agent still works but
        the interaction feels broken. read1() returns whatever has arrived.
        """
        passthrough, declared, bodiless = response_framing(
            resp.status, resp.getheaders())

        self.send_response(resp.status)
        for k, v in passthrough:
            self.send_header(k, v)
        if bodiless:
            pass
        elif declared is not None:
            self.send_header("Content-Length", declared)
        else:
            # No length up front (streaming): re-frame as chunked so the client
            # can consume it incrementally and still see a clean end-of-message.
            self.send_header("Transfer-Encoding", "chunked")
        # Set before the flush, not after: once end_headers() has begun writing
        # there is no state in which sending a different response is still
        # correct, and a partial head is exactly the case where appending a
        # second one does the most damage. See the handler in _forward.
        self.response_started = True
        self.end_headers()

        sent = 0
        if bodiless:
            return sent
        while True:
            buf = resp.read1(CHUNK)
            if not buf:
                break
            if declared is None:
                self.wfile.write(f"{len(buf):X}\r\n".encode())
                self.wfile.write(buf)
                self.wfile.write(b"\r\n")
            else:
                self.wfile.write(buf)
            self.wfile.flush()
            sent += len(buf)
        if declared is None:
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        return sent


MAX_CONCURRENT = 32

# ...and how many of those one caller may hold. The global bound alone is a
# denial-of-service lever rather than a protection: a single hostile sandbox
# opening MAX_CONCURRENT connections takes the whole pool and every other
# sandbox is refused. Measured, with nothing more exotic than 32 sockets that
# connect and send no bytes at all.
#
# Sandboxes do not share a budget, so one in a loop cannot reach past its own.
# Eight concurrent streams is generous for an agent; past it the connection is
# refused immediately rather than queued, so the caller gets a fast error
# instead of a hang.
MAX_PER_CALLER = 8

# The bucket unidentified callers share. They are refused a credential by
# _identify anyway; the ceiling exists so that a caller the socket tables cannot
# resolve still cannot occupy the pool.
UNIDENTIFIED = "unidentified"


class CallerCeilingExceeded(Exception):
    """Raised out of Handler.setup() by a caller already at MAX_PER_CALLER.

    An exception rather than a return, because setup() has no way to decline:
    BaseRequestHandler runs setup/handle/finish from its constructor. Raising
    reaches process_request_thread, which reports it through handle_error and
    closes the connection in its finally -- releasing the thread immediately,
    which is what makes the refusal cheap.
    """

    def __init__(self, bucket):
        super().__init__(f"caller {bucket} is at its connection ceiling")
        self.bucket = bucket


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    block_on_close = False

    # TLS to the guest, when configured. Applied per connection in
    # Handler.setup(), never to the listening socket -- see that method.
    guest_tls_context = None

    _slots = None  # set in __init__; a semaphore, not a count

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # ThreadingMixIn spawns one thread per connection with no ceiling, so a
        # sandbox in a loop can exhaust host threads.
        self._slots = threading.BoundedSemaphore(MAX_CONCURRENT)
        self._lock = threading.Lock()
        self._held = {}       # caller bucket -> live connections
        self._caller_of = {}  # accepted socket -> uid, handed to its handler
        self._inflight = 0    # request-body bytes reserved across all handlers

    def reserve_body(self, length):
        """Claim `length` bytes of the shared body budget, or refuse.

        Reserved on the declared Content-Length, before the body is read: the
        budget exists so the bytes are never allocated, so a check made after
        reading them would measure the damage rather than prevent it. The
        length is already known to be a non-negative number no larger than
        MAX_REQUEST_BYTES -- request_framing rejects it otherwise -- so a caller
        cannot claim the whole budget by declaring a number it will not send.
        """
        if length <= 0:
            return True
        with self._lock:
            if self._inflight + length > MAX_INFLIGHT_BYTES:
                return False
            self._inflight += length
        return True

    def release_body(self, length):
        if length <= 0:
            return
        with self._lock:
            self._inflight -= length

    def _bucket(self, uid):
        return UNIDENTIFIED if uid is None else uid

    def admit_caller(self, request, uid):
        """Count this connection against its caller's ceiling, or refuse it.

        Called from the handler thread rather than the accept loop, and that
        placement is measured rather than tasteful. Resolving a caller means
        reading /proc/net/tcp, which the kernel generates on demand: 3.8ms per
        connection with ~1300 sockets on the host, and it grows with that
        number. In the accept loop -- where the first version of this put it --
        every one of those milliseconds is time no other caller can be accepted,
        which hands a caller a way to slow the whole broker down by connecting
        in a loop. A quieter version of the denial of service the ceiling exists
        to stop.

        In the handler it costs a thread, which is what MAX_CONCURRENT bounds,
        and the thread is released as soon as the refusal is raised. A caller
        over its ceiling therefore holds nothing.

        The read still dominates and is still per connection. Asking the kernel
        for one socket instead of the table (a NETLINK_INET_DIAG query filtered
        by port) would make it O(1), and is the obvious next move if this ever
        matters -- but it means hand-rolled netlink parsing in the one function
        whose wrong answer is the wrong credential, so it is not a change to
        make casually.
        """
        bucket = self._bucket(uid)
        with self._lock:
            held = self._held.get(bucket, 0)
            if held >= MAX_PER_CALLER:
                return False
            self._held[bucket] = held + 1
            self._caller_of[request] = uid
        return True

    def process_request(self, request, client_address):
        """Take a global slot, or refuse before a thread exists to be starved."""
        if not self._slots.acquire(blocking=False):
            log("deny", reason="too-many-connections", src=client_address[0])
            # Bypass our own shutdown_request: we never took a slot, and
            # releasing one we do not hold would inflate the pool for everyone.
            super().shutdown_request(request)
            return

        # No try/except around this. `t.start()` does raise when the host is out
        # of threads, and the slot must come back when it does -- but
        # BaseServer._handle_request_noblock already calls shutdown_request on
        # any exception out of process_request. Releasing it here as well is a
        # double release, which a BoundedSemaphore turns into "Semaphore
        # released too many times" at the worst possible moment. Written that
        # way first; TestAFailedSpawnDoesNotLeakASlot caught it.
        super().process_request(request, client_address)

    def shutdown_request(self, request):
        """Called by ThreadingMixIn once the handler thread is done."""
        try:
            with self._lock:
                if request in self._caller_of:
                    bucket = self._bucket(self._caller_of.pop(request))
                    remaining = self._held.get(bucket, 1) - 1
                    if remaining > 0:
                        self._held[bucket] = remaining
                    else:
                        # Drop the key rather than leave a zero: the map is
                        # keyed by uid and would otherwise grow one entry per
                        # workload that ever called, for the life of the process.
                        self._held.pop(bucket, None)
            super().shutdown_request(request)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address):
        """One line for the expected, a traceback for the rest.

        A stalled TLS handshake, a caller that vanishes mid-request, a caller
        over its ceiling: ordinary here, saying nothing an operator can act on,
        and the default's full traceback for each one is itself a log-flooding
        lever for a hostile sandbox.

        Anything else is a bug in this program, and swallowing its traceback
        would mean debugging the broker from a single exception name with no
        line number. Those keep the default.
        """
        exc = sys.exception()
        if isinstance(exc, CallerCeilingExceeded):
            log("deny", reason="too-many-connections-for-caller",
                caller=exc.bucket)
        elif isinstance(exc, (OSError, ssl.SSLError, TimeoutError, EOFError)):
            # ssl.SSLError and TimeoutError are OSError subclasses; named for
            # the reader, not for the isinstance.
            log("connection-error", error=type(exc).__name__)
        else:
            super().handle_error(request, client_address)


def upstream_tls_context(relax_x509_strict=False):
    """Verified TLS to the provider, using the host's trust store. There is
    no option to disable verification and there should not be one."""
    ctx = ssl.create_default_context()
    if relax_x509_strict:
        # Python 3.13+ enables VERIFY_X509_STRICT in create_default_context(),
        # which enforces RFC 5280 details most CAs honor but some private ones
        # do not -- notably a root without a keyUsage extension, which fails as
        # "CA cert does not include key usage extension" even though curl and
        # Node accept the same chain.
        #
        # This clears ONLY that strictness flag. Chain building, signature
        # verification, expiry, and hostname matching all still apply. It is
        # not a path to an unverified connection. Fix the CA instead where you
        # can; this exists for the case where you cannot.
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return ctx


def guest_tls_context(cert, key):
    """HTTPS to the guest, or None: for agents that refuse to send credentials
    over plaintext. One cert for one name, signed by a private CA the guest
    trusts -- internal PKI, not interception.

    Applied per connection in Handler.setup(); the listening socket stays
    plain. Wrapping the listener is the obvious spelling and it moves the
    handshake into accept(), where one caller stalling it stops the broker
    accepting anything at all.
    """
    if not (cert and key):
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx
