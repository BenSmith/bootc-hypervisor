"""The broker's server: one handler thread per admitted connection.

Handler settles the caller's identity once per connection, looks the
request's Host up in the profile table, and forwards one buffered request at a time to
the fixed upstream with the credential attached -- the decisions themselves
are broker_request's. Server bounds the pool: a global ceiling, a small
shared ceiling for every caller that is not the one served, and an in-flight
body budget, each refusing fast rather than queueing. The two TLS contexts at the end are the program's:
verified TLS out to the provider, and optional TLS in from the guest.

Used by `libexec/agent-broker`. Installed to /usr/libexec/workloadctl/broker_server.py.
"""

import email.utils
import http.client
import http.server
import socketserver
import ssl
import sys
import threading
import time

from broker_profiles import normalise_host
from broker_request import forwarded_headers, request_framing, response_framing
from peer_identity import local_endpoints, peer_uid

# At most this much request body summed over every connection at once. The
# request is buffered whole before it is forwarded, and broker_request's
# MAX_REQUEST_BYTES bounds only one of them: MAX_CONCURRENT connections each
# sending a legal 64 MiB body would reserve 8 GiB of host RAM. Neither the
# per-request nor the connection limit helps, because no single request
# exceeds its own share -- the sum is the whole problem, and it is not a
# limit either of them expresses.
#
# It matters more here than it would elsewhere: this runs on a hypervisor, so
# the memory in question is memory the VMs are using, and a sandboxed agent
# inside one of those VMs is exactly who would be reaching for it.
#
# Past the budget a request is refused with 503 rather than queued, so a caller
# gets a fast error it can retry instead of a hang -- the same choice the
# connection ceilings make.
MAX_INFLIGHT_BYTES = 256 * 1024 * 1024

# The upstream leg's two timeouts, and the defaults the flags override. The
# read timeout is long on purpose: streamed completions idle between tokens
# for far longer than a connect should be allowed to take.
CONNECT_TIMEOUT = 15.0
READ_TIMEOUT = 900.0

CHUNK = 64 * 1024

# How long a connection may make no progress before it is dropped. Without one,
# a caller that opens a socket and sends nothing holds its handler thread for
# ever -- and with a bounded pool, enough of those deny the broker to the
# workload it serves.
#
# It bounds each blocking operation, not the request, so a client trickling
# bytes is not caught by this; MAX_FOREIGN is what stops any caller but the
# served one taking the pool that way. Idle keep-alive connections are also
# reaped by it, which is ordinary (nginx defaults to 75s) and costs a
# reconnect at worst.
CONNECTION_TIMEOUT = 60.0


def log(event, **fields):
    """One structured line per event, to stderr -> journal. Never logs bodies,
    headers, or anything derived from the credential."""
    parts = " ".join(f"{k}={v}" for k, v in fields.items())
    print(f"[{time.strftime('%H:%M:%S')}] {event} {parts}", file=sys.stderr, flush=True)


class Handler(http.server.BaseHTTPRequestHandler):
    # Set by main(). Class attributes so every request sees the same objects.
    # `name` is a label for the log lines; `workload_uid` is the identity of
    # the one caller this instance serves, told to it and never looked up;
    # `profiles` is keyed by normalised Host.
    name = None
    workload_uid = None
    profiles = {}
    overflow = 65534
    upstream_context = None
    connect_timeout = CONNECT_TIMEOUT
    read_timeout = READ_TIMEOUT

    protocol_version = "HTTP/1.1"

    # Applied to the connection by StreamRequestHandler.setup(). See
    # CONNECTION_TIMEOUT.
    timeout = CONNECTION_TIMEOUT

    def setup(self):
        """Resolve the caller, take a slot against its ceiling, then hand off.

        Identity is settled here, once per connection rather than once per
        request: it is what the caller's ceiling is applied to, and what
        _identify then uses without scanning the socket tables again.

        TLS to the guest is also completed here rather than on the listening
        socket. Wrapping the listener makes accept() perform the handshake, so
        a caller that connected and then stalled it would block the accept
        loop for every other caller -- a denial of service that
        MAX_CONCURRENT does not bound, because the connection never reaches a
        handler at all. In this thread the same stall costs one slot and
        expires on the timeout.
        """
        try:
            self.caller_uid = peer_uid(local_endpoints(self.request),
                                       self.client_address)
        except OSError:
            self.caller_uid = None  # peer vanished between accept and lookup
        served = (self.caller_uid is not None
                  and self.caller_uid != self.overflow
                  and self.caller_uid == self.workload_uid)
        if not self.server.admit_caller(self.request, self.caller_uid,
                                        served=served):
            raise CallerCeilingExceeded(
                self.caller_uid if served else FOREIGN)

        guest_ctx = self.server.guest_tls_context
        if guest_ctx is not None:
            # Before wrapping: the handshake happens inside wrap_socket, and an
            # unarmed socket would let it hang for as long as the caller likes.
            self.request.settimeout(self.timeout)
            self.request = guest_ctx.wrap_socket(self.request, server_side=True)
        super().setup()

    def log_message(self, fmt, *args):
        pass  # replaced by explicit structured logging in _forward

    # Every method an HTTP API uses lands in one place. Which of them a
    # request may use is the inspector's policy, applied before the request
    # is sent here; a method missing from this list is answered 501 by the
    # base class, after that policy permitted it. CONNECT and TRACE are not
    # here: one asks a proxy to open a tunnel and the other echoes the
    # request back, credential and all.
    def do_GET(self):
        self._forward("GET")

    def do_HEAD(self):
        self._forward("HEAD")

    def do_POST(self):
        self._forward("POST")

    def do_PUT(self):
        self._forward("PUT")

    def do_PATCH(self):
        self._forward("PATCH")

    def do_DELETE(self):
        self._forward("DELETE")

    def do_OPTIONS(self):
        self._forward("OPTIONS")

    def _identify(self):
        """(sandbox, label) for this caller; sandbox is None if it gets nothing.

        The uid on the far end is the identity, resolved once when the
        connection was admitted (Server.process_request) because the caller's
        connection ceiling has to know who is calling before it grants a slot.
        The two failures that mean the *mechanism* is broken -- no peer socket,
        or a uid this namespace cannot map -- are refusals, because both make
        every caller look alike.

        The uid is compared to the ONE the instance was started for, and
        never resolved to a name: an instance serves one workload (ADR 007
        decision 6), so this is an assertion rather than a route, and the
        broker holds no notion of what a uid is called. The label the log
        line carries is the name it was handed, or the bare uid for a caller
        that is not it.

        This settles the caller. The `Host` is per request rather than per
        connection: one keep-alive connection from one inspector may carry
        requests for two credential-backed hosts, and resolving the profile
        once at setup would give the second request the first request's
        credential.
        """
        uid = self.caller_uid
        if uid is None:
            return None, "no-peer-socket"
        if uid == self.overflow:
            return None, "uid-unmapped"
        if uid == self.workload_uid:
            return self.name, self.name
        return None, f"uid:{uid}"

    def send_error(self, code, message=None, explain=None):
        """The base class's refusals -- a request line it cannot parse, a
        method with no do_ -- answered the way every other refusal here is.

        Its own is an HTML page naming the error in Python's words, which
        the inspector would relay to the guest as the provider's answer.
        """
        log("deny", reason=f"http-{code}", detail=message or "")
        self._fail(code)

    def _fail(self, status):
        """Answer without forwarding, and end the connection.

        The body is the status's own phrase and nothing else, and there is
        no Server header. The inspector relays this response to the guest
        as the provider's, so any sentence of ours in it -- a credential
        that is not configured, a broker at its limit, an upstream that
        failed -- tells the guest a broker is there. The reason is in the
        log line each caller writes before this.

        close_connection is set for every refusal, not just politeness in a
        header. A rejected request has left its body unread -- rejected because
        it was unreadable, in the chunked and bad-length cases -- so the next
        thing on the wire is body bytes where a request line should be. Reading
        on desynchronises the connection: a following pipelined request
        silently receives no response at all.
        """
        body = f"{http.HTTPStatus(status).phrase}\n".encode()
        self.close_connection = True
        self.send_response_only(status)
        self.send_header("Date", email.utils.formatdate(usegmt=True))
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
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
            self._fail(403)
            return

        # The other half of the decision. Resolved from THIS BROKER'S OWN
        # TABLE -- the header selects a row and supplies nothing. A Host with
        # no row is refused: there is no default profile (ADR 007 decision
        # 3), so a workload's second, unlisted destination cannot silently
        # receive its first destination's key.
        host = normalise_host(self.headers.get("Host"))
        profile = self.profiles.get(host) if host else None
        if profile is None:
            log("deny", reason="host-not-configured", sandbox=label,
                host=host or "")
            self._fail(403)
            return
        sandbox = profile.name

        length, rejection = request_framing(self.path, self.headers)
        if rejection is not None:
            status, reason, message = rejection
            log("deny", reason=reason, sandbox=sandbox, bytes=length,
                detail=message.strip())
            self._fail(status)
            return
        if not self.server.reserve_body(length):
            log("deny", reason="inflight-body-limit", sandbox=sandbox,
                bytes=length)
            self._fail(503)
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
                timeout=self.connect_timeout,
            )
            conn.request(method, path, body=body, headers=headers)
            # Streamed completions can idle between tokens for far longer than
            # a connect timeout should allow.
            conn.sock.settimeout(self.read_timeout)
            resp = conn.getresponse()
            sent = self._relay(resp)
            log("ok", sandbox=sandbox, method=method, path=self.path,
                status=resp.status, bytes=sent,
                ms=int((time.monotonic() - started) * 1000))
        # ValueError is http.client refusing a header or a target before a
        # byte is sent, with the offending value in its message. Named here
        # so it is logged by type like the rest, not printed as a traceback
        # by the server: one of the values is the credential. build_profiles
        # refuses such a credential at start; this is the line that holds
        # if something reaches here anyway.
        except (OSError, http.client.HTTPException, ValueError) as exc:
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
                    self._fail(502)
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
            resp.status, resp.getheaders(), self.command)

        # _only: no Server and no Date of ours; the provider's pass through.
        self.send_response_only(resp.status)
        for k, v in passthrough:
            self.send_header(k, v)
        if bodiless:
            # A HEAD answer keeps the length a GET would have had: it is the
            # thing a HEAD is sent to learn. 204 and 304 have none to keep.
            if self.command == "HEAD" and declared is not None:
                self.send_header("Content-Length", declared)
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


# How many connections the broker holds at once. The one caller it serves
# is the inspector, which funnels EVERY brokered request of its workload
# into this one identity -- each guest connection to a brokered host holds
# a broker connection of its own, kept alive between requests -- so this
# is the workload's whole brokered concurrency, and it is sized against
# the inspector's own MAX_CONNECTIONS rather than against one agent's
# streams. Past it a connection is refused, not queued: a fast error
# instead of a hang. The request bodies are bounded separately, by
# MAX_INFLIGHT_BYTES, so the pool's size is threads, not memory.
MAX_CONCURRENT = 128

# ...and how many of those every OTHER caller may hold, together. The one
# served caller is the only one that gets anything, but a refusal still
# costs a thread until it is answered, and on an address other uids can
# dial they must not be able to take the pool from the workload with
# sockets that connect and send nothing. One shared
# bucket rather than one per uid, so a host with many users cannot sum
# its way past it.
MAX_FOREIGN = 8

# The bucket every caller that is not the served one shares: other uids,
# callers the socket tables could not resolve, and the overflow uid.
FOREIGN = "foreign"


class CallerCeilingExceeded(Exception):
    """Raised out of Handler.setup() by a caller already at its ceiling.

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
        self._caller_of = {}  # accepted socket -> its caller's bucket
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

    def admit_caller(self, request, uid, *, served=False):
        """Count this connection against its caller's ceiling, or refuse it.

        The served caller is bounded by the pool alone; every other caller
        shares MAX_FOREIGN. `served` is the handler's to say, because which
        uid is served is the handler's.

        Called from the handler thread rather than the accept loop, and that
        placement is measured rather than tasteful. Resolving a caller means
        reading /proc/net/tcp, which the kernel generates on demand: 3.8ms per
        connection with ~1300 sockets on the host, and it grows with that
        number. In the accept loop every one of those milliseconds is time no
        other caller can be accepted, which hands a caller a way to slow the
        whole broker down by connecting in a loop.

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
        bucket = uid if served else FOREIGN
        limit = MAX_CONCURRENT if served else MAX_FOREIGN
        with self._lock:
            held = self._held.get(bucket, 0)
            if held >= limit:
                return False
            self._held[bucket] = held + 1
            self._caller_of[request] = bucket
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
        # released too many times" at the worst possible moment.
        super().process_request(request, client_address)

    def shutdown_request(self, request):
        """Called by ThreadingMixIn once the handler thread is done."""
        try:
            with self._lock:
                if request in self._caller_of:
                    bucket = self._caller_of.pop(request)
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
