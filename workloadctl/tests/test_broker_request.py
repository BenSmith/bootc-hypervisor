"""The credential broker's request path: what leaves the host, and who may hold
a connection open.

This is the half of the broker that touches the credential, and it had no tests
at all — 37 of them covered config parsing and caller identity, and none reached
`_forward`. Two defects lived in the gap: a caller's own auth header rode
upstream beside the real one whenever `auth_header` was not one of the four
hardcoded names, and a chunked request body was dropped in silence and answered
200. Both are asserted below, on the pure functions the request path was split
into precisely so they could be.

Most of the socket tests at the bottom are about connection *admission* rather
than content, so they need no upstream: they are decided before the broker
would forward anything. The last class is the exception — what the caller is
left holding when an upstream dies *after* the answer started — so it stands a
fake upstream up behind the real server.
"""

import contextlib
import io
import os
import socket
import threading
import unittest
from email.message import Message
from unittest import mock

import broker_profiles
import broker_request
import broker_server


def headers(**pairs):
    """An email.message.Message, which is what BaseHTTPRequestHandler parses
    request headers into — including its case-insensitive lookup."""
    msg = Message()
    for key, value in pairs.items():
        msg[key.replace("_", "-")] = value
    return msg


def profile(auth_header="x-api-key", auth_value="REAL-SECRET", host="api.example.com"):
    return broker_profiles.Profile(
        name="agent/api.example.com", host=host, port=443,
        auth_header=auth_header, auth_format="{secret}",
        secret="REAL-SECRET", auth_value=auth_value,
    )


def profile_table(prof=None):
    """A per-Host table covering the hosts these tests dial.

    "x" is in it because most of these send `Host: x` -- they are about framing,
    budgets and relaying rather than about dispatch, and rewriting their bytes
    to carry a realistic name would obscure what each one is actually asserting.

    Registering a table rather than stubbing Handler._identify is deliberate:
    every one of these used to reach the handler through the fallback profile
    `allow_unknown_callers` produced, and that is gone. A stub would take the
    real Host lookup out of the path, so a change that stopped checking the
    Host would leave this whole file green.
    """
    prof = prof or profile()
    return {"x": prof, "api.example.com": prof}


class TestForwardedHeaders(unittest.TestCase):

    def test_the_credential_is_attached(self):
        out = broker_request.forwarded_headers(headers(), profile())
        self.assertEqual(out["x-api-key"], "REAL-SECRET")

    def test_the_upstream_host_replaces_the_callers(self):
        out = broker_request.forwarded_headers(headers(Host="broker.local"), profile())
        self.assertEqual(out["Host"], "api.example.com")
        self.assertEqual([k for k in out if k.lower() == "host"], ["Host"])

    def test_credential_shaped_headers_are_dropped(self):
        out = broker_request.forwarded_headers(
            headers(Authorization="Bearer stolen", x_api_key="stolen",
                    api_key="stolen", x_goog_api_key="stolen", Cookie="s=1"),
            profile())
        self.assertEqual(
            [k for k in out if k.lower() != "host"], ["x-api-key"])
        self.assertEqual(out["x-api-key"], "REAL-SECRET")

    def test_case_does_not_smuggle_one_past_the_strip_list(self):
        out = broker_request.forwarded_headers(headers(AUTHORIZATION="Bearer stolen"),
                                       profile())
        self.assertNotIn("stolen", "".join(out.values()))

    def test_the_configured_auth_header_is_stripped_by_name(self):
        """The regression. `auth_header` may be any string, and only four names
        are on the fixed list — so with a custom one the caller's copy used to
        survive under a different capitalisation and reach the provider beside
        the real credential."""
        out = broker_request.forwarded_headers(
            headers(x_custom_key="ATTACKER"),
            profile(auth_header="X-Custom-Key"))
        self.assertEqual(list(out.values()).count("ATTACKER"), 0)
        self.assertEqual(out["X-Custom-Key"], "REAL-SECRET")

    def test_hop_by_hop_headers_do_not_cross(self):
        out = broker_request.forwarded_headers(
            headers(Connection="keep-alive", TE="trailers",
                    Transfer_Encoding="chunked"), profile())
        self.assertEqual([k for k in out if k.lower() != "host"], ["x-api-key"])

    def test_everything_else_passes_through(self):
        """A denylist on purpose: provider SDKs send version and beta headers
        that change faster than an allowlist would be maintained."""
        out = broker_request.forwarded_headers(
            headers(anthropic_version="2023-06-01", anthropic_beta="a,b",
                    Content_Type="application/json"), profile())
        self.assertEqual(out["anthropic-version"], "2023-06-01")
        self.assertEqual(out["anthropic-beta"], "a,b")
        self.assertEqual(out["Content-Type"], "application/json")


class TestRequestFraming(unittest.TestCase):

    def test_an_ordinary_request_is_accepted(self):
        length, rejection = broker_request.request_framing(
            "/v1/messages", headers(Content_Length="12"))
        self.assertEqual(length, 12)
        self.assertIsNone(rejection)

    def test_no_content_length_means_no_body(self):
        length, rejection = broker_request.request_framing("/v1/models", headers())
        self.assertEqual((length, rejection), (0, None))

    def test_an_empty_content_length_is_not_an_error(self):
        length, rejection = broker_request.request_framing(
            "/v1/models", headers(Content_Length="  "))
        self.assertEqual((length, rejection), (0, None))

    def test_an_absolute_target_is_refused(self):
        _, rejection = broker_request.request_framing(
            "https://elsewhere.example/v1", headers())
        self.assertEqual(rejection[0], 400)
        self.assertEqual(rejection[1], "absolute-target")

    def test_a_chunked_body_is_refused_rather_than_dropped(self):
        """It used to be neither: Transfer-Encoding is hop-by-hop and was
        stripped, no Content-Length meant length 0, and the body went nowhere
        while the caller got a 200 for a request the provider never saw."""
        _, rejection = broker_request.request_framing(
            "/v1/messages", headers(Transfer_Encoding="chunked"))
        self.assertEqual(rejection[0], 411)
        self.assertEqual(rejection[1], "chunked-request")

    def test_a_non_numeric_content_length_is_refused(self):
        """It used to raise ValueError out of the handler: no log line, no
        response, just a reset connection."""
        _, rejection = broker_request.request_framing(
            "/v1/messages", headers(Content_Length="twelve"))
        self.assertEqual(rejection[0], 400)

    def test_two_content_lengths_are_refused(self):
        """Two lengths frame two messages; taking the first leaves the rest of
        the other in the socket, to be read as the next request line."""
        msg = Message()
        msg["Content-Length"] = "4"
        msg["Content-Length"] = "40"
        _, rejection = broker_request.request_framing("/v1/messages", msg)
        self.assertEqual(rejection[0], 400)
        self.assertEqual(rejection[1], "duplicate-content-length")

    def test_a_negative_content_length_is_refused(self):
        """rfile.read(-1) reads to EOF, so this held a slot for as long as the
        caller cared to keep the socket open."""
        _, rejection = broker_request.request_framing(
            "/v1/messages", headers(Content_Length="-1"))
        self.assertEqual(rejection[0], 400)

    def test_an_oversized_body_is_refused(self):
        length, rejection = broker_request.request_framing(
            "/v1/messages",
            headers(Content_Length=str(broker_request.MAX_REQUEST_BYTES + 1)))
        self.assertEqual(rejection[0], 413)
        self.assertEqual(length, broker_request.MAX_REQUEST_BYTES + 1)

    def test_the_size_limit_is_inclusive(self):
        length, rejection = broker_request.request_framing(
            "/v1/messages", headers(Content_Length=str(broker_request.MAX_REQUEST_BYTES)))
        self.assertEqual((length, rejection), (broker_request.MAX_REQUEST_BYTES, None))


class TestResponseFraming(unittest.TestCase):

    def test_a_declared_length_is_carried_through(self):
        passthrough, declared, bodiless = broker_request.response_framing(
            200, [("Content-Type", "application/json"), ("Content-Length", "17")])
        self.assertEqual(passthrough, [("Content-Type", "application/json")])
        self.assertEqual(declared, "17")
        self.assertFalse(bodiless)

    def test_content_length_is_found_whatever_its_case(self):
        _, declared, _ = broker_request.response_framing(200, [("content-length", "5")])
        self.assertEqual(declared, "5")

    def test_a_stream_declares_no_length(self):
        passthrough, declared, _ = broker_request.response_framing(
            200, [("Content-Type", "text/event-stream")])
        self.assertIsNone(declared)
        self.assertEqual(passthrough, [("Content-Type", "text/event-stream")])

    def test_hop_by_hop_headers_do_not_come_back(self):
        passthrough, _, _ = broker_request.response_framing(
            200, [("Connection", "keep-alive"), ("Transfer-Encoding", "chunked"),
                  ("Content-Type", "application/json")])
        self.assertEqual(passthrough, [("Content-Type", "application/json")])

    def test_the_providers_date_and_server_come_back(self):
        """The inspector relays an unbrokered host's head verbatim, so a
        brokered host's must carry the provider's own Date and Server too.
        These were once dropped for the broker's own, which named the broker
        on every brokered response the guest read."""
        passthrough, _, _ = broker_request.response_framing(
            200, [("Date", "Mon, 01 Jan 2035 00:00:00 GMT"),
                  ("Server", "upstream-edge/2"),
                  ("Content-Type", "application/json")])
        self.assertEqual(passthrough,
                         [("Date", "Mon, 01 Jan 2035 00:00:00 GMT"),
                          ("Server", "upstream-edge/2"),
                          ("Content-Type", "application/json")])

    def test_204_and_304_carry_no_body(self):
        for status in (204, 304):
            _, _, bodiless = broker_request.response_framing(status, [])
            self.assertTrue(bodiless, status)

    def test_a_response_to_head_carries_no_body(self):
        """Its Content-Length describes the GET it stands in for."""
        _, declared, bodiless = broker_request.response_framing(
            200, [("content-length", "5")], "HEAD")
        self.assertTrue(bodiless)
        self.assertEqual(declared, "5")
        _, _, bodiless = broker_request.response_framing(
            200, [("content-length", "5")], "GET")
        self.assertFalse(bodiless)


class BrokerServerCase(unittest.TestCase):
    """A real broker on loopback, for the checks that are about connections.

    No upstream is configured or needed: every request below is answered or
    dropped before the broker would forward anything.
    """

    handler_timeout = None

    def setUp(self):
        case = self

        class H(broker_server.Handler):
            connect_timeout = 1.0
            read_timeout = 1.0
            profiles = profile_table()
            overflow = 65534
            # The caller here is the test process, so the instance is started
            # for its uid -- as the flag would say -- or _identify would
            # refuse it before any of these assertions ran.
            name = "agent"
            workload_uid = os.getuid()
            if case.handler_timeout is not None:
                timeout = case.handler_timeout

        self.server = broker_server.Server(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join, 5)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def connect(self):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        self.addCleanup(sock.close)
        return sock

    def drain(self, sock, timeout=5):
        sock.settimeout(timeout)
        chunks = []
        with contextlib.suppress(TimeoutError, OSError):
            while True:
                buf = sock.recv(65536)
                if not buf:
                    break
                chunks.append(buf)
        return b"".join(chunks)


class TestOneCallerCannotTakeThePool(BrokerServerCase):
    """The denial of service the global bound alone permitted.

    MAX_CONCURRENT caps live connections; on its own it is a lever rather than a
    protection, because one sandbox reaching the cap refuses every other. These
    connections send no bytes at all — which was enough, and is why the fix is a
    per-caller ceiling and not a larger pool.
    """

    def test_a_caller_is_refused_past_its_own_ceiling(self):
        with mock.patch.object(broker_server, "MAX_PER_CALLER", 2):
            held = [self.connect() for _ in range(2)]
            self.assertTrue(all(s.fileno() >= 0 for s in held))
            refused = self.connect()
            self.assertEqual(self.drain(refused, timeout=5), b"",
                             "past the ceiling the connection must be closed")

    def test_the_ceiling_is_released_when_a_connection_ends(self):
        with mock.patch.object(broker_server, "MAX_PER_CALLER", 1):
            first = self.connect()
            first.close()
            # A slot freed by the previous caller is usable, not leaked: the
            # bookkeeping is a live count, not a high-water mark.
            second = self.connect()
            second.sendall(b"GET /v1/models HTTP/1.1\r\nHost: x\r\n"
                           b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
            self.assertIn(b"411", self.drain(second))


class TestAFailedSpawnDoesNotLeakASlot(unittest.TestCase):
    """`t.start()` raises when the host is out of threads, and nothing
    downstream runs shutdown_request for a thread that never started.

    A leaked global slot is bad; a leaked per-caller slot is worse, because it
    locks that one caller out for the life of the process — and the host being
    out of threads is exactly the moment the broker needs to recover on its own.
    The pool here is one connection wide so a single leak is the difference
    between working and wedged.
    """

    def test_the_slot_comes_back_after_the_thread_fails_to_start(self):
        # This case builds its own server rather than using BrokerServerCase, so
        # it needs the same identity: without it the probe below is refused
        # at _identify and answers 403, which would ALSO prove the slot came
        # back -- and would make the 411 assertion pass for the wrong reason if
        # it were ever loosened.
        with mock.patch.object(broker_server, "MAX_CONCURRENT", 1):
            class H(broker_server.Handler):
                connect_timeout, read_timeout = 1.0, 1.0
                profiles, overflow = profile_table(), 65534
                name, workload_uid = "agent", os.getuid()

            server = broker_server.Server(("127.0.0.1", 0), H)
            self.addCleanup(server.server_close)
            port = server.server_address[1]

            with mock.patch("threading.Thread.start",
                            side_effect=RuntimeError("can't start new thread")):
                doomed = socket.create_connection(("127.0.0.1", port), timeout=5)
                self.addCleanup(doomed.close)
                # BaseServer reports it through handle_error and closes the
                # connection itself; the traceback is wanted behaviour (this is
                # a bug, not a hostile caller) and only noise here.
                with contextlib.redirect_stderr(io.StringIO()):
                    server.handle_request()

            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(thread.join, 5)
            self.addCleanup(server.shutdown)

            after = socket.create_connection(("127.0.0.1", port), timeout=5)
            self.addCleanup(after.close)
            after.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n"
                          b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
            after.settimeout(5)
            self.assertIn(b"411", after.recv(200),
                          "the only slot was never returned")


class TestIdleConnectionsAreReaped(BrokerServerCase):
    handler_timeout = 0.5

    def test_a_connection_that_sends_nothing_is_dropped(self):
        """Without a timeout this held its handler thread for ever, and enough
        of them denied the broker to every sandbox on the host."""
        sock = self.connect()
        self.assertEqual(self.drain(sock, timeout=5), b"")


class TestARefusalEndsTheConnection(BrokerServerCase):
    """A rejected request leaves its body unread, so the connection can no
    longer be framed. Reading on desynchronises it: measured, before the fix, as
    a following pipelined request that received no response at all while the
    first was answered 200.
    """

    def test_a_chunked_request_is_refused_and_the_connection_closed(self):
        sock = self.connect()
        sock.sendall(b"POST /first HTTP/1.1\r\nHost: x\r\n"
                     b"Transfer-Encoding: chunked\r\n\r\n"
                     b"4\r\nabcd\r\n0\r\n\r\n"
                     b"GET /second HTTP/1.1\r\nHost: x\r\n\r\n")
        received = self.drain(sock)
        self.assertIn(b"411", received)
        self.assertEqual(received.count(b"HTTP/1.1"), 1,
                         "the leftover body must not be parsed as a request")
        self.assertIn(b"Connection: close", received)


class StubResponse:
    """An upstream response that hands out `chunks` and then ends.

    `die` picks how it ends: IncompleteRead, which is how a dropped upstream
    really presents and is the HTTPException the request path already catches,
    or a clean b"" EOF.
    """

    def __init__(self, status, hdrs, chunks, die=True):
        self.status, self._headers = status, hdrs
        self._chunks, self._die = list(chunks), die

    def getheaders(self):
        return self._headers

    def read1(self, _n):
        if self._chunks:
            return self._chunks.pop(0)
        if self._die:
            raise broker_server.http.client.IncompleteRead(b"", 1)
        return b""


class TestTheBodyBudgetIsShared(BrokerServerCase):
    """The bound the other two limits do not express.

    A request body is buffered whole before it is forwarded. MAX_REQUEST_BYTES
    bounds one of them and MAX_PER_CALLER bounds one caller's connections, so
    every individual request stays legal while the sum does not: 32 connections
    each sending 64 MiB reserved 2 GiB. On a hypervisor that is memory the VMs
    are using.
    """

    def test_a_request_past_the_shared_budget_is_refused(self):
        with mock.patch.object(broker_server, "MAX_INFLIGHT_BYTES", 64):
            sock = self.connect()
            sock.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\n"
                         b"Content-Length: 128\r\n\r\n" + b"x" * 128)
            received = self.drain(sock)
        self.assertIn(b"503", received.split(b"\r\n")[0])

    def test_a_bodiless_request_never_costs_budget(self):
        """Otherwise a full budget stops GETs, which hold nothing."""
        with mock.patch.object(broker_server, "MAX_INFLIGHT_BYTES", 0):
            self.assertTrue(self.server.reserve_body(0))

    def test_one_request_can_exhaust_the_budget_for_another(self):
        """The property under test: the budget is shared, not per connection.
        A per-connection cap is what MAX_REQUEST_BYTES already was."""
        with mock.patch.object(broker_server, "MAX_INFLIGHT_BYTES", 100):
            self.assertTrue(self.server.reserve_body(60))
            self.assertFalse(self.server.reserve_body(60),
                             "two 60-byte bodies fit in a 100-byte budget")
            self.server.release_body(60)
            self.assertTrue(self.server.reserve_body(60),
                            "the budget did not come back when the first ended")
            self.server.release_body(60)
        self.assertEqual(self.server._inflight, 0)

    def test_the_budget_comes_back_after_a_refusal(self):
        """The leak that would turn a transient overload into a wedged broker:
        every later request refused because a reservation was never returned."""
        with mock.patch.object(broker_server, "MAX_INFLIGHT_BYTES", 64):
            for _ in range(3):
                sock = self.connect()
                sock.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\n"
                             b"Content-Length: 128\r\n\r\n" + b"x" * 128)
                self.drain(sock)
        self.assertEqual(self.server._inflight, 0)


class DyingUpstream:
    """Stands in for HTTPSConnection. Answers, then ends per its response."""

    response = None  # set per test

    def __init__(self, *args, **kwargs):
        self.sock = mock.Mock()

    def request(self, *args, **kwargs):
        pass

    def getresponse(self):
        return self.response

    def close(self):
        pass


class TestAnUpstreamDyingMidResponse(BrokerServerCase):
    """What the caller is left holding when the upstream drops mid-answer.

    The head is already on the wire by then, so there is no way to retract it
    and send a 502 instead: doing that writes a second complete response *into
    the body of the first*. Under Content-Length the caller either truncates at
    the declared length or keeps the trailing garbage; under chunked, the raw
    status line is parsed as a chunk header. Both hand back something shaped
    like an answer, which for relayed model output is the worst outcome
    available — worse than an error, because nothing downstream can tell.

    Truncation is the fix and the assertion: one status line, no second
    response, and a body that ends without its terminator.
    """

    def _drive(self, status, hdrs, chunks, die=True):
        upstream = DyingUpstream
        upstream.response = StubResponse(status, hdrs, chunks, die=die)
        with mock.patch.object(broker_server.http.client, "HTTPSConnection", upstream):
            sock = self.connect()
            sock.sendall(b"GET /v1/messages HTTP/1.1\r\nHost: x\r\n\r\n")
            return self.drain(sock)

    def test_a_streaming_response_is_truncated_not_capped_with_a_502(self):
        received = self._drive(200, [("content-type", "text/event-stream")],
                               [b"data: one\n\n", b"data: two\n\n"])

        self.assertIn(b"200", received.split(b"\r\n")[0],
                      "the upstream's own status must still reach the caller")
        self.assertEqual(received.count(b"HTTP/1.1 "), 1,
                         "a second response was written into the first's body")
        self.assertNotIn(b"502", received)
        self.assertIn(b"data: one", received, "delivered bytes are kept")
        self.assertFalse(received.endswith(b"0\r\n\r\n"),
                         "a terminated chunked body claims the answer is "
                         "complete, which is exactly what it is not")

    def test_a_counted_response_stops_short_of_its_declared_length(self):
        received = self._drive(200, [("content-length", "4096")], [b"partial"])

        self.assertEqual(received.count(b"HTTP/1.1 "), 1,
                         "a second response was written into the first's body")
        self.assertNotIn(b"502", received)
        head, _, body = received.partition(b"\r\n\r\n")
        self.assertIn(b"Content-Length: 4096", head)
        self.assertLess(len(body), 4096,
                        "short of the declared length is how the caller learns "
                        "the message was cut off")

    def test_a_failure_before_the_head_still_answers_502(self):
        """The other side of the same branch: nothing is on the wire yet, so a
        real error response is both possible and correct."""
        class DeadOnArrival(DyingUpstream):
            def getresponse(self):
                raise broker_server.http.client.IncompleteRead(b"", 1)

        with mock.patch.object(broker_server.http.client, "HTTPSConnection",
                               DeadOnArrival):
            sock = self.connect()
            sock.sendall(b"GET /v1/messages HTTP/1.1\r\nHost: x\r\n\r\n")
            received = self.drain(sock)

        self.assertIn(b"502", received.split(b"\r\n")[0])


class TestARelayedResponseIsWellFormed(TestAnUpstreamDyingMidResponse):
    """Header hygiene on the wire, where the duplicates actually appear.

    response_framing is unit-tested above, but it only decides what is passed
    *through* — BaseHTTPRequestHandler's send_response adds a Date and a
    Server of its own, so whether the caller ends up with the provider's one
    of each is a property of the two together and cannot be seen from either
    alone.
    """

    def _headers_of(self, received):
        head = received.partition(b"\r\n\r\n")[0]
        counts = {}
        for line in head.split(b"\r\n")[1:]:
            name = line.split(b":")[0].strip().lower()
            counts[name] = counts.get(name, 0) + 1
        return counts

    def test_the_caller_gets_the_providers_date_and_server_once(self):
        received = self._drive(
            200,
            [("Date", "Mon, 01 Jan 2035 00:00:00 GMT"),
             ("Server", "upstream-edge/2"),
             ("Content-Type", "application/json"),
             ("Content-Length", "2")],
            [b"{}"], die=False)

        counts = self._headers_of(received)
        self.assertEqual(counts.get(b"date"), 1, "duplicate Date reached the caller")
        self.assertEqual(counts.get(b"server"), 1,
                         "duplicate Server reached the caller")
        self.assertEqual(counts.get(b"content-length"), 1,
                         "the upstream's length survived the re-framing")
        self.assertIn(b"Server: upstream-edge/2", received)
        self.assertIn(b"Date: Mon, 01 Jan 2035 00:00:00 GMT", received)
        self.assertNotIn(b"customs", received.lower(),
                         "the broker named itself to the sandbox")
        self.assertTrue(received.endswith(b"{}"))


class TestAnUnsendableCredentialStaysOutOfTheJournal(BrokerServerCase):
    """The second line behind build_profiles' refusal at start.

    A header value http.client will not send raises ValueError with the
    value in its message. Uncaught, the server printed that traceback to
    stderr -- the journal -- with the credential in it, on every request.
    """

    def test_it_is_a_bare_502_logged_by_type(self):
        leaky = profile(auth_value="Bearer sk-first\nsk-second")
        self.server.RequestHandlerClass.profiles = profile_table(leaky)
        err = io.StringIO()
        with mock.patch("sys.stderr", err), \
                mock.patch.object(broker_server, "log") as log:
            sock = self.connect()
            sock.sendall(b"GET /v1/messages HTTP/1.1\r\n"
                         b"Host: api.example.com\r\n\r\n")
            received = self.drain(sock)
        self.assertNotIn("sk-first", err.getvalue())
        self.assertNotIn("sk-second", err.getvalue())
        self.assertIn(b" 502 ", received.split(b"\r\n", 1)[0])
        log.assert_any_call("upstream-error", sandbox="agent/api.example.com",
                            path="/v1/messages", error="ValueError",
                            streamed=False)


class TestARefusalSaysNothingOfTheBroker(BrokerServerCase):
    """The inspector relays the broker's answer to the guest as the
    provider's, so a refusal of the broker's own may carry the status and
    its phrase and nothing that says a broker is there: no Server, no
    sentence. The reason is the log line's."""

    def _assert_generic(self, received, status, phrase):
        head, _, body = received.partition(b"\r\n\r\n")
        self.assertIn(f" {status} ".encode(), head.split(b"\r\n")[0])
        self.assertEqual(body, phrase + b"\n")
        self.assertNotIn(b"\r\nserver:", head.lower())
        self.assertIn(b"\r\nDate: ", head)

    def test_a_failed_upstream_is_a_bare_502(self):
        class Unresolvable(DyingUpstream):
            def request(self, *args, **kwargs):
                raise OSError(-2, "Name or service not known")

        with mock.patch.object(broker_server.http.client, "HTTPSConnection",
                               Unresolvable), \
                mock.patch.object(broker_server, "log") as log:
            sock = self.connect()
            sock.sendall(b"GET /v1/messages HTTP/1.1\r\nHost: x\r\n\r\n")
            received = self.drain(sock)
        self._assert_generic(received, 502, b"Bad Gateway")
        log.assert_any_call("upstream-error", sandbox="agent/api.example.com",
                            path="/v1/messages", error="OSError",
                            streamed=False)

    def test_an_unconfigured_host_is_a_bare_403(self):
        with mock.patch.object(broker_server, "log") as log:
            sock = self.connect()
            sock.sendall(b"GET / HTTP/1.1\r\nHost: unlisted.example\r\n"
                         b"\r\n")
            received = self.drain(sock)
        self._assert_generic(received, 403, b"Forbidden")
        log.assert_called_with("deny", reason="host-not-configured",
                               sandbox="agent", host="unlisted.example")

    def test_a_framing_refusal_keeps_its_reason_in_the_log(self):
        with mock.patch.object(broker_server, "log") as log:
            sock = self.connect()
            sock.sendall(b"POST / HTTP/1.1\r\nHost: x\r\n"
                         b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
            received = self.drain(sock)
        self._assert_generic(received, 411, b"Length Required")
        log.assert_called_with(
            "deny", reason="chunked-request", sandbox="agent/api.example.com",
            bytes=0,
            detail="chunked request bodies are not accepted; send "
                   "Content-Length")

    def test_the_base_classs_own_refusal_is_no_python_page(self):
        """A method with no do_ is refused by BaseHTTPRequestHandler, whose
        own answer is an HTML page in Python's words."""
        with mock.patch.object(broker_server, "log") as log:
            sock = self.connect()
            sock.sendall(b"TRACE / HTTP/1.1\r\nHost: x\r\n\r\n")
            received = self.drain(sock)
        self._assert_generic(received, 501, b"Not Implemented")
        self.assertEqual(log.call_args.args, ("deny",))
        self.assertEqual(log.call_args.kwargs["reason"], "http-501")


class TestEveryApiMethodIsRelayed(BrokerServerCase):
    """The broker serves the methods an HTTP API uses, not a subset.

    Which method a request may use is the inspector's policy, applied
    before the request is sent here. A method this handler has no do_ for
    is answered 501 by the base class, so a policy permitting PATCH on a
    brokered host got a 501 from the broker, after the policy said yes.
    """

    def setUp(self):
        super().setUp()
        self.seen = []
        case = self

        class Recording(DyingUpstream):
            def request(self, method, path, body=None, headers=None):
                case.seen.append((method, dict(headers or {})))
                self._method = method

            def getresponse(self):
                body = [] if self._method == "HEAD" else [b"ok"]
                return StubResponse(200, [("content-length", "2")], body,
                                    die=False)

        self.enterContext(mock.patch.object(
            broker_server.http.client, "HTTPSConnection", Recording))

    def _send(self, method):
        sock = self.connect()
        sock.sendall(method.encode() + b" /v1/x HTTP/1.1\r\nHost: x\r\n"
                     b"Content-Length: 0\r\nConnection: close\r\n\r\n")
        return self.drain(sock)

    def test_each_method_reaches_the_upstream_with_the_credential(self):
        for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            with self.subTest(method=method):
                received = self._send(method)
                self.assertIn(b" 200 ", received.split(b"\r\n")[0])
                self.assertTrue(received.endswith(b"ok"))
                self.assertEqual(self.seen[-1][0], method)
                self.assertEqual(self.seen[-1][1]["x-api-key"],
                                 "REAL-SECRET")

    def test_head_is_relayed_with_its_length_and_no_body(self):
        received = self._send("HEAD")
        head, _, body = received.partition(b"\r\n\r\n")
        self.assertIn(b" 200 ", head.split(b"\r\n")[0])
        self.assertIn(b"Content-Length: 2", head)
        self.assertNotIn(b"chunked", head.lower())
        self.assertEqual(body, b"")
        self.assertEqual(self.seen[-1][0], "HEAD")

    def test_a_refused_head_carries_no_body(self):
        sock = self.connect()
        sock.sendall(b"HEAD /v1/x HTTP/1.1\r\nHost: unlisted.example\r\n"
                     b"Connection: close\r\n\r\n")
        head, _, body = self.drain(sock).partition(b"\r\n\r\n")
        self.assertIn(b" 403 ", head.split(b"\r\n")[0])
        self.assertEqual(body, b"")

    def test_connect_and_trace_are_still_refused(self):
        for method in ("CONNECT", "TRACE"):
            with self.subTest(method=method):
                received = self._send(method)
                self.assertIn(b" 501 ", received.split(b"\r\n")[0])
        self.assertEqual(self.seen, [])


class TestTheHostSelectsTheCredential(BrokerServerCase):
    """ADR 007 decision 3, at the request boundary rather than at config load.

    The key is (workload, Host). What has to hold is that the header SELECTS a
    row and supplies nothing else: an unlisted Host gets no credential at all
    rather than the sandbox's other one, and a body claiming a different
    destination than the header changes neither which key is attached nor where
    the request goes.
    """

    def setUp(self):
        super().setUp()
        # Two hosts with two different keys -- the shape the per-Host key
        # exists for, and the one a table with a single profile per instance
        # could not represent.
        cls = type(self.server.RequestHandlerClass.__name__,
                   (self.server.RequestHandlerClass,), {})
        cls.profiles = {
            "api.example.com": profile(auth_value="KEY-FOR-EXAMPLE"),
            "api.github.com": profile(
                auth_value="KEY-FOR-GITHUB", host="api.github.com"),
        }
        self.server.RequestHandlerClass = cls
        self.seen = []
        case = self

        class Recording(DyingUpstream):
            def __init__(self, host, port, **kwargs):
                super().__init__()
                self._host = host

            def request(self, method, path, body=None, headers=None):
                case.seen.append((self._host, path, dict(headers or {})))

            def getresponse(self):
                return StubResponse(200, [("content-length", "2")], [b"ok"],
                                    die=False)

        self.enterContext(mock.patch.object(
            broker_server.http.client, "HTTPSConnection", Recording))

    def _get(self, host, extra=b""):
        # Connection: close so drain() returns on EOF rather than on its own
        # timeout -- these assertions are about dispatch, and paying five
        # seconds each to prove keep-alive works is a cost the keep-alive test
        # below already covers.
        sock = self.connect()
        sock.sendall(b"GET /v1/x HTTP/1.1\r\nHost: " + host.encode() +
                     b"\r\nConnection: close\r\n" + extra + b"\r\n")
        return self.drain(sock)

    def test_each_host_gets_its_own_credential(self):
        self._get("api.example.com")
        self._get("api.github.com")
        self.assertEqual([h for h, _, _ in self.seen],
                         ["api.example.com", "api.github.com"])
        self.assertEqual([hdrs["x-api-key"] for _, _, hdrs in self.seen],
                         ["KEY-FOR-EXAMPLE", "KEY-FOR-GITHUB"])

    def test_an_unlisted_host_gets_no_credential_rather_than_the_other_one(self):
        """The failure this refusal prevents is silent in the worst way: the
        request succeeds, against the wrong provider, carrying a real key."""
        received = self._get("api.elsewhere.com")
        self.assertIn(b"403", received.split(b"\r\n")[0])
        self.assertEqual(self.seen, [], "nothing may reach an upstream")

    def test_a_host_is_matched_lowercased_and_without_its_port(self):
        self._get("API.Example.com:443")
        self.assertEqual([h for h, _, _ in self.seen], ["api.example.com"])

    def test_a_missing_host_header_is_refused(self):
        sock = self.connect()
        sock.sendall(b"GET /v1/x HTTP/1.0\r\nConnection: close\r\n\r\n")
        self.assertIn(b"403", self.drain(sock).split(b"\r\n")[0])
        self.assertEqual(self.seen, [])

    def test_a_body_claiming_another_destination_changes_nothing(self):
        """§14's assertion shape. The profile is resolved from this instance's
        own table; the only thing the caller contributes is which row."""
        sock = self.connect()
        payload = b'{"host":"api.github.com"}'
        sock.sendall(b"POST /v1/x HTTP/1.1\r\nHost: api.example.com\r\n"
                     b"Connection: close\r\nContent-Length: " +
                     str(len(payload)).encode() + b"\r\n\r\n" + payload)
        self.drain(sock)
        self.assertEqual([h for h, _, _ in self.seen], ["api.example.com"])
        self.assertEqual([hdrs["x-api-key"] for _, _, hdrs in self.seen],
                         ["KEY-FOR-EXAMPLE"])

    def test_two_hosts_on_one_keep_alive_connection_get_their_own(self):
        """Identity is per connection and the Host is per REQUEST. Resolving
        the profile once at setup would give the second request the first's
        credential, which no test sending one request per connection can see."""
        sock = self.connect()
        sock.sendall(b"GET /v1/x HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
                     b"GET /v1/y HTTP/1.1\r\nHost: api.github.com\r\n"
                     b"Connection: close\r\n\r\n")
        self.drain(sock)
        self.assertEqual([hdrs["x-api-key"] for _, _, hdrs in self.seen],
                         ["KEY-FOR-EXAMPLE", "KEY-FOR-GITHUB"])

    def test_the_forwarded_path_is_the_callers_own(self):
        """`prefix` is deleted. A base path would rewrite the very path the
        inspector's `paths` patterns admitted."""
        self._get("api.example.com")
        self.assertEqual([p for _, p, _ in self.seen], ["/v1/x"])


if __name__ == "__main__":
    unittest.main()
