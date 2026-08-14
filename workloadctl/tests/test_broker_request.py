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
import socket
import threading
import unittest
from email.message import Message
from unittest import mock

from tests import load_script

broker = load_script("libexec/agent-broker")


def headers(**pairs):
    """An email.message.Message, which is what BaseHTTPRequestHandler parses
    request headers into — including its case-insensitive lookup."""
    msg = Message()
    for key, value in pairs.items():
        msg[key.replace("_", "-")] = value
    return msg


def profile(auth_header="x-api-key", auth_value="REAL-SECRET", host="api.example.com"):
    return broker.Profile(
        name="agent", host=host, port=443, prefix="/v1",
        auth_header=auth_header, auth_format="{secret}",
        secret="REAL-SECRET", auth_value=auth_value,
    )


class TestForwardedHeaders(unittest.TestCase):

    def test_the_credential_is_attached(self):
        out = broker.forwarded_headers(headers(), profile())
        self.assertEqual(out["x-api-key"], "REAL-SECRET")

    def test_the_upstream_host_replaces_the_callers(self):
        out = broker.forwarded_headers(headers(Host="broker.local"), profile())
        self.assertEqual(out["Host"], "api.example.com")
        self.assertEqual([k for k in out if k.lower() == "host"], ["Host"])

    def test_credential_shaped_headers_are_dropped(self):
        out = broker.forwarded_headers(
            headers(Authorization="Bearer stolen", x_api_key="stolen",
                    api_key="stolen", x_goog_api_key="stolen", Cookie="s=1"),
            profile())
        self.assertEqual(
            [k for k in out if k.lower() != "host"], ["x-api-key"])
        self.assertEqual(out["x-api-key"], "REAL-SECRET")

    def test_case_does_not_smuggle_one_past_the_strip_list(self):
        out = broker.forwarded_headers(headers(AUTHORIZATION="Bearer stolen"),
                                       profile())
        self.assertNotIn("stolen", "".join(out.values()))

    def test_the_configured_auth_header_is_stripped_by_name(self):
        """The regression. `auth_header` may be any string, and only four names
        are on the fixed list — so with a custom one the caller's copy used to
        survive under a different capitalisation and reach the provider beside
        the real credential."""
        out = broker.forwarded_headers(
            headers(x_custom_key="ATTACKER"),
            profile(auth_header="X-Custom-Key"))
        self.assertEqual(list(out.values()).count("ATTACKER"), 0)
        self.assertEqual(out["X-Custom-Key"], "REAL-SECRET")

    def test_hop_by_hop_headers_do_not_cross(self):
        out = broker.forwarded_headers(
            headers(Connection="keep-alive", TE="trailers",
                    Transfer_Encoding="chunked"), profile())
        self.assertEqual([k for k in out if k.lower() != "host"], ["x-api-key"])

    def test_everything_else_passes_through(self):
        """A denylist on purpose: provider SDKs send version and beta headers
        that change faster than an allowlist would be maintained."""
        out = broker.forwarded_headers(
            headers(anthropic_version="2023-06-01", anthropic_beta="a,b",
                    Content_Type="application/json"), profile())
        self.assertEqual(out["anthropic-version"], "2023-06-01")
        self.assertEqual(out["anthropic-beta"], "a,b")
        self.assertEqual(out["Content-Type"], "application/json")


class TestRequestFraming(unittest.TestCase):

    def test_an_ordinary_request_is_accepted(self):
        length, rejection = broker.request_framing(
            "/v1/messages", headers(Content_Length="12"))
        self.assertEqual(length, 12)
        self.assertIsNone(rejection)

    def test_no_content_length_means_no_body(self):
        length, rejection = broker.request_framing("/v1/models", headers())
        self.assertEqual((length, rejection), (0, None))

    def test_an_empty_content_length_is_not_an_error(self):
        length, rejection = broker.request_framing(
            "/v1/models", headers(Content_Length="  "))
        self.assertEqual((length, rejection), (0, None))

    def test_an_absolute_target_is_refused(self):
        _, rejection = broker.request_framing(
            "https://elsewhere.example/v1", headers())
        self.assertEqual(rejection[0], 400)
        self.assertEqual(rejection[1], "absolute-target")

    def test_a_chunked_body_is_refused_rather_than_dropped(self):
        """It used to be neither: Transfer-Encoding is hop-by-hop and was
        stripped, no Content-Length meant length 0, and the body went nowhere
        while the caller got a 200 for a request the provider never saw."""
        _, rejection = broker.request_framing(
            "/v1/messages", headers(Transfer_Encoding="chunked"))
        self.assertEqual(rejection[0], 411)
        self.assertEqual(rejection[1], "chunked-request")

    def test_a_non_numeric_content_length_is_refused(self):
        """It used to raise ValueError out of the handler: no log line, no
        response, just a reset connection."""
        _, rejection = broker.request_framing(
            "/v1/messages", headers(Content_Length="twelve"))
        self.assertEqual(rejection[0], 400)

    def test_two_content_lengths_are_refused(self):
        """Two lengths frame two messages; taking the first leaves the rest of
        the other in the socket, to be read as the next request line."""
        msg = Message()
        msg["Content-Length"] = "4"
        msg["Content-Length"] = "40"
        _, rejection = broker.request_framing("/v1/messages", msg)
        self.assertEqual(rejection[0], 400)
        self.assertEqual(rejection[1], "duplicate-content-length")

    def test_a_negative_content_length_is_refused(self):
        """rfile.read(-1) reads to EOF, so this held a slot for as long as the
        caller cared to keep the socket open."""
        _, rejection = broker.request_framing(
            "/v1/messages", headers(Content_Length="-1"))
        self.assertEqual(rejection[0], 400)

    def test_an_oversized_body_is_refused(self):
        length, rejection = broker.request_framing(
            "/v1/messages",
            headers(Content_Length=str(broker.MAX_REQUEST_BYTES + 1)))
        self.assertEqual(rejection[0], 413)
        self.assertEqual(length, broker.MAX_REQUEST_BYTES + 1)

    def test_the_size_limit_is_inclusive(self):
        length, rejection = broker.request_framing(
            "/v1/messages", headers(Content_Length=str(broker.MAX_REQUEST_BYTES)))
        self.assertEqual((length, rejection), (broker.MAX_REQUEST_BYTES, None))


class TestResponseFraming(unittest.TestCase):

    def test_a_declared_length_is_carried_through(self):
        passthrough, declared, bodiless = broker.response_framing(
            200, [("Content-Type", "application/json"), ("Content-Length", "17")])
        self.assertEqual(passthrough, [("Content-Type", "application/json")])
        self.assertEqual(declared, "17")
        self.assertFalse(bodiless)

    def test_content_length_is_found_whatever_its_case(self):
        _, declared, _ = broker.response_framing(200, [("content-length", "5")])
        self.assertEqual(declared, "5")

    def test_a_stream_declares_no_length(self):
        passthrough, declared, _ = broker.response_framing(
            200, [("Content-Type", "text/event-stream")])
        self.assertIsNone(declared)
        self.assertEqual(passthrough, [("Content-Type", "text/event-stream")])

    def test_hop_by_hop_headers_do_not_come_back(self):
        passthrough, _, _ = broker.response_framing(
            200, [("Connection", "keep-alive"), ("Transfer-Encoding", "chunked"),
                  ("Content-Type", "application/json")])
        self.assertEqual(passthrough, [("Content-Type", "application/json")])

    def test_headers_the_handler_stamps_itself_do_not_come_back(self):
        """BaseHTTPRequestHandler writes Date and Server onto every response,
        so relaying the upstream's produces two of each — a duplicate that a
        client resolves by picking one, and that intermediaries resolve
        differently from each other."""
        passthrough, _, _ = broker.response_framing(
            200, [("Date", "Mon, 01 Jan 2035 00:00:00 GMT"),
                  ("Server", "upstream-edge/2"),
                  ("Content-Type", "application/json")])
        self.assertEqual(passthrough, [("Content-Type", "application/json")])

    def test_204_and_304_carry_no_body(self):
        for status in (204, 304):
            _, _, bodiless = broker.response_framing(status, [])
            self.assertTrue(bodiless, status)


class BrokerServerCase(unittest.TestCase):
    """A real broker on loopback, for the checks that are about connections.

    No upstream is configured or needed: every request below is answered or
    dropped before the broker would forward anything.
    """

    handler_timeout = None

    def setUp(self):
        case = self

        class H(broker.Handler):
            config = {"connect_timeout": 1.0, "read_timeout": 1.0}
            profiles = {}
            fallback = profile()
            overflow = 65534
            if case.handler_timeout is not None:
                timeout = case.handler_timeout

        self.server = broker.Server(("127.0.0.1", 0), H)
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
        with mock.patch.object(broker, "MAX_PER_CALLER", 2):
            held = [self.connect() for _ in range(2)]
            self.assertTrue(all(s.fileno() >= 0 for s in held))
            refused = self.connect()
            self.assertEqual(self.drain(refused, timeout=5), b"",
                             "past the ceiling the connection must be closed")

    def test_the_ceiling_is_released_when_a_connection_ends(self):
        with mock.patch.object(broker, "MAX_PER_CALLER", 1):
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
        with mock.patch.object(broker, "MAX_CONCURRENT", 1):
            class H(broker.Handler):
                config = {"connect_timeout": 1.0, "read_timeout": 1.0}
                profiles, fallback, overflow = {}, profile(), 65534

            server = broker.Server(("127.0.0.1", 0), H)
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
            raise broker.http.client.IncompleteRead(b"", 1)
        return b""


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
        with mock.patch.object(broker.http.client, "HTTPSConnection", upstream):
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
                raise broker.http.client.IncompleteRead(b"", 1)

        with mock.patch.object(broker.http.client, "HTTPSConnection",
                               DeadOnArrival):
            sock = self.connect()
            sock.sendall(b"GET /v1/messages HTTP/1.1\r\nHost: x\r\n\r\n")
            received = self.drain(sock)

        self.assertIn(b"502", received.split(b"\r\n")[0])


class TestARelayedResponseIsWellFormed(TestAnUpstreamDyingMidResponse):
    """Header hygiene on the wire, where the duplicates actually appear.

    response_framing is unit-tested above, but it only decides what is passed
    *through* — the handler adds Date and Server itself afterwards, so whether
    the caller ends up with one of each is a property of the two together and
    cannot be seen from either alone.
    """

    def _headers_of(self, received):
        head = received.partition(b"\r\n\r\n")[0]
        counts = {}
        for line in head.split(b"\r\n")[1:]:
            name = line.split(b":")[0].strip().lower()
            counts[name] = counts.get(name, 0) + 1
        return counts

    def test_the_caller_gets_one_date_and_one_server(self):
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
        self.assertNotIn(b"upstream-edge/2", received,
                         "the provider's edge is named to the sandbox")
        self.assertTrue(received.endswith(b"{}"))


if __name__ == "__main__":
    unittest.main()
