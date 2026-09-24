"""egress_relay.relay: both directions at once, over plain sockets and TLS.

The relay sits between two peers that each may write before they read.
An origin that answers before it has read the upload -- a 401 or 413
during a large POST, a WebSocket, a bidirectional h2 stream -- waits on
its write while the guest waits on its own, and a relay that blocks in
one direction's write never reads the other: all three stall until the
idle timeout ends the connection. Each exchange here is sized past what
the socket buffers absorb, which is what makes the stall reachable.
"""

import select
import socket
import ssl
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import egress_relay
from egress_ca import ca_openssl_argv, leaf_openssl_argv

from tests.test_inspect_terminate import _have_openssl, _run

# Past every socket buffer between the two peers, so a relay that serves
# one direction at a time is made to.
SIZE = 8 * 1024 * 1024
TLS_SIZE = 4 * 1024 * 1024


def _pattern(n, seed):
    """`n` bytes that are not all one value, so a reordering shows."""
    block = bytes((seed + i) % 251 for i in range(4096))
    return (block * (n // len(block) + 1))[:n]


class _Peer:
    """One end of the exchange: writes `outgoing` and reads until the far
    end closes or `expect` bytes have arrived, both at once on one thread,
    since an SSLSocket cannot be read and written from two. With
    `answer_first`, it writes everything before it reads a byte, as an
    origin answering early does."""

    def __init__(self, sock, outgoing, expect, answer_first=False):
        self.sock = sock
        self.outgoing = outgoing
        self.expect = expect
        self.answer_first = answer_first
        self.received = bytearray()
        self.error = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def _run(self):
        try:
            if self.answer_first:
                self.sock.settimeout(30)
                self.sock.sendall(self.outgoing)
                while len(self.received) < self.expect:
                    chunk = self.sock.recv(65536)
                    if not chunk:
                        break
                    self.received += chunk
            else:
                self._duplex()
        except Exception as exc:  # noqa: BLE001
            self.error = exc

    def _duplex(self):
        sock, out, sent = self.sock, memoryview(self.outgoing), 0
        sock.setblocking(False)
        deadline = time.monotonic() + 30
        while sent < len(out) or len(self.received) < self.expect:
            if time.monotonic() > deadline:
                raise TimeoutError(f"sent {sent}, received "
                                   f"{len(self.received)}")
            writing = [sock] if sent < len(out) else []
            buffered = getattr(sock, "pending", None) and sock.pending()
            readable, writable, _ = select.select(
                [sock], writing, [], 0 if buffered else 1)
            if readable or buffered:
                try:
                    chunk = sock.recv(65536)
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError,
                        BlockingIOError):
                    chunk = None
                if chunk == b"":
                    break
                if chunk:
                    self.received += chunk
            if writable:
                try:
                    # The same bytes after a refusal, as TLS requires.
                    sent += sock.send(out[sent:sent + 16384])
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError,
                        BlockingIOError):
                    pass


def _relay_in_thread(client, upstream, **kw):
    outcome = {}

    def run():
        try:
            egress_relay.relay(client, upstream, **kw)
            outcome["returned"] = True
        except Exception as exc:  # noqa: BLE001
            outcome["raised"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, outcome


class TestBothDirectionsAtOnce(unittest.TestCase):
    """The stall, over plain sockets."""

    def setUp(self):
        patch = mock.patch.object(egress_relay, "RELAY_IDLE_TIMEOUT", 5.0)
        patch.start()
        self.addCleanup(patch.stop)

    def _pairs(self):
        guest, relay_client = socket.socketpair()
        relay_upstream, origin = socket.socketpair()
        for s in (guest, relay_client, relay_upstream, origin):
            self.addCleanup(s.close)
        return guest, relay_client, relay_upstream, origin

    def test_an_origin_that_answers_first_is_not_a_stall(self):
        guest, relay_client, relay_upstream, origin = self._pairs()
        upload, answer = _pattern(SIZE, 1), _pattern(SIZE, 2)
        started = time.monotonic()
        thread, outcome = _relay_in_thread(relay_client, relay_upstream)
        g = _Peer(guest, upload, SIZE).start()
        o = _Peer(origin, answer, SIZE, answer_first=True).start()
        g.thread.join(20)
        o.thread.join(20)
        took = time.monotonic() - started
        self.assertIsNone(g.error)
        self.assertIsNone(o.error)
        self.assertEqual(len(o.received), SIZE, "the upload stalled")
        self.assertEqual(len(g.received), SIZE, "the answer stalled")
        self.assertEqual(bytes(o.received), upload)
        self.assertEqual(bytes(g.received), answer)
        self.assertLess(took, egress_relay.RELAY_IDLE_TIMEOUT,
                        "it waited out the idle timeout")
        origin.close()
        thread.join(10)
        self.assertEqual(outcome, {"returned": True})

    def test_bytes_read_before_a_close_are_delivered(self):
        """The origin sends and closes at once, and the guest reads late:
        what the relay already took is still the guest's."""
        guest, relay_client, relay_upstream, origin = self._pairs()
        answer = _pattern(2 * 1024 * 1024, 3)
        thread, outcome = _relay_in_thread(relay_client, relay_upstream)
        writer = threading.Thread(
            target=lambda: (origin.sendall(answer), origin.close()),
            daemon=True)
        writer.start()
        time.sleep(0.5)
        got = _Peer(guest, b"", len(answer)).start()
        got.thread.join(20)
        thread.join(10)
        self.assertEqual(bytes(got.received), answer)
        self.assertEqual(outcome, {"returned": True})

    def test_a_close_either_way_ends_the_relay(self):
        """A half-close would hold a slot for a direction the guest has
        abandoned; the origin here stays open and silent."""
        guest, relay_client, relay_upstream, _origin = self._pairs()
        thread, outcome = _relay_in_thread(relay_client, relay_upstream)
        guest.sendall(b"last words")
        guest.close()
        thread.join(5)
        self.assertEqual(outcome, {"returned": True})
        _origin.settimeout(5)
        self.assertEqual(_origin.recv(100), b"last words")

    def test_idle_with_nothing_held_returns(self):
        with mock.patch.object(egress_relay, "RELAY_IDLE_TIMEOUT", 0.3):
            _g, relay_client, relay_upstream, _o = self._pairs()
            thread, outcome = _relay_in_thread(relay_client, relay_upstream)
            thread.join(5)
        self.assertEqual(outcome, {"returned": True})

    def test_a_peer_that_never_reads_is_ended_by_the_idle_timeout(self):
        """Bytes the far side will not take are a failure, not a quiet end:
        the relay raises, as the blocking write it replaced did."""
        with mock.patch.object(egress_relay, "RELAY_IDLE_TIMEOUT", 0.5):
            _guest, relay_client, relay_upstream, origin = self._pairs()
            thread, outcome = _relay_in_thread(relay_client, relay_upstream)
            writer = threading.Thread(
                target=lambda: origin.sendall(_pattern(SIZE, 4)),
                daemon=True)
            writer.start()
            thread.join(10)
        self.assertIsInstance(outcome.get("raised"), TimeoutError, outcome)

    def test_after_a_close_a_side_that_takes_nothing_ends_it_quietly(self):
        """The origin answers and closes; the guest neither reads nor
        closes. The flush goes idle, and the relay ends as it would have
        at the close, not as a failure. The buffer is raised past the
        answer, so the relay reads as far as the close."""
        with mock.patch.object(egress_relay, "RELAY_IDLE_TIMEOUT", 0.5), \
                mock.patch.object(egress_relay, "RELAY_BUFFER", 2 * SIZE):
            _guest, relay_client, relay_upstream, origin = self._pairs()
            thread, outcome = _relay_in_thread(relay_client, relay_upstream)
            writer = threading.Thread(
                target=lambda: (origin.sendall(_pattern(SIZE, 8)),
                                origin.close()),
                daemon=True)
            writer.start()
            thread.join(10)
        self.assertEqual(outcome, {"returned": True})

    def test_the_guest_check_sees_every_byte_before_it_is_forwarded(self):
        """The check may raise to end the relay, and the bytes it refused
        never reach the origin."""
        guest, relay_client, relay_upstream, origin = self._pairs()
        seen = bytearray()

        class Refused(Exception):
            pass

        def check(data):
            if b"REFUSE" in data:
                raise Refused()
            seen.extend(data)

        thread, outcome = _relay_in_thread(relay_client, relay_upstream,
                                           on_client_bytes=check)
        guest.sendall(b"fine")
        origin.settimeout(5)
        self.assertEqual(origin.recv(100), b"fine")
        guest.sendall(b"REFUSE")
        thread.join(5)
        self.assertIsInstance(outcome.get("raised"), Refused)
        self.assertEqual(bytes(seen), b"fine")
        origin.settimeout(0.3)
        with self.assertRaises(TimeoutError):
            origin.recv(100)

    def test_the_sockets_are_left_with_the_idle_timeout(self):
        guest, relay_client, relay_upstream, _origin = self._pairs()
        thread, _ = _relay_in_thread(relay_client, relay_upstream)
        guest.close()
        thread.join(5)
        for s in (relay_client, relay_upstream):
            self.assertEqual(s.gettimeout(), egress_relay.RELAY_IDLE_TIMEOUT)


@unittest.skipUnless(_have_openssl(), "openssl is not installed")
class TestBothDirectionsAtOnceOverTls(unittest.TestCase):
    """The same exchange with both legs TLS, as a terminated connection has
    after a 101 or in an h2 session: one SSLSocket per leg carries both
    directions, and a write may need a read first. A read of less than a
    record leaves the rest decrypted inside the engine, invisible to
    select(), so the chunk is shrunk to put every read on that path."""

    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp())
        ca_key, ca_cert = cls.dir / "ca.key", cls.dir / "ca.crt"
        _run(ca_openssl_argv("relay", ca_key, ca_cert, now=time.time()))
        key, cert = cls.dir / "leaf.key", cls.dir / "leaf.crt"
        _run(leaf_openssl_argv("relay.test", ca_key, ca_cert, key, cert,
                               now=time.time()))
        cls.server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.server.load_cert_chain(str(cert), str(key))
        cls.client = ssl.create_default_context(cafile=str(ca_cert))

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.dir, ignore_errors=True)

    def setUp(self):
        for name, value in (("RELAY_IDLE_TIMEOUT", 5.0), ("RELAY_CHUNK", 1000)):
            patch = mock.patch.object(egress_relay, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def _tls_pair(self):
        """(client end, server end) of one TLS session over loopback TCP.

        Not a socketpair: a close without close_notify makes OpenSSL write
        an alert, which a Unix socket refuses with EPIPE where TCP accepts
        it, and the relay would see a broken pipe where it sees the end.
        """
        with socket.create_server(("127.0.0.1", 0)) as listener:
            a = socket.create_connection(listener.getsockname())
            b, _ = listener.accept()
        client = self.client.wrap_socket(a, server_hostname="relay.test",
                                         do_handshake_on_connect=False)
        server = self.server.wrap_socket(b, server_side=True,
                                         do_handshake_on_connect=False)
        for s in (client, server):
            self.addCleanup(s.close)
        shake = threading.Thread(target=server.do_handshake, daemon=True)
        shake.start()
        client.do_handshake()
        shake.join(10)
        return client, server

    def test_an_origin_that_answers_first_is_not_a_stall(self):
        guest, relay_client = self._tls_pair()
        relay_upstream, origin = self._tls_pair()
        upload, answer = _pattern(TLS_SIZE, 5), _pattern(TLS_SIZE, 6)
        thread, outcome = _relay_in_thread(relay_client, relay_upstream)
        g = _Peer(guest, upload, TLS_SIZE).start()
        o = _Peer(origin, answer, TLS_SIZE, answer_first=True).start()
        g.thread.join(30)
        o.thread.join(30)
        self.assertIsNone(g.error)
        self.assertIsNone(o.error)
        self.assertEqual(bytes(o.received), upload, "the upload stalled")
        self.assertEqual(bytes(g.received), answer, "the answer stalled")
        origin.close()
        thread.join(10)
        self.assertEqual(outcome, {"returned": True})

    @staticmethod
    def _drain_tickets(sock):
        """Take the session tickets an origin sends after its handshake, as
        the inspector's dial does with its early read."""
        sock.setblocking(False)
        try:
            sock.recv(65536)
        except ssl.SSLWantReadError:
            pass
        sock.setblocking(True)

    def _deliver(self, guest, relay_client, relay_upstream, origin):
        thread, outcome = _relay_in_thread(relay_client, relay_upstream)
        message = _pattern(3000, 7)
        guest.sendall(message)
        origin.settimeout(5)
        got = b""
        while len(got) < len(message):
            got += origin.recv(65536)
        self.assertEqual(got, message)
        # The origin's end: the guest's still holds an unread session
        # ticket, and a close over unread bytes is a reset.
        origin.close()
        thread.join(5)
        self.assertEqual(outcome, {"returned": True})

    def test_a_short_message_waiting_in_the_engine_is_delivered(self):
        """One record of three chunks: the first read leaves the rest
        decrypted, where select() never reports it."""
        guest, relay_client = self._tls_pair()
        relay_upstream, origin = self._tls_pair()
        self._drain_tickets(relay_upstream)
        self._deliver(guest, relay_client, relay_upstream, origin)

    def test_a_record_with_no_data_does_not_hold_the_other_direction(self):
        """The origin's session ticket makes its socket readable with no
        application byte behind it. A blocking read there waits for data
        that is not coming while the guest's bytes go unforwarded."""
        guest, relay_client = self._tls_pair()
        relay_upstream, origin = self._tls_pair()
        self._deliver(guest, relay_client, relay_upstream, origin)

if __name__ == "__main__":
    unittest.main()
