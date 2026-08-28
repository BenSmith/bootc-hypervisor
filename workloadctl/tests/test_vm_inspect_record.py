"""The per-request record's join key — rung 5 T1a.

Rungs 2–4 log a decision per connection and per request, and none of those
lines say WHICH connection. `peer=` is on every one of them and cannot serve:
a source port repeats across the requests on one keep-alive connection and is
reused by the kernel after close, so grouping by it merges unrelated
connections and splits one connection's own requests apart.

T1a puts a connection id at the front of `where` — which every decision path
in the listener interpolates — and a request ordinal in the two request loops.
These tests hold three properties: the key is on every line, one connection's
lines share it, and two connections do not.
"""

import io
import re
import socket
import threading
import unittest
import unittest.mock

from tests import load_script
from vm import VM_INSPECT_LOG_ID_FIELD, VM_INSPECT_LOG_REQ_FIELD

_MOD = None


def _mod():
    """The listener module, loaded once — see test_vm_inspect_listener._mod."""
    global _MOD
    if _MOD is None:
        _MOD = load_script("libexec/workload-vm-inspect-listener")
    return _MOD


ID = re.compile(r"\bid=([0-9a-f]{12})\b")
REQ = re.compile(r"\breq=(\d+)\b")

CLEARTEXT = ("198.18.1.1", 8080)
TLS = ("198.18.1.1", 8443)


def _listener_with(local):
    m = unittest.mock.Mock()
    m.getsockname.return_value = local
    return m


class _Harness(unittest.TestCase):

    def _pair(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        a.settimeout(3.0)
        b.settimeout(3.0)
        return a, b

    def _serve(self, feed, *, local=CLEARTEXT, hosts=(), peer=("192.0.2.1", 1024)):
        """One connection, driven through _serve — the function _handle's
        thread calls, so the lines are the real ones and the assertion is not
        a race against a daemon thread."""
        mod = _mod()
        out = io.StringIO()
        listener = mod.Listener(
            [_listener_with(local)], out,
            policy=mod.Policy(tls="splice", hosts=tuple(hosts)))
        ours, guest = self._pair()
        guest.sendall(feed)
        guest.shutdown(socket.SHUT_WR)
        listener._serve(ours, peer, local, mod.plane_for_port(local[1]),
                        mod.secrets.token_hex(6))
        return out.getvalue()

    def _lines(self, log):
        return [ln for ln in log.splitlines() if ln.strip()]


class TestTheFieldNamesAreShared(unittest.TestCase):
    """lib/ restates what this entrypoint emits, because lib/ cannot import an
    extension-less script. The restatement is only safe while a rename over
    there fails a test here — otherwise the reader keeps looking for a field
    nobody emits any more and reports every join as a miss."""

    def test_the_id_field_name_matches(self):
        self.assertEqual(_mod().LOG_ID_FIELD, VM_INSPECT_LOG_ID_FIELD)

    def test_the_request_field_name_matches(self):
        self.assertEqual(_mod().LOG_REQ_FIELD, VM_INSPECT_LOG_REQ_FIELD)


class TestEveryLineCarriesTheId(_Harness):
    """`where` leads with the id, so every path that interpolates it gets one
    — which is the whole reason the field went there rather than onto the
    handful of lines someone remembered to edit."""

    def test_a_refused_request_carries_one(self):
        log = self._serve(b"GET / HTTP/1.1\r\nHost: nobody.example\r\n\r\n")
        self.assertRegex(log, ID)

    def test_a_forwarded_request_carries_one(self):
        mod = _mod()
        origin = []

        def dial(addr, timeout=None):
            near, far = self._pair()
            far.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            origin.append(far)
            return near

        with unittest.mock.patch.object(
                socket, "create_connection", side_effect=dial):
            log = self._serve(
                b"GET / HTTP/1.1\r\nHost: ok.example\r\nConnection: close\r\n\r\n",
                hosts=("ok.example",))
        self.assertIn("forward ", log)
        self.assertRegex(log, ID)

    def test_a_tls_connection_with_no_readable_name_carries_one(self):
        log = self._serve(b"\x16\x03\x01\x00\x05rubbish", local=TLS)
        self.assertIn("drop ", log)
        self.assertRegex(log, ID)

    def test_the_id_leads_the_line_after_the_verb(self):
        """Anchored, not merely present. A reader grepping one connection out
        of a file wants a fixed position to cut on, and a field that drifted
        to the end of the line would still pass a bare `assertIn`."""
        log = self._serve(b"GET / HTTP/1.1\r\nHost: nobody.example\r\n\r\n")
        for line in self._lines(log):
            self.assertRegex(line, r"^\w+ id=[0-9a-f]{12} plane=")

    def test_a_connection_the_ceiling_rejects_carries_one(self):
        """The rejection path never reaches _serve, which is exactly why the
        id is minted in _handle: a guest reporting a stall it got no answer to
        is correlated through these two lines or through nothing."""
        mod = _mod()
        out = io.StringIO()
        listener = mod.Listener([_listener_with(CLEARTEXT)], out, limit=0)
        conn = unittest.mock.MagicMock()
        conn.recv.return_value = b""
        listener._handle(conn, ("192.0.2.1", 1024), _listener_with(CLEARTEXT))
        self.assertIn("rejected ", out.getvalue())
        self.assertRegex(out.getvalue(), ID)

    def test_a_connection_no_thread_could_be_started_for_carries_one(self):
        mod = _mod()
        out = io.StringIO()
        listener = mod.Listener([_listener_with(CLEARTEXT)], out)
        conn = unittest.mock.MagicMock()
        conn.recv.return_value = b""
        with unittest.mock.patch.object(
                threading.Thread, "start",
                side_effect=RuntimeError("can't start new thread")):
            listener._handle(conn, ("192.0.2.1", 1024),
                             _listener_with(CLEARTEXT))
        self.assertIn("cannot start thread", out.getvalue())
        self.assertRegex(out.getvalue(), ID)


class TestTheIdGroupsOneConnection(_Harness):

    def test_every_line_of_one_connection_shares_it(self):
        """Three requests, two of them refused, on one connection. If the id
        were minted per request rather than per connection this passes each
        line individually and groups nothing."""
        log = self._serve(
            b"GET /a HTTP/1.1\r\nHost: nobody.example\r\n\r\n"
            b"GET /b HTTP/1.1\r\nHost: other.example\r\n\r\n"
            b"GET /c HTTP/1.1\r\nHost: third.example\r\n\r\n")
        found = set(ID.findall(log))
        self.assertEqual(len(self._lines(log)), 3)
        self.assertEqual(len(found), 1, f"one connection, one id: {log!r}")

    def test_two_connections_do_not_share_it(self):
        feed = b"GET / HTTP/1.1\r\nHost: nobody.example\r\n\r\n"
        first = set(ID.findall(self._serve(feed)))
        second = set(ID.findall(self._serve(feed)))
        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 1)
        self.assertNotEqual(first, second)

    def test_the_id_is_not_a_counter(self):
        """Restarts are the case. The listener is socket-activated, so a
        counter begins again at zero every time the socket re-triggers it,
        while the record file it keys outlives that restart — two unrelated
        connections would collide on the one key a reader joins on."""
        mod = _mod()
        out = io.StringIO()
        listener = mod.Listener([_listener_with(CLEARTEXT)], out, limit=0)
        for _ in range(4):
            conn = unittest.mock.MagicMock()
            conn.recv.return_value = b""
            listener._handle(conn, ("192.0.2.1", 1024),
                             _listener_with(CLEARTEXT))
        found = ID.findall(out.getvalue())
        self.assertEqual(len(found), 4)
        self.assertEqual(len(set(found)), 4)
        self.assertNotIn("000000000000", found)


class TestTheRequestOrdinal(_Harness):

    def test_it_counts_the_requests_on_one_connection(self):
        log = self._serve(
            b"GET /a HTTP/1.1\r\nHost: nobody.example\r\n\r\n"
            b"GET /b HTTP/1.1\r\nHost: other.example\r\n\r\n"
            b"GET /c HTTP/1.1\r\nHost: third.example\r\n\r\n")
        self.assertEqual(REQ.findall(log), ["1", "2", "3"])

    def test_a_connection_level_line_has_none(self):
        """The TLS front takes its decision before any request exists, so a
        `req=` there would be inventing an ordinal for something that is not a
        request — and a reader joining on it would attribute a connection's
        refusal to whichever request happened to be numbered 1."""
        log = self._serve(b"\x16\x03\x01\x00\x05rubbish", local=TLS)
        self.assertNotRegex(log, REQ)


if __name__ == "__main__":
    unittest.main()
