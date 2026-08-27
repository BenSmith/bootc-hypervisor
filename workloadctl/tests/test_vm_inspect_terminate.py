"""workload-vm-inspect-listener: the terminated TLS plane (rung 3 T5, T6).

Rung 2's plane spliced: it read a name and replayed the guest's own bytes. This
one TERMINATES -- the listener completes the guest's handshake with a leaf its
own CA signed, opens a separately verified session to the origin, and authorises
every request inside.

WHY THESE TESTS ARE END TO END AND NOT ARGV ASSERTIONS

Every interesting failure on this path is invisible to a test that inspects
arguments. A leaf whose subjectAltName is not marked critical builds a perfect
argv and is then refused by every client. A wrap_socket that consumes the
ClientHello leaves the handshake to hang. A trust store that is loaded but not
consulted looks identical to one that is. So each of these drives a REAL client
against a REAL origin through the real listener: the assertion is on bytes that
came back, and the parts that cannot be true at once fail loudly.

THE ORIGIN IS A SECOND CA, ON PURPOSE

The workload CA signs what the guest sees; a separate throwaway root signs what
the ORIGIN presents. Sharing one would make the upstream verification test pass
for the wrong reason -- the inspector would be verifying a certificate its own
CA signed, which is exactly the check that must not accidentally hold.
"""

import io
import os
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import unittest.mock
from pathlib import Path

from tests import load_script
from vm import (
    VM_INSPECT_PORT_TLS, vm_ca_cert_path, vm_ca_key_path, vm_ca_openssl_argv,
    vm_leaf_openssl_argv,
)

_MOD = None


def _mod():
    global _MOD
    if _MOD is None:
        _MOD = load_script("libexec/workload-vm-inspect-listener")
    return _MOD


def _have_openssl():
    return bool(__import__("shutil").which("openssl"))


def _run(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise AssertionError(f"{argv[:3]} failed: {result.stderr}")


def _make_ca(directory, name):
    """A CA keypair in `directory`, minted by the code under test."""
    directory.mkdir(parents=True, exist_ok=True)
    key, cert = directory / "ca.key", directory / "ca.crt"
    _run(vm_ca_openssl_argv(name, key, cert, now=time.time()))
    return key, cert


def _make_leaf(directory, name, ca_key, ca_cert, stem):
    """A server certificate for `name`, as one PEM holding cert and key.

    Uses the product's own leaf argv, so the origin in these tests is presenting
    a certificate built the same way the inspector's is -- including the
    critical subjectAltName, which is the property an empty subject requires and
    which nothing about the argv reveals.
    """
    key = directory / f"{stem}.key"
    cert = directory / f"{stem}.crt"
    _run(vm_leaf_openssl_argv(name, ca_key, ca_cert, key, cert,
                              now=time.time()))
    pem = directory / f"{stem}.pem"
    pem.write_text(cert.read_text() + key.read_text())
    return pem


class _Origin:
    """A one-connection TLS origin on 127.0.0.1, in its own thread.

    Records the request bytes it managed to read, so a test can assert that a
    refused exchange never reached it -- which is the whole claim of catching a
    client-certificate alert before forwarding anything.
    """

    def __init__(self, pem, *, client_ca=None, response=None, follow=False,
                 alpn=("http/1.1",)):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(str(pem))
        # Configurable so an h2 test can have a real origin that offers `h2`
        # and answers with frames. A fixed list here would make every h2
        # assertion pass or fail on this file's opinion rather than on the
        # listener's, which is the shape these tests exist to avoid.
        self.ctx.set_alpn_protocols(list(alpn))
        self.alpn_seen = []
        if client_ca is not None:
            # TLS 1.3 only, so the CertificateRequest arrives AFTER a successful
            # handshake and the alert lands on the first read. Under 1.2 the
            # same requirement is a handshake_failure, which is the case the
            # design writes down as not distinguishable.
            self.ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            self.ctx.verify_mode = ssl.CERT_REQUIRED
            self.ctx.load_verify_locations(str(client_ca))
        self.response = response or (
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
        # `follow` keeps reading after the response has been sent, appending
        # each further chunk to `requests`. It is what an upgraded connection
        # needs: the bytes that matter there arrive AFTER the 101, and an origin
        # that closes on the first recv cannot see them at all.
        self.follow = follow
        self.requests = []
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while True:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            try:
                conn = self.ctx.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError):
                raw.close()
                continue
            try:
                conn.settimeout(5.0)
                self.alpn_seen.append(conn.selected_alpn_protocol())
                data = conn.recv(65536)
                if data:
                    self.requests.append(data)
                    conn.sendall(self.response)
                    while self.follow:
                        more = conn.recv(65536)
                        if not more:
                            break
                        self.requests.append(more)
            except (ssl.SSLError, OSError):
                pass
            finally:
                conn.close()

    def close(self):
        self.sock.close()


def _tcp_pair():
    """A connected pair of real TCP sockets: (listener side, guest side)."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    guest = socket.socket()
    guest.connect(server.getsockname())
    ours, _ = server.accept()
    server.close()
    return ours, guest


@unittest.skipUnless(_have_openssl(), "openssl is not installed")
class TerminationCase(unittest.TestCase):
    """A workload CA, a throwaway origin root, and a listener that terminates."""

    HOST = "localhost"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))
        self.state = self.tmp / "state"
        ca_dir = self.state / "ca"
        ca_dir.mkdir(parents=True)
        _run(vm_ca_openssl_argv("demo", vm_ca_key_path(self.state),
                                vm_ca_cert_path(self.state), now=time.time()))
        self.origin_ca_key, self.origin_ca_cert = _make_ca(
            self.tmp / "origin-root", "origin-root")
        self.origin_pem = _make_leaf(self.tmp, self.HOST, self.origin_ca_key,
                                     self.origin_ca_cert, "origin")

    def _minter(self, mod, **kwargs):
        from vm_mint import Minter
        kwargs.setdefault("clock_check", lambda: "ok")
        return Minter("demo", self.state, **kwargs)

    def _listener(self, mod, origin, *, hosts=("localhost",), trust=True,
                  minter=None, http2=(), entries=()):
        out = io.StringIO()
        # `entries` is [[vm.network.policy]] as (host, methods, paths) triples.
        policy = mod.Policy(
            tls="inspect", hosts=tuple(hosts), http2=tuple(http2),
            policy=tuple(mod.VmPolicyEntry(host=h, methods=m, paths=pa)
                         for h, m, pa in entries))
        listener = mod.Listener([unittest.mock.Mock()], out, policy=policy,
                                minter=minter or self._minter(mod))
        if trust:
            # BOTH contexts, each keeping its own offer. Pointing them at one
            # object would make an h2 test pass while the product offered
            # http/1.1 upstream, which is the drift the two-context split
            # exists to prevent.
            for attr, alpn in (("_upstream_ctx", ["http/1.1"]),
                               ("_upstream_ctx_h2", ["h2"])):
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.load_verify_locations(str(self.origin_ca_cert))
                ctx.set_alpn_protocols(alpn)
                setattr(listener, attr, ctx)
        return listener, out

    def _guest_context(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(str(vm_ca_cert_path(self.state)))
        return ctx

    def _exchange(self, listener, origin, *, request=None, host=None,
                  guest_ctx=None):
        """Drive one whole connection and return (response bytes, error).

        The listener half runs in a thread because both ends of a TLS handshake
        have to be live at once; the test is the guest.
        """
        ours, guest = _tcp_pair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        # Short, and not the product's numbers: every assertion here is about
        # bytes that arrive promptly or not at all, and a break-on-purpose run
        # -- where a handshake is MEANT to hang -- has to end in seconds rather
        # than in the listener's own patience.
        ours.settimeout(3.0)
        guest.settimeout(3.0)
        mod = _mod()
        served = threading.Thread(
            target=listener._serve_tls, args=(ours, "plane=tls"), daemon=True)
        with unittest.mock.patch.object(mod, "VM_INSPECT_ORIG_TLS",
                                        origin.port):
            served.start()
            ctx = guest_ctx or self._guest_context()
            response, error = b"", None
            tls = None
            try:
                tls = ctx.wrap_socket(guest, server_hostname=host or self.HOST)
                tls.sendall(request or (
                    f"GET / HTTP/1.1\r\nHost: {host or self.HOST}\r\n"
                    f"Connection: close\r\n\r\n").encode())
                while True:
                    chunk = tls.recv(65536)
                    if not chunk:
                        break
                    response += chunk
            except (ssl.SSLError, OSError) as exc:
                error = exc
            finally:
                if tls is not None:
                    tls.close()
            served.join(timeout=15)
        return response, error

    def _open_fds(self):
        return len(os.listdir("/proc/self/fd"))


class TestAnAllowlistedHostIsReachedThroughTheInspector(TerminationCase):

    def test_the_guest_gets_the_origins_bytes(self):
        """The gate: CA installed, allowlisted name, the origin's own body.

        Everything the rung claims has to hold at once for this to pass -- the
        leaf verifies against the workload CA, the peeked ClientHello was still
        there for the handshake, the upstream leg verified against a different
        root, and the request was relayed and answered.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, out = self._listener(mod, origin)
        response, error = self._exchange(listener, origin)
        self.assertIsNone(error)
        self.assertIn(b"200 OK", response)
        self.assertTrue(response.endswith(b"hello"), response)
        self.assertIn(b"Host: localhost", origin.requests[0])
        self.assertIn("terminate", out.getvalue())
        self.assertEqual(listener.status()["dispositions"]["terminated"], 1)
        self.assertEqual(listener.status()["dispositions"]["forwarded"], 1)

    def test_a_second_request_reuses_the_leaf_rather_than_minting(self):
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        minter = self._minter(mod)
        listener, _ = self._listener(mod, origin, minter=minter)
        self._exchange(listener, origin)
        self._exchange(listener, origin)
        self.assertEqual(minter.stats["mints"], 1)
        self.assertEqual(minter.stats["hits"], 1)
        self.assertEqual(listener.status()["mint"]["mints"], 1)


class TestADeniedNameIsBumpedRatherThanClosed(TerminationCase):

    def test_the_guest_gets_a_readable_403_through_a_chain_it_trusts(self):
        """The property the CA exists for.

        Spliced, a refused name is a closed connection and the guest learns
        nothing it can distinguish from the host being down. Terminated, the
        same refusal is a 403 naming the host, delivered inside a TLS session
        the guest's own verification accepted.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, out = self._listener(mod, origin, hosts=("nothing.example",))
        response, error = self._exchange(listener, origin)
        self.assertIsNone(error, f"the handshake must succeed: {error}")
        self.assertIn(b"403 Forbidden", response)
        self.assertIn(b"localhost is not on this workload's egress allowlist",
                      response)
        self.assertEqual(origin.requests, [],
                         "a denied name must never reach an origin")
        status = listener.status()
        self.assertEqual(status["bumped"], 1)
        self.assertEqual(status["drop_reasons"]["not allowlisted"], 1)
        self.assertEqual(status["dispositions"]["terminated"], 0)

    def test_the_wrapped_socket_is_closed_before_the_handler_returns(self):
        """wrap_socket DETACHES the socket it wraps, so `_serve`'s own close is
        a no-op from that point and this is the only thing that closes the
        guest's connection.

        Asserted on the fd rather than on a count of open descriptors: CPython
        refcounting collects the SSLSocket soon after the handler returns and
        closes it anyway, so a count-based test passes with the close deleted.
        What is actually being defended is that the close is DETERMINISTIC in a
        process holding up to MAX_CONNECTIONS of these, not that a collector
        eventually gets to it.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, _ = self._listener(mod, origin, hosts=("nothing.example",))
        wrapped = []
        real = listener._wrap_guest

        def capture(conn, leaf, *args):
            # *args, not the current signature spelled out: this test is about
            # the CLOSE, and a wrapper that had to be edited every time an
            # argument joined _wrap_guest would fail as a missing socket rather
            # than as the mismatch it is.
            sock = real(conn, leaf, *args)
            wrapped.append(sock)
            return sock

        listener._wrap_guest = capture
        self._exchange(listener, origin)
        self.assertEqual(len(wrapped), 1)
        self.assertEqual(wrapped[0].fileno(), -1,
                         "the handler returned with the guest's socket open")

    def test_the_denial_leaf_lands_in_the_denial_directory(self):
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        minter = self._minter(mod)
        listener, _ = self._listener(mod, origin, hosts=("nothing.example",),
                                     minter=minter)
        self._exchange(listener, origin)
        self.assertEqual(len(minter.denials), 1)
        self.assertEqual(len(minter.working_set), 0)


class TestAnUnverifiableUpstreamIsBumpedWithA502(TerminationCase):

    def test_the_502_names_the_host_and_the_reason(self):
        """A failed handshake here would be an opaque error to the guest.

        The 502 body is the ONLY place the reason reaches it, so the reason has
        to be in the body -- and it has to point at the HOST's anchors, because
        that is where the operator's one-line fix lives.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        # trust=False: the listener keeps its real default context, which does
        # not know the throwaway origin root.
        listener, out = self._listener(mod, origin, trust=False)
        response, error = self._exchange(listener, origin)
        self.assertIsNone(error)
        self.assertIn(b"502 Bad Gateway", response)
        self.assertIn(b"localhost", response)
        self.assertIn(b"could not be verified", response)
        self.assertIn(b"THIS HOST", response)
        status = listener.status()
        self.assertEqual(
            status["drop_reasons"]["upstream certificate unverified"], 1)
        self.assertEqual(status["bumped"], 1)

    def test_the_leaf_stays_in_the_working_set_not_the_denial_set(self):
        """The name was allowlisted; only the host was unreachable.

        Filing it under denials would let a transient upstream failure push a
        legitimate name into the small cache a flood can churn, so the next
        successful connection to it pays for a mint it should not.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        minter = self._minter(mod)
        listener, _ = self._listener(mod, origin, trust=False, minter=minter)
        self._exchange(listener, origin)
        self.assertEqual(len(minter.working_set), 1)
        self.assertEqual(len(minter.denials), 0)


class TestTheClientCertificateCase(TerminationCase):

    def test_tls13_required_is_named_and_the_request_never_arrives(self):
        """One of three cases, and the only distinguishable one.

        Under TLS 1.3 the CertificateRequest is answered after the handshake
        succeeds, so the alert lands on the first read -- which the inspector
        takes BEFORE forwarding anything, which is what keeps the request out of
        the origin.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem, client_ca=self.origin_ca_cert)
        self.addCleanup(origin.close)
        listener, out = self._listener(mod, origin)
        response, error = self._exchange(listener, origin)
        self.assertIsNone(error)
        self.assertIn(b"502 Bad Gateway", response)
        self.assertIn(b"client certificate", response)
        self.assertIn(b'tls = "splice"', response)
        self.assertEqual(origin.requests, [],
                         "the request must not reach an origin that will "
                         "refuse the session")
        self.assertEqual(
            listener.status()["drop_reasons"][
                "upstream wants a client certificate"], 1)

    def test_the_tls12_case_names_the_possibility_without_asserting_it(self):
        """Written down as unmet rather than guessed at.

        `handshake_failure` is shared with half a dozen causes, so the sentence
        says "this is also what that looks like" instead of claiming it.
        """
        mod = _mod()
        listener, _ = self._listener(mod, unittest.mock.Mock(), trust=False)
        exc = ssl.SSLError("handshake failure")
        exc.reason = "SSLV3_ALERT_HANDSHAKE_FAILURE"
        reason, text = listener._upstream_tls_failure("api.example", exc)
        self.assertEqual(reason, mod.DROP_UNVERIFIED)
        self.assertIn("not distinguishable", text)
        self.assertIn("api.example", text)


class TestTheHostHeaderIsPinnedToTheServerName(TerminationCase):

    def test_another_name_inside_the_session_is_misdirected(self):
        """421, not 403: the name may well be allowlisted.

        What it is not is the name this session's certificate was minted for,
        and relaying it down this connection would send it to an origin its own
        Host header never authorised.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, out = self._listener(
            mod, origin, hosts=("localhost", "other.example"))
        response, error = self._exchange(
            listener, origin,
            request=b"GET / HTTP/1.1\r\nHost: other.example\r\n"
                    b"Connection: close\r\n\r\n")
        self.assertIsNone(error)
        self.assertIn(b"421 Misdirected Request", response)
        self.assertEqual(origin.requests, [])
        # The ALLOWLISTED half: `other.example` is on this workload's list, so
        # the mismatch is a client reusing a session across two names it was
        # given, not a guest reaching for one it was not. See T7.
        status = listener.status()
        self.assertEqual(
            status["drop_reasons"][
                "host does not match the server name (allowlisted)"], 1)
        self.assertEqual(
            status["drop_reasons"]["host does not match the server name"], 0)
        self.assertEqual(
            status["per_host"][
                "host does not match the server name (allowlisted)"],
            {"other.example": 1})

    def test_a_name_on_no_list_inside_the_session_is_the_other_figure(self):
        """Rung 4 T7. Same refusal, same 421, different figure.

        This is the attack §4's binding exists to close -- a guest reusing a
        session it was granted to reach a name it never was -- and an operator
        reading a merged count could not tell it from the coalescing client
        above. `admits` decides which figure and nothing else: the request is
        refused either way, and it is refused BEFORE the allowlist check, so
        the guest learns no more than the 421 already tells it.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, out = self._listener(mod, origin, hosts=("localhost",))
        response, error = self._exchange(
            listener, origin,
            request=b"GET / HTTP/1.1\r\nHost: evil.example\r\n"
                    b"Connection: close\r\n\r\n")
        self.assertIsNone(error)
        self.assertIn(b"421 Misdirected Request", response)
        self.assertEqual(origin.requests, [])
        status = listener.status()
        self.assertEqual(
            status["drop_reasons"]["host does not match the server name"], 1)
        self.assertEqual(
            status["drop_reasons"][
                "host does not match the server name (allowlisted)"], 0)
        # No per-host map for this half: the guest picks the name and there is
        # no bound on how many it invents. The log line carries it.
        self.assertNotIn("host does not match the server name",
                         status["per_host"])
        self.assertIn("host=evil.example", out.getvalue())
        self.assertNotIn("(allowlisted)", out.getvalue())

    def test_neither_binding_figure_is_a_policy_denial(self):
        """Rung 4 T7. `not allowlisted` and `not permitted by policy` stay at
        zero through both, or the figure §4 asks to be read at a glance is
        being read out of a bucket three different decisions land in."""
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, _ = self._listener(
            mod, origin, hosts=("localhost", "other.example"))
        self._exchange(
            listener, origin,
            request=b"GET / HTTP/1.1\r\nHost: other.example\r\n"
                    b"Connection: close\r\n\r\n")
        reasons = listener.status()["drop_reasons"]
        self.assertEqual(reasons["not allowlisted"], 0)
        self.assertEqual(reasons["not permitted by policy"], 0)

    def test_a_trailing_root_dot_is_the_same_name(self):
        """`localhost.` and `localhost` are one name, and a naive comparison
        rejects a legitimate request. §4's normalisation, as a fixture."""
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, _ = self._listener(mod, origin)
        response, error = self._exchange(
            listener, origin,
            request=b"GET / HTTP/1.1\r\nHost: localhost.\r\n"
                    b"Connection: close\r\n\r\n")
        self.assertIsNone(error)
        self.assertNotIn(b"421", response)
        self.assertEqual(len(origin.requests), 1)

    def test_an_uppercase_host_is_the_same_name(self):
        """DNS names are case-insensitive; the binding has to be too."""
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, _ = self._listener(mod, origin)
        response, error = self._exchange(
            listener, origin,
            request=b"GET / HTTP/1.1\r\nHost: LOCALHOST\r\n"
                    b"Connection: close\r\n\r\n")
        self.assertIsNone(error)
        self.assertNotIn(b"421", response)
        self.assertEqual(len(origin.requests), 1)

    def test_the_port_spelling_is_accepted_end_to_end(self):
        """`Host: name:443` reaches the origin rather than being bound out.

        The unit test below asserts the parser accepts it; this asserts the
        BINDING does, which is a different comparison -- the port is dropped
        before the pinned name is compared, and a copy that kept it would
        refuse the ordinary spelling on the plane it is ordinary on.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, _ = self._listener(mod, origin)
        response, error = self._exchange(
            listener, origin,
            request=b"GET / HTTP/1.1\r\nHost: localhost:443\r\n"
                    b"Connection: close\r\n\r\n")
        self.assertIsNone(error)
        self.assertNotIn(b"421", response)
        self.assertEqual(len(origin.requests), 1)

    def test_a_denied_host_mid_connection_leaves_its_neighbours_alone(self):
        """Rung 4 T7, §7.3. Three requests on ONE session: good, bound out,
        good. The 421 is the middle one's alone -- pinning to the first Host
        or tearing the connection down would either send a later request to an
        upstream it never authorised or lose one that was authorised.

        The THIRD request is asserted on the log rather than on the origin:
        `_Origin` answers one request per connection and closes, so the reused
        upstream is dead by then and the exchange ends `relay failed`. That is
        the fixture, not the listener -- what is under test is that the request
        was authorised and forwarded after the refusal, which is a line the
        loop only reaches by having stayed on the connection.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, out = self._listener(
            mod, origin, hosts=("localhost", "other.example"))
        response, error = self._exchange(
            listener, origin,
            request=b"GET /one HTTP/1.1\r\nHost: localhost\r\n\r\n"
                    b"GET /two HTTP/1.1\r\nHost: other.example\r\n\r\n"
                    b"GET /three HTTP/1.1\r\nHost: localhost\r\n"
                    b"Connection: close\r\n\r\n")
        self.assertIsNone(error)
        self.assertEqual(response.count(b"421 Misdirected Request"), 1)
        self.assertIn(b"200 OK", response)
        self.assertEqual([r.split(b" ")[1] for r in origin.requests], [b"/one"])
        log = out.getvalue()
        self.assertEqual(log.count("forward plane=tls host=localhost"), 2,
                         "the request after the refusal must be authorised")
        self.assertEqual(log.count("host=other.example"), 1)
        self.assertEqual(
            listener.status()["drop_reasons"][
                "host does not match the server name (allowlisted)"], 1)

    def test_the_port_this_plane_reaches_is_accepted_in_a_host_header(self):
        """`Host: name:443` is the ordinary spelling on a terminated plane.

        The shared parser hard-coded port 80 while only the cleartext plane used
        it; a copy that still did would refuse this as naming a destination
        neither end is on.
        """
        mod = _mod()
        self.assertEqual(
            mod.host_from_authority("localhost:443", mod.SCHEME_HTTPS).host,
            "localhost")
        with self.assertRaises(mod.RequestUnreadable):
            mod.host_from_authority("localhost:443", mod.SCHEME_HTTP)
        with self.assertRaises(mod.RequestUnreadable):
            mod.host_from_authority("localhost:80", mod.SCHEME_HTTPS)


class TestUpgradesAreRelayedAfterThePolicyCheck(TerminationCase):

    def test_a_101_hands_the_connection_to_the_relay_and_says_so(self):
        """The REQUEST was policed; the stream is not, and the log says which.

        An upgraded connection cannot carry further HTTP requests, so nothing is
        being re-authorised and lost -- but "policy stopped applying here" is
        not something an operator should have to infer.
        """
        mod = _mod()
        origin = _Origin(
            self.origin_pem,
            response=b"HTTP/1.1 101 Switching Protocols\r\n"
                     b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                     b"\x81\x03abc")
        self.addCleanup(origin.close)
        listener, out = self._listener(mod, origin)
        response, error = self._exchange(
            listener, origin,
            request=b"GET /ws HTTP/1.1\r\nHost: localhost\r\n"
                    b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        self.assertIn(b"101 Switching Protocols", response)
        self.assertIn(b"\x81\x03abc", response,
                      "the post-101 bytes must be relayed, buffer included")
        self.assertIn("upgrade", out.getvalue())
        self.assertIn("policy no longer applies", out.getvalue())
        # THE HALF THIS TEST USED TO MISS. _Origin answers 101 whatever it is
        # sent, so every assertion above held while the offer was being stripped
        # on the way upstream -- `Upgrade` and `Connection` are both in
        # _NOT_FORWARDED, so for one rung no real origin could ever have
        # answered 101 and this whole path was unreachable in production. The
        # request the origin actually received is the only thing that says
        # otherwise.
        self.assertTrue(origin.requests, "the origin saw no request at all")
        upstream = origin.requests[0]
        self.assertIn(b"Upgrade: websocket", upstream,
                      "the upgrade offer must reach the origin, or nothing can "
                      "ever answer 101")
        self.assertIn(b"Connection: upgrade", upstream)

    def test_the_guests_pipelined_bytes_survive_the_upgrade(self):
        """Bytes sent behind the upgrade request belong to the tunnel.

        A client is entitled to write its first frame in the same segment as the
        request that upgrades. Those bytes are read off the socket by the head
        parser and sit in its buffer, and the 101 path has to hand them to the
        upstream -- it forwarded the origin's surplus to the guest for a rung
        while dropping the guest's on the floor, which presents as a tunnel that
        opens and then stalls rather than as lost bytes.
        """
        mod = _mod()
        origin = _Origin(
            self.origin_pem, follow=True,
            response=b"HTTP/1.1 101 Switching Protocols\r\n"
                     b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        self.addCleanup(origin.close)
        listener, _out = self._listener(mod, origin)
        self._exchange(
            listener, origin,
            request=b"GET /ws HTTP/1.1\r\nHost: localhost\r\n"
                    b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                    b"\x81\x03xyz")
        self.assertIn(b"\x81\x03xyz", b"".join(origin.requests),
                      "the guest's pipelined frame must reach the origin")

    def test_an_h2c_upgrade_is_not_carried(self):
        """HTTP/2 is the one upgrade that would cost the per-request check.

        An h2c connection carries HPACK-compressed frames this relay cannot
        read, so forwarding the offer would hand the guest a way out of
        per-request authorisation. The request still completes as the ordinary
        HTTP/1.1 exchange it also is -- a declined upgrade, which is behaviour
        HTTP already defines, not a refusal the guest has to interpret.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, _out = self._listener(mod, origin)
        response, _error = self._exchange(
            listener, origin,
            request=b"GET / HTTP/1.1\r\nHost: localhost\r\n"
                    b"Upgrade: h2c\r\nConnection: Upgrade\r\n"
                    b"HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n\r\n")
        self.assertIn(b"200 OK", response)
        upstream = origin.requests[0]
        self.assertNotIn(b"Upgrade:", upstream)
        self.assertNotIn(b"Connection: upgrade", upstream)


class TestARedirectOffTheAllowlistIsNamedWhereBothNamesAreKnown(
        TerminationCase):
    """The only point in the system that knows both names.

    Driven through a REAL exchange rather than by calling the helper: what is
    being defended is that a response passing through the relay reaches this
    check at all. A test that called `_note_redirect` itself would stay green
    with the call site deleted, which is the shape of failure this rung has
    already been bitten by once.
    """

    def _redirecting_origin(self, location):
        body = (f"HTTP/1.1 302 Found\r\nLocation: {location}\r\n"
                f"Content-Length: 0\r\nConnection: close\r\n\r\n").encode()
        origin = _Origin(self.origin_pem, response=body)
        self.addCleanup(origin.close)
        return origin

    def test_the_note_names_the_origin_and_the_target(self):
        mod = _mod()
        origin = self._redirecting_origin("https://cdn.elsewhere/x")
        listener, out = self._listener(mod, origin)
        response, error = self._exchange(listener, origin)
        self.assertIn(b"302 Found", response)
        line = out.getvalue()
        self.assertIn("cdn.elsewhere", line)
        self.assertIn("not allowlisted", line)
        self.assertIn("host=localhost", line)

    def test_a_redirect_that_stays_on_the_list_is_silent(self):
        mod = _mod()
        origin = self._redirecting_origin("https://other.example/x")
        listener, out = self._listener(
            mod, origin, hosts=("localhost", "other.example"))
        self._exchange(listener, origin)
        self.assertNotIn("redirected to", out.getvalue())

    def test_a_relative_location_names_no_host(self):
        mod = _mod()
        self.assertIsNone(mod.redirect_host("/next"))
        self.assertIsNone(mod.redirect_host("//host-relative/x"))

    def test_a_port_in_the_location_does_not_lose_the_name(self):
        """host_from_authority refuses a port the plane does not reach, which
        is right for authorising and wrong for reporting."""
        mod = _mod()
        self.assertEqual(mod.redirect_host("https://cdn.elsewhere:8443/x"),
                         "cdn.elsewhere")


class TestTheStartRefusesWhatItCannotDo(unittest.TestCase):

    def test_inspect_without_a_ca_fails_the_start(self):
        """Loud at start, not at the first connection.

        The CA is made by `workload-vm-inspect up` before this process is ever
        activated, so its absence is a provisioning failure -- and one that
        surfaced as a single refused connection an hour after boot is a
        provisioning failure nobody attributes.
        """
        mod = _mod()
        with tempfile.TemporaryDirectory() as tmp:
            with unittest.mock.patch.object(
                    mod, "workload_state_dir", lambda n: Path(tmp)):
                with self.assertRaises(FileNotFoundError) as caught:
                    mod.build_minter("demo", mod.Policy(tls="inspect",
                                                        hosts=("a.example",)))
        self.assertIn("egress CA", str(caught.exception))

    def test_splice_needs_no_minter(self):
        mod = _mod()
        self.assertIsNone(
            mod.build_minter("demo", mod.Policy(tls="splice", hosts=())))

    def test_a_terminating_listener_with_no_minter_drops_loudly(self):
        """Unreachable through main(), and it still must not be silent.

        The alternative is a listener that fails every guest handshake with an
        opaque certificate error while reporting itself up.
        """
        mod = _mod()
        out = io.StringIO()
        listener = mod.Listener([unittest.mock.Mock()], out,
                                policy=mod.Policy(tls="inspect",
                                                  hosts=("a.example",)))
        ours, guest = _tcp_pair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        listener._serve_tls(ours, "plane=tls")
        self.assertIn("has no minter", out.getvalue())
        self.assertEqual(
            listener.status()["drop_reasons"]["could not mint a leaf"], 1)


class TestThePeekLeavesTheHelloWhereItWas(unittest.TestCase):
    """wrap_socket consumes from the SOCKET; a hello already read is gone.

    This is the difference between the two modes' readers, and it is not
    visible in either one's output -- a consuming read parses the same name and
    then hangs the handshake.
    """

    def _hello(self):
        """A real ClientHello, captured by starting one and never finishing."""
        holder = socket.socket()
        holder.bind(("127.0.0.1", 0))
        holder.listen(1)
        self.addCleanup(holder.close)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        client = socket.socket()
        client.settimeout(2.0)
        client.connect(holder.getsockname())
        self.addCleanup(client.close)
        def start_and_abandon():
            # It never completes -- nothing on the far end answers -- and the
            # exception it dies of is the point of the fixture, not a failure.
            try:
                ctx.wrap_socket(client, server_hostname="peek.example")
            except (ssl.SSLError, OSError):
                pass

        threading.Thread(target=start_and_abandon, daemon=True).start()
        conn, _ = holder.accept()
        conn.settimeout(5.0)
        return conn

    def test_peeking_reads_the_name_and_consumes_nothing(self):
        mod = _mod()
        conn = self._hello()
        self.addCleanup(conn.close)
        raw, hello = mod.read_client_hello(conn, peek=True)
        self.assertEqual(hello.server_name, "peek.example")
        again, _ = mod.read_client_hello(conn, peek=True)
        self.assertEqual(again[:len(raw)], raw,
                         "a peek that consumed would not find it twice")

    def test_the_splice_reader_consumes_what_it_reads(self):
        mod = _mod()
        conn = self._hello()
        self.addCleanup(conn.close)
        raw, hello = mod.read_client_hello(conn)
        self.assertEqual(hello.server_name, "peek.example")
        conn.settimeout(0.3)
        with self.assertRaises(mod.HelloUnreadable):
            mod.read_client_hello(conn)

    def test_a_hello_that_never_arrives_whole_is_refused_not_spun_on(self):
        """MSG_WAITALL is advisory under a socket timeout, so a dribbling peer
        gets short reads forever. Without the no-progress guard that is a
        ceiling slot held until the peer feels like closing."""
        mod = _mod()
        ours, guest = _tcp_pair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        ours.settimeout(0.3)
        guest.sendall(bytes([0x16, 0x03, 0x01, 0x40, 0x00]))   # 16 KiB claimed
        started = time.monotonic()
        with self.assertRaises(mod.HelloUnreadable):
            mod.read_client_hello(ours, peek=True)
        self.assertLess(time.monotonic() - started, 10.0)


class TestWhatCountsAsTheStartOfARequest(unittest.TestCase):
    """The predicate on its own. Three-valued, and each value earns its place.

    True and False are the two verdicts; None is `not enough bytes yet`, which
    is what lets the caller stop waiting the moment the answer is settled
    instead of always waiting for a full method's worth of bytes.
    """

    def check(self, start, expected):
        self.assertIs(_mod().is_http_request_start(start), expected,
                      f"for {start!r}")

    def test_a_request_line_is_one(self):
        for start in (b"GET / HTTP/1.1", b"POST /x", b"OPTIONS *",
                      b"BASELINE-CONTROL /a"):
            self.check(start, True)

    def test_a_binary_first_byte_is_not(self):
        for start in (b"\x16\x03\x01\x02\x00",      # TLS inside the session
                      b"\x00\x00\x00\x00",
                      b"\x10\x1a\x00\x04MQTT"):
            self.check(start, False)

    def test_a_text_protocol_that_is_not_http_is_not(self):
        # SSH gets three uppercase letters in before the hyphen-digit that
        # gives it away, which is why the check cannot stop at byte one.
        self.check(b"SSH-2.0-OpenSSH_9.6", False)
        self.check(b"PING\r\n", False)

    def test_a_prefix_too_short_to_judge_is_undecided(self):
        for start in (b"", b"G", b"GE", b"OPTION"):
            self.check(start, None)

    def test_a_run_longer_than_any_method_is_not_a_method(self):
        self.check(b"A" * _mod().HTTP_METHOD_MAX, False)

    def test_the_h2_preface_is_left_to_the_parser(self):
        """`PRI * HTTP/2.0` IS a request line; what it is not is one this
        listener speaks ON THIS PATH. It gets the parser's 400, not a close.
        The preface-and-frame check that reads it properly is reached only for
        a host in [[vm.network.http2]]; a host that is not in that list and
        opens with the preface anyway is a client ignoring the ALPN, and it is
        answered rather than closed."""
        self.check(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", True)

    def test_a_leading_space_is_not_a_method(self):
        self.check(b" GET / HTTP/1.1", False)

    def test_a_lowercase_method_is_refused_in_the_harmless_direction(self):
        """Named, not lamented. The alphabet is the one every registered method
        is spelled with; a lowercase extension method would be closed here
        rather than answered, and widening this is one character."""
        self.check(b"get / HTTP/1.1", False)


@unittest.skipUnless(_have_openssl(), "openssl is not installed")
class TestNonHttpInsideATerminatedSessionIsClosed(TerminationCase):
    """Rung 3 T6. Before termination these bytes were spliced and neither end
    noticed; now this listener is the one reading them."""

    NOT_HTTP = bytes(range(32)) + b"\x00" * 8

    def test_the_guest_gets_nothing_back_and_the_origin_sees_nothing(self):
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, out = self._listener(mod, origin)
        response, _ = self._exchange(listener, origin, request=self.NOT_HTTP)
        self.assertEqual(response, b"",
                         "a close, not an HTTP response written into a "
                         "protocol that is not HTTP")
        self.assertEqual(origin.requests, [])
        self.assertIn("reason='not HTTP", out.getvalue())

    def test_it_is_counted_as_not_http_and_not_as_an_unreadable_request(self):
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._listener(mod, origin)
        self._exchange(listener, origin, request=self.NOT_HTTP)
        reasons = listener.status()["drop_reasons"]
        self.assertEqual(reasons[mod.DROP_NOT_HTTP], 1)
        self.assertEqual(reasons[mod.DROP_UNREADABLE_REQUEST], 0)
        self.assertEqual(reasons[mod.DROP_TIMED_OUT], 0)

    def test_the_remedy_it_names_is_the_PER_HOST_key(self):
        """Rung 4 tier 6. Rung 3 could only say `tls = "splice"`, which gives
        up inspection for every OTHER name on the workload to fix one host.
        [[vm.network.splice]] exists now, and the line has to name it -- an
        operator does what the log tells them, so a line naming the wrong hatch
        is how a workload ends up spliced whole."""
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, out = self._listener(mod, origin)
        self._exchange(listener, origin, request=self.NOT_HTTP)
        line = out.getvalue()
        self.assertIn("[[vm.network.splice]]", line)
        self.assertIn("localhost", line)

    def test_a_malformed_but_recognisable_request_still_gets_its_400(self):
        """The check must not swallow the case it looks most like. A request
        line that begins as one and then fails to parse is an HTTP peer making
        an HTTP mistake, and it gets an answer it can read."""
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._listener(mod, origin)
        response, _ = self._exchange(
            listener, origin,
            request=b"GET /\x01\x02 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertTrue(response.startswith(b"HTTP/1.1 400 "), response[:40])
        self.assertEqual(
            listener.status()["drop_reasons"][mod.DROP_NOT_HTTP], 0)

    def test_a_decidable_prefix_does_not_wait_for_a_whole_method(self):
        """A peer that sends four bytes and then waits is answered on those
        four. Without the `until` this costs a decision timeout to decide
        something already decided."""
        mod = _mod()
        ours, guest = _tcp_pair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        ours.settimeout(5.0)
        guest.sendall(b"\x00\x01\x02\x03")
        stream = mod._Stream(ours)
        started = time.monotonic()
        start = stream.peek_start(
            until=lambda buf: mod.is_http_request_start(buf) is not None)
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertIs(mod.is_http_request_start(start), False)

    def test_the_peeked_bytes_are_still_there_for_the_parser(self):
        """The peek does not consume: an HTTP connection reaches the request
        loop with its head intact, which is why there is no MSG_PEEK here."""
        mod = _mod()
        ours, guest = _tcp_pair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        ours.settimeout(5.0)
        head = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        guest.sendall(head)
        stream = mod._Stream(ours)
        stream.peek_start()
        self.assertEqual(stream.read_head(), head)


@unittest.skipUnless(_have_openssl(), "openssl is not installed")
class TestTheNonHttpRefusalIsSplitByPolicy(TerminationCase):
    """Rung 4 tier 6. The same wire failure, two figures, because the two have
    different remedies -- and the second remedy includes a DELETION the first
    does not.

    A host with no policy entry needs one line: put it in
    [[vm.network.splice]]. A host with a policy entry needs that line AND the
    entry removed, because `validate` refuses a host that is in both. Merged
    into one count an operator can see that something needs splicing but not
    that some of their method and path rules never ran, and nothing at startup
    could have told them -- whether a host speaks HTTP is not knowable from the
    file, which is why §8 made this a runtime report rather than a validation
    rule.
    """

    NOT_HTTP = bytes(range(32)) + b"\x00" * 8

    def _governed(self, mod, origin):
        return self._listener(
            mod, origin,
            entries=(("localhost", ("GET",), ("/v1/*",)),))

    def test_a_governed_host_lands_in_the_policy_bucket_not_the_plain_one(self):
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._governed(mod, origin)
        self._exchange(listener, origin, request=self.NOT_HTTP)
        reasons = listener.status()["drop_reasons"]
        self.assertEqual(reasons[mod.DROP_NOT_HTTP_POLICY], 1)
        self.assertEqual(reasons[mod.DROP_NOT_HTTP], 0)

    def test_an_ungoverned_host_stays_in_the_plain_bucket(self):
        """The other half of the same guard. A split that put everything in one
        bucket would pass the test above on its own."""
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._listener(mod, origin)
        self._exchange(listener, origin, request=self.NOT_HTTP)
        reasons = listener.status()["drop_reasons"]
        self.assertEqual(reasons[mod.DROP_NOT_HTTP], 1)
        self.assertEqual(reasons[mod.DROP_NOT_HTTP_POLICY], 0)

    def test_a_WILDCARD_policy_entry_governs_the_name_it_covers(self):
        """The split is asked of the policy's matcher, not of a literal host
        string. An entry written `*.example` governs `api.example`, and a check
        comparing names would put that host in the wrong bucket -- the same
        defect §3's widening trap is about, one plane along."""
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._listener(
            mod, origin, entries=(("*host", ("GET",), ("/",)),))
        self._exchange(listener, origin, request=self.NOT_HTTP)
        self.assertEqual(
            listener.status()["drop_reasons"][mod.DROP_NOT_HTTP_POLICY], 1)

    def test_both_are_per_host_so_the_operator_gets_names_not_totals(self):
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._governed(mod, origin)
        self._exchange(listener, origin, request=self.NOT_HTTP)
        per_host = listener.status()["per_host"]
        self.assertEqual(per_host[mod.DROP_NOT_HTTP_POLICY],
                         {"localhost": 1})
        self.assertEqual(per_host[mod.DROP_NOT_HTTP], {})

    def test_the_governed_line_names_the_deletion_as_well_as_the_key(self):
        """Half the remedy is the trap. An operator told only to splice adds
        the entry, `validate` refuses the file, and the message that sent them
        there said nothing about why."""
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, out = self._governed(mod, origin)
        self._exchange(listener, origin, request=self.NOT_HTTP)
        line = out.getvalue()
        self.assertIn("[[vm.network.splice]]", line)
        self.assertIn("[[vm.network.policy]]", line)
        self.assertIn("deleted", line)

    def test_the_ungoverned_line_does_NOT_mention_policy(self):
        """A remedy that names a key the operator has not written sends them
        looking for a file they do not have."""
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, out = self._listener(mod, origin)
        self._exchange(listener, origin, request=self.NOT_HTTP)
        self.assertNotIn("policy", out.getvalue())

    def test_the_guest_still_gets_a_close_and_the_origin_still_gets_nothing(
            self):
        """Tier 6 changed the accounting and the sentence. It must not have
        changed the disposition -- these bytes reach no origin either way."""
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._governed(mod, origin)
        response, _ = self._exchange(listener, origin, request=self.NOT_HTTP)
        self.assertEqual(response, b"")
        self.assertEqual(origin.requests, [])

    def test_a_governed_host_that_DOES_speak_http_is_not_counted_at_all(self):
        """The bucket is for connections that never became requests. A request
        the policy denies is `not permitted by policy`, which is a different
        reason with a different meaning -- one says the rules did not run, the
        other says they ran and said no."""
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._governed(mod, origin)
        self._exchange(
            listener, origin,
            request=b"DELETE /v1/x HTTP/1.1\r\nHost: localhost\r\n\r\n")
        reasons = listener.status()["drop_reasons"]
        self.assertEqual(reasons[mod.DROP_NOT_HTTP_POLICY], 0)
        self.assertEqual(reasons[mod.DROP_NOT_HTTP], 0)
        self.assertEqual(reasons[mod.DROP_NOT_PERMITTED], 1)


@unittest.skipUnless(_have_openssl(), "openssl is not installed")
class TestAnHttp2HostIsRelayedAtFrameLevel(TerminationCase):
    """Rung 4 T4/T5. [[vm.network.http2]], end to end through a real handshake.

    THIS IS THE TEST THE UNIT ONES CANNOT REPLACE. Every part of this feature
    can be individually green while the seam is inert: the ALPN swap chooses a
    tuple nothing hands to a context, the framing scanner is fed by nothing,
    the preface is read off a stream whose buffered surplus is then dropped so
    the guest's opening SETTINGS never reaches the origin. All three build a
    plausible argv and produce a connection that hangs. So this drives a real
    client, offering h2, at a real origin that also offers h2, and asserts on
    the protocol both ends actually negotiated and on the frames that came
    back.
    """

    SETTINGS = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    SETTINGS_ACK = b"\x00\x00\x00\x04\x01\x00\x00\x00\x00"

    def _h2_origin(self, follow=False):
        """An origin that speaks h2 and answers with one frame.

        `follow` keeps it reading after that answer. It is off by default so
        the relay ends when the origin closes and a test's read loop
        terminates -- and ON for the mid-session test, which otherwise never
        gets its second write read at all.
        """
        origin = _Origin(self.origin_pem, alpn=("h2",),
                         response=self.SETTINGS_ACK, follow=follow)
        self.addCleanup(origin.close)
        return origin

    def _h2_exchange(self, listener, origin, payload, then=None):
        """One h2 connection, guest side. Returns (bytes back, error, alpn).

        `then` is written after the first bytes come back, which is the only
        way to reach the RELAY's copy of the framing scanner: everything sent
        in one write arrives while the preface is still being read and is
        handled by the pre-relay feed instead. A break disabling the relay
        scanner reads green without this.
        """
        ours, guest = _tcp_pair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        ours.settimeout(3.0)
        guest.settimeout(3.0)
        mod = _mod()
        served = threading.Thread(
            target=listener._serve_tls, args=(ours, "plane=tls"), daemon=True)
        negotiated = []
        with unittest.mock.patch.object(mod, "VM_INSPECT_ORIG_TLS",
                                        origin.port):
            served.start()
            ctx = self._guest_context()
            ctx.set_alpn_protocols(["h2"])
            back, error, tls = b"", None, None
            try:
                tls = ctx.wrap_socket(guest, server_hostname=self.HOST)
                negotiated.append(tls.selected_alpn_protocol())
                tls.sendall(payload)
                while True:
                    chunk = tls.recv(65536)
                    if not chunk:
                        break
                    back += chunk
                    if then is not None:
                        tls.sendall(then)
                        then = None
            except (ssl.SSLError, OSError) as exc:
                error = exc
            finally:
                if tls is not None:
                    tls.close()
            served.join(timeout=15)
        return back, error, negotiated[0] if negotiated else None

    def test_both_legs_negotiate_h2_and_the_frames_cross(self):
        """The gate. h2 offered to the guest, h2 offered upstream, the guest's
        preface and opening SETTINGS delivered to the origin, and the origin's
        own frame delivered back."""
        mod = _mod()
        origin = self._h2_origin()
        listener, out = self._listener(mod, origin, http2=("localhost",))
        back, error, alpn = self._h2_exchange(
            listener, origin, mod.H2_PREFACE + self.SETTINGS)
        self.assertIsNone(error)
        self.assertEqual(alpn, "h2", "the guest leg did not negotiate h2")
        self.assertEqual(origin.alpn_seen, ["h2"],
                         "the upstream leg did not negotiate h2")
        self.assertEqual(origin.requests[0], mod.H2_PREFACE + self.SETTINGS,
                         "the preface and the opening SETTINGS must both "
                         "reach the origin, unaltered")
        self.assertEqual(back, self.SETTINGS_ACK)
        self.assertIn("terminate", out.getvalue())
        self.assertIn("h2", out.getvalue())

    def test_a_host_not_listed_is_offered_http11_on_the_same_listener(self):
        """Per host, not per listener -- which is the whole mechanism. ALPN is
        selected after the SNI is known, so one connection can be downgraded
        while another on the same listener keeps h2."""
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, _ = self._listener(mod, origin, http2=("other.example",))
        response, error = self._exchange(listener, origin)
        self.assertIsNone(error)
        self.assertIn(b"200 OK", response)
        self.assertEqual(origin.alpn_seen, ["http/1.1"])

    def test_an_http11_request_on_an_http2_host_is_refused(self):
        """What makes the key mean SPEAKS H2 rather than EXEMPT. Without the
        preface check this is a byte relay: no Host binding, no policy, and a
        guest opting out of the terminating plane by writing different first
        bytes on a host somebody listed for performance."""
        mod = _mod()
        origin = self._h2_origin()
        listener, out = self._listener(mod, origin, http2=("localhost",))
        back, _, _ = self._h2_exchange(
            listener, origin,
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertEqual(back, b"", "a close, not an HTTP answer")
        self.assertEqual(origin.requests, [],
                         "a refused stream must never reach the origin")
        self.assertEqual(
            listener.status()["drop_reasons"][mod.DROP_NOT_H2], 1)
        self.assertIn("not HTTP/2", out.getvalue())
        self.assertIn("splic", out.getvalue(),
                      "the refusal must name a remedy `validate` accepts")

    def test_a_preface_followed_by_a_non_settings_frame_is_refused(self):
        """The preface alone is not enough: a guest that sends it and then
        anything at all would otherwise be relayed, because a 24-bit length
        field makes almost any byte string parse as frames."""
        mod = _mod()
        origin = self._h2_origin()
        listener, _ = self._listener(mod, origin, http2=("localhost",))
        headers = b"\x00\x00\x05\x01\x04\x00\x00\x00\x01hpack"
        self._h2_exchange(listener, origin, mod.H2_PREFACE + headers)
        self.assertEqual(
            listener.status()["drop_reasons"][mod.DROP_NOT_H2], 1)
        self.assertEqual(origin.requests, [],
                         "the scanner must run BEFORE the forward, or a "
                         "stream it refuses has already reached the origin "
                         "and the refusal is only a log line")

    def test_a_preface_that_is_not_THE_preface_is_refused(self):
        """The preface check on its own, with the framing check unable to cover

        for it. The obvious version of this test -- send an HTTP/1.1 request --
        passes with the preface check deleted, because the bytes after its
        first 24 do not parse as a frame either and the scanner refuses them.
        So the payload here is 24 bytes that are NOT the preface followed by a
        perfectly legal SETTINGS frame: only the preface check can say no, and
        with it gone this is relayed to the origin.
        """
        mod = _mod()
        origin = self._h2_origin()
        listener, _ = self._listener(mod, origin, http2=("localhost",))
        self.assertEqual(len(mod.H2_PREFACE), 24)
        back, _, _ = self._h2_exchange(
            listener, origin, b"X" * 24 + self.SETTINGS)
        self.assertEqual(back, b"")
        self.assertEqual(origin.requests, [])
        self.assertEqual(
            listener.status()["drop_reasons"][mod.DROP_NOT_H2], 1)

    def test_a_stream_that_stops_framing_MID_SESSION_is_refused_AT_THE_END(self):
        """The relay's copy of the scanner, and the limit of what it can do.

        Every other payload here arrives in one write and is consumed by the
        feed before the relay starts, so a break disabling the relay's
        on_client_bytes leaves the rest of this class green.

        AND THE NAME OF THIS TEST IS THE FINDING. The first version asserted
        that the refused bytes never reached the origin, which is what the
        pre-relay feed achieves and what the check reads as if it does. It
        does not: a frame header is 24 arbitrary length bits, so `GET /secr`
        parses as a frame announcing a 4.6MB payload and the scanner has
        nothing to object to until the connection ends short of it. By then
        the bytes are relayed.

        So the mid-session guarantee is ALIGNMENT AT CLOSE, not refusal in
        flight -- which is worth having (the connection is counted and named
        as not-h2, and an operator sees the host) and is worth writing down as
        the weaker thing it is. What actually binds `http2` to h2 is the
        preface and the opening SETTINGS, both of which are checked before a
        byte moves. Closing this residual means decoding frames properly,
        which is §16's HPACK work.
        """
        mod = _mod()
        origin = self._h2_origin(follow=True)
        listener, _ = self._listener(mod, origin, http2=("localhost",))
        self._h2_exchange(listener, origin,
                          mod.H2_PREFACE + self.SETTINGS,
                          then=b"GET /secret HTTP/1.1\r\n\r\n")
        self.assertEqual(
            listener.status()["drop_reasons"][mod.DROP_NOT_H2], 1)
        # Pinned as it is, not as it ought to be: this is the residual, and a
        # test that asserted the stronger property would have to be deleted by
        # whoever eventually closes it rather than tightened.
        self.assertIn(b"GET /secret", b"".join(origin.requests))

    def test_the_upstream_leg_is_closed_when_the_session_ends(self):
        """Found by a ResourceWarning while every other assertion here was
        green, which is the whole reason it gets a test.

        The h2 branch does not go through _serve_terminated, and that is where
        the upstream socket is closed on the HTTP/1.1 path -- so this leaked
        one verified TLS socket, owned by the workload uid, per connection, in
        a process a guest can open connections to at will. Nothing about the
        exchange is wrong while it happens: the frames cross, the counters
        reconcile, and the collector eventually gets the socket.
        """
        mod = _mod()
        origin = self._h2_origin()
        listener, _ = self._listener(mod, origin, http2=("localhost",))
        legs = []
        real = listener._dial_upstream_tls

        def capture(host, *args):
            leg = real(host, *args)
            legs.append(leg)
            return leg

        listener._dial_upstream_tls = capture
        self._h2_exchange(listener, origin, mod.H2_PREFACE + self.SETTINGS)
        self.assertEqual(len(legs), 1)
        # ON THE FD, not on a count of open descriptors. This file already
        # records why (see the guest-socket close test): CPython collects the
        # socket soon after the handler returns and closes it anyway, so a
        # count-based test passes with the close deleted -- which is exactly
        # what a first attempt at this test did.
        self.assertEqual(legs[0].sock.fileno(), -1,
                         "the h2 branch returned with its upstream leg open")

    def test_the_refusal_is_counted_per_host(self):
        """It is an operator's list of hosts to reconsider -- the entry is
        wrong, or the host needs splicing -- so it is worth a name, exactly
        like the non-HTTP refusal it shares a remedy with."""
        mod = _mod()
        origin = self._h2_origin()
        listener, _ = self._listener(mod, origin, http2=("localhost",))
        self._h2_exchange(listener, origin, b"not h2 at all, not even close")
        per_host = listener.status()["per_host"][mod.DROP_NOT_H2]
        self.assertEqual(dict(per_host).get("localhost"), 1, per_host)


class TestWhatTheStatusFileCarriesFromARealExchange(TerminationCase):
    """Rung 3 T8, through the seam rather than over the counters. A figure that
    is only ever moved by a test calling record_drop is a figure nothing on the
    live path is known to move."""

    def test_an_unverifiable_upstream_names_the_host_it_could_not_verify(self):
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._listener(mod, origin, trust=False)
        self._exchange(listener, origin)
        snap = listener.status()
        self.assertEqual(snap["per_host"][mod.DROP_UNVERIFIED],
                         {self.HOST: 1})

    def test_the_ca_an_operator_must_install_is_in_the_status(self):
        """Rung 5 compares this against the anchor in the guest. Nothing else
        produces the value -- this process is what mints with it."""
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._listener(mod, origin)
        self._exchange(listener, origin)
        ca = listener.status()["mint"]["ca"]
        self.assertRegex(ca["sha256"], r"^([0-9A-F]{2}:){31}[0-9A-F]{2}$")
        self.assertGreater(ca["not_after"], time.time())

    def test_a_denied_name_moves_the_denial_half_of_the_mint_figures(self):
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._listener(mod, origin, hosts=("elsewhere.example",))
        self._exchange(listener, origin)
        mint = listener.status()["mint"]
        self.assertEqual((mint["mints"], mint["denied_mints"]), (1, 1))
        self.assertEqual(mint["denials"], 1)
        self.assertEqual(mint["working_set"], 0)


if __name__ == "__main__":
    unittest.main()


class TestACountIsASCIIOrItIsNotACount(unittest.TestCase):
    """`str.isdigit()` is the wrong guard in front of `int()` on this path.

    The RESPONSE head is decoded latin-1 on purpose -- so that a raw byte in a
    filename cannot kill an exchange the policy authorised -- and latin-1 spells
    the superscripts. `"²".isdigit()` is True and `int("²")` raises,
    so a Content-Length or a status code written with one passed the guard and
    then raised ValueError out of a call site that catches RequestUnreadable and
    OSError: the connection thread died with a traceback and no counter moved.

    Refusal is the right answer, not repair -- the same voice as every other
    framing refusal here.
    """

    def test_a_superscript_content_length_is_refused_not_crashed(self):
        mod = _mod()
        with self.assertRaises(mod.RequestUnreadable):
            mod.response_framing(200, "GET", (("content-length", "²"),))

    def test_a_superscript_status_code_is_refused_not_crashed(self):
        mod = _mod()
        self.assertFalse(mod._is_count("²"))
        self.assertFalse(mod._is_count("2²"))

    def test_ordinary_counts_still_pass(self):
        mod = _mod()
        self.assertTrue(mod._is_count("0"))
        self.assertTrue(mod._is_count("4096"))
        self.assertEqual(
            mod.response_framing(200, "GET", (("content-length", "5"),)),
            mod.Framing("length", 5))

    def test_the_request_side_agrees(self):
        """Safe there already -- that head is ASCII -- and checked anyway.

        The guarantee that makes the request side safe lives two functions away
        in `_split_head`. A guard written to depend on it is one refactor from
        being wrong, so both sides use the same predicate and both are asserted.
        """
        mod = _mod()
        with self.assertRaises(mod.RequestUnreadable):
            mod.request_framing((("content-length", "²"),))


class TestTheCachesCannotEvictALeafInFlight(unittest.TestCase):
    """A cache must hold more entries than there are connection slots.

    Eviction unlinks the victim's PEM, and a leaf is opened by the caller AFTER
    the minter has handed it over. So if the least-recently-used entry can be
    one a live connection still holds, a flood can delete a certificate out from
    under a handshake about to use it -- which fails as a missing file and reads
    as the guest not trusting the CA.

    The two numbers live in different files and nothing else makes them meet.
    """

    def test_every_cache_is_larger_than_the_connection_ceiling(self):
        from vm_mint import DENIAL_CACHE_MAX, LEAF_CACHE_MAX
        mod = _mod()
        for name, size in (("working set", LEAF_CACHE_MAX),
                           ("denial set", DENIAL_CACHE_MAX)):
            with self.subTest(cache=name):
                self.assertGreater(
                    size, mod.MAX_CONNECTIONS,
                    f"the {name} holds {size} entries against "
                    f"{mod.MAX_CONNECTIONS} connection slots, so its "
                    f"least-recently-used entry can be one in flight")


class TestARedialThatCannotBeVerifiedSaysSo(TerminationCase):
    """`ssl.SSLError` IS an `OSError`, and one generic arm hid the difference.

    The front of a terminated connection has always split the two -- a
    certificate that will not verify gets the sentence naming THIS HOST's trust
    anchors, an unreachable host gets the one naming the host. The REDIAL did
    not: `_upstream_for` is reached again whenever an origin answers
    `Connection: close` or an HTTP/1.0 exchange ends, and its handler caught
    OSError only. So a verification failure on a redial was reported as
    "upstream unreachable", and then paid for a second getaddrinfo to decide
    which flavour of unreachable to call it.
    """

    def _drive(self, mod, exc):
        listener, out = self._listener(mod, _Origin(self.origin_pem))
        ours, guest = _tcp_pair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        ours.settimeout(3.0)
        guest.settimeout(3.0)
        guest.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        with unittest.mock.patch.object(
                listener, "_upstream_for", side_effect=exc):
            listener._serve_one_request(
                mod._Stream(ours), ours, "where", {}, True)
        return listener, guest.recv(65536), out.getvalue()

    def test_a_verification_failure_is_not_called_unreachable(self):
        mod = _mod()
        listener, response, log = self._drive(
            mod, ssl.SSLCertVerificationError("self-signed certificate"))
        self.assertIn(b"502", response)
        self.assertIn(b"could not be verified", response,
                      "the guest's 502 is the only place the reason lands")
        self.assertIn(b"THIS HOST", response,
                      "an operator has to be told whose trust store to fix")
        self.assertIn(mod.DROP_UNVERIFIED, log)
        self.assertNotIn(mod.DROP_UNREACHABLE, log)

    def test_an_ordinary_dial_failure_still_goes_the_other_way(self):
        """The other arm still works -- this is a split, not a replacement.

        The reason is `internal destination` rather than `upstream
        unreachable`, and that is _dial_failure_reason being right: the host
        here is `localhost`, which resolves into loopback, and a name resolving
        into private space with no [[vm.network.internal]] entry is a config an
        operator is one line from fixing. Asserted as the specific string rather
        than "not the TLS one", or the test would still pass if the split
        collapsed back into a single arm.
        """
        mod = _mod()
        listener, response, log = self._drive(
            mod, ConnectionRefusedError("connection refused"))
        self.assertIn(b"502", response)
        self.assertIn(b"could not be reached", response)
        self.assertIn(mod.DROP_INTERNAL, log)
        self.assertNotIn(mod.DROP_UNVERIFIED, log)
