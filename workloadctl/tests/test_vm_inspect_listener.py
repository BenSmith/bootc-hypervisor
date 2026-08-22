"""workload-vm-inspect-listener: the socket-activated listener, rung 1.

The listener only logs (the inspector design, §7.7.1): a
connection arrives, one line is written, the connection is closed. These tests
hold the shape that the later rungs ride on — that the plane comes from
getsockname() and not the fd name, that the socket is never opened by the
process itself, that the connection ceiling rejects rather than queues, and
that the installed path agrees with the constant the unit's ExecStart reads.
"""

import io
import json
import os
import shutil
import socket
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from tests import load_script
from vm import (
    VM_INSPECT_LISTENER_BIN, VM_INSPECT_PORT_CLEARTEXT, VM_INSPECT_PORT_TLS,
    vm_hostname_match, vm_inspect_policy,
)

ROOT = Path(__file__).resolve().parent.parent
LISTENER_FILE = ROOT / "libexec" / "workload-vm-inspect-listener"


_MOD = None


def _mod():
    """The listener module, loaded once.

    `load_script` re-execs the file on every call, which would make each call
    return a fresh module with a fresh `NotSocketActivated` class — so the
    exception one call raises is not the class another call's assertRaises
    checks for. Caching keeps the class identity stable across the test."""
    global _MOD
    if _MOD is None:
        _MOD = load_script("libexec/workload-vm-inspect-listener")
    return _MOD


def _mock_conn():
    """A stand-in for an accepted socket: records settimeout and close."""
    return unittest.mock.MagicMock()


def _listener_with(local):
    """A stand-in for an inherited listener whose getsockname() answers `local`."""
    m = unittest.mock.Mock()
    m.getsockname.return_value = local
    return m


def _serve_line(local, peer=("192.0.2.1", 1024)):
    """The admitted connection's log line, driven synchronously through _serve.

    _handle spawns a daemon thread for an admitted connection, which would make
    an assertion on the buffer a race; _serve is what that thread calls, so
    driving it directly is the same line, deterministically.
    """
    mod = _mod()
    out = io.StringIO()
    listener = mod.Listener([_listener_with(local)], out)
    conn = _mock_conn()
    plane = mod.plane_for_port(local[1])
    listener._serve(conn, peer, local, plane)
    return out.getvalue()


class TestPlaneDetection(unittest.TestCase):
    """The plane is the accepting port, from getsockname() on the inherited fd.

    The fd name cannot tell the planes apart under Accept=no, so the port is
    the only honest source; a port that is neither of ours names no plane.
    """

    def test_the_cleartext_port_is_the_cleartext_plane(self):
        mod = _mod()
        self.assertEqual(mod.plane_for_port(VM_INSPECT_PORT_CLEARTEXT), "cleartext")

    def test_the_tls_port_is_the_tls_plane(self):
        mod = _mod()
        self.assertEqual(mod.plane_for_port(VM_INSPECT_PORT_TLS), "tls")

    def test_a_third_port_is_neither(self):
        """A port that is not one of the two the socket unit binds names no
        plane: naming it one would be a guess, and a guess here is a
        misdirected policy decision in a later rung."""
        mod = _mod()
        self.assertIsNone(mod.plane_for_port(9999))

    def test_the_plane_in_the_logged_line_comes_from_getsockname(self):
        """Driven on the cleartext plane, which is the one still log-only.

        The TLS plane now reads bytes off the socket, so a mock connection
        cannot stand in for one; TestTlsPlane drives that side over a real
        socketpair. The property under test is the same either way -- the
        plane in the line is the accepting port, not the fd name.
        """
        local = ("198.18.0.1", VM_INSPECT_PORT_CLEARTEXT)
        log = _serve_line(local)
        self.assertIn("plane=cleartext", log)
        self.assertIn(f"local=198.18.0.1:{VM_INSPECT_PORT_CLEARTEXT}", log)
        self.assertIn("peer=192.0.2.1:1024", log)


class TestExplicitTimeout(unittest.TestCase):
    """Every accepted socket gets a stated timeout, none of them the default.

    This rung reads no bytes, so the number only bounds a socket nobody reads;
    it is set anyway so rung 2's peek inherits a value rather than blocking.
    """

    def test_the_accepted_socket_is_set_to_the_stated_timeout(self):
        mod = _mod()
        conn = _mock_conn()
        out = io.StringIO()
        listener = mod.Listener([_listener_with(
            ("198.18.0.1", VM_INSPECT_PORT_CLEARTEXT))], out)
        listener._handle(conn, ("192.0.2.1", 1024),
                         _listener_with(("198.18.0.1", VM_INSPECT_PORT_CLEARTEXT)))
        conn.settimeout.assert_called_once_with(mod.CONNECTION_TIMEOUT)
        self.assertIsInstance(mod.CONNECTION_TIMEOUT, float)

    def test_the_timeout_is_set_even_when_the_connection_is_rejected(self):
        """The timeout is a ceiling the peek inherits, so it lands on the socket
        before the ceiling is consulted — a rejected socket carries it too."""
        mod = _mod()
        conn = _mock_conn()
        out = io.StringIO()
        listener = mod.Listener([_listener_with(
            ("198.18.0.1", VM_INSPECT_PORT_TLS))], out, limit=0)
        listener._handle(conn, ("192.0.2.1", 1024),
                         _listener_with(("198.18.0.1", VM_INSPECT_PORT_TLS)))
        conn.settimeout.assert_called_once_with(mod.CONNECTION_TIMEOUT)
        conn.close.assert_called()


class TestCeiling(unittest.TestCase):
    """Above the ceiling a connection is refused, not queued.

    §7.7.1: an unbounded accept queue turns a guest's connection storm into
    memory growth; a refused connection is a fast, countable failure. The
    rejection path runs synchronously in the accept loop, so these drive
    _handle directly and read the log without a thread race.
    """

    def test_at_the_ceiling_the_next_connection_is_rejected_not_queued(self):
        # limit=0 makes every connection over capacity immediately, so the
        # reject path runs with no admitted thread to race a slot release.
        mod = _mod()
        out = io.StringIO()
        local = ("198.18.0.1", VM_INSPECT_PORT_CLEARTEXT)
        listener = mod.Listener([_listener_with(local)], out, limit=0)
        conns = [_mock_conn() for _ in range(2)]
        for c in conns:
            listener._handle(c, ("192.0.2.1", 1024), _listener_with(local))
        text = out.getvalue()
        # The reason names the ceiling, and a rejected connection is closed
        # immediately — not held in an unbounded accept queue.
        self.assertEqual(text.count("connection ceiling reached"), 2)
        self.assertEqual(text.count("rejected"), 2)
        conns[0].close.assert_called()
        conns[1].close.assert_called()

    def test_releasing_an_admission_opens_a_slot(self):
        mod = _mod()
        ceiling = mod.Ceiling(1)
        self.assertTrue(ceiling.admit())
        self.assertFalse(ceiling.admit())
        self.assertEqual(ceiling.rejected, 1)
        ceiling.release()
        self.assertTrue(ceiling.admit())


class TestThreadStartFailure(unittest.TestCase):
    """A slot admitted for a thread that never started has to come back.

    The admission happens before the thread exists, so if Thread.start() raises
    the slot is held by nothing. Nothing ever returns it: _serve's release only
    runs for a thread that ran. Each failure therefore lowers the effective
    ceiling for the life of the process, and the condition that causes it —
    the process being unable to get another thread — is precisely a connection
    storm, so the listener degrades to refusing everything at exactly the
    moment the ceiling is supposed to be doing its job, while still reporting
    itself active.
    """

    def _listener_that_cannot_start_threads(self, out, limit=1):
        mod = _mod()
        local = ("198.18.0.1", VM_INSPECT_PORT_CLEARTEXT)
        listener = mod.Listener([_listener_with(local)], out, limit=limit)
        return mod, listener, local

    def test_a_thread_that_cannot_start_gives_its_slot_back(self):
        out = io.StringIO()
        mod, listener, local = self._listener_that_cannot_start_threads(out)
        boom = unittest.mock.Mock(side_effect=RuntimeError("can't start new thread"))
        with unittest.mock.patch.object(mod.threading, "Thread") as thread:
            thread.return_value.start = boom
            for _ in range(5):
                listener._handle(_mock_conn(), ("192.0.2.1", 1024),
                                 _listener_with(local))
        # Five failures against a ceiling of one. Without the release, the
        # first would consume the only slot and the other four would be
        # refused by the cap instead — so the ceiling still having a free slot
        # is what proves the give-back.
        self.assertTrue(listener._ceiling.admit())

    def test_the_connection_is_closed_and_the_reason_is_logged(self):
        out = io.StringIO()
        mod, listener, local = self._listener_that_cannot_start_threads(out)
        conn = _mock_conn()
        with unittest.mock.patch.object(mod.threading, "Thread") as thread:
            thread.return_value.start = unittest.mock.Mock(
                side_effect=RuntimeError("can't start new thread"))
            listener._handle(conn, ("192.0.2.1", 1024), _listener_with(local))
        text = out.getvalue()
        self.assertIn("rejected", text)
        self.assertIn("cannot start thread", text)
        # Closed, not leaked: an unserved connection the guest holds open is
        # an fd this process never gets back.
        conn.close.assert_called()

    def test_a_failed_start_counts_as_a_rejection(self):
        out = io.StringIO()
        mod, listener, local = self._listener_that_cannot_start_threads(out)
        with unittest.mock.patch.object(mod.threading, "Thread") as thread:
            thread.return_value.start = unittest.mock.Mock(
                side_effect=RuntimeError("can't start new thread"))
            listener._handle(_mock_conn(), ("192.0.2.1", 1024),
                             _listener_with(local))
        # The guest saw a closed connection, same as a cap hit. A tally that
        # counted only cap hits would report zero here and understate it.
        self.assertEqual(listener.rejected, 1)


class TestRejectionTally(unittest.TestCase):
    """The count is surfaced, because a ceiling nobody can read is
    indistinguishable from one that never fires."""

    def test_the_shutdown_line_names_the_count(self):
        mod = _mod()
        out = io.StringIO()
        local = ("198.18.0.1", VM_INSPECT_PORT_CLEARTEXT)
        listener = mod.Listener([_listener_with(local)], out, limit=0)
        for _ in range(3):
            listener._handle(_mock_conn(), ("192.0.2.1", 1024),
                             _listener_with(local))
        listener.log_summary()
        self.assertIn("stopped: 3 connection(s) rejected", out.getvalue())

    def test_a_quiet_run_still_reports_its_zero(self):
        # The zero is the useful reading: it separates "the ceiling never
        # fired" from "nothing was logged about it".
        mod = _mod()
        out = io.StringIO()
        listener = mod.Listener(
            [_listener_with(("198.18.0.1", VM_INSPECT_PORT_CLEARTEXT))], out)
        listener.log_summary()
        self.assertIn("stopped: 0 connection(s) rejected", out.getvalue())

    def test_the_summary_is_emitted_when_the_accept_loop_ends(self):
        # Wired into main's finally, so a SIGTERM shutdown reports it.
        src = Path(_mod().__file__).read_text()
        self.assertIn("listener.log_summary()", src)


class TestSocketActivation(unittest.TestCase):
    """The process takes its sockets from the .socket unit, and fails loudly
    if not: a fallback bind would move the bind back into the workload SELinux
    domain."""

    def _recover(self, env):
        mod = _mod()
        with unittest.mock.patch.dict(os.environ, env, clear=True):
            return mod.inherited_listening_sockets()

    def test_a_pid_that_is_not_ours_is_refused(self):
        mod = _mod()
        with self.assertRaises(mod.NotSocketActivated) as ctx:
            self._recover({"LISTEN_PID": "999999", "LISTEN_FDS": "4"})
        self.assertIn("999999", str(ctx.exception))
        self.assertIn(str(mod.os.getpid()), str(ctx.exception))

    def test_an_absent_listen_fds_is_refused(self):
        with self.assertRaises(_mod().NotSocketActivated) as ctx:
            self._recover({"LISTEN_PID": str(os.getpid())})
        self.assertIn("LISTEN_FDS", str(ctx.exception))

    def test_an_absent_listen_pid_is_refused(self):
        with self.assertRaises(_mod().NotSocketActivated) as ctx:
            self._recover({"LISTEN_FDS": "4"})
        self.assertIn("LISTEN_PID", str(ctx.exception))

    def test_a_non_integer_listen_fds_is_refused(self):
        with self.assertRaises(_mod().NotSocketActivated):
            self._recover({"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "four"})

    def test_listening_sockets_are_recovered_from_the_fd_range(self):
        mod = _mod()
        with unittest.mock.patch.dict(
                os.environ,
                {"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "4"}, clear=True), \
                unittest.mock.patch.object(mod.socket, "socket",
                                           return_value=unittest.mock.Mock()) as m:
            result = mod.inherited_listening_sockets()
            self.assertEqual(len(result), 4)
            # The fds are 3 .. 3+LISTEN_FDS, in order, and family/type come
            # back from the fd rather than being spelled.
            self.assertEqual([c.kwargs["fileno"] for c in m.call_args_list],
                             [3, 4, 5, 6])


class TestInstalledPath(unittest.TestCase):
    """The installed path and the constant the unit's ExecStart read agree."""

    def test_the_spec_installs_the_listener_at_the_vm_constant_path(self):
        self.assertEqual(VM_INSPECT_LISTENER_BIN,
                         "/usr/libexec/workloadctl/workload-vm-inspect-listener")
        spec = (ROOT / "rpm" / "workloadctl.spec").read_text()
        self.assertIn("%{_libexecdir}/workloadctl/workload-vm-inspect-listener", spec)
        self.assertIn("libexec/workload-vm-inspect-listener", spec)

    def test_the_listener_source_has_no_literal_listener_ports(self):
        """The plane comes from the vm.py constants, never a hardcoded 8080 or
        8443: a literal would let the port drift from the constant the redirect
        and the socket unit both key on."""
        source = LISTENER_FILE.read_text()
        self.assertNotIn("8080", source)
        self.assertNotIn("8443", source)


# --- rung 2: the TLS plane ---


def _hello_bytes(extensions=b"", *, server_name="example.com"):
    """A ClientHello, wrapped in one TLS record.

    Built by hand rather than taken from a capture so each test can state the
    one thing it varies -- a GREASE extension, an oversized block, a name in a
    different case -- against an otherwise ordinary hello.
    """
    ext = b""
    if server_name is not None:
        host = server_name.encode()
        entry = b"\x00" + len(host).to_bytes(2, "big") + host
        sni = len(entry).to_bytes(2, "big") + entry
        ext += b"\x00\x00" + len(sni).to_bytes(2, "big") + sni
    ext += extensions
    body = (
        b"\x03\x03"                    # legacy_version
        + b"\xaa" * 32                  # random
        + b"\x00"                      # legacy_session_id (empty)
        + b"\x00\x02\x13\x01"         # cipher_suites
        + b"\x01\x00"                  # legacy_compression_methods
        + len(ext).to_bytes(2, "big") + ext
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def _grease_extension(value=0x0a0a):
    """One GREASE extension (RFC 8701), which every ECH-capable client sends
    with no ECH config at all."""
    return value.to_bytes(2, "big") + b"\x00\x00"


class TestClientHelloParser(unittest.TestCase):
    """Enough of RFC 8446 §4.1.2 to read a name, and nothing more."""

    def test_a_plain_hello_yields_its_server_name(self):
        mod = _mod()
        raw = _hello_bytes()
        _, hello = mod.read_client_hello(_FakeSocket([raw]))
        self.assertEqual(hello.server_name, "example.com")

    def test_a_grease_hello_parses(self):
        """GREASE gets no special case and must not need one: a reserved
        extension type is a well-formed extension, skipped by its length like
        any other. Code that enumerated the reserved values could get the list
        wrong; code that ignores them cannot."""
        mod = _mod()
        raw = _hello_bytes(_grease_extension() + _grease_extension(0x1a1a))
        _, hello = mod.read_client_hello(_FakeSocket([raw]))
        self.assertEqual(hello.server_name, "example.com")
        self.assertIn(0x0a0a, hello.extensions)

    def test_a_three_hundred_byte_extension_block_parses(self):
        """A hello with a large extension block -- a post-quantum key share is
        the case that made this ordinary -- must parse, and must parse when it
        spans more than one TLS record."""
        mod = _mod()
        big = b"\x00\x2a" + (300).to_bytes(2, "big") + b"\x00" * 300
        raw = _hello_bytes(big)
        _, hello = mod.read_client_hello(_FakeSocket([raw]))
        self.assertEqual(hello.server_name, "example.com")

    def test_a_hello_split_across_reads_is_reassembled(self):
        """The peek must not assume one recv is one record: TCP is a stream,
        and a hello that arrives in two segments is the common case for the
        large ones above."""
        mod = _mod()
        raw = _hello_bytes(b"\x00\x2a" + (300).to_bytes(2, "big") + b"\x00" * 300)
        sock = _FakeSocket([raw[:20], raw[20:100], raw[100:]])
        got, hello = mod.read_client_hello(sock)
        self.assertEqual(hello.server_name, "example.com")
        self.assertEqual(got, raw)

    def test_a_hello_with_no_sni_reads_but_names_nothing(self):
        """Legal TLS, and simply unallowlistable: there is no name to match."""
        mod = _mod()
        raw = _hello_bytes(server_name=None)
        _, hello = mod.read_client_hello(_FakeSocket([raw]))
        self.assertIsNone(hello.server_name)

    def test_a_truncated_length_is_refused_not_silently_short(self):
        """Every length in a ClientHello is written by the peer. Python's
        slicing returns a short result rather than raising, so a parser that
        sliced would accept a field the peer said was longer than it sent."""
        mod = _mod()
        raw = _hello_bytes()
        # Keep the record header honest, cut the body.
        cut = raw[:5] + raw[5:20]
        cut = cut[:3] + (15).to_bytes(2, "big") + cut[5:]
        with self.assertRaises(mod.HelloUnreadable):
            mod.read_client_hello(_FakeSocket([cut]))

    def test_a_non_handshake_first_byte_is_refused(self):
        mod = _mod()
        with self.assertRaises(mod.HelloUnreadable):
            mod.read_client_hello(_FakeSocket([b"GET / HTTP/1.1\r\n\r\n"]))

    def test_an_oversized_hello_is_refused_rather_than_buffered(self):
        """The read loop is driven by lengths the guest writes, so it needs a
        bound that is not one of them."""
        mod = _mod()
        raw = b"\x16\x03\x01" + (60000).to_bytes(2, "big")
        with self.assertRaises(mod.HelloUnreadable):
            mod.read_client_hello(_FakeSocket([raw]), max_bytes=1024)


class _FakeSocket:
    """A socket that yields a fixed script of reads. Returns b"" when spent,
    which is what a real socket does at EOF."""

    def __init__(self, chunks):
        self._chunks = list(chunks)

    def recv(self, _n):
        return self._chunks.pop(0) if self._chunks else b""


class TestHostnameMatching(unittest.TestCase):
    """One matcher, shared with the cleartext plane and with tinyproxy's list."""

    def test_a_name_differing_only_in_case_matches(self):
        """DNS is case-insensitive and fnmatchcase is not, which is exactly
        why both sides are normalised before it is called."""
        self.assertTrue(vm_hostname_match("EXAMPLE.COM", ["example.com"]))
        self.assertTrue(vm_hostname_match("example.com", ["Example.COM"]))

    def test_a_trailing_root_dot_matches(self):
        """`example.com.` and `example.com` are the same name; a guest that
        writes either spelling gets the same decision, or the spelling is the
        bypass."""
        self.assertTrue(vm_hostname_match("example.com.", ["example.com"]))

    def test_the_apex_trap_is_preserved(self):
        """`*.example.com` does not authorise `example.com`. Documented in
        three tracked files and matched this way by tinyproxy today: widening
        it here would silently grant every existing config a destination its
        operator did not write down."""
        self.assertFalse(vm_hostname_match("example.com", ["*.example.com"]))
        self.assertTrue(vm_hostname_match("a.example.com", ["*.example.com"]))

    def test_an_empty_list_authorises_nothing(self):
        self.assertFalse(vm_hostname_match("example.com", []))


class TestPolicyLoading(unittest.TestCase):
    """The lists are read once, at start, out of the runtime directory."""

    def _write(self, doc):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        path = os.path.join(d, "inspect.json")
        with open(path, "w") as f:
            f.write(doc)
        return path

    def test_the_document_the_helper_writes_is_the_one_the_listener_reads(self):
        """The two halves are tested against each other, not against a literal:
        a listener reading a key the helper does not write is a policy that
        loads clean and authorises nothing."""
        mod = _mod()
        path = self._write(json.dumps(vm_inspect_policy(
            {"hosts": ["example.com"], "tls": "splice"})))
        policy = mod.load_policy(path)
        self.assertEqual(policy.hosts, ("example.com",))
        self.assertEqual(policy.tls, "splice")

    def test_a_missing_document_is_an_error_not_an_empty_policy(self):
        """An empty `hosts` list is a legal configuration, so a listener that
        fell back to one could not tell "the operator allowed nothing" from
        "the file was not there" -- and would enforce the strictest reading of
        a policy it never read while reporting itself healthy."""
        mod = _mod()
        with self.assertRaises(OSError):
            mod.load_policy("/nonexistent/inspect.json")

    def test_a_malformed_document_is_an_error(self):
        mod = _mod()
        with self.assertRaises(ValueError):
            mod.load_policy(self._write("[]"))
        with self.assertRaises(ValueError):
            mod.load_policy(self._write('{"hosts": "example.com"}'))

    def test_main_refuses_without_a_workload_name(self):
        """argv[1] is how the listener knows which policy is its own; without
        it there is nothing on four identically-named fds to recover it from."""
        mod = _mod()
        self.assertEqual(mod.main(["x"]), 2)


class TestTlsPlane(unittest.TestCase):
    """Peek, match, splice -- driven over real sockets, because the plane now
    reads and writes bytes and a mock cannot stand in for one."""

    def _listener(self, hosts):
        mod = _mod()
        out = io.StringIO()
        listener = mod.Listener(
            [], out, policy=mod.Policy(tls="splice", hosts=tuple(hosts)))
        return mod, listener, out

    def _client(self, payload):
        """A connected socketpair with `payload` already queued from the guest
        side. Returns the end the listener is given."""
        guest, ours = socket.socketpair()
        self.addCleanup(guest.close)
        self.addCleanup(ours.close)
        guest.sendall(payload)
        ours.settimeout(2.0)
        return ours, guest

    def test_an_unreadable_hello_is_a_distinct_reason_from_a_name_miss(self):
        """Both fail the guest's connection identically. An operator with one
        bucket for the two cannot tell a guest reaching for a host it may not
        have from a guest speaking something that is not TLS at the TLS port,
        which is the tunnelling signature."""
        mod, listener, out = self._listener(["example.com"])
        conn, _ = self._client(b"GET / HTTP/1.1\r\n\r\n")
        listener._serve_tls(conn, "plane=tls")
        unreadable = out.getvalue()

        mod, listener, out = self._listener(["allowed.example"])
        conn, _ = self._client(_hello_bytes(server_name="denied.example"))
        listener._serve_tls(conn, "plane=tls")
        miss = out.getvalue()

        self.assertIn("no readable name", unreadable)
        self.assertIn("not allowlisted", miss)
        self.assertNotIn("not allowlisted", unreadable)
        self.assertNotIn("no readable name", miss)

    def test_a_hello_with_no_name_is_a_no_readable_name_drop(self):
        _, listener, out = self._listener(["example.com"])
        conn, _ = self._client(_hello_bytes(server_name=None))
        listener._serve_tls(conn, "plane=tls")
        self.assertIn("no readable name", out.getvalue())

    def test_an_unlisted_name_never_reaches_an_upstream(self):
        """The drop is the point: a connection that got as far as dialling
        upstream has already told the network which host the guest wanted."""
        _, listener, out = self._listener(["allowed.example"])
        conn, _ = self._client(_hello_bytes(server_name="denied.example"))
        with unittest.mock.patch.object(socket, "create_connection") as dial:
            listener._serve_tls(conn, "plane=tls")
        dial.assert_not_called()
        self.assertIn("host=denied.example", out.getvalue())

    def test_the_bytes_replayed_upstream_are_the_bytes_read(self):
        """The splice property, and the only test that holds it.

        A ClientHello re-serialised from a parse is a different ClientHello --
        different extension order, different GREASE, a different fingerprint --
        so the server would complete a handshake with a client that is not the
        guest. Byte-identical is the whole claim of `tls = "splice"`.
        """
        mod, listener, _ = self._listener(["example.com"])
        raw = _hello_bytes(_grease_extension())
        conn, guest = self._client(raw)
        upstream, far = socket.socketpair()
        self.addCleanup(upstream.close)
        self.addCleanup(far.close)
        with unittest.mock.patch.object(
                socket, "create_connection", return_value=upstream) as dial:
            # Close the guest end after the hello so the relay ends promptly;
            # the assertion is about what reached the far side first.
            guest.shutdown(socket.SHUT_WR)
            listener._serve_tls(conn, "plane=tls")
        far.settimeout(2.0)
        self.assertEqual(far.recv(len(raw)), raw)
        self.assertEqual(dial.call_args.args[0], ("example.com", 443))

    def test_the_upstream_is_dialled_by_name_not_by_address(self):
        """§7.4. The address the guest aimed at is this inspector's own
        listener -- the redirect already rewrote it -- so resolving the
        authorised name here is what makes the destination the one the policy
        named rather than one the guest chose."""
        _, listener, _ = self._listener(["*.example.com"])
        conn, guest = self._client(_hello_bytes(server_name="a.example.com"))
        guest.shutdown(socket.SHUT_WR)
        upstream, far = socket.socketpair()
        self.addCleanup(upstream.close)
        self.addCleanup(far.close)
        with unittest.mock.patch.object(
                socket, "create_connection", return_value=upstream) as dial:
            listener._serve_tls(conn, "plane=tls")
        host, port = dial.call_args.args[0]
        self.assertEqual(host, "a.example.com")
        self.assertEqual(port, 443)

    def test_an_unreachable_upstream_is_its_own_reason(self):
        _, listener, out = self._listener(["example.com"])
        conn, _ = self._client(_hello_bytes())
        with unittest.mock.patch.object(
                socket, "create_connection",
                side_effect=OSError("Name or service not known")):
            listener._serve_tls(conn, "plane=tls")
        self.assertIn("upstream unreachable", out.getvalue())
        self.assertNotIn("not allowlisted", out.getvalue())


class TestCleartextPlaneUnchanged(unittest.TestCase):
    """Port 80 is still log-only; tinyproxy filters it by name today, so this
    unit neither regressed it nor took it over. T4b does."""

    def test_the_cleartext_plane_still_only_logs(self):
        log = _serve_line(("198.18.0.1", VM_INSPECT_PORT_CLEARTEXT))
        self.assertIn("plane=cleartext", log)
        self.assertNotIn("drop", log)
        self.assertNotIn("splice", log)


if __name__ == "__main__":
    unittest.main()
