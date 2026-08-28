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
import threading
import time
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
    """A stand-in for an accepted socket: records settimeout and close.

    Its recv answers b"" -- a peer that closed without sending anything. The
    planes both read now, so a mock that answered a MagicMock to recv would
    raise inside the daemon thread _handle spawns, where nothing would fail a
    test and everything would print a traceback.
    """
    m = unittest.mock.MagicMock()
    m.recv.return_value = b""
    return m


def _listener_with(local):
    """A stand-in for an inherited listener whose getsockname() answers `local`."""
    m = unittest.mock.Mock()
    m.getsockname.return_value = local
    return m


def _serve_line(test, local, peer=("192.0.2.1", 1024)):
    """One connection's log line, driven synchronously through _serve.

    _handle spawns a daemon thread for an admitted connection, which would make
    an assertion on the buffer a race; _serve is what that thread calls, so
    driving it directly is the same line, deterministically.

    Both planes read bytes now, so the connection is a real socketpair carrying
    one request the empty policy refuses -- the refusal is what produces the
    line whose plane, local and peer are under test.
    """
    mod = _mod()
    out = io.StringIO()
    listener = mod.Listener([_listener_with(local)], out)
    ours, guest = socket.socketpair()
    test.addCleanup(ours.close)
    test.addCleanup(guest.close)
    ours.settimeout(2.0)
    guest.sendall(b"GET / HTTP/1.1\r\nHost: nobody.example\r\n\r\n")
    guest.shutdown(socket.SHUT_WR)
    plane = mod.plane_for_port(local[1])
    listener._serve(ours, peer, local, plane, "0" * 12)
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
        """Driven on the cleartext plane over a real connection.

        Both planes read bytes off the socket now, so the line comes from a
        request the policy refuses rather than from the bare accept. The
        property under test is unchanged -- the plane in the line is the
        accepting port, not the fd name.
        """
        local = ("198.18.0.1", VM_INSPECT_PORT_CLEARTEXT)
        log = _serve_line(self, local)
        self.assertIn("plane=cleartext", log)
        self.assertIn(f"local=198.18.0.1:{VM_INSPECT_PORT_CLEARTEXT}", log)
        self.assertIn("peer=192.0.2.1:1024", log)


class TestExplicitTimeout(unittest.TestCase):
    """Every accepted socket gets a stated timeout, none of them the default.

    It is set before anything touches the socket -- before the ceiling is even
    consulted -- so the peek and the request head both inherit it rather than
    blocking on a guest that says nothing.
    """

    def test_the_accepted_socket_is_set_to_the_stated_timeout(self):
        """The FIRST call, not the only one.

        The cleartext plane returns the socket to this same number at the top
        of every request it serves, so a `called_once` assertion here would be
        an assertion about how many requests the connection carried.
        """
        mod = _mod()
        conn = _mock_conn()
        out = io.StringIO()
        listener = mod.Listener([_listener_with(
            ("198.18.0.1", VM_INSPECT_PORT_CLEARTEXT))], out)
        listener._handle(conn, ("192.0.2.1", 1024),
                         _listener_with(("198.18.0.1", VM_INSPECT_PORT_CLEARTEXT)))
        self.assertEqual(conn.settimeout.call_args_list[0],
                         unittest.mock.call(mod.CONNECTION_TIMEOUT))
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

    def test_a_rejected_connection_reaches_the_counters_too(self):
        """The log line and the counter are two separate statements and only
        one of them was being checked. A refused connection is closed on the
        guest exactly as every other drop is, so a disposition total that
        omitted it would not account for every connection the guest saw end."""
        mod = _mod()
        local = ("198.18.0.1", VM_INSPECT_PORT_CLEARTEXT)
        listener = mod.Listener([_listener_with(local)], io.StringIO(), limit=0)
        for _ in range(2):
            listener._handle(_mock_conn(), ("192.0.2.1", 1024),
                             _listener_with(local))
        snap = listener.status()
        self.assertEqual(snap["dispositions"]["dropped"], 2)
        self.assertEqual(snap["drop_reasons"]["connection ceiling reached"], 2)
        self.assertEqual(snap["concurrency"]["refused"], 2)

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
    """One matcher, shared with the cleartext plane and with the `hosts` list
    the retired proxy matched the same way."""

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
        three tracked files and was matched this way by the retired proxy: widening
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

    def test_every_key_the_helper_writes_is_a_key_the_listener_reads(self):
        """The forward half of the sentence above, which the per-key tests
        below do not cover.

        Each of those asserts that a key the LISTENER reads survives the trip,
        so a helper that stopped writing one fails. Nothing asserted the other
        direction: `load_policy` reads by `doc.get(...)` and ignores what it
        does not know, so a key added to vm_inspect_policy and never wired into
        the listener loads clean and authorises nothing -- silently, across two
        processes, which is the seam a unit gate is least likely to see.

        Policy._fields is the source of truth for the reader, the way
        DROP_REASONS and PER_HOST_REASONS are for the counters. A key added to
        the document with no field behind it fails here, and the fix is to
        decide deliberately whether the listener should be reading it.
        """
        mod = _mod()
        doc = vm_inspect_policy({
            "hosts": ["example.com"],
            "internal": [{"host": "nas.example.com", "reason": "nas"}],
            "splice": [{"host": "pinned.example.com", "reason": "pinned"}],
            "http2": [{"host": "grpc.example.com", "reason": "gRPC"}],
            "policy": [{"host": "api.example.com", "methods": ["GET"]}]})
        self.assertEqual(set(doc), set(mod.Policy._fields))

    def test_the_document_carries_the_internal_list_through(self):
        """The listener's copy of [[vm.network.internal]] authorises nothing --
        it is what tells a wildcard-trap refusal apart from a host that is
        simply down. Dropped on load, every internal-destination refusal is
        misfiled as 'upstream unreachable' and the counter that exists to name
        the wildcard trap never moves."""
        mod = _mod()
        path = self._write(json.dumps(vm_inspect_policy({
            "hosts": ["nas.example.com"], "tls": "splice",
            "internal": [{"host": "nas.example.com"}]})))
        policy = mod.load_policy(path)
        self.assertEqual(policy.internal, ("nas.example.com",))

    def test_the_document_carries_the_policy_entries_through(self):
        """Both halves against each other, not against a literal: a listener
        reading a key the helper does not write governs nothing while the
        config says every request is constrained."""
        mod = _mod()
        path = self._write(json.dumps(vm_inspect_policy({
            "hosts": ["a.example"],
            "policy": [{"host": "a.example", "methods": ["GET"],
                        "paths": ["/v2/*"]}]})))
        entry, = mod.load_policy(path).policy
        self.assertEqual(entry.host, "a.example")
        self.assertEqual(entry.methods, ("GET",))
        self.assertEqual(entry.paths, ("/v2/*",))

    def test_an_absent_key_survives_the_LOAD_as_absent(self):
        """null and [] are different answers and the loader must keep them
        apart, not only the writer.

        `tuple(methods or ())` reads correct and turns every unconstrained
        entry into one that permits NOTHING. That fails closed, so it fails
        quietly: the workload reaches none of its hosts, every unit test about
        the matcher still passes because the matcher was never wrong, and the
        only symptom is a guest that gets a 403 for a request its config
        permits.
        """
        mod = _mod()
        path = self._write(json.dumps(vm_inspect_policy({
            "policy": [{"host": "a.example"}]})))
        entry, = mod.load_policy(path).policy
        self.assertIsNone(entry.methods)
        self.assertIsNone(entry.paths)
        self.assertTrue(entry.permits("DELETE", "/anything"))

    def test_the_document_carries_the_http2_list_through(self):
        """Both halves against each other. A listener that dropped this on load
        offers `http/1.1` to a host the operator listed for h2, which fails as
        that one host being broken rather than as a key being ignored."""
        mod = _mod()
        path = self._write(json.dumps(vm_inspect_policy({
            "hosts": ["grpc.example.com"],
            "http2": [{"host": "grpc.example.com", "reason": "gRPC"}]})))
        policy = mod.load_policy(path)
        self.assertEqual(policy.http2, ("grpc.example.com",))
        self.assertTrue(policy.speaks_h2("grpc.example.com"))

    def test_a_malformed_http2_list_is_an_error(self):
        mod = _mod()
        path = self._write(json.dumps({"hosts": [], "http2": "grpc.example"}))
        with self.assertRaises(ValueError):
            mod.load_policy(path)

    def test_a_malformed_policy_entry_is_an_error(self):
        mod = _mod()
        with self.assertRaises(ValueError):
            mod.load_policy(self._write('{"hosts": [], "policy": "a.example"}'))
        with self.assertRaises(ValueError):
            mod.load_policy(self._write('{"hosts": [], "policy": [{"m": 1}]}'))

    def test_a_lowercase_method_in_the_document_is_normalised_on_load(self):
        """The reader normalises as well as the writer, which is the
        convention `internal` and the responder's static map already hold.
        VmPolicyEntry.permits compares `method.upper()` against these, so a
        document carrying `["get"]` would deny every GET on that host -- fails
        closed, and therefore in silence, on a file that reads as permitting
        it."""
        mod = _mod()
        path = self._write(json.dumps({
            "tls": "inspect", "hosts": ["a.example"],
            "policy": [{"host": "a.example", "methods": ["get"],
                        "paths": ["/v1/*"]}]}))
        policy = mod.load_policy(path)
        self.assertEqual(policy.policy[0].methods, ("GET",))
        self.assertTrue(policy.permits("a.example", "GET", "/v1/x"))

    def test_a_non_string_in_methods_or_paths_is_dropped_not_carried(self):
        """Carried, it reaches fnmatchcase and raises TypeError out of the
        request path -- one guest request killing the connection on a
        malformed line in a file, rather than being ignored the way every
        other reader here ignores a shape validation owns."""
        mod = _mod()
        path = self._write(json.dumps({
            "tls": "inspect", "hosts": ["a.example"],
            "policy": [{"host": "a.example", "methods": ["GET", 7],
                        "paths": ["/v1/*", None]}]}))
        entry, = mod.load_policy(path).policy
        self.assertEqual(entry.methods, ("GET",))
        self.assertEqual(entry.paths, ("/v1/*",))

    def test_an_absent_key_survives_the_normalisation(self):
        """None and () are still different after it. A normaliser that turned
        an absent `methods` into an empty tuple would make every
        unconstrained entry permit nothing."""
        mod = _mod()
        path = self._write(json.dumps({
            "tls": "inspect", "hosts": ["a.example"],
            "policy": [{"host": "a.example"}]}))
        entry, = mod.load_policy(path).policy
        self.assertIsNone(entry.methods)
        self.assertIsNone(entry.paths)

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


class TestPerHostSplice(unittest.TestCase):
    """[[vm.network.splice]] -- HLD §11 hatch 2, on a terminating listener.

    The key exists before the messages that name it: every non-HTTP refusal
    this rung writes tells the operator to splice the host, and a remedy
    `validate` rejects is worse than no remedy at all.
    """

    def _listener(self, hosts, splice, tls="inspect"):
        mod = _mod()
        out = io.StringIO()
        listener = mod.Listener(
            [], out,
            policy=mod.Policy(tls=tls, hosts=tuple(hosts),
                              splice=tuple(splice)),
            minter=unittest.mock.Mock())
        return mod, listener, out

    def _client(self, payload):
        guest, ours = socket.socketpair()
        self.addCleanup(guest.close)
        self.addCleanup(ours.close)
        guest.sendall(payload)
        ours.settimeout(2.0)
        return ours, guest

    def test_the_whole_workload_mode_splices_every_host(self):
        """One question, asked in one place. `tls == "splice"` in one branch
        and a list check in another is how a path gets one of the two and
        reads correct at its own call site."""
        mod = _mod()
        policy = mod.Policy(tls="splice", hosts=("a.example",), splice=())
        self.assertTrue(policy.splices("a.example"))
        self.assertTrue(policy.splices("anything.at.all"))

    def test_the_per_host_list_is_matched_as_patterns(self):
        mod = _mod()
        policy = mod.Policy(tls="inspect", hosts=("*.golang.org",),
                            splice=("*.golang.org",))
        self.assertTrue(policy.splices("sum.golang.org"))
        self.assertFalse(policy.splices("github.com"))

    def test_a_spliced_host_on_a_terminating_listener_is_not_terminated(self):
        mod, listener, out = self._listener(
            ["sum.golang.org"], ["sum.golang.org"])
        conn, guest = self._client(_hello_bytes(server_name="sum.golang.org"))
        guest.shutdown(socket.SHUT_WR)
        upstream, far = socket.socketpair()
        self.addCleanup(upstream.close)
        self.addCleanup(far.close)
        with unittest.mock.patch.object(listener, "_serve_tls_inspect") as term:
            with unittest.mock.patch.object(
                    socket, "create_connection", return_value=upstream):
                listener._serve_tls(conn, "plane=tls")
        term.assert_not_called()
        self.assertIn("splice", out.getvalue())
        self.assertIn("host=sum.golang.org", out.getvalue())

    def test_the_peeked_hello_reaches_the_origin_ONCE_and_unmodified(self):
        """The seam the peek opens, and the one that fails silently.

        On a terminating listener the hello is PEEKED -- it has to be, because
        the splice decision needs the name that is inside it -- so the bytes
        are still on the socket when the relay starts. Replaying `raw` as well
        delivers the hello twice, the origin fails the handshake on the
        duplicate, and the host somebody exempted precisely because it was
        breaking breaks in a new way that looks the same.
        """
        _, listener, _ = self._listener(["example.com"], ["example.com"])
        raw = _hello_bytes(_grease_extension())
        conn, guest = self._client(raw)
        guest.shutdown(socket.SHUT_WR)
        upstream, far = socket.socketpair()
        self.addCleanup(upstream.close)
        self.addCleanup(far.close)
        with unittest.mock.patch.object(
                socket, "create_connection", return_value=upstream):
            listener._serve_tls(conn, "plane=tls")
        far.settimeout(2.0)
        upstream.close()
        received = b""
        while True:
            try:
                chunk = far.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            received += chunk
        self.assertEqual(received, raw)

    def test_a_host_not_on_the_splice_list_is_still_terminated(self):
        _, listener, _ = self._listener(
            ["a.example", "b.example"], ["a.example"])
        conn, guest = self._client(_hello_bytes(server_name="b.example"))
        guest.shutdown(socket.SHUT_WR)
        with unittest.mock.patch.object(listener, "_serve_tls_inspect") as term:
            listener._serve_tls(conn, "plane=tls")
        term.assert_called_once()
        self.assertEqual(term.call_args.args[2], "b.example")

    def test_a_spliced_name_on_no_allowlist_gets_the_READABLE_refusal(self):
        """The allowlist decision comes first, and the order is not cosmetic.

        A `splice` PATTERN can cover names `hosts` does not -- `*.example.com`
        spliced with one name of it allowlisted -- and validation cannot catch
        that, because the pattern does match allowlisted names. Splicing first
        would answer such a name with a silent close where every other denial
        on this listener is a bump-then-403 the guest can read.
        """
        _, listener, _ = self._listener(
            ["good.example.com"], ["*.example.com"])
        conn, guest = self._client(_hello_bytes(server_name="evil.example.com"))
        guest.shutdown(socket.SHUT_WR)
        with unittest.mock.patch.object(listener, "_serve_tls_inspect") as term:
            with unittest.mock.patch.object(socket, "create_connection") as dial:
                listener._serve_tls(conn, "plane=tls")
        dial.assert_not_called()
        term.assert_called_once()
        self.assertEqual(term.call_args.args[3], False)   # `allowed`

    def test_the_document_carries_the_splice_list_through(self):
        """Both halves against each other, not against a literal: a listener
        reading a key the helper does not write splices nothing while the
        config says it does."""
        mod = _mod()
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        path = os.path.join(d, "inspect.json")
        with open(path, "w") as f:
            json.dump(vm_inspect_policy({
                "hosts": ["sum.golang.org"],
                "splice": [{"host": "sum.golang.org", "reason": "a log"}]}), f)
        self.assertEqual(mod.load_policy(path).splice, ("sum.golang.org",))

    def test_the_list_is_carried_even_under_tls_splice(self):
        """The document describes the FILE, not the file filtered through the
        mode -- so a listener restarted onto `inspect` reads a document that
        already says what the per-host list was."""
        doc = vm_inspect_policy({
            "tls": "splice", "hosts": ["sum.golang.org"],
            "splice": [{"host": "sum.golang.org", "reason": "a log"}]})
        self.assertEqual(doc["splice"], ["sum.golang.org"])


class TestHttp2Framing(unittest.TestCase):
    """The check that makes [[vm.network.http2]] mean SPEAKS H2, not EXEMPT.

    Without it a listed host is a byte relay -- no Host binding, no `paths`, no
    `methods`, and nothing establishing the bytes are h2 -- so a guest reaches
    a full policy opt-out on any host somebody added for performance, by
    writing different first bytes. That is the shape HLD §8 reversed itself to
    remove, surviving one key along.
    """

    @staticmethod
    def _frame(kind, stream=0, payload=b"", flags=0):
        return (len(payload).to_bytes(3, "big") + bytes([kind, flags])
                + stream.to_bytes(4, "big") + payload)

    def test_the_preface_is_the_exact_rfc_bytes(self):
        """Pinned as a literal rather than rebuilt from parts. It is 24 fixed
        bytes chosen so an HTTP/1.1 server cannot mistake them for a request,
        and a version this file computed could be wrong in a way that only
        showed up against a real client."""
        mod = _mod()
        self.assertEqual(mod.H2_PREFACE,
                         b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        self.assertEqual(len(mod.H2_PREFACE), 24)

    def test_a_settings_frame_on_stream_zero_opens_a_connection(self):
        mod = _mod()
        framing = mod.H2Framing()
        framing.feed(self._frame(0x4, payload=b"\x00\x03\x00\x00\x00\x64"))
        self.assertTrue(framing.aligned)

    def test_an_empty_settings_frame_opens_a_connection(self):
        """RFC 9113 §3.4: the client's opening SETTINGS MAY be empty, and a
        check requiring a payload would refuse conforming clients."""
        mod = _mod()
        framing = mod.H2Framing()
        framing.feed(self._frame(0x4))
        self.assertTrue(framing.aligned)

    def test_a_first_frame_that_is_not_settings_is_refused(self):
        """This is one of the two checks with real teeth. A guest that sent the
        preface and then whatever it liked would otherwise be relayed, because
        the length field is 24 arbitrary bits and nearly any byte string parses
        as frames."""
        mod = _mod()
        framing = mod.H2Framing()
        with self.assertRaises(mod.NotH2):
            framing.feed(self._frame(0x1, stream=1, payload=b"headers"))

    def test_a_first_settings_frame_off_stream_zero_is_refused(self):
        mod = _mod()
        framing = mod.H2Framing()
        with self.assertRaises(mod.NotH2):
            framing.feed(self._frame(0x4, stream=1))

    def test_an_opening_settings_frame_of_a_ragged_length_is_refused(self):
        """Settings are 6 bytes each (RFC 9113 §6.5), so a length that is not a
        multiple of six is not a SETTINGS frame whatever the type byte says."""
        mod = _mod()
        framing = mod.H2Framing()
        with self.assertRaises(mod.NotH2):
            framing.feed(self._frame(0x4, payload=b"\x00\x03\x00"))

    def test_a_frame_header_split_across_reads_is_reassembled(self):
        """The scanner is fed whatever recv returned, not whole frames. A
        version that parsed each chunk independently would refuse every real
        connection whose opening SETTINGS straddled a segment boundary --
        intermittently, and under load first."""
        mod = _mod()
        framing = mod.H2Framing()
        frame = self._frame(0x4, payload=b"\x00\x03\x00\x00\x00\x64")
        for i in range(1, len(frame)):
            scanner = mod.H2Framing()
            scanner.feed(frame[:i])
            scanner.feed(frame[i:])
            self.assertTrue(scanner.aligned, i)
        framing.feed(frame)
        self.assertTrue(framing.aligned)

    def test_several_frames_in_one_read_stay_aligned(self):
        mod = _mod()
        framing = mod.H2Framing()
        framing.feed(self._frame(0x4)
                     + self._frame(0x1, stream=1, payload=b"hpack")
                     + self._frame(0x0, stream=1, payload=b"body"))
        self.assertTrue(framing.aligned)

    def test_a_stream_that_stops_part_way_through_a_frame_is_not_aligned(self):
        """The one thing continuous framing actually catches. A relay checking
        only the first frame would carry anything at all after it."""
        mod = _mod()
        framing = mod.H2Framing()
        framing.feed(self._frame(0x4) + b"\x00\x00\x40\x00\x00\x00\x00")
        self.assertFalse(framing.aligned)

    def test_the_reserved_bit_of_a_stream_id_is_ignored_not_refused(self):
        """RFC 9113 §4.1: receivers must ignore it. Refusing a sender that sets
        it would fail a conforming connection over a bit nothing reads."""
        mod = _mod()
        framing = mod.H2Framing()
        framing.feed(b"\x00\x00\x00\x04\x00\x80\x00\x00\x00")
        self.assertTrue(framing.aligned)

    def test_an_http11_request_never_reaches_the_framing_check(self):
        """The preface does nearly all the work, and this says why the framing
        scanner is not asked to be a conformance checker: everything that is
        not h2 fails on byte one, before any of it runs."""
        mod = _mod()
        self.assertNotEqual(b"GET / HTTP/1.1\r\n"[:len(mod.H2_PREFACE)],
                            mod.H2_PREFACE)


class TestHttp2AlpnSelection(unittest.TestCase):
    """Which protocol each leg offers, chosen from configuration alone.

    §6 requires the upstream leg up BEFORE a leaf is minted, so nothing here
    can sniff the guest and then speak what came back. And the offer BINDS
    NOBODY -- a server offering http/1.1 alone facing a client offering h2
    alone completes the handshake with no protocol negotiated and no alert -- so
    these tests pin what is configured, and the refusals in TestHttp2Framing
    and the non-HTTP check are what make it stick.
    """

    def _policy(self, mod, **kw):
        return mod.Policy(tls="inspect", hosts=("a.example", "grpc.example"),
                          **kw)

    def test_speaks_h2_is_the_list_and_not_the_mode(self):
        mod = _mod()
        policy = self._policy(mod, http2=("grpc.example",))
        self.assertTrue(policy.speaks_h2("grpc.example"))
        self.assertFalse(policy.speaks_h2("a.example"))

    def test_speaks_h2_matches_by_pattern_and_normalises_the_name(self):
        mod = _mod()
        policy = mod.Policy(tls="inspect", hosts=("*.example",),
                            http2=("*.grpc.example",))
        self.assertTrue(policy.speaks_h2("a.GRPC.example."))
        self.assertFalse(policy.speaks_h2("grpc.example"),
                         "fnmatch, not DNS suffix matching: the apex trap")

    def test_the_two_contexts_offer_different_protocols(self):
        """One context per offer rather than one whose ALPN is set per dial:
        contexts are shared across connections, so mutating one before a
        handshake races every other connection using it -- silently, and in the
        direction that gives a host the offer another host asked for."""
        mod = _mod()
        listener = mod.Listener([], io.StringIO(),
                                policy=self._policy(mod, http2=("grpc.example",)))
        self.assertIsNot(listener._upstream_ctx, listener._upstream_ctx_h2)
        self.assertEqual(mod.UPSTREAM_ALPN, ("http/1.1",))
        self.assertEqual(mod.ALPN_H2, ("h2",))


class TestLogInjection(unittest.TestCase):
    """A name the guest wrote must not be able to write a line of this log.

    The log is the operator's evidence, and it is line-oriented: a bare LF
    inside a name ends the record journald stores and makes what follows a
    second, fabricated entry that reads exactly like one this program emitted.
    A guest that can forge `splice plane=tls ... host=github.com` can forge the
    record of a decision that never happened.

    The cleartext plane already refuses the whole control class in
    `_reject_controls`, for the smuggling reason. These are the other two
    readers of a guest-written name.
    """

    def _listener(self, hosts):
        mod = _mod()
        out = io.StringIO()
        listener = mod.Listener(
            [], out, policy=mod.Policy(tls="splice", hosts=tuple(hosts)))
        return mod, listener, out

    _forged = "evil.example\nsplice plane=tls local=127.0.0.1:1 " \
              "peer=127.0.0.1:2 host=allowed.example"

    def test_an_sni_with_a_newline_is_not_a_readable_name(self):
        mod = _mod()
        with self.assertRaises(mod.HelloUnreadable):
            mod.read_client_hello(
                _FakeSocket([_hello_bytes(server_name=self._forged)]))

    def test_a_forged_sni_writes_exactly_one_line_and_not_the_forged_one(self):
        """The end-to-end property, over the plane rather than the parser: one
        connection, one record, and the record is a refusal."""
        _, listener, out = self._listener(["allowed.example"])
        guest, ours = socket.socketpair()
        self.addCleanup(guest.close)
        self.addCleanup(ours.close)
        guest.sendall(_hello_bytes(server_name=self._forged))
        ours.settimeout(2.0)
        listener._serve_tls(ours, "plane=tls")
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 1, lines)
        self.assertIn("no readable name", lines[0])
        self.assertNotIn("splice", lines[0])

    def test_the_refusal_does_not_quote_the_name_it_refuses(self):
        """Naming the character is the diagnosis; echoing the name would put
        the injected bytes into the record the refusal exists to protect."""
        _, listener, out = self._listener(["allowed.example"])
        guest, ours = socket.socketpair()
        self.addCleanup(guest.close)
        self.addCleanup(ours.close)
        guest.sendall(_hello_bytes(server_name=self._forged))
        ours.settimeout(2.0)
        listener._serve_tls(ours, "plane=tls")
        self.assertNotIn("evil.example", out.getvalue())
        self.assertIn(repr("\n"), out.getvalue())

    def test_a_forged_sni_never_reaches_the_status_document(self):
        """`unlisted_names` is rendered by diagnose, so a name that got as far
        as being counted is a name that got as far as the operator."""
        _, listener, _ = self._listener(["allowed.example"])
        guest, ours = socket.socketpair()
        self.addCleanup(guest.close)
        self.addCleanup(ours.close)
        guest.sendall(_hello_bytes(server_name=self._forged))
        ours.settimeout(2.0)
        listener._serve_tls(ours, "plane=tls")
        snapshot = json.dumps(
            listener.counters.snapshot(open_now=0, refused=0))
        self.assertNotIn("evil.example", snapshot)

    def test_every_control_character_is_refused_not_only_the_newline(self):
        """LF is the one that forges a record; CR, NUL and DEL are refused with
        it because a field with any of them has no reading both ends share."""
        mod = _mod()
        for ch in ("\n", "\r", "\x00", "\x7f", "\t", "\x1b"):
            with self.subTest(ch=ch):
                with self.assertRaises(mod.HelloUnreadable):
                    mod.read_client_hello(
                        _FakeSocket([_hello_bytes(
                            server_name=f"a{ch}b.example")]))

    def test_an_ordinary_name_still_reads(self):
        """The guard must not cost the names that are not attacks."""
        mod = _mod()
        _, hello = mod.read_client_hello(
            _FakeSocket([_hello_bytes(server_name="Fine-Name.EXAMPLE.com")]))
        self.assertEqual(hello.server_name, "Fine-Name.EXAMPLE.com")


_OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"


class _CleartextRig(unittest.TestCase):
    """Drives one guest connection through the cleartext plane over real
    sockets. A mock cannot stand in for a socket here: the whole unit is about
    where one message ends and the next begins in a byte stream.
    """

    def _pair(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        a.settimeout(2.0)
        b.settimeout(2.0)
        return a, b

    def _run(self, hosts, request_bytes, responses=(), policy=None):
        """Serve `request_bytes` under a policy of `hosts`.

        `policy` overrides the whole document, for the cases whose subject
        is a key other than `hosts`.

        Returns (log, what the guest was sent, [(dialled address, bytes the
        upstream received)]). Each dialled upstream is a socketpair whose far
        end is pre-loaded with the matching entry of `responses`, so the
        response is already waiting when the relay comes to read it.
        """
        mod = _mod()
        out = io.StringIO()
        listener = mod.Listener(
            [], out,
            policy=policy or mod.Policy(tls="splice", hosts=tuple(hosts)))
        ours, guest = self._pair()
        guest.sendall(request_bytes)
        guest.shutdown(socket.SHUT_WR)
        dialled = []

        def dial(addr, timeout=None):
            near, far = self._pair()
            index = len(dialled)
            if index < len(responses):
                far.sendall(responses[index])
            # Drained CONCURRENTLY, not after the fact. The relay sends a
            # request body upstream before it reads the response, so an
            # upstream nobody is reading fills its socket buffer and the send
            # blocks -- which is a property of this rig's socketpair, not of
            # the listener, but it caps every body the rig can carry at one
            # buffer and looks exactly like a relay defect.
            buf = bytearray()
            pump = threading.Thread(target=_pump, args=(far, buf), daemon=True)
            pump.start()
            dialled.append((addr, buf, pump))
            return near

        # The relay moves an upstream onto RELAY_IDLE_TIMEOUT, which is a
        # tunnel bound and two minutes long. A test whose upstream is silent
        # would wait all of it, so the rig shortens both numbers -- one place,
        # not a sleep-shaped constant in every case.
        with unittest.mock.patch.object(
                socket, "create_connection", side_effect=dial), \
                unittest.mock.patch.object(mod, "RELAY_IDLE_TIMEOUT", 2.0), \
                unittest.mock.patch.object(mod, "CONNECTION_TIMEOUT", 2.0):
            listener._serve_cleartext(ours, "plane=cleartext")
        ours.close()
        for _, _, pump in dialled:
            pump.join(timeout=3.0)
        return (out.getvalue(), _read_all(guest),
                [(addr, bytes(buf)) for addr, buf, _ in dialled])


def _pump(sock, buf):
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                return
            buf += chunk
    except (TimeoutError, OSError):
        return


def _read_all(sock):
    out = b""
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                return out
            out += chunk
    except (TimeoutError, OSError):
        return out


class TestPolicyGovernsIsAskedWhereThereIsNoRequest(unittest.TestCase):
    """Rung 4 tier 6. `governs` is not `permits` with the arguments left off.

    `permits` answers "was this request allowed"; `governs` is asked about a
    connection that never carried a request at all, and answers the operator's
    question instead -- are there `methods` and `paths` on this host that never
    got to run? The two are separate because a merge in either direction is
    silent: permits() on a governed host with no request would have to invent a
    method and a path, and reading governs() as permission would let any host
    somebody wrote a rule for through without the rule.
    """

    def _policy(self, *entries, hosts=("a.example",)):
        mod = _mod()
        return mod.Policy(
            tls="inspect", hosts=tuple(hosts),
            policy=tuple(mod.VmPolicyEntry(host=h, methods=m, paths=pa)
                         for h, m, pa in entries))

    def test_a_host_with_an_entry_is_governed(self):
        policy = self._policy(("a.example", ("GET",), ("/v1/*",)))
        self.assertTrue(policy.governs("a.example"))

    def test_an_allowlisted_host_with_no_entry_is_not(self):
        """`hosts` is not policy. A host allowed by name alone has no rules to
        have failed to run, and counting it in the policy bucket would tell an
        operator to go looking for an entry that is not there."""
        policy = self._policy(("b.example", ("GET",), ("/v1/*",)),
                              hosts=("a.example", "b.example"))
        self.assertFalse(policy.governs("a.example"))

    def test_no_entries_at_all_governs_nothing(self):
        self.assertFalse(self._policy().governs("a.example"))

    def test_it_matches_by_pattern_and_normalises_the_name(self):
        policy = self._policy(("*.example", ("GET",), ("/",)),
                              hosts=("*.example",))
        self.assertTrue(policy.governs("API.a.Example."))
        self.assertFalse(policy.governs("example"),
                         "fnmatch, not DNS suffix matching: the apex trap")

    def test_it_does_not_care_whether_the_entry_would_permit_anything(self):
        """A host whose only entry permits GET /v1 alone is governed just as
        much as one permitting everything. The figure is about rules EXISTING,
        not about what they say -- an entry that permits nothing the guest
        wanted is still an entry that never ran."""
        policy = self._policy(("a.example", ("GET",), ("/v1/only",)))
        self.assertTrue(policy.governs("a.example"))
        self.assertFalse(policy.permits("a.example", "POST", "/other"))


class TestPolicyEnforcement(_CleartextRig):
    """[[vm.network.policy]] applied to a real request, over real sockets.

    The cleartext plane because it is the same request loop the terminated
    plane runs -- `_serve_one_request` is shared -- and it can be driven
    without a handshake.
    """

    def _policy(self, hosts, *entries):
        mod = _mod()
        return mod.Policy(
            tls="splice", hosts=tuple(hosts),
            policy=tuple(mod.VmPolicyEntry(host=h, methods=m, paths=p)
                         for h, m, p in entries))

    def _get(self, target="/", host="a.example", method="GET"):
        return (f"{method} {target} HTTP/1.1\r\nHost: {host}\r\n"
                f"\r\n").encode()

    def test_a_permitted_method_and_path_is_forwarded(self):
        log, _, dialled = self._run(
            [], self._get("/v2/thing"), (_OK,),
            policy=self._policy([], ("a.example", ("GET",), ("/v2/*",))))
        self.assertIn("forward", log)
        self.assertEqual(len(dialled), 1)

    def test_a_method_no_entry_permits_is_a_403(self):
        log, sent, dialled = self._run(
            [], self._get("/v2/thing", method="DELETE"),
            policy=self._policy([], ("a.example", ("GET",), ("/v2/*",))))
        self.assertIn("not permitted by policy", log)
        self.assertIn(b"403", sent)
        self.assertEqual(dialled, [],
                         "a refused request must never reach an origin")

    def test_a_path_no_entry_permits_is_a_403(self):
        log, sent, dialled = self._run(
            [], self._get("/admin"),
            policy=self._policy([], ("a.example", ("GET",), ("/v2/*",))))
        self.assertIn("not permitted by policy", log)
        self.assertIn(b"403", sent)
        self.assertEqual(dialled, [])

    def test_the_two_refusals_are_DISTINCT_reasons(self):
        """An operator with one bucket for the two reads a working allowlist
        as a broken one, and a guest told `not on the allowlist` about a host
        that plainly is goes looking in the wrong file."""
        policy = self._policy(["b.example"],
                              ("a.example", ("GET",), ("/v2/*",)))
        refused, sent_refused, _ = self._run(
            [], self._get("/admin"), policy=policy)
        unlisted, sent_unlisted, _ = self._run(
            [], self._get("/", host="c.example"), policy=policy)
        self.assertIn("not permitted by policy", refused)
        self.assertNotIn("not allowlisted", refused)
        self.assertIn("not allowlisted", unlisted)
        self.assertNotIn("not permitted by policy", unlisted)
        self.assertIn(b"egress policy", sent_refused)
        self.assertIn(b"egress allowlist", sent_unlisted)

    def test_a_policy_host_is_reachable_without_appearing_in_hosts(self):
        """§3: a name in `policy` need not also appear in `hosts`. A listener
        that admitted on `hosts` alone would refuse every host of a workload
        whose entire allowlist is written as policy entries -- and report it as
        `not allowlisted` for a name the file plainly carries."""
        log, _, dialled = self._run(
            [], self._get("/v2/x"), (_OK,),
            policy=self._policy([], ("a.example", ("GET",), ("/v2/*",))))
        self.assertNotIn("not allowlisted", log)
        self.assertEqual(len(dialled), 1)

    def test_hosts_does_not_union_into_policy_on_a_live_request(self):
        """The composition rule, driven rather than asserted about a matcher.

        `*.example` is in .hosts for an unrelated reason. Under the union
        reading it contributes "any method, any path" to a.example and the
        path restriction is gone -- with a 200 rather than a 403 and nothing
        anywhere saying a rule stopped applying.
        """
        log, sent, dialled = self._run(
            [], self._get("/admin"), (_OK,),
            policy=self._policy(["*.example"],
                                ("a.example", ("GET",), ("/v2/*",))))
        self.assertIn("not permitted by policy", log)
        self.assertIn(b"403", sent)
        self.assertEqual(dialled, [])

    def test_a_host_no_entry_matches_falls_back_to_hosts_with_no_rules(self):
        log, _, dialled = self._run(
            [], self._get("/anything", host="b.example"), (_OK,),
            policy=self._policy(["b.example"],
                                ("a.example", ("GET",), ("/v2/*",))))
        self.assertIn("forward", log)
        self.assertEqual(len(dialled), 1)

    def test_paths_matches_the_path_alone_and_not_the_query(self):
        """Both readings are defensible and silence picks the worse one:
        matching the full target denies `/v1/messages?stream=true` for a reason
        the operator cannot see anywhere in their config."""
        log, _, dialled = self._run(
            [], self._get("/v1/messages?stream=true", method="POST"), (_OK,),
            policy=self._policy(
                [], ("a.example", ("POST",), ("/v1/messages",))))
        self.assertIn("forward", log)
        self.assertEqual(len(dialled), 1)

    def test_the_path_matched_is_the_NORMALISED_one(self):
        """Rung 3 landed normalisation ahead of the matcher precisely for this:
        `/v2/../admin` matches `/v2/*` as written and resolves at the origin to
        `/admin`."""
        log, sent, dialled = self._run(
            [], self._get("/v2/../admin"),
            policy=self._policy([], ("a.example", ("GET",), ("/v2/*",))))
        self.assertIn("not permitted by policy", log)
        self.assertIn(b"403", sent)
        self.assertEqual(dialled, [])

    def test_an_entry_with_neither_key_permits_anything_on_its_host(self):
        """The single-entry shorthand, which still enforces Host binding and
        the allowlist and nothing else."""
        log, _, dialled = self._run(
            [], self._get("/anything", method="DELETE"), (_OK,),
            policy=self._policy([], ("a.example", None, None)))
        self.assertIn("forward", log)
        self.assertEqual(len(dialled), 1)

    def test_entries_union_across_a_repeated_host(self):
        policy = self._policy(
            [], ("a.example", ("POST",), ("/v1/messages",)),
            ("a.example", ("GET",), ("/v1/models", "/v1/models/*")))
        for method, target in (("POST", "/v1/messages"),
                               ("GET", "/v1/models/x")):
            log, _, dialled = self._run(
                [], self._get(target, method=method), (_OK,), policy=policy)
            self.assertIn("forward", log, (method, target))
        log, _, dialled = self._run(
            [], self._get("/v1/models", method="POST"), policy=policy)
        self.assertIn("not permitted by policy", log)
        self.assertEqual(dialled, [])

    def test_the_refusal_is_counted_under_its_own_reason(self):
        mod = _mod()
        out = io.StringIO()
        listener = mod.Listener(
            [], out, policy=self._policy(
                [], ("a.example", ("GET",), ("/v2/*",))))
        listener.counters.record_drop(mod.DROP_NOT_PERMITTED, "a.example")
        snap = listener.counters.snapshot(open_now=0, refused=0)
        self.assertEqual(snap["drop_reasons"][mod.DROP_NOT_PERMITTED], 1)
        self.assertNotIn(mod.DROP_UNCLASSIFIED, snap.get("drop_reasons", {}))


class TestCleartextAuthorisation(unittest.TestCase):
    """The name that authorises, and the answer a refusal gets.

    Unlike 443 a denial is speakable here -- there is no session for the guest
    to be inside -- so a refused request gets a real 403 naming the host rather
    than a connection that closed for reasons it cannot see.
    """

    _run = _CleartextRig._run
    _pair = _CleartextRig._pair

    def test_an_allowlisted_host_is_relayed_to_an_upstream_dialled_by_name(self):
        log, got, ups = self._run(["a.example"],
                                  b"GET /p HTTP/1.1\r\nHost: a.example\r\n\r\n",
                                  [_OK])
        self.assertEqual([addr for addr, _ in ups], [("a.example", 80)])
        self.assertIn(b"GET /p HTTP/1.1", ups[0][1])
        self.assertIn(b"HTTP/1.1 200 OK", got)
        self.assertIn("forward", log)

    def test_an_unlisted_host_gets_a_403_naming_it_and_no_upstream(self):
        log, got, ups = self._run(
            ["a.example"], b"GET / HTTP/1.1\r\nHost: denied.example\r\n\r\n")
        self.assertEqual(ups, [])
        self.assertIn(b"HTTP/1.1 403 Forbidden", got)
        self.assertIn(b"denied.example", got)
        self.assertIn("host=denied.example reason='not allowlisted'", log)

    def test_the_matcher_is_the_one_the_tls_plane_uses(self):
        """One matcher, not two. The apex trap has to be preserved here for
        the same reason it is preserved there: `*.example.com` does not
        authorise `example.com`, that is what the retired proxy did with the same list
        today, and a plane that widened it would grant every existing config a
        destination its operator did not write down."""
        _, got, ups = self._run(
            ["*.example.com"], b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        self.assertEqual(ups, [])
        self.assertIn(b"403", got)
        _, _, ups = self._run(
            ["*.example.com"],
            b"GET / HTTP/1.1\r\nHost: A.Example.Com.:80\r\n\r\n", [_OK])
        self.assertEqual([addr for addr, _ in ups], [("a.example.com", 80)])

    def test_an_absolute_form_target_does_not_reach_upstream_unnormalised(self):
        """Legal HTTP/1.1, and one line of guest input. It moves the
        authorising name out of the Host header -- which RFC 9110 then says to
        ignore -- so a plane that read Host and forwarded the target verbatim
        would authorise one host and fetch from another."""
        _, _, ups = self._run(
            ["a.example"],
            b"GET http://a.example/p?q=1 HTTP/1.1\r\nHost: evil.example\r\n\r\n",
            [_OK])
        self.assertEqual([addr for addr, _ in ups], [("a.example", 80)])
        sent = ups[0][1]
        self.assertIn(b"GET /p?q=1 HTTP/1.1\r\n", sent)
        self.assertNotIn(b"http://", sent)
        self.assertIn(b"Host: a.example\r\n", sent)
        self.assertNotIn(b"evil.example", sent)

    def test_the_absolute_form_authority_is_what_is_authorised(self):
        """The other direction of the same trap: a Host header naming an
        allowlisted host does not authorise an absolute-form target that names
        another one."""
        log, got, ups = self._run(
            ["a.example"],
            b"GET http://denied.example/ HTTP/1.1\r\nHost: a.example\r\n\r\n")
        self.assertEqual(ups, [])
        self.assertIn("host=denied.example", log)
        self.assertIn(b"403", got)

    def test_an_authority_naming_another_port_is_refused(self):
        """This plane is reached by a redirect keyed on `tcp dport 80` and it
        dials port 80. Ignoring the port would mean authorising and dialling
        one thing while telling the origin another, which is how a vhost
        decision gets made on a port nobody connected to."""
        log, _, ups = self._run(
            ["a.example"],
            b"GET / HTTP/1.1\r\nHost: a.example:8080\r\n\r\n")
        self.assertEqual(ups, [])
        self.assertIn("only ever reaches port 80", log)

    def test_the_port_is_dropped_from_the_host_we_emit(self):
        _, _, ups = self._run(
            ["a.example"], b"GET / HTTP/1.1\r\nHost: a.example:80\r\n\r\n",
            [_OK])
        self.assertIn(b"Host: a.example\r\n", ups[0][1])

    def test_the_guests_own_version_goes_upstream(self):
        """Speaking 1.1 upstream for a 1.0 guest invites a chunked response,
        and the response head is relayed verbatim -- so a client that has never
        heard of chunked would be handed a chunked body."""
        _, _, ups = self._run(
            ["a.example"],
            b"GET / HTTP/1.0\r\nHost: a.example\r\n\r\n",
            [b"HTTP/1.0 200 OK\r\n\r\nhi"])
        head = ups[0][1].split(b"\r\n\r\n", 1)[0]
        self.assertIn(b"GET / HTTP/1.0\r\n", head)
        self.assertIn(b"Connection: close", head)

    def test_a_request_with_no_authorising_name_is_not_a_policy_decision(self):
        """A name that could not be read and a name that was refused fail the
        request identically. An operator with one bucket for the two cannot
        tell a guest reaching for a host it may not have from a guest speaking
        something that is not HTTP at the HTTP port."""
        log, got, ups = self._run(["a.example"], b"GET / HTTP/1.1\r\n\r\n")
        self.assertEqual(ups, [])
        self.assertIn("unreadable request", log)
        self.assertNotIn("not allowlisted", log)
        self.assertIn(b"400 Bad Request", got)

    def test_connect_is_refused(self):
        """This listener is transparent: a guest that reaches it believes it
        is talking to an origin and has no proxy to tunnel through, so a
        CONNECT is a guest trying to make one out of it."""
        log, got, ups = self._run(
            ["a.example"], b"CONNECT a.example:443 HTTP/1.1\r\n"
                           b"Host: a.example:443\r\n\r\n")
        self.assertEqual(ups, [])
        self.assertIn("CONNECT", log)
        self.assertIn(b"400", got)


class TestCleartextFraming(unittest.TestCase):
    """Every case here is a request-smuggling class, and every one of them is
    REFUSED rather than resolved. Where two readings of a message are possible
    this plane declines the message: a relay that picks one guesses, the origin
    behind it guesses too, and a request smuggles through the gap.
    """

    _run = _CleartextRig._run
    _pair = _CleartextRig._pair

    def test_content_length_and_transfer_encoding_together_are_refused(self):
        log, got, ups = self._run(
            ["a.example"],
            b"POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\n"
            b"Transfer-Encoding: chunked\r\n\r\nhello")
        self.assertEqual(ups, [])
        self.assertIn("both Content-Length and Transfer-Encoding", log)
        self.assertIn(b"400", got)

    def test_two_content_length_headers_are_refused_even_when_they_agree(self):
        """Refused whether or not they agree: accepting the agreeing case
        makes the disagreeing one the path nothing exercises."""
        log, got, ups = self._run(
            ["a.example"],
            b"POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\n"
            b"Content-Length: 5\r\n\r\nhello")
        self.assertEqual(ups, [])
        self.assertIn("Content-Length headers", log)
        self.assertIn(b"400", got)

    def test_a_transfer_encoding_that_is_not_a_single_chunked_is_refused(self):
        log, _, ups = self._run(
            ["a.example"],
            b"POST / HTTP/1.1\r\nHost: a.example\r\n"
            b"Transfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n")
        self.assertEqual(ups, [])
        self.assertIn("is not a single 'chunked'", log)

    def test_an_obs_fold_continuation_line_is_refused(self):
        """A folded line lets a header hide inside another header's value,
        which is a disagreement between parsers about how many headers there
        are."""
        log, _, ups = self._run(
            ["a.example"],
            b"GET / HTTP/1.1\r\nHost: a.example\r\nX-Thing: one\r\n"
            b"\tContent-Length: 5\r\n\r\n")
        self.assertEqual(ups, [])
        self.assertIn("obs-fold", log)

    def test_a_bare_lf_in_a_header_value_never_reaches_upstream(self):
        """The head is framed on CRLF, so a lone LF inside a value survives the
        split and travels upstream inside the field it was written in. An
        origin that accepts bare-LF line endings -- many do -- reads it as the
        start of a line, which makes it a whole second request line smuggled
        past the authorisation of the one in front of it, wearing our own Host
        header."""
        log, got, ups = self._run(
            ["a.example"],
            b"GET / HTTP/1.1\r\nHost: a.example\r\n"
            b"X-T: v\nGET /admin HTTP/1.1\nHost: a.example\r\n\r\n")
        self.assertEqual(ups, [])
        self.assertIn("control character", log)
        self.assertIn(b"400", got)

    def test_a_bare_lf_in_the_request_target_never_reaches_upstream(self):
        log, _, ups = self._run(
            ["a.example"],
            b"GET /a\nX-Evil: 1 HTTP/1.1\r\nHost: a.example\r\n\r\n")
        self.assertEqual(ups, [])
        self.assertIn("control character", log)

    def test_a_nul_in_a_header_value_is_refused(self):
        log, _, ups = self._run(
            ["a.example"],
            b"GET / HTTP/1.1\r\nHost: a.example\r\nX-T: a\x00b\r\n\r\n")
        self.assertEqual(ups, [])
        self.assertIn("control character", log)

    def test_a_tab_inside_a_header_value_is_still_legal(self):
        """The control-character refusal must not take valid OWS with it: a
        HTAB inside a value is legal and a relay that refused it would reject
        ordinary traffic."""
        _, _, ups = self._run(
            ["a.example"],
            b"GET / HTTP/1.1\r\nHost: a.example\r\nX-T: a\tb\r\n\r\n",
            [_OK])
        self.assertEqual(len(ups), 1)

    def test_one_declared_chunk_does_not_set_this_processs_footprint(self):
        """The chunk size is a hex number the PEER writes. Reading a whole
        chunk before forwarding any of it lets one line of guest input decide
        how much memory this process holds -- beside the workloads, on their
        host. The bytes are relayed in bounded pieces instead."""
        mod = _mod()
        # Bigger than one RELAY_CHUNK, so the relay loop must iterate, and
        # small enough to fit the rig's socketpair -- the rig writes the whole
        # request before serving it, which is itself why a real large-body case
        # belongs to splice_rig and not here.
        body = b"A" * (mod.RELAY_CHUNK + 1000)
        # The assertion is about MEMORY, so it is made where memory is spent:
        # the largest single read. Asserting on the bytes that arrive cannot
        # tell a streamed chunk from a buffered one -- the same bytes arrive
        # either way, which is exactly why this property survives a test that
        # only reads the socket.
        reads = []
        original = mod._Stream.read_exactly

        def recording(self, n):
            reads.append(n)
            return original(self, n)

        with unittest.mock.patch.object(
                mod._Stream, "read_exactly", recording):
            _, _, ups = self._run(
                ["a.example"],
                b"POST / HTTP/1.1\r\nHost: a.example\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n",
                [_OK])
        sent = ups[0][1]
        self.assertIn(b"%x\r\n" % len(body), sent)
        self.assertIn(body, sent)
        self.assertLessEqual(max(reads), mod.RELAY_CHUNK,
                             "a chunk was read whole before any of it moved")

    def test_more_trailers_than_the_ceiling_is_refused(self):
        mod = _mod()
        trailers = b"".join(b"X-T%d: v\r\n" % i
                            for i in range(mod.MAX_TRAILER_LINES + 2))
        log, _, ups = self._run(
            ["a.example"],
            b"POST / HTTP/1.1\r\nHost: a.example\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n0\r\n" + trailers
            + b"\r\n", [_OK])
        self.assertIn("trailer lines", log)

    def test_the_framing_emitted_upstream_is_the_one_we_computed(self):
        """Not the guest's headers forwarded verbatim: two parsers cannot
        disagree about a length one of them wrote. The chunk extension is
        dropped for the same reason -- it is a field the guest writes after the
        head has been authorised."""
        _, _, ups = self._run(
            ["a.example"],
            b"POST / HTTP/1.1\r\nHost: a.example\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\n\r\n",
            [_OK])
        sent = ups[0][1]
        self.assertIn(b"Transfer-Encoding: chunked\r\n", sent)
        self.assertIn(b"5\r\nhello\r\n0\r\n\r\n", sent)
        self.assertNotIn(b"ext=1", sent)

    def test_the_guests_framing_headers_are_not_forwarded_alongside_ours(self):
        """The one that a "drop Host and forward the rest" relay passes every
        other test with. Emitting our computed framing is only half the rule --
        the guest's own framing headers have to be GONE, or the origin sees two
        of them and is back to choosing which one says where the body ends."""
        _, _, ups = self._run(
            ["a.example"],
            b"POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\n"
            b"Connection: keep-alive\r\nProxy-Connection: keep-alive\r\n"
            b"X-Thing: kept\r\n\r\nhello",
            [_OK])
        head = ups[0][1].split(b"\r\n\r\n", 1)[0].lower()
        self.assertEqual(head.count(b"content-length:"), 1)
        self.assertEqual(head.count(b"transfer-encoding:"), 0)
        self.assertEqual(head.count(b"connection:"), 1)
        self.assertEqual(head.count(b"proxy-connection:"), 0)
        self.assertIn(b"x-thing: kept", head)

    def test_a_chunked_request_carries_exactly_one_framing_header_upstream(self):
        _, _, ups = self._run(
            ["a.example"],
            b"POST / HTTP/1.1\r\nHost: a.example\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
            [_OK])
        head = ups[0][1].split(b"\r\n\r\n", 1)[0].lower()
        self.assertEqual(head.count(b"transfer-encoding:"), 1)
        self.assertEqual(head.count(b"content-length:"), 0)

    def test_a_head_response_body_is_not_waited_for(self):
        """A HEAD response carries a Content-Length describing a body it does
        not send. A relay that read the header before the status would block on
        bytes that are never coming -- which presents as a hung guest, not as a
        failure."""
        _, got, ups = self._run(
            ["a.example"],
            b"HEAD / HTTP/1.1\r\nHost: a.example\r\n\r\n"
            b"GET /second HTTP/1.1\r\nHost: a.example\r\n\r\n",
            [b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" + _OK])
        self.assertIn(b"GET /second", ups[0][1])
        self.assertIn(b"Content-Length: 100", got)


class TestCleartextPerRequest(unittest.TestCase):
    """One connection, many requests, each authorised on its own.

    A decision taken once at the front of a connection authorises everything
    behind the first name, and the framing that says where one request ends is
    written by the guest -- so these two properties are the unit.
    """

    _run = _CleartextRig._run
    _pair = _CleartextRig._pair

    def test_a_pipelined_second_host_gets_its_own_decision(self):
        log, got, ups = self._run(
            ["a.example"],
            b"GET /one HTTP/1.1\r\nHost: a.example\r\n\r\n"
            b"GET /two HTTP/1.1\r\nHost: denied.example\r\n\r\n",
            [_OK])
        self.assertEqual([addr for addr, _ in ups], [("a.example", 80)])
        self.assertNotIn(b"/two", ups[0][1])
        self.assertIn("forward", log)
        self.assertIn("host=denied.example reason='not allowlisted'", log)
        self.assertIn(b"200 OK", got)
        self.assertIn(b"403 Forbidden", got)

    def test_an_http_10_request_never_reuses_its_upstream(self):
        """rebuild_request tells the origin `Connection: close` for an
        HTTP/1.0 request -- deliberately, because speaking 1.1 upstream on a
        1.0 guest's behalf invites a chunked response the guest has never
        heard of. A socket we asked the origin to close must not then be
        handed to the next request.

        RFC 9112 §9.6 requires the origin to echo `close`, and when it does
        _relay_response ends the whole client connection. An origin that
        omits it -- 1.0 origins do -- used to leave the entry cached and dead,
        and the guest's next request for the same name died as `relay failed`
        instead of being redialled. Two dials for two requests is the whole
        assertion.
        """
        _, got, ups = self._run(
            ["a.example"],
            b"GET /one HTTP/1.0\r\nHost: a.example\r\n"
            b"Connection: keep-alive\r\n\r\n"
            b"GET /two HTTP/1.0\r\nHost: a.example\r\n"
            b"Connection: keep-alive\r\n\r\n",
            [_OK, _OK])
        self.assertEqual([addr for addr, _ in ups],
                         [("a.example", 80), ("a.example", 80)])
        self.assertIn(b"/one", ups[0][1])
        self.assertNotIn(b"/two", ups[0][1])
        self.assertIn(b"/two", ups[1][1])
        # And the guest got both answers -- the point of the redial.
        self.assertEqual(got.count(b"200 OK"), 2)

    def test_a_transient_upstream_is_in_no_map_for_the_sweep_to_find(self):
        """Why the exchange has to close it itself.

        _serve_cleartext's `finally` closes what is in `upstreams`, and a
        transient upstream is deliberately not in it -- so nothing else on any
        path out would close it, and a leaked host socket owned by the workload
        uid would live as long as the client connection. The closure sits in
        _serve_one_request's own finally; this pins the premise it rests on.
        """
        mod = _mod()
        listener = mod.Listener([], io.StringIO(),
                                policy=mod.Policy(tls="splice",
                                                  hosts=("a.example",)))
        near, far = self._pair()
        upstreams = {}
        with unittest.mock.patch.object(socket, "create_connection",
                                        return_value=near):
            up = listener._upstream_for("a.example", upstreams,
                                        reusable=False)
        self.assertIs(up.sock, near)
        self.assertEqual({}, upstreams)
        del far

    def test_an_http_11_request_still_reuses_one_upstream(self):
        """The other direction of the same change: 1.1 requests carry
        `Connection: keep-alive` upstream and must still share one socket, or
        the fix above has turned reuse off for everything."""
        _, _, ups = self._run(
            ["a.example"],
            b"GET /one HTTP/1.1\r\nHost: a.example\r\n\r\n"
            b"GET /two HTTP/1.1\r\nHost: a.example\r\n\r\n",
            [_OK, _OK])
        self.assertEqual([addr for addr, _ in ups], [("a.example", 80)])
        self.assertIn(b"/one", ups[0][1])
        self.assertIn(b"/two", ups[0][1])

    def test_two_allowed_hosts_get_two_upstreams(self):
        """Upstreams are keyed by the authorised NAME, never by the client
        connection: no request is ever sent down one an earlier request
        chose."""
        _, _, ups = self._run(
            ["*.example"],
            b"GET /one HTTP/1.1\r\nHost: a.example\r\n\r\n"
            b"GET /two HTTP/1.1\r\nHost: b.example\r\n\r\n",
            [_OK, _OK])
        self.assertEqual([addr for addr, _ in ups],
                         [("a.example", 80), ("b.example", 80)])
        self.assertIn(b"/one", ups[0][1])
        self.assertNotIn(b"/two", ups[0][1])
        self.assertIn(b"/two", ups[1][1])

    def test_a_second_host_is_never_sent_down_the_first_ones_upstream(self):
        """The bypass this keying exists to prevent: a connection reused
        across names sends a request the policy authorised for ONE host to a
        host it authorised for another."""
        _, _, ups = self._run(
            ["*.example"],
            b"GET /one HTTP/1.1\r\nHost: a.example\r\n\r\n"
            b"GET /two HTTP/1.1\r\nHost: b.example\r\n\r\n",
            [_OK, _OK])
        for (addr, sent) in ups:
            for line in sent.split(b"\r\n"):
                if line.lower().startswith(b"host:"):
                    self.assertEqual(
                        line.split(b" ", 1)[1].decode(), addr[0],
                        "a request reached an upstream dialled for another name")

    def test_the_same_host_twice_reuses_one_upstream(self):
        _, _, ups = self._run(
            ["a.example"],
            b"GET /one HTTP/1.1\r\nHost: a.example\r\n\r\n"
            b"GET /two HTTP/1.1\r\nHost: a.example\r\n\r\n",
            [_OK + _OK])
        self.assertEqual(len(ups), 1)
        self.assertIn(b"/one", ups[0][1])
        self.assertIn(b"/two", ups[0][1])

    def test_distinct_hosts_past_the_cap_evict_the_least_recently_used(self):
        """The upstream map is bounded, and a wildcard policy is why.

        `hosts = ["*.example"]` makes every distinct subdomain a name the
        guest may open a socket for, and the map outlives the request that
        opened it -- so without a ceiling a guest pipelines a1, a2, ... down
        one connection and opens sockets until the process is out of file
        descriptors, every one of them a host socket owned by the workload
        uid. Past the cap the oldest is closed; a name that comes back is
        redialled, which is a round trip rather than a refusal.
        """
        mod = _mod()
        request = b"".join(
            b"GET /%s HTTP/1.1\r\nHost: %s.example\r\n\r\n" % (h, h)
            for h in (b"a", b"b", b"c", b"a"))
        with unittest.mock.patch.object(mod, "UPSTREAMS_MAX", 2):
            _, got, ups = self._run(["*.example"], request, [_OK] * 4)
        # Four dials for four requests: a was evicted when c arrived, so the
        # second a.example is a fresh socket rather than the first one reused.
        self.assertEqual([addr for addr, _ in ups],
                         [("a.example", 80), ("b.example", 80),
                          ("c.example", 80), ("a.example", 80)])
        self.assertIn(b"/a ", ups[0][1])
        self.assertNotIn(b"/a ", ups[1][1])
        self.assertIn(b"/a ", ups[3][1])
        self.assertEqual(got.count(b"200 OK"), 4,
                         "eviction must cost a redial, never a request")

    def test_a_host_still_within_the_cap_is_reused_not_redialled(self):
        """The eviction is least-recently-USED, not least-recently-opened: a
        name the guest keeps returning to stays young and stays open."""
        mod = _mod()
        request = b"".join(
            b"GET /%s HTTP/1.1\r\nHost: %s.example\r\n\r\n" % (h, h)
            for h in (b"a", b"b", b"a", b"c", b"a"))
        with unittest.mock.patch.object(mod, "UPSTREAMS_MAX", 2):
            _, got, ups = self._run(
                ["*.example"], request, [_OK + _OK + _OK, _OK, _OK])
        # a is touched before every eviction, so it is never the oldest: three
        # dials for three names, and b is the one that goes.
        self.assertEqual([addr for addr, _ in ups],
                         [("a.example", 80), ("b.example", 80),
                          ("c.example", 80)])
        self.assertEqual(got.count(b"200 OK"), 5)

    def test_the_cap_is_generous_enough_for_an_honest_connection(self):
        """A bound low enough to evict a real client's working set would trade
        a fd leak for a redial on every request."""
        self.assertGreaterEqual(_mod().UPSTREAMS_MAX, 4)

    def test_a_403_does_not_leave_the_next_request_read_out_of_the_body(self):
        """The bypass through the error path, which is the path every test
        exercises least. A refusal answered without draining leaves the reader
        positioned inside the refused request's body -- so the guest writes its
        next request THERE, and it is read as a request rather than as data."""
        smuggled = b"GET /smuggled HTTP/1.1\r\nHost: a.example\r\n\r\n"
        request = (b"POST / HTTP/1.1\r\nHost: denied.example\r\n"
                   b"Content-Length: %d\r\n\r\n" % len(smuggled)) + smuggled
        request += b"GET /real HTTP/1.1\r\nHost: a.example\r\n\r\n"
        log, got, ups = self._run(["a.example"], request, [_OK])
        self.assertEqual(len(ups), 1)
        self.assertIn(b"GET /real", ups[0][1])
        self.assertNotIn(b"/smuggled", ups[0][1])
        self.assertIn(b"403 Forbidden", got)
        self.assertIn(b"200 OK", got)

    def test_a_body_over_the_drain_ceiling_closes_the_connection_instead(self):
        """Draining is a service to the connection, not an obligation: a guest
        that answers a refusal with more than the ceiling gets the connection
        closed rather than the courtesy of having it all read."""
        mod = _mod()
        _, got, ups = self._run(
            ["a.example"],
            b"POST / HTTP/1.1\r\nHost: denied.example\r\nContent-Length: %d\r\n"
            b"\r\n" % (mod.DRAIN_MAX + 1))
        self.assertEqual(ups, [])
        self.assertIn(b"403 Forbidden", got)
        self.assertIn(b"Connection: close", got)


class TestCleartextTimeouts(unittest.TestCase):
    """Which of the two numbers bounds which wait, on the plane that has three.

    The TLS plane has two waits and moves once. The cleartext plane authorises
    per REQUEST, so it has three: the wait for a head (a decision), the transfer
    once a request is authorised (a relay), and the wait for the NEXT head on a
    kept-alive connection (an idle). Giving the third the decision number is
    the mistake this class exists to hold shut: it cuts keep-alive at five
    seconds AND counts each cut as `unreadable request`, which is the bucket
    that is supposed to mean a guest speaking something that is not HTTP.
    """

    CONNECTION = 0.20
    IDLE = 0.75

    def _pair(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        a.settimeout(3.0)
        b.settimeout(3.0)
        return a, b

    def _serve(self, hosts, feed, responses=(), watch=None):
        """Serve a guest that does NOT close its end.

        `feed` is written to the guest side before serving and nothing more is
        ever written, so every case here ends on a timeout rather than on EOF.
        Returns (log, counters snapshot, elapsed seconds).
        """
        mod = _mod()
        out = io.StringIO()
        listener = mod.Listener(
            [], out, policy=mod.Policy(tls="splice", hosts=tuple(hosts)))
        ours, guest = self._pair()
        guest.sendall(feed)
        pumps = []

        def dial(addr, timeout=None):
            near, far = self._pair()
            if len(pumps) < len(responses):
                far.sendall(responses[len(pumps)])
            buf = bytearray()
            pump = threading.Thread(target=_pump, args=(far, buf), daemon=True)
            pump.start()
            pumps.append(pump)
            return near

        real_copy_body = mod.copy_body

        def copy_body(src, dst, framing):
            if watch is not None:
                watch.append(ours.gettimeout())
            return real_copy_body(src, dst, framing)

        started = time.monotonic()
        with unittest.mock.patch.object(
                socket, "create_connection", side_effect=dial), \
                unittest.mock.patch.object(mod, "copy_body", copy_body), \
                unittest.mock.patch.object(
                    mod, "CONNECTION_TIMEOUT", self.CONNECTION), \
                unittest.mock.patch.object(
                    mod, "RELAY_IDLE_TIMEOUT", self.IDLE):
            listener._serve_cleartext(ours, "plane=cleartext")
        elapsed = time.monotonic() - started
        for pump in pumps:
            pump.join(timeout=3.0)
        return (out.getvalue(),
                listener.counters.snapshot(open_now=0, refused=0), elapsed)

    def _drops(self, snapshot):
        return {k: v for k, v in snapshot["drop_reasons"].items() if v}

    def test_a_guest_that_says_nothing_is_cut_at_the_decision_timeout(self):
        """The first wait is the decision's: a connection that has been
        accepted and says nothing is holding one of MAX_CONNECTIONS slots for
        nothing."""
        log, snap, elapsed = self._serve(["a.example"], b"")
        self.assertLess(elapsed, self.IDLE)
        self.assertEqual(self._drops(snap), {"timed out": 1})
        self.assertIn("timed out", log)

    def test_a_stalled_head_is_a_timeout_not_an_unreadable_request(self):
        """Bytes arrived and stopped. That is a peer that gave up mid-message,
        not a peer speaking a protocol we could not read -- and the two have to
        stay apart, because one of them is the tunnelling signal."""
        log, snap, elapsed = self._serve(
            ["a.example"], b"GET / HTTP/1.1\r\nHost: a.exa")
        self.assertLess(elapsed, self.IDLE)
        self.assertEqual(self._drops(snap), {"timed out": 1})
        self.assertNotIn("unreadable request", log)

    def test_an_idle_kept_alive_connection_is_not_counted_as_a_drop(self):
        """The regression this class is named for. One authorised request, an
        answer, and then a guest that simply holds the connection: the close is
        this end letting go of something nobody was using, not a request that
        could not be read."""
        log, snap, elapsed = self._serve(
            ["a.example"], b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
            responses=[_OK])
        self.assertEqual(self._drops(snap), {})
        self.assertEqual(snap["dispositions"]["forwarded"], 1)
        self.assertIn("close plane=cleartext", log)

    def test_the_idle_wait_is_the_tunnel_number_not_the_decision_one(self):
        """Measured, because the count above would also be satisfied by a
        connection cut at five seconds and merely counted differently."""
        _, _, elapsed = self._serve(
            ["a.example"], b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
            responses=[_OK])
        self.assertGreater(elapsed, self.CONNECTION * 2)

    def test_an_authorised_request_relays_under_the_idle_timeout(self):
        """The socket leaves the decision timeout when the decision is made.
        Held here rather than inferred from a slow transfer: the failure is a
        large download cut at five seconds by whichever end paused first, and
        a test that reproduced that would be a test that waits for it."""
        watch = []
        self._serve(["a.example"],
                    b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
                    responses=[_OK], watch=watch)
        # Twice: the request body going up and the response body coming
        # back are both transfers, and both are bounded by idleness.
        self.assertEqual(len(watch), 2)
        self.assertEqual(set(watch), {self.IDLE})

    def test_the_decision_timeout_is_restored_for_the_next_head(self):
        """A relayed request must not leave the tunnel number behind for the
        head that follows it: a guest that starts a second head and abandons it
        would then hold its slot for the idle bound."""
        log, snap, elapsed = self._serve(
            ["a.example"],
            b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"
            b"GET /two HTTP/1.1\r\nHost: a.exa",
            responses=[_OK])
        self.assertEqual(self._drops(snap), {"timed out": 1})
        self.assertLess(elapsed, self.IDLE)


class TestCleartextExpectContinue(unittest.TestCase):
    """`Expect: 100-continue` is answered AFTER policy, never before.

    The natural implementation answers it while reading the head, which grants
    a continue on a request that is about to be refused -- the guest then sends
    a body nobody will read, on a connection about to close.
    """

    _run = _CleartextRig._run
    _pair = _CleartextRig._pair

    def test_a_refused_request_is_never_told_to_continue(self):
        log, got, ups = self._run(
            ["a.example"],
            b"POST / HTTP/1.1\r\nHost: denied.example\r\nContent-Length: 5\r\n"
            b"Expect: 100-continue\r\n\r\n")
        self.assertEqual(ups, [])
        self.assertNotIn(b"100 Continue", got)
        self.assertIn(b"403 Forbidden", got)

    def test_a_refused_expect_closes_rather_than_pretending_to_drain(self):
        """The one refusal that cannot be drained: the guest is waiting for a
        continue policy has just decided not to give, so there is no body to
        read to the end of and the connection cannot be trusted to start the
        next request cleanly."""
        _, got, _ = self._run(
            ["a.example"],
            b"POST / HTTP/1.1\r\nHost: denied.example\r\nContent-Length: 5\r\n"
            b"Expect: 100-continue\r\n\r\n")
        self.assertIn(b"Connection: close", got)

    def test_an_authorised_request_is_told_to_continue(self):
        """And the Expect is not forwarded: waiting for the origin's own
        interim answer would mean reading the response before the body had been
        sent, and the two waits deadlock."""
        _, got, ups = self._run(
            ["a.example"],
            b"POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\n"
            b"Expect: 100-continue\r\n\r\nhello",
            [_OK])
        self.assertIn(b"100 Continue", got)
        self.assertIn(b"hello", ups[0][1])
        self.assertNotIn(b"Expect", ups[0][1])

    def test_an_expectation_we_cannot_honour_is_refused(self):
        log, got, ups = self._run(
            ["a.example"],
            b"POST / HTTP/1.1\r\nHost: a.example\r\nExpect: other\r\n\r\n")
        self.assertEqual(ups, [])
        self.assertIn("cannot honour", log)


class TestResponseHeadLeniency(unittest.TestCase):
    """The relay must not be stricter than the web it relays.

    The head coming BACK was written by an origin this workload's own policy
    authorised, and it is relayed to the guest verbatim; the only reason to
    parse it is to find where the body ends. Parsing it with the guest-hardening
    request parser made real, ordinary responses fail as `relay failed` -- a
    dead connection on a request the policy allowed, which reads to an operator
    as the inspector being broken.
    """

    _run = _CleartextRig._run
    _pair = _CleartextRig._pair

    def _relay(self, response):
        return self._run(
            ["a.example"],
            b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
            [response])

    def test_a_non_ascii_byte_in_a_header_is_relayed(self):
        """A filename with an accent in it, which is the everyday case: raw
        UTF-8 in Content-Disposition is emitted by real servers and is not a
        second encoding of anything."""
        head = ("HTTP/1.1 200 OK\r\n"
                "Content-Disposition: attachment; filename=\"caf\u00e9.pdf\"\r\n"
                "Content-Length: 2\r\n\r\n").encode("utf-8") + b"hi"
        log, got, _ = self._relay(head)
        self.assertNotIn("relay failed", log)
        self.assertIn(b"200 OK", got)
        self.assertIn("caf\u00e9.pdf".encode("utf-8"), got)
        self.assertTrue(got.endswith(b"hi"))

    def test_an_obs_fold_continuation_is_relayed_not_refused(self):
        """Deprecated, still emitted. It folds into the value it continues
        rather than aborting the exchange."""
        head = (b"HTTP/1.1 200 OK\r\n"
                b"X-Note: first\r\n\tsecond\r\n"
                b"Content-Length: 2\r\n\r\nhi")
        log, got, _ = self._relay(head)
        self.assertNotIn("relay failed", log)
        self.assertIn(b"200 OK", got)
        self.assertTrue(got.endswith(b"hi"))

    def test_a_header_name_outside_tchar_is_dropped_not_fatal(self):
        """No framing header has a name like that, and the line is relayed
        verbatim either way -- so it cannot change where the body ends."""
        head = (b"HTTP/1.1 200 OK\r\n"
                b"X Bad Name: whatever\r\n"
                b"Content-Length: 2\r\n\r\nhi")
        log, got, _ = self._relay(head)
        self.assertNotIn("relay failed", log)
        self.assertIn(b"X Bad Name: whatever", got)
        self.assertTrue(got.endswith(b"hi"))

    def test_the_framing_headers_are_still_read_strictly(self):
        """Leniency is about fields that do not frame the message. An origin
        that frames a response two ways at once is still refused: guessing
        which one it meant is how a relay loses track of where the body ends.
        """
        head = (b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 2\r\n"
                b"Transfer-Encoding: chunked\r\n\r\nhi")
        log, _, _ = self._relay(head)
        self.assertIn("relay failed", log)

    def test_a_bare_newline_in_the_head_is_still_refused(self):
        """The one defect leniency must not cover: a bare LF changes where a
        MESSAGE ends, not where a field does, and the head is relayed to the
        guest verbatim."""
        head = (b"HTTP/1.1 200 OK\r\n"
                b"X-Note: a\nX-Smuggled: b\r\n"
                b"Content-Length: 2\r\n\r\nhi")
        log, _, _ = self._relay(head)
        self.assertIn("relay failed", log)


class TestInterimResponses(unittest.TestCase):
    """1xx heads are relayed, and they are counted.

    The loop that reads them is driven by the far end. Every other loop in this
    file that a guest or a peer can drive carries a ceiling, and an allowlisted
    origin is not a trusted one -- it can hold a guest's connection, and one of
    MAX_CONNECTIONS slots, with interim heads and no final answer.
    """

    _run = _CleartextRig._run
    _pair = _CleartextRig._pair

    def test_an_interim_response_is_passed_through_before_the_final_one(self):
        _, got, _ = self._run(
            ["a.example"], b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
            [b"HTTP/1.1 103 Early Hints\r\n\r\n" + _OK])
        self.assertIn(b"103 Early Hints", got)
        self.assertIn(b"200 OK", got)

    def test_an_endless_run_of_interim_heads_ends_the_exchange(self):
        mod = _mod()
        flood = b"HTTP/1.1 100 Continue\r\n\r\n" * (mod.INTERIM_MAX + 5)
        log, got, _ = self._run(
            ["a.example"], b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
            [flood])
        self.assertIn("relay failed", log)
        self.assertIn("interim", log)
        self.assertNotIn(b"200 OK", got)

    def test_a_run_within_the_ceiling_still_reaches_the_final_response(self):
        """The bound must not be what breaks an origin sending early hints."""
        mod = _mod()
        head = b"HTTP/1.1 103 Early Hints\r\n\r\n" * mod.INTERIM_MAX
        _, got, _ = self._run(
            ["a.example"], b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
            [head + _OK])
        self.assertIn(b"200 OK", got)


class TestCleartextUpstreamFailure(unittest.TestCase):
    """An unreachable upstream is its own reason, as it is on the TLS plane.

    Three outcomes, three reasons: a request that could not be read, a name on
    no list, and a host that could not be reached fail the guest identically,
    and an operator with one bucket for them cannot tell a policy decision from
    a broken resolver.
    """

    _pair = _CleartextRig._pair

    def test_an_unreachable_upstream_is_not_reported_as_a_policy_decision(self):
        mod = _mod()
        out = io.StringIO()
        listener = mod.Listener(
            [], out, policy=mod.Policy(tls="splice", hosts=("a.example",)))
        ours, guest = self._pair()
        guest.sendall(b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")
        guest.shutdown(socket.SHUT_WR)
        with unittest.mock.patch.object(
                socket, "create_connection",
                side_effect=OSError("Name or service not known")):
            listener._serve_cleartext(ours, "plane=cleartext")
        ours.close()
        log, got = out.getvalue(), _read_all(guest)
        self.assertIn("upstream unreachable", log)
        self.assertNotIn("not allowlisted", log)
        self.assertIn(b"502 Bad Gateway", got)


def _ech_extension(payload=b"\x00" * 8):
    """An encrypted_client_hello extension.

    Its contents are never read -- by the parser, which skips it by length, or
    by the tripwire, which keys on the type alone. A real client sends this
    same codepoint with deliberately fake contents (GREASE ECH) on ordinary
    connections, which is exactly why the capability count is not the alarm.
    """
    return (0xfe0d).to_bytes(2, "big") + len(payload).to_bytes(2, "big") + payload


class TestEchFixture(unittest.TestCase):
    """The captured handshake, pinned as a regression.

    Hand-built helloes prove the parser handles the shapes we thought of. This
    one is a real ECH ClientHello from a real client, and the property it pins
    is the one the whole tripwire rests on: an ECH hello parses like any other
    and yields the COVER name, so the extension is what is observable and the
    name never is.
    """

    FIXTURE = ROOT / "tests" / "fixtures" / "ech-clienthello.bin"

    def test_the_fixture_is_present(self):
        """Cited by the design; a missing fixture would make every assertion
        below vacuously skip rather than fail."""
        self.assertTrue(self.FIXTURE.exists())

    def test_it_parses_to_the_cover_name(self):
        mod = _mod()
        raw = self.FIXTURE.read_bytes()
        _, hello = mod.read_client_hello(_FakeSocket([raw]))
        self.assertEqual(hello.server_name, "cloudflare-ech.com")

    def test_it_carries_the_ech_extension(self):
        mod = _mod()
        _, hello = mod.read_client_hello(_FakeSocket([self.FIXTURE.read_bytes()]))
        self.assertIn(mod.TLS_EXT_ECH, hello.extensions)

    def test_the_parser_does_not_decrypt_or_special_case_it(self):
        """The ECH extension must be skipped by its length like every other.
        A parser that reached inside it would be a TLS implementation, which
        the peek must not become."""
        mod = _mod()
        _, hello = mod.read_client_hello(_FakeSocket([self.FIXTURE.read_bytes()]))
        # Every extension after the ECH one is still recovered, which is only
        # true if it was skipped correctly rather than terminating the walk.
        self.assertGreater(len(hello.extensions),
                           hello.extensions.index(mod.TLS_EXT_ECH) + 1)


class TestEchTripwire(unittest.TestCase):
    """Two numbers, and the reason they are two.

    Capability is dominated by GREASE and moves the moment an ECH-capable
    client is installed in the guest. The alarm is the pair -- extension
    present AND the name on no list. Counting only the first is how a tripwire
    ends up permanently lit and therefore ignored.
    """

    def _listener(self, hosts):
        mod = _mod()
        out = io.StringIO()
        return mod, mod.Listener(
            [], out, policy=mod.Policy(tls="splice", hosts=tuple(hosts))), out

    def _serve(self, listener, payload):
        guest, ours = socket.socketpair()
        self.addCleanup(guest.close)
        self.addCleanup(ours.close)
        guest.sendall(payload)
        ours.settimeout(2.0)
        listener._serve_tls(ours, "plane=tls")

    def test_an_allowlisted_ech_hello_moves_capability_and_not_the_alarm(self):
        """THE case the split exists for: an ordinary modern client reaching
        an allowed host. If this lit the alarm, the alarm would be lit on every
        healthy workload from the day a browser was installed."""
        mod, listener, _ = self._listener(["allowed.example"])
        self._serve(listener, _hello_bytes(
            _ech_extension(), server_name="allowed.example"))
        self.assertEqual(listener.counters.ech_seen, 1)
        self.assertEqual(listener.counters.ech_alarm, 0)

    def test_an_unlisted_ech_hello_moves_both(self):
        mod, listener, _ = self._listener(["allowed.example"])
        self._serve(listener, _hello_bytes(
            _ech_extension(), server_name="denied.example"))
        self.assertEqual(listener.counters.ech_seen, 1)
        self.assertEqual(listener.counters.ech_alarm, 1)

    def test_an_ech_hello_with_no_sni_counts_toward_the_alarm(self):
        """The stronger form of the signal, not a weaker one: the extension
        was there and the name matched nothing at all."""
        _, listener, _ = self._listener(["allowed.example"])
        self._serve(listener, _hello_bytes(_ech_extension(), server_name=None))
        self.assertEqual(listener.counters.ech_seen, 1)
        self.assertEqual(listener.counters.ech_alarm, 1)

    def test_a_hello_without_the_extension_moves_neither(self):
        """Including one that is refused. The tripwire is about ECH, not about
        denial, and a figure that moved on every policy miss would measure the
        allowlist rather than the guest's TLS stack."""
        _, listener, _ = self._listener(["allowed.example"])
        self._serve(listener, _hello_bytes(server_name="denied.example"))
        self.assertEqual(listener.counters.ech_seen, 0)
        self.assertEqual(listener.counters.ech_alarm, 0)

    def test_ordinary_grease_extensions_do_not_count_as_ech(self):
        """RFC 8701 GREASE on other codepoints is not ECH. Counting it would
        make capability meaningless."""
        _, listener, _ = self._listener(["allowed.example"])
        self._serve(listener, _hello_bytes(
            _grease_extension() + _grease_extension(0x1a1a),
            server_name="allowed.example"))
        self.assertEqual(listener.counters.ech_seen, 0)

    def test_an_unreadable_hello_moves_no_ech_figure(self):
        """The extension list comes from the parse. Bytes that did not parse
        have no extensions to have been seen, and guessing would put junk in
        the capability count and make the alarm's denominator a fiction."""
        _, listener, _ = self._listener(["allowed.example"])
        self._serve(listener, b"GET / HTTP/1.1\r\n\r\n")
        self.assertEqual(listener.counters.ech_seen, 0)
        self.assertEqual(listener.counters.ech_alarm, 0)

    def test_the_fixture_lights_the_alarm_when_its_name_is_unlisted(self):
        """End to end on the real capture rather than a hand-built hello."""
        _, listener, _ = self._listener(["allowed.example"])
        raw = (ROOT / "tests" / "fixtures" / "ech-clienthello.bin").read_bytes()
        self._serve(listener, raw)
        self.assertEqual(listener.counters.ech_seen, 1)
        self.assertEqual(listener.counters.ech_alarm, 1)


class TestCounters(unittest.TestCase):
    """The rung's figures, emitted rather than rendered."""

    def _listener(self, hosts=("allowed.example",), internal=(), splice=(),
                  http2=(), policy=()):
        mod = _mod()
        out = io.StringIO()
        return mod, mod.Listener([], out, policy=mod.Policy(
            tls="splice", hosts=tuple(hosts),
            internal=tuple(internal), splice=tuple(splice),
            http2=tuple(http2),
            policy=tuple(mod.VmPolicyEntry(host=h, methods=m, paths=p)
                         for h, m, p in policy))), out

    def test_every_drop_reason_is_present_before_anything_happens(self):
        """A reason absent from the file and a reason reading zero are the
        same fact and must look the same, or an operator reads a missing key
        as 'not measured' and goes looking for a bug that is not there."""
        _, listener, _ = self._listener()
        reasons = listener.status()["drop_reasons"]
        self.assertIn("not allowlisted", reasons)
        self.assertIn("no readable name", reasons)
        self.assertIn("internal destination", reasons)
        self.assertTrue(all(v == 0 for v in reasons.values()))

    def test_the_dispositions_add_up_to_the_drops(self):
        """A total that did not include the ceiling's rejections would not
        account for every connection the guest saw closed."""
        _, listener, _ = self._listener()
        c = listener.counters
        c.record_drop("not allowlisted", "a.example")
        c.record_drop("no readable name")
        c.record_drop("connection ceiling reached")
        snap = listener.status()
        self.assertEqual(snap["dispositions"]["dropped"], 3)
        self.assertEqual(sum(snap["drop_reasons"].values()), 3)

    def test_a_drop_reason_the_counters_do_not_know_still_counts_as_a_drop(self):
        """The disposition is the figure that must never undercount; a reason
        added to the log and not to this map degrades to unattributed rather
        than to invisible."""
        _, listener, _ = self._listener()
        listener.counters.record_drop("something new")
        self.assertEqual(listener.status()["dispositions"]["dropped"], 1)

    def test_an_unknown_reason_still_reconciles_the_two_maps(self):
        """`dropped` and the sum of `drop_reasons` must agree unconditionally.
        An unattributed drop that vanished from the reason map would leave an
        operator reconciling the two against a number that lost rows, with
        nothing in the file to say a row had been lost."""
        _, listener, _ = self._listener()
        listener.counters.record_drop("not allowlisted", "a.example")
        listener.counters.record_drop("something new")
        snap = listener.status()
        self.assertEqual(snap["drop_reasons"]["(unclassified)"], 1)
        self.assertEqual(sum(snap["drop_reasons"].values()),
                         snap["dispositions"]["dropped"])

    def test_the_unclassified_bucket_is_absent_rather_than_zero(self):
        """It reads zero on every correct build, and a line that always reads
        zero is a line an operator learns to skip -- which is the line that
        matters on the one build where it does not. Same argument as (other)."""
        _, listener, _ = self._listener()
        listener.counters.record_drop("not allowlisted", "a.example")
        self.assertNotIn("(unclassified)",
                         listener.status()["drop_reasons"])

    def test_no_call_site_passes_a_drop_reason_as_a_literal(self):
        """The guard on the bucket above. `record_drop` cannot reject a reason
        it does not know -- it must count the drop either way -- so the only
        thing keeping a new reason in step with the pre-seed is that every call
        site names a constant, and every constant is in DROP_REASONS."""
        import re
        mod = _mod()
        source = LISTENER_FILE.read_text()
        calls = re.findall(r"record_drop\(\s*([^,)]+)", source)
        self.assertGreater(len(calls), 5)
        for arg in calls:
            arg = arg.strip()
            if arg in ("self", "reason", "reason: str"):
                continue          # the definition and the docstring's own text
            self.assertFalse(arg.startswith(('"', "'")),
                             f"record_drop called with the literal {arg}")
            self.assertIn(getattr(mod, arg), mod.DROP_REASONS)

    def test_the_pre_seed_is_exactly_the_named_reasons(self):
        _, listener, _ = self._listener()
        mod = _mod()
        self.assertEqual(set(listener.status()["drop_reasons"]),
                         set(mod.DROP_REASONS))

    def test_the_reasons_and_the_call_sites_are_the_same_set(self):
        """Drift is possible in both directions and neither is visible at
        runtime. A call site naming a reason the tuple lacks lands in
        (unclassified); a tuple entry no call site uses reads zero forever and
        is indistinguishable from a refusal that never happened to fire."""
        import re
        mod = _mod()
        # The tuple's own definition is removed before scanning, or every entry
        # in it would count as its own use and the guard would assert nothing.
        source = re.sub(r"DROP_REASONS = \([^)]*\)", "",
                        LISTENER_FILE.read_text())
        named = {arg.strip() for arg in
                 re.findall(r"record_drop\(\s*([^,)]+)", source)
                 if arg.strip().startswith("DROP_")}
        named |= set(re.findall(r"return (DROP_\w+)", source))
        # A reason chosen well before the call site that spends it -- the
        # terminated plane decides a refusal, then delivers it through a
        # completed handshake -- reaches record_drop through a variable, so the
        # tuple it was built into is where its name actually appears.
        named |= set(re.findall(r"\(\s*(DROP_\w+),", source))
        self.assertEqual({getattr(mod, n) for n in named},
                         set(mod.DROP_REASONS))

    def test_the_lists_loaded_at_start_are_reported(self):
        """`drift` cannot see them, so this is the only place the question
        'what is this process actually enforcing' has an answer."""
        _, listener, _ = self._listener(hosts=["a.example", "b.example"],
                                        internal=["nas.internal"])
        lists = listener.status()["lists"]
        self.assertEqual(lists["hosts"], ["a.example", "b.example"])
        self.assertEqual(lists["internal"], ["nas.internal"])
        self.assertEqual(lists["tls"], "splice")

    def test_every_list_that_decides_something_is_reported(self):
        """Three of these decide on their own -- `splice` exempts a host from
        termination, `http2` changes what is offered on both legs, `policy`
        decides individual requests. Reporting `hosts` and `internal` alone
        answers 'what is this process enforcing' with a subset, in the one
        file whose purpose is that the answer is not a guess."""
        _, listener, _ = self._listener(
            splice=("pinned.example",), http2=("grpc.example",),
            policy=(("api.example", ("GET",), ("/v1/*",)),))
        lists = listener.status()["lists"]
        self.assertEqual(lists["splice"], ["pinned.example"])
        self.assertEqual(lists["http2"], ["grpc.example"])
        self.assertEqual(lists["policy"],
                         [{"host": "api.example", "methods": ["GET"],
                           "paths": ["/v1/*"]}])

    def test_the_reported_policy_carries_the_rules_and_not_just_the_names(self):
        """Which hosts are governed is half the question; what they are
        governed BY is the half an operator reads this file for. An absent key
        stays null, because null and [] are different answers here too."""
        _, listener, _ = self._listener(
            policy=(("api.example", None, ("/v1/*",)),))
        entry, = listener.status()["lists"]["policy"]
        self.assertIsNone(entry["methods"])
        self.assertEqual(entry["paths"], ["/v1/*"])

    def test_the_lists_key_names_every_list_the_policy_holds(self):
        """The drift guard for the three above: a list added to Policy and not
        to `lists` is reported by nothing, and every existing assertion here
        still passes.

        Derived from which fields HOLD a list rather than from Policy._fields
        whole, so that a future scalar on Policy -- a timeout, a limit -- is
        not dragged into a key that says `lists` on the tin. `tls` is named
        separately for that reason: it is the mode the lists are read under,
        which an operator needs beside them, and it is the one key here with no
        list behind it.
        """
        mod, listener, _ = self._listener()
        policy = listener._policy
        lists = {f for f in mod.Policy._fields
                 if isinstance(getattr(policy, f), tuple)}
        self.assertIn("policy", lists)      # the derivation found something
        self.assertEqual(set(listener.status()["lists"]), lists | {"tls"})

    def test_concurrency_reports_live_and_refused_together(self):
        """One number cannot separate a guest storming the listener from a
        ceiling set too low for a real workload."""
        _, listener, _ = self._listener()
        conc = listener.status()["concurrency"]
        self.assertIn("open", conc)
        self.assertIn("refused", conc)

    def test_the_per_host_map_is_bounded(self):
        """The keys are guest-chosen. Unbounded here is a cardinality
        explosion on the HOST, through the exporter."""
        _, listener, _ = self._listener()
        for i in range(200):
            listener.counters.record_drop("internal destination", f"h{i}.example")
        snap = listener.status()
        self.assertLessEqual(len(snap["internal_refusals"]), 21)
        self.assertEqual(snap["internal_refusals_total"], 200)

    def test_a_splice_is_counted_as_a_splice(self):
        _, listener, _ = self._listener()
        listener.counters.record_splice()
        self.assertEqual(listener.status()["dispositions"]["spliced"], 1)

    def test_every_per_host_reason_has_its_own_map(self):
        """Rung 3 T8. Each of these is a refusal an operator acts on by NAME --
        an entry to add, a root to install, a workload to splice -- so the
        figure has to say which host, not only how many."""
        mod, listener, _ = self._listener()
        for reason in mod.PER_HOST_REASONS:
            listener.counters.record_drop(reason, "named.example")
        per_host = listener.status()["per_host"]
        self.assertEqual(sorted(per_host), sorted(mod.PER_HOST_REASONS))
        for reason in mod.PER_HOST_REASONS:
            self.assertEqual(per_host[reason], {"named.example": 1}, reason)

    def test_the_reasons_an_operator_acts_on_by_name_are_the_ones_split(self):
        """`not allowlisted` deliberately gets NO per-host map: the guest picks
        those names, there is no bound on how many it invents, and the answer is
        the allowlist itself rather than a list to read."""
        mod, listener, _ = self._listener()
        self.assertNotIn(mod.DROP_NOT_ALLOWLISTED, mod.PER_HOST_REASONS)
        self.assertNotIn(mod.DROP_MISDIRECTED, mod.PER_HOST_REASONS)
        listener.counters.record_drop(mod.DROP_NOT_ALLOWLISTED, "a.example")
        self.assertNotIn(mod.DROP_NOT_ALLOWLISTED,
                         listener.status()["per_host"])

    def test_the_allowlisted_half_of_the_binding_rejection_is_named(self):
        """Rung 4 T7. The key space is this workload's own file, so unlike the
        un-allowlisted half there is no unbounded set of guest-chosen names --
        and WHICH pair of names a client is coalescing is the whole question."""
        mod, listener, _ = self._listener()
        self.assertIn(mod.DROP_MISDIRECTED_LISTED, mod.PER_HOST_REASONS)
        listener.counters.record_drop(mod.DROP_MISDIRECTED_LISTED,
                                      "other.example")
        self.assertEqual(
            listener.status()["per_host"][mod.DROP_MISDIRECTED_LISTED],
            {"other.example": 1})

    def test_the_two_binding_rejections_are_two_figures(self):
        """Rung 4 T7. A non-zero binding count is either an attack or a broken
        assumption in §4, and one bucket cannot say which. Both are counted,
        both under their own reason, and neither lands on a policy figure."""
        mod, listener, _ = self._listener()
        listener.counters.record_drop(mod.DROP_MISDIRECTED, "evil.example")
        listener.counters.record_drop(mod.DROP_MISDIRECTED_LISTED,
                                      "other.example")
        reasons = listener.status()["drop_reasons"]
        self.assertEqual(reasons[mod.DROP_MISDIRECTED], 1)
        self.assertEqual(reasons[mod.DROP_MISDIRECTED_LISTED], 1)
        self.assertEqual(reasons[mod.DROP_NOT_ALLOWLISTED], 0)
        self.assertEqual(reasons[mod.DROP_NOT_PERMITTED], 0)

    def test_both_binding_reasons_are_found_by_one_grep(self):
        """The `not HTTP` convention one tier earlier: an operator who greps
        the reason out of the log must not lose the half they did not think
        to look for."""
        mod, _, _ = self._listener()
        self.assertTrue(
            mod.DROP_MISDIRECTED_LISTED.startswith(mod.DROP_MISDIRECTED),
            "the split reason must carry the original as its prefix")

    def test_the_splice_candidates_are_countable_per_host(self):
        """The two reasons whose remedy is `tls = "splice"` on the workload."""
        mod, listener, _ = self._listener()
        listener.counters.record_drop(mod.DROP_CLIENT_CERT, "mtls.example")
        listener.counters.record_drop(mod.DROP_NOT_HTTP, "pg.example")
        listener.counters.record_drop(mod.DROP_NOT_HTTP, "pg.example")
        per_host = listener.status()["per_host"]
        self.assertEqual(per_host[mod.DROP_CLIENT_CERT], {"mtls.example": 1})
        self.assertEqual(per_host[mod.DROP_NOT_HTTP], {"pg.example": 2})

    def test_the_totals_survive_the_bound_the_names_do_not(self):
        """A top-N can lose WHICH names; it must never lose HOW MANY."""
        mod, listener, _ = self._listener()
        for i in range(200):
            listener.counters.record_drop(mod.DROP_UNVERIFIED, f"h{i}.example")
        snap = listener.status()
        self.assertLessEqual(len(snap["per_host"][mod.DROP_UNVERIFIED]), 21)
        self.assertEqual(snap["per_host_totals"][mod.DROP_UNVERIFIED], 200)

    def test_a_drop_with_no_host_moves_only_the_reason(self):
        """Not every refusal knows a name -- a ceiling rejection has none --
        and inventing a key for it would be a host that never existed."""
        mod, listener, _ = self._listener()
        listener.counters.record_drop(mod.DROP_NOT_HTTP)
        snap = listener.status()
        self.assertEqual(snap["per_host"][mod.DROP_NOT_HTTP], {})
        self.assertEqual(snap["drop_reasons"][mod.DROP_NOT_HTTP], 1)


class TestInternalAttribution(unittest.TestCase):
    """Two failures arrive as one OSError, and telling them apart is the whole
    value of the internal-refusal figure.

    Nothing here decides anything: the kernel's wl_internal_ok4/6 elements are
    the one enforcement point. This only names what already happened.
    """

    def _listener(self, internal=()):
        mod = _mod()
        return mod, mod.Listener([], io.StringIO(), policy=mod.Policy(
            tls="splice", hosts=("host.example",), internal=tuple(internal)))

    def test_a_name_resolving_into_private_space_is_an_internal_refusal(self):
        mod, listener = self._listener()
        with unittest.mock.patch.object(
                mod.socket, "getaddrinfo",
                return_value=[(2, 1, 6, "", ("192.168.5.5", 443))]):
            self.assertEqual(listener._dial_failure_reason("host.example"),
                             "internal destination")

    def test_a_name_with_an_internal_entry_is_a_host_that_is_down(self):
        """It has the exemption the drop would otherwise have caught, so the
        failure is not the wildcard trap -- and reporting it as one sends an
        operator to edit a config line that is already correct."""
        mod, listener = self._listener(internal=["host.example"])
        with unittest.mock.patch.object(
                mod.socket, "getaddrinfo",
                return_value=[(2, 1, 6, "", ("192.168.5.5", 443))]):
            self.assertEqual(listener._dial_failure_reason("host.example"),
                             "upstream unreachable")

    def test_a_public_address_is_a_host_that_is_down(self):
        mod, listener = self._listener()
        with unittest.mock.patch.object(
                mod.socket, "getaddrinfo",
                return_value=[(2, 1, 6, "", ("93.184.216.34", 443))]):
            self.assertEqual(listener._dial_failure_reason("host.example"),
                             "upstream unreachable")

    def test_a_name_that_no_longer_resolves_degrades_to_the_generic_reason(self):
        """This runs on a path that has already failed. A counter is not worth
        raising a second exception over."""
        mod, listener = self._listener()
        with unittest.mock.patch.object(
                mod.socket, "getaddrinfo", side_effect=OSError("no such host")):
            self.assertEqual(listener._dial_failure_reason("host.example"),
                             "upstream unreachable")

    def test_the_internal_list_is_matched_on_the_normalised_name(self):
        """`Host.Example.` and `host.example` are the same name; a spelling
        that missed here would misattribute the counter."""
        mod, listener = self._listener(internal=["host.example"])
        with unittest.mock.patch.object(
                mod.socket, "getaddrinfo",
                return_value=[(2, 1, 6, "", ("10.0.0.9", 443))]):
            self.assertEqual(
                listener._dial_failure_reason(
                    mod.vm_normalise_hostname("Host.Example.")),
                "upstream unreachable")


class TestStatusFile(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.dir))
        self.path = os.path.join(self.dir, "inspect-status.json")

    def _listener(self, path):
        mod = _mod()
        return mod, mod.Listener(
            [], io.StringIO(), policy=mod.Policy(tls="splice", hosts=()),
            status_path=path)

    def test_it_writes_the_counters(self):
        _, listener = self._listener(self.path)
        listener.counters.record_splice()
        listener.write_status()
        doc = json.loads(Path(self.path).read_text())
        self.assertEqual(doc["dispositions"]["spliced"], 1)
        self.assertIn("written_at", doc)

    def test_no_path_means_count_but_never_write(self):
        """A figure that only accumulates when someone is watching is a figure
        nobody can trust."""
        _, listener = self._listener(None)
        listener.counters.record_splice()
        listener.write_status()
        self.assertEqual(listener.status()["dispositions"]["spliced"], 1)

    def test_an_unwritable_path_never_takes_the_listener_down(self):
        """This runs on the accept loop -- the thread whose death stops the
        guest reaching anything at all. A missing diagnostic is the lesser
        failure by a wide margin."""
        _, listener = self._listener(os.path.join(self.dir, "no", "such",
                                                  "status.json"))
        listener.write_status()   # must not raise

    def test_the_failure_is_logged_rather_than_swallowed_silently(self):
        mod = _mod()
        out = io.StringIO()
        listener = mod.Listener(
            [], out, policy=mod.Policy(tls="splice", hosts=()),
            status_path=os.path.join(self.dir, "no", "such", "status.json"))
        listener.write_status()
        self.assertIn("could not write", out.getvalue())

    def test_an_unserialisable_counter_never_takes_the_listener_down(self):
        """The wrapper promises it never raises, and the except clause has to
        be as wide as the promise. json.dump raises TypeError, not OSError, for
        a value it cannot encode -- so a counter added in a later rung that is
        not a plain int or str would, under a narrower clause, kill the accept
        loop and with it the guest's whole egress. It must cost the status file
        instead."""
        mod = _mod()
        out = io.StringIO()
        listener = mod.Listener(
            [], out, policy=mod.Policy(tls="splice", hosts=()),
            status_path=self.path)
        listener.status = lambda: {"a_later_rungs_counter": object()}
        listener.write_status()   # must not raise
        self.assertIn("could not write", out.getvalue())


class TestTargetNormalisation(unittest.TestCase):
    """Rung 3 T7. The table, and the encoded-separator cases it exists for.

    Nothing here changes a disposition -- there is no `paths` key until rung 4.
    What it fixes is the string: the one this listener acts on and the one the
    origin acts on have to be the same string BEFORE a matcher is written
    against either.
    """

    def norm(self, target):
        return _mod().normalise_path(target)

    def test_dot_segments_resolve(self):
        for target, expected in (
                ("/repos/myorg/../../secret", "/secret"),
                ("/a/./b", "/a/b"),
                ("/a/b/../c", "/a/c"),
                ("/a/b/..", "/a/"),
                ("/a/b/.", "/a/b/"),
                ("/../../etc/passwd", "/etc/passwd"),
                ("/..", "/"),
                ("/", "/"),
        ):
            self.assertEqual(self.norm(target), expected, target)

    def test_duplicate_slashes_collapse(self):
        self.assertEqual(self.norm("/a//b///c"), "/a/b/c")
        self.assertEqual(self.norm("//"), "/")

    def test_a_trailing_slash_is_kept_because_it_names_another_resource(self):
        self.assertEqual(self.norm("/a/"), "/a/")
        self.assertEqual(self.norm("/a"), "/a")

    def test_unreserved_encodings_decode(self):
        self.assertEqual(self.norm("/%61%62c"), "/abc")
        self.assertEqual(self.norm("/a%2Db%5Fc%7Ed"), "/a-b_c~d")

    def test_reserved_encodings_stay_encoded_in_uppercase(self):
        """`%3F` is not a `?` -- decoding it would move the query boundary --
        and one spelling per path is what keeps a matcher honest."""
        self.assertEqual(self.norm("/a%3fb"), "/a%3Fb")
        self.assertEqual(self.norm("/a%20b"), "/a%20b")
        self.assertEqual(self.norm("/%c3%a9"), "/%C3%A9")

    def test_an_encoded_dot_decodes_and_then_resolves(self):
        """The other end of the traversal case: the dots become dots before
        the resolution runs, so `%2e%2e` cannot slip past it."""
        self.assertEqual(self.norm("/a/%2e%2e/b"), "/b")
        self.assertEqual(self.norm("/a/%2E/b"), "/a/b")

    def test_an_encoded_slash_is_refused(self):
        """The case the whole unit turns on. Origins are split on whether
        `%2f` separates two segments, so neither reading is one this listener
        may pick on the guest's behalf."""
        mod = _mod()
        for target in ("/repos/myorg%2f..%2f..%2fsecret", "/a%2Fb",
                       "/a/%2e%2e%2fb"):
            with self.assertRaises(mod.RequestUnreadable, msg=target) as caught:
                self.norm(target)
            self.assertIn("encoded slash", str(caught.exception))

    def test_a_stray_percent_is_refused(self):
        mod = _mod()
        for target in ("/a%", "/a%zz", "/a%2"):
            with self.assertRaises(mod.RequestUnreadable, msg=target):
                self.norm(target)

    def test_the_query_is_carried_through_untouched(self):
        """`paths` will match the path alone. Matching the full target would
        deny `/v1/messages?stream=true` under `paths = ["/v1/messages"]` for a
        reason an operator cannot see in their config."""
        self.assertEqual(self.norm("/a/../b?x=%2f&y=%2E"), "/b?x=%2f&y=%2E")
        self.assertEqual(self.norm("/a?"), "/a?")

    def test_params_are_left_inside_their_segment(self):
        """Stripping `;params` is a legacy reading, and this listener does not
        get to decide the origin shares it."""
        self.assertEqual(self.norm("/a;v=1/b"), "/a;v=1/b")

    def test_a_fragment_is_refused(self):
        mod = _mod()
        with self.assertRaises(mod.RequestUnreadable):
            self.norm("/a#b")

    def test_an_absolute_form_target_is_normalised_too(self):
        """Otherwise the one form that moves the name out of the Host header is
        also the one that skips the path work."""
        mod = _mod()
        target, authority = mod.normalise_target(
            "GET", "http://h.example/a/../b")
        self.assertEqual((target, authority), ("/b", "h.example"))

    def test_an_absolute_form_authority_ends_before_a_query(self):
        """A query can carry a slash of its own, and splitting the authority on
        that one puts half the query into the name being authorised."""
        mod = _mod()
        target, authority = mod.normalise_target(
            "GET", "http://h.example?next=/a/b")
        self.assertEqual(authority, "h.example")
        self.assertEqual(target, "/?next=/a/b")


class TestTheNormalisedFormIsWhatGoesUpstream(_CleartextRig):
    """The half a table cannot hold. A normalisation the origin never sees is
    a second reading of the path, which is the defect it was written to close.
    """

    def test_the_origin_gets_the_resolved_path(self):
        log, _, dialled = self._run(
            ["h.example"],
            b"GET /repos/myorg/../../secret HTTP/1.1\r\nHost: h.example\r\n"
            b"Connection: close\r\n\r\n",
            responses=[_OK])
        self.assertEqual(len(dialled), 1)
        sent = dialled[0][1]
        self.assertTrue(sent.startswith(b"GET /secret HTTP/1.1\r\n"),
                        sent[:60])
        self.assertNotIn(b"..", sent.split(b"\r\n")[0])
        self.assertIn("forward", log)

    def test_an_encoded_slash_never_reaches_an_origin(self):
        log, answer, dialled = self._run(
            ["h.example"],
            b"GET /a%2f..%2fb HTTP/1.1\r\nHost: h.example\r\n\r\n")
        self.assertEqual(dialled, [])
        self.assertTrue(answer.startswith(b"HTTP/1.1 400 "), answer[:40])
        self.assertIn("unreadable request", log)


if __name__ == "__main__":
    unittest.main()
