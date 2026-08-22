"""workload-vm-inspect-listener: the socket-activated listener, rung 1.

The listener only logs (the inspector design, §7.7.1): a
connection arrives, one line is written, the connection is closed. These tests
hold the shape that the later rungs ride on — that the plane comes from
getsockname() and not the fd name, that the socket is never opened by the
process itself, that the connection ceiling rejects rather than queues, and
that the installed path agrees with the constant the unit's ExecStart reads.
"""

import io
import os
import unittest
import unittest.mock
from pathlib import Path

from tests import load_script
from vm import VM_INSPECT_LISTENER_BIN, VM_INSPECT_PORT_CLEARTEXT, VM_INSPECT_PORT_TLS

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
        local = ("198.18.0.1", VM_INSPECT_PORT_TLS)
        log = _serve_line(local)
        self.assertIn("plane=tls", log)
        self.assertIn(f"local=198.18.0.1:{VM_INSPECT_PORT_TLS}", log)
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


if __name__ == "__main__":
    unittest.main()
