"""Caller identity.

The thing under test fails silently when it fails at all: a broker that cannot
tell callers apart still returns 200 to every one of them. So nothing here
asserts that a request succeeded -- every test asserts on the recovered uid, or
on a refusal.
"""

import ipaddress
import socket
import struct
import threading
import unittest
from unittest import mock

import broker_server
import peer_identity


def proc_row(local, remote, uid, inode, state="01"):
    """One /proc/net/tcp data line, in the kernel's column order."""
    return (f"   0: {local} {remote} {state} 00000000:00000000 00:00000000 "
            f"00000000 {uid:>8} 0 {inode} 1 0000000000000000 100 0 0 10 0")


class TestProcAddress(unittest.TestCase):
    """Addresses are hex, in 32-bit words, each little-endian."""

    def test_ipv4(self):
        self.assertEqual(peer_identity._proc_addr("0100007F"),
                         ipaddress.ip_address("127.0.0.1"))

    def test_ipv4_high_octets_are_not_byte_swapped_wrongly(self):
        # 127.128.0.1 -- a workload management address, where a per-byte rather
        # than per-word reversal would still produce something plausible.
        self.assertEqual(peer_identity._proc_addr("0100807F"),
                         ipaddress.ip_address("127.128.0.1"))

    def test_ipv6(self):
        self.assertEqual(peer_identity._proc_addr("00000000000000000000000001000000"),
                         ipaddress.ip_address("::1"))

    def test_v4_mapped_collapses_to_v4(self):
        """A dual-stack listener reports peers as ::ffff:a.b.c.d, and the row
        for the same socket may sit in either table. Both sides must flatten or
        an exact match never happens."""
        self.assertEqual(peer_identity._proc_addr("0000000000000000FFFF00000100007F"),
                         ipaddress.ip_address("127.0.0.1"))


class TestPeerUidFrom(unittest.TestCase):
    """Row matching, against synthetic tables."""

    locals_ = [("127.0.0.1", 8081)]
    peer = ("127.0.0.1", 45000)

    def rows(self, **kwargs):
        # The peer's row is our connection mirrored.
        return [proc_row("0100007F:AFC8", "0100007F:1F91", **kwargs)]

    def test_finds_the_mirrored_row(self):
        found = peer_identity.peer_uid_from(self.rows(uid=10000, inode=45338),
                                     self.locals_, self.peer)
        self.assertEqual(found, 10000)

    def test_ownerless_row_is_not_trusted(self):
        """A TIME_WAIT remnant has inode 0 and is reported with uid 0. Reading
        that as identity would attribute the request to root."""
        found = peer_identity.peer_uid_from(self.rows(uid=0, inode=0),
                                     self.locals_, self.peer)
        self.assertIsNone(found)

    def test_our_own_listening_row_is_not_mistaken_for_the_peer(self):
        rows = [proc_row("0100007F:1F91", "00000000:0000", uid=999, inode=1)]
        self.assertIsNone(peer_identity.peer_uid_from(rows, self.locals_, self.peer))

    def test_the_port_prefilter_does_not_skip_the_right_row(self):
        """The scan rejects rows without the peer's port hex anywhere in them,
        which is a filter and must not become a second matching rule: the port
        can appear in another row's *remote* column, and the row that matches on
        both columns still has to win."""
        peer, ours = ("127.0.0.1", 0x9000), ("127.0.0.1", 8081)
        decoy = proc_row("0100007F:1F91", "0100007F:9000", uid=0, inode=555)
        real = proc_row("0100007F:9000", "0100007F:1F91", uid=10001, inode=777)
        self.assertEqual(
            peer_identity.peer_uid_from([decoy, real], [ours], peer), 10001)

    def test_a_row_without_the_peer_port_is_never_considered(self):
        other = proc_row("0100007F:8888", "0100007F:1F91", uid=10002, inode=778)
        self.assertIsNone(
            peer_identity.peer_uid_from([other], [("127.0.0.1", 8081)],
                                 ("127.0.0.1", 0x9000)))

    def test_a_different_connection_does_not_match(self):
        rows = [proc_row("0100007F:AFC9", "0100007F:1F91", uid=10000, inode=7)]
        self.assertIsNone(peer_identity.peer_uid_from(rows, self.locals_, self.peer))

    def test_malformed_lines_are_skipped_not_fatal(self):
        rows = ["garbage", "", "   1: zz:zz yy:yy 01"] + self.rows(uid=10001,
                                                                   inode=9)
        self.assertEqual(peer_identity.peer_uid_from(rows, self.locals_, self.peer),
                         10001)


class TestPeerUidThroughRedirect(unittest.TestCase):
    """The shape a host-side per-uid redirect actually produces.

    Measured, not assumed: under output DNAT the client socket keeps recording
    the address it dialled, so its row's remote is the ADVERTISED endpoint while
    the server is bound to the translated one. Matching only getsockname() finds
    nothing and every guest gets a 403 -- which is why local_endpoints offers
    both.
    """

    advertised = ("192.0.2.1", 8081)      # what the guest dialled
    translated = ("127.0.0.1", 8081)      # where the broker is actually bound
    peer = ("192.0.2.1", 58224)

    # local=192.0.2.1:58224  rem=192.0.2.1:8081
    rows = [proc_row("010200C0:E370", "010200C0:1F91", uid=10000, inode=1157636)]

    def test_the_bound_address_alone_does_not_match(self):
        self.assertIsNone(
            peer_identity.peer_uid_from(self.rows, [self.translated], self.peer))

    def test_the_advertised_endpoint_matches(self):
        self.assertEqual(
            peer_identity.peer_uid_from(self.rows, [self.advertised], self.peer), 10000)

    def test_offering_both_covers_translated_and_direct_alike(self):
        both = [self.translated, self.advertised]
        self.assertEqual(peer_identity.peer_uid_from(self.rows, both, self.peer), 10000)
        direct = [proc_row("0100007F:AFC8", "0100007F:1F91", uid=10001, inode=2)]
        self.assertEqual(
            peer_identity.peer_uid_from(direct, both, ("127.0.0.1", 45000)), 10001)


class TestLocalEndpointsV6(unittest.TestCase):
    """The v6 half of the original-destination recovery.

    The redirect has a v6 rule of its own, so a v6 dial arrives translated
    exactly as a v4 one does. SO_ORIGINAL_DST under SOL_IP does not serve it --
    it raises on a v6 socket -- so without a SOL_IPV6 lookup the endpoint list
    holds only getsockname(), the peer's /proc/net/tcp6 row records the address
    it DIALLED, nothing matches, and the caller is admitted as unresolved. The
    failure is a counter climbing and nothing else, which is why it needs a
    test that fails when the branch is deleted rather than one that watches a
    real connection succeed.
    """

    def _sockaddr_in6(self, addr, port):
        return struct.pack("!HH4x16s4x", socket.AF_INET6, port,
                           socket.inet_pton(socket.AF_INET6, addr))

    def test_the_original_v6_destination_is_offered(self):
        sock = mock.Mock()
        sock.getsockname.return_value = ("2001:2::a", 8443, 0, 0)

        def getsockopt(level, opt, size):
            if level == socket.IPPROTO_IPV6:
                return self._sockaddr_in6("2606:4700::1111", 443)
            raise OSError("not an IPv4 socket")

        sock.getsockopt.side_effect = getsockopt
        self.assertEqual(
            peer_identity.local_endpoints(sock),
            [("2001:2::a", 8443), ("2606:4700::1111", 443)])

    def test_a_v4_socket_is_unaffected(self):
        # Both options are asked for now; the v6 one must not disturb the
        # answer a v4 connection already produced.
        sock = mock.Mock()
        sock.getsockname.return_value = ("198.18.0.1", 8443)

        def getsockopt(level, opt, size):
            if level == socket.SOL_IP:
                return struct.pack("!HH4s8x", socket.AF_INET, 443,
                                   socket.inet_aton("93.184.216.34"))
            raise OSError("not an IPv6 socket")

        sock.getsockopt.side_effect = getsockopt
        self.assertEqual(
            peer_identity.local_endpoints(sock),
            [("198.18.0.1", 8443), ("93.184.216.34", 443)])

    def test_neither_option_answering_is_not_an_error(self):
        # An untranslated connection -- local testing, or a direct dial -- has
        # no conntrack entry in either family. It must still offer its own
        # bound address rather than raise.
        sock = mock.Mock()
        sock.getsockname.return_value = ("127.0.0.1", 8081)
        sock.getsockopt.side_effect = OSError("no conntrack entry")
        self.assertEqual(peer_identity.local_endpoints(sock), [("127.0.0.1", 8081)])


class TestPeerUidLiveV6(unittest.TestCase):
    """Against the real kernel over IPv6, which reads /proc/net/tcp6."""

    def test_recovers_the_uid_of_a_real_v6_connection(self):
        import os

        if not socket.has_ipv6:
            self.skipTest("no IPv6 support in this interpreter")
        srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.addCleanup(srv.close)
        try:
            srv.bind(("::1", 0))
        except OSError as e:
            self.skipTest(f"no loopback IPv6 on this host: {e}")
        srv.listen(1)

        held = []
        threading.Thread(
            target=lambda: held.append(
                socket.create_connection(srv.getsockname()[:2])),
            daemon=True).start()
        conn, peer = srv.accept()
        self.addCleanup(conn.close)

        found = peer_identity.peer_uid(peer_identity.local_endpoints(conn), peer[:2])
        self.assertEqual(found, os.getuid())
        for sock in held:
            sock.close()


class TestPeerUidLive(unittest.TestCase):
    """Against the real kernel, not a fixture."""

    def test_recovers_the_uid_of_a_real_connection(self):
        import os

        srv = socket.socket()
        self.addCleanup(srv.close)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)

        held = []
        # Hold the client socket open. A closed one lands in TIME_WAIT, whose
        # row the kernel reports with uid 0 -- which is why letting it be
        # garbage-collected makes this look like it passed against root.
        threading.Thread(
            target=lambda: held.append(socket.create_connection(srv.getsockname())),
            daemon=True).start()
        conn, peer = srv.accept()
        self.addCleanup(conn.close)

        found = peer_identity.peer_uid([conn.getsockname()], peer)
        self.assertEqual(found, os.getuid())
        for sock in held:
            sock.close()

    def test_a_peer_that_closed_before_the_lookup_is_orphaned(self):
        """Written, closed, and only then accepted: the row is still in the
        table with no socket behind it, so it names nobody -- and says so,
        rather than reading as a row that could not be found."""
        import os

        srv = socket.socket()
        self.addCleanup(srv.close)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        client = socket.create_connection(srv.getsockname())
        client.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        client.close()
        conn, peer = srv.accept()
        self.addCleanup(conn.close)

        endpoints = peer_identity.local_endpoints(conn)
        self.assertEqual(peer_identity.peer_caller(endpoints, peer[:2]),
                         (None, True))

        live = socket.create_connection(srv.getsockname())
        self.addCleanup(live.close)
        conn2, peer2 = srv.accept()
        self.addCleanup(conn2.close)
        self.assertEqual(
            peer_identity.peer_caller(peer_identity.local_endpoints(conn2),
                                      peer2[:2]),
            (os.getuid(), False))

    def test_a_peer_that_reset_leaves_no_row_but_reads_closed(self):
        """Written, reset, and only then accepted: the reset takes the row
        with it, so the lookup finds nothing -- the answer it gives for a
        live caller lost to churn. The connection's own state tells them
        apart, and the queued request is still there to be read."""
        srv = socket.socket()
        self.addCleanup(srv.close)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        client = socket.create_connection(srv.getsockname())
        client.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                          struct.pack("ii", 1, 0))
        client.close()
        conn, peer = srv.accept()
        self.addCleanup(conn.close)

        endpoints = peer_identity.local_endpoints(conn)
        self.assertEqual(peer_identity.peer_caller(endpoints, peer[:2]),
                         (None, False))
        self.assertIs(peer_identity.peer_closed(conn), True)

        live = socket.create_connection(srv.getsockname())
        self.addCleanup(live.close)
        conn2, _peer2 = srv.accept()
        self.addCleanup(conn2.close)
        self.assertIs(peer_identity.peer_closed(conn2), False)
        live.close()
        self.assertEqual(conn2.recv(1), b"")
        self.assertIs(peer_identity.peer_closed(conn2), True)


INITIAL_NS = "         0          0 4294967295\n"
# What `unshare -Ur` produces: one uid mapped, everything else invisible.
SINGLE_UID_NS = "         0       1000          1\n"
# A container: restricted, but it still maps the whole workload uid range.
CONTAINER_NS = "         0          0          1\n         1          1      65536\n"
# A rootless container: the same shape, with the two columns different. The
# user is root inside and the subuid range is 1..65536 inside; outside they
# are the user's uid and a range starting far above it.
ROOTLESS_NS = "         0       1000          1\n         1     524288      65536\n"


class TestUsernsShape(unittest.TestCase):

    def test_the_initial_namespace_maps_everything(self):
        self.assertTrue(peer_identity.userns_maps_everything(INITIAL_NS))

    def test_a_single_mapped_uid_does_not(self):
        self.assertFalse(peer_identity.userns_maps_everything(SINGLE_UID_NS))

    def test_a_container_map_does_not(self):
        self.assertFalse(peer_identity.userns_maps_everything(CONTAINER_NS))

    def test_an_empty_map_does_not(self):
        self.assertFalse(peer_identity.userns_maps_everything(""))


class TestUnmappableUids(unittest.TestCase):
    """The startup guard, checked against the uids that matter rather than the
    shape of the map -- a namespace can be restricted and still map every
    workload, and refusing that would be a false alarm.

    Uids, and no passwd lookup: the broker is told its caller's uid and
    this answers about that number. There is no `_wl-` prefix anywhere in
    either daemon's process now, which is asserted below by the module
    importing nothing that could look one up."""

    def unmappable(self, uid_map, uid=10000):
        return peer_identity.unmappable_uids([uid], uid_map)

    def test_the_initial_namespace_can_see_every_workload(self):
        self.assertEqual(self.unmappable(INITIAL_NS), [])

    def test_a_restricted_namespace_that_still_covers_workloads_is_fine(self):
        """This is the case the first version of the guard got wrong: it
        demanded the initial map and would have refused to run here."""
        self.assertEqual(self.unmappable(CONTAINER_NS), [])

    def test_a_uid_outside_the_map_is_reported(self):
        self.assertEqual(self.unmappable(SINGLE_UID_NS), [10000])

    def test_a_uid_above_the_mapped_range_is_reported(self):
        self.assertEqual(self.unmappable(CONTAINER_NS, uid=70000), [70000])

    def test_the_inside_column_is_the_one_compared(self):
        """Every layout before the rootless container had the two columns
        equal, so a check against the outside column passed everywhere it
        was tried and refused every uid the first rootless broker had. The
        uid a program is told is an inside value; so is what the kernel
        reports to it."""
        self.assertEqual(self.unmappable(ROOTLESS_NS, uid=200), [])
        self.assertEqual(self.unmappable(ROOTLESS_NS, uid=65536), [])
        self.assertEqual(self.unmappable(ROOTLESS_NS, uid=65537), [65537])
        # The outside numbering is the parent's; that number means nothing
        # inside and is not representable there.
        self.assertEqual(self.unmappable(ROOTLESS_NS, uid=524288), [524288])
        self.assertEqual(self.unmappable(ROOTLESS_NS, uid=1000), [])

    def test_the_module_looks_nothing_up(self):
        """No pwd, no prefix: a uid is compared to a uid. The lookup that
        turned one into a workload name was the last workload-side fact in
        the broker's process."""
        import inspect
        source = inspect.getsource(peer_identity)
        self.assertNotIn("import pwd", source)
        self.assertNotIn("_wl", source)
        self.assertFalse(hasattr(peer_identity, "workload_name"))


class TestIdentifyRefusals(unittest.TestCase):
    """Nothing rescues a caller the table does not name.

    There used to be something: `allow_unknown_callers` produced a fallback
    profile, and these cases pinned that it did NOT cover the two failures
    meaning the mechanism itself is broken -- no peer socket, and a uid this
    namespace cannot map -- because both make every caller look alike, which is
    the failure the port exists to remove.

    The flag is gone (ADR 007 decision 6: an instance serves one workload and
    its config is generated from that workload's own TOML), so the distinction
    those tests drew has collapsed into "every unlisted caller is refused". They
    are kept, with the labels asserted, because the labels are what a log reader
    uses to tell the three refusals apart -- and "unidentified" logged for all
    three would be the same erasure by another route.
    """

    def _handler(self, uid, workload_uid=10001):
        """A handler whose connection was admitted with `uid` on the far end,
        in an instance started for `workload_uid`.

        caller_uid is what Server.process_request resolved when it granted this
        connection a slot; the handler no longer looks it up itself, so the
        fixture is the uid rather than a patched lookup. workload_uid is the
        --caller-uid the instance was started with.
        """
        handler = broker_server.Handler.__new__(broker_server.Handler)
        handler.name = "agent"
        handler.workload_uid = workload_uid
        handler.profiles = {"api.example.com": "profile-of-agent"}
        handler.overflow = 65534
        handler.caller_uid = uid
        return handler

    def test_no_peer_socket_is_refused_and_says_so(self):
        sandbox, label = self._handler(None)._identify()
        self.assertIsNone(sandbox)
        self.assertEqual(label, "no-peer-socket")

    def test_an_unmapped_uid_is_refused_and_says_so(self):
        sandbox, label = self._handler(65534)._identify()
        self.assertIsNone(sandbox)
        self.assertEqual(label, "uid-unmapped")

    def test_another_uid_gets_nothing(self):
        sandbox, label = self._handler(10002)._identify()
        self.assertIsNone(sandbox)
        # The label still carries the uid, so the log line says WHICH caller
        # was refused rather than only that one was -- and it is the bare
        # number, because the broker has no name for a uid that is not its
        # own workload's.
        self.assertEqual(label, "uid:10002")

    def test_the_configured_caller_resolves_to_its_name_and_not_to_a_profile(self):
        """_identify settles the caller. Returning a profile here would mean
        resolving it once per CONNECTION, and one keep-alive connection from
        an inspector may carry requests for two credential-backed hosts --
        the second would get the first's credential."""
        sandbox, label = self._handler(10001)._identify()
        self.assertEqual(sandbox, "agent")
        self.assertEqual(label, "agent")

    def test_the_uid_is_compared_and_never_resolved(self):
        """An instance whose workload_uid was never set serves nobody: the
        comparison is against the flag, not against a lookup that might
        find a `_wl-` user behind the caller."""
        sandbox, _label = self._handler(10001, workload_uid=None)._identify()
        self.assertIsNone(sandbox)


if __name__ == "__main__":
    unittest.main()
