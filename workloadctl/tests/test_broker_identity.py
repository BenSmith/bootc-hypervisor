"""Caller identity.

The thing under test fails silently when it fails at all: a broker that cannot
tell callers apart still returns 200 to every one of them. So nothing here
asserts that a request succeeded -- every test asserts on the recovered uid, or
on a refusal.
"""

import ipaddress
import socket
import threading
import unittest
from unittest import mock

from tests import load_script

broker = load_script("libexec/agent-broker")


def proc_row(local, remote, uid, inode, state="01"):
    """One /proc/net/tcp data line, in the kernel's column order."""
    return (f"   0: {local} {remote} {state} 00000000:00000000 00:00000000 "
            f"00000000 {uid:>8} 0 {inode} 1 0000000000000000 100 0 0 10 0")


class TestProcAddress(unittest.TestCase):
    """Addresses are hex, in 32-bit words, each little-endian."""

    def test_ipv4(self):
        self.assertEqual(broker._proc_addr("0100007F"),
                         ipaddress.ip_address("127.0.0.1"))

    def test_ipv4_high_octets_are_not_byte_swapped_wrongly(self):
        # 127.128.0.1 -- a workload management address, where a per-byte rather
        # than per-word reversal would still produce something plausible.
        self.assertEqual(broker._proc_addr("0100807F"),
                         ipaddress.ip_address("127.128.0.1"))

    def test_ipv6(self):
        self.assertEqual(broker._proc_addr("00000000000000000000000001000000"),
                         ipaddress.ip_address("::1"))

    def test_v4_mapped_collapses_to_v4(self):
        """A dual-stack listener reports peers as ::ffff:a.b.c.d, and the row
        for the same socket may sit in either table. Both sides must flatten or
        an exact match never happens."""
        self.assertEqual(broker._proc_addr("0000000000000000FFFF00000100007F"),
                         ipaddress.ip_address("127.0.0.1"))


class TestPeerUidFrom(unittest.TestCase):
    """Row matching, against synthetic tables."""

    locals_ = [("127.0.0.1", 8081)]
    peer = ("127.0.0.1", 45000)

    def rows(self, **kwargs):
        # The peer's row is our connection mirrored.
        return [proc_row("0100007F:AFC8", "0100007F:1F91", **kwargs)]

    def test_finds_the_mirrored_row(self):
        found = broker.peer_uid_from(self.rows(uid=10000, inode=45338),
                                     self.locals_, self.peer)
        self.assertEqual(found, 10000)

    def test_ownerless_row_is_not_trusted(self):
        """A TIME_WAIT remnant has inode 0 and is reported with uid 0. Reading
        that as identity would attribute the request to root."""
        found = broker.peer_uid_from(self.rows(uid=0, inode=0),
                                     self.locals_, self.peer)
        self.assertIsNone(found)

    def test_our_own_listening_row_is_not_mistaken_for_the_peer(self):
        rows = [proc_row("0100007F:1F91", "00000000:0000", uid=999, inode=1)]
        self.assertIsNone(broker.peer_uid_from(rows, self.locals_, self.peer))

    def test_the_port_prefilter_does_not_skip_the_right_row(self):
        """The scan rejects rows without the peer's port hex anywhere in them,
        which is a filter and must not become a second matching rule: the port
        can appear in another row's *remote* column, and the row that matches on
        both columns still has to win."""
        peer, ours = ("127.0.0.1", 0x9000), ("127.0.0.1", 8081)
        decoy = proc_row("0100007F:1F91", "0100007F:9000", uid=0, inode=555)
        real = proc_row("0100007F:9000", "0100007F:1F91", uid=10001, inode=777)
        self.assertEqual(
            broker.peer_uid_from([decoy, real], [ours], peer), 10001)

    def test_a_row_without_the_peer_port_is_never_considered(self):
        other = proc_row("0100007F:8888", "0100007F:1F91", uid=10002, inode=778)
        self.assertIsNone(
            broker.peer_uid_from([other], [("127.0.0.1", 8081)],
                                 ("127.0.0.1", 0x9000)))

    def test_a_different_connection_does_not_match(self):
        rows = [proc_row("0100007F:AFC9", "0100007F:1F91", uid=10000, inode=7)]
        self.assertIsNone(broker.peer_uid_from(rows, self.locals_, self.peer))

    def test_malformed_lines_are_skipped_not_fatal(self):
        rows = ["garbage", "", "   1: zz:zz yy:yy 01"] + self.rows(uid=10001,
                                                                   inode=9)
        self.assertEqual(broker.peer_uid_from(rows, self.locals_, self.peer),
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
            broker.peer_uid_from(self.rows, [self.translated], self.peer))

    def test_the_advertised_endpoint_matches(self):
        self.assertEqual(
            broker.peer_uid_from(self.rows, [self.advertised], self.peer), 10000)

    def test_offering_both_covers_translated_and_direct_alike(self):
        both = [self.translated, self.advertised]
        self.assertEqual(broker.peer_uid_from(self.rows, both, self.peer), 10000)
        direct = [proc_row("0100007F:AFC8", "0100007F:1F91", uid=10001, inode=2)]
        self.assertEqual(
            broker.peer_uid_from(direct, both, ("127.0.0.1", 45000)), 10001)


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

        found = broker.peer_uid([conn.getsockname()], peer)
        self.assertEqual(found, os.getuid())
        for sock in held:
            sock.close()


class TestWorkloadName(unittest.TestCase):

    def test_strips_the_workload_prefix(self):
        with mock.patch.object(broker.pwd, "getpwuid",
                               return_value=mock.Mock(pw_name="_wl-agent-scratch")):
            self.assertEqual(broker.workload_name(10000), "agent-scratch")

    def test_a_non_workload_user_is_not_a_workload(self):
        with mock.patch.object(broker.pwd, "getpwuid",
                               return_value=mock.Mock(pw_name="nginx")):
            self.assertIsNone(broker.workload_name(978))

    def test_an_unknown_uid_is_not_a_workload(self):
        with mock.patch.object(broker.pwd, "getpwuid", side_effect=KeyError):
            self.assertIsNone(broker.workload_name(4242))


INITIAL_NS = "         0          0 4294967295\n"
# What `unshare -Ur` produces: one uid mapped, everything else invisible.
SINGLE_UID_NS = "         0       1000          1\n"
# A container: restricted, but it still maps the whole workload uid range.
CONTAINER_NS = "         0          0          1\n         1          1      65536\n"


class TestUsernsShape(unittest.TestCase):

    def test_the_initial_namespace_maps_everything(self):
        self.assertTrue(broker.userns_maps_everything(INITIAL_NS))

    def test_a_single_mapped_uid_does_not(self):
        self.assertFalse(broker.userns_maps_everything(SINGLE_UID_NS))

    def test_a_container_map_does_not(self):
        self.assertFalse(broker.userns_maps_everything(CONTAINER_NS))

    def test_an_empty_map_does_not(self):
        self.assertFalse(broker.userns_maps_everything(""))


class TestUnmappableSandboxes(unittest.TestCase):
    """The startup guard, checked against the uids that matter rather than the
    shape of the map -- a namespace can be restricted and still map every
    workload, and refusing that would be a false alarm."""

    def sandboxes(self, uid_map, uid=10000):
        with mock.patch.object(broker.pwd, "getpwnam",
                               return_value=mock.Mock(pw_uid=uid)):
            return broker.unmappable_sandboxes(["agent-scratch"], uid_map)

    def test_the_initial_namespace_can_see_every_workload(self):
        self.assertEqual(self.sandboxes(INITIAL_NS), [])

    def test_a_restricted_namespace_that_still_covers_workloads_is_fine(self):
        """This is the case the first version of the guard got wrong: it
        demanded the initial map and would have refused to run here."""
        self.assertEqual(self.sandboxes(CONTAINER_NS), [])

    def test_a_workload_outside_the_map_is_reported_by_name(self):
        found = self.sandboxes(SINGLE_UID_NS)
        self.assertEqual(len(found), 1)
        self.assertIn("_wl-agent-scratch", found[0])
        self.assertIn("10000", found[0])

    def test_a_workload_above_the_mapped_range_is_reported(self):
        self.assertEqual(len(self.sandboxes(CONTAINER_NS, uid=70000)), 1)

    def test_a_sandbox_whose_user_does_not_exist_yet_is_not_an_error(self):
        with mock.patch.object(broker.pwd, "getpwnam", side_effect=KeyError):
            self.assertEqual(
                broker.unmappable_sandboxes(["not-created"], SINGLE_UID_NS), [])


class TestIdentifyRefusals(unittest.TestCase):
    """allow_unknown_callers must not rescue a broken mechanism.

    Both cases below make every caller look alike. Letting the fallback cover
    them would turn 'I cannot tell you apart' into 'you are all the same
    permitted sandbox', which is the failure the port exists to remove.
    """

    def _handler(self, uid):
        """A handler whose connection was admitted with `uid` on the far end.

        caller_uid is what Server.process_request resolved when it granted this
        connection a slot; the handler no longer looks it up itself, so the
        fixture is the uid rather than a patched lookup.
        """
        handler = broker.Handler.__new__(broker.Handler)
        handler.profiles = {}
        handler.fallback = "a-permissive-profile"
        handler.overflow = 65534
        handler.caller_uid = uid
        return handler

    def test_no_peer_socket_is_refused_even_when_unknown_are_allowed(self):
        profile, label = self._handler(None)._identify()
        self.assertIsNone(profile)
        self.assertEqual(label, "no-peer-socket")

    def test_an_unmapped_uid_is_refused_even_when_unknown_are_allowed(self):
        profile, label = self._handler(65534)._identify()
        self.assertIsNone(profile)
        self.assertEqual(label, "uid-unmapped")

    def test_an_ordinary_unknown_caller_still_gets_the_fallback(self):
        with mock.patch.object(broker, "workload_name",
                               return_value="not-in-config"):
            profile, label = self._handler(10001)._identify()
        self.assertEqual(profile, "a-permissive-profile")
        self.assertEqual(label, "not-in-config")


if __name__ == "__main__":
    unittest.main()
