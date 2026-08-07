#!/usr/bin/env python3
"""Unit tests for VM address resolution (agent / lease / ARP / mDNS branches).

Regression coverage for the ARP parse bug: `ip neigh show dev <iface>` omits
the `dev <iface>` tokens it prints in the unfiltered form, so the MAC is not at
a fixed column. The lookup must find it via the `lladdr` marker, not parts[4].

And for the gap that exposed: on a pre-existing LAN bridge the ARP table is the
only host-side source, and it is passive — a healthy but long-idle VM falls out
of it and became unreachable to `exec`/`shell` while still serving traffic.
qemu-guest-agent is the source that does not depend on host-side state, so it is
tried first.
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


import substrate_vm as substrate
from vm import vm_mac_address


def _completed(stdout="", returncode=0):
    return SimpleNamespace(stdout=stdout, returncode=returncode)


def _iface(name, hw, *addrs):
    """One guest-network-get-interfaces entry; addrs are (type, ip) pairs."""
    return {
        "name": name,
        "hardware-address": hw,
        "ip-addresses": [
            {"ip-address-type": t, "ip-address": ip} for t, ip in addrs
        ],
    }


class TestVmGuestIpArp(unittest.TestCase):
    """ARP fallback on a pre-existing LAN bridge (no dnsmasq lease)."""

    def setUp(self):
        self.name = "git"
        self.mac = vm_mac_address(self.name)
        self.ip = "192.168.0.157"
        # No managed-bridge marker -> skip lease, go straight to ARP.
        marker = mock.MagicMock()
        marker.exists.return_value = False
        self._path_patch = mock.patch.object(substrate, "Path", return_value=marker)
        self._path_patch.start()
        self.addCleanup(self._path_patch.stop)
        # These cases are about the host-side chain. The agent socket path is
        # built from a module constant rather than substrate.Path, so it escapes
        # the patch above and would otherwise be answered by whatever is really
        # in /run on the machine running the tests.
        self._agent_patch = mock.patch.object(
            substrate, "_vm_guest_agent_addresses", return_value=[])
        self._agent_patch.start()
        self.addCleanup(self._agent_patch.stop)

    def test_dev_filtered_format(self):
        """`ip neigh show dev br0`: <ip> lladdr <mac> <state> (4 fields).

        This is the format that actually ships and the one the old
        `len(parts) >= 5 and parts[4]` parse silently failed to match.
        """
        neigh = (
            f"192.168.0.89 lladdr 52:54:00:65:d2:6d REACHABLE\n"
            f"{self.ip} lladdr {self.mac} REACHABLE\n"
            f"192.168.0.1 lladdr a0:63:91:2c:e5:ef STALE\n"
        )
        with mock.patch.object(substrate.subprocess, "run",
                               return_value=_completed(neigh)):
            self.assertEqual(substrate._vm_guest_ip(self.name, "br0"), self.ip)

    def test_unfiltered_format_still_works(self):
        """<ip> dev <iface> lladdr <mac> <state> (6 fields) also resolves."""
        neigh = f"{self.ip} dev br0 lladdr {self.mac} REACHABLE\n"
        with mock.patch.object(substrate.subprocess, "run",
                               return_value=_completed(neigh)):
            self.assertEqual(substrate._vm_guest_ip(self.name, "br0"), self.ip)

    def test_mac_mismatch_falls_through_to_mdns(self):
        """No matching MAC in ARP -> mDNS fallback supplies the IP."""
        neigh = "192.168.0.89 lladdr 52:54:00:65:d2:6d REACHABLE\n"

        def fake_run(argv, *a, **k):
            if argv[:2] == ["ip", "neigh"]:
                return _completed(neigh)
            if argv[:2] == ["getent", "hosts"]:
                return _completed(f"{self.ip} {self.name}.local\n", returncode=0)
            return _completed("", returncode=1)

        with mock.patch.object(substrate.subprocess, "run", side_effect=fake_run):
            self.assertEqual(substrate._vm_guest_ip(self.name, "br0"), self.ip)

    def test_nothing_matches_returns_none(self):
        def fake_run(argv, *a, **k):
            if argv[:2] == ["getent", "hosts"]:
                return _completed("", returncode=2)
            return _completed("")  # empty ARP table

        with mock.patch.object(substrate.subprocess, "run", side_effect=fake_run):
            self.assertIsNone(substrate._vm_guest_ip(self.name, "br0"))


class TestVmGuestAgent(unittest.TestCase):
    """qemu-guest-agent: the guest's own answer, tried before any host source."""

    name = "git"

    def setUp(self):
        self.mac = vm_mac_address(self.name)
        # The fall-through cases below assert they reach ARP, so the lease
        # branch has to be closed deterministically. Without this the marker
        # check reads the real /run, and the suite would behave differently on a
        # host that happens to be running managed-bridge VMs.
        marker = mock.MagicMock()
        marker.exists.return_value = False
        self._path_patch = mock.patch.object(substrate, "Path", return_value=marker)
        self._path_patch.start()
        self.addCleanup(self._path_patch.stop)

    def _agent(self, interfaces, *, socket_present=True):
        """Patch the agent socket + a QMPClient that replies with `interfaces`.

        The client answers guest-sync by echoing the nonce it was handed, so
        every case here gets past the handshake without restating it.
        """
        sock = mock.MagicMock()
        sock.exists.return_value = socket_present

        def execute(command, arguments=None, **_):
            if command == "guest-sync":
                return {"return": arguments["id"]}
            return {"return": interfaces}

        client = mock.MagicMock()
        client.execute.side_effect = execute
        return (
            mock.patch.object(substrate, "vm_guest_agent_socket", return_value=sock),
            mock.patch.object(substrate, "QMPClient", return_value=client),
            client,
        )

    def test_ipv4_before_ipv6(self):
        interfaces = [
            _iface("enp1s0", self.mac,
                   ("ipv6", "fd00::157"), ("ipv4", "192.168.0.157")),
        ]
        p_sock, p_client, _ = self._agent(interfaces)
        with p_sock, p_client:
            self.assertEqual(
                substrate._vm_guest_addresses(self.name, "br0"),
                ["192.168.0.157", "fd00::157"],
            )

    def test_only_our_nic_is_trusted(self):
        """A guest-internal bridge is not an address the host can reach, and
        returning one would be worse than returning nothing: a non-empty answer
        short-circuits the fallback chain, so `exec` would SSH at an unroutable
        address instead of letting ARP find the real one."""
        interfaces = [
            _iface("lo", "00:00:00:00:00:00", ("ipv4", "127.0.0.1")),
            _iface("podman0", "9a:11:22:33:44:55", ("ipv4", "10.88.0.1")),
            _iface("tun0", "", ("ipv4", "10.9.0.2")),
        ]
        arp = f"192.168.0.157 lladdr {self.mac} STALE\n"
        p_sock, p_client, _ = self._agent(interfaces)
        with p_sock, p_client, \
             mock.patch.object(substrate.subprocess, "run",
                               return_value=_completed(arp)):
            # Falls through to ARP rather than handing back 10.88.0.1.
            self.assertEqual(
                substrate._vm_guest_ip(self.name, "br0"), "192.168.0.157")

    def test_stale_reply_is_discarded_by_the_sync_nonce(self):
        """A previous lookup that timed out mid-command leaves its reply queued
        in the port. Without the nonce it would be read as the answer to a
        question this call never asked."""
        interfaces = [_iface("enp1s0", self.mac, ("ipv4", "192.168.0.157"))]
        stale = {"return": [_iface("enp1s0", self.mac, ("ipv4", "10.0.0.99"))]}
        sock = mock.MagicMock()
        sock.exists.return_value = True

        client = mock.MagicMock()
        # guest-sync's first read lands on the leftover reply; the nonce echo is
        # behind it and only next_message() gets there.
        state = {}

        def execute(command, arguments=None, **_):
            if command == "guest-sync":
                state["token"] = arguments["id"]
                return stale
            return {"return": interfaces}

        client.execute.side_effect = execute
        client.next_message.side_effect = lambda: {"return": state["token"]}

        with mock.patch.object(substrate, "vm_guest_agent_socket", return_value=sock), \
             mock.patch.object(substrate, "QMPClient", return_value=client):
            self.assertEqual(
                substrate._vm_guest_addresses(self.name, "br0"),
                ["192.168.0.157"],
            )

    def test_unanswered_sync_falls_through(self):
        """A channel that never echoes the nonce is not a channel we can read."""
        sock = mock.MagicMock()
        sock.exists.return_value = True
        client = mock.MagicMock()
        client.execute.return_value = {"return": "not-the-token"}
        client.next_message.return_value = None
        arp = f"192.168.0.157 lladdr {self.mac} STALE\n"
        with mock.patch.object(substrate, "vm_guest_agent_socket", return_value=sock), \
             mock.patch.object(substrate, "QMPClient", return_value=client), \
             mock.patch.object(substrate.subprocess, "run",
                               return_value=_completed(arp)):
            self.assertEqual(
                substrate._vm_guest_ip(self.name, "br0"), "192.168.0.157")

    def test_wins_over_stale_arp(self):
        """The whole point: the agent answers even when the neighbour table has
        a *different*, stale idea of where the guest is."""
        interfaces = [_iface("enp1s0", self.mac, ("ipv4", "192.168.0.157"))]
        p_sock, p_client, _ = self._agent(interfaces)
        with p_sock, p_client, \
             mock.patch.object(substrate.subprocess, "run") as run:
            self.assertEqual(
                substrate._vm_guest_ip(self.name, "br0"), "192.168.0.157")
        run.assert_not_called()

    def test_no_negotiate_on_the_agent_channel(self):
        """QGA shares QMP's framing but has no greeting — negotiating would
        block until the recv timeout on every single lookup."""
        p_sock, p_client, client = self._agent(
            [_iface("enp1s0", self.mac, ("ipv4", "10.0.0.9"))])
        with p_sock, p_client:
            substrate._vm_guest_addresses(self.name, "br0")
        client.negotiate.assert_not_called()
        self.assertEqual(
            [c.args[0] for c in client.execute.call_args_list],
            ["guest-sync", "guest-network-get-interfaces"])

    def test_link_local_and_loopback_dropped(self):
        """Nothing reachable is left, so the agent yields nothing and the
        host-side chain gets its turn rather than being handed a dead address."""
        interfaces = [
            _iface("lo", "00:00:00:00:00:00",
                   ("ipv4", "127.0.0.1"), ("ipv6", "::1")),
            _iface("enp1s0", self.mac,
                   ("ipv4", "169.254.3.4"), ("ipv6", "fe80::1")),
        ]
        p_sock, p_client, _ = self._agent(interfaces)
        with p_sock, p_client, \
             mock.patch.object(substrate.subprocess, "run",
                               return_value=_completed("", returncode=2)):
            self.assertEqual(substrate._vm_guest_addresses(self.name, "br0"), [])

    def test_absent_socket_skips_agent_without_connecting(self):
        p_sock, p_client, client = self._agent([], socket_present=False)
        with p_sock, p_client, \
             mock.patch.object(substrate.subprocess, "run",
                               return_value=_completed("", returncode=2)):
            substrate._vm_guest_addresses(self.name, "br0")
        client.connect.assert_not_called()

    def test_agent_failure_falls_through_to_arp(self):
        """A guest with no qemu-ga running: QEMU accepts our connection and
        nothing ever replies. That is an ordinary state, not an error."""
        ip = "192.168.0.157"
        sock = mock.MagicMock()
        sock.exists.return_value = True
        client = mock.MagicMock()
        client.execute.side_effect = TimeoutError("no reply")
        neigh = f"{ip} lladdr {self.mac} STALE\n"
        with mock.patch.object(substrate, "vm_guest_agent_socket", return_value=sock), \
             mock.patch.object(substrate, "QMPClient", return_value=client), \
             mock.patch.object(substrate.subprocess, "run",
                               return_value=_completed(neigh)):
            self.assertEqual(substrate._vm_guest_ip(self.name, "br0"), ip)


class TestVmGuestIpLease(unittest.TestCase):
    """dnsmasq lease lookup on a workloadctl-managed bridge."""

    def test_lease_match(self):
        name = "demo-vm"
        ip = "192.168.200.123"
        with tempfile.TemporaryDirectory() as d:
            lease = Path(d) / "workload-bridge.leases"
            # dnsmasq lease format: <ts> <mac> <ip> <hostname> <client-id>
            lease.write_text(
                f"1700000000 52:54:00:aa:bb:cc {ip} {name} 01:52:54:00:aa:bb:cc\n"
            )
            marker = mock.MagicMock()
            marker.exists.return_value = True  # bridge-managed present
            with mock.patch.object(substrate, "Path", return_value=marker), \
                 mock.patch.object(substrate, "_vm_guest_agent_addresses",
                                   return_value=[]), \
                 mock.patch.object(substrate, "VM_DHCP_LEASE_FILE", lease):
                self.assertEqual(substrate._vm_guest_ip(name), ip)


if __name__ == "__main__":
    unittest.main()
