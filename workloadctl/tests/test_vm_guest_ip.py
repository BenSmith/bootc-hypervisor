#!/usr/bin/env python3
"""Unit tests for _vm_guest_ip IP resolution (lease / ARP / mDNS branches).

Regression coverage for the ARP parse bug: `ip neigh show dev <iface>` omits
the `dev <iface>` tokens it prints in the unfiltered form, so the MAC is not at
a fixed column. The lookup must find it via the `lladdr` marker, not parts[4].
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

LIB_DIR = os.path.join(os.path.dirname(__file__), '..', 'lib')
sys.path.insert(0, LIB_DIR)

import substrate
from vm import vm_mac_address


def _completed(stdout="", returncode=0):
    return SimpleNamespace(stdout=stdout, returncode=returncode)


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
                 mock.patch.object(substrate, "VM_DHCP_LEASE_FILE", lease):
                self.assertEqual(substrate._vm_guest_ip(name), ip)


if __name__ == "__main__":
    unittest.main()
