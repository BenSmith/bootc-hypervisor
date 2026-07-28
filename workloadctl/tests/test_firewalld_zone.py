#!/usr/bin/env python3
"""The shipped firewalld zone for the managed VM bridge, as an artifact.

The zone is what stands between a guest and a rejected DHCP lease, and nothing
else in the suite reads the file. Its three load-bearing properties are all
cross-file: the interface name must match VM_BRIDGE_NAME, the zone name must
match what the generator writes into workload-bridge.service, and the RPM must
actually install it. A mismatch in any of them is silent — the VM boots and
simply never gets an address.
"""
import re
import unittest
import xml.etree.ElementTree as ET

from tests import REPO_ROOT

from vm import VM_BRIDGE_FIREWALLD_ZONE, VM_BRIDGE_NAME

ZONE = REPO_ROOT / "firewalld" / "workloadctl.xml"
SPEC = REPO_ROOT / "rpm" / "workloadctl.spec"


class TestFirewalldZone(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = ET.fromstring(ZONE.read_text())
        cls.spec = SPEC.read_text()

    def test_zone_file_is_named_for_the_zone(self):
        # firewalld takes the zone name from the filename, not from the XML.
        self.assertEqual(ZONE.stem, VM_BRIDGE_FIREWALLD_ZONE)

    def test_binds_the_managed_bridge_by_name(self):
        # This binding is what survives `firewall-cmd --reload` (reload rebuilds
        # runtime state from permanent config, dropping the runtime
        # --change-interface the bridge service does).
        interfaces = [e.get("name") for e in self.root.findall("interface")]
        self.assertEqual(interfaces, [VM_BRIDGE_NAME])

    def test_target_accept_so_guest_traffic_is_forwarded(self):
        # Guests reach the outside world through the NAT masquerade
        # workload-bridge.service installs; a default-target zone would drop
        # those forwarded packets.
        self.assertEqual(self.root.get("target"), "ACCEPT")

    def test_host_facing_surface_is_dhcp_dns_and_icmp_then_reject(self):
        services = {e.get("name") for e in self.root.findall("service")}
        self.assertEqual(services, {"dhcp", "dns"})
        protocols = {e.get("value") for e in self.root.findall("protocol")}
        self.assertEqual(protocols, {"icmp", "ipv6-icmp"})
        # ssh is deliberately absent (nm-shared and libvirt both allow it):
        # workloadctl SSHes host -> guest, which returns on an established
        # connection, so guests never need to reach sshd on the host.
        self.assertNotIn("ssh", services)
        # Everything else host-directed is rejected by a lowest-priority rule;
        # without it, target=ACCEPT would expose every host port to guests.
        rules = self.root.findall("rule")
        self.assertEqual(len(rules), 1, ET.tostring(self.root))
        self.assertEqual(rules[0].get("priority"), "32767")
        self.assertIsNotNone(rules[0].find("reject"))

    def test_rpm_installs_the_zone_into_the_vendor_dir(self):
        # /usr/lib, not /etc/firewalld/zones: a copy in /etc shadows the shipped
        # one permanently, so later updates to the zone would stop applying.
        self.assertIn(
            "%{_prefix}/lib/firewalld/zones/workloadctl.xml", self.spec)
        self.assertRegex(
            self.spec,
            r"install -Dpm 0644 %\{_sourcedir\}/firewalld/workloadctl\.xml")
        self.assertNotIn("%{_sysconfdir}/firewalld", self.spec)

    def test_rpm_reloads_firewalld_so_a_running_daemon_sees_the_zone(self):
        # A running firewalld only learns about a new zone file on reload;
        # without this the first VM enabled after install finds no zone. Written
        # longhand rather than as firewalld-filesystem's %firewalld_reload:
        # an undefined macro expands to nothing, so building from a checkout on
        # a host without that package would silently drop the reload. One
        # occurrence in %post, one in %postun.
        reload_cmd = ("test -x /usr/bin/firewall-cmd && "
                      "firewall-cmd --reload --quiet || :")
        self.assertEqual(self.spec.count(reload_cmd), 2, self.spec)
        self.assertNotIn("firewalld_reload}", self.spec)
        self.assertIn("Requires:       firewalld-filesystem", self.spec)

    def test_zone_name_fits_firewalld_and_nftables_limits(self):
        self.assertLessEqual(len(VM_BRIDGE_FIREWALLD_ZONE), 17)
        self.assertRegex(VM_BRIDGE_FIREWALLD_ZONE, r"^[A-Za-z0-9_-]+$")

    def test_no_stale_libvirt_zone_reference_survives(self):
        # The bug this zone replaces: borrowing libvirt's zone, which does not
        # exist on a host without libvirt installed.
        generator = (REPO_ROOT / "generators" / "workload-generate").read_text()
        self.assertNotIn("--zone=libvirt", generator)
        self.assertNotRegex(ZONE.read_text(), r"zone=[\"']?libvirt")


if __name__ == "__main__":
    unittest.main()
