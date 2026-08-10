#!/usr/bin/env python3
"""Unit tests for the passt VM network backend (ADR 006).

Two things are worth stating about what this module chooses to test.

First, **the uid derivations are tested against spelled-out expected values**,
not against the formula that produced them. Re-deriving `127.128.0.0 + (uid -
UID_MIN)` in the test would only assert that the code agrees with itself, and
these values are load-bearing in a way that makes silent drift expensive: the
management address is where `workloadctl exec` connects, and the nflog group is
which workload's traffic a capture actually shows.

Second, **the per-family DNS rule gets more attention than its size suggests**,
because passt fails *open* here. Half-configuring a family does not break DNS;
it advertises the host's real nameservers to the guest, which is precisely the
disclosure the configuration exists to prevent. A test that only asked "does
DNS work" would pass on a leaking configuration.
"""

import importlib.machinery
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vm import (
    VM_MGMT_SSH_PORT,
    parse_vm_port,
    validate_vm_network,
    vm_management_address,
    vm_nflog_group,
)
from workload_lib import UID_MAX, UID_MIN


def _load(path, name):
    """Load one of the extension-less entrypoints as a module."""
    spec = importlib.util.spec_from_loader(
        name, importlib.machinery.SourceFileLoader(name, path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestUidDerivedValues(unittest.TestCase):
    """The uid is the network identity; everything else falls out of it."""

    def test_management_addresses_are_spelled_out(self):
        self.assertEqual(vm_management_address(10000), "127.128.0.0")
        self.assertEqual(vm_management_address(10003), "127.128.0.3")
        self.assertEqual(vm_management_address(10256), "127.128.1.0")
        self.assertEqual(vm_management_address(UID_MAX), "127.128.167.196")

    def test_nflog_groups_are_the_offset(self):
        self.assertEqual(vm_nflog_group(10000), 0)
        self.assertEqual(vm_nflog_group(10003), 3)
        self.assertEqual(vm_nflog_group(UID_MAX), UID_MAX - UID_MIN)

    def test_the_whole_uid_range_fits_its_targets(self):
        # 42,949 workloads must fit inside 127.128.0.0/9 and the 16-bit nflog
        # group space. The nflog half is the tighter of the two and the one
        # that would fail silently — a group number above 65535 would be
        # truncated by the kernel, so two workloads would share a capture.
        self.assertLess(vm_nflog_group(UID_MAX), 65536)
        self.assertTrue(vm_management_address(UID_MAX).startswith("127."))

    def test_base_avoids_the_debian_hosts_entry(self):
        # 127.0.1.1 is conventionally the system hostname in Debian's
        # /etc/hosts. Nothing in the range may collide with it.
        self.assertNotIn("127.0.1.1",
                         {vm_management_address(u)
                          for u in (UID_MIN, UID_MIN + 1, UID_MIN + 257)})

    def test_out_of_range_uids_raise_rather_than_wrap(self):
        # A uid outside the workload window would silently alias onto another
        # workload's address and capture group.
        for uid in (0, 999, UID_MIN - 1, UID_MAX + 1):
            with self.assertRaises(ValueError):
                vm_management_address(uid)
            with self.assertRaises(ValueError):
                vm_nflog_group(uid)

    def test_management_port_is_unprivileged(self):
        # passt binds this as the workload user, not as root, so it has to stay
        # above net.ipv4.ip_unprivileged_port_start (1024 by default). This is
        # why it is 2222 and not 22.
        self.assertGreater(VM_MGMT_SSH_PORT, 1024)


class TestPortSpecs(unittest.TestCase):
    def test_container_convention_forms(self):
        self.assertEqual(parse_vm_port("8080:80"), (None, 8080, 80, "tcp"))
        self.assertEqual(parse_vm_port("8080"), (None, 8080, 8080, "tcp"))
        self.assertEqual(parse_vm_port("8080:80/udp"), (None, 8080, 80, "udp"))
        self.assertEqual(parse_vm_port("127.0.0.1:8080:80"),
                         ("127.0.0.1", 8080, 80, "tcp"))
        self.assertEqual(parse_vm_port("[::1]:8080:80"), ("::1", 8080, 80, "tcp"))

    def test_bare_host_port_is_not_read_as_a_bind_address(self):
        # Regression: a bind-address branch matching a bare run of digits makes
        # "8080:80" parse as address 8080 / port 80, which binds the wrong
        # thing and is not obviously wrong when read back.
        addr, host, guest, _ = parse_vm_port("8080:80")
        self.assertIsNone(addr)
        self.assertEqual((host, guest), (8080, 80))

    def test_malformed_specs_rejected(self):
        for spec in ("bad", "0:80", "70000", "999.1.1.1:80", "8080:80/sctp", ""):
            with self.assertRaises(ValueError, msg=spec):
                parse_vm_port(spec)


class TestNetworkValidation(unittest.TestCase):
    def test_empty_section_selects_passt_but_needs_an_egress_decision(self):
        # An empty [vm.network] selects passt, but `egress` defaults to
        # "filtered" and the implicit allow that would make an empty allowlist
        # workable is the per-workload proxy, which is a later step. So until
        # the proxy exists the operator has to say which way they want it --
        # loudly, because a VM that is silently unfiltered while the config
        # reads "filtered" is the exact misreport this layer exists to prevent.
        errs = validate_vm_network({})
        self.assertTrue(any("could reach nothing at all" in e for e in errs))

    def test_an_explicit_decision_either_way_is_valid(self):
        self.assertEqual(validate_vm_network({"egress": "open"}), [])
        self.assertEqual(
            validate_vm_network({"allow": ["192.168.0.10:22"]}), [])

    def test_ports_are_rejected_alongside_a_bridge(self):
        # A bridged guest has its own LAN address and nothing of ours is in its
        # data path to bind host ports with, so accepting these would produce a
        # config that reads as if ports were published when none are.
        errs = validate_vm_network({"bridge": "br0", "ports": ["8080:80"]})
        self.assertTrue(any("no effect with .bridge" in e for e in errs))

    def test_outbound_if_rejected_alongside_a_bridge(self):
        errs = validate_vm_network({"bridge": "br0", "outbound_if": "eno1"})
        self.assertTrue(any("no effect with .bridge" in e for e in errs))

    def test_resolver_enum(self):
        # egress is spelled out so these assert only about `resolver`.
        for mode in ("host", "none"):
            self.assertEqual(
                validate_vm_network({"resolver": mode, "egress": "open"}), [])
        self.assertTrue(
            validate_vm_network({"resolver": "lan", "egress": "open"}))

    def test_egress_enum(self):
        self.assertEqual(
            validate_vm_network({"egress": "filtered",
                                 "allow": ["10.0.0.1:22"]}), [])
        self.assertTrue(any(
            "must be one of" in e
            for e in validate_vm_network({"egress": "strict"})))

    def test_allow_entries_must_be_addresses_not_hostnames(self):
        # The allowlist becomes elements of a set keyed on ip/ip6 daddr. A
        # hostname would have to be resolved once at unit start and would then
        # be silently wrong for the life of the VM the moment the record moved.
        errs = validate_vm_network({"allow": ["git.example:22"]})
        self.assertTrue(any("Addresses only" in e for e in errs), errs)

    def test_allow_accepts_both_families(self):
        self.assertEqual(
            validate_vm_network({"allow": ["10.0.0.1:22",
                                           "[2001:db8::1]:443"]}), [])

    def test_allow_rejects_a_bare_v6_address_without_brackets(self):
        # Unbracketed, the final ':' before the port is ambiguous with the
        # address's own colons.
        self.assertTrue(validate_vm_network({"allow": ["2001:db8::1:22"]}))

    def test_allow_port_range(self):
        self.assertTrue(any("out of range" in e for e in
                            validate_vm_network({"allow": ["10.0.0.1:70000"]})))

    def test_egress_keys_are_rejected_alongside_a_bridge(self):
        # A bridged guest sends from its own LAN address, so no host socket
        # carries the workload uid and there is nothing for the filter to match.
        for key, value in (("egress", "filtered"), ("allow", ["10.0.0.1:22"])):
            errs = validate_vm_network({"bridge": "br0", key: value})
            self.assertTrue(any("no effect with .bridge" in e for e in errs),
                            f"{key}: {errs}")

    def test_a_bridged_vm_needs_no_egress_decision(self):
        # The filtered-with-empty-allow error must not fire here: the escape
        # hatch is unfiltered by definition, not by omission.
        self.assertEqual(validate_vm_network({"bridge": "br0"}), [])

    def test_bridge_name_must_be_a_valid_interface(self):
        self.assertTrue(validate_vm_network({"bridge": "this-name-is-far-too-long"}))
        self.assertTrue(validate_vm_network({"bridge": "bad name"}))
        self.assertEqual(validate_vm_network({"bridge": "br0"}), [])


class TestNetdevDnsDerivation(unittest.TestCase):
    """libexec/workload-vm-netdev — the host-derived half of the netdev.

    passt's DNS handling is per address family and half-configuring a family
    fails open: supplying `--dns` for one family suppresses only that family's
    branch of the resolv.conf scan, leaving the other to advertise the host's
    real nameservers over NDP RDNSS / DHCPv6.
    """

    @classmethod
    def setUpClass(cls):
        cls.mod = _load("libexec/workload-vm-netdev", "workload_vm_netdev")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _resolv_conf(self, text):
        """Point the module's RESOLV_CONF at a real file holding `text`."""
        path = Path(self.tmp.name) / "resolv.conf"
        path.write_text(text)
        return mock.patch.object(self.mod, "RESOLV_CONF", path)

    def test_single_family_uses_the_native_properties(self):
        fragment, _ = self.mod.build_dns_fragment(
            {4: "192.168.0.1"}, {4: "127.0.0.53"})
        self.assertEqual(
            fragment,
            "dns-forward=192.168.0.1,dns=192.168.0.1,dns-host=127.0.0.53")

    def test_second_family_goes_through_param(self):
        # The QEMU netdev's dns-forward/dns/dns-host properties are
        # single-valued, so only one family can use them; the other has to go
        # through the repeatable param= escape hatch.
        fragment, _ = self.mod.build_dns_fragment(
            {4: "192.168.0.1", 6: "fd00::1"},
            {4: "127.0.0.53", 6: "fd00::53"})
        self.assertIn("dns-forward=192.168.0.1", fragment)
        self.assertIn("param=--dns-forward,param=fd00::1", fragment)
        self.assertIn("param=--dns-host,param=fd00::53", fragment)

    def test_a_family_without_a_resolver_is_omitted_entirely(self):
        # THE leak case. Emitting --dns for v6 without --dns-host suppresses
        # the scan that would have defaulted ip6.dns_host, so IPv6 DNS flows
        # get rewritten to an unspecified address. Omitting the family is safe:
        # the scan runs, finds nothing, advertises nothing.
        fragment, _ = self.mod.build_dns_fragment(
            {4: "192.168.0.1", 6: "fd00::1"}, {4: "127.0.0.53"})
        self.assertNotIn("fd00::1", fragment)
        self.assertNotIn("param=", fragment)

    def test_a_family_without_a_gateway_is_omitted_entirely(self):
        fragment, _ = self.mod.build_dns_fragment(
            {4: "192.168.0.1"}, {4: "127.0.0.53", 6: "fd00::53"})
        self.assertNotIn("fd00::53", fragment)

    def test_all_three_or_none_holds_for_every_family(self):
        for gateways, resolvers in (
            ({4: "192.168.0.1"}, {4: "127.0.0.53"}),
            ({4: "192.168.0.1", 6: "fd00::1"}, {4: "127.0.0.53", 6: "fd00::53"}),
            ({4: "192.168.0.1", 6: "fd00::1"}, {4: "127.0.0.53"}),
            ({6: "fd00::1"}, {6: "fd00::53"}),
        ):
            fragment, _ = self.mod.build_dns_fragment(gateways, resolvers)
            # Count the option occurrences: forward and host must
            # appear the same number of times, once per configured family.
            forwards = fragment.count("dns-forward")
            hosts = fragment.count("dns-host")
            self.assertEqual(forwards, hosts, fragment)

    def test_no_resolver_at_all_yields_a_non_empty_fallback(self):
        # An empty expansion would leave a dangling comma in the netdev
        # argument and QEMU would refuse to start, so "no DNS" has to be
        # spelled explicitly rather than as the empty string.
        fragment, notes = self.mod.build_dns_fragment({}, {})
        self.assertEqual(fragment, "dhcp-dns=off")
        self.assertTrue(fragment)
        self.assertTrue(any("no usable resolver" in n for n in notes))

    def test_resolv_conf_parsing_takes_the_first_per_family(self):
        text = (
            "# comment\n"
            "search internal.example\n"
            "nameserver 127.0.0.53\n"
            "nameserver 192.168.0.3\n"
            "nameserver fd00::53\n"
            "nameserver fd00::54\n"
        )
        with self._resolv_conf(text):
            self.assertEqual(self.mod.host_resolvers(),
                             {4: "127.0.0.53", 6: "fd00::53"})

    def test_loopback_resolvers_are_kept(self):
        # dns-host is where passt sends the query host-side, where a stub
        # resolver is reachable. It is never disclosed to the guest, so there
        # is no reason to skip it — and skipping it would break DNS on every
        # systemd-resolved host.
        with self._resolv_conf("nameserver 127.0.0.53\n"):
            self.assertEqual(self.mod.host_resolvers(), {4: "127.0.0.53"})

    def test_unreadable_resolv_conf_is_not_fatal(self):
        missing = Path(self.tmp.name) / "does-not-exist"
        with mock.patch.object(self.mod, "RESOLV_CONF", missing):
            self.assertEqual(self.mod.host_resolvers(), {})

    def test_link_local_gateway_is_not_used(self):
        # An fe80::/10 gateway is scoped to an interface, so handing it to the
        # guest as a resolver address gives it something it cannot disambiguate.
        completed = mock.MagicMock(returncode=0,
                                   stdout="default via fe80::1 dev eth0\n")
        with mock.patch.object(self.mod.subprocess, "run",
                               return_value=completed):
            self.assertEqual(self.mod.default_gateways(), {})

    def test_missing_ip_binary_is_not_fatal(self):
        with mock.patch.object(self.mod.subprocess, "run",
                               side_effect=OSError("no ip")):
            self.assertEqual(self.mod.default_gateways(), {})


class TestPasstRunsAsTheWorkloadUser(unittest.TestCase):
    """The uid QEMU is started with IS the VM's network identity.

    passt inherits the uid of whoever spawns it, and every uid-derived value in
    ADR 006 -- the management address, the nflog group, and (from step 2) the
    `meta skuid` egress rule -- is keyed on that inheritance holding.

    It holds only because the VM unit carries `User=_wl-<name>`. Started as
    root, passt does not fail: it logs `Started as root, will change to nobody`
    once and drops to `nobody`, after which traffic keeps flowing normally
    while every VM on the host shares one uid and per-workload policy silently
    matches nothing. Measured on Fedora 44 / passt 0^20260728 / QEMU 10.2.2
    (2026-08-10): as a normal user the helper runs as that user; under `sudo`
    the same command line yields `nobody passt --quiet ...`.

    Because the degraded mode is indistinguishable from the working one at the
    traffic level, the `User=` directive is asserted here rather than left to
    the snapshot test, which would accept its removal as a rendering change.
    """

    def test_vm_unit_sets_user_so_passt_inherits_the_workload_uid(self):
        from tests.test_generator_snapshot import render_matrix

        units = {name: text for name, text in render_matrix().items()
                 if name.startswith("vm-")}
        self.assertTrue(units, "no VM fixtures rendered")

        checked = 0
        for name, text in units.items():
            # Setup/build helpers legitimately run as root (they create the
            # user and write into /var before it can be resolved); the unit
            # that execs QEMU must not.
            if "qemu-system" not in text:
                continue
            checked += 1
            self.assertRegex(
                text, r"(?m)^User=_wl-",
                f"{name} execs QEMU without User=_wl-<name>; passt would "
                f"inherit root and silently drop to nobody")
        self.assertGreater(checked, 0, "no rendered unit execs QEMU")


if __name__ == "__main__":
    unittest.main()
