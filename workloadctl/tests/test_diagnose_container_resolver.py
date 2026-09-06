#!/usr/bin/env python3
"""A `[network]` trigger can take a container's DNS away, and only the host knows.

The property, read straight off nftables/workload-filter.nft: a workload with
any `[network]` trigger has its uid put in `wl_filtered`, and the last rule in
the output chain drops everything from a `wl_filtered` uid that no earlier rule
accepted. The accepts are the 80/443 redirect, the reply direction of an
accepted connection, the workload's own `[[network.allow]]` elements, and
`oif lo`. There is a port-53 accept in that file and it does NOT cover this --
it is scoped to `wl_egress_cg`, the inspector's own cgroup, which a container
is never in.

So DNS survives or dies on a fact about the HOST, not about the workload:

  - a loopback stub in resolv.conf (127.0.0.53) is re-originated to loopback
    and accepted by `oif lo`;
  - a LAN resolver is a workload-uid socket to a routable address on port 53,
    which no rule accepts.

WHY THIS FILE EXISTS. The second case has never been observed on hardware, and
that is the finding rather than a reassurance: every host the container egress
rig has ever run on uses the systemd-resolved stub, so all 78 rows passed
through the `oif lo` accept without anyone choosing it. The break is invisible
to the whole unit suite for the same reason it is invisible to the rig -- it is
a property of a file neither of them reads. Cf. the project's standing lesson
that a control can enforce perfectly and name nothing.

The symptom carries no route to the cause: every unit is active, the inspector
is listening, and inside the container every name fails at once. This check is
the only thing on the host that sees both halves, so the wiring cases below go
through collect_diagnose_checks rather than calling the function directly -- a
check nobody calls passes its own tests and reports nothing.
"""

import ipaddress
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import cmd_diagnose
import workload_lib
from workloadctl_core import WorkloadConfig

UID = 10001

FILTERED_TOML = """\
[workload]
name = "capp"

[container]
image = "localhost/app:latest"

[network]
hosts = ["example.invalid"]
"""

# No trigger, so no wl_filtered membership and no drop to be caught by.
UNFILTERED_TOML = """\
[workload]
name = "plain"

[container]
image = "localhost/app:latest"
"""

# A VM has a synthesising responder of its own (D7 gives containers none), so
# its resolver path does not go through this rule at all.
VM_TOML = """\
[workload]
name = "vmw"

[vm]
memory = "2G"
vcpus = 2
image = "https://example.invalid/cloud.qcow2"

[vm.network]
egress = "filtered"
hosts = ["example.invalid"]
"""


def _ip(*addrs):
    return [ipaddress.ip_address(a) for a in addrs]


class ContainerResolverCheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(
            mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        for name, toml in (("capp", FILTERED_TOML),
                           ("plain", UNFILTERED_TOML),
                           ("vmw", VM_TOML)):
            (self.tmp / name).mkdir()
            (self.tmp / name / "workload.toml").write_text(toml)
        self.enterContext(mock.patch.object(
            WorkloadConfig, "uid", new_callable=mock.PropertyMock,
            return_value=UID))

    def _run(self, name="capp", **kwargs):
        return cmd_diagnose.container_resolver_check(
            WorkloadConfig(name), **kwargs)

    # --- the host that has never been tested ---------------------------------

    def test_a_lan_resolver_with_no_allow_entry_fails(self):
        _, ok, message = self._run(nameservers=_ip("192.168.0.1"), armed=set())
        self.assertFalse(ok)
        self.assertIn("192.168.0.1", message)
        # The remedy has to be the actual TOML, not "add an allow entry":
        # the entry needs port 53 specifically, and an operator who writes it
        # without the port arms nothing that matches.
        self.assertIn("[[network.allow]]", message)
        self.assertIn("port    = 53", message)
        self.assertIn('address = "192.168.0.1"', message)

    def test_the_message_says_the_allowlist_itself_stops_resolving(self):
        """The part that makes this counter-intuitive enough to need saying:
        the workload cannot resolve the very hostnames its own [network].hosts
        names, so the trigger disables the thing it was written to enable."""
        _, _, message = self._run(nameservers=_ip("192.168.0.1"), armed=set())
        self.assertIn("allowlist", message)

    # --- the host every hardware run has used --------------------------------

    def test_a_loopback_stub_passes_without_any_allow_entry(self):
        check, ok, message = self._run(
            nameservers=_ip("127.0.0.53"), armed=set())
        self.assertEqual(check, "container_resolver")
        self.assertTrue(ok, message)

    def test_an_armed_allow_entry_on_53_passes(self):
        _, ok, message = self._run(nameservers=_ip("192.168.0.1"),
                                   armed={("192.168.0.1", "53")})
        self.assertTrue(ok, message)

    def test_an_allow_entry_on_another_port_does_not_count(self):
        """The element is (uid, address, port). An entry for the resolver's
        address on 443 authorises nothing on 53, and reading it as coverage
        would report DNS healthy on a host where it is dropped."""
        _, ok, _ = self._run(nameservers=_ip("192.168.0.1"),
                             armed={("192.168.0.1", "443")})
        self.assertFalse(ok)

    def test_a_v6_resolver_is_read_from_the_v6_set(self):
        _, ok, message = self._run(nameservers=_ip("2001:db8::1"),
                                   armed={("2001:db8::1", "53")})
        self.assertTrue(ok, message)

    def test_loopback_v6_is_accepted_by_oif_lo_too(self):
        _, ok, message = self._run(nameservers=_ip("::1"), armed=set())
        self.assertTrue(ok, message)

    # --- the mixed host, which is not the same finding -----------------------

    def test_a_reachable_resolver_beside_a_blocked_one_is_still_reported(self):
        """Not a pass: resolution works only while the loopback stub answers,
        and the fallback the host would ride out is dropped for this workload
        alone. Not the total-failure message either -- telling an operator
        their container resolves nothing when it currently resolves fine is
        how a check gets ignored."""
        _, ok, message = self._run(
            nameservers=_ip("127.0.0.53", "192.168.0.1"), armed=set())
        self.assertFalse(ok)
        self.assertIn("192.168.0.1", message)
        self.assertIn("127.0.0.53", message)
        self.assertNotIn("resolves NOTHING", message)

    def test_the_total_case_says_so_in_those_words(self):
        _, ok, message = self._run(nameservers=_ip("192.168.0.1"), armed=set())
        self.assertFalse(ok)
        self.assertIn("resolves NOTHING", message)

    # --- when to say nothing at all ------------------------------------------

    def test_an_unfiltered_container_gets_no_line(self):
        # No trigger, no wl_filtered membership, no drop. A line here would
        # be a finding about a rule this workload never meets.
        self.assertIsNone(self._run("plain", nameservers=_ip("192.168.0.1"),
                                    armed=set()))

    def test_a_vm_gets_no_line(self):
        self.assertIsNone(self._run("vmw", nameservers=_ip("192.168.0.1"),
                                    armed=set()))

    def test_an_unreadable_resolv_conf_asserts_nothing(self):
        # None and [] are different answers: unreadable is no opinion, and
        # reporting a failure off a file we could not open would be a guess.
        self.assertIsNone(self._run(nameservers=None, armed=set()))

    def test_a_resolv_conf_naming_no_resolver_asserts_nothing(self):
        self.assertIsNone(self._run(nameservers=[], armed=set()))


class HostNameserversTests(unittest.TestCase):
    def _parse(self, text):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "resolv.conf"
            path.write_text(text)
            return cmd_diagnose.host_nameservers(path)

    def test_reads_every_nameserver_line(self):
        self.assertEqual(
            self._parse("search lan\nnameserver 192.168.0.1\n"
                        "nameserver 192.168.0.2\n"),
            _ip("192.168.0.1", "192.168.0.2"))

    def test_a_comment_is_not_a_nameserver(self):
        self.assertEqual(
            self._parse("# nameserver 10.0.0.1\nnameserver 192.168.0.1\n"),
            _ip("192.168.0.1"))

    def test_a_trailing_comment_is_stripped(self):
        self.assertEqual(
            self._parse("nameserver 192.168.0.1 # the router\n"),
            _ip("192.168.0.1"))

    def test_a_v6_scope_id_is_dropped(self):
        # The zone qualifies the address for a sender; the filter matches on
        # the address, and both sides of that comparison come from places
        # that record no zone.
        self.assertEqual(self._parse("nameserver fe80::1%eth0\n"),
                         _ip("fe80::1"))

    def test_options_and_junk_are_ignored_rather_than_raising(self):
        self.assertEqual(
            self._parse("options edns0\nnameserver\nnameserver not-an-ip\n"
                        "nameserver 192.168.0.1\n"),
            _ip("192.168.0.1"))

    def test_a_missing_file_is_none_and_not_empty(self):
        self.assertIsNone(
            cmd_diagnose.host_nameservers(Path("/nonexistent/resolv.conf")))


class ResolverCheckIsWiredTests(unittest.TestCase):
    """The check is emitted by the battery, on a real config.

    Deleting the two-line call from collect_diagnose_checks leaves every test
    above green -- verified by mutation, which is why this class exists.
    """

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(
            mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        for name, toml in (("capp", FILTERED_TOML), ("vmw", VM_TOML)):
            (self.tmp / name).mkdir()
            (self.tmp / name / "workload.toml").write_text(toml)
        self.manager = mock.Mock()
        self.manager.user_exists.return_value = True
        self.manager.get_image_id.return_value = "sha256:" + "0" * 64
        self.manager.podman.return_value.image_id.return_value = (
            "sha256:" + "0" * 64)
        self.enterContext(mock.patch.object(
            WorkloadConfig, "uid", new_callable=mock.PropertyMock,
            return_value=UID))
        self.enterContext(mock.patch.object(
            cmd_diagnose.subprocess, "run",
            return_value=mock.Mock(returncode=1, stdout="", stderr="")))
        self.enterContext(mock.patch.object(
            cmd_diagnose, "service_active", return_value=(False, "inactive")))
        self.enterContext(mock.patch.object(
            cmd_diagnose, "host_nameservers", return_value=_ip("192.168.0.1")))
        self.enterContext(mock.patch.object(
            cmd_diagnose, "_nft_json", return_value=None))

    def _checks(self, name):
        checks, _ = cmd_diagnose.collect_diagnose_checks(
            WorkloadConfig(name), self.manager)
        return checks

    def test_a_filtered_container_gets_the_line(self):
        names = {c["check"] for c in self._checks("capp")}
        self.assertIn("container_resolver", names)

    def test_a_vm_does_not(self):
        names = {c["check"] for c in self._checks("vmw")}
        self.assertNotIn("container_resolver", names)

    def test_it_lands_before_the_allow_drift_line(self):
        # The workload resolves a name before it dials what it was told, and
        # an operator who meets the dial's verdict first is sent after the
        # wrong thing -- the same ordering vm_resolve_check is placed for.
        order = [c["check"] for c in self._checks("capp")]
        if "container_resolver" in order and "allow_drift" in order:
            self.assertLess(order.index("container_resolver"),
                            order.index("allow_drift"))


if __name__ == "__main__":
    unittest.main()
