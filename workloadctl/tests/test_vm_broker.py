"""The uid-keyed redirect to a host-side credential broker.

Values that appear in a shipped .nft file are spelled out here rather than
imported and re-derived: the point of the test is that the file and the module
agree, and a test that computes both sides from the same constant cannot fail
when they drift apart.
"""

import tempfile
import unittest
from pathlib import Path

from tests import load_script
from vm import (
    NFT_BROKER_MAP, NFT_BROKER_SKELETON, NFT_BROKER_TABLE, VM_BROKER_ENV_VAR,
    VM_BROKER_LISTEN_ADDR, VM_BROKER_LISTEN_PORT, VM_BROKER_PORT,
    VM_PROXY_ADDR, VM_PROXY_PORT, validate_vm_network, vm_broker_element,
    vm_broker_env, vm_broker_map_command, vm_uses_broker,
)

NFT_FILE = Path(__file__).resolve().parent.parent / "nftables" / "workload-broker.nft"


def config(**net):
    return {"vm": {"network": net}}


class TestUsesBroker(unittest.TestCase):

    def test_absent_key_means_no_broker(self):
        self.assertFalse(vm_uses_broker(config()))

    def test_false_means_no_broker(self):
        self.assertFalse(vm_uses_broker(config(broker=False)))

    def test_true_means_broker(self):
        self.assertTrue(vm_uses_broker(config(broker=True)))

    def test_a_bridged_vm_is_outside_this(self):
        """Nothing of ours is in a bridged guest's data path, so there is no uid
        to key the redirect on."""
        self.assertFalse(vm_uses_broker(config(broker=True, bridge="br0")))

    def test_a_container_workload_has_no_vm_section(self):
        self.assertFalse(vm_uses_broker({"container": {"image": "x"}}))


class TestElements(unittest.TestCase):

    def test_the_element_carries_the_listener_not_the_advertised_address(self):
        """The key is the uid and the value is where the broker actually is;
        the advertised address never appears in an element."""
        self.assertEqual(vm_broker_element(10000), "10000 : 127.0.0.1 . 8081")

    def test_add_and_delete_name_the_same_map(self):
        add = vm_broker_map_command(10000, "add")
        delete = vm_broker_map_command(10000, "delete")
        self.assertEqual(add[1], "add")
        self.assertEqual(delete[1], "delete")
        self.assertEqual(add[2:], ["element", "inet", "workload_broker",
                                   "wl_broker_dest", "{ 10000 : 127.0.0.1 . 8081 }"])

    def test_the_table_and_map_names_are_what_the_nft_file_declares(self):
        text = NFT_FILE.read_text()
        self.assertIn("add table inet workload_broker", text)
        self.assertIn("add map inet workload_broker wl_broker_dest", text)
        self.assertEqual(NFT_BROKER_TABLE, "inet workload_broker")
        self.assertEqual(NFT_BROKER_MAP, "wl_broker_dest")


class TestAdvertisedEndpoint(unittest.TestCase):
    """The endpoint the guest dials has to match the rule byte for byte -- the
    rule is a literal so the file stays applicable with a bare `nft -f`."""

    def test_the_rule_matches_the_advertised_address_and_port(self):
        text = NFT_FILE.read_text()
        self.assertIn("ip daddr 192.0.2.1 tcp dport 8081", text)
        self.assertEqual(VM_PROXY_ADDR, "192.0.2.1")
        self.assertEqual(VM_BROKER_PORT, 8081)

    def test_it_shares_the_proxy_address_but_not_its_port(self):
        """One dummy link and one host address serve both; the port is what
        separates them, so a collision here would silently route a guest's
        broker traffic into the hostname proxy."""
        self.assertNotEqual(VM_BROKER_PORT, VM_PROXY_PORT)

    def test_the_listener_is_not_the_advertised_address(self):
        """If these were equal the rule would translate to itself and loop."""
        self.assertNotEqual(VM_BROKER_LISTEN_ADDR, VM_PROXY_ADDR)
        self.assertEqual((VM_BROKER_LISTEN_ADDR, VM_BROKER_LISTEN_PORT),
                         ("127.0.0.1", 8081))

    def test_the_skeleton_path_is_the_packaged_one(self):
        self.assertEqual(NFT_BROKER_SKELETON,
                         "/usr/share/workloadctl/workload-broker.nft")
        self.assertTrue(NFT_FILE.exists())


class TestGuestEnv(unittest.TestCase):

    def test_no_broker_means_no_env(self):
        self.assertEqual(vm_broker_env(config()), {})

    def test_the_guest_is_told_the_advertised_endpoint(self):
        self.assertEqual(vm_broker_env(config(broker=True)),
                         {"WORKLOAD_BROKER_URL": "http://192.0.2.1:8081"})

    def test_the_url_is_an_ip_literal(self):
        """Reaching the broker must not depend on DNS -- which is exactly what
        a compromised guest would attack to escape policy."""
        url = vm_broker_env(config(broker=True))[VM_BROKER_ENV_VAR]
        self.assertNotIn("localhost", url)
        host = url.split("//", 1)[1].split(":", 1)[0]
        self.assertTrue(all(part.isdigit() for part in host.split(".")))

    def test_a_bridged_vm_is_told_nothing(self):
        self.assertEqual(vm_broker_env(config(broker=True, bridge="br0")), {})


class TestValidation(unittest.TestCase):

    def test_a_bool_is_accepted(self):
        self.assertEqual(
            [e for e in validate_vm_network({"broker": True}) if "broker" in e],
            [])

    def test_a_string_is_rejected(self):
        errors = validate_vm_network({"broker": "yes"})
        self.assertTrue(any("must be true or false" in e for e in errors))

    def test_broker_with_bridge_is_rejected(self):
        """Silently ignoring it would leave an operator believing a credential
        boundary exists."""
        errors = validate_vm_network({"broker": True, "bridge": "br0"})
        self.assertTrue(any("no effect with .bridge" in e for e in errors))

    def test_broker_false_with_bridge_is_not_an_error(self):
        errors = validate_vm_network({"broker": False, "bridge": "br0"})
        self.assertEqual([e for e in errors if "broker" in e], [])

    def test_broker_is_independent_of_egress_mode(self):
        """Unlike .hosts, this does not require filtering. The broker holds the
        credential either way, so an open VM still cannot obtain one -- there is
        no misreport to prevent."""
        for mode in ("filtered", "open"):
            errors = validate_vm_network({"broker": True, "egress": mode})
            self.assertEqual([e for e in errors if "broker" in e], [], mode)


class TestEveryVmRunsTheHelper(unittest.TestCase):
    """The entitlement is withdrawn as deliberately as it is granted.

    Emitting the ExecStartPre only for entitled VMs was the obvious reading and
    it leaves a hole: map elements are keyed by uid, get_next_uid() reuses the
    lowest free one, and an element that outlives its workload then belongs to
    whichever workload inherits that uid — one that runs no broker code and so
    never notices. The helper decides; the unit only has to call it.

    Which is why *every* VM calls it, bridged included. A bridged VM is never
    entitled, but it owns a uid like any other, and being outside the map is
    not the same as being outside the reuse that makes stale elements possible.
    Skipping the sweep for it left the inheriting workload as the one case the
    sweep did not cover.
    """

    @classmethod
    def setUpClass(cls):
        cls.gen = load_script("generators/workload-generate")

    def unit(self, **net):
        return self.gen.generate_vm_service(
            {"workload": {"name": "web"}, "vm": {"network": net}},
            "_wl-web", 10005)

    def test_an_entitled_vm_calls_it(self):
        self.assertIn('ExecStartPre=+/usr/libexec/workloadctl/workload-vm-broker up "web"',
                      self.unit(broker=True))

    def test_a_vm_without_a_broker_calls_it_too(self):
        """So that a uid inherited from a workload that had one is cleared."""
        self.assertIn('ExecStartPre=+/usr/libexec/workloadctl/workload-vm-broker up "web"',
                      self.unit())

    def test_the_call_is_not_tolerant(self):
        """A guest told to reach a broker nothing translates for it reports an
        unreachable API, not a missing entitlement."""
        unit = self.unit(broker=True)
        self.assertNotIn("ExecStartPre=-+/usr/libexec/workloadctl/workload-vm-broker",
                         unit)

    def test_the_element_is_withdrawn_on_stop_kill_and_failure(self):
        self.assertIn('ExecStopPost=-+/usr/libexec/workloadctl/workload-vm-broker down "web"',
                      self.unit(broker=True))

    def test_a_bridged_vm_sweeps_too(self):
        """It can never hold an element of its own — vm_uses_broker is False for
        it — but it can inherit one, which is what the sweep is for."""
        unit = self.unit(bridge="br0")
        self.assertIn('workload-vm-broker up "web"', unit)
        self.assertIn('ExecStopPost=-+/usr/libexec/workloadctl/workload-vm-broker '
                      'down "web"', unit)

    def test_a_bridged_vm_is_not_failed_by_the_sweep(self):
        """The one place tolerance is right. A bridged guest is never told a
        broker address, so nothing it does depends on this running — and a
        purely bridged host needs nftables for nothing else, so a missing nft
        must not take its VMs down."""
        self.assertIn('ExecStartPre=-+/usr/libexec/workloadctl/workload-vm-broker '
                      'up "web"', self.unit(bridge="br0"))

    def test_a_bridged_vm_still_gets_no_element(self):
        """The sweep is not an entitlement: the helper reads the config and a
        bridged VM never qualifies, whatever `broker` says."""
        self.assertFalse(vm_uses_broker(config(broker=True, bridge="br0")))


class TestRedirectLandsWhereTheBrokerListens(unittest.TestCase):
    """The destination of the redirect and the broker's own listener.

    These are two independent definitions of one address: VM_BROKER_LISTEN_ADDR
    and VM_BROKER_LISTEN_PORT are what every map element sends a guest's packet
    to, and the broker's config defaults are where it accepts one. They were a
    cross-repo constant that neither side checked until the broker moved into
    this package -- which is most of the reason it moved.

    A drift here is invisible from either side alone and produces a guest
    connection refused *after* translation: identical, from the guest, to the
    broker being down, to the workload having no map element, and to the
    advertised address not existing.
    """

    def defaults(self):
        """The broker's effective config when the operator sets neither key."""
        broker = load_script("libexec/agent-broker")
        with tempfile.NamedTemporaryFile("w", suffix=".toml") as fh:
            # upstream and credential are required; nothing here reads them.
            fh.write('upstream = "https://api.example.invalid"\n'
                     'credential = "unused"\n')
            fh.flush()
            return broker.load_config(fh.name)

    def test_address_matches(self):
        self.assertEqual(self.defaults()["listen_address"], VM_BROKER_LISTEN_ADDR)

    def test_port_matches(self):
        self.assertEqual(int(self.defaults()["listen_port"]), VM_BROKER_LISTEN_PORT)


if __name__ == "__main__":
    unittest.main()
