"""The uid-keyed redirect to a host-side credential broker.

Values that appear in a shipped .nft file are spelled out here rather than
imported and re-derived: the point of the test is that the file and the module
agree, and a test that computes both sides from the same constant cannot fail
when they drift apart.
"""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from tests import load_script
from vm import (
    NFT_BROKER_MAP, NFT_BROKER_SKELETON, NFT_BROKER_TABLE, VM_BROKER_ENV_VAR,
    VM_BROKER_LISTEN_ADDR, VM_BROKER_LISTEN_PORT, VM_BROKER_PORT,
    VM_ADVERTISED_ADDR, validate_vm_network, vm_broker_element,
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
        self.assertEqual(VM_ADVERTISED_ADDR, "192.0.2.1")
        self.assertEqual(VM_BROKER_PORT, 8081)

    def test_it_is_the_only_thing_at_the_advertised_address(self):
        """Through rung 1 the advertised address carried two services and the
        port was what separated them -- a collision would have routed a guest's
        broker traffic into the hostname proxy. Rung 2 deleted the proxy, so
        this asserts the weaker thing that is now true: the skeleton has exactly
        one rule matching the advertised address, and it is the broker's."""
        rules = [ln for ln in NFT_FILE.read_text().splitlines()
                 if ln.startswith("add rule") and VM_ADVERTISED_ADDR in ln]
        self.assertEqual(len(rules), 1, rules)
        self.assertIn(f"tcp dport {VM_BROKER_PORT}", rules[0])

    def test_the_listener_is_not_the_advertised_address(self):
        """If these were equal the rule would translate to itself and loop."""
        self.assertNotEqual(VM_BROKER_LISTEN_ADDR, VM_ADVERTISED_ADDR)
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

    THE ADDRESS HALF IS RETIRED, and it is retired rather than moved. It pinned
    VM_BROKER_LISTEN_ADDR against the broker's `listen_address` DEFAULT, and
    that default is gone: an instance now binds the address derived from its own
    workload's uid, and defaulting it to 127.0.0.1 is the specific mistake ADR
    007 names as growing the hole decision 6 closes. So there is no second
    definition left to compare against -- the reconciliation is a render
    assertion on the generated config, and lives with the generator.

    What replaces it here is the assertion that the default is ABSENT, because
    "the pin was retired" and "the pin was quietly deleted along with the
    property" are the two ways this class could stop mentioning the address, and
    only one of them is correct.
    """

    def defaults(self):
        """The broker's effective config when the operator sets neither key."""
        broker = load_script("libexec/agent-broker")
        with tempfile.NamedTemporaryFile("w", suffix=".toml") as fh:
            fh.write('listen_address = "127.129.0.3"\n'
                     'upstream = "https://api.example.invalid"\n'
                     'credential = "unused"\n'
                     '[sandboxes.agent.hosts."api.example.invalid"]\n')
            fh.flush()
            return broker.load_config(fh.name)

    def test_there_is_no_listen_address_default_to_agree_with(self):
        broker = load_script("libexec/agent-broker")
        with tempfile.NamedTemporaryFile("w", suffix=".toml") as fh:
            fh.write('upstream = "https://api.example.invalid"\n'
                     'credential = "unused"\n'
                     '[sandboxes.agent.hosts."api.example.invalid"]\n')
            fh.flush()
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    broker.load_config(fh.name)
        self.assertIn("no safe default", str(caught.exception))
        self.assertNotEqual(VM_BROKER_LISTEN_ADDR, "")

    def test_port_matches(self):
        """The port half survives, and has to: the map elements this file is
        about still carry VM_BROKER_LISTEN_PORT, and the broker still defaults
        to 8081. The two go together, and both go in the same commit."""
        self.assertEqual(int(self.defaults()["listen_port"]), VM_BROKER_LISTEN_PORT)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Rung 6 T4: the generated per-workload instance
#
# Everything above this line is about the RETIRED shape -- one host-wide broker
# reached at an advertised endpoint through a uid-keyed nft map. Everything
# below is about the instance that replaces it: generated per workload, bound to
# an address derived from that workload's uid, and dialled only by that
# workload's inspector. The two coexist for one rung; T6 deletes the first.
# ---------------------------------------------------------------------------

from vm import (  # noqa: E402  (deliberately after the retired-shape imports)
    UID_MIN, VM_BROKER_BIN, VM_BROKER_INSTANCE_PORT, VM_CA_ENV_VARS,
    VM_RESERVED_GUEST_ENV,
    render_vm_broker_config, vm_broker_config_path, vm_broker_credential,
    vm_broker_hosts, vm_broker_listen_address, vm_broker_upstream_addresses,
    vm_credential_env, vm_host_resolver_addresses, vm_uses_credentials,
)
import tomllib


def cred_config(name="agent", **net):
    """A filtered VM declaring one credential-backed host."""
    base = {
        "egress": "filtered",
        "hosts": ["api.example.test"],
        "credential": [{"name": "example-token",
                        "placeholder": "sk-000000PLACEHOLDER",
                        "env": "EXAMPLE_API_KEY"}],
        "policy": [{"host": "api.example.test", "credential": "example-token"}],
    }
    base.update(net)
    return {"workload": {"name": name}, "vm": {"network": base}}


class TestUsesCredentials(unittest.TestCase):
    """Which workloads get an instance at all.

    Both halves of the predicate matter and only one is obvious. The declared
    credential is the obvious half. The inspection half is what stops a bridged
    or unfiltered VM from getting a unit that decrypts a provider key for a path
    that does not exist -- nothing dials the broker but the inspector, now that
    the advertised endpoint is gone.
    """

    def test_a_filtered_vm_with_a_credential_gets_one(self):
        self.assertTrue(vm_uses_credentials(cred_config()))

    def test_no_credential_blocks_means_no_instance(self):
        cfg = cred_config()
        cfg["vm"]["network"]["credential"] = []
        cfg["vm"]["network"]["policy"] = [{"host": "api.example.test"}]
        self.assertFalse(vm_uses_credentials(cfg))

    def test_a_bridged_vm_gets_none_even_declaring_one(self):
        self.assertFalse(vm_uses_credentials(cred_config(bridge="br0")))

    def test_an_open_egress_vm_gets_none(self):
        self.assertFalse(vm_uses_credentials(cred_config(egress="open")))

    def test_a_container_workload_is_not_a_vm(self):
        self.assertFalse(vm_uses_credentials({"workload": {"name": "web"},
                                              "container": {"image": "x"}}))


class TestTheGeneratedConfig(unittest.TestCase):
    """render_vm_broker_config -- what the instance is told, and what it is not.

    The address assertions are NEGATIVE as well as positive on purpose. Both
    wrong values (127.0.0.1, the broker's own retired default, and 0.0.0.0) put
    one workload's broker where every other workload's inspector is dialling,
    which is exactly the hole ADR 007 decision 6 closes; a test that only
    asserted the derived value would pass on a render that also bound the world.
    """

    def render(self, cfg=None, uid=UID_MIN + 5):
        return render_vm_broker_config(cfg or cred_config(), uid)

    def test_it_is_parseable_toml(self):
        tomllib.loads(self.render())

    def test_the_listen_address_is_the_uid_derived_one(self):
        cfg = tomllib.loads(self.render())
        self.assertEqual(cfg["listen_address"],
                         vm_broker_listen_address(UID_MIN + 5))

    def test_the_listen_address_is_never_localhost_or_the_world(self):
        for uid in (UID_MIN, UID_MIN + 1, UID_MIN + 300):
            addr = tomllib.loads(self.render(uid=uid))["listen_address"]
            self.assertNotIn(addr, ("127.0.0.1", "0.0.0.0", "::", "*"))

    def test_the_port_is_the_instance_port(self):
        self.assertEqual(tomllib.loads(self.render())["listen_port"],
                         VM_BROKER_INSTANCE_PORT)

    def test_the_sandbox_key_is_the_workload_name(self):
        """The broker resolves a caller's uid to a workload NAME and looks it
        up here; a key that is anything else refuses every request."""
        cfg = tomllib.loads(self.render(cred_config(name="myagent")))
        self.assertEqual(list(cfg["sandboxes"]), ["myagent"])

    def test_the_host_row_carries_the_upstream_and_the_credential_id(self):
        row = tomllib.loads(self.render())["sandboxes"]["agent"]["hosts"][
            "api.example.test"]
        self.assertEqual(row["upstream"], "https://api.example.test")
        _path, cred_id = vm_broker_credential("agent", "example-token")
        self.assertEqual(row["credential"], cred_id)
        self.assertEqual(row["placeholder"], "sk-000000PLACEHOLDER")

    def test_the_upstream_carries_no_path(self):
        """A base path here would be prepended to the request the inspector
        already matched against `paths`, so the origin would be sent a target
        no rule in this design ever saw."""
        row = tomllib.loads(self.render())["sandboxes"]["agent"]["hosts"][
            "api.example.test"]
        self.assertEqual(row["upstream"].count("/"), 2)

    def test_a_host_with_no_credential_gets_no_row(self):
        cfg = cred_config()
        cfg["vm"]["network"]["policy"].append({"host": "plain.example.test"})
        hosts = tomllib.loads(self.render(cfg))["sandboxes"]["agent"]["hosts"]
        self.assertEqual(list(hosts), ["api.example.test"])

    def test_two_hosts_may_share_one_credential(self):
        cfg = cred_config()
        cfg["vm"]["network"]["hosts"].append("api2.example.test")
        cfg["vm"]["network"]["policy"].append(
            {"host": "api2.example.test", "credential": "example-token"})
        hosts = tomllib.loads(self.render(cfg))["sandboxes"]["agent"]["hosts"]
        self.assertEqual(sorted(hosts), ["api.example.test", "api2.example.test"])

    def test_a_placeholder_carrying_a_quote_does_not_break_the_file(self):
        cfg = cred_config()
        cfg["vm"]["network"]["credential"][0]["placeholder"] = 'a"b\\c'
        row = tomllib.loads(self.render(cfg))["sandboxes"]["agent"]["hosts"][
            "api.example.test"]
        self.assertEqual(row["placeholder"], 'a"b\\c')

    def test_the_config_path_is_under_the_units_runtime_directory(self):
        self.assertEqual(str(vm_broker_config_path("agent")),
                         "/run/workloadctl/broker/agent/broker.toml")


class TestTheCredentialId(unittest.TestCase):
    """The systemd credential id is the SEAL name, and it carries the workload.

    systemd-creds binds the id into the blob and verifies it on decrypt, so a
    generated unit pointing at another workload's file -- the path is guessable
    -- fails at start instead of serving that workload's key. Asked of
    cmd_secret rather than spelled twice.
    """

    def test_it_matches_what_cmd_secret_seals_under(self):
        from cmd_secret import credential_path
        path, cred_id = vm_broker_credential("agent", "example-token")
        expected_path, expected_id = credential_path(
            Path("/etc/credstore.encrypted"), "broker/agent/example-token")
        self.assertEqual((path, cred_id), (expected_path, expected_id))

    def test_it_carries_the_workload_name(self):
        _path, cred_id = vm_broker_credential("agent", "example-token")
        self.assertEqual(cred_id, "broker-agent-example-token")

    def test_two_workloads_get_different_ids_for_one_credential_name(self):
        _p1, a = vm_broker_credential("one", "token")
        _p2, b = vm_broker_credential("two", "token")
        self.assertNotEqual(a, b)


class TestTheGeneratedUnit(unittest.TestCase):
    """The instance's unit. Four properties, each load-bearing on its own."""

    @classmethod
    def setUpClass(cls):
        cls.gen = load_script("generators/workload-generate")

    def unit(self, cfg=None, uid=UID_MIN + 5):
        return self.gen.generate_vm_broker_service(cfg or cred_config(), uid)

    def test_it_runs_as_a_dynamic_user_and_never_as_the_workload(self):
        """The whole of ADR 007's protection. The inspector runs as the uid
        QEMU runs as; this must not, or a guest escape obtains the key."""
        unit = self.unit()
        self.assertIn("DynamicUser=yes", unit)
        self.assertNotIn("User=_wl-", unit)

    def test_one_load_credential_line_per_declared_credential(self):
        cfg = cred_config()
        cfg["vm"]["network"]["hosts"].append("api2.example.test")
        cfg["vm"]["network"]["policy"].append(
            {"host": "api2.example.test", "credential": "example-token"})
        lines = [l for l in self.unit(cfg).splitlines()
                 if l.startswith("LoadCredentialEncrypted=")]
        self.assertEqual(lines, [
            "LoadCredentialEncrypted=broker-agent-example-token:"
            "/etc/credstore.encrypted/broker/agent/example-token"])

    def test_the_egress_bound_is_present_in_both_halves(self):
        """The instance's uid is not in wl_filtered, so nothing else bounds
        this leg: an allow list with no deny under it bounds nothing, and a
        deny with no allow list is a broker that reaches nobody."""
        unit = self.unit()
        self.assertIn("IPAddressDeny=any", unit)
        self.assertIn("IPAddressAllow=localhost", unit)

    def test_the_resolver_is_allowed(self):
        """Not optional: without it the broker's own lookups die, which
        presents as the provider being down."""
        resolvers = vm_host_resolver_addresses()
        unit = self.unit()
        for addr in resolvers:
            self.assertIn(f"IPAddressAllow={addr}", unit)

    def test_resolved_upstreams_are_allowed(self):
        import vm as vm_mod
        real = vm_mod.socket.getaddrinfo
        try:
            vm_mod.socket.getaddrinfo = lambda host, *a, **k: [
                (2, 1, 6, "", ("203.0.113.7", 0))]
            unit = self.unit()
        finally:
            vm_mod.socket.getaddrinfo = real
        self.assertIn("IPAddressAllow=203.0.113.7", unit)
        self.assertLess(unit.index("IPAddressAllow=203.0.113.7"),
                        unit.index("IPAddressDeny=any"))

    def test_an_unresolvable_upstream_contributes_nothing(self):
        """And is not an error. With the deny under it, the failure is a
        provider this broker cannot reach -- not a broker that reaches all."""
        self.assertEqual(vm_broker_upstream_addresses(cred_config()), [])

    def test_it_starts_before_and_stops_with_the_vm(self):
        unit = self.unit()
        self.assertIn("Before=workload-agent.service", unit)
        self.assertIn("PartOf=workload-agent.service", unit)

    def test_the_config_is_written_by_an_unprivileged_execstartpre(self):
        """Unprivileged so the file is owned by the dynamic user that reads it,
        and not tolerant: a broker started against a stale config attaches the
        wrong credential to a request, silently."""
        unit = self.unit()
        self.assertIn('ExecStartPre=/usr/libexec/workloadctl/'
                      'workload-vm-broker config "agent"', unit)
        self.assertNotIn("ExecStartPre=+/usr/libexec/workloadctl/"
                         "workload-vm-broker config", unit)
        self.assertNotIn("ExecStartPre=-/usr/libexec/workloadctl/"
                         "workload-vm-broker config", unit)

    def test_the_runtime_directory_is_private_to_the_instance(self):
        unit = self.unit()
        self.assertIn("RuntimeDirectory=workloadctl/broker/agent", unit)
        self.assertIn("RuntimeDirectoryMode=0700", unit)

    def test_it_execs_the_packaged_broker_against_the_generated_config(self):
        self.assertIn(f'ExecStart={VM_BROKER_BIN} '
                      f'"{vm_broker_config_path("agent")}"', self.unit())


class TestTheVmUnitWaitsForIt(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.gen = load_script("generators/workload-generate")

    def vm_unit(self, cfg):
        return self.gen.generate_vm_service(cfg, "_wl-agent", UID_MIN + 5)

    def test_a_credential_workload_requires_its_broker(self):
        unit = self.vm_unit(cred_config())
        self.assertIn("workload-agent-broker.service", unit)

    def test_a_workload_without_one_does_not(self):
        cfg = cred_config()
        cfg["vm"]["network"]["credential"] = []
        cfg["vm"]["network"]["policy"] = [{"host": "api.example.test"}]
        self.assertNotIn("workload-agent-broker.service", self.vm_unit(cfg))


class TestTheRunFile(unittest.TestCase):
    """Superset semantics, which is what buys `drift` and `remove` coverage."""

    def files(self, cfg):
        from workload_lib import workload_run_files

        class _Cfg:
            def __init__(self, config):
                self.config = config
                self.name = config["workload"]["name"]
                self.is_vm = True
                self.mode = "single"
                self.uid = UID_MIN + 5

            def container_names(self):
                return []

        return {f.path.name: f for f in workload_run_files(_Cfg(cfg))}

    def test_it_is_listed_and_emitted_for_a_credential_workload(self):
        entry = self.files(cred_config())["workload-agent-broker.service"]
        self.assertEqual((entry.kind, entry.role), ("unit", "broker"))
        self.assertTrue(entry.emitted)

    def test_it_is_listed_but_not_emitted_without_a_credential(self):
        """So a workload that drops its last credential has the unit unlinked
        rather than left behind holding material nothing selects."""
        cfg = cred_config()
        cfg["vm"]["network"]["credential"] = []
        cfg["vm"]["network"]["policy"] = [{"host": "api.example.test"}]
        entry = self.files(cfg)["workload-agent-broker.service"]
        self.assertFalse(entry.emitted)


class TestTheGuestHalf(unittest.TestCase):
    """One line: the placeholder reaches the guest under the declared name."""

    def test_the_placeholder_is_seeded_under_the_declared_variable(self):
        self.assertEqual(vm_credential_env(cred_config()),
                         {"EXAMPLE_API_KEY": "sk-000000PLACEHOLDER"})

    def test_a_workload_with_no_credentials_seeds_nothing(self):
        self.assertEqual(vm_credential_env({"workload": {"name": "x"},
                                            "vm": {"network": {}}}), {})

    def test_the_rendered_seed_carries_it(self):
        ensure = load_script("libexec/workload-ensure-user")
        out = ensure._render_default_user_data(
            name="agent", guest_user="fedora", pubkey="ssh-ed25519 AAAA u@h",
            mounts=[], has_data_disk=False,
            guest_env=vm_credential_env(cred_config()))
        self.assertIn("EXAMPLE_API_KEY", out)
        self.assertIn("sk-000000PLACEHOLDER", out)

    def test_it_cannot_collide_with_a_variable_workloadctl_seeds(self):
        """The seed merges the two, so a collision resolves silently either
        way: a guest with no placeholder (401s) or one with no CA path (every
        HTTPS request failing validation inside the guest)."""
        cfg = cred_config()
        cfg["vm"]["network"]["credential"][0]["env"] = VM_CA_ENV_VARS[0]
        errors = validate_vm_network(cfg["vm"]["network"])
        self.assertTrue(any("already seeds" in e for e in errors), errors)

    def test_two_credentials_cannot_share_one_variable(self):
        cfg = cred_config()
        cfg["vm"]["network"]["credential"].append(
            {"name": "second-token", "placeholder": "sk-2",
             "env": "EXAMPLE_API_KEY"})
        cfg["vm"]["network"]["policy"].append(
            {"host": "api.example.test", "credential": "second-token"})
        errors = validate_vm_network(cfg["vm"]["network"])
        self.assertTrue(any("used by two" in e for e in errors), errors)

    def test_the_reserved_set_is_derived_from_its_producers(self):
        self.assertTrue(set(VM_CA_ENV_VARS) <= VM_RESERVED_GUEST_ENV)
        self.assertIn(VM_BROKER_ENV_VAR, VM_RESERVED_GUEST_ENV)


class TestAWildcardHostCannotBeBrokered(unittest.TestCase):
    """The broker's table has no patterns in it.

    An entry like `*.example.test` with a credential would be authorised by the
    inspector and refused by the broker, which is a 403 on a request every
    other layer agreed to, naming a host the file appears to cover.
    """

    def test_it_is_refused(self):
        cfg = cred_config()
        cfg["vm"]["network"]["hosts"] = ["*.example.test"]
        cfg["vm"]["network"]["policy"] = [
            {"host": "*.example.test", "credential": "example-token"}]
        errors = validate_vm_network(cfg["vm"]["network"])
        self.assertTrue(any("per exact Host" in e for e in errors), errors)

    def test_a_wildcard_without_a_credential_is_still_fine(self):
        cfg = cred_config()
        cfg["vm"]["network"]["hosts"] = ["*.example.test", "api.example.test"]
        cfg["vm"]["network"]["policy"] = [
            {"host": "*.example.test"},
            {"host": "api.example.test", "credential": "example-token"}]
        errors = validate_vm_network(cfg["vm"]["network"])
        self.assertFalse([e for e in errors if "per exact Host" in e], errors)


class TestBrokerHosts(unittest.TestCase):

    def test_only_credential_backed_entries_appear(self):
        cfg = cred_config()
        cfg["vm"]["network"]["policy"].append({"host": "plain.example.test"})
        self.assertEqual(vm_broker_hosts(cfg),
                         [("api.example.test", "example-token")])

    def test_file_order_is_preserved(self):
        cfg = cred_config()
        cfg["vm"]["network"]["hosts"].append("api2.example.test")
        cfg["vm"]["network"]["policy"].insert(
            0, {"host": "api2.example.test", "credential": "example-token"})
        self.assertEqual([h for h, _c in vm_broker_hosts(cfg)],
                         ["api2.example.test", "api.example.test"])


class TestDriftSeesAHandEditedInstance(unittest.TestCase):
    """The free coverage the unit shape was chosen for, asserted not assumed.

    A broker instance whose unit has silently diverged from the bundle is a
    credential-SELECTION bug -- the wrong key on the wrong host, on the one path
    that carries a real one. `drift` catches it with no machinery of its own
    because the unit is an ordinary run-file, and that is one of the two reasons
    the design chose a full generated unit over a template or a drop-in. If it
    ever stops being one (emitted somewhere else, or written by a helper at
    start), this test is what notices.
    """

    def setUp(self):
        import os
        import shutil
        import cmd_drift
        from unittest import mock
        from tests import script_env
        from tests.test_generator_snapshot import (
            FIXTURES, run_generator, write_config)

        cfg_dir = tempfile.mkdtemp(prefix="drift-cfg-")
        sysusers_dir = tempfile.mkdtemp(prefix="drift-sysusers-")
        # Generated straight INTO the live dir rather than copied there: the
        # units bake the services directory into a few Exec paths, so a copy
        # from somewhere else would differ from a fresh render in every unit
        # and every workload would read as drifted for a reason that is this
        # test's staging rather than the product.
        self.live = Path(tempfile.mkdtemp(prefix="drift-live-"))
        for cleanup in (cfg_dir, sysusers_dir, self.live):
            self.addCleanup(shutil.rmtree, cleanup, ignore_errors=True)
        for name, toml_content in FIXTURES["vm-credential"]:
            write_config(cfg_dir, name, toml_content)
        result = run_generator(cfg_dir, self.live, sysusers_dir)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.unit = self.live / "workload-vmcred-broker.service"

        # collect_drift re-runs the generator with os.environ plus two keys of
        # its own. On a host every module it imports sits beside it in
        # /usr/libexec/workloadctl; in the checkout they do not, so the
        # interpreter path has to come from the environment -- and the
        # generator exits 0 whatever happens (never blocking boot), so without
        # this the regeneration produces nothing and EVERY live unit reads as
        # an orphan rather than as a failure.
        self.enterContext(mock.patch.dict(
            os.environ, {"PYTHONPATH": script_env()["PYTHONPATH"]}))

        self.policy_root = Path(tempfile.mkdtemp(prefix="drift-policy-"))
        self.addCleanup(shutil.rmtree, self.policy_root, ignore_errors=True)

        self.cmd_drift = cmd_drift
        for attr, value in (("LIVE_UNITS_DIR", self.live),
                            ("POLICY_ROOT", self.policy_root),
                            ("workload_config_dir", lambda: Path(cfg_dir))):
            self.enterContext(mock.patch.object(cmd_drift, attr, value))

    def test_the_instance_is_generated_at_all(self):
        self.assertTrue(self.unit.exists(),
                        "no broker unit was emitted for a credential workload")

    def test_an_untouched_instance_is_not_drift(self):
        names = [name for name, _live, _gen in self.cmd_drift.collect_drift()]
        self.assertNotIn("workload-vmcred-broker.service", names)

    def test_a_hand_edited_instance_is_reported(self):
        self.unit.write_text(
            self.unit.read_text().replace("IPAddressDeny=any", ""))
        names = [name for name, _live, _gen in self.cmd_drift.collect_drift()]
        self.assertIn("workload-vmcred-broker.service", names)


class TestTheHelperWritesTheConfig(unittest.TestCase):
    """`workload-vm-broker config` -- the ExecStartPre that materialises D2.

    It runs unprivileged, as the instance's own DynamicUser, inside the unit's
    sandbox: everything it reads is world-readable and the only thing it writes
    is the unit's RuntimeDirectory. That is what makes the file owned by the uid
    that reads it, with no chown and no window in which it is wider.
    """

    def setUp(self):
        from unittest import mock
        self.mod = load_script("libexec/workload-vm-broker")
        self.tmp = Path(tempfile.mkdtemp(prefix="broker-config-"))
        self.addCleanup(__import__("shutil").rmtree, self.tmp,
                        ignore_errors=True)
        self.path = self.tmp / "broker.toml"
        self.enterContext(mock.patch.object(
            self.mod, "vm_broker_config_path", lambda name: self.path))
        self.enterContext(mock.patch.object(
            self.mod.pwd, "getpwnam",
            lambda user: type("pw", (), {"pw_uid": UID_MIN + 5})))

    def write(self, cfg):
        from unittest import mock
        with mock.patch.object(self.mod, "load_config", lambda name: cfg):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                return self.mod.write_config(cfg["workload"]["name"])

    def test_it_writes_the_rendered_config(self):
        self.assertEqual(self.write(cred_config()), 0)
        self.assertEqual(tomllib.loads(self.path.read_text())["listen_address"],
                         vm_broker_listen_address(UID_MIN + 5))

    def test_the_file_is_readable_by_nobody_else(self):
        self.write(cred_config())
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_it_leaves_no_temporary_behind(self):
        self.write(cred_config())
        self.assertEqual([p.name for p in self.tmp.iterdir()], ["broker.toml"])

    def test_a_second_run_replaces_rather_than_appends(self):
        """The config is a pure function of the TOML, rewritten at every start
        -- which is what stops an instance serving the previous boot's set."""
        self.write(cred_config())
        cfg = cred_config()
        cfg["vm"]["network"]["credential"][0]["placeholder"] = "sk-SECOND"
        self.write(cfg)
        row = tomllib.loads(self.path.read_text())["sandboxes"]["agent"][
            "hosts"]["api.example.test"]
        self.assertEqual(row["placeholder"], "sk-SECOND")

    def test_a_workload_with_no_credentials_is_refused(self):
        """Reaching here means a unit outlived the config that produced it.
        Refused rather than written empty, so the message names the cause."""
        cfg = cred_config()
        cfg["vm"]["network"]["credential"] = []
        cfg["vm"]["network"]["policy"] = [{"host": "api.example.test"}]
        self.assertEqual(self.write(cfg), 1)
        self.assertFalse(self.path.exists())

    def test_the_verb_is_rejected_with_the_wrong_argument_count(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            self.assertEqual(self.mod.main(["prog", "config"]), 2)
        self.assertIn("<config|up|down>", buf.getvalue())


# ---------------------------------------------------------------------------
# Rung 6 T5 — the inspector dials the broker.
#
# The branch is small (`_upstream_for` already took the dial as an argument),
# and everything worth pinning is what it does NOT do: it does not consult the
# origin, it does not re-resolve the host to explain a failure that never
# touched DNS, and it does not merge its refusal into `upstream unreachable`.
# Each of those failing is silent -- the request still gets an answer, the
# counters still reconcile, and only a reader who already suspected the seam
# would notice ([[unit-gates-dont-see-the-seam]]).
# ---------------------------------------------------------------------------

import json
import os
import socket
import threading
import time

from vm import (
    VM_BROKER_INSTANCE_PORT, VM_DROP_BROKER_UNREACHABLE,
    VM_DROP_UNREACHABLE, VM_INSPECT_RECORD_FIELDS,
    VmPolicyEntry, vm_broker_listen_address, vm_inspect_policy,
    vm_inspect_policy_text,
)
import vm_inspect_figures

LISTENER = Path(__file__).resolve().parent.parent / "libexec" / "workload-vm-inspect-listener"
CIL = Path(__file__).resolve().parent.parent / "security" / "workload-inspect.cil"

_LISTENER_MOD = None


def listener_mod():
    global _LISTENER_MOD
    if _LISTENER_MOD is None:
        _LISTENER_MOD = load_script("libexec/workload-vm-inspect-listener")
    return _LISTENER_MOD


# Captured before any test patches it: the rig's own upstream pair is built
# with create_connection, and the fake dial patches that name globally.
_REAL_CREATE_CONNECTION = socket.create_connection

_OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
_UNAUTHORIZED = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"

# The address this workload's broker would answer on. Injected rather than
# derived from os.getuid(), because the suite does not run as _wl-<name> and
# vm_broker_listen_address refuses a uid outside the workload range -- see
# TestTheBrokerAddressComesFromTheUid for the derivation itself.
BROKER_ADDR = vm_broker_listen_address(10007)


def _pump(sock, buf):
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                return
            buf += chunk
    except (TimeoutError, OSError):
        return


class _BrokerRig(unittest.TestCase):
    """One guest request through the cleartext plane, with every dial captured.

    Real socketpairs on both legs. A mock upstream cannot stand in here: what
    is under test is which ADDRESS was dialled and which BYTES arrived there,
    and both are properties of a stream.
    """

    def _pair(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        a.settimeout(3.0)
        b.settimeout(3.0)
        return a, b

    def _tcp_pair(self):
        """A REAL TCP pair whose near end has a 127.129.x.y peer.

        A socketpair will not do for the upstream leg: `_Record.dialled` reads
        `getpeername()`, and an AF_UNIX socket answers something that is not an
        address pair -- so the record's `upstream` stays null and the one field
        rung 6 decision 6 is about is untested. Bound on the broker's own
        address, which 127/8 makes free, so the record carries the address
        family the decision turns on rather than a stand-in for it.

        The PORT is ephemeral and deliberately not asserted anywhere: what
        create_connection was ASKED for is captured separately, and inventing a
        rig that could also bind 8081 would need a privileged port-free host
        and would prove nothing more.
        """
        server = socket.socket()
        self.addCleanup(server.close)
        server.bind((BROKER_ADDR, 0))
        server.listen(1)
        near = _REAL_CREATE_CONNECTION(server.getsockname(), timeout=3.0)
        self.addCleanup(near.close)
        far, _ = server.accept()
        self.addCleanup(far.close)
        near.settimeout(3.0)
        far.settimeout(3.0)
        return near, far

    def _policy(self, entries, hosts=()):
        mod = listener_mod()
        return mod.Policy(tls="splice", hosts=tuple(hosts),
                          policy=tuple(entries))

    def _serve(self, policy, request, responses=(), refuse=False,
               record=False):
        """Drive one cleartext connection. Returns (log, dialled, snapshot, records).

        `dialled` is [(address, bytes-that-arrived)] in dial order, which is
        the assertion this whole class exists to make.
        """
        mod = listener_mod()
        out = io.StringIO()
        record_path = None
        if record:
            tmp = tempfile.TemporaryDirectory(prefix="broker-rec-")
            self.addCleanup(tmp.cleanup)
            record_path = str(Path(tmp.name) / "requests.log")
        listener = mod.Listener([], out, policy=policy,
                                record_path=record_path,
                                broker_address=BROKER_ADDR)
        ours, guest = self._pair()
        guest.sendall(request)
        dialled = []

        def dial(addr, timeout=None):
            if refuse:
                raise ConnectionRefusedError(111, "Connection refused")
            near, far = self._tcp_pair()
            if len(dialled) < len(responses):
                far.sendall(responses[len(dialled)])
            buf = bytearray()
            pump = threading.Thread(target=_pump, args=(far, buf), daemon=True)
            pump.start()
            dialled.append((addr, buf, pump))
            return near

        with unittest.mock.patch.object(
                socket, "create_connection", side_effect=dial), \
                unittest.mock.patch.object(mod, "CONNECTION_TIMEOUT", 0.20), \
                unittest.mock.patch.object(mod, "RELAY_IDLE_TIMEOUT", 0.75):
            listener._serve_cleartext(ours, _where())
        for _, _, pump in dialled:
            pump.join(timeout=3.0)
        records = []
        if record_path and Path(record_path).exists():
            records = [json.loads(line) for line
                       in Path(record_path).read_text().splitlines() if line]
        answer = b""
        try:
            while chunk := guest.recv(65536):
                answer += chunk
        except (TimeoutError, OSError):
            pass
        self.answer = answer
        return (out.getvalue(), [(addr, bytes(buf)) for addr, buf, _ in dialled],
                listener.counters.snapshot(open_now=0, refused=0), records)


def _where():
    mod = listener_mod()
    return mod._Where(f"{mod.LOG_ID_FIELD}=abc plane=cleartext",
                      cid="abc", plane="cleartext")


BROKERED = VmPolicyEntry(host="api.provider", methods=None, paths=None,
                         credential="provider-key")
PLAIN = VmPolicyEntry(host="plain.example", methods=None, paths=None)

_GET_BROKERED = (b"GET /v1/models HTTP/1.1\r\nHost: api.provider\r\n\r\n")
_GET_PLAIN = (b"GET / HTTP/1.1\r\nHost: plain.example\r\n\r\n")


class TestTheBrokeredRequestGoesToTheBroker(_BrokerRig):

    def test_the_dial_is_the_brokers_address_and_port(self):
        """Not the origin, and not 127.0.0.1. Both negatives are asserted
        because the second is the hole ADR 007 decision 6 closes: a broker on
        127.0.0.1 is reachable by every workload on the box."""
        _, dialled, _, _ = self._serve(
            self._policy([BROKERED]), _GET_BROKERED, responses=[_OK])
        self.assertEqual(len(dialled), 1)
        addr, _ = dialled[0]
        self.assertEqual(addr, (BROKER_ADDR, VM_BROKER_INSTANCE_PORT))
        self.assertNotEqual(addr[0], "127.0.0.1")
        self.assertNotEqual(addr[0], "api.provider")

    def test_the_host_header_reaches_the_broker_unchanged(self):
        """Half the broker's `(uid, Host)` key. The other half is the uid on
        the far end of this socket, which is not ours to send -- so if the
        Host were rewritten here the broker would dispatch on nothing."""
        _, dialled, _, _ = self._serve(
            self._policy([BROKERED]), _GET_BROKERED, responses=[_OK])
        _, sent = dialled[0]
        self.assertIn(b"Host: api.provider\r\n", sent)
        self.assertIn(b"GET /v1/models ", sent)

    def test_a_host_with_no_credential_still_goes_to_the_origin(self):
        """The branch is per HOST, not per workload: one brokered entry must
        not divert the rest of the allowlist through the broker."""
        _, dialled, _, _ = self._serve(
            self._policy([BROKERED, PLAIN]), _GET_PLAIN, responses=[_OK])
        addr, _ = dialled[0]
        self.assertEqual(addr, ("plain.example", 80))

    def test_policy_is_applied_before_the_credential_is_looked_up(self):
        """A credential cannot widen what a guest may ask for. The entry
        permits GET only, so a POST is refused and nothing is dialled -- if
        the branch ran first, the broker would attach a key to a request this
        workload's own policy denies."""
        entry = VmPolicyEntry(host="api.provider", methods=("GET",),
                              paths=None, credential="provider-key")
        log, dialled, snap, _ = self._serve(
            self._policy([entry]),
            b"POST /v1/models HTTP/1.1\r\nHost: api.provider\r\n\r\n")
        self.assertEqual(dialled, [])
        self.assertEqual(snap["drop_reasons"]["not permitted by policy"], 1)
        self.assertEqual(snap["credentialed"], 0)


class TestTheRefusalWhenTheBrokerIsDown(_BrokerRig):

    def test_the_reason_is_its_own_and_not_upstream_unreachable(self):
        """Rung 6 decision 5. 'the provider is down' and 'a unit on this host
        is not answering' need different operator responses, and
        `workloadctl egress --reason` validates against a closed set -- so a
        merged reason is a filter that cannot select this failure."""
        log, _, snap, _ = self._serve(
            self._policy([BROKERED]), _GET_BROKERED, refuse=True)
        self.assertEqual(snap["drop_reasons"][VM_DROP_BROKER_UNREACHABLE], 1)
        self.assertEqual(snap["drop_reasons"][VM_DROP_UNREACHABLE], 0)
        self.assertIn(VM_DROP_BROKER_UNREACHABLE, log)

    def test_the_guest_is_told_the_request_was_not_sent(self):
        """A silent close is the one outcome this listener argues against at
        length: a guest told 'no' by a dead socket cannot tell a refusal from
        the host being down. It gets a 502, and the body says the request did
        NOT reach the origin -- which matters more here than on a dead
        upstream, because a retry against the same host will do the same thing
        until an operator touches the host."""
        self._serve(self._policy([BROKERED]), _GET_BROKERED, refuse=True)
        self.assertIn(b"502", self.answer)
        self.assertIn(b"NOT sent", self.answer)

    def test_the_operator_is_pointed_at_the_unit_and_at_audit_log(self):
        """The AVC and a broker that failed to start are indistinguishable
        from here -- the counter cannot tell them apart and neither can the
        502. So the sentence names both remedies rather than asserting one,
        per this module's own 'a policy gap wearing a network error's
        clothes'."""
        self._serve(self._policy([BROKERED]), _GET_BROKERED, refuse=True)
        self.assertIn(b"broker.service", self.answer)
        self.assertIn(b"audit.log", self.answer)

    def test_the_failed_host_is_not_re_resolved(self):
        """_dial_failure_reason exists to tell the wildcard trap from a dead
        host, and it does that by RE-RESOLVING the name. On this leg the name
        was never dialled -- a loopback address on this box was -- so running
        it would attribute a dead broker to whatever api.provider resolves to,
        and would pay a synchronous getaddrinfo for the wrong answer."""
        mod = listener_mod()
        with unittest.mock.patch.object(
                mod.Listener, "_dial_failure_reason") as failure:
            self._serve(self._policy([BROKERED]), _GET_BROKERED, refuse=True)
        failure.assert_not_called()

    def test_an_unbrokered_host_still_gets_the_resolving_reason(self):
        """The guard for the test above: the generic path must keep the
        behaviour the broker path opts out of."""
        mod = listener_mod()
        with unittest.mock.patch.object(
                mod.Listener, "_dial_failure_reason",
                return_value=VM_DROP_UNREACHABLE) as failure:
            self._serve(self._policy([PLAIN]), _GET_PLAIN, refuse=True)
        failure.assert_called_once()


    def test_a_uid_outside_the_workload_range_is_a_refusal_not_a_traceback(self):
        """A listener started by hand, outside its unit, derives no broker
        address. That has to reach the caller's broker arm as a legible
        refusal: a bare ValueError kills the connection thread with a
        traceback and tells the operator nothing about what is wrong."""
        mod = listener_mod()
        listener = mod.Listener([], io.StringIO(),
                                policy=self._policy([BROKERED]))
        with unittest.mock.patch.object(os, "getuid", return_value=0):
            with self.assertRaises(OSError) as caught:
                listener._dial_broker("api.provider")
        self.assertIn("outside the workload range", str(caught.exception))


class TestTheRecordOfABrokeredRequest(_BrokerRig):
    """Rung 6 decision 6: `upstream` stays honest and `credential` is what
    makes it readable."""

    def _one(self, request=_GET_BROKERED, responses=(_OK,), policy=None):
        _, _, _, records = self._serve(
            policy or self._policy([BROKERED]), request,
            responses=list(responses), record=True)
        self.assertEqual(len(records), 1, records)
        return records[0]

    def test_the_credential_name_is_recorded(self):
        self.assertEqual(self._one()["credential"], "provider-key")

    def test_the_upstream_is_the_broker_and_not_the_origin(self):
        """`upstream` is documented as the address actually dialled, and on a
        brokered request that is a loopback address. Recording the origin
        instead would put a second, false definition of 'what this request
        touched' in the one document rung 5 built to be evidence."""
        rec = self._one()
        self.assertTrue(rec["upstream"].startswith("127.129."), rec["upstream"])
        self.assertNotIn("api.provider", rec["upstream"])

    def test_the_host_is_still_the_name_that_was_authorised(self):
        """Which is what makes the loopback `upstream` readable rather than
        mysterious: `host` says where the request went, `credential` says why
        `upstream` is a local address."""
        self.assertEqual(self._one()["host"], "api.provider")

    def test_an_unbrokered_request_records_a_null_credential(self):
        """Absent and null are different facts everywhere in this record, and
        this field is no exception -- a reader must be able to tell 'not
        brokered' from 'the writer dropped the key'."""
        rec = self._one(request=_GET_PLAIN,
                        policy=self._policy([BROKERED, PLAIN]))
        self.assertIn("credential", rec)
        self.assertIsNone(rec["credential"])

    def test_the_field_is_in_the_shared_vocabulary(self):
        self.assertIn("credential", VM_INSPECT_RECORD_FIELDS)
        self.assertIn("credential", listener_mod().RECORD_FIELDS)


class TestTheCredentialFigures(_BrokerRig):
    """[[counter-with-no-writer-reads-zero]]: 0 is a legal value for every one
    of these, so a row in the FIGURES table proves nothing on its own. Each
    test here makes the writer fire."""

    def test_a_brokered_request_moves_the_total(self):
        _, _, snap, _ = self._serve(
            self._policy([BROKERED]), _GET_BROKERED, responses=[_OK])
        self.assertEqual(snap["credentialed"], 1)

    def test_the_breakdowns_name_the_host_and_the_credential(self):
        """Two breakdowns of one total, because the two questions differ:
        which brokered host is the guest using, and is this key used at all.
        The second is what catches a policy entry pointing at a credential
        nothing triggers -- the one to read before rotating a key."""
        _, _, snap, _ = self._serve(
            self._policy([BROKERED]), _GET_BROKERED, responses=[_OK])
        self.assertEqual(snap["credentialed_hosts"]["api.provider"], 1)
        self.assertEqual(snap["per_credential"]["provider-key"], 1)

    def test_a_dead_broker_is_not_counted_as_a_credential_used(self):
        """The request reached no provider and carried no key. Counting it
        would report a credential as used on a request that reached nobody --
        and the drop reason already says what happened."""
        _, _, snap, _ = self._serve(
            self._policy([BROKERED]), _GET_BROKERED, refuse=True)
        self.assertEqual(snap["credentialed"], 0)
        self.assertEqual(snap["drop_reasons"][VM_DROP_BROKER_UNREACHABLE], 1)

    def test_a_401_from_the_origin_is_counted(self):
        """§11's second named failure, and the reason it is a counter rather
        than a note: every layer of ours succeeded. The record says
        decision=forward, the policy admitted the host, the broker attached
        material -- and the provider said no."""
        _, _, snap, _ = self._serve(
            self._policy([BROKERED]), _GET_BROKERED, responses=[_UNAUTHORIZED])
        self.assertEqual(snap["credential_unauthorized"], 1)

    def test_a_200_is_not(self):
        _, _, snap, _ = self._serve(
            self._policy([BROKERED]), _GET_BROKERED, responses=[_OK])
        self.assertEqual(snap["credential_unauthorized"], 0)

    def test_a_401_on_an_unbrokered_host_is_not_counted(self):
        """The figure's whole meaning is 'the credential was wrong'. An
        origin that wants authorisation the guest was always going to supply
        itself is an ordinary 401 and not this."""
        _, _, snap, _ = self._serve(
            self._policy([BROKERED, PLAIN]), _GET_PLAIN,
            responses=[_UNAUTHORIZED])
        self.assertEqual(snap["credential_unauthorized"], 0)

    def test_every_new_figure_reads_from_a_key_the_listener_writes(self):
        """The table is the mechanism, and a row whose `path` does not exist
        in the document renders 0 forever -- indistinguishable from a figure
        that is measured and idle."""
        _, _, snap, _ = self._serve(
            self._policy([BROKERED]), _GET_BROKERED, responses=[_UNAUTHORIZED])
        for key in ("credentialed", "credential_unauthorized"):
            figure = vm_inspect_figures.FIGURES_BY_KEY[key]
            self.assertEqual(len(figure.path), 1)
            self.assertIn(figure.path[0], snap)
            self.assertEqual(snap[figure.path[0]], 1)


class TestTheListenerReadsTheCredentialFromTheDocument(unittest.TestCase):
    """The seam T1 wrote the key at and T5 reads it at. Neither half is
    exercised by the other's tests, and a document that carries the key while
    the listener drops it is a workload whose every request quietly reaches
    the origin unbrokered."""

    def _load(self, net):
        mod = listener_mod()
        with tempfile.TemporaryDirectory(prefix="policy-") as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(vm_inspect_policy_text(net))
            return mod.load_policy(str(path))

    def test_the_credential_survives_the_round_trip(self):
        policy = self._load({
            "policy": [{"host": "api.provider", "credential": "provider-key"}],
            "credential": [{"name": "provider-key", "env": "PROVIDER_KEY",
                            "placeholder": "sk-placeholder"}],
        })
        self.assertEqual(policy.credential_for("api.provider"), "provider-key")

    def test_a_host_with_no_entry_has_no_credential(self):
        policy = self._load({"hosts": ["plain.example"]})
        self.assertIsNone(policy.credential_for("plain.example"))

    def test_an_unbrokered_entry_has_no_credential(self):
        policy = self._load({
            "policy": [{"host": "plain.example", "methods": ["GET"]}]})
        self.assertIsNone(policy.credential_for("plain.example"))

    def test_a_hand_edited_document_with_a_non_string_does_not_kill_the_start(self):
        """The listener reads a FILE. A refusal here fails the START, which
        takes the whole workload's egress down for a typo -- worse than one
        host reaching the origin unbrokered and saying so in the record."""
        mod = listener_mod()
        with tempfile.TemporaryDirectory(prefix="policy-") as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps({
                "tls": "inspect", "hosts": [],
                "policy": [{"host": "api.provider", "credential": 7}]}))
            policy = mod.load_policy(str(path))
        self.assertIsNone(policy.credential_for("api.provider"))

    def test_the_first_governing_entry_that_carries_one_wins(self):
        """`validate` refuses two entries that match one host and disagree, so
        this is unreachable from a generated document. It is reached from a
        hand-edited one, and first-match is deterministic and matches the
        order the file states -- an arbitrary pick would make an editing
        mistake behave differently on different boots."""
        mod = listener_mod()
        policy = mod.Policy(
            tls="inspect", hosts=(),
            policy=(VmPolicyEntry("api.provider", None, ("/a",), None),
                    VmPolicyEntry("api.provider", None, ("/b",), "second")))
        self.assertEqual(policy.credential_for("api.provider"), "second")


class TestTheBrokerAddressComesFromTheUid(unittest.TestCase):

    def test_the_listener_derives_it_from_its_own_uid(self):
        """No registry and no allocation step: the inspector and the broker's
        unit reach the same address from the same uid, so the two halves
        cannot drift."""
        mod = listener_mod()
        listener = mod.Listener([], io.StringIO())
        with unittest.mock.patch.object(os, "getuid", return_value=10007), \
                unittest.mock.patch.object(
                    socket, "create_connection") as dial:
            listener._dial_broker("api.provider")
        dial.assert_called_once()
        self.assertEqual(dial.call_args[0][0],
                         (BROKER_ADDR, VM_BROKER_INSTANCE_PORT))

    def test_it_is_derived_once_and_kept(self):
        mod = listener_mod()
        listener = mod.Listener([], io.StringIO())
        with unittest.mock.patch.object(os, "getuid", return_value=10007), \
                unittest.mock.patch.object(socket, "create_connection"):
            listener._dial_broker("api.provider")
            listener._dial_broker("api.provider")
        self.assertEqual(listener._broker_address, BROKER_ADDR)


class TestTheReasonIsPinnedAcrossTheTwoHalves(unittest.TestCase):
    """lib/vm.py restates the listener's string because the listener is an
    extension-less entrypoint nothing in lib/ can import. Restating is only
    safe with the pin."""

    def test_the_string_is_the_same_on_both_sides(self):
        self.assertEqual(VM_DROP_BROKER_UNREACHABLE,
                         listener_mod().DROP_BROKER_UNREACHABLE)

    def test_egress_can_filter_on_it(self):
        from vm import VM_INSPECT_RECORD_REASONS
        self.assertIn(VM_DROP_BROKER_UNREACHABLE, VM_INSPECT_RECORD_REASONS)
        self.assertIn(VM_DROP_BROKER_UNREACHABLE, listener_mod().DROP_REASONS)


class TestTheSelinuxRuleShipsWithTheDial(unittest.TestCase):
    """F2, and the reason it is here rather than harvested at tier 3: without
    the rule the first credential-backed request on an enforcing host is an
    AVC, and every test above still passes
    ([[silent-selinux-denials-pass-functional-tests]])."""

    def test_the_inspector_may_connect_to_the_brokers_port_type(self):
        text = CIL.read_text()
        self.assertIn(
            "(allow wlinspect_t transproxy_port_t (tcp_socket (name_connect)))",
            text)

    def test_the_port_the_rule_was_read_for_is_the_port_the_code_dials(self):
        """8081 is transproxy_port_t on a real host, and the specific type
        wins over unreserved_port_t. Moving the port silently invalidates the
        rule above -- so the constant is pinned to the number the comment was
        written about."""
        self.assertEqual(VM_BROKER_INSTANCE_PORT, 8081)
        self.assertIn("8081 is", CIL.read_text())


class TestWhatDiagnoseSaysAboutBrokeredTraffic(unittest.TestCase):
    """The runtime counterpart to `_credential_fragments`, which reads the
    bundle. This reads the inspector's own document, and the two are wanted at
    different moments: one answers 'is this host brokered at all', this one
    answers 'the provider is refusing me and every unit here is green'."""

    BROKERED_LISTS = {"policy": [{"host": "api.provider", "methods": None,
                                  "paths": None,
                                  "credential": "provider-key"}]}

    def _fragments(self, **status):
        import cmd_diagnose
        doc = {"lists": self.BROKERED_LISTS, "dispositions": {"forwarded": 1},
               "drop_reasons": {}, "credentialed": 1,
               "credential_unauthorized": 0, "per_credential": {}}
        doc.update(status)
        return cmd_diagnose._credential_usage_fragments(doc)

    def test_a_workload_that_brokers_nothing_says_nothing(self):
        """Gated on the LOADED policy, not on the config: this function
        describes what the running listener did, and on a workload with no
        credential there is nothing here to describe. Ungated, the idle line
        below would fire on every filtered VM on the fleet."""
        import cmd_diagnose
        self.assertEqual(
            cmd_diagnose._credential_usage_fragments(
                {"lists": {"policy": [{"host": "a", "credential": None}]},
                 "dispositions": {"forwarded": 3}, "credentialed": 0}),
            [])

    def test_the_healthy_case_is_silent(self):
        self.assertEqual(self._fragments(), [])

    def test_a_401_names_the_credential_and_says_the_layers_succeeded(self):
        out = self._fragments(credential_unauthorized=2,
                              per_credential={"provider-key": 2})
        self.assertEqual(len(out), 1)
        self.assertIn("provider-key", out[0])
        self.assertIn("401/403", out[0])
        self.assertIn("EVERY LAYER HERE SUCCEEDED", out[0])

    def test_a_dead_broker_points_at_the_unit_and_at_audit_log(self):
        out = self._fragments(
            drop_reasons={VM_DROP_BROKER_UNREACHABLE: 4}, credentialed=0)
        self.assertEqual(len(out), 1)
        self.assertIn("broker.service", out[0])
        self.assertIn("audit.log", out[0])
        self.assertNotIn("no request has been sent", out[0])

    def test_a_configured_but_unused_broker_is_named_once_traffic_exists(self):
        """Configured-and-idle is exactly the state an operator is trying to
        tell apart from a broker that is not working, and neither produces a
        drop. It is said only where the guest HAS made requests -- before that
        there is nothing to conclude."""
        out = self._fragments(credentialed=0)
        self.assertEqual(len(out), 1)
        self.assertIn("has made requests", out[0])

    def test_a_guest_that_has_done_nothing_yet_is_not_accused(self):
        out = self._fragments(credentialed=0, dispositions={"forwarded": 0})
        self.assertEqual(out, [])
