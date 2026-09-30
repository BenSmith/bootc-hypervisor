"""The per-workload credential broker instance (ADR 007).

Values that appear in a shipped file -- a generated unit, the broker's
ExecStart= line -- are spelled out here rather than imported and re-derived:
the point of the test is that the file and the module agree, and a test that
computes both sides from the same constant cannot fail when they drift apart.

WHAT USED TO BE AT THE TOP OF THIS FILE, and why it is worth a line rather than
a silent deletion: ~255 lines about a uid-keyed nft map that translated one
advertised endpoint (192.0.2.1:8081) to one host-wide broker on 127.0.0.1:8081,
plus the WORKLOAD_BROKER_URL the guest was told. Rung 6 deleted that whole
mechanism. The gates that survive it are elsewhere and are deliberately not
re-created here: `[vm.network].broker` is now a hard error, asserted in
tests/test_egress.py with the other retired-key refusals; the reservation
that entry needed is inherited from 127.128.0.0/9 and asserted by
TestReservedRanges; and the sweep the generator ran on every VM's stop is gone
with the map, asserted below by its absence.
"""

import importlib
from tests import CUSTOMS_LIBEXEC, load_script

# `lib/` reaches sys.path via tests/__init__, so this import follows it.
import vm_default_seed
import io
import tempfile
import unittest
from pathlib import Path

from guest_ca import CA_ENV_VARS
from guest_ca import RESERVED_GUEST_ENV
from broker_config import (BROKER_BIN, vm_broker_command,
                           broker_credential, vm_broker_hosts,
                           vm_broker_upstream_addresses, vm_credential_entries,
                           vm_credential_env, host_resolver_addresses,
                           vm_uses_credentials)
import inspect_arm
from nft_elements import internal_ok_elements
from vm_validate import validate_vm_network
from customs import broker_profiles
from workload_addr import BROKER_INSTANCE_PORT, UID_MIN, broker_listen_address
import ipaddress


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


def flags_of(cmd):
    """{flag: [values]} of a broker argv, the binary dropped. A list per
    flag because --host and the three per-credential flags repeat."""
    table = {}
    for i in range(1, len(cmd), 2):
        table.setdefault(cmd[i], []).append(cmd[i + 1])
    return table


class TestTheGeneratedCommand(unittest.TestCase):
    """vm_broker_command -- what the instance is told, and what it is not.

    The address assertions are NEGATIVE as well as positive on purpose. Both
    wrong values (127.0.0.1, the broker's own retired default, and 0.0.0.0) put
    one workload's broker where every other workload's inspector is dialling,
    which is exactly the hole ADR 007 decision 6 closes; a test that only
    asserted the derived value would pass on a command that also bound the
    world.
    """

    def command(self, cfg=None, uid=UID_MIN + 5):
        return vm_broker_command(cfg or cred_config(), uid)

    def flags(self, cfg=None, uid=UID_MIN + 5):
        return flags_of(self.command(cfg, uid))

    def test_it_is_the_packaged_binary_and_flag_value_pairs(self):
        cmd = self.command()
        self.assertEqual(cmd[0], BROKER_BIN)
        self.assertEqual(len(cmd) % 2, 1, cmd)
        self.assertTrue(all(cmd[i].startswith("--")
                            for i in range(1, len(cmd), 2)), cmd)
        self.assertFalse(any(cmd[i].startswith("--")
                             for i in range(2, len(cmd), 2)), cmd)

    def test_the_listen_address_is_the_uid_derived_one(self):
        self.assertEqual(self.flags()["--listen"],
                         [f"{broker_listen_address(UID_MIN + 5)}:"
                          f"{BROKER_INSTANCE_PORT}"])

    def test_the_listen_address_is_never_localhost_or_the_world(self):
        for uid in (UID_MIN, UID_MIN + 1, UID_MIN + 300):
            addr = self.flags(uid=uid)["--listen"][0].rsplit(":", 1)[0]
            self.assertNotIn(addr, ("127.0.0.1", "0.0.0.0", "::", "*"))

    def test_the_caller_is_the_uid_the_address_was_made_from(self):
        """Written twice, as the address and as the caller, because the
        broker is told both and computes neither."""
        self.assertEqual(self.flags(uid=UID_MIN + 5)["--caller-uid"],
                         [str(UID_MIN + 5)])

    def test_the_name_is_the_workload_name(self):
        """A label for the log lines, and nothing the broker looks anything
        up by -- the caller is the uid."""
        self.assertEqual(self.flags(cred_config(name="myagent"))["--name"],
                         ["myagent"])

    def test_the_host_flag_carries_the_host_and_the_credential_id(self):
        _path, cred_id = broker_credential("agent", "example-token")
        self.assertEqual(self.flags()["--host"],
                         [f"api.example.test={cred_id}"])
        self.assertEqual(self.flags()["--placeholder"],
                         [f"{cred_id}=sk-000000PLACEHOLDER"])

    def test_the_credential_id_is_what_the_unit_loads_it_under(self):
        """The id on --host is the filename the broker reads under
        $CREDENTIALS_DIRECTORY, so it must be the seal name the unit's
        LoadCredentialEncrypted= writes there -- the two are one string."""
        cfg = cred_config()
        unit = TestTheGeneratedUnit().unit(cfg)
        loaded = [ln.split("=", 1)[1].split(":", 1)[0]
                  for ln in unit.splitlines()
                  if ln.startswith("LoadCredentialEncrypted=")]
        named = [v.split("=", 1)[1] for v in self.flags(cfg)["--host"]]
        self.assertEqual(loaded, named)

    def test_the_upstream_is_not_a_flag(self):
        """https://<host> and no path, supplied by the broker: a base path
        would be prepended to the request the inspector already matched
        against `paths`, so the origin would be sent a target no rule in
        this design ever saw. With nothing to vary there is nothing to
        hand over."""
        self.assertNotIn("--upstream", self.flags())
        self.assertEqual(broker_profiles.UPSTREAM_PORT, 443)

    def test_a_host_with_no_credential_gets_no_flag(self):
        cfg = cred_config()
        cfg["vm"]["network"]["policy"].append({"host": "plain.example.test"})
        self.assertEqual([v.split("=")[0] for v in self.flags(cfg)["--host"]],
                         ["api.example.test"])

    def test_two_hosts_may_share_one_credential(self):
        """Two --host flags, ONE --placeholder: the broker refuses a
        credential described twice."""
        cfg = cred_config()
        cfg["vm"]["network"]["hosts"].append("api2.example.test")
        cfg["vm"]["network"]["policy"].append(
            {"host": "api2.example.test", "credential": "example-token"})
        flags = self.flags(cfg)
        self.assertEqual(sorted(v.split("=")[0] for v in flags["--host"]),
                         ["api.example.test", "api2.example.test"])
        self.assertEqual(len(flags["--placeholder"]), 1)

    def test_a_placeholder_carrying_a_quote_reaches_the_broker_intact(self):
        """Unquoted in the argv; the unit quotes each value with dq. A
        placeholder with a quote, a backslash, a `$` and a `%` is the case
        that would break either half on its own."""
        cfg = cred_config()
        cfg["vm"]["network"]["credential"][0]["placeholder"] = 'a"b\\c$d%e'
        self.assertEqual(self.flags(cfg)["--placeholder"][0].split("=", 1)[1],
                         'a"b\\c$d%e')

    def test_the_broker_accepts_what_the_command_says(self):
        """The whole line, through the shipped reader: every flag the
        command emits is one build_profiles takes, and the table it builds
        is keyed by the host the command named. test_broker_closure pins
        the flag SET against the entrypoint's parser; this pins the
        VALUES."""
        cfg = cred_config()
        flags = self.flags(cfg)
        profiles = broker_profiles.build_profiles(
            flags["--name"][0], flags["--host"], flags.get("--placeholder", []),
            flags.get("--auth-header", []), flags.get("--auth-format", []),
            load=lambda cred_id: f"secret-of-{cred_id}")
        self.assertEqual(list(profiles), ["api.example.test"])
        _path, cred_id = broker_credential("agent", "example-token")
        self.assertEqual(profiles["api.example.test"].secret,
                         f"secret-of-{cred_id}")
        self.assertEqual(profiles["api.example.test"].name,
                         "agent/api.example.test")


class TestTheCredentialId(unittest.TestCase):
    """The systemd credential id is the SEAL name, and it carries the workload.

    systemd-creds binds the id into the blob and verifies it on decrypt, so a
    generated unit pointing at another workload's file -- the path is guessable
    -- fails at start instead of serving that workload's key. Asked of
    secrets_template rather than spelled twice.
    """

    def test_it_matches_what_the_cli_seals_under(self):
        from secrets_template import credential_path
        path, cred_id = broker_credential("agent", "example-token")
        expected_path, expected_id = credential_path(
            Path("/etc/credstore.encrypted"), "broker/agent/example-token")
        self.assertEqual((path, cred_id), (expected_path, expected_id))

    def test_it_carries_the_workload_name(self):
        _path, cred_id = broker_credential("agent", "example-token")
        self.assertEqual(cred_id, "broker-agent-example-token")

    def test_two_workloads_get_different_ids_for_one_credential_name(self):
        _p1, a = broker_credential("one", "token")
        _p2, b = broker_credential("two", "token")
        self.assertNotEqual(a, b)


class TestTheGeneratedUnit(unittest.TestCase):
    """The instance's unit. Four properties, each load-bearing on its own."""

    def unit(self, cfg=None, uid=UID_MIN + 5):
        # The VM call site's four values, spelled here as gen_vm spells
        # them: the generator takes no defaults, so a test of the VM shape
        # has to say which shape it is testing.
        gen = importlib.import_module("gen_egress")
        cfg = cfg or cred_config()
        return gen.generate_broker_service(
            cfg, uid,
            before=f"workload-{cfg['workload']['name']}.service",
            hosts=vm_broker_hosts(cfg),
            upstream=vm_broker_upstream_addresses(cfg),
            command=vm_broker_command(cfg, uid))

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
        lines = [ln for ln in self.unit(cfg).splitlines()
                 if ln.startswith("LoadCredentialEncrypted=")]
        self.assertEqual(lines, [
            "LoadCredentialEncrypted=broker-agent-example-token:"
            "/etc/credstore.encrypted/broker/agent/example-token"])

    def test_it_is_started_once_the_broker_says_it_is_listening(self):
        """Type=notify, with the broker's own READY=1 (customs 0.5.0): as
        Type=exec the unit is started at the exec, and the unit ordered
        after it can send the broker a request before its socket exists."""
        unit = self.unit()
        self.assertIn("\nType=notify\n", unit)
        self.assertNotIn("NotifyAccess=", unit)

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
        resolvers = host_resolver_addresses()
        unit = self.unit()
        for addr in resolvers:
            self.assertIn(f"IPAddressAllow={addr}", unit)

    def test_resolved_upstreams_are_allowed(self):
        import nft_elements as vm_mod
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

    def test_it_execs_the_packaged_broker_with_every_value_on_the_line(self):
        """The ExecStart= is the command, each value dq-quoted and each flag
        bare: the unit is the only place the broker is told anything, so a
        value that did not reach the line is one the broker starts without.
        Spelled out rather than rendered through the same helper, so a
        change to how the line is written is a change to this string."""
        _path, cred_id = broker_credential("agent", "example-token")
        self.assertIn(
            f'ExecStart={BROKER_BIN} --name "agent" '
            f'--listen "{broker_listen_address(UID_MIN + 5)}:8081" '
            f'--caller-uid "{UID_MIN + 5}" '
            f'--host "api.example.test={cred_id}" '
            f'--placeholder "{cred_id}=sk-000000PLACEHOLDER"\n', self.unit())

    def test_a_placeholder_is_quoted_for_a_systemd_exec_line(self):
        """dq, not a bare join: a quote, a backslash, a `$` and a `%` each
        have a systemd spelling, and a placeholder is the one value on the
        line an operator writes freely."""
        cfg = cred_config()
        cfg["vm"]["network"]["credential"][0]["placeholder"] = 'a"b\\c$d%e'
        line = [ln for ln in self.unit(cfg).splitlines()
                if ln.startswith("ExecStart=")][0]
        self.assertIn('=a\\"b\\\\c$$d%%e"', line)

    def test_there_is_no_config_file_no_writer_and_no_runtime_directory(self):
        """The three things the document cost, asserted absent: a broker
        that reads a file at start is a broker whose unit and whose file
        can disagree, and the ExecStartPre that kept them agreeing was a
        second binary with the workload side's whole closure."""
        unit = self.unit()
        self.assertNotIn("ExecStartPre=", unit)
        self.assertNotIn("RuntimeDirectory", unit)
        self.assertNotIn("broker.toml", unit)
        self.assertNotIn("workload-broker-config", unit)


class TestTheVmUnitWaitsForIt(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.gen = importlib.import_module("gen_vm")

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
        from run_files import workload_run_files

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
        out = vm_default_seed.render_default_user_data(
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
        cfg["vm"]["network"]["credential"][0]["env"] = CA_ENV_VARS[0]
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
        """One producer now, and it used to be two.

        WORKLOAD_BROKER_URL was the other, and rung 6 stopped seeding it -- the
        guest is told no broker address at all. Derived rather than listed for
        exactly this reason: the set exists to refuse a credential `env` that
        would silently overwrite a variable workloadctl writes, so a name kept
        in it after its writer went refuses a legal name for a collision that
        cannot happen.
        """
        self.assertEqual(set(RESERVED_GUEST_ENV), set(CA_ENV_VARS))


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
        import shutil
        import cmd_drift
        from unittest import mock
        from tests import script_env
        from tests.test_generator_snapshot import (
            FIXTURES, GENERATOR, run_generator, write_config)

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

        # Pin the generator to THIS CHECKOUT. cmd_drift._find_generator prefers
        # /usr/libexec/workloadctl/workload-generate and only falls back to the
        # checkout when that is absent, which is right for the product and
        # wrong for a test: setUp renders the live tree with the checkout's
        # generator, so on a host that has the RPM installed collect_drift
        # would re-render with a DIFFERENT generator and every unit here would
        # be compared against another build's output. An installed copy that
        # predates this branch does not know `[[vm.network.credential]]` at
        # all, refuses the fixture, and emits nothing -- so every live unit
        # reads as an orphan and the drift list is the whole workload rather
        # than the one hand-edited file. Only test_broker ran the real
        # collect_drift unpinned; test_cmd_drift patches this same hook and
        # test_substrate patches subprocess.run.
        self.enterContext(mock.patch.object(
            cmd_drift, "_find_generator", lambda: Path(GENERATOR)))

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

from customs.egress_record import (
    DROP_BROKER_UNREACHABLE,
    DROP_REASONS,
    DROP_UNREACHABLE,
    LOG_ID_FIELD,
    RECORD_FIELDS,
    Where,
)
from egress_policy import vm_inspect_policy_text
from customs.inspect_document import VmPolicyEntry
from customs.inspect_policy import Policy, load_policy
from customs import egress_relay
from customs.egress_upstream import Upstream
from customs import inspect_http
from customs.inspect_listener import Listener
from customs.inspect_http import serve_cleartext
import inspect_figures

CIL = Path(__file__).resolve().parent.parent / "security" / "workload-inspect.cil"

_LISTENER_MOD = None


def listener_mod():
    global _LISTENER_MOD
    if _LISTENER_MOD is None:
        _LISTENER_MOD = load_script(CUSTOMS_LIBEXEC / "customs-inspect")
    return _LISTENER_MOD


# Captured before any test patches it: the rig's own upstream pair is built
# with create_connection, and the fake dial patches that name globally.
_REAL_CREATE_CONNECTION = socket.create_connection

_OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
_UNAUTHORIZED = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"

# The address this workload's broker would answer on. Injected rather than
# derived from os.getuid(), because the suite does not run as _wl-<name> and
# broker_listen_address refuses a uid outside the workload range -- see
# TestTheBrokerEndpointComesFromTheUid for the derivation itself, which is the
# generator's and not the inspector's.
BROKER_ADDR = broker_listen_address(10007)
BROKER_ENDPOINT = (BROKER_ADDR, BROKER_INSTANCE_PORT)


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
        return Policy(tls="splice", hosts=tuple(hosts),
                          policy=tuple(entries))

    def _serve(self, policy, request, responses=(), refuse=False,
               record=False):
        """Drive one cleartext connection. Returns (log, dialled, snapshot, records).

        `dialled` is [(address, bytes-that-arrived)] in dial order, which is
        the assertion this whole class exists to make.
        """
        out = io.StringIO()
        record_path = None
        if record:
            tmp = tempfile.TemporaryDirectory(prefix="broker-rec-")
            self.addCleanup(tmp.cleanup)
            record_path = str(Path(tmp.name) / "requests.log")
        listener = Listener([], out, policy=policy,
                                record_path=record_path,
                                broker_endpoint=BROKER_ENDPOINT)
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
                unittest.mock.patch.object(
                    egress_relay, "CONNECTION_TIMEOUT", 0.20), \
                unittest.mock.patch.object(
                    egress_relay, "RELAY_IDLE_TIMEOUT", 0.75):
            serve_cleartext(listener.inspection, ours, _where())
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
                listener.inspection.counters.snapshot(open_now=0, refused=0), records)


def _where():
    return Where(f"{LOG_ID_FIELD}=abc plane=cleartext",
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
        self.assertEqual(addr, (BROKER_ADDR, BROKER_INSTANCE_PORT))
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
        self.assertEqual(snap["drop_reasons"][DROP_BROKER_UNREACHABLE], 1)
        self.assertEqual(snap["drop_reasons"][DROP_UNREACHABLE], 0)
        self.assertIn(DROP_BROKER_UNREACHABLE, log)

    def test_the_guest_gets_a_502_that_names_nothing(self):
        """A silent close is the one outcome this listener argues against at
        length: a guest told 'no' by a dead socket cannot tell a refusal from
        the host being down. It gets a 502 -- and a generic body, because the
        sentence below names the broker, its unit and SELinux, and a guest
        that could read it would learn it is sandboxed. The body once carried
        that sentence."""
        self._serve(self._policy([BROKERED]), _GET_BROKERED, refuse=True)
        self.assertIn(b"502", self.answer)
        self.assertTrue(self.answer.endswith(b"\r\n\r\nBad Gateway\n"),
                        self.answer)

    def test_the_operator_is_pointed_at_the_unit_and_at_the_pair(self):
        """A broker that failed to start and a --broker that names another
        endpoint are indistinguishable from here, so the journal's sentence
        names both, and says the request was NOT sent: a retry will do the
        same thing until an operator touches the host."""
        log, _, _, _ = self._serve(
            self._policy([BROKERED]), _GET_BROKERED, refuse=True)
        self.assertIn("NOT sent", log)
        self.assertIn("broker's unit", log)
        self.assertIn("--listen", log)

    def test_the_failed_host_is_not_re_resolved(self):
        """dial_failure_reason exists to tell the wildcard trap from a dead
        host, and it does that by RE-RESOLVING the name. On this leg the name
        was never dialled -- a loopback address on this box was -- so running
        it would attribute a dead broker to whatever api.provider resolves to,
        and would pay a synchronous getaddrinfo for the wrong answer."""
        with unittest.mock.patch.object(
                inspect_http, "dial_failure_reason") as failure:
            self._serve(self._policy([BROKERED]), _GET_BROKERED, refuse=True)
        failure.assert_not_called()

    def test_an_unbrokered_host_still_gets_the_resolving_reason(self):
        """The guard for the test above: the generic path must keep the
        behaviour the broker path opts out of."""
        with unittest.mock.patch.object(
                inspect_http, "dial_failure_reason",
                return_value=DROP_UNREACHABLE) as failure:
            self._serve(self._policy([PLAIN]), _GET_PLAIN, refuse=True)
        failure.assert_called_once()


    def test_a_listener_with_no_endpoint_is_a_refusal_not_a_traceback(self):
        """A listener started by hand, outside its unit, is handed no broker
        endpoint. That has to reach the caller's broker arm as a legible
        refusal: a bare exception kills the connection thread with a
        traceback and tells the operator nothing about what is wrong."""
        upstream = Upstream()
        with self.assertRaises(OSError) as caught:
            upstream.dial_broker("api.provider")
        self.assertIn("without a broker endpoint", str(caught.exception))
        self.assertIn("api.provider", str(caught.exception))


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
        self.assertIn("credential", RECORD_FIELDS)
        self.assertIn("credential", RECORD_FIELDS)


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
        self.assertEqual(snap["drop_reasons"][DROP_BROKER_UNREACHABLE], 1)

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
            figure = inspect_figures.FIGURES_BY_KEY[key]
            self.assertEqual(len(figure.path), 1)
            self.assertIn(figure.path[0], snap)
            self.assertEqual(snap[figure.path[0]], 1)


class TestTheListenerReadsTheCredentialFromTheDocument(unittest.TestCase):
    """The seam T1 wrote the key at and T5 reads it at. Neither half is
    exercised by the other's tests, and a document that carries the key while
    the listener drops it is a workload whose every request quietly reaches
    the origin unbrokered."""

    def _load(self, net):
        with tempfile.TemporaryDirectory(prefix="policy-") as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(vm_inspect_policy_text(net))
            return load_policy(str(path))

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
        with tempfile.TemporaryDirectory(prefix="policy-") as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps({
                "tls": "inspect", "hosts": [],
                "policy": [{"host": "api.provider", "credential": 7}]}))
            policy = load_policy(str(path))
        self.assertIsNone(policy.credential_for("api.provider"))

    def test_the_first_governing_entry_that_carries_one_wins(self):
        """`validate` refuses two entries that match one host and disagree, so
        this is unreachable from a generated document. It is reached from a
        hand-edited one, and first-match is deterministic and matches the
        order the file states -- an arbitrary pick would make an editing
        mistake behave differently on different boots."""
        policy = Policy(
            tls="inspect", hosts=(),
            policy=(VmPolicyEntry("api.provider", None, ("/a",), None),
                    VmPolicyEntry("api.provider", None, ("/b",), "second")))
        self.assertEqual(policy.credential_for("api.provider"), "second")


class TestTheBrokerEndpointComesFromTheUid(unittest.TestCase):
    """The derivation is the GENERATOR's (gen_egress.inspect_listener_command),
    not the inspector's. The inspector takes an (address, port) pair on its
    command line and dials it; it has no idea that a uid becomes a loopback
    address, which is what keeps workload_addr and the rest of the host
    layout out of its closure.
    """

    def test_the_generator_derives_it_from_the_workloads_uid(self):
        """No registry and no allocation step: the inspector's unit and the
        broker's unit are both rendered from the same uid with the same
        function, so the two halves cannot drift."""
        from gen_egress import inspect_listener_command
        cmd = inspect_listener_command("web", 10007)
        self.assertEqual(cmd[cmd.index("--broker") + 1],
                         f"{BROKER_ADDR}:{BROKER_INSTANCE_PORT}")

    def test_the_two_units_carry_the_same_pair(self):
        """The inspector's --broker and the broker's --listen, for one uid,
        read back from the two commands. A mismatch presents exactly as the
        broker being down -- connection refused, no log line on either side
        -- which is why it is asserted on the rendered values and not on
        the function both call."""
        from gen_egress import inspect_listener_command
        dial = inspect_listener_command("web", 10007)
        cfg = cred_config(name="web")
        bind = vm_broker_command(cfg, 10007)
        self.assertEqual(dial[dial.index("--broker") + 1],
                         bind[bind.index("--listen") + 1])

    def test_the_entrypoint_parses_the_pair_it_is_given(self):
        """And derives nothing when it is not: a hand-written unit may
        serve a policy with no brokered host at all, and the refusal belongs
        on the first brokered request (the Upstream test above), not on the
        start."""
        mod = listener_mod()
        self.assertEqual(mod.broker_endpoint(f"{BROKER_ADDR}:{BROKER_INSTANCE_PORT}"),
                         BROKER_ENDPOINT)
        self.assertIsNone(mod.broker_endpoint(None))

    def test_the_inspector_dials_exactly_what_it_was_handed(self):
        upstream = Upstream(BROKER_ENDPOINT)
        with unittest.mock.patch.object(socket, "create_connection") as dial:
            upstream.dial_broker("api.provider")
            upstream.dial_broker("api.provider")
        self.assertEqual(dial.call_count, 2)
        for call in dial.call_args_list:
            self.assertEqual(call[0][0], BROKER_ENDPOINT)

    def test_the_inspector_does_not_import_the_derivation(self):
        """The property the split buys, asserted directly: egress_upstream
        names neither the address function nor the port constant. A dial that
        derived either would be one workloadctl-shaped assumption back inside
        the inspector."""
        from customs import egress_upstream
        source = Path(egress_upstream.__file__).read_text()
        self.assertNotIn("broker_listen_address", source)
        self.assertNotIn("BROKER_INSTANCE_PORT", source)
        self.assertNotIn("getuid", source)


class TestTheReasonIsSelectable(unittest.TestCase):
    """`workloadctl egress --reason` validates against DROP_REASONS, so a
    reason outside it is a refusal nobody can ask about."""

    def test_egress_can_filter_on_it(self):
        self.assertIn(DROP_BROKER_UNREACHABLE, DROP_REASONS)


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
        self.assertEqual(BROKER_INSTANCE_PORT, 8081)
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
        import diagnose_inspect
        doc = {"lists": self.BROKERED_LISTS, "dispositions": {"forwarded": 1},
               "drop_reasons": {}, "credentialed": 1,
               "credential_unauthorized": 0, "per_credential": {}}
        doc.update(status)
        return diagnose_inspect._credential_usage_fragments(doc)

    def test_a_workload_that_brokers_nothing_says_nothing(self):
        """Gated on the LOADED policy, not on the config: this function
        describes what the running listener did, and on a workload with no
        credential there is nothing here to describe. Ungated, the idle line
        below would fire on every filtered VM on the fleet."""
        import diagnose_inspect
        self.assertEqual(
            diagnose_inspect._credential_usage_fragments(
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
            drop_reasons={DROP_BROKER_UNREACHABLE: 4}, credentialed=0)
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


class TestTheRetiredKeyIsARefusal(unittest.TestCase):
    """`[vm.network].broker` fails by name; it is not ignored (ADR 007 d11).

    A deprecation was the alternative and is refused by premise 3: the key was
    a REACHABILITY switch for a mechanism that no longer exists, so accepting
    it and doing nothing would leave an operator believing a credential
    boundary exists where there is none. That is the same failure the key's own
    old .bridge check was written to prevent, so it is held to the standard it
    set.
    """

    def _errors(self, **net):
        from vm_validate import validate_vm_network
        return [e for e in validate_vm_network(net) if "broker" in e]

    def test_true_is_refused(self):
        errors = self._errors(broker=True)
        self.assertTrue(errors, "broker = true must not validate")
        self.assertTrue(any("was removed" in e for e in errors), errors)

    def test_false_is_refused_too(self):
        """The value is immaterial: the KEY names a mechanism that is gone.

        `broker = false` used to be a legal way to say nothing, so a check that
        only refused the truthy form would let the most likely leftover through
        -- an operator who turned it off rather than deleting the line.
        """
        self.assertTrue(self._errors(broker=False))

    def test_the_message_names_the_replacement_and_both_tables(self):
        """Naming the removal without naming the successor sends an operator
        to the schema doc for a key that is no longer in it."""
        message = " ".join(self._errors(broker=True))
        self.assertIn("[[vm.network.credential]]", message)
        self.assertIn("[[vm.network.policy]]", message)
        self.assertIn("credential", message)

    def test_it_is_refused_on_a_bridged_vm_as_well(self):
        """The old check made this case its own error ("no effect with
        .bridge"). It must not survive as a softer path: a bridged VM carrying
        the key is the same stale config as any other."""
        self.assertTrue(self._errors(broker=True, bridge="br0"))


class TestTheMapSweepIsGone(unittest.TestCase):
    """The generator's SECOND broker block, which no grep for a config key
    finds.

    It emitted `workload-broker-config up`/`down` on EVERY VM -- bridged ones
    included -- to scrub an element a reused uid could inherit from a deleted
    workload. That sweep was load-bearing while the map existed and is deleted
    with it: the entitlement now lives in the workload's own generated unit,
    which goes away with the workload, so there is nothing a uid can inherit.

    Asserted by absence, which is the shape [[unit-gates-dont-see-the-seam]]
    warns about. It was pinned against the helper's surviving `config` verb
    so that deleting the helper outright could not satisfy it -- and then
    the helper WAS deleted outright, with the document it wrote, so the
    positive half is now that no VM unit names the helper at all: the
    broker instance is the one unit that ever did, and its ExecStart= names
    the broker.
    """

    def _unit(self, config):
        gen = importlib.import_module("gen_vm")
        return gen.generate_vm_service(config, "_wl-agent", 10007)

    def test_no_vm_arms_a_broker_map_element(self):
        for label, net in (("filtered", {"egress": "filtered",
                                         "hosts": ["example.test"]}),
                           ("open", {"egress": "open"}),
                           ("bridged", {"bridge": "br0"})):
            with self.subTest(label):
                unit = self._unit({"workload": {"name": "agent"},
                                   "vm": {"network": net}})
                self.assertNotIn("workload-broker-config up", unit)
                self.assertNotIn("workload-broker-config down", unit)

    def test_the_helper_is_gone_and_nothing_names_it(self):
        """The negative above is only meaningful while nothing regrows it.
        The helper file is gone; the broker unit -- its one caller -- execs
        the broker; and no generated VM unit spells its name."""
        self.assertFalse((Path(__file__).resolve().parent.parent
                          / "libexec" / "workload-broker-config").exists())
        unit = TestTheGeneratedUnit().unit()
        self.assertNotIn("workload-broker-config", unit)
        self.assertIn(f"ExecStart={BROKER_BIN} ", unit)


class TestTheAdvertisedAddressIsNotAdded(unittest.TestCase):
    """D10: the dummy link survives, the 192.0.2.1 on it does not.

    Both halves are asserted, because each alone is the wrong change. Dropping
    the link would break every filtered workload's inspector addresses, which
    is what the link carries now; keeping the address leaves a host answering
    on a documentation range that nothing listens on and that the internal drop
    now refuses.
    """

    def _argvs(self):
        from workload_addr import ensure_advertised_interface

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        seen = []

        def run(argv):
            seen.append(argv)
            return Result()

        ensure_advertised_interface(run)
        return seen

    def test_the_link_is_still_created_and_brought_up(self):
        argvs = self._argvs()
        self.assertTrue(any("link" in a and "add" in a for a in argvs))
        self.assertTrue(any(a[1:3] == ["link", "set"] and "up" in a
                            for a in argvs), argvs)

    def test_no_address_is_added(self):
        for argv in self._argvs():
            self.assertNotIn("addr", argv, argv)
            self.assertFalse(any("192.0.2" in str(part) for part in argv), argv)

    def test_the_constant_is_gone_rather_than_unused(self):
        """An unused constant is the residue this rung exists to stop leaving,
        and it is what a later reader would wire back up."""
        import nft_elements
        self.assertFalse(hasattr(nft_elements, "VM_ADVERTISED_ADDR"))

    def test_test_net_1_is_now_an_internal_destination(self):
        """The consequence, and the reason the range moves rather than simply
        losing its exclusion comment: with nothing carrying it, TEST-NET-1 is
        exactly what the internal drop exists to refuse."""
        from nft_constants import INTERNAL_PREFIXES4
        self.assertIn("192.0.2.0/24", INTERNAL_PREFIXES4)


class TestTheRetiredMechanismLeavesNoSymbols(unittest.TestCase):
    """Every name F3 lists, asserted absent from lib/nft_elements.py.

    One test rather than eight, and by attribute rather than by grep: a
    half-deleted mechanism is what leaves a caller importing a name that still
    resolves, and this is the cheapest thing that notices.
    """

    def test_none_of_them_resolve(self):
        import nft_elements
        for name in ("VM_BROKER_PORT", "VM_BROKER_LISTEN_ADDR",
                     "VM_BROKER_LISTEN_PORT", "VM_BROKER_ENV_VAR",
                     "NFT_BROKER_SKELETON", "NFT_BROKER_TABLE",
                     "NFT_BROKER_MAP", "vm_uses_broker", "vm_broker_element",
                     "vm_broker_map_command", "vm_broker_env"):
            with self.subTest(name):
                self.assertFalse(hasattr(nft_elements, name))

    def test_the_guest_is_told_nothing_about_a_broker(self):
        """RESERVED_GUEST_ENV loses its second producer.

        Not cosmetic: the set is what refuses a credential's `env` for
        colliding with a variable workloadctl seeds. Nothing seeds
        WORKLOAD_BROKER_URL any more, so continuing to reserve it would refuse
        a legal name for a collision that cannot happen.
        """
        self.assertEqual(set(RESERVED_GUEST_ENV), set(CA_ENV_VARS))
        self.assertNotIn("WORKLOAD_BROKER_URL", RESERVED_GUEST_ENV)

    def test_the_skeleton_and_the_host_wide_unit_are_gone(self):
        root = Path(__file__).resolve().parent.parent
        self.assertFalse((root / "nftables" / "workload-broker.nft").exists())
        self.assertFalse((root / "systemd" / "agent-broker.service").exists())

    def test_the_spec_ships_neither(self):
        """Deleting a file the spec still installs makes the RPM fail to build,
        which is a late and confusing way to learn about a missed line."""
        spec = (Path(__file__).resolve().parent.parent
                / "rpm" / "workloadctl.spec").read_text()
        self.assertNotIn("workload-broker.nft", spec)
        self.assertNotIn("%{_unitdir}/agent-broker.service", spec)
        self.assertNotIn("systemd/agent-broker.service", spec)
        self.assertNotIn("libexec/agent-broker", spec)


class TestTheBrokerAddressIsExemptedFromTheInternalDrop(unittest.TestCase):
    """The second defect broker_rig.py found on real guests.

    The broker listens on 127.129.x.y. That is inside 127.0.0.0/8, which is
    inside `wl_internal4`, and the drop keyed on this workload's cgroup sits
    ABOVE the skeleton's `oif lo accept` -- so the inspector's dial to its own
    broker was dropped by the rule that exists to stop a GUEST reaching the
    LAN. Nothing said so: the connect timed out, the listener counted
    `credential broker unreachable`, and the guest got a 502 telling an
    operator to go and look at a unit that was running perfectly.

    Every unit test passed, because no unit test sends a packet. What can be
    asserted here is the wiring and the premise underneath it, which is what
    these two do.
    """

    def _up(self):
        source = (Path(__file__).resolve().parent.parent
                  / "lib" / "inspect_arm.py").read_text()
        return source[source.index("def up("):source.index("def down(")]

    def test_the_address_is_one_the_drop_would_match(self):
        """The premise. If the broker's address were NOT in the internal set,
        the exemption below would be dead code and this whole class would be
        asserting a no-op -- so the range membership is asserted rather than
        assumed."""
        addr = ipaddress.ip_address(broker_listen_address(UID_MIN + 7))
        armed = internal_ok_elements(UID_MIN + 7, [addr])
        self.assertTrue(
            any(entries for entries in armed.values()),
            f"{addr} is not in wl_internal4, so the inspector's dial to it "
            f"was never dropped and this exemption is unnecessary")

    def test_the_arming_helper_adds_it_only_for_a_workload_that_has_one(self):
        """A workload with no credentials must gain no exemption: the element
        is a hole in the drop, and one opened for a workload with no broker
        behind it is a hole with nothing on the other side."""
        up = self._up()
        self.assertIn("sub.uses_credentials(config)", up)
        self.assertIs(inspect_arm.VM.uses_credentials, vm_uses_credentials)
        self.assertIn("broker_listen_address(uid)", up)
        # Appended to the list the exemptions are built from, and BEFORE the
        # commands are generated -- after them it would be armed by nothing.
        self.assertLess(up.index("broker_listen_address(uid)"),
                        up.index('internal_ok_commands(uid, addresses, "add")'))
        # And purged with the rest, so dropping the last credential removes it.
        self.assertLess(up.index("purge_internal_exemptions(uid, name)"),
                        up.index("broker_listen_address(uid)"))


def _cred_net(policy, credential):
    return {"egress": "filtered", "credential": credential, "policy": policy}


class TestTheProvidersAuthConvention(unittest.TestCase):
    """`auth_header`/`auth_format` on [[vm.network.credential]].

    ADR 007 names the profile as `(upstream, credential, auth_header,
    auth_format)` and lists "one profile per sandbox" as the limit this rung
    removes. The first render emitted the first two and silently defaulted the
    rest, so every generated instance ran `x-api-key: {secret}` -- and a
    provider wanting `Authorization: Bearer` answered 401 on a request the
    inspector had recorded as fully authorised and brokered. The hand-written
    host-wide config could express it; the generated one could not, which made
    the new shape a regression for a whole class of provider with no key in
    workload.toml to fix it with.
    """

    def _flags(self, credential, policy=None):
        policy = policy or [{"host": "api.x.test", "credential": "k"}]
        config = {"workload": {"name": "agent"},
                  "vm": {"network": _cred_net(policy, credential)}}
        self.assertEqual(
            validate_vm_network(config["vm"]["network"]), [],
            "the fixture itself does not validate")
        return flags_of(vm_broker_command(config, UID_MIN + 7))

    def test_a_provider_that_wants_bearer_can_be_named(self):
        flags = self._flags([{"name": "k", "placeholder": "P", "env": "E",
                              "auth_header": "Authorization",
                              "auth_format": "Bearer {secret}"}])
        _path, cred_id = broker_credential("agent", "k")
        self.assertEqual(flags["--auth-header"], [f"{cred_id}=Authorization"])
        self.assertEqual(flags["--auth-format"], [f"{cred_id}=Bearer {{secret}}"])

    def test_saying_nothing_emits_nothing_rather_than_the_default(self):
        """The default belongs to the broker, in one place. Writing it out here
        would make two copies, and the second one is the one that goes stale
        after the first changes."""
        flags = self._flags([{"name": "k", "placeholder": "P", "env": "E"}])
        self.assertNotIn("--auth-header", flags)
        self.assertNotIn("--auth-format", flags)

    def test_the_broker_applies_both_where_they_are_written(self):
        """Keyed by the credential id, which is how the broker joins them
        to a --host. A key it cannot join is refused at startup, which for a
        generated unit is a restart loop."""
        flags = self._flags([{"name": "k", "placeholder": "P", "env": "E",
                              "auth_header": "Authorization",
                              "auth_format": "Bearer {secret}"}])
        profiles = broker_profiles.build_profiles(
            "agent", flags["--host"], flags["--placeholder"],
            flags["--auth-header"], flags["--auth-format"],
            load=lambda cred_id: "S")
        self.assertEqual(profiles["api.x.test"].auth_header, "Authorization")
        self.assertEqual(profiles["api.x.test"].auth_value, "Bearer S")

    def test_a_header_that_is_not_a_header_is_refused(self):
        for bad in ("X-Key: oops", "X Key", "X-Key\nInjected", ""):
            with self.subTest(header=bad):
                errors = validate_vm_network(_cred_net(
                    [{"host": "api.x.test", "credential": "k"}],
                    [{"name": "k", "placeholder": "P", "env": "E",
                      "auth_header": bad}]))
                self.assertTrue(any("auth_header" in e for e in errors), bad)

    def test_a_header_that_cannot_carry_a_credential_is_refused(self):
        """Framing and hop-by-hop names. Each produces a request that goes
        upstream with no material on it -- the credential is either overwritten
        or stripped -- and a 401 whose cause is invisible from every layer
        here."""
        for bad in ("Content-Length", "host", "Connection",
                    "Transfer-Encoding", "Proxy-Authorization"):
            with self.subTest(header=bad):
                errors = validate_vm_network(_cred_net(
                    [{"host": "api.x.test", "credential": "k"}],
                    [{"name": "k", "placeholder": "P", "env": "E",
                      "auth_header": bad}]))
                self.assertTrue(any("auth_header" in e for e in errors), bad)

    def test_a_format_that_the_broker_would_exit_on_is_refused_here(self):
        """The broker renders auth_format once at startup with str.format and
        exits on a bad one. For a GENERATED unit that is a workload whose
        broker will not start, so the same verdict is delivered at `validate`
        where it names the key."""
        for bad in ("Bearer {token}", "Bearer", "Bearer {secret} {secret}",
                    "Bearer {"):
            with self.subTest(fmt=bad):
                errors = validate_vm_network(_cred_net(
                    [{"host": "api.x.test", "credential": "k"}],
                    [{"name": "k", "placeholder": "P", "env": "E",
                      "auth_format": bad}]))
                self.assertTrue(any("auth_format" in e for e in errors), bad)

    def test_an_absent_key_stays_none_rather_than_becoming_the_default(self):
        creds = vm_credential_entries(
            {"credential": [{"name": "k", "placeholder": "P", "env": "E"}]})
        self.assertIsNone(creds[0].auth_header)
        self.assertIsNone(creds[0].auth_format)


class TestOneFlagPerHost(unittest.TestCase):
    """Splitting one host's rules across policy entries must still start.

    `/v1/*` for GET and `/v2/*` for POST, one credential, is the ordinary way
    to write §3 and it validates -- the per-host credential rule only refuses
    entries that DISAGREE about which credential. Rendered per entry, the
    old document held `[sandboxes.agent.hosts."api.x.test"]` twice, which
    TOML refused outright: the broker exited at start and every brokered
    request 502'd, on a workload whose config `validate` had just called
    clean. The broker refuses a repeated --host for a reason of its own (two
    spellings of one host), so the collapse is still what keeps it up.
    """

    def _config(self, policy):
        return {"workload": {"name": "agent"},
                "vm": {"network": _cred_net(
                    policy,
                    [{"name": "k", "placeholder": "P", "env": "E"}])}}

    def test_two_entries_for_one_host_emit_one_flag(self):
        policy = [{"host": "api.x.test", "credential": "k",
                   "paths": ["/v1/*"], "methods": ["GET"]},
                  {"host": "api.x.test", "credential": "k",
                   "paths": ["/v2/*"], "methods": ["POST"]}]
        config = self._config(policy)
        self.assertEqual(validate_vm_network(config["vm"]["network"]), [],
                         "the fixture is refused, so the command is untested")
        flags = flags_of(vm_broker_command(config, UID_MIN + 7))
        # The assertion is that the BROKER TAKES IT. A count of flags would
        # pass against a command the reader then refused for another reason.
        profiles = broker_profiles.build_profiles(
            "agent", flags["--host"], flags["--placeholder"], load=lambda c: "S")
        self.assertEqual(list(profiles), ["api.x.test"])

    def test_two_hosts_still_get_two_flags(self):
        """The collapse must be on the host, not on the credential: two hosts
        sharing one credential are two upstreams."""
        policy = [{"host": "a.x.test", "credential": "k"},
                  {"host": "b.x.test", "credential": "k"}]
        flags = flags_of(vm_broker_command(self._config(policy), UID_MIN + 7))
        self.assertEqual(sorted(v.split("=")[0] for v in flags["--host"]),
                         ["a.x.test", "b.x.test"])
