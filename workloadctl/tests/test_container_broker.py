"""The container-side credential broker instance (Phase 2 of container egress parity).

There is no second broker here, and that is the design rather than an
economy. `libexec/agent-broker`, the unit generator, the `broker.toml` render,
the run-file entry and the nftables carve-out are all the VM ones, reached
from the container branch with substrate-specific values passed in. So most
of what this file asserts is that the two callers produce the SAME artifact
for the same declaration -- because the alternative shape, a container twin of
each, would have reproduced both of the render defects the VM side was already
fixed for (a per-entry duplicate table that TOML refuses, and a dropped
`auth_header`/`auth_format` that 401s a fully authorised request).

The one place the two substrates genuinely differ is ordering, and it is the
one that reaches a host unnoticed: `Before=workload-<name>.service` is correct
for a VM and for a single-mode container, and WRONG in pod/bridge mode, where
the umbrella carries `After=` its member services -- so it would order the
broker after every container has already started. Same hole the inspector
arming was moved off the umbrella for, and single mode being unaffected is
exactly what hides it.
"""

import ipaddress
import tempfile
import unittest
from pathlib import Path

from tests.test_generator import run_generator, write_config
from vm import vm_internal_ok_elements
from broker_config import (
    VM_BROKER_INSTANCE_PORT, container_broker_hosts,
    container_broker_upstream_addresses, container_uses_credentials,
    render_container_broker_config, render_vm_broker_config,
    vm_broker_credential,
)
from workload_addr import UID_MIN, vm_broker_listen_address
from workload_lib import validate_container_network

import tomllib


CREDENTIAL = {"name": "example-token",
              "placeholder": "sk-000000PLACEHOLDER",
              "env": "EXAMPLE_API_KEY"}


def cred_net(**over):
    net = {
        "hosts": ["api.example.test"],
        "ca_delivery": "env",
        "credential": [dict(CREDENTIAL)],
        "policy": [{"host": "api.example.test", "credential": "example-token"}],
    }
    net.update(over)
    return net


def cred_config(name="capp", **over):
    return {"workload": {"name": name},
            "container": {"image": "localhost/app:latest"},
            "network": cred_net(**over)}


CRED_TOML = """\
[workload]
name = "{name}"
{extra}
[network]
hosts = ["api.example.test"]
ca_delivery = "env"

[[network.credential]]
name = "example-token"
placeholder = "sk-000000PLACEHOLDER"
env = "EXAMPLE_API_KEY"

[[network.policy]]
host = "api.example.test"
credential = "example-token"
"""

SINGLE = """
[container]
image = "docker.io/library/nginx:latest"
"""

POD = """
mode = "pod"

[[containers]]
name = "app"

[containers.container]
image = "docker.io/library/nginx:latest"

[[containers]]
name = "side"

[containers.container]
image = "docker.io/library/nginx:latest"
"""

BRIDGE = POD.replace('mode = "pod"', 'mode = "bridge"')


class TestUsesCredentials(unittest.TestCase):
    """Which container workloads get an instance at all.

    Both halves, same as the VM predicate: a declared credential AND
    inspection. The inspector is the only thing that dials the broker on
    either substrate, so an instance for an uninspected container would hold
    a decrypted provider key for a path that does not exist.
    """

    def test_a_declaring_inspected_container_gets_one(self):
        self.assertTrue(container_uses_credentials(cred_config()))

    def test_no_credential_block_means_no_instance(self):
        config = cred_config()
        config["network"].pop("credential")
        config["network"]["policy"] = [{"host": "api.example.test"}]
        self.assertFalse(container_uses_credentials(config))

    def test_no_network_table_at_all_means_no_instance(self):
        self.assertFalse(container_uses_credentials(
            {"workload": {"name": "capp"},
             "container": {"image": "localhost/app:latest"}}))

    def test_host_mode_gets_none_even_declaring_one(self):
        """Host mode is never inspected (one netns, many uids), so it can
        never be brokered either -- and validate refuses the combination."""
        config = cred_config()
        config["network"]["mode"] = "host"
        self.assertFalse(container_uses_credentials(config))

    def test_a_malformed_network_table_is_not_an_instance(self):
        self.assertFalse(container_uses_credentials(
            {"workload": {"name": "capp"}, "network": "yes"}))


class TestValidationRefusesWhatCannotBeBrokered(unittest.TestCase):
    """The rules the schema reference states for containers.

    Each names a failure that arrives somewhere else: an undeclared
    credential is a host the operator believes is brokered and is not (the
    request reaches the provider carrying the placeholder and gets a 401 on a
    fully authorised request), and a wildcard carrying one is authorised here
    and refused at a broker whose table has no patterns in it.
    """

    def _errors(self, **over):
        return validate_container_network(cred_net(**over))

    def test_a_credential_no_block_declares_is_refused(self):
        errors = self._errors(
            policy=[{"host": "api.example.test", "credential": "absent"}])
        self.assertTrue(any("absent" in e and "declares" in e for e in errors),
                        errors)

    def test_a_wildcard_carrying_a_credential_is_refused(self):
        errors = self._errors(
            hosts=["*.example.test"],
            policy=[{"host": "*.example.test", "credential": "example-token"}])
        self.assertTrue(
            any("exact host" in e for e in errors), errors)

    def test_a_credential_nothing_selects_is_refused(self):
        errors = self._errors(policy=[{"host": "api.example.test"}])
        self.assertTrue(
            any("example-token" in e and "selects it" in e for e in errors),
            errors)

    def test_host_mode_names_credential_among_the_conflicts(self):
        """P2-0. Without this the key reads as accepted under host mode --
        and the whole point of the message is that it names the keys the
        bundle actually set."""
        errors = validate_container_network(
            {"mode": "host", "credential": [dict(CREDENTIAL)]})
        self.assertTrue(
            any("[network].credential" in e and 'mode = "host"' in e
                for e in errors), errors)

    def test_a_clean_declaration_validates(self):
        self.assertEqual(self._errors(), [])


class TestTheRenderIsTheVmRender(unittest.TestCase):
    """P2-1: one renderer, two callers.

    ContainerCredential and VmCredential are field-identical by construction,
    so the same declaration must produce the same file. Asserted against the
    VM render itself rather than against a spelled-out expectation, because
    what matters is that the two cannot drift -- a container twin would have
    carried its own copy of every defect this render has been fixed for.
    """

    def _vm_equivalent(self, name="capp"):
        return {"workload": {"name": name},
                "vm": {"network": {"egress": "filtered",
                                   "hosts": ["api.example.test"],
                                   "credential": [dict(CREDENTIAL)],
                                   "policy": [{"host": "api.example.test",
                                               "credential": "example-token"}]}}}

    def test_the_two_substrates_render_the_same_bytes(self):
        uid = UID_MIN + 3
        self.assertEqual(render_container_broker_config(cred_config(), uid),
                         render_vm_broker_config(self._vm_equivalent(), uid))

    def test_it_parses_and_carries_the_uid_derived_address(self):
        uid = UID_MIN + 3
        doc = tomllib.loads(render_container_broker_config(cred_config(), uid))
        self.assertEqual(doc["listen_address"], vm_broker_listen_address(uid))
        self.assertEqual(doc["listen_port"], VM_BROKER_INSTANCE_PORT)
        self.assertNotEqual(doc["listen_address"], "127.0.0.1")

    def test_two_policy_entries_for_one_host_render_one_table(self):
        """S6, which is a file that TOML refuses: split a host's rules across
        entries -- the ordinary way to write a method/path policy -- and a
        per-entry render emits the same table twice, so the broker exits at
        start and every brokered request 502s on a config `validate` just
        called clean."""
        config = cred_config(policy=[
            {"host": "api.example.test", "methods": ["GET"],
             "paths": ["/v1/*"], "credential": "example-token"},
            {"host": "api.example.test", "methods": ["POST"],
             "paths": ["/v2/*"], "credential": "example-token"},
        ])
        doc = tomllib.loads(
            render_container_broker_config(config, UID_MIN + 3))
        self.assertEqual(
            list(doc["sandboxes"]["capp"]["hosts"]), ["api.example.test"])

    def test_the_providers_auth_convention_reaches_the_file(self):
        """S5. Without these two keys the broker falls back to its own
        default, and a provider wanting `Authorization: Bearer` answers 401
        on a request every layer here authorised."""
        credential = dict(CREDENTIAL, auth_header="Authorization",
                          auth_format="Bearer {credential}")
        doc = tomllib.loads(render_container_broker_config(
            cred_config(credential=[credential]), UID_MIN + 3))
        host = doc["sandboxes"]["capp"]["hosts"]["api.example.test"]
        self.assertEqual(host["auth_header"], "Authorization")
        self.assertEqual(host["auth_format"], "Bearer {credential}")

    def test_an_omitted_convention_leaves_the_key_out(self):
        """One default, in the broker. Writing it here would be a second copy
        to disagree with the first."""
        host = tomllib.loads(render_container_broker_config(
            cred_config(), UID_MIN + 3))["sandboxes"]["capp"]["hosts"]
        self.assertNotIn("auth_header", host["api.example.test"])

    def test_an_uncredentialed_entry_is_not_in_the_table(self):
        """A host the container reaches carrying whatever it holds is not the
        broker's business, and a row for it would authorise material there."""
        config = cred_config(
            hosts=["api.example.test", "plain.example.test"],
            policy=[{"host": "api.example.test", "credential": "example-token"},
                    {"host": "plain.example.test"}])
        self.assertEqual(container_broker_hosts(config),
                         [("api.example.test", "example-token")])


class TestTheGeneratedUnit(unittest.TestCase):
    """P2-2/P2-3: emitted from the container branch, ordered correctly."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def _generate(self, name, extra):
        write_config(self.config_dir, name,
                     CRED_TOML.format(name=name, extra=extra))
        result = run_generator(self.config_dir, self.services_dir,
                               self.sysusers_dir)
        self.assertEqual(result.returncode, 0, result.stderr)
        path = Path(self.services_dir) / f"workload-{name}-broker.service"
        return path

    def test_a_declaring_single_mode_container_gets_the_unit(self):
        self.assertTrue(self._generate("capp", SINGLE).exists())

    # --- something has to START it (found on hardware, not here) ---------
    #
    # The generator emitted the instance, ordered it ahead of the right unit,
    # gave it its egress bound and its wl_internal_ok4 element -- and nothing
    # pulled it in, so it sat inactive and every brokered request 502'd while
    # the workload's own units all read active. `Before=` ORDERS a unit; it
    # does not start one. Every row in this file passed with the defect in
    # place because each of them reads the broker unit's own text, and the
    # missing half was in a different unit entirely.

    def _unit_text(self, name, extra, unit):
        self._generate(name, extra)
        return (Path(self.services_dir) / unit).read_text()

    def test_single_mode_requires_the_broker_from_the_workload_service(self):
        text = self._unit_text("capp", SINGLE, "workload-capp.service")
        self.assertIn("Requires=workload-capp-broker.service", text)
        self.assertIn("After=workload-capp-broker.service", text)

    def test_pod_mode_requires_it_from_the_POD_unit(self):
        # The head unit, for the reason it owns the egress arming: the
        # umbrella is After= its members, so a Requires= there would start the
        # broker after every container had already run.
        text = self._unit_text("cpod", POD, "workload-cpod-pod.service")
        self.assertIn("Requires=workload-cpod-broker.service", text)

    def test_bridge_mode_requires_it_from_the_NET_unit(self):
        text = self._unit_text("cbr", BRIDGE, "workload-cbr-net.service")
        self.assertIn("Requires=workload-cbr-broker.service", text)

    def test_the_umbrella_is_not_what_requires_it_in_pod_mode(self):
        # The premise, pinned: if the umbrella ever stopped being After= its
        # members, putting the dependency on the head unit would stop being a
        # fix and this row is what would notice.
        text = self._unit_text("cpod", POD, "workload-cpod.service")
        self.assertIn("After=", text)
        self.assertNotIn("Requires=workload-cpod-broker.service", text)

    def test_a_workload_with_no_credential_requires_no_broker(self):
        write_config(self.config_dir, "plain", """\
            [workload]
            name = "plain"

            [container]
            image = "docker.io/library/nginx:latest"

            [network]
            hosts = ["api.example.test"]
            """)
        result = run_generator(self.config_dir, self.services_dir,
                               self.sysusers_dir)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = (Path(self.services_dir) / "workload-plain.service").read_text()
        self.assertNotIn("broker", text)

    def test_a_container_declaring_none_gets_no_unit(self):
        write_config(self.config_dir, "plain", """\
            [workload]
            name = "plain"

            [container]
            image = "docker.io/library/nginx:latest"

            [network]
            hosts = ["api.example.test"]
            """)
        result = run_generator(self.config_dir, self.services_dir,
                               self.sysusers_dir)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(
            (Path(self.services_dir) / "workload-plain-broker.service").exists())

    def test_single_mode_orders_it_before_the_container_unit(self):
        unit = self._generate("capp", SINGLE).read_text()
        self.assertIn("Before=workload-capp.service", unit)

    def test_pod_mode_orders_it_before_the_POD_unit_not_the_umbrella(self):
        """P2-3, and the row this class exists for. The umbrella is `After=`
        its members, so `Before=workload-<name>.service` here would put the
        broker after every container has started: the first brokered request
        in that window is refused with `credential broker unreachable` while
        every unit reads healthy."""
        unit = self._generate("cpod", POD).read_text()
        self.assertIn("Before=workload-cpod-pod.service", unit)
        self.assertNotIn("Before=workload-cpod.service", unit)

    def test_bridge_mode_orders_it_before_the_NET_unit(self):
        unit = self._generate("cbr", BRIDGE).read_text()
        self.assertIn("Before=workload-cbr-net.service", unit)
        self.assertNotIn("Before=workload-cbr.service", unit)

    def test_the_head_unit_it_precedes_is_the_one_that_precedes_the_members(self):
        """The premise the row above rests on. If the pod head unit were not
        itself ordered ahead of the member containers, ordering the broker
        before it would buy nothing -- so the property is asserted rather
        than assumed, on the same generated pair."""
        self._generate("cpod", POD)
        member = (Path(self.services_dir)
                  / "workload-cpod-app.service").read_text()
        self.assertIn("After=workload-cpod-pod.service", member)

    def test_the_instance_is_a_dynamic_user_and_not_the_workload_uid(self):
        """The whole of the protection: the workload uid is what a container
        escape obtains, and the credential is only ever decrypted into the
        broker's own tmpfs."""
        unit = self._generate("capp", SINGLE).read_text()
        self.assertIn("DynamicUser=yes", unit)
        self.assertNotIn("User=_wl-capp", unit)

    def test_it_loads_the_material_under_its_seal_name(self):
        unit = self._generate("capp", SINGLE).read_text()
        path, cred_id = vm_broker_credential("capp", "example-token")
        self.assertIn(f"LoadCredentialEncrypted={cred_id}:{path}", unit)

    def test_one_load_line_per_declared_credential_not_per_host(self):
        """Two hosts may share one credential, and loading it twice under one
        id is an error systemd reports at start."""
        write_config(self.config_dir, "cshare", """\
            [workload]
            name = "cshare"

            [container]
            image = "docker.io/library/nginx:latest"

            [network]
            hosts = ["a.example.test", "b.example.test"]
            ca_delivery = "env"

            [[network.credential]]
            name = "example-token"
            placeholder = "sk-000000PLACEHOLDER"
            env = "EXAMPLE_API_KEY"

            [[network.policy]]
            host = "a.example.test"
            credential = "example-token"

            [[network.policy]]
            host = "b.example.test"
            credential = "example-token"
            """)
        result = run_generator(self.config_dir, self.services_dir,
                               self.sysusers_dir)
        self.assertEqual(result.returncode, 0, result.stderr)
        unit = (Path(self.services_dir)
                / "workload-cshare-broker.service").read_text()
        self.assertEqual(unit.count("LoadCredentialEncrypted="), 1)

    def test_it_is_bounded_by_an_address_allowlist_with_a_deny_under_it(self):
        """The instance's uid is NOT in wl_filtered -- that disjointness is
        what the protection rests on -- so workload-filter.nft's default-deny
        never applies to this leg and these two directives are its sole
        egress bound. A missing IPAddressDeny= is not a degraded bound but no
        bound at all."""
        unit = self._generate("capp", SINGLE).read_text()
        self.assertIn("IPAddressAllow=localhost", unit)
        self.assertIn("IPAddressDeny=any", unit)
        self.assertLess(unit.index("IPAddressAllow=localhost"),
                        unit.index("IPAddressDeny=any"))

    def test_it_stops_with_the_workload_that_owns_it(self):
        unit = self._generate("capp", SINGLE).read_text()
        self.assertIn("PartOf=workload-capp.service", unit)

    def test_the_container_never_learns_where_it_is(self):
        """The invariant. A container that could name the broker could be
        pointed at another workload's, so the address must appear in the
        broker's own unit and nowhere the workload reads."""
        self._generate("capp", SINGLE)
        addr = vm_broker_listen_address(
            int([l for l in (Path(self.sysusers_dir) / "workload-capp.conf")
                 .read_text().split("\n") if l.startswith("u ")][0].split()[2]))
        service = (Path(self.services_dir)
                   / "workload-capp.service").read_text()
        self.assertNotIn(addr, service)


class TestTheUpstreamAllowlist(unittest.TestCase):
    def test_an_unresolvable_upstream_contributes_nothing_and_is_not_an_error(self):
        """The safe failure: with IPAddressDeny=any under the list, an
        unresolvable upstream is a broker that cannot reach that provider and
        says so per request, rather than one that reaches everything."""
        self.assertEqual(container_broker_upstream_addresses(cred_config()), [])

    def test_an_uncredentialed_host_is_not_allowlisted(self):
        config = cred_config(
            hosts=["api.example.test", "plain.example.test"],
            policy=[{"host": "api.example.test", "credential": "example-token"},
                    {"host": "plain.example.test"}])
        self.assertEqual(container_broker_upstream_addresses(config), [])


class TestThePlaceholderSeed(unittest.TestCase):
    """The container half of the fiction.

    Without it the brokered path does not work at all, and it fails in the one
    place nothing on the host can see: the container holds nothing in the
    variable its client reads, so either the client refuses to send a request
    -- inside the container, before a packet, which looks nothing like a
    policy failure -- or it sends one with no header for the broker's
    substitution to replace and the provider answers 401 on a request every
    layer here authorised.
    """

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def _unit(self, name, extra):
        write_config(self.config_dir, name,
                     CRED_TOML.format(name=name, extra=extra))
        result = run_generator(self.config_dir, self.services_dir,
                               self.sysusers_dir)
        self.assertEqual(result.returncode, 0, result.stderr)
        return (Path(self.services_dir) / f"workload-{name}.service").read_text()

    def test_the_container_is_seeded_with_the_placeholder(self):
        unit = self._unit("capp", SINGLE)
        self.assertIn('--env EXAMPLE_API_KEY="sk-000000PLACEHOLDER"', unit)

    def test_a_container_declaring_none_is_seeded_with_nothing(self):
        write_config(self.config_dir, "plain", """\
            [workload]
            name = "plain"

            [container]
            image = "docker.io/library/nginx:latest"

            [network]
            hosts = ["api.example.test"]
            """)
        result = run_generator(self.config_dir, self.services_dir,
                               self.sysusers_dir)
        self.assertEqual(result.returncode, 0, result.stderr)
        unit = (Path(self.services_dir) / "workload-plain.service").read_text()
        self.assertNotIn("--env EXAMPLE_API_KEY", unit)

    def test_the_real_material_is_never_in_the_unit(self):
        """The container gets the fiction and only the fiction. The sealed
        material is decrypted into the broker's own tmpfs, under a dynamic
        user disjoint from the workload's, and nothing the workload can read
        ever holds it."""
        unit = self._unit("capp", SINGLE)
        self.assertNotIn("LoadCredentialEncrypted", unit)
        self.assertNotIn("broker-capp-example-token", unit)


class TestTheRunFileEntry(unittest.TestCase):
    """P2-4. Superset semantics: listed for every container so a workload that
    drops its last credential has the unit unlinked rather than left behind
    holding material nothing selects -- invisible to `drift` and `disable`
    otherwise. `present=` is the same predicate the generator emits on, so
    the two cannot disagree about which workloads have one.
    """

    def _entry(self, toml_text):
        from unittest import mock
        import workload_lib
        from workloadctl_core import WorkloadConfig
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "capp").mkdir()
            (root / "capp" / "workload.toml").write_text(toml_text)
            with mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", root), \
                    mock.patch.object(WorkloadConfig, "uid",
                                      new_callable=mock.PropertyMock,
                                      return_value=UID_MIN + 1):
                wc = WorkloadConfig("capp")
                config = wc.config
                files = workload_lib.workload_run_files(wc)
        entry = next(f for f in files
                     if f.path.name == "workload-capp-broker.service")
        return entry, config

    def test_a_declaring_container_has_it_emitted(self):
        entry, _ = self._entry(CRED_TOML.format(name="capp", extra=SINGLE))
        self.assertTrue(entry.emitted)

    def test_a_container_with_no_credential_still_lists_it_unemitted(self):
        entry, _ = self._entry("""\
[workload]
name = "capp"

[container]
image = "docker.io/library/nginx:latest"

[network]
hosts = ["api.example.test"]
""")
        self.assertFalse(entry.emitted)

    def test_the_present_half_is_the_generator_predicate(self):
        """Not a restatement of it: a second copy is how the two come to
        disagree, and the disagreement is a live unit nothing tracks."""
        entry, config = self._entry(CRED_TOML.format(name="capp", extra=SINGLE))
        self.assertEqual(entry.emitted, container_uses_credentials(config))


class TestTheInternalCarveOut(unittest.TestCase):
    """P2-5. The broker's own address is 127.129.x.y, inside wl_internal4, and
    the drop keyed on this workload sits above the `oif lo accept` -- so
    without an exemption the inspector's dial to its own broker is dropped by
    the rule that exists to stop the workload reaching the LAN.

    It presents as a broker that is down: the connect times out, the listener
    counts `credential broker unreachable`, and the container gets a 502
    naming a unit that is running perfectly. No unit test sends a packet, so
    what is asserted here is the arming's shape and its ordering.
    """

    def _up(self):
        source = (Path(__file__).resolve().parent.parent
                  / "libexec" / "workload-container-inspect").read_text()
        return source[source.index("def up("):source.index("def down(")]

    def test_the_address_is_one_the_drop_would_match(self):
        """The premise. If the broker's address were not in the internal set
        the exemption would be dead code and this class would assert a
        no-op."""
        addr = ipaddress.ip_address(vm_broker_listen_address(UID_MIN + 7))
        armed = vm_internal_ok_elements(UID_MIN + 7, [addr])
        self.assertTrue(any(entries for entries in armed.values()),
                        f"{addr} is not in wl_internal4")

    def test_it_is_armed_only_for_a_workload_that_has_a_broker(self):
        up = self._up()
        self.assertIn("container_uses_credentials(config)", up)
        self.assertIn("vm_broker_listen_address(uid)", up)

    def test_it_is_appended_before_the_commands_are_built(self):
        up = self._up()
        self.assertLess(up.index("vm_broker_listen_address(uid)"),
                        up.index('vm_internal_ok_commands(uid, addresses, "add")'),
                        "appended after the commands, it is armed by nothing")

    def test_it_is_purged_with_the_rest(self):
        """So dropping the last credential removes the hole rather than
        leaving one open with nothing behind it."""
        up = self._up()
        self.assertLess(up.index("purge_internal_exemptions(uid, name)"),
                        up.index("vm_broker_listen_address(uid)"))


if __name__ == "__main__":
    unittest.main()
