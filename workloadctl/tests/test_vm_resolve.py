"""The synthesising responder, from workloadctl's side.

The responder is customs' customs-resolve, and its wire behaviour is held by
customs' own suite. What is workloadctl's is everything it is handed: the
uid-derived address it listens on, the predicate deciding which workloads get
one, the static map it answers `allow`-by-name destinations from, and the
units that run it. tests/test_customs_seam.py runs the program on what this
side writes.

A static-map miss sends an `allow`-by-name destination to a port the inspector
does not serve, which hangs rather than refuses, and none of the failures here
produce an error message naming DNS.
"""

import importlib
import ipaddress
import unittest
from pathlib import Path

from egress_policy import (
    inspect_policy_path, resolve_static, resolve_static_path, vm_uses_resolve,
)
from nft_constants import SIDECAR_SLICE
from nft_elements import vm_filter_elements, resolve_status_path
from vm_network_config import vm_allow_resolved
from workload_addr import (
    UID_MAX, UID_MIN, MGMT_NETWORK, RESOLVE_ADDR_BASE,
    RESOLVE_LISTENER_BIN, RESOLVE_STATIC_FILE, RESOLVE_PORT,
    inspect_address, management_address, reserved_range, resolve_address,
)

UID = 10004  # the worked example the rest of the inspect tests use


def net_config(**net):
    return {"vm": {"network": net}}


class TestAddress(unittest.TestCase):
    """The uid-derived responder address, and the reservation it inherits."""

    def test_the_offset_is_the_uid_offset(self):
        self.assertEqual(resolve_address(UID_MIN), "127.130.0.0")
        self.assertEqual(resolve_address(UID_MIN + 3), "127.130.0.3")
        self.assertEqual(resolve_address(UID),
                         str(ipaddress.IPv4Address(
                             RESOLVE_ADDR_BASE + (UID - UID_MIN))))

    def test_a_uid_outside_the_workload_range_is_refused(self):
        for uid in (UID_MIN - 1, UID_MAX + 1, 0):
            with self.assertRaises(ValueError):
                resolve_address(uid)

    def test_the_whole_range_stays_inside_the_management_reservation(self):
        """Why there is no new ReservedRange for the responder.

        The management /9 was cut wide on purpose -- its own comment says the
        ranges hung on loopback after it would inherit the reservation. If this
        ever stopped holding, `ports` could bind a guest port on another
        workload's nameserver and start order would decide which one answered,
        with nothing logged either way.
        """
        for uid in (UID_MIN, UID, UID_MAX):
            addr = ipaddress.IPv4Address(resolve_address(uid))
            self.assertIn(addr, MGMT_NETWORK, uid)

    def test_ports_cannot_bind_a_responder_address(self):
        """The reservation, exercised through the check `ports` actually uses
        rather than asserted about the network object."""
        self.assertIsNotNone(
            reserved_range(resolve_address(UID), RESOLVE_PORT))

    def test_it_does_not_collide_with_the_management_address(self):
        """Same arithmetic, different base. A shared base would put the
        responder on the management address at a different port, which is a
        second service inside a range documented as never configurable."""
        for uid in (UID_MIN, UID, UID_MAX):
            self.assertNotEqual(resolve_address(uid),
                                management_address(uid))

    def test_the_address_is_loopback(self):
        """Not the 198.18.0.0/16 advertised link. 127/8 is unreachable from the
        guest by construction, so passt's interception is the only path to the
        responder -- an address the guest could dial directly is a nameserver
        every other workload on the host can query too."""
        self.assertTrue(
            ipaddress.IPv4Address(resolve_address(UID)).is_loopback)


class TestPredicate(unittest.TestCase):
    """vm_uses_resolve: the inspector's terms plus `resolver` not "none"."""

    def test_a_filtered_vm_gets_one_by_default(self):
        self.assertTrue(vm_uses_resolve(net_config()))
        self.assertTrue(vm_uses_resolve(net_config(egress="filtered")))

    def test_resolver_none_switches_it_off(self):
        self.assertFalse(vm_uses_resolve(net_config(resolver="none")))

    def test_resolver_host_keeps_it_on(self):
        self.assertTrue(vm_uses_resolve(net_config(resolver="host")))

    def test_open_egress_does_not_get_one(self):
        """A responder under `egress = "open"` would answer every name with an
        inspector address that nothing redirects to."""
        self.assertFalse(vm_uses_resolve(net_config(egress="open")))
        self.assertFalse(
            vm_uses_resolve(net_config(egress="open", resolver="host")))

    def test_a_bridged_vm_does_not_get_one(self):
        self.assertFalse(vm_uses_resolve(net_config(bridge="br0")))

    def test_a_container_workload_does_not_get_one(self):
        self.assertFalse(vm_uses_resolve({"container": {"image": "x"}}))
        self.assertFalse(vm_uses_resolve({}))


class TestStaticMap(unittest.TestCase):
    """What the arming path writes for customs-resolve --static to read."""

    def test_an_address_form_allow_entry_is_not_in_the_map(self):
        """`allow` by address names no hostname, so there is nothing to answer
        for -- and inventing a name for it would be a name the operator never
        wrote."""
        net = {"allow": [{"address": "192.0.2.7:2222", "reason": "forge"}]}
        self.assertEqual(resolve_static(vm_allow_resolved(net["allow"])), {})

    def test_a_named_allow_entry_lands_in_the_map(self):
        resolved = [(_entry("git.local", 2222),
                     [ipaddress.IPv4Address("192.0.2.9")])]
        self.assertEqual(resolve_static(resolved),
                         {"git.local": ["192.0.2.9"]})

    def test_the_map_key_is_normalised(self):
        """One name, one entry, whatever the operator typed. Two spellings
        becoming two keys is a lookup that misses for the spelling the guest
        used."""
        resolved = [(_entry("Git.Local.", 2222),
                     [ipaddress.IPv4Address("192.0.2.9")])]
        self.assertEqual(list(resolve_static(resolved)),
                         ["git.local"])

    def test_both_families_of_one_name_are_kept(self):
        resolved = [(_entry("git.local", 2222),
                     [ipaddress.IPv4Address("192.0.2.9"),
                      ipaddress.IPv6Address("2001:db8::9")])]
        self.assertEqual(resolve_static(resolved),
                         {"git.local": ["192.0.2.9", "2001:db8::9"]})

    def test_two_entries_for_one_name_are_one_key(self):
        """Two ports on one forge are two `allow` entries and one name; the
        second must add to the first entry, not replace it or repeat it."""
        resolved = [(_entry("git.local", 22),
                     [ipaddress.IPv4Address("192.0.2.9")]),
                    (_entry("git.local", 2222),
                     [ipaddress.IPv4Address("192.0.2.9"),
                      ipaddress.IPv4Address("192.0.2.10")])]
        self.assertEqual(resolve_static(resolved),
                         {"git.local": ["192.0.2.9", "192.0.2.10"]})

    def test_the_map_and_the_nft_elements_come_from_one_resolution(self):
        """The whole reason vm_allow_resolved is a function of its own.

        A second, independent resolution is the same name asked twice, and a
        round-robin or short-TTL record answering differently the second time
        sends the guest to an address the set does not hold -- which is a hang
        against the default-deny drop, not a refusal. Here one resolution feeds
        both, and every address the responder would hand out is in the set.
        """
        resolved = [(_entry("git.local", 2222),
                     [ipaddress.IPv4Address("192.0.2.9"),
                      ipaddress.IPv4Address("192.0.2.10")])]
        elements = vm_filter_elements(UID, [], resolved)
        armed = {e.split(" . ")[1] for e in elements["wl_allow4"]}
        served = set(resolve_static(resolved)["git.local"])
        self.assertEqual(served, armed)

    def test_resolution_is_shared_by_default_too(self):
        """vm_filter_elements without a `resolved` still resolves for itself,
        so every pre-existing caller is unchanged."""
        net = {"allow": [{"address": "192.0.2.7:2222", "reason": "forge"}]}
        self.assertEqual(vm_filter_elements(UID, net["allow"]),
                         vm_filter_elements(UID, net["allow"],
                                            vm_allow_resolved(net["allow"])))

    def test_the_map_is_beside_the_inspectors_policy(self):
        path = resolve_static_path("web")
        self.assertTrue(path.endswith(f"/web/{RESOLVE_STATIC_FILE}"), path)
        self.assertEqual(Path(path).parent,
                         Path(inspect_policy_path("web")).parent)


def _entry(host, port):
    from vm_network_config import VmAllowEntry
    return VmAllowEntry(address=None, host=host, port=port, reason="test")


class TestGeneratedUnits(unittest.TestCase):
    """The socket and service the generator emits."""

    @classmethod
    def setUpClass(cls):
        cls.gen = importlib.import_module("gen_vm")
        cls.egress = importlib.import_module("gen_egress")
        config = {"workload": {"name": "web"}, "vm": {"network": {}}}
        cls.socket_unit = cls.egress.generate_resolve_socket(
            config, "_wl-web", UID)
        cls.service = cls.egress.generate_resolve_service(
            config, "_wl-web", UID)
        cls.address = resolve_address(UID)

    def test_the_service_turns_the_user_site_off(self):
        """As the workload user, site.py would stat a dir under the
        workload's home, which wlresolve_t may not traverse."""
        self.assertIn("Environment=PYTHONNOUSERSITE=1",
                      self.service.splitlines())

    def test_both_transports_are_bound(self):
        """UDP alone leaves a client that opened TCP for its own reasons
        hanging, with nothing to diagnose from."""
        self.assertIn(f"ListenDatagram={self.address}:{RESOLVE_PORT}",
                      self.socket_unit.splitlines())
        self.assertIn(f"ListenStream={self.address}:{RESOLVE_PORT}",
                      self.socket_unit.splitlines())

    def test_the_socket_has_no_address_add(self):
        """The difference from the inspector's socket, and the trap this unit
        of work names. All of 127/8 is local on `lo`, so a `/32` add would be a
        no-op that a later reader takes for load-bearing -- and it would invent
        an address whose absence the inspector's fail-at-bind argument would
        then appear to depend on."""
        self.assertNotIn("ExecStartPre", self.socket_unit)
        self.assertNotIn("ip addr add", self.socket_unit)
        self.assertNotIn("ExecStopPost", self.socket_unit)

    def test_the_socket_does_not_freebind(self):
        self.assertNotIn("FreeBind", self.socket_unit)

    def test_the_trigger_limit_is_set_explicitly(self):
        """Accept=no silently lowers the default to 20 per 2s and hitting it
        fails the socket PERMANENTLY. A guest boot is a burst of lookups."""
        self.assertIn("Accept=no", self.socket_unit.splitlines())
        self.assertIn("TriggerLimitBurst=200", self.socket_unit.splitlines())
        self.assertIn("TriggerLimitIntervalSec=2s", self.socket_unit.splitlines())

    def test_the_socket_stops_with_the_vm(self):
        self.assertIn("PartOf=workload-web.service", self.socket_unit.splitlines())
        self.assertIn("Before=workload-web.service", self.socket_unit.splitlines())

    def test_the_service_arms_no_cgroup_exemption(self):
        """The responder is NOT a member of wl_egress_cg, and the nft file must
        not say it is.

        Three tracked comments claimed the set held two members per workload,
        the inspector and the responder. Nothing arms the second: there is no
        vm_resolve_cgroup, and this unit emits no nft command at all. The claim
        was harmless -- the responder originates nothing, so it needs no
        exemption -- and that is exactly what made it dangerous to leave
        standing: the next change that gives the responder an outbound socket
        would have it dropped by the default deny, with three comments
        asserting that cannot happen.
        """
        import nft_elements
        self.assertNotIn("wl_egress_cg", self.service)
        self.assertNotIn("wl_inspect_cg", self.service)
        self.assertNotIn("nft", self.service)
        self.assertFalse(hasattr(nft_elements, "vm_resolve_cgroup"), (
            "a vm_resolve_cgroup exists now, so the responder may be armed "
            "into wl_egress_cg -- update the nft comments this test guards"))

    # Every tracked file that documents either cgroup set. The list is the
    # test: a fifth file growing a comment about these sets and not being added
    # here is exactly how the claim survived its first correction.
    CGROUP_SET_FILES = (
        ("nftables", "workload-filter.nft"),
        ("nftables", "workload-proxy.nft"),
        ("lib", "nft_elements.py"),
        ("libexec", "workload-vm-inspect"),
    )

    # A paragraph that names a cgroup set AND the responder has to be DENYING
    # membership, so it must carry one of these.
    #
    # Denial phrases, not bare negations. The obvious "does it say `not`
    # anywhere" version passes on the false text, because these paragraphs are
    # long and one of them quotes an nftables error containing "No such file" --
    # a marker that has nothing to do with the claim being checked. Each phrase
    # here can only appear in a sentence about membership.
    #
    # And not a blocklist of the false phrasings either: the first version of
    # this test banned the two exact strings that had just been fixed, which
    # pinned the WORDING rather than the claim and let three re-phrasings of it
    # stand in three other files.
    DENIALS = (
        "deliberately not",
        "not the second",
        "not a second",
        "is not here",
        "originates nothing",
        "opens no socket",
        "no upstream socket",
        "nothing arms",
        "no vm_resolve_cgroup",
    )

    @staticmethod
    def _normalise(para):
        """A paragraph as one lowercase line, comment markers gone.

        The phrases above are sentences and these files wrap at 79 columns, so
        every one of them is split across a line break and a `#` in at least
        one file. Matching the raw text would make the test pass or fail on
        where a line happened to wrap.
        """
        stripped = " ".join(line.lstrip("#").strip()
                            for line in para.splitlines())
        return " ".join(stripped.split()).lower()

    def _cgroup_paragraphs(self, path):
        """Blank-line-separated blocks of `path` that name a cgroup set."""
        text = path.read_text()
        return [para for para in text.split("\n\n")
                if "wl_egress_cg" in para or "wl_inspect_cg" in para]

    def test_no_tracked_file_claims_the_responder_is_exempted(self):
        """The responder is NOT a member of either cgroup set, and no comment
        may say it is.

        Four tracked files document these sets and three of them claimed the
        membership was two per workload, the inspector and the responder.
        Nothing arms the second: there is no vm_resolve_cgroup, and the
        responder's unit emits no nft command at all.

        The claim is harmless while the responder stays as it is -- it
        originates nothing, so it needs no exemption -- and that is exactly
        what makes it dangerous to leave standing. The next change that gives
        the responder an outbound socket would have it dropped by the default
        deny and redirected into the inspector, with comments in three files
        asserting that cannot happen.
        """
        root = Path(__file__).resolve().parent.parent
        for parts in self.CGROUP_SET_FILES:
            path = root.joinpath(*parts)
            for para in self._cgroup_paragraphs(path):
                flat = self._normalise(para)
                if "responder" not in flat and "-resolve.service" not in flat:
                    continue
                self.assertTrue(
                    any(phrase in flat for phrase in self.DENIALS),
                    f"{path.name} has a paragraph naming a cgroup set and the "
                    f"responder with nothing denying membership:\n{para}")

    def test_the_kernel_policy_never_names_the_responder_unit(self):
        """The structural half, which needs no reading of prose.

        Neither .nft file has any business naming workload-<name>-resolve.
        service: no rule keys on that cgroup, no element is armed for it, and
        the one comment that did name it was describing a path nothing
        resolves. A file that starts naming it again is a file whose comments
        have drifted back, whatever words they use.
        """
        root = Path(__file__).resolve().parent.parent
        for parts in (("nftables", "workload-filter.nft"),
                      ("nftables", "workload-proxy.nft")):
            path = root.joinpath(*parts)
            hits = [line.strip() for line in path.read_text().splitlines()
                    if "-resolve.service" in line]
            # The lines, not the file: assertNotIn on a whole .nft prints the
            # entire policy into the failure, which buries the one line that
            # changed.
            self.assertEqual([], hits, f"{path.name} names the responder unit")

    def test_the_service_runs_as_the_workload_user(self):
        self.assertIn("User=_wl-web", self.service.splitlines())
        self.assertIn("Group=_wl-web", self.service.splitlines())

    def test_the_service_execs_customs_resolve_with_its_flags(self):
        inspect = inspect_address(UID)
        self.assertIn(
            f'ExecStart={RESOLVE_LISTENER_BIN} --name "web"'
            f' --address "{inspect.v4}"'
            f' --policy "{inspect_policy_path("web")}"'
            f' --static "{resolve_static_path("web")}"'
            f' --status "{resolve_status_path("web")}"',
            self.service.splitlines())

    def test_the_synthesised_addresses_are_the_inspectors(self):
        """Every synthesised A points the guest at the listener its 80
        and 443 are redirected to anyway, so a guest that ignores the
        redirect and one that does not arrive at the same place. No AAAA:
        passt's DHCPv6 can hand the guest the inspector's v6 address as its
        own, and a dial to it is then refused inside the guest."""
        cmd = self.egress.resolve_command("web", UID)
        flags = {cmd[i]: cmd[i + 1] for i in range(1, len(cmd), 2)}
        self.assertEqual(flags["--address"], inspect_address(UID).v4)
        self.assertNotIn("--address6", flags)

    def test_the_service_carries_no_cgroup_exemptions(self):
        """The inspector's two exemptions exist because it ORIGINATES traffic.
        The responder originates none -- it has no upstream socket at all --
        so an exemption here would be a hole with nothing behind it."""
        self.assertNotIn("wl_inspect_cg", self.service)
        self.assertNotIn("wl_egress_cg", self.service)
        self.assertNotIn("nft", self.service)

    def test_the_service_stops_with_the_workload(self):
        """So an edited config applies on a plain restart rather than the
        previous run's map being served alongside the new workload."""
        self.assertIn("StopPropagatedFrom=workload-web.service",
                      self.service.splitlines())

    def test_a_restart_is_not_propagated_as_a_restart(self):
        """PartOf= restarts the responder with the workload, and on hardware
        it came back up and read the static map a second before the
        workload's prestart rewrote it. A propagated stop leaves it down
        until the first query."""
        self.assertNotIn("PartOf=", self.service)

    def test_the_slice_is_pinned(self):
        self.assertIn(f"Slice={SIDECAR_SLICE}", self.service.splitlines())

    def test_the_vm_requires_the_responder_socket(self):
        """Requires=, not Wants=. The guest has exactly one nameserver, so a VM
        booted with its responder socket unbound resolves nothing at all while
        looking healthy."""
        config = {"workload": {"name": "web"},
                  "vm": {"memory": "1G", "network": {}}}
        vm_unit = self.gen.generate_vm_service(config, "_wl-web", UID, [])
        self.assertIn("workload-web-resolve.socket", vm_unit)

    def test_resolver_none_pulls_in_no_responder(self):
        """One knob, one meaning. A VM told to ask nobody must not be handed a
        hard prerequisite on a nameserver -- the unit is not generated for it,
        so a Requires= would fail its start on a missing file."""
        config = {"workload": {"name": "web"},
                  "vm": {"memory": "1G", "network": {"resolver": "none"}}}
        vm_unit = self.gen.generate_vm_service(config, "_wl-web", UID, [])
        self.assertNotIn("workload-web-resolve.socket", vm_unit)

    def test_open_egress_pulls_in_no_responder(self):
        config = {"workload": {"name": "web"},
                  "vm": {"memory": "1G", "network": {"egress": "open"}}}
        vm_unit = self.gen.generate_vm_service(config, "_wl-web", UID, [])
        self.assertNotIn("workload-web-resolve.socket", vm_unit)


if __name__ == "__main__":
    unittest.main()
