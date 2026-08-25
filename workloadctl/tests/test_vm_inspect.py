"""The uid-keyed transparent redirect to a per-workload egress inspector.

Values that appear in a shipped .nft file are spelled out here rather than
imported and re-derived: the point of the test is that the file, the module
and the built commands agree, and a test that computes both sides from the
same constant cannot fail when they drift apart. The element strings are
asserted against the worked example in the design (uid 10004), not against
the builder's own output.
"""

import unittest
from pathlib import Path

from vm import (
    IP_BIN, NFT_BIN, NFT_MAP_INSPECT4, NFT_MAP_INSPECT6, NFT_PROXY_TABLE,
    NFT_SET_INSPECT_CG, NFT_SET_INSPECT_DST,
    NFT_SET_INSPECT_DST6, NFT_SET_INSPECT_SELF, NFT_SET_INSPECT_SELF6,
    NFT_SET_PROXY_CG, NFT_TABLE, VM_INSPECT_ORIG_CLEARTEXT,
    VM_INSPECT_ORIG_TLS, VM_INSPECT_PORT_CLEARTEXT, VM_INSPECT_PORT_TLS,
    VM_PROXY_IFACE, vm_inspect_cgroup, vm_inspect_cgroup_command,
    vm_inspect_cgroup_filter_command, vm_inspect_dst_elements,
    vm_inspect_element_commands, vm_inspect_link_address_commands,
    vm_inspect_link_delete_commands, vm_inspect_map_elements,
    vm_inspect_policy, vm_inspect_policy_path, vm_inspect_self_elements,
    vm_proxy_hosts, vm_proxy_runtime_dir, VM_TLS_DEFAULT,
)

ROOT = Path(__file__).resolve().parent.parent
PROXY_SKELETON_FILE = ROOT / "nftables" / "workload-proxy.nft"
FILTER_SKELETON_FILE = ROOT / "nftables" / "workload-filter.nft"


def argv_of(commands, set_name):
    """The one command in `commands` that names `set_name`."""
    hits = [c for c in commands if set_name in c]
    assert len(hits) == 1, f"expected one command for {set_name}, got {hits}"
    return hits[0]


class TestOriginalPorts(unittest.TestCase):
    """The two ORIGINAL ports the redirect matches.

    workload-proxy.nft spells `tcp dport { 80, 443 }` literally so the file
    stays applicable with a bare `nft -f`; the map key carries those same
    two ports, so the constants and the file must agree rather than drift.
    """

    def test_the_skeleton_matches_the_constants(self):
        text = PROXY_SKELETON_FILE.read_text()
        self.assertIn(f"tcp dport {{ {VM_INSPECT_ORIG_CLEARTEXT}, "
                      f"{VM_INSPECT_ORIG_TLS} }}", text)
        self.assertEqual((VM_INSPECT_ORIG_CLEARTEXT, VM_INSPECT_ORIG_TLS),
                         (80, 443))

    def test_the_original_ports_are_not_the_listener_ports(self):
        """The key and the value select different things: the original port
        picks the listener port, so conflating the two would redirect a dial
        to 8080 and never match a dial to 80."""
        self.assertNotEqual(VM_INSPECT_ORIG_CLEARTEXT, VM_INSPECT_PORT_CLEARTEXT)
        self.assertNotEqual(VM_INSPECT_ORIG_TLS, VM_INSPECT_PORT_TLS)


class TestMapElements(unittest.TestCase):
    """The DNAT map elements, against the worked example (uid 10004)."""

    def test_the_worked_example_v4(self):
        self.assertEqual(
            vm_inspect_map_elements(10004)[NFT_MAP_INSPECT4],
            ["10004 . 80 : 198.18.1.4 . 8080",
             "10004 . 443 : 198.18.1.4 . 8443"])

    def test_the_worked_example_v6(self):
        # 2001:2::198.18.1.4 is a legal spelling of the v6 twin; the kernel
        # prints the canonical form, which is what the element carries.
        self.assertEqual(
            vm_inspect_map_elements(10004)[NFT_MAP_INSPECT6],
            ["10004 . 80 : 2001:2::c612:104 . 8080",
             "10004 . 443 : 2001:2::c612:104 . 8443"])

    def test_the_key_carries_the_original_port_and_the_value_the_listener(self):
        """The concatenated key is uid . ORIGINAL port, so the map itself
        selects the listener port and the socket that accepted the
        connection tells the inspector whether it is TLS or cleartext."""
        elements = vm_inspect_map_elements(10000)
        v4 = {key.split(" : ", 1)[0]: key.split(" : ", 1)[1]
              for key in elements[NFT_MAP_INSPECT4]}
        self.assertEqual(v4["10000 . 80"], "198.18.1.0 . 8080")
        self.assertEqual(v4["10000 . 443"], "198.18.1.0 . 8443")

    def test_neither_element_names_the_advertised_address(self):
        """The value is where the listener actually is; the advertised
        address appears only in the proxy's map, never here."""
        for family in (NFT_MAP_INSPECT4, NFT_MAP_INSPECT6):
            for element in vm_inspect_map_elements(10004)[family]:
                self.assertNotIn("192.0.2.1", element)


class TestDstElements(unittest.TestCase):
    """The accept-set elements hold the TRANSLATED tuple."""

    def test_the_worked_example(self):
        self.assertEqual(
            vm_inspect_dst_elements(10004)[NFT_SET_INSPECT_DST],
            ["10004 . 198.18.1.4 . 8080", "10004 . 198.18.1.4 . 8443"])
        self.assertEqual(
            vm_inspect_dst_elements(10004)[NFT_SET_INSPECT_DST6],
            ["10004 . 2001:2::c612:104 . 8080", "10004 . 2001:2::c612:104 . 8443"])

    def test_the_original_port_never_appears(self):
        """The filter hook runs after dstnat, so the element must name the
        destination as rewritten; a 80 or 443 in here would match nothing and
        the redirected connection would fall through to the default drop."""
        elements = " ".join(vm_inspect_dst_elements(10004)[NFT_SET_INSPECT_DST]
                            + vm_inspect_dst_elements(10004)[NFT_SET_INSPECT_DST6])
        self.assertNotIn(". 80 ", elements)
        self.assertNotIn(". 443", elements)


class TestSelfElements(unittest.TestCase):
    """The wrong-port drop-set elements are keyed with NO port."""

    def test_the_worked_example(self):
        self.assertEqual(
            vm_inspect_self_elements(10004)[NFT_SET_INSPECT_SELF],
            ["10004 . 198.18.1.4"])
        self.assertEqual(
            vm_inspect_self_elements(10004)[NFT_SET_INSPECT_SELF6],
            ["10004 . 2001:2::c612:104"])

    def test_naming_a_port_would_defeat_the_guard(self):
        """The whole purpose is to catch dials to ports nothing serves; a
        port in the key would make exactly those unmatchable."""
        for family in (NFT_SET_INSPECT_SELF, NFT_SET_INSPECT_SELF6):
            for element in vm_inspect_self_elements(10004)[family]:
                self.assertEqual(element.count(" . "), 1)


class TestElementCommands(unittest.TestCase):
    """The six arming commands: both tables, by their constants."""

    def test_six_argv_two_per_family(self):
        commands = vm_inspect_element_commands(10004, "add")
        self.assertEqual(len(commands), 6)
        self.assertTrue(all(c[0] == NFT_BIN for c in commands))

    def test_every_argv_names_a_constant_not_a_literal(self):
        """A bare literal means a missed constant: the object name in the
        argv must be the very constant the skeleton was tested against."""
        commands = vm_inspect_element_commands(10004, "add")
        objects = [c[5] for c in commands]
        self.assertEqual(
            objects,
            [NFT_MAP_INSPECT4, NFT_MAP_INSPECT6,
             NFT_SET_INSPECT_DST, NFT_SET_INSPECT_DST6,
             NFT_SET_INSPECT_SELF, NFT_SET_INSPECT_SELF6])

    def test_the_maps_arm_in_the_proxy_table_only(self):
        """Both tables named: the DNAT maps live in inet workload_proxy, the
        guard sets in inet workload_filter. A helper that arms one table and
        not the other leaves a workload that looks configured and reaches
        nothing."""
        commands = vm_inspect_element_commands(10004, "add")
        for name in (NFT_MAP_INSPECT4, NFT_MAP_INSPECT6):
            self.assertEqual(argv_of(commands, name)[3:5],
                             NFT_PROXY_TABLE.split())
        for name in (NFT_SET_INSPECT_DST, NFT_SET_INSPECT_DST6,
                     NFT_SET_INSPECT_SELF, NFT_SET_INSPECT_SELF6):
            self.assertEqual(argv_of(commands, name)[3:5],
                             NFT_TABLE.split())

    def test_arm_and_disarm_differ_only_in_the_action(self):
        add = vm_inspect_element_commands(10004, "add")
        delete = vm_inspect_element_commands(10004, "delete")
        self.assertEqual(len(delete), len(add))
        for a, d in zip(add, delete):
            self.assertEqual(a[1], "add")
            self.assertEqual(d[1], "delete")
            self.assertEqual(a[2:], d[2:])

    def test_an_unknown_action_raises(self):
        with self.assertRaises(ValueError):
            vm_inspect_element_commands(10004, "replace")


class TestSkeletonNamesAgree(unittest.TestCase):
    """The elements name objects the skeletons actually declare.

    An element for a set that does not exist fails at load, not at
    validation: the built command is what tier 2 loads, and a name that is
    absent from the skeleton is a runtime failure no text assertion on the
    element alone would catch.
    """

    def test_the_proxy_skeleton_declares_both_maps(self):
        text = PROXY_SKELETON_FILE.read_text()
        self.assertIn(f"add map inet workload_proxy {NFT_MAP_INSPECT4}", text)
        self.assertIn(f"add map inet workload_proxy {NFT_MAP_INSPECT6}", text)
        self.assertIn(f"add set inet workload_proxy {NFT_SET_INSPECT_CG}", text)

    def test_the_filter_skeleton_declares_all_four_sets(self):
        text = FILTER_SKELETON_FILE.read_text()
        for name in (NFT_SET_INSPECT_DST, NFT_SET_INSPECT_DST6,
                     NFT_SET_INSPECT_SELF, NFT_SET_INSPECT_SELF6):
            self.assertIn(f"add set inet workload_filter {name}", text)


class TestCgroupCommands(unittest.TestCase):
    """The two cgroup exemption builders name OPPOSITE tables."""

    def test_the_redirect_exemption_lives_in_the_proxy_table(self):
        """wl_inspect_cg feeds the `return` rule in workload-proxy.nft; sets
        are table-scoped, so naming the filter table fails only at load time
        with `did you mean set 'wl_proxy_cg' in table inet
        'workload_filter'?`."""
        argv = vm_inspect_cgroup_command("web", "add")
        self.assertEqual(argv[3:5], NFT_PROXY_TABLE.split())
        self.assertEqual(argv[5], NFT_SET_INSPECT_CG)

    def test_the_egress_exemption_lives_in_the_filter_table(self):
        """wl_proxy_cg feeds the accept rule in workload-filter.nft; the
        inspector is a filtered uid, so without it its own upstream
        connections hit the default-deny drop and it reaches nothing."""
        argv = vm_inspect_cgroup_filter_command("web", "add")
        self.assertEqual(argv[3:5], NFT_TABLE.split())
        self.assertEqual(argv[5], NFT_SET_PROXY_CG)

    def test_the_two_builders_name_opposite_tables(self):
        proxy_side = vm_inspect_cgroup_command("web", "add")
        filter_side = vm_inspect_cgroup_filter_command("web", "add")
        self.assertNotEqual(proxy_side[3:5], filter_side[3:5])
        self.assertNotEqual(proxy_side[5], filter_side[5])
        # The element VALUE is the same cgroup on both sides: one process,
        # two exemptions.
        self.assertEqual(proxy_side[6], filter_side[6])

    def test_the_element_names_the_inspector_units_cgroup(self):
        # -inspect, not -inspector: the element resolves a path, so the unit
        # name must match the service unit that actually runs, or the rule is
        # a `return` that matches nothing and the inspector's own egress is
        # dropped.
        self.assertEqual(vm_inspect_cgroup("web"),
                         "workloads.slice/workload-web-inspect.service")
        argv = vm_inspect_cgroup_command("web", "add")
        self.assertEqual(argv[6],
                         '{ "workloads.slice/workload-web-inspect.service" }')
        # Two components, so the rule's `level 2` match is exact.
        self.assertEqual(vm_inspect_cgroup("web").count("/"), 1)


class TestLinkAddressCommands(unittest.TestCase):
    """The per-workload listener addresses on the shared dummy link."""

    def test_the_addresses_are_host_global_host_local(self):
        v4, v6 = vm_inspect_link_address_commands(10004)
        self.assertEqual(v4, [IP_BIN, "addr", "add", "198.18.1.4/32",
                              "dev", VM_PROXY_IFACE])
        self.assertEqual(v6, [IP_BIN, "addr", "add", "2001:2::c612:104/128",
                              "dev", VM_PROXY_IFACE, "nodad"])

    def test_nodad_is_on_v6_only(self):
        """A dummy link runs no DAD (measured 2026-08-19), so the flag
        changes nothing today; it states the intent and stays correct if the
        address moves to a link type that does run DAD."""
        v4, v6 = vm_inspect_link_address_commands(10004)
        self.assertNotIn("nodad", v4)
        self.assertIn("nodad", v6)

    def test_the_delete_twin_removes_exactly_what_the_add_puts_on(self):
        v4_add, v6_add = vm_inspect_link_address_commands(10004)
        v4_del, v6_del = vm_inspect_link_delete_commands(10004)
        # Same address, same dev, the verb flipped: a delete that named a
        # different prefix would leave the add's address on the link.
        self.assertEqual(v4_del, [IP_BIN, "addr", "del", "198.18.1.4/32",
                                  "dev", VM_PROXY_IFACE])
        self.assertEqual(v6_del, [IP_BIN, "addr", "del", "2001:2::c612:104/128",
                                  "dev", VM_PROXY_IFACE])


class TestHelperArmsBothTables(unittest.TestCase):
    """libexec/workload-vm-inspect: both skeletons, both tables, no cgroups.

    The helper is the first thing in the work that writes to the kernel; the
    properties worth pinning down are the ones a silent edit drops, so they
    are asserted on the source the way test_vm_proxy.py does, plus a
    mocked subprocess run for the order in which the writes happen.
    """

    @classmethod
    def setUpClass(cls):
        from tests import load_script
        cls.mod = load_script("libexec/workload-vm-inspect")

    def test_up_applies_both_skeletons_before_any_element(self):
        """The constants are what the source names (not their values): a
        skeleton applied after the first element would not create a table
        for a host that never had one, and the element add would fail."""
        source = (ROOT / "libexec" / "workload-vm-inspect").read_text()
        up = source[source.index("def up("):source.index("def down(")]
        self.assertLess(up.index("NFT_PROXY_SKELETON"),
                        up.index("vm_inspect_element_commands"))
        self.assertLess(up.index("NFT_SKELETON"),
                        up.index("vm_inspect_element_commands"))
        self.assertIn("check=True", up)

    def test_up_never_arms_the_cgroup_elements(self):
        """An element resolves to a cgroup id at add time and systemd makes
        a fresh cgroup on every start: the add belongs to the unit that owns
        the cgroup (T5), not to this helper, which runs as ExecStartPre while
        that cgroup is not yet the one being armed."""
        source = (ROOT / "libexec" / "workload-vm-inspect").read_text()
        up = source[source.index("def up("):source.index("def down(")]
        self.assertNotIn("vm_inspect_cgroup_command", up)
        self.assertNotIn("vm_inspect_cgroup_filter_command", up)

    def test_up_clears_the_previous_instances_status_file(self):
        """/run/workload-vm/<name> is the VM service's RuntimeDirectory with
        RuntimeDirectoryPreserve=yes, and the inspector is socket-activated --
        so without this, an operator reading `diagnose` between a VM start and
        the guest's first dial sees the LAST boot's ECH alarms and internal
        refusals with nothing marking them as stale. Cleared at arm rather than
        at stop because a stop is not guaranteed to run."""
        source = (ROOT / "libexec" / "workload-vm-inspect").read_text()
        up = source[source.index("def up("):source.index("def down(")]
        self.assertIn("clear_status(vm_inspect_status_path(name))", up)

    def test_down_removes_elements_and_addresses_but_not_the_link(self):
        source = (ROOT / "libexec" / "workload-vm-inspect").read_text()
        down = source[source.index("def down("):source.index("def main(")]
        self.assertIn("vm_inspect_element_commands(uid, \"delete\")", down)
        self.assertIn("vm_inspect_link_delete_commands", down)
        # The shared link and the advertised address are never torn down.
        self.assertNotIn('"link", "del"', down)
        self.assertNotIn("VM_PROXY_ADDR", down)

    def test_up_arms_the_internal_exemptions_after_the_skeleton(self):
        """Same ordering property as the six above, for the same reason.

        An element add against a table that does not exist yet fails the start,
        and the internal_ok sets live in the filter table the skeleton creates.
        """
        source = (ROOT / "libexec" / "workload-vm-inspect").read_text()
        up = source[source.index("def up("):source.index("def down(")]
        self.assertIn("vm_internal_ok_commands", up)
        self.assertLess(up.index("NFT_SKELETON"),
                        up.index("vm_internal_ok_commands"))
        self.assertLess(up.index('vm_internal_ok_commands(uid, addresses, "delete")'),
                        up.index('vm_internal_ok_commands(uid, addresses, "add")'),
                        "purge before arming, or an edited config leaves a "
                        "dropped host's element behind")

    def test_down_clears_the_internal_exemptions_and_tolerates_absence(self):
        """`up` fails loudly, `down` tolerates everything.

        A name that stopped resolving between start and stop must not block the
        stop -- and the elements it armed are per-workload and die with the
        reboot at the latest.
        """
        source = (ROOT / "libexec" / "workload-vm-inspect").read_text()
        down = source[source.index("def down("):source.index("def main(")]
        self.assertIn('vm_internal_ok_commands(uid, addresses, "delete")', down)
        # The calls, not the prose -- the comment above them says "not
        # check=True" and a substring search would match that.
        self.assertNotIn("run(argv, check=True)", down)
        self.assertIn("except ValueError", down)

    def test_up_writes_the_policy_before_it_arms_the_redirect(self):
        """The listener is socket-activated, so the guest's first dial can
        start it the instant the redirect exists. A policy written after the
        arming is a window in which the listener starts, cannot read its
        lists, and fails -- on a connection the guest already made.
        """
        source = (ROOT / "libexec" / "workload-vm-inspect").read_text()
        up = source[source.index("def up("):source.index("def down(")]
        self.assertIn("write_policy(name)", up)
        self.assertLess(up.index("write_policy(name)"),
                        up.index("vm_inspect_element_commands"))

    def test_the_policy_is_written_group_readable_and_not_world_readable(self):
        """The listener runs as _wl-<name> and must read it; 0640 rather than
        0644 keeps one workload's policy from being enumerable by another,
        exactly as the proxy's generated files are."""
        source = (ROOT / "libexec" / "workload-vm-inspect").read_text()
        write = source[source.index("def write_policy("):source.index("def up(")]
        self.assertIn("0o640", write)
        self.assertIn("os.replace(tmp, path)", write)


class TestPolicyDocument(unittest.TestCase):
    """What `hosts` means to the inspector, and what `internal` does not."""

    def test_the_hosts_list_is_the_one_tinyproxy_is_given(self):
        """At this rung the two enforce the same patterns by two mechanisms.
        Generating them from one source is what keeps a redirected connection
        and a proxied one making the same decision about the same name."""
        net = {"hosts": ["*.example.com", "git.local"]}
        self.assertEqual(vm_inspect_policy(net)["hosts"], vm_proxy_hosts(net))

    def test_internal_hosts_are_not_added_to_the_allowlist(self):
        """An `internal` entry names a host that is ALREADY on a list --
        validation refuses one that is not -- and what it excepts is the
        inspector's upstream leg from the internal drop. Adding it here would
        make it a second, quieter way to authorise a name."""
        net = {"hosts": ["git.local"],
               "internal": [{"host": "git.local", "reason": "the forge"}]}
        self.assertEqual(vm_inspect_policy(net)["hosts"], ["git.local"])

    def test_the_tls_mode_travels_with_the_lists(self):
        self.assertEqual(vm_inspect_policy({})["tls"], VM_TLS_DEFAULT)
        self.assertEqual(vm_inspect_policy({"tls": "splice"})["tls"], "splice")

    def test_the_policy_path_is_in_the_workloads_runtime_dir(self):
        """The same directory tinyproxy.conf is written into, and for the same
        reason: /run does not exist when the boot generator runs, so writing at
        start is what makes an edited list apply on a plain restart."""
        self.assertEqual(vm_inspect_policy_path("web"),
                         f"{vm_proxy_runtime_dir('web')}/inspect.json")


if __name__ == "__main__":
    unittest.main()
