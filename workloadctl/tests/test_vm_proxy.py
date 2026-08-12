#!/usr/bin/env python3
"""Hostname policy: the per-workload tinyproxy, its redirect, and its domain.

Everything here is checkable without root, nftables or SELinux — the generated
config and unit are strings, the CIL and nft skeleton are parsed as text, and
diagnose's verdict logic takes injected observations. What cannot be checked
here is whether the redirect actually translates and the policy actually
permits, which is what the enforcing bench run is for.
"""

import unittest
from pathlib import Path
from types import SimpleNamespace

from vm import (
    NFT_PROXY_MAP, NFT_PROXY_SKELETON, NFT_PROXY_TABLE, NFT_SET_PROXY_CG,
    VM_BROKER_ENV_VAR, vm_broker_env,
    VM_PROXY_ADDR, VM_PROXY_BIN, VM_PROXY_IFACE, VM_PROXY_PORT,
    VM_PROXY_PORT_HTTPS, vm_management_address, vm_proxy_config,
    vm_proxy_element, vm_proxy_env, vm_proxy_filter_file, vm_proxy_hosts,
    vm_proxy_cgroup, vm_proxy_cgroup_command, VM_PROXY_SLICE,
    vm_proxy_map_command, vm_proxy_runtime_dir, vm_uses_proxy,
    validate_vm_network,
)

ROOT = Path(__file__).resolve().parent.parent
CIL = ROOT / "security" / "workload-proxy.cil"
NFT = ROOT / "nftables" / "workload-proxy.nft"
SPEC = ROOT / "rpm" / "workloadctl.spec"


def net_config(**net):
    return {"vm": {"network": net}}


class TestProxyPredicate(unittest.TestCase):
    """`hosts` alone decides whether a workload gets an instance."""

    def test_hosts_enables_the_proxy(self):
        self.assertTrue(vm_uses_proxy(net_config(hosts=["example.com"])))

    def test_no_hosts_means_no_proxy(self):
        self.assertFalse(vm_uses_proxy(net_config()))
        self.assertFalse(vm_uses_proxy(net_config(hosts=[])))
        self.assertFalse(vm_uses_proxy({}))

    def test_a_bridged_vm_never_gets_one(self):
        """Nothing of ours is in a bridged guest's data path, so there is no
        uid to key the redirect on — the instance would be unreachable."""
        self.assertFalse(
            vm_uses_proxy(net_config(bridge="br0", hosts=["example.com"])))


class TestGeneratedConfig(unittest.TestCase):
    """The tinyproxy.conf. Each assertion here is a silent hole if it regresses."""

    def setUp(self):
        self.addr = vm_management_address(10005)
        self.conf = vm_proxy_config("web", self.addr, ["example.com", "*.co.uk"])

    def test_listens_only_on_the_workloads_management_address(self):
        self.assertIn(f"Listen {self.addr}\n", self.conf)
        self.assertNotIn("Listen 0.0.0.0", self.conf)

    def test_default_deny_is_set(self):
        """Without it the Filter file is a DENYLIST and every unlisted host is
        permitted — an allowlist that silently allows everything."""
        self.assertIn("FilterDefaultDeny Yes", self.conf)

    def test_filter_matches_the_host_not_the_url(self):
        self.assertIn("FilterURLs Off", self.conf)
        self.assertIn("FilterType fnmatch", self.conf)

    def test_connect_is_pinned_to_https(self):
        """With no ConnectPort, CONNECT may target any port and the proxy
        becomes a general TCP tunnel out of the guest."""
        self.assertIn(f"ConnectPort {VM_PROXY_PORT_HTTPS}", self.conf)

    def test_allows_the_advertised_address_as_a_client(self):
        """The guest's packet is routed to the advertised address before it is
        translated, so the host picks that as the source and the proxy sees the
        client connecting FROM it. Omit this and every request 403s while the
        listener, the redirect and the guest all look healthy."""
        self.assertIn(f"Allow {VM_PROXY_ADDR}\n", self.conf)
        self.assertIn("Allow 127.0.0.0/8\n", self.conf)

    def test_paths_are_inside_the_workloads_own_runtime_dir(self):
        rt = vm_proxy_runtime_dir("web")
        self.assertIn(f'PidFile "{rt}/tinyproxy.pid"', self.conf)
        self.assertIn(f'LogFile "{rt}/tinyproxy.log"', self.conf)
        self.assertIn(f'Filter "{rt}/hosts.allow"', self.conf)

    def test_filter_file_is_one_pattern_per_line(self):
        self.assertEqual(vm_proxy_filter_file(["a.com", "*.b.com"]),
                         "a.com\n*.b.com\n")


class TestRedirect(unittest.TestCase):
    """The uid-keyed map element and the nft skeleton it goes into."""

    def setUp(self):
        self.nft = NFT.read_text()

    def test_element_keys_on_uid_and_carries_address_and_port(self):
        self.assertEqual(vm_proxy_element(10005, "127.128.0.5"),
                         f"10005 : 127.128.0.5 . {VM_PROXY_PORT}")

    def test_map_command_targets_the_proxy_table(self):
        argv = vm_proxy_map_command(10005, "127.128.0.5", "add")
        self.assertEqual(argv[1:3], ["add", "element"])
        self.assertIn(NFT_PROXY_TABLE.split()[1], argv)
        self.assertIn(NFT_PROXY_MAP, argv)

    def test_skeleton_and_constants_agree_on_the_advertised_endpoint(self):
        """The .nft file spells the endpoint literally so it stays applicable
        with a bare `nft -f`; this is what keeps the two in step."""
        self.assertIn(f"ip daddr {VM_PROXY_ADDR} tcp dport {VM_PROXY_PORT}",
                      self.nft)

    def test_the_chain_is_not_called_redirect(self):
        """`redirect` is a reserved word in nft and the parse error points at
        the chain name without saying why."""
        self.assertNotIn("chain redirect", self.nft)

    def test_the_map_uses_concrete_types_on_both_sides(self):
        """A map may not mix a `typeof` key with a plain data type, and
        ipv4_addr has no typeof serialization."""
        self.assertIn("type uid : ipv4_addr . inet_service", self.nft)

    def test_the_rule_is_flushed_before_it_is_added(self):
        """`add rule` appends, so a second VM applying the skeleton would
        otherwise duplicate it."""
        self.assertLess(self.nft.index("flush chain"),
                        self.nft.index("add rule"))

    def test_nat_hook_runs_before_the_filter_chain(self):
        """dstnat (-100) before filter (0) is what lets the filter chain see the
        translated destination — the workload's own loopback address, already
        accepted by the skeleton's `oif lo` rule."""
        self.assertIn("hook output priority dstnat", self.nft)

    def test_there_is_no_skuid_predicate_on_the_rule(self):
        """The map lookup IS the predicate: a uid absent from the map produces
        no match, and the packet goes to an address where nothing listens."""
        rule = [ln for ln in self.nft.splitlines()
                if ln.startswith("add rule")][0]
        self.assertNotIn("meta skuid @", rule)
        self.assertIn("meta skuid map @", rule)


class TestProxyEgressExemption(unittest.TestCase):
    """The proxy shares the guest's uid, so `meta skuid` cannot separate them.

    Under default-deny that means the drop catches the proxy too and hostname
    policy permits nothing at all — observed on a live VM as a CONNECT that
    reaches the proxy, resolves, and dies on its outbound SYN.
    """

    @classmethod
    def setUpClass(cls):
        cls.nft = (ROOT / "nftables" / "workload-filter.nft").read_text()

    def test_the_filter_skeleton_carries_the_cgroup_set(self):
        self.assertIn("add set inet workload_filter wl_proxy_cg", self.nft)
        self.assertIn("typeof socket cgroupv2 level 2", self.nft)

    def test_the_exemption_is_evaluated_before_the_drop(self):
        rules = [ln for ln in self.nft.splitlines() if ln.startswith("add rule")]
        exempt = next(i for i, ln in enumerate(rules) if "wl_proxy_cg" in ln)
        drop = next(i for i, ln in enumerate(rules) if ln.endswith("drop"))
        self.assertLess(exempt, drop)

    def test_the_exemption_widens_no_destination_or_port(self):
        """Widening by port instead — 'let this uid reach 443 anywhere' — is
        the bypass the default-deny chain exists to close."""
        rule = next(ln for ln in self.nft.splitlines()
                    if ln.startswith("add rule") and "wl_proxy_cg" in ln)
        for token in ("daddr", "dport", "443"):
            self.assertNotIn(token, rule)

    def test_the_element_names_the_proxy_units_cgroup(self):
        self.assertEqual(vm_proxy_cgroup("web"),
                         "workloads.slice/workload-web-proxy.service")

    def test_the_exemption_lives_in_the_filter_table(self):
        """Not the proxy table: the rule it feeds has to sit in the output
        chain ahead of the drop, and that chain is the filter skeleton's."""
        argv = vm_proxy_cgroup_command("web", "add")
        self.assertIn("workload_filter", argv)
        self.assertIn(NFT_SET_PROXY_CG, argv)

    def test_the_helper_replaces_the_element_rather_than_accumulating(self):
        """An element resolves to a cgroup id at add time and systemd creates a
        fresh cgroup on every start, so last start's element is stale."""
        source = (ROOT / "libexec" / "workload-vm-proxy").read_text()
        up = cls_body(source, "def up")
        cg = up[up.index("vm_proxy_cgroup_command"):]
        self.assertLess(cg.index('"delete"'), cg.index('"add"'))

    def test_the_proxy_slice_is_pinned_so_level_2_stays_exact(self):
        """A nested custom slice would deepen the cgroup path and the match
        would silently stop firing, dropping the proxy's own traffic."""
        self.assertEqual(VM_PROXY_SLICE, "workloads.slice")
        self.assertEqual(vm_proxy_cgroup("web").count("/"), 1)


class TestInterfaceProvisioning(unittest.TestCase):
    def test_the_address_is_queried_before_it_is_added(self):
        """iproute2 answers a duplicate address with "Address already assigned",
        not the "File exists" a duplicate link produces — so tolerating the
        wrong phrase fails only on the SECOND start of a workload."""
        # Lives in lib/vm.py, not the proxy script: the broker helper needs the
        # same advertised interface, and libexec entrypoints have no extension
        # so neither can import the other.
        source = (ROOT / "lib" / "vm.py").read_text()
        body = cls_body(source, "def ensure_advertised_interface")
        self.assertIn('"addr", "show"', body)
        self.assertLess(body.index('"addr", "show"'), body.index('"addr", "add"'))


class TestGuestEnvironment(unittest.TestCase):
    def test_advertises_one_address_to_every_guest(self):
        env = vm_proxy_env(net_config(hosts=["example.com"]))
        url = f"http://{VM_PROXY_ADDR}:{VM_PROXY_PORT}"
        self.assertEqual(env["HTTPS_PROXY"], url)
        self.assertEqual(env["https_proxy"], url)

    def test_the_endpoint_is_an_ip_literal(self):
        """DNS is precisely what a compromised guest would attack to escape
        hostname policy, so the proxy path must not depend on it."""
        env = vm_proxy_env(net_config(hosts=["example.com"]))
        self.assertNotIn("://workload", env["HTTPS_PROXY"])
        host = env["HTTPS_PROXY"].split("//")[1].split(":")[0]
        self.assertTrue(all(part.isdigit() for part in host.split(".")))

    def test_no_proxy_covers_the_guests_own_loopback(self):
        env = vm_proxy_env(net_config(hosts=["example.com"]))
        self.assertIn("127.0.0.1", env["NO_PROXY"])

    def test_no_proxy_covers_the_advertised_address(self):
        """A workload with both a proxy and a broker is handed one address for
        both, at different ports. Without this a client that honours proxy
        variables asks the proxy to fetch the broker, and the proxy's allowlist
        holds internet hostnames rather than this address -- so the guest gets a
        403 that reads like the broker refusing it."""
        for env in (vm_proxy_env(net_config(hosts=["example.com"])),
                    vm_proxy_env(net_config(hosts=["example.com"], broker=True))):
            self.assertIn(VM_PROXY_ADDR, env["NO_PROXY"])
            self.assertIn(VM_PROXY_ADDR, env["no_proxy"])

    def test_the_proxy_and_broker_urls_are_both_bypassed_by_one_entry(self):
        """One host entry covers every port, so the broker needs no entry of its
        own and adding a third endpoint later needs no change here."""
        env = vm_proxy_env(net_config(hosts=["example.com"], broker=True))
        bypass = env["NO_PROXY"].split(",")
        for url in (env["HTTPS_PROXY"], vm_broker_env(net_config(broker=True))[VM_BROKER_ENV_VAR]):
            self.assertIn(url.split("//")[1].split(":")[0], bypass)

    def test_a_workload_without_hosts_gets_nothing(self):
        self.assertEqual(vm_proxy_env(net_config()), {})


class TestValidation(unittest.TestCase):
    def test_filtered_with_hosts_and_no_allow_is_now_valid(self):
        """Before the proxy existed, `filtered` required a non-empty allow.
        A hostname allowlist is the other valid answer."""
        errors = validate_vm_network({"egress": "filtered",
                                      "hosts": ["example.com"]})
        self.assertEqual(errors, [])

    def test_filtered_with_neither_is_still_rejected(self):
        errors = validate_vm_network({"egress": "filtered"})
        self.assertTrue(any("reach nothing at all" in e for e in errors))

    def test_a_url_is_rejected(self):
        errors = validate_vm_network({"hosts": ["https://example.com"]})
        self.assertTrue(any("drop the scheme" in e for e in errors))

    def test_a_path_is_rejected(self):
        """FilterURLs is off, so a pattern with a path matches nothing — a
        silent hole in an allowlist."""
        errors = validate_vm_network({"hosts": ["example.com/api"]})
        self.assertTrue(any("never matches" in e for e in errors))

    def test_a_port_is_rejected(self):
        errors = validate_vm_network({"hosts": ["example.com:8443"]})
        self.assertTrue(any("use .allow for other ports" in e for e in errors))

    def test_bare_wildcard_is_rejected(self):
        """It is egress = 'open' spelled in a way nobody notices in review."""
        errors = validate_vm_network({"hosts": ["*"], "egress": "filtered"})
        self.assertTrue(any("egress = 'open'" in e for e in errors))

    def test_a_wildcard_subdomain_is_accepted(self):
        self.assertEqual(
            validate_vm_network({"hosts": ["*.fedoraproject.org"],
                                 "egress": "filtered"}), [])

    def test_hosts_with_bridge_is_rejected(self):
        errors = validate_vm_network({"bridge": "br0", "hosts": ["a.com"]})
        self.assertTrue(any("no effect with .bridge" in e for e in errors))

    def test_hosts_with_open_egress_is_rejected(self):
        """The drop is what makes the allowlist binding. Without it the proxy
        stops only cooperative guests, while still costing a daemon that parses
        guest-controlled HTTP — attack surface for a control that does not
        hold. Third member of the family with .bridge and ["*"]."""
        errors = validate_vm_network({"hosts": ["a.com"], "egress": "open"})
        self.assertTrue(any("nothing requires the guest to use the proxy" in e
                            for e in errors))

    def test_the_rejection_names_both_ways_out(self):
        """Refused rather than silently skipped, so the error has to say what
        to do: enforce it, or drop it."""
        errors = validate_vm_network({"hosts": ["a.com"], "egress": "open"})
        joined = " ".join(errors)
        self.assertIn("egress = 'filtered'", joined)
        self.assertIn("drop .hosts", joined)

    def test_hosts_under_filtered_egress_is_the_supported_shape(self):
        self.assertEqual(
            validate_vm_network({"hosts": ["a.com"], "egress": "filtered"}), [])

    def test_hosts_must_be_a_list(self):
        errors = validate_vm_network({"hosts": "example.com"})
        self.assertTrue(any("must be an array" in e for e in errors))


class TestCilModule(unittest.TestCase):
    """The domain, read as text. Whether it compiles is the bench's business."""

    @classmethod
    def setUpClass(cls):
        cls.text = CIL.read_text()
        cls.rules = [ln.strip() for ln in cls.text.splitlines()
                     if ln.strip() and not ln.strip().startswith(";")]

    def test_declares_the_domain_and_its_entrypoint_type(self):
        for decl in ("(type wlproxy_t)", "(type wlproxy_exec_t)"):
            self.assertIn(decl, self.rules)

    def test_object_r_is_declared_before_the_filecon(self):
        """Without it semodule rejects the module: 'Type wlproxy_exec_t is
        invalid for role object_r'."""
        self.assertLess(self.text.index("(roletype object_r wlproxy_exec_t)"),
                        self.text.index("(filecon"))

    def test_the_filecon_names_usr_bin_not_usr_sbin(self):
        """Fedora symlinks /usr/sbin to bin, so a filecon on the symlinked path
        matches nothing at all — silently, while the entry sits visibly in
        file_contexts and matchpathcon reports bin_t."""
        self.assertIn('(filecon "/usr/bin/tinyproxy"', self.text)
        self.assertFalse([r for r in self.rules if "/usr/sbin" in r])

    def test_the_entrypoint_is_narrow(self):
        """Retyping the binary is the point: left as bin_t the domain would
        need bin_t:file entrypoint, and every bin_t binary could enter it."""
        self.assertIn(
            "(allow wlproxy_t wlproxy_exec_t (file (entrypoint execute map "
            "getattr ioctl open read)))", self.rules)
        self.assertNotIn("bin_t (file (entrypoint", self.text)

    def test_systemd_transitions_into_the_domain_directly(self):
        """Unlike QEMU, which needs a runcon wrapper because the policy has no
        init_t -> svirt_t transition, this module declares its own."""
        self.assertIn("(typetransition init_t wlproxy_exec_t process wlproxy_t)",
                      self.rules)

    def test_binds_the_squid_port_label(self):
        """3128 is squid's registered port, so a confined tinyproxy on the
        conventional proxy port needs a name_bind on squid's label."""
        self.assertIn("(allow wlproxy_t squid_port_t (tcp_socket (name_bind)))",
                      self.rules)

    def test_reaches_only_its_own_runtime_dir(self):
        """The proxy terminates guest-controlled input, so its filesystem
        surface is the whole reason it is not simply run as svirt_t."""
        file_targets = {ln.split()[2] for ln in self.rules
                        if ln.startswith("(allow wlproxy_t")
                        and ("(file " in ln or "(dir " in ln)}
        self.assertEqual(
            file_targets - {"wlproxy_exec_t"},
            {"qemu_var_run_t", "net_conf_t", "init_var_run_t"})

    def test_grants_no_write_to_workload_images_or_state(self):
        for forbidden in ("svirt_image_t", "container_file_t", "var_lib_t"):
            self.assertNotIn(forbidden, self.text)

    def test_needs_no_namespace_or_capability_machinery(self):
        """A 14-rule module with no capabilities at all is what confirms the
        tinyproxy-over-squid choice."""
        for forbidden in ("capability", "cap_userns", "mounton", "pivot_root"):
            self.assertNotIn(forbidden, self.text)

    def test_parens_balance(self):
        self.assertEqual(self.text.count("("), self.text.count(")"))


class TestRpmShipsTheModule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = SPEC.read_text()

    def test_installs_the_cil_and_the_nft_skeleton(self):
        self.assertIn("security/workload-proxy.cil", self.spec)
        self.assertIn("nftables/workload-proxy.nft", self.spec)

    def test_installs_the_skeleton_where_the_helper_looks_for_it(self):
        self.assertIn(NFT_PROXY_SKELETON.replace("/usr/share", "%{_datadir}"),
                      self.spec)

    def test_post_loads_the_module_and_relabels_the_binary(self):
        self.assertIn("semodule -i %{_datadir}/workloadctl/workload-proxy.cil",
                      self.spec)
        self.assertIn("restorecon /usr/bin/tinyproxy", self.spec)

    def test_uninstall_removes_the_module_and_restores_the_label(self):
        postun = self.spec.split("%postun", 1)[1]
        self.assertIn("semodule -r workload-proxy", postun)
        self.assertIn("restorecon /usr/bin/tinyproxy", postun)

    def test_requires_tinyproxy_rather_than_recommending_it(self):
        """A VM with hostname policy is default-deny with the proxy as its only
        route out, so a missing binary is not a degraded feature."""
        self.assertIn("Requires:       tinyproxy", self.spec)

    def test_ships_the_helper(self):
        self.assertIn("libexec/workload-vm-proxy", self.spec)


class TestGeneratedUnit(unittest.TestCase):
    """The sidecar unit, from the generator."""

    @classmethod
    def setUpClass(cls):
        from tests import load_script
        gen = load_script("generators/workload-generate")
        cls.gen = gen
        cls.config = {
            "workload": {"name": "web"},
            "vm": {"memory": "2048", "network": {"hosts": ["example.com"],
                                                 "egress": "filtered"}},
        }
        cls.unit = gen.generate_vm_proxy_service(cls.config, "_wl-web")

    def test_runs_as_the_workload_user(self):
        """So the proxy's own outbound traffic carries the same uid as the
        guest's and one `meta skuid` rule governs both paths."""
        self.assertIn("User=_wl-web", self.unit)
        self.assertIn("Group=_wl-web", self.unit)

    def test_declares_no_runtime_directory(self):
        """The VM service owns /run/workload-vm/<name>; a second claimant would
        refcount-cleanup it on proxy stop and yank the VM's qmp socket."""
        self.assertNotIn("RuntimeDirectory=", self.unit)

    def test_execstart_is_the_bare_binary(self):
        """The module declares the init_t transition, so there is no runcon
        wrapper — and a shell in between would be bin_t and refused."""
        self.assertIn(f"ExecStart={VM_PROXY_BIN} -d -c", self.unit)
        self.assertNotIn("runcon", self.unit)

    def test_prestart_runs_as_root_and_is_not_tolerant(self):
        """A redirect that failed to install leaves a healthy-looking proxy
        that no guest can reach."""
        self.assertIn("ExecStartPre=+/usr/libexec/workloadctl/workload-vm-proxy "
                      'up "web"', self.unit)
        self.assertNotIn("ExecStartPre=-+", self.unit)

    def test_withdraws_the_redirect_on_stop_kill_and_failure(self):
        """ExecStopPost, not ExecStop: systemd runs it on kill and on failure."""
        self.assertIn("ExecStopPost=-+/usr/libexec/workloadctl/workload-vm-proxy "
                      'down "web"', self.unit)

    def test_stops_with_the_vm(self):
        self.assertIn("PartOf=workload-web.service", self.unit)
        self.assertIn("Before=workload-web.service", self.unit)

    def test_the_vm_service_requires_it(self):
        """A hard prerequisite, not a Wants=: a filtered VM booted without its
        proxy looks healthy and can reach nothing."""
        vm_unit = self.gen.generate_vm_service(self.config, "_wl-web", 10005)
        self.assertIn("workload-web-proxy.service", vm_unit)

    def test_a_vm_without_hosts_gets_no_dependency(self):
        config = {"workload": {"name": "web"},
                  "vm": {"network": {"egress": "open"}}}
        vm_unit = self.gen.generate_vm_service(config, "_wl-web", 10005)
        self.assertNotIn("workload-web-proxy.service", vm_unit)


class TestCloudInit(unittest.TestCase):
    """The guest is told where its proxy is — advisory, and bound by the
    default-deny chain rather than by the guest's cooperation."""

    @classmethod
    def setUpClass(cls):
        from tests import load_script
        cls.ensure = load_script("libexec/workload-ensure-user")

    def _render(self, hosts):
        return self.ensure._render_default_user_data(
            name="web", guest_user="fedora", pubkey="ssh-ed25519 AAAA",
            mounts=[], has_data_disk=False,
            guest_env=vm_proxy_env(net_config(hosts=hosts)) if hosts else {})

    def test_writes_the_proxy_into_the_guest_environment(self):
        text = self._render(["example.com"])
        self.assertIn("write_files:", text)
        self.assertIn("/etc/environment", text)
        self.assertIn(f"HTTPS_PROXY=http://{VM_PROXY_ADDR}:{VM_PROXY_PORT}",
                      text)

    def test_covers_shells_that_never_go_through_pam(self):
        text = self._render(["example.com"])
        self.assertIn("/etc/profile.d/99-workload-proxy.sh", text)
        self.assertIn("export HTTPS_PROXY=", text)

    def test_a_workload_without_hosts_gets_no_write_files(self):
        self.assertNotIn("write_files:", self._render(None))


class TestDiagnose(unittest.TestCase):
    """Three things must hold together, and each fails silently on its own."""

    def setUp(self):
        from cmd_diagnose import vm_proxy_check
        self.check = vm_proxy_check
        self.config = SimpleNamespace(
            name="web", uid=10005, is_vm=True,
            vm_bridge=None,
            vm_network={"hosts": ["example.com"], "egress": "filtered"},
            config=net_config(hosts=["example.com"], egress="filtered"))

    def test_no_line_for_a_workload_without_hosts(self):
        self.config.config = net_config()
        self.assertIsNone(self.check(self.config))

    def test_passes_when_redirect_and_address_are_both_present(self):
        name, ok, msg = self.check(
            self.config, elements=["10005 : 127.128.0.5 . 3128"],
            address_present=True)
        self.assertEqual(name, "vm_proxy")
        self.assertTrue(ok)
        self.assertIn("hostname policy on 1 pattern", msg)

    def test_fails_when_the_table_is_absent(self):
        _, ok, msg = self.check(self.config, elements=None, address_present=True)
        self.assertFalse(ok)
        self.assertIn("table is absent", msg)

    def test_fails_when_this_uid_has_no_element(self):
        """The proxy listens, the guest boots, status is green — and every
        request to the advertised address goes nowhere."""
        _, ok, msg = self.check(
            self.config, elements=["10099 : 127.128.0.99 . 3128"],
            address_present=True)
        self.assertFalse(ok)
        self.assertIn("no element", msg)
        self.assertIn("workload-web-proxy.service", msg)

    def test_fails_when_the_advertised_address_is_missing(self):
        _, ok, msg = self.check(
            self.config, elements=["10005 : 127.128.0.5 . 3128"],
            address_present=False)
        self.assertFalse(ok)
        self.assertIn(VM_PROXY_IFACE, msg)

    def test_reads_nfts_real_map_element_shape(self):
        """nft 1.1.6 renders a map element as a two-item list [key, value] —
        NOT the {"elem": {...}} shape a counted set element uses. Reading only
        the dict shape reported a working redirect as missing on a live host."""
        _, ok, _ = self.check(
            self.config,
            elements=[[10005, {"concat": ["127.128.0.5", 3128]}]],
            address_present=True)
        self.assertTrue(ok)

    def test_reads_the_dict_element_shape_too(self):
        _, ok, _ = self.check(
            self.config,
            elements=[{"elem": {"key": 10005, "val": ["127.128.0.5", 3128]}}],
            address_present=True)
        self.assertTrue(ok)

    def test_a_map_document_yields_its_elements(self):
        """`nft -j list map` renders under "map", not "set" — matching only on
        "set" silently returns nothing and reads as "not armed"."""
        from vm import nft_set_elements
        payload = {"nftables": [{"map": {"name": NFT_PROXY_MAP,
                                         "elem": [[10005, "x"]]}}]}
        self.assertEqual(nft_set_elements(payload), [[10005, "x"]])


class TestTeardown(unittest.TestCase):
    def test_purge_sweeps_the_redirect_element(self):
        """The map is keyed on uid, so an element left behind would be
        inherited by whatever workload is issued that uid next."""
        source = (ROOT / "lib" / "substrate_vm.py").read_text()
        self.assertIn("workload-vm-proxy", source)


class TestHelperContract(unittest.TestCase):
    """The runtime helper, read as text — it needs root and nft to run."""

    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "libexec" / "workload-vm-proxy").read_text()

    def test_never_tears_down_the_shared_interface(self):
        """The link and the chain are shared, hold no per-workload state, and
        cost nothing idle — which is why there is no refcount to get wrong."""
        down = cls_body(self.source, "def down")
        self.assertNotIn("link", down)
        self.assertNotIn("ensure_advertised_interface", down)

    def test_up_purges_before_adding(self):
        """`add element` on an existing key does not overwrite it, so a
        reallocated uid would keep pointing at a stale listen address."""
        up = cls_body(self.source, "def up")
        self.assertLess(up.index('"delete"'), up.index('"add"'))

    def test_config_is_replaced_atomically(self):
        """A restart racing a rewrite would otherwise read a half-written file
        and exit 70."""
        self.assertIn("os.replace", self.source)

    def test_missing_hosts_is_a_no_op_not_a_failure(self):
        """So an edited config that drops `hosts` stops cleanly rather than
        blocking the workload's start."""
        up = cls_body(self.source, "def up")
        self.assertIn("vm_uses_proxy", up)
        self.assertIn("return 0", up.split("vm_uses_proxy")[1][:400])


def cls_body(source: str, marker: str) -> str:
    """The text of one top-level def, up to the next one."""
    start = source.index(marker)
    rest = source[start + len(marker):]
    end = rest.find("\ndef ")
    return rest if end == -1 else rest[:end]


if __name__ == "__main__":
    unittest.main()
