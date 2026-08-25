"""The inspector's socket and service units, from the generator.

Every assertion here is a silent hole if it regresses: a property that is wrong
produces a unit that looks configured and then either reaches nothing or
redirects into itself. The values are asserted from the same constants the
generator reads, so a drift between the constant and the rendered unit is a
failure.

These were written before the listener program existed, when no functional test
could have caught any of it. It exists now (libexec/workload-vm-inspect-listener,
tests/test_vm_inspect_listener.py), which is why the unit numbers the original
docstring cited are gone: rung 2 reuses those labels for different work, and a
stale "T5a" reads as a live forward reference to it.
"""

import unittest
import unittest.mock

from vm import (
    NFT_SET_INSPECT_CG, NFT_SET_EGRESS_CG,
    VM_EGRESS_DEFAULT, VM_INSPECT_PORT_CLEARTEXT, VM_INSPECT_PORT_TLS,
    VM_SIDECAR_SLICE, VM_INSPECT_LISTENER_BIN, vm_inspect_address,
    vm_inspect_cgroup, vm_inspect_cgroup_command,
    vm_inspect_cgroup_filter_command, vm_uses_inspect,
)
from workload_lib import dq

UID = 10004  # worked example, matching test_vm_inspect.py


def net_config(**net):
    return {"vm": {"network": net}}


def _config(net):
    return {"workload": {"name": "web"}, "vm": {"network": net}}


class TestPredicate(unittest.TestCase):
    """vm_uses_inspect: not bridged, egress filtered."""

    def test_filtered_default_applies(self):
        self.assertTrue(vm_uses_inspect(net_config()))

    def test_filtered_explicit_applies(self):
        self.assertTrue(vm_uses_inspect(net_config(egress="filtered")))

    def test_open_egress_does_not_apply(self):
        self.assertFalse(vm_uses_inspect(net_config(egress="open")))

    def test_a_container_workload_is_not_inspected(self):
        """The predicate has to be right standing alone.

        Every caller is behind a VM-only branch today, so a container config
        reaching this returned True and nothing noticed. A predicate documented
        as the single source of a decision that is wrong for a config shape it
        happily accepts is a bug waiting for its next caller.
        """
        self.assertFalse(vm_uses_inspect({"workload": {"name": "x"},
                                          "container": {"image": "y"}}))
        self.assertFalse(vm_uses_inspect({}))

    def test_a_bridged_vm_never_applies(self):
        self.assertFalse(
            vm_uses_inspect(net_config(bridge="br0", egress="filtered")))

    def test_default_egress_is_filtered(self):
        """VM_EGRESS_DEFAULT is filtered, so a VM whose network sets no egress
        is inspected — the default-deny posture, not an opt-in."""
        self.assertEqual(VM_EGRESS_DEFAULT, "filtered")
        self.assertTrue(vm_uses_inspect(net_config()))


class TestGeneratedSocket(unittest.TestCase):
    """The .socket unit, from the generator.

    The address-add lives here, not on the service: the socket binds its
    ListenStream= before the service ever runs, so an ExecStartPre on the
    service is too late by one unit.
    """

    @classmethod
    def setUpClass(cls):
        from tests import load_script
        cls.gen = load_script("generators/workload-generate")
        cls.addr = vm_inspect_address(UID)
        # The uid is a parameter, not a lookup. It used to be mocked here --
        # which is precisely what hid the defect the mock was standing in for:
        # on a first enable the user does not exist yet, and a real getpwnam
        # raised. See test_generation_does_not_need_the_user_to_exist_yet.
        cls.unit = cls.gen.generate_vm_inspect_socket(_config({}), "_wl-web", UID)

    def test_the_address_add_is_on_the_socket(self):
        """On the socket unit, privileged, not tolerant: an address that
        failed to add leaves a socket bound to nothing that no guest can
        reach."""
        self.assertIn(
            "ExecStartPre=+/usr/libexec/workloadctl/workload-vm-inspect "
            'up "web"', self.unit)
        self.assertNotIn("ExecStartPre=-+", self.unit)

    def test_the_address_remove_is_on_the_socket_and_tolerant(self):
        self.assertIn(
            "ExecStopPost=-+/usr/libexec/workloadctl/workload-vm-inspect "
            'down "web"', self.unit)

    def test_the_service_carrying_the_prestart_is_rejected(self):
        """The whole point of §7.7: the prestart on the service is too late by
        one unit. It belongs on the socket, which is what binds first."""
        service = self.gen.generate_vm_inspect_service(_config({}), "_wl-web")
        self.assertNotIn("workload-vm-inspect up", service)
        self.assertNotIn("ExecStartPre=+/usr/libexec/workloadctl/"
                         "workload-vm-inspect", service)

    def test_all_four_listenstreams_from_the_constants(self):
        """v4 and v6, cleartext and TLS, never a literal."""
        self.assertIn(
            f"ListenStream={self.addr.v4}:{VM_INSPECT_PORT_CLEARTEXT}",
            self.unit)
        self.assertIn(f"ListenStream={self.addr.v4}:{VM_INSPECT_PORT_TLS}",
                      self.unit)
        self.assertIn(
            f"ListenStream=[{self.addr.v6}]:{VM_INSPECT_PORT_CLEARTEXT}",
            self.unit)
        self.assertIn(f"ListenStream=[{self.addr.v6}]:{VM_INSPECT_PORT_TLS}",
                      self.unit)
        # Exactly four — a fifth (a literal, a stray family, a duplicated
        # port) or a missing one would be a silent hole.
        self.assertEqual(
            sum(1 for ln in self.unit.splitlines()
                if ln.startswith("ListenStream=")), 4)

    def test_accept_is_no(self):
        self.assertIn("Accept=no", self.unit)

    def test_both_trigger_limit_directives_are_explicit(self):
        """Accept=no silently lowers the default to 20 per 2s and hitting it
        fails the socket unit permanently; both must be present with a value."""
        self.assertRegex(self.unit, r"TriggerLimitIntervalSec=\S+")
        self.assertRegex(self.unit, r"TriggerLimitBurst=\S+")

    def test_freebind_is_absent(self):
        """FreeBind converts a loud bind failure into a silent blackhole;
        a later well-meant addition of it must be caught here, not in
        production."""
        self.assertNotIn("FreeBind", self.unit)

    def test_the_socket_is_ordered_after_the_setup_service(self):
        """Without this the VM does not boot, and only on a real host.

        The socket's ExecStartPre calls `workload-vm-inspect up`, whose second
        statement is a getpwnam of _wl-<name>. User creation is deferred to
        workload-<name>-setup.service and /run is tmpfs, so the user does not
        exist until that unit has run. The VM unit's After= orders the VM
        behind all of its prerequisites but does not order them against each
        other, so an unordered socket starts concurrently with setup and
        usually wins the race -- getpwnam raises, ExecStartPre fails, and the
        VM's Requires= on the socket takes the VM down with it.

        The proxy sidecar has carried both directives since it was written;
        this is the assertion that keeps the pair from drifting apart again.
        """
        self.assertIn("Requires=workload-web-setup.service", self.unit)
        self.assertIn("After=workload-web-setup.service", self.unit)

    def test_partof_and_before_the_vm(self):
        self.assertIn("PartOf=workload-web.service", self.unit)
        self.assertIn("Before=workload-web.service", self.unit)


class TestGenerationPredatesTheUser(unittest.TestCase):
    """Generation must not depend on _wl-<name> existing.

    The generator runs during early boot and on `workloadctl enable`. On a
    first enable it has only just WRITTEN the sysusers config -- the user does
    not exist until systemd-sysusers runs, which is after generation. A
    getpwnam here therefore raises KeyError on every first enable, and the
    generator's per-workload try/except turns that into "ERROR processing
    <toml>" and no VM units at all: the workload cannot start, at all, ever,
    on the boot it was created.

    This is a runtime-only failure that no other test in this file can see,
    because they all supply a uid. So this one makes getpwnam raise the way a
    real first enable does.
    """

    def test_generation_does_not_need_the_user_to_exist_yet(self):
        from tests import load_script
        gen = load_script("generators/workload-generate")
        with unittest.mock.patch.object(
                gen.pwd, "getpwnam",
                side_effect=KeyError(
                    "getpwnam(): name not found: '_wl-web'")):
            unit = gen.generate_vm_inspect_socket(_config({}), "_wl-web", UID)
        addr = vm_inspect_address(UID)
        self.assertIn(str(addr.v4), unit)


class TestGeneratedService(unittest.TestCase):
    """The .service unit, from the generator.

    The cgroup elements live here, not on the socket: an element resolves to a
    cgroup id at add time and systemd makes a fresh cgroup on every start, so
    the add belongs to the unit that owns the cgroup and the remove to the
    point at which the path still resolves to the id being retired.
    """

    @classmethod
    def setUpClass(cls):
        from tests import load_script
        cls.gen = load_script("generators/workload-generate")
        cls.unit = cls.gen.generate_vm_inspect_service(_config({}), "_wl-web")

    def test_runs_as_the_workload_user(self):
        self.assertIn("User=_wl-web", self.unit)
        self.assertIn("Group=_wl-web", self.unit)

    def test_the_slice_is_pinned_literally(self):
        """Pinned, NOT taken from [resources].slice: both cgroup exemptions are
        `socket cgroupv2 level 2` matches, so the path must be exactly two
        components — a nested custom slice would deepen it and both would
        silently stop firing."""
        # The WHOLE line, not a substring of it. `assertIn` against the unit
        # text passes for Slice=workloads.slice/anything.slice, which is
        # exactly the nesting this test exists to forbid -- and a nested slice
        # deepens the path so both `level 2` matches silently stop firing.
        # Found by nesting the slice in the generator and watching the whole
        # suite stay green.
        self.assertIn(f"Slice={VM_SIDECAR_SLICE}", self.unit.splitlines())
        self.assertEqual(VM_SIDECAR_SLICE, "workloads.slice")
        # The element names the cgroup on the pinned slice, two components...
        self.assertEqual(vm_inspect_cgroup("web").count("/"), 1)
        # ...and on the SAME slice the unit pins. Two independent spellings of
        # the path exist -- the unit's Slice= and the element the rule matches
        # -- and a drift between them is a redirect that never returns.
        self.assertTrue(vm_inspect_cgroup("web").startswith(f"{VM_SIDECAR_SLICE}/"),
                        vm_inspect_cgroup("web"))

    def test_both_cgroup_elements_are_armed_on_start(self):
        """Both or neither on the way in: the redirect exemption without the
        egress one redirects the inspector's dials into itself; the egress
        one without the redirect one leaves its upstream caught by the
        default-deny drop."""
        prefix = "ExecStartPre="
        pre = [ln[len(prefix):] for ln in self.unit.splitlines()
               if ln.startswith(prefix)]
        self.assertEqual(len(pre), 2)
        expected = {
            "+" + " ".join(dq(a) for a in
                           vm_inspect_cgroup_command("web", "add")),
            "+" + " ".join(dq(a) for a in
                           vm_inspect_cgroup_filter_command("web", "add")),
        }
        self.assertEqual(set(pre), expected)
        # One element per table: the redirect exemption in the proxy table,
        # the egress exemption in the filter table.
        self.assertEqual(sum("wl_inspect_cg" in ln for ln in pre), 1)
        self.assertEqual(sum("wl_egress_cg" in ln for ln in pre), 1)

    def test_both_cgroup_elements_are_removed_on_stop(self):
        """ExecStopPost, not ExecStop: a killed or failed inspector still
        withdraws them, and `-` is tolerant because they are legitimately
        absent when the start failed before arming them."""
        prefix = "ExecStopPost="
        post = [ln[len(prefix):] for ln in self.unit.splitlines()
                if ln.startswith(prefix)]
        self.assertEqual(len(post), 2)
        expected = {
            "-+" + " ".join(dq(a) for a in
                            vm_inspect_cgroup_command("web", "delete")),
            "-+" + " ".join(dq(a) for a in
                            vm_inspect_cgroup_filter_command("web", "delete")),
        }
        self.assertEqual(set(post), expected)
        self.assertEqual(sum("wl_inspect_cg" in ln for ln in post), 1)
        self.assertEqual(sum("wl_egress_cg" in ln for ln in post), 1)

    def test_execstart_is_the_listener_binary(self):
        self.assertIn(f"ExecStart={VM_INSPECT_LISTENER_BIN}", self.unit)

    def test_execstart_names_the_workload(self):
        """The listener resolves its policy path from argv[1].

        Socket activation gives it four identically-named fds and no way to
        recover which workload it serves, so an ExecStart that dropped the
        argument produces a listener that cannot find inspect.json -- which
        fails its start, but only on the guest's first dial, long after the
        generator ran.
        """
        self.assertIn(f'ExecStart={VM_INSPECT_LISTENER_BIN} {dq("web")}',
                      self.unit)

    def test_partof_the_vm(self):
        """PartOf= is what makes the service actually stop with the VM, which
        is what makes an edited list apply on a plain restart."""
        self.assertIn("PartOf=workload-web.service", self.unit)

    def test_the_service_is_ordered_after_the_setup_service(self):
        """User=_wl-<name> must be resolvable before systemd executes anything.

        Lower risk than the socket's copy -- socket activation happens long
        after boot -- but asserted so the two halves cannot drift, which is how
        a reader concludes the socket's ordering was the accident.
        """
        self.assertIn("Requires=workload-web-setup.service", self.unit)
        self.assertIn("After=workload-web-setup.service", self.unit)

    def test_no_before_the_vm(self):
        """Before= the VM is the socket's job; the service is pulled in by the
        socket, so a Before= here would misstate who owns the ordering."""
        self.assertNotIn("Before=", self.unit)


class TestSidecarHardening(unittest.TestCase):
    """The sandbox both egress sidecars run in.

    ADR 008 names this process as the cost of the design -- code parsing
    hostile guest input, on the path for all HTTP and HTTPS -- and it shipped
    confined by SELinux alone, next to a virtiofsd sidecar whose own
    confinement is argued at length. Held here so the sandbox cannot quietly
    fall off a unit that still looks configured.
    """

    @classmethod
    def setUpClass(cls):
        from tests import load_script
        cls.gen = load_script("generators/workload-generate")
        cls.inspect = cls.gen.generate_vm_inspect_service(_config({}), "_wl-web")
        cls.resolve = cls.gen.generate_vm_resolve_service(_config({}), "_wl-web")

    def units(self):
        return (("inspect", self.inspect), ("resolve", self.resolve))

    def test_both_units_drop_every_capability(self):
        """Neither binds a privileged port: both take their listeners from
        their socket unit, which is the whole reason those exist."""
        for which, unit in self.units():
            with self.subTest(unit=which):
                self.assertIn("CapabilityBoundingSet=", unit.splitlines())
                self.assertIn("AmbientCapabilities=", unit.splitlines())

    def test_both_units_get_a_read_only_hierarchy_and_one_writable_path(self):
        for which, unit in self.units():
            with self.subTest(unit=which):
                self.assertIn("ProtectSystem=strict", unit)
                self.assertIn("PrivateTmp=yes", unit)
                self.assertIn('ReadWritePaths="/run/workload-vm/web"', unit)

    def test_neither_unit_carries_no_new_privileges(self):
        """It breaks the `#!` entrypoint transition from init_t with a bare
        203/EXEC that points nowhere near the cause -- the same measurement the
        virtiofsd sidecar's comment records."""
        for which, unit in self.units():
            with self.subTest(unit=which):
                self.assertNotIn("NoNewPrivileges", unit)
                self.assertNotIn("DynamicUser", unit)

    def test_the_inspector_keeps_the_families_getaddrinfo_needs(self):
        """Losing AF_NETLINK or AF_UNIX turns every upstream dial into
        `upstream unreachable` -- a policy gap wearing a network error's
        clothes."""
        line = [l for l in self.inspect.splitlines()
                if l.startswith("RestrictAddressFamilies=")]
        self.assertEqual(len(line), 1, self.inspect)
        families = set(line[0].split("=", 1)[1].split())
        self.assertEqual(
            families, {"AF_INET", "AF_INET6", "AF_UNIX", "AF_NETLINK"})

    def test_the_responder_is_denied_the_family_a_resolver_call_would_need(self):
        """It must contain no call that could consult a resolver. AF_NETLINK's
        absence is what makes a getaddrinfo that appeared here fail at the
        socket rather than quietly reach a nameserver."""
        line = [l for l in self.resolve.splitlines()
                if l.startswith("RestrictAddressFamilies=")]
        self.assertEqual(len(line), 1, self.resolve)
        families = set(line[0].split("=", 1)[1].split())
        self.assertNotIn("AF_NETLINK", families)
        self.assertIn("AF_INET", families)

    def test_the_inspectors_task_ceiling_covers_its_connection_ceiling(self):
        """One thread per connection, so a TasksMax below MAX_CONNECTIONS is a
        listener that refuses connections it counted as admitted."""
        from tests import load_script
        listener = load_script("libexec/workload-vm-inspect-listener")
        tasks = [l for l in self.inspect.splitlines()
                 if l.startswith("TasksMax=")]
        self.assertEqual(len(tasks), 1)
        self.assertGreater(int(tasks[0].split("=", 1)[1]),
                           listener.MAX_CONNECTIONS)

    def test_both_units_bound_their_memory(self):
        for which, unit in self.units():
            with self.subTest(unit=which):
                self.assertTrue(
                    any(l.startswith("MemoryMax=") for l in unit.splitlines()),
                    unit)


class TestGeneratorWiring(unittest.TestCase):
    """The emit block: a bridged VM and an open-egress VM generate neither
    unit; a filtered non-bridged VM generates both — AND the VM unit pulls the
    socket in. The emit tests assert only that a file is written, and that was
    not enough: a generated unit that nothing pulls in is a file, not a
    service. The socket has no [Install] and units generated into /run are
    never enabled, so the VM's Requires= is the ONLY thing that binds it —
    and the arming of the nft elements and listener addresses lives entirely
    in the socket's ExecStartPre, which runs only when the socket binds."""

    @classmethod
    def setUpClass(cls):
        from tests import load_script
        cls.gen = load_script("generators/workload-generate")
        # Patch the generator's pwd lookup so the test runs without a real
        # _wl-web user: the inspect socket generator looks the uid up to
        # derive the listener addresses. Must be active before generation.
        cls._pw_patch = unittest.mock.patch.object(
            cls.gen.pwd, "getpwnam",
            return_value=unittest.mock.Mock(pw_uid=UID))
        cls._pw_patch.start()

    @classmethod
    def tearDownClass(cls):
        cls._pw_patch.stop()

    def _predicate(self, net):
        return self.gen.vm_uses_inspect(_config(net))

    def _vm_unit_requires(self, net):
        """The VM unit's Requires= line, or None if it carries none."""
        unit = self.gen.generate_vm_service(_config(net), "_wl-web", UID)
        lines = [ln for ln in unit.splitlines()
                 if ln.startswith("Requires=")]
        self.assertEqual(len(lines), 1)
        return lines[0]

    def test_filtered_non_bridged_emits(self):
        self.assertTrue(self._predicate({}))
        self.assertTrue(self._predicate({"egress": "filtered"}))

    def test_bridged_does_not_emit(self):
        self.assertFalse(
            self._predicate({"bridge": "br0", "egress": "filtered"}))

    def test_open_egress_does_not_emit(self):
        self.assertFalse(self._predicate({"egress": "open"}))

    def test_the_vm_unit_requires_the_inspect_socket(self):
        """A generated unit that nothing pulls in is a file, not a service:
        without this Requires= the socket never binds, its ExecStartPre
        (the nft arming) never runs, and a guest dial to 443 lands on an
        empty DNAT map. Requires=, not Wants=: the same list feeds After=,
        which is what makes the VM's start wait for the bind."""
        for net in ({}, {"egress": "filtered"}):
            requires = self._vm_unit_requires(net)
            # assertIn, not endswith: the responder's socket joined the same
            # list behind this one, and a position assertion would have made
            # every future prerequisite look like a regression of this one.
            self.assertIn("workload-web-inspect.socket", requires.split(),
                          requires)

    def test_open_egress_vm_does_not_require_the_inspect_socket(self):
        """An unfiltered VM would be the workload the redirect breaks, so it
        gets no socket and must not pull one in."""
        self.assertNotIn(
            "workload-web-inspect.socket",
            self._vm_unit_requires({"egress": "open"}))

    def test_bridged_vm_does_not_require_the_inspect_socket(self):
        """A bridged guest has no host socket in its data path: nothing to
        require, and the socket would bind to nothing the guest can reach."""
        self.assertNotIn(
            "workload-web-inspect.socket",
            self._vm_unit_requires({"bridge": "br0", "egress": "filtered"}))


if __name__ == "__main__":
    unittest.main()
