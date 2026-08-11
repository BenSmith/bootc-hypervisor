#!/usr/bin/env python3
"""Packet capture: vantages, plans, bounds, and the rules each backend needs.

Everything in lib/pcap.py is a pure function of a config, which is what lets
`--dry-run` and the helper share one object. These tests hold that equivalence
in place, and pin the handful of facts that were measured rather than reasoned:
the snaplen default, what `filter-dump` cannot do, and that `log group` takes a
literal.
"""

import unittest
from pathlib import Path
from types import SimpleNamespace

from pcap import (
    CT_MARK_MASK, CT_MARK_TAG, CT_MARK_UID_MASK, DIRECTION_DEFAULT,
    PCAP_INPUT_CHAIN, PCAP_OUTPUT_CHAIN, PCAP_UNIT_PREFIX,
    QEMU_MAXLEN_UNLIMITED, SNAPLEN_DEFAULT,
    VANTAGE_GUEST, VANTAGE_HOST, available_vantages, build_plan,
    filter_dump_object, parse_duration, parse_size, parse_snaplen,
    log_rule_handles, pcap_delete_command, pcap_input_rule, pcap_output_rule,
    pcap_rule_commands, pcap_unit_name,
    pcap_vantages, render_plan, systemd_run_argv, tcpdump_argv,
    validate_request,
)

ROOT = Path(__file__).resolve().parent.parent


def vm_config(name="fj", uid=10003, bridge=None):
    return SimpleNamespace(
        name=name, uid=uid, is_vm=True, vm_bridge=bridge,
        vm_network={} if bridge is None else {"bridge": bridge},
        config={"vm": {"network": {}}},
        get_network_mode=lambda: "pasta")


def container_config(name="web", uid=10004, mode="pasta", containers=None,
                     topology=None):
    """`mode` is the [network] mode; `topology` is workload.mode
    (single|pod|bridge), which is what decides namespace sharing."""
    names = containers or [name]
    return SimpleNamespace(
        name=name, uid=uid, is_vm=False, vm_bridge=None, vm_network={},
        config={"network": {"mode": mode}},
        get_network_mode=lambda: mode,
        mode=topology or ("single" if names == [name] else "pod"),
        container_names=lambda: names,
        podman_container_name=lambda c: (
            f"workload-{name}" if names == [name] else f"workload-{name}-{c}"),
    )


class TestVantages(unittest.TestCase):
    """A vantage is an interface — which needs no new concept, because tcpdump
    users already accept `any`, `lo` and `nflog:3`."""

    def test_a_passt_vm_offers_both(self):
        self.assertEqual(available_vantages(vm_config()),
                         [VANTAGE_HOST, VANTAGE_GUEST])

    def test_a_bridged_vm_has_no_host_vantage(self):
        """Nothing of ours is in that guest's data path — no host socket, so
        no uid for nflog to key on."""
        vantages = {v.name: v for v in pcap_vantages(vm_config(bridge="br0"))}
        self.assertFalse(vantages[VANTAGE_HOST].available)
        self.assertIn("bridge", vantages[VANTAGE_HOST].detail)
        self.assertTrue(vantages[VANTAGE_GUEST].available)

    def test_a_host_network_container_has_no_guest_vantage(self):
        """Measured on podman 5.8.4: its netns inode is identical to the
        host's, so there is genuinely nothing to enter."""
        vantages = {v.name: v
                    for v in pcap_vantages(container_config(mode="host"))}
        self.assertTrue(vantages[VANTAGE_HOST].available)
        self.assertFalse(vantages[VANTAGE_GUEST].available)

    def test_a_host_network_container_says_why_host_side_matters(self):
        """For those workloads the uid is the ONLY thing separating their
        traffic from the host's own."""
        vantages = {v.name: v
                    for v in pcap_vantages(container_config(mode="host"))}
        self.assertIn("ONLY", vantages[VANTAGE_HOST].detail)

    def test_mode_none_offers_nothing(self):
        self.assertEqual(available_vantages(container_config(mode="none")), [])

    def test_a_vms_guest_side_is_a_dumb_backend(self):
        """filter-dump accepts only `file` and `maxlen`. -D says so before a
        user hits it, rather than four special cases at the point of failure."""
        guest = [v for v in pcap_vantages(vm_config())
                 if v.name == VANTAGE_GUEST][0]
        self.assertFalse(guest.supports_filter)
        self.assertFalse(guest.supports_direction)
        self.assertFalse(guest.supports_rotation)

    def test_a_containers_guest_side_takes_a_full_filter(self):
        """AF_PACKET in a namespace is lossy under load but takes a filter
        expression; filter-dump is lossless and takes none."""
        guest = [v for v in pcap_vantages(container_config())
                 if v.name == VANTAGE_GUEST][0]
        self.assertTrue(guest.supports_filter)

    def test_no_host_vantage_anywhere_takes_a_filter(self):
        """nflog is nflog on every substrate."""
        for config in (vm_config(), container_config(),
                       container_config(mode="host")):
            host = [v for v in pcap_vantages(config)
                    if v.name == VANTAGE_HOST][0]
            self.assertFalse(host.supports_filter, config.get_network_mode())


class TestBounds(unittest.TestCase):
    def test_durations(self):
        self.assertEqual(parse_duration("30s"), 30)
        self.assertEqual(parse_duration("5m"), 300)
        self.assertEqual(parse_duration("1h"), 3600)
        self.assertEqual(parse_duration("0"), 0)

    def test_sizes_are_decimal_like_tcpdumps(self):
        self.assertEqual(parse_size("100M"), 100_000_000)
        self.assertEqual(parse_size("2G"), 2_000_000_000)

    def test_a_bad_bound_says_what_is_accepted(self):
        with self.assertRaises(ValueError) as ctx:
            parse_duration("soon")
        self.assertIn("30s, 5m, 1h", str(ctx.exception))

    def test_snaplen_defaults_to_1500_not_to_everything(self):
        """Diverges from tcpdump (262144), Retina (0) and AWS (whole frames),
        none of which face passt's 65520-byte MTU: at 10.9 KB per packet an
        untruncated capture hits a 100 MB cap in seconds."""
        self.assertEqual(SNAPLEN_DEFAULT, 1500)
        self.assertEqual(parse_snaplen(None, [VANTAGE_HOST]),
                         {VANTAGE_HOST: 1500})

    def test_snaplen_is_the_only_per_vantage_knob(self):
        """Because the correct value genuinely differs by side, while every
        bound stays global so the files cover the same window."""
        self.assertEqual(
            parse_snaplen("guest:1500,host:0", [VANTAGE_HOST, VANTAGE_GUEST]),
            {VANTAGE_HOST: 0, VANTAGE_GUEST: 1500})

    def test_a_scalar_snaplen_applies_to_every_vantage(self):
        self.assertEqual(parse_snaplen("128", [VANTAGE_HOST, VANTAGE_GUEST]),
                         {VANTAGE_HOST: 128, VANTAGE_GUEST: 128})

    def test_an_unknown_vantage_in_the_snaplen_spec_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_snaplen("wire:100", [VANTAGE_HOST])


class TestHostVantageRules(unittest.TestCase):
    """nflog is the only mechanism that can produce a per-workload host-side
    capture at all: by the time a packet is on the wire the owning socket is
    not part of it, so only netfilter sees `meta skuid`."""

    def test_the_output_rule_is_non_terminating(self):
        """This is the property `--dry-run` exists to let an operator confirm
        before it goes into the security-critical table."""
        rule = pcap_output_rule(10003, 1500)
        self.assertTrue(rule.endswith("continue"))
        for verdict in ("drop", "accept", "reject"):
            self.assertNotIn(verdict, rule)

    def test_the_group_is_a_literal_not_an_expression(self):
        """`log group ct mark`, `log group ct mark and 0x3fffffff` and
        `log group @nh,0,16` are all parse errors, which is what forces one
        input rule per workload rather than one generic rule."""
        rule = pcap_output_rule(10003, 1500)
        self.assertIn("log group 3 ", rule)
        self.assertNotIn("log group ct", rule)

    def test_inbound_is_selected_by_conntrack_mark(self):
        """A rule in the output hook never sees inbound packets, and nftables
        has no input-side uid match at all — `socket uid` is a parse error."""
        rule = pcap_input_rule(10003, 1500)
        self.assertIn(f"ct mark and {CT_MARK_MASK:#x} == {CT_MARK_TAG:#x}", rule)
        self.assertIn(f"ct mark and {CT_MARK_UID_MASK:#x} == 10003", rule)
        self.assertNotIn("skuid", rule)

    def test_the_mark_tag_agrees_with_the_always_on_skeleton(self):
        """The skeleton marks unconditionally, not only while capturing: a
        rule installed when a capture starts can only attribute connections
        opened afterwards, and the connection an operator is chasing is
        already established by the time they come looking."""
        skeleton = (ROOT / "nftables" / "workload-filter.nft").read_text()
        self.assertIn(f"ct mark set meta skuid or {CT_MARK_TAG:#x}", skeleton)

    def test_out_only_installs_no_input_chain(self):
        commands = pcap_rule_commands(10003, 1500, "out")
        self.assertEqual(len(commands), 2)  # chain, then rule
        self.assertNotIn(PCAP_INPUT_CHAIN, " ".join(
            part for command in commands for part in command))

    def test_out_creates_the_chain_before_the_rule(self):
        commands = pcap_rule_commands(10003, 1500, "out")
        self.assertIn("chain", commands[0])
        self.assertIn(PCAP_OUTPUT_CHAIN, commands[0])
        self.assertIn("rule", commands[1])

    def test_no_rule_is_ever_added_to_the_skeletons_own_chains(self):
        """The bug this exists to prevent, and it was silent in both halves.

        `nft add rule` APPENDS, and the skeleton's `output` chain ends with a
        terminating accept/drop for every filtered uid — so a log rule appended
        there is unreachable for exactly the workloads this feature exists to
        observe, and counts nothing while looking installed. The skeleton also
        carries `flush chain ... output` so it can be re-applied idempotently,
        which meant every VM start deleted an in-flight capture's rule.

        Both are avoided by the same thing: never write into a chain the
        skeleton owns.
        """
        skeleton = (ROOT / "nftables" / "workload-filter.nft").read_text()
        owned = {line.split()[-1] for line in skeleton.splitlines()
                 if line.startswith(("add chain ", "flush chain "))}
        self.assertTrue(owned, "parsed no chains out of the skeleton")
        for direction in ("in", "out", "inout"):
            for command in pcap_rule_commands(10003, 1500, direction):
                if "rule" not in command and "chain" not in command:
                    continue
                self.assertFalse(
                    owned & set(command),
                    f"pcap writes into a skeleton-owned chain "
                    f"({owned & set(command)}) for direction {direction!r}: "
                    f"{' '.join(command)}")

    def test_the_output_chain_runs_ahead_of_policy(self):
        """Capture before the verdict, so a DROPPED packet still appears —
        which is the question an egress-filtering feature gets asked."""
        chain_cmd = pcap_rule_commands(10003, 1500, "out")[0]
        spec = " ".join(chain_cmd)
        self.assertIn("hook output", spec)
        self.assertIn("filter - 10", spec)
        skeleton = (ROOT / "nftables" / "workload-filter.nft").read_text()
        policy = [line for line in skeleton.splitlines()
                  if line.startswith("add chain") and "hook output" in line][0]
        self.assertIn("priority 0", policy,
                      "the policy chain moved; re-check that filter-10 is "
                      "still ahead of it")

    def test_in_creates_the_chain_before_the_rule(self):
        commands = pcap_rule_commands(10003, 1500, "in")
        self.assertIn("chain", commands[0])
        self.assertIn("rule", commands[1])

    def test_rules_are_deleted_by_handle_never_by_text(self):
        """nft has no other way to delete a rule. A text-shaped delete fails
        SILENTLY under a tolerant runner, leaving a log rule in the
        security-critical table with nothing owning it — which is exactly what
        the first implementation did, and what the bench caught."""
        self.assertEqual(
            pcap_delete_command("output", 7)[-2:], ["handle", "7"])

    def test_handles_are_narrowed_to_one_nflog_group(self):
        """So one workload's teardown cannot take a concurrent capture's
        rule with it."""
        payload = {"nftables": [
            {"rule": {"handle": 4, "expr": [{"log": {"group": 3}}]}},
            {"rule": {"handle": 5, "expr": [{"log": {"group": 9}}]}},
            {"rule": {"handle": 6, "expr": [{"counter": {}}]}},
        ]}
        self.assertEqual(log_rule_handles(payload, 3), [4])
        self.assertEqual(sorted(log_rule_handles(payload)), [4, 5])

    def test_the_reader_is_pointed_at_this_workloads_group(self):
        argv = tcpdump_argv(10003, 1500)
        self.assertIn("nflog:3", argv)

    def test_the_reader_does_not_ask_tcpdump_for_pcapng(self):
        """tcpdump cannot write pcapng — `--pcap-ng` is not a tcpdump option
        at all (checked against 4.99.6). QEMU's filter-dump writes classic
        pcap too, so both vantages agree on the format."""
        self.assertNotIn("--pcap-ng", tcpdump_argv(10003, 1500))


class TestGuestVantageObject(unittest.TestCase):
    def test_maxlen_carries_the_snaplen(self):
        obj = filter_dump_object(0, "/tmp/g.pcapng", 1500)
        self.assertEqual(obj["maxlen"], 1500)
        self.assertEqual(obj["qom-type"], "filter-dump")

    def test_no_truncation_is_spelled_as_65536_not_zero(self):
        """QEMU rejects maxlen=0 outright (net/dump.c:199-203)."""
        obj = filter_dump_object(0, "/tmp/g.pcapng", 0)
        self.assertEqual(obj["maxlen"], QEMU_MAXLEN_UNLIMITED)

    def test_the_object_carries_no_filter_field(self):
        obj = filter_dump_object(0, "/tmp/g.pcapng", 1500)
        self.assertEqual(set(obj) - {"qom-type", "id", "netdev", "file",
                                     "maxlen"}, set())


class TestValidation(unittest.TestCase):
    def _errors(self, config, **kwargs):
        params = dict(vantages=[VANTAGE_HOST], direction=DIRECTION_DEFAULT,
                      bpf=None, write=None, detach=False, json_output=False,
                      rotation=False, tcpdump_present=True)
        params.update(kwargs)
        return validate_request(config, **params)

    def test_the_host_vantage_takes_no_bpf_filter(self):
        """MEASURED: libpcap cannot compile a filter for the nflog link type,
        and tcpdump refuses to start rather than silently ignoring it. §6.5's
        capability table says this vantage supports FILTER; it does not."""
        errors = self._errors(vm_config(), bpf=["port", "443"])
        self.assertTrue(any("NFLOG link-layer type filtering" in e
                            for e in errors))

    def test_a_filter_on_a_vm_is_rejected_for_both_vantages(self):
        errors = self._errors(vm_config(),
                              vantages=[VANTAGE_HOST, VANTAGE_GUEST],
                              bpf=["port", "443"])
        joined = " ".join(errors)
        self.assertIn("host", joined)
        self.assertIn("filter-dump", joined)

    def test_a_container_guest_vantage_still_takes_a_filter(self):
        """It is a real AF_PACKET capture in a namespace — lossy under load,
        but it takes a full expression."""
        self.assertEqual(
            self._errors(container_config(), vantages=[VANTAGE_GUEST],
                         bpf=["port", "443"]), [])

    def test_a_missing_tcpdump_is_reported_rather_than_hit_at_use(self):
        errors = self._errors(vm_config(), tcpdump_present=False)
        self.assertTrue(any("tcpdump is not installed" in e for e in errors))

    def test_direction_on_a_vm_guest_vantage_is_rejected(self):
        errors = self._errors(vm_config(), vantages=[VANTAGE_GUEST],
                              direction="in")
        self.assertTrue(any("always inout" in e for e in errors))

    def test_rotation_on_a_vm_guest_vantage_is_rejected(self):
        errors = self._errors(vm_config(), vantages=[VANTAGE_GUEST],
                              rotation=True)
        self.assertTrue(any("rotation" in e for e in errors))

    def test_json_and_stdout_capture_both_claim_stdout(self):
        errors = self._errors(vm_config(), json_output=True, write="-")
        self.assertTrue(any("both claim stdout" in e for e in errors))

    def test_json_without_a_file_would_discard_the_capture(self):
        """The packets ARE the output, so the capture would run and throw away
        everything it captured."""
        errors = self._errors(vm_config(), json_output=True)
        self.assertTrue(any("nothing to report" in e for e in errors))

    def test_detach_without_a_file_is_rejected(self):
        errors = self._errors(vm_config(), detach=True)
        self.assertTrue(any("discards everything" in e for e in errors))

    def test_detach_to_stdout_is_rejected(self):
        errors = self._errors(vm_config(), detach=True, write="-")
        self.assertTrue(any("meaningless" in e for e in errors))

    def test_an_unavailable_vantage_is_rejected_with_its_reason(self):
        errors = self._errors(vm_config(bridge="br0"), vantages=[VANTAGE_HOST])
        self.assertTrue(any("bridge" in e for e in errors))

    def test_two_vantages_need_a_directory(self):
        errors = self._errors(vm_config(),
                              vantages=[VANTAGE_HOST, VANTAGE_GUEST],
                              write="/tmp/one.pcapng")
        self.assertTrue(any("must be a directory" in e for e in errors))


class TestContainerTargeting(unittest.TestCase):
    """WORKLOAD/CONTAINER. Accepting the syntax and ignoring the container half
    captures a sibling's namespace with nothing said about it."""

    def _errors(self, config, **kwargs):
        params = dict(vantages=[VANTAGE_GUEST], direction=DIRECTION_DEFAULT,
                      bpf=None, write=None, detach=False, json_output=False,
                      rotation=False, tcpdump_present=True)
        params.update(kwargs)
        return validate_request(config, **params)

    def test_a_single_container_workload_needs_no_container_name(self):
        self.assertEqual(self._errors(container_config()), [])

    def test_pod_mode_needs_no_container_name(self):
        """Pod containers share ONE network namespace, so a guest-side capture
        is whole-workload and naming a member changes nothing."""
        config = container_config(containers=["web", "db"], topology="pod")
        self.assertEqual(self._errors(config), [])

    def test_bridge_mode_must_name_one(self):
        """Only bridge mode gives each container its own netns."""
        config = container_config(containers=["web", "db"], topology="bridge")
        errors = self._errors(config)
        self.assertTrue(any("name one as" in e for e in errors))

    def test_the_host_vantage_never_needs_a_container_name(self):
        """Every container of a workload runs as the same user, so `meta skuid`
        gathers all of them — the host vantage is whole-workload by
        construction, on every topology."""
        config = container_config(containers=["web", "db"], topology="bridge")
        self.assertEqual(self._errors(config, vantages=[VANTAGE_HOST]), [])

    def test_an_unknown_container_is_rejected(self):
        config = container_config(containers=["web", "db"])
        errors = self._errors(config, container="cache")
        self.assertTrue(any("is not a container in" in e for e in errors))

    def test_a_vm_has_no_containers(self):
        errors = self._errors(vm_config(), container="anything")
        self.assertTrue(any("has no containers" in e for e in errors))

    def test_the_plan_carries_the_podman_name_not_the_workload_name(self):
        """`workload-<name>` for a single-container workload and
        `workload-<name>-<container>` for a pod member — guessing the bare
        workload name finds nothing."""
        plan = build_plan(container_config(containers=["web", "db"]),
                          vantages=[VANTAGE_GUEST],
                          snaplen={VANTAGE_GUEST: 1500}, direction="inout",
                          write=None, duration=0, max_size=0, container="db")
        self.assertEqual(plan.podman_container, "workload-web-db")
        self.assertEqual(plan.to_json()["podman_container"], "workload-web-db")

    def test_a_vm_plan_carries_no_podman_name(self):
        plan = build_plan(vm_config(), vantages=[VANTAGE_GUEST],
                          snaplen={VANTAGE_GUEST: 1500}, direction="inout",
                          write=None, duration=0, max_size=0)
        self.assertIsNone(plan.podman_container)


class TestPlan(unittest.TestCase):
    """The plan is computed, never templated — real uid, real group, real
    netdev — so a vantage whose line cannot be computed is not captured."""

    def setUp(self):
        self.plan = build_plan(
            vm_config(), vantages=[VANTAGE_HOST, VANTAGE_GUEST],
            snaplen={VANTAGE_HOST: 1500, VANTAGE_GUEST: 1500},
            direction="inout", write="/var/tmp/fj", duration=300,
            max_size=100_000_000)

    def test_it_carries_the_real_uid_and_group(self):
        rendered = render_plan(self.plan)
        self.assertIn("uid 10003", rendered)
        self.assertIn("nflog:3", rendered)

    def test_it_shows_the_exact_rule_before_installing_it(self):
        """Which is what makes --dry-run an audit step rather than pedagogy."""
        rendered = render_plan(self.plan)
        self.assertIn("meta skuid 10003 log group 3", rendered)
        self.assertIn("continue", rendered)

    def test_it_names_the_unit_that_owns_teardown(self):
        rendered = render_plan(self.plan)
        self.assertIn(pcap_unit_name("fj"), rendered)
        self.assertIn("killed", rendered)

    def test_it_promises_only_what_it_installs(self):
        """A container's guest-side vantage is an nsenter'd tcpdump with no
        QEMU anywhere near it, and a guest-only capture installs no nftables
        rule — a plan that promises to remove either would be a worse promise
        than saying nothing."""
        container = build_plan(
            container_config(), vantages=[VANTAGE_GUEST],
            snaplen={VANTAGE_GUEST: 1500}, direction="inout", write=None,
            duration=0, max_size=0)
        rendered = render_plan(container)
        self.assertNotIn("QEMU object", rendered)
        self.assertNotIn("nftables rule", rendered)
        self.assertIn("the capture stops", rendered)

    def test_a_vm_guest_capture_still_promises_the_qemu_object(self):
        vm_guest = build_plan(
            vm_config(), vantages=[VANTAGE_GUEST],
            snaplen={VANTAGE_GUEST: 1500}, direction="inout", write=None,
            duration=0, max_size=0)
        rendered = render_plan(vm_guest)
        self.assertIn("the QEMU object is removed", rendered)
        self.assertNotIn("nftables rule", rendered)

    def test_a_host_only_capture_promises_only_the_rule(self):
        host_only = build_plan(
            vm_config(), vantages=[VANTAGE_HOST],
            snaplen={VANTAGE_HOST: 1500}, direction="inout", write=None,
            duration=0, max_size=0)
        self.assertIn("the nftables rule is removed", render_plan(host_only))

    def test_it_states_both_bounds_and_that_they_are_shared(self):
        rendered = render_plan(self.plan)
        self.assertIn("5m or 100M", rendered)
        self.assertIn("same window", rendered)

    def test_one_file_per_vantage_under_a_directory(self):
        rendered = render_plan(self.plan)
        self.assertIn("/var/tmp/fj/host.pcap", rendered)

    def test_a_single_vantage_writes_the_path_it_was_given(self):
        plan = build_plan(vm_config(), vantages=[VANTAGE_HOST],
                          snaplen={VANTAGE_HOST: 1500}, direction="inout",
                          write="/var/tmp/one.pcapng", duration=0, max_size=0)
        self.assertIn("/var/tmp/one.pcapng", render_plan(plan))

    def test_the_json_plan_and_the_prose_describe_one_thing(self):
        payload = self.plan.to_json()
        self.assertEqual(payload["uid"], 10003)
        self.assertEqual([s["vantage"] for s in payload["steps"]],
                         [VANTAGE_HOST, VANTAGE_GUEST])
        self.assertEqual(payload["unit"], pcap_unit_name("fj"))

    def test_the_plan_explains_what_a_1500_byte_snaplen_buys(self):
        self.assertIn("TLS SNI", render_plan(self.plan))


class TestOwnership(unittest.TestCase):
    """A try/finally handles Ctrl-C and nothing else — not a dropped session,
    not kill -9, not someone walking away."""

    def test_one_unit_per_workload(self):
        """Which is also what refuses a second concurrent capture: suffixing
        would let two captures double the rules and object ids."""
        self.assertEqual(pcap_unit_name("fj"), f"{PCAP_UNIT_PREFIX}fj.service")

    def test_the_duration_bound_is_the_units_runtime_max(self):
        argv = systemd_run_argv("fj", ["run", "fj", "{}"], duration=300)
        self.assertIn("--property=RuntimeMaxSec=300", argv)

    def test_a_disabled_duration_sets_no_runtime_max(self):
        argv = systemd_run_argv("fj", ["run", "fj", "{}"], duration=0)
        self.assertFalse(any("RuntimeMaxSec" in a for a in argv))

    def test_the_unit_is_collected_so_nothing_accumulates(self):
        argv = systemd_run_argv("fj", ["run", "fj", "{}"], duration=300)
        self.assertIn("--collect", argv)

    def test_teardown_is_an_execstoppost_not_only_a_finally(self):
        """A finally covers an ordinary exit and nothing else — not kill -9,
        not an OOM kill, not RuntimeMaxSec landing between two statements."""
        argv = systemd_run_argv("fj", ["run", "fj", "{}"], duration=300)
        self.assertTrue(any(a.startswith("--property=ExecStopPost=")
                            and a.endswith("cleanup fj") for a in argv))


class TestHelperContract(unittest.TestCase):
    """The helper, read as text — it needs root, nft and a live VM to run."""

    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "libexec" / "workload-pcap").read_text()

    def test_teardown_runs_in_a_finally(self):
        self.assertIn("finally:", self.source)

    def test_the_plan_is_read_not_recomputed(self):
        """If the helper re-derived it from the config the two could disagree,
        and the contract of --dry-run is that what was printed is what runs."""
        self.assertIn("json.loads(argv[3])", self.source)

    def test_the_probe_is_emitted_after_the_tap_not_before(self):
        """A probe emitted before the object exists is not in the file, and
        the correction would then be measured against whatever unrelated
        packet happened to be first."""
        body = self.source[self.source.index("def main("):]
        self.assertLess(body.index("guest_vm_up"), body.index("emit_probe"))

    def test_the_correction_needs_nothing_from_the_guest(self):
        """Deriving it from guest uptime would leave a full timezone offset in
        place, silently, on every non-UTC host."""
        probe = self.source[self.source.index("def emit_probe"):
                            self.source.index("def correct_timestamps")]
        self.assertNotIn("/proc/uptime", probe)
        # No command run inside the guest, and nothing read out of it: the
        # probe is a bare TCP connect from this side.
        self.assertNotIn("subprocess", probe)
        self.assertIn("socket.create_connection", probe)

    def test_sigterm_is_turned_into_an_unwind(self):
        """Python's default SIGTERM terminates outright without running finally
        blocks — so the ordinary `systemctl stop` path was the one path where a
        guest-side capture never got finalized."""
        self.assertIn("signal.signal(signal.SIGTERM", self.source)
        handler = self.source[self.source.index("def _exit_on_term"):
                              self.source.index("signal.signal(")]
        self.assertIn("SystemExit", handler)

    def test_the_guest_file_is_staged_where_a_confined_qemu_can_write(self):
        """QEMU runs as the workload user and as svirt_t, so an operator path
        fails on DAC before SELinux has an opinion — and fails silently:
        object-add is accepted and no file ever appears."""
        from pcap import guest_staging_path
        self.assertTrue(guest_staging_path("fj").startswith("/run/workload-vm/fj"))

    def test_the_staged_file_is_checked_rather_than_trusted(self):
        """Because the failure mode is a capture that reports success and
        produces nothing."""
        body = self.source[self.source.index("def guest_vm_up"):]
        self.assertIn("os.path.exists(staging)", body[:1600])

    def test_an_unfinalized_staged_file_is_reported_not_deleted(self):
        """The packets are real and the operator asked for them; only the
        timestamps are uncorrected."""
        body = self.source[self.source.index("def cleanup"):]
        self.assertNotIn("os.unlink(staging)", body[:1400])

    def test_both_capinfos_labels_are_accepted(self):
        """capinfos says "Earliest packet time" (wireshark 4.x) where older
        builds say "First packet time". Matching one is a silent no-op: the
        correction is skipped and the file keeps a timestamp hours in the
        future with nothing saying so."""
        self.assertIn("Earliest packet time", self.source)
        self.assertIn("First packet time", self.source)

    def test_a_failed_correction_is_reported_not_silent(self):
        body = self.source[self.source.index("def _first_packet_time"):]
        self.assertIn("WARNING", body[:900])

    def test_cleanup_is_idempotent_and_needs_no_plan(self):
        """It runs as ExecStopPost, including after a start that never got far
        enough to have a plan."""
        self.assertIn("def cleanup(name: str)", self.source)

    def test_the_capture_chains_are_removed_with_the_rules(self):
        """An empty chain in the security-critical table is one more thing for
        drift to have to explain."""
        self.assertIn("delete", self._host_down())
        self.assertIn("PCAP_CHAINS", self._host_down())

    def test_a_chain_is_only_deleted_once_it_holds_no_other_rule(self):
        """`nft delete chain` does NOT refuse a non-empty base chain — it
        succeeds and takes the rules with it. Verified on nftables 1.1.6.

        So the original "delete it and let it fail harmlessly if someone else
        still has a rule in there" was not harmless: one workload's capture
        ending silently ended every concurrent one. The re-list matters as much
        as the guard — checking the payload from before our own deletes would
        never find the chain empty.
        """
        down = self._host_down()
        delete_at = down.index('"delete", "chain"')
        guard = down[:delete_at]
        self.assertIn("if not still_there:", guard,
                      "the chain delete is not guarded on the chain being "
                      "empty of other captures' rules")
        self.assertEqual(
            2, guard.count("list\", \"chain"),
            "host_down must re-list after deleting its own rules; the earlier "
            "payload predates them and would always look non-empty")

    def _host_down(self) -> str:
        return self.source[self.source.index("def host_down"):
                           self.source.index("# --- guest vantage, VM ---")]

    def test_the_container_pid_goes_through_the_podman_wrapper(self):
        """Talking to a workload user's rootless podman needs
        XDG_RUNTIME_DIR, HOME and that user's session bus. A hand-rolled
        `runuser` supplies none of them and does not even leave a cwd the
        workload user can enter."""
        body = self.source[self.source.index("def container_netns_pid"):]
        # Assert on the code, not the docstring, which names runuser to say
        # why it is not used.
        code = body.split('"""')[2]
        self.assertIn("Podman.for_user", code)
        self.assertNotIn("runuser", code)

    def test_the_container_interface_is_discovered_not_assumed(self):
        """pasta names its tun after the host interface it templated from and
        podman may pass its own; measured, neither is tap0."""
        body = self.source[self.source.index("def container_interface"):]
        self.assertIn("route", body[:800])
        self.assertNotIn('"tap0"', body[:800])


class TestDetachVerifies(unittest.TestCase):
    """Detached, a refused object-add or a tcpdump that dies on startup happens
    after this command would have exited 0."""

    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "lib" / "cmd_pcap.py").read_text()

    def test_the_settle_check_dwells_rather_than_returning_on_first_active(self):
        """Type=exec marks a unit active the moment the exec succeeds, so a
        helper that dies a moment later is observably active first — and
        returning on that reading reports success for something already dead."""
        body = self.source[self.source.index("def _settled"):]
        self.assertNotIn('if state == "active":\n            return True', body)
        self.assertIn("deadline", body[:900])

    def test_a_second_capture_is_refused_before_the_plan_is_narrated(self):
        """Printing the plan first would describe something that is not going
        to happen."""
        # After the dry-run branch, which renders the plan legitimately.
        body = self.source[self.source.index("    require_root()\n\n"):]
        self.assertLess(body.index("already being captured"),
                        body.index("_say(args, render_plan(plan))"))

    def test_a_failed_unit_is_reported_not_swallowed(self):
        body = self.source[self.source.index("def _settled"):]
        self.assertIn('"failed"', body[:900])


class TestDiagnose(unittest.TestCase):
    def setUp(self):
        from cmd_diagnose import capture_check
        self.check = capture_check
        self.config = SimpleNamespace(name="fj", uid=10003, is_vm=True)

    def test_no_line_when_nothing_is_capturing(self):
        self.assertIsNone(self.check(self.config, unit_active=False,
                                     log_rules=0))

    def test_a_running_capture_is_a_pass_that_explains_the_rule(self):
        """A capture is a deliberate act, not a fault — but an operator who
        finds an unexplained rule in that table is right to be alarmed."""
        name, ok, msg = self.check(self.config, unit_active=True, log_rules=1)
        self.assertEqual(name, "capture")
        self.assertTrue(ok)
        self.assertIn("non-terminating", msg)
        self.assertIn("pcap --stop fj", msg)

    def test_orphaned_rules_with_no_unit_are_flagged(self):
        _, ok, msg = self.check(self.config, unit_active=False, log_rules=2)
        self.assertFalse(ok)
        self.assertIn("nothing owns them", msg)


if __name__ == "__main__":
    unittest.main()
