"""
test_runtime_vm_egress_isolation.py — the two-VM proof ADR 006 rests on.

The claim under test is §8's first security property: *per-VM egress policy
keyed on something the guest cannot forge*. Concretely, "one `meta skuid` rule
blocks this workload and not its sibling."

**This needs two VMs, and that is why it is here rather than in the unit
suite.** A single filtered VM that cannot reach a destination proves only that
something, somewhere, is broken — a missing route, a dead resolver, a host with
no egress at all. The property is only visible in the *difference*: a sibling
reaching the same destination, on the same host, at the same instant, through
the same passt netdev, differing only in which uid the rule matches. Everything
else about the two workloads is identical by construction (the two TOMLs differ
in exactly two lines), so the difference has one available explanation.

The unit suite already proves the rules are *constructed* correctly — the set
types, the element expressions, that v4 and v6 never cross-fire. What it cannot
reach is whether the kernel, given those elements, actually separates two live
workloads. That gap was carried as explicit testing debt from step 2 of the
implementation sequence, which said to budget it rather than discover it later.

Shape and gates match test_runtime_vm_restart.py: nested inside the harness
guest, skipped without /dev/kvm or the VM toolchain.
"""

import json
import time

import pytest

from fixtures import (
    dump_journal, poll_vm_reachable, skip_if_no_kvm, skip_if_no_vm_toolchain,
    _enable_workload, _install_toml, _purge_workload,
)

pytestmark = [pytest.mark.runtime, pytest.mark.slow]

FILTERED = "rt-vm-egress-filtered"
OPEN = "rt-vm-egress-open"

# Two destinations that answer TCP and need no DNS to reach. ALLOWED is the one
# entry in the filtered workload's `allow` list; BLOCKED is deliberately absent
# from it. Both are probed from both guests.
ALLOWED = ("1.1.1.1", 53)
BLOCKED = ("9.9.9.9", 53)

# Long enough that a real connection completes, short enough that a drop does
# not stall the test. A dropped SYN produces a timeout, not a refusal, so this
# is the actual cost of every negative probe.
PROBE_TIMEOUT = 6


def _probe(target, workload: str, dest: tuple[str, int]) -> bool:
    """Can this guest open a TCP connection to `dest`?

    bash's /dev/tcp rather than nc or curl: it needs no package in the guest
    image, resolves nothing, and distinguishes "connected" from "did not"
    without interpreting a protocol. `timeout` bounds the dropped case, which
    hangs rather than failing fast.
    """
    host, port = dest
    result = target.wl_exec(
        workload,
        ["bash", "-c",
         f"timeout {PROBE_TIMEOUT} bash -c "
         f"'echo > /dev/tcp/{host}/{port}' && echo REACHED || echo BLOCKED"],
        sudo=True, check=False, timeout=PROBE_TIMEOUT + 30,
    )
    return result.rc == 0 and "REACHED" in result.stdout


def _uid(target, workload: str) -> int:
    result = target.run(f"id -u _wl-{workload}", sudo=True, check=True)
    return int(result.stdout.strip())


def _filtered_uids(target) -> set[int]:
    """The uids currently in `wl_filtered`, read from the live ruleset.

    Parsed, not grepped: a regex over the JSON would also match handles, table
    ids and ports, and the whole value of this helper is that an empty result
    means "nothing is armed" rather than "the pattern missed".
    """
    result = target.run(
        "nft -j list set inet workload_filter wl_filtered",
        sudo=True, check=False, timeout=30)
    if result.rc != 0:
        return set()
    try:
        payload = json.loads(result.stdout)
    except ValueError:
        return set()
    uids: set[int] = set()
    for item in payload.get("nftables", []):
        if "set" not in item:
            continue
        for elem in item["set"].get("elem", []) or []:
            # nft renders a counted element as {"elem": {"val": …}} and a bare
            # one as the value itself.
            if isinstance(elem, dict) and "elem" in elem:
                elem = elem["elem"].get("val", elem)
            try:
                uids.add(int(elem))
            except (TypeError, ValueError):
                continue
    return uids


def test_one_skuid_rule_blocks_one_vm_and_not_its_sibling(target):
    skip_if_no_kvm(target)
    skip_if_no_vm_toolchain(target)

    for name in (FILTERED, OPEN):
        _install_toml(target, f"{name}.toml")

    try:
        for name in (FILTERED, OPEN):
            try:
                _enable_workload(target, name, timeout=900,
                                 expect_container=False)
            except Exception:
                dump_journal(target, name)
                raise

        for name in (FILTERED, OPEN):
            reachable = poll_vm_reachable(target, name, token=f"{name}-up",
                                          timeout=420)
            if not (reachable and reachable.rc == 0):
                dump_journal(target, name)
            assert reachable is not None and reachable.rc == 0, (
                f"{name} never became reachable, so nothing below would mean "
                f"anything (last rc="
                f"{None if reachable is None else reachable.rc})")

        # Deploy-time guard, before any probe: confirm the postures the test
        # assumes are the postures actually in force. If the filtered uid never
        # made it into wl_filtered, every probe below would pass for the wrong
        # reason and the test would report a green that means nothing.
        filtered_uid = _uid(target, FILTERED)
        open_uid = _uid(target, OPEN)
        armed = _filtered_uids(target)
        assert filtered_uid in armed, (
            f"{FILTERED} (uid {filtered_uid}) is not in wl_filtered, so it is "
            f"running unfiltered while its config says otherwise. Armed: "
            f"{sorted(armed)}")
        assert open_uid not in armed, (
            f"{OPEN} (uid {open_uid}) is in wl_filtered but its config says "
            f"egress = 'open' — a stale element from an earlier config would "
            f"make the comparison below meaningless. Armed: {sorted(armed)}")

        # Precondition, not an assertion about our code: if the host itself
        # cannot reach the blocked destination, the filtered VM's failure to
        # reach it says nothing. Skip rather than pass.
        host_probe = target.run(
            f"timeout {PROBE_TIMEOUT} bash -c "
            f"'echo > /dev/tcp/{BLOCKED[0]}/{BLOCKED[1]}'",
            sudo=True, check=False, timeout=PROBE_TIMEOUT + 10)
        if host_probe.rc != 0:
            pytest.skip(
                f"the harness host cannot reach {BLOCKED[0]}:{BLOCKED[1]} "
                f"itself, so a guest failing to reach it would prove nothing")

        # THE PROPERTY. Both probes run against the same destination, minutes
        # apart at most, from two guests that differ only in posture.
        open_reaches_blocked = _probe(target, OPEN, BLOCKED)
        filtered_reaches_blocked = _probe(target, FILTERED, BLOCKED)

        assert open_reaches_blocked, (
            f"the CONTROL VM could not reach {BLOCKED[0]}:{BLOCKED[1]}. Its "
            f"uid ({open_uid}) is not in wl_filtered, so nothing of ours "
            f"should be stopping it — this is an egress problem in the "
            f"harness, not evidence about the filter")
        assert not filtered_reaches_blocked, (
            f"the FILTERED VM reached {BLOCKED[0]}:{BLOCKED[1]}, which is not "
            f"in its allow list. uid {filtered_uid} is in wl_filtered, so the "
            f"drop rule either did not match or was not reached")

        # And the filtered VM is filtered, not merely broken: the one entry in
        # its allow list still works. Without this the assertion above is
        # satisfied by a VM with no network at all.
        assert _probe(target, FILTERED, ALLOWED), (
            f"the FILTERED VM could not reach {ALLOWED[0]}:{ALLOWED[1]}, which "
            f"IS in its allow list — so it is not filtered, it is cut off, and "
            f"the negative result above proves nothing")

    finally:
        for name in (FILTERED, OPEN):
            _purge_workload(target, name)


def test_purging_one_vm_leaves_its_siblings_filter_armed(target):
    """The teardown half of the same property.

    A workload's elements are swept on purge, and the sweep is keyed on its own
    uid. Getting that wrong in the disarming direction is silent in exactly the
    way this design exists to prevent: the surviving VM keeps running, keeps
    passing every health check, and is no longer filtered.

    Same two workloads, opposite roles — here the *filtered* one survives.
    """
    skip_if_no_kvm(target)
    skip_if_no_vm_toolchain(target)

    for name in (FILTERED, OPEN):
        _install_toml(target, f"{name}.toml")

    try:
        for name in (FILTERED, OPEN):
            try:
                _enable_workload(target, name, timeout=900,
                                 expect_container=False)
            except Exception:
                dump_journal(target, name)
                raise

        filtered_uid = _uid(target, FILTERED)
        assert filtered_uid in _filtered_uids(target), (
            f"{FILTERED} was not armed to begin with, so this test cannot say "
            f"anything about what a sibling's purge does to it")

        _purge_workload(target, OPEN)
        # Give the stop path time to run ExecStopPost and the purge sweep.
        time.sleep(5)

        assert filtered_uid in _filtered_uids(target), (
            f"purging {OPEN} disarmed {FILTERED} (uid {filtered_uid}) — the "
            f"surviving VM is now running unfiltered while its config says "
            f"otherwise, and nothing about it looks wrong")

        # It is armed in the ruleset; confirm it is armed in effect too.
        reachable = poll_vm_reachable(target, FILTERED,
                                      token=f"{FILTERED}-alive", timeout=300)
        assert reachable is not None and reachable.rc == 0, (
            f"{FILTERED} became unreachable when its sibling was purged")
        assert not _probe(target, FILTERED, BLOCKED), (
            f"after {OPEN} was purged, {FILTERED} could reach "
            f"{BLOCKED[0]}:{BLOCKED[1]} — its drop is no longer in force")

    finally:
        for name in (FILTERED, OPEN):
            _purge_workload(target, name)
