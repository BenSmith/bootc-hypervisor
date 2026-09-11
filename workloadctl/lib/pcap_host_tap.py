"""The host vantage of a capture: the nft log rules, and what they matched.

The rules go into inet workload_filter's pcap chains and are read back with
`tcpdump -i nflog:<group>`. Every helper here works from the plan JSON the
CLI rendered; nothing is recomputed from the workload's config.
"""
import os
import subprocess

from helper_main import log, run
from nft import nft_chain
from nft_constants import NFT_BIN, NFT_SKELETON, NFT_TABLE
from pcap import (
    PCAP_CHAINS, VANTAGE_HOST, PcapFormatError, log_rule_handles, log_rule_packets,
    pcap_delete_command, pcap_packet_count, pcap_rule_commands, tcpdump_argv,
    vantage_path,
)
from workload_addr import nflog_group


def host_up(plan: dict) -> None:
    """Install the log rules. The skeleton first: it carries the `ct mark set`
    rule inbound attribution depends on, and a host that has never started a
    filtered VM has no table at all.

    Applying the skeleton flushes its `output` chain. That is safe here only
    because our rules live in chains of our own (PCAP_CHAINS) which the
    skeleton neither declares nor flushes — when the log rule was appended to
    `output`, this very line deleted the rule of any capture already running,
    as did every VM start.
    """
    run([NFT_BIN, "-f", NFT_SKELETON], check=True)
    for command in pcap_rule_commands(plan["uid"],
                                      plan["snaplen"][VANTAGE_HOST],
                                      plan["direction"]):
        run(command, check=True)
    log(f"  Logging uid {plan['uid']} to nflog group "
        f"{nflog_group(plan['uid'])} ({plan['direction']})")


def matched_packets(uid: int) -> int | None:
    """What the KERNEL handed to nflog for this workload, from the rule counter.

    Must be read before host_down deletes the rules. Returns None when no log
    rule is present, which is not zero: "nothing was captured" and "there was
    nothing to capture with" are different answers and only one of them is a
    bug.
    """
    group = nflog_group(uid)
    total = 0
    found = False
    for chain in PCAP_CHAINS:
        payload = nft_chain(chain)
        if payload is None:
            continue
        if log_rule_handles(payload, group):
            found = True
            total += log_rule_packets(payload, group)
    return total if found else None


def report_completeness(plan: dict) -> None:
    """Say whether the host-side file actually holds what the kernel matched.

    nflog drops under load and does not report it — tcpdump's own "dropped by
    kernel" admitted 7 against an actual shortfall of 530 in the run that
    motivated this, because the loss happens upstream of libpcap. So the only
    trustworthy completeness signal is the rule counter, and the only place it
    can be read is here, before teardown removes the rule.

    Silent on the happy path. An operator who did not lose packets does not
    need to be told about a failure mode they did not hit.
    """
    matched = matched_packets(plan["uid"])
    if matched is None:
        return
    path = vantage_path(plan["write"], VANTAGE_HOST, len(plan["vantages"]))
    if not path or path == "-" or not os.path.exists(path):
        log(f"  Host vantage: {matched} packets matched")
        return
    captured = _packet_count(path)
    if captured is None or captured >= matched:
        in_file = "unknown" if captured is None else str(captured)
        log(f"  Host vantage: {matched} packets matched, {in_file} in the file")
        return
    lost = matched - captured
    log(f"  WARNING: the host-side capture is INCOMPLETE — the kernel matched "
        f"{matched} packets and only {captured} reached {path} ({lost} lost, "
        f"{lost * 100.0 / matched:.2f}%). nflog copies packets over a netlink "
        f"buffer that overflows under load; the packets were sent, this file "
        f"just does not have all of them. Do not read a gap here as the "
        f"workload not having sent something. The guest vantage (-i guest) "
        f"taps QEMU's datapath and has no such failure mode.")


def _packet_count(path: str) -> int | None:
    """Packets actually in a pcap file. None when it cannot be read at all.

    Read directly rather than through capinfos, which is absent on a default
    install — see the format notes in lib/pcap.py.
    """
    try:
        return pcap_packet_count(path)
    except (OSError, PcapFormatError) as e:
        log(f"  WARNING: could not count packets in {path}: {e}")
        return None


def host_down(uid: int) -> None:
    """Remove this capture's log rules, by handle.

    BY HANDLE, because nft has no other way to delete a rule: a delete spelled
    with the rule's own text fails, and fails *silently* under a tolerant
    runner — which leaves a log rule in the security-critical table with
    nothing owning it. Found on the bench, where the first implementation's
    teardown removed nothing at all.

    Narrowed to this workload's nflog group so a concurrent capture on another
    workload keeps its rule.

    Tolerant throughout: a rule is legitimately absent when the start failed
    partway, or after the break-glass `nft delete table`.
    """
    group = nflog_group(uid)
    removed = 0
    for chain in PCAP_CHAINS:
        payload = nft_chain(chain)
        if payload is None:
            continue
        # Highest handle first: deleting does not renumber, but reverse order
        # keeps the intent obvious if that ever changes.
        for handle in sorted(log_rule_handles(payload, group), reverse=True):
            if run(pcap_delete_command(chain, handle)).returncode == 0:
                removed += 1
        # Take the chain with us, but ONLY once it holds no other capture's
        # rule. `nft delete chain` does NOT refuse a non-empty base chain — it
        # succeeds and takes the rules with it — so "delete and let it fail
        # harmlessly" is not a thing that happens: it silently ended every
        # concurrent capture. Re-list rather than reusing `payload`, which is
        # from before our own deletes.
        remaining = nft_chain(chain)
        if remaining is None:
            continue
        if not log_rule_handles(remaining):
            run([NFT_BIN, "delete", "chain", *NFT_TABLE.split(), chain])
    if removed:
        log(f"  Removed {removed} log rule(s) for nflog group {group}")


def host_reader(plan: dict) -> subprocess.Popen:
    argv = tcpdump_argv(
        plan["uid"], plan["snaplen"][VANTAGE_HOST],
        write=vantage_path(plan["write"], VANTAGE_HOST, len(plan["vantages"])),
        packet_count=plan.get("packet_count"),
        rotate_size=plan.get("rotate_size"),
        file_count=plan.get("file_count"),
        rotate_seconds=plan.get("rotate_seconds"),
        numeric=plan.get("numeric", False),
        bpf=plan.get("bpf"),
        buffer_kib=plan.get("buffer_kib"))
    log(f"  {' '.join(argv)}")
    return subprocess.Popen(argv)
