"""
Packet capture: vantages, plans, and the argv/rules each backend needs.

Everything here is a pure function of a workload's config — no subprocesses, no
root, no nftables — so the plan `pcap --dry-run` prints is the same object the
helper executes. That equivalence is the point (ADR 006 §6.6): whatever one
does, the other must describe, or the plan stops being a promise.

The verb is `pcap` rather than `trace` because `trace` means event tracing
everywhere nearby (ftrace, strace, distributed tracing), and `dump` in the virt
world means a *memory* dump. Someone who wants a packet capture looks for pcap.

Installed to /usr/libexec/workloadctl/pcap.py.
"""

import re
import shutil
from dataclasses import dataclass, field

from vm import NFT_BIN, NFT_TABLE, vm_nflog_group
from workload_lib import UID_MIN


# --- what a vantage is ---
#
# A vantage is an interface, which needs no new concept: tcpdump users already
# accept pseudo-devices (`any`, `lo`, `nflog:3`). Under passt the guest's view
# and the wire view genuinely differ, so both are offered.
#
#   host   the real host socket, after passt/pasta re-originated the traffic
#   guest  the workload's own framing, before translation
#
# The host-side one is the only mechanism that can produce a per-workload
# capture at all: by the time a packet is on the wire the owning socket is not
# part of it, so only netfilter sees `meta skuid`.

VANTAGE_HOST = "host"
VANTAGE_GUEST = "guest"
VANTAGES = (VANTAGE_HOST, VANTAGE_GUEST)

DIRECTIONS = ("in", "out", "inout")
DIRECTION_DEFAULT = "inout"

# Diverges from every piece of prior art, all of which defaults to capturing
# whole packets: tcpdump 262144, Retina's --packet-size 0, AWS traffic mirroring
# whole frames. None of them face passt's 65520-byte MTU. Measured at 10.9 KB
# per packet, an untruncated capture hits a 100 MB cap in ~9,000 packets — i.e.
# seconds. 1500 keeps the first segment of each connection, where the TLS SNI
# and the HTTP request line live, which is the question an egress-filtering
# feature exists to ask.
SNAPLEN_DEFAULT = 1500

DURATION_DEFAULT = "5m"
MAX_SIZE_DEFAULT = "100M"

# QEMU rejects maxlen=0 outright (net/dump.c:199-203), so "no truncation" has to
# be spelled as its default. maxlen counts the Ethernet frame with the vnet
# header already excluded (net/dump.c:158).
QEMU_MAXLEN_UNLIMITED = 65536


# The host vantage can silently under-report, and this is why every host-side
# rule carries a `counter`.
#
# nflog copies each matched packet to userspace over a netlink socket whose
# receive buffer can overflow. The network is unaffected — the *capture* loses
# packets. QEMU's filter-dump sits in the datapath and has no such failure mode,
# which is a second reason to keep both vantages.
#
# Measured on nftables 1.1.6 / tcpdump 4.99.6, 200k UDP packets at ~1400 bytes:
# the rule counter recorded all 200,000 while tcpdump received 199,470 /
# 199,830 / 199,872 across three runs. Reproducible, and at a rate a VM pulling
# a large file will reach.
#
# The dangerous part is not the loss, it is that nothing reports it.
# tcpdump's own "dropped by kernel" admitted 7, 0 and 2 against actual
# shortfalls of 530, 170 and 128 — the drop happens upstream of libpcap, so
# libpcap's accounting is self-consistent and wrong ("199470 captured, 199470
# received by filter"). /proc/net/netfilter/nfnetlink_log does not exist on
# current kernels either. A capture that silently under-reports is worse than
# no capture when the question is "did this workload reach X", because absence
# of evidence reads as evidence of absence.
#
# So the rule counts what the kernel matched, and teardown compares that against
# the packets actually in the file. That comparison is the only signal there is.
LOSS_NOTE = ("nflog can drop under load and does not report it; the rule "
             "counter is compared against the file on stop")


@dataclass
class Vantage:
    """One capture point, available or not, with the reason if not."""
    name: str
    available: bool
    detail: str
    # What this vantage can honor. A VM's guest side is a dumb backend and `-D`
    # says so before a user hits it, rather than four special cases at the
    # point of failure.
    supports_filter: bool = True
    supports_direction: bool = True
    supports_rotation: bool = True


def pcap_vantages(config) -> list[Vantage]:
    """Both vantages for one workload, each marked available or not.

    The container rows were measured on podman 5.8.4 rather than inferred: a
    host-network container's netns inode is *identical* to the host's, so there
    is genuinely nothing to enter, and `mode = "none"` does get its own netns
    but with only a loopback in it.
    """
    if config.is_vm:
        bridged = config.vm_bridge is not None
        return [
            Vantage(
                VANTAGE_HOST, not bridged,
                ("the traffic as it leaves this machine, after passt "
                 "re-originated it onto host sockets owned by this "
                 "workload. " + LOSS_NOTE)
                if not bridged else
                f"unavailable: [vm.network].bridge = {config.vm_bridge!r}, so "
                f"the guest sends from its own LAN address and no host socket "
                f"carries its uid",
                supports_filter=False,
            ),
            Vantage(
                VANTAGE_GUEST, True,
                "what the VM itself put on the wire, before passt translated it",
                # filter-dump accepts only `file` and `maxlen` — no BPF, no
                # direction (it taps the netdev, so always inout), no rotation.
                # This is a capability difference, not merely a difference of
                # vantage, and it is a second reason to keep both.
                supports_filter=False,
                supports_direction=False,
                supports_rotation=False,
            ),
        ]

    mode = config.get_network_mode()
    if mode == "host":
        return [
            Vantage(VANTAGE_HOST, True,
                    "the traffic as it leaves this machine. For a host-network "
                    "container the workload uid is the ONLY thing separating "
                    "its traffic from the host's own. " + LOSS_NOTE,
                    supports_filter=False),
            Vantage(VANTAGE_GUEST, False,
                    "unavailable: [network] mode = \"host\" shares the host's "
                    "network namespace, so there is nothing separate to tap"),
        ]
    if mode == "none":
        return [
            Vantage(VANTAGE_HOST, False,
                    "unavailable: [network] mode = \"none\" — the workload "
                    "originates no host sockets"),
            Vantage(VANTAGE_GUEST, False,
                    "unavailable: [network] mode = \"none\" — the namespace "
                    "exists but holds only a loopback"),
        ]
    return [
        Vantage(VANTAGE_HOST, True,
                "the traffic as it leaves this machine, after pasta "
                "re-originated it onto host sockets owned by this workload. "
                + LOSS_NOTE,
                supports_filter=False),
        Vantage(VANTAGE_GUEST, True,
                "what the workload put on the wire inside its own network "
                "namespace, before pasta translated it — DHCP, ARP/NDP, and "
                "the DNS pasta answers itself never appear host-side"),
    ]


def available_vantages(config) -> list[str]:
    return [v.name for v in pcap_vantages(config) if v.available]


# --- bounds and sizes ---

_DURATION_RE = re.compile(r"^(\d+)([smh]?)$")
_SIZE_RE = re.compile(r"^(\d+)([KMG]?)B?$", re.IGNORECASE)
_DURATION_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600}
_SIZE_UNITS = {"": 1, "k": 1000, "m": 1000 ** 2, "g": 1000 ** 3}


def parse_duration(text: str) -> int:
    """"30s" / "5m" / "1h" -> seconds. 0 disables the bound."""
    match = _DURATION_RE.match(str(text).strip())
    if not match:
        raise ValueError(
            f"{text!r} is not a duration — use 30s, 5m, 1h, or 0 to disable")
    return int(match.group(1)) * _DURATION_UNITS[match.group(2)]


def parse_size(text: str) -> int:
    """"100M" / "2G" -> bytes. Decimal units, as tcpdump's -C uses."""
    match = _SIZE_RE.match(str(text).strip())
    if not match:
        raise ValueError(f"{text!r} is not a size — use 100M, 2G, 500K")
    return int(match.group(1)) * _SIZE_UNITS[match.group(2).lower()]


def parse_snaplen(spec, vantages: list[str]) -> dict[str, int]:
    """`-s` as a scalar (128) or per-vantage (guest:1500,host:0).

    The only per-vantage knob there is. Per-vantage applies to what a backend
    does to each packet, and the correct snaplen genuinely differs by side —
    at a 65520-byte guest MTU a 1500-byte snaplen discards ~98% of the bytes,
    while host-side the same number discards almost none. Every *bound* stays
    global, because the first one to trip stops all vantages so the files cover
    the same window.
    """
    out = {name: SNAPLEN_DEFAULT for name in vantages}
    if spec is None:
        return out
    text = str(spec).strip()
    if ":" not in text:
        try:
            value = int(text)
        except ValueError:
            raise ValueError(
                f"-s {spec!r} is neither a number nor "
                f"vantage:number pairs") from None
        return {name: value for name in vantages}
    for part in text.split(","):
        vantage, _, raw = part.partition(":")
        vantage = vantage.strip()
        if vantage not in VANTAGES:
            raise ValueError(
                f"-s {spec!r}: {vantage!r} is not a vantage "
                f"({', '.join(VANTAGES)})")
        try:
            out[vantage] = int(raw)
        except ValueError:
            raise ValueError(f"-s {spec!r}: {raw!r} is not a number") from None
    return out


# --- the host-side vantage: nflog ---
#
# `log group` takes a LITERAL, never an expression. `log group ct mark`,
# `log group ct mark and 0x3fffffff` and `log group @nh,0,16` are all parse
# errors, so the group is computed here and emitted as a constant — which
# forces one rule per workload being captured rather than one generic rule
# serving all of them. Unlike the policy chain, where units only ever add set
# elements, capture adds and removes *rules*.

# Tag the conntrack mark rather than storing a bare uid, so a site's own marks
# stay distinguishable from ours. Must agree with the skeleton's `ct mark set`.
CT_MARK_TAG = 0x40000000
CT_MARK_MASK = 0xC0000000
CT_MARK_UID_MASK = 0x3FFFFFFF

# BOTH directions get their own chain, created on demand. The outbound one is
# not merely tidiness — it is the difference between working and not:
#
#   - `nft add rule` APPENDS, and the skeleton's `output` chain ends with a
#     terminating `accept`/`drop` for every filtered uid. A log rule appended
#     there is unreachable for exactly the workloads this feature exists to
#     observe. Verified on nftables 1.1.6: the rule lands at the bottom, below
#     `meta skuid @wl_filtered counter drop`, and never counts a packet.
#   - the skeleton carries `flush chain ... output` so it can be re-applied
#     idempotently, so every VM start — and every other workload's capture —
#     silently deleted an in-flight capture's rule. Set elements survive a
#     flush; appended rules do not.
#
# Priority filter-10 puts capture AHEAD of policy, which also means a packet is
# captured before the drop decides its fate. That is the more useful vantage
# anyway: "what did this workload try to reach" is the question an
# egress-filtering feature gets asked. It is after nat's dstnat (-100), so a
# packet through the hostname proxy is captured with its translated
# destination — the same view the policy chain has.
PCAP_OUTPUT_CHAIN = "pcap_output"
PCAP_INPUT_CHAIN = "pcap_input"
PCAP_CHAINS = (PCAP_OUTPUT_CHAIN, PCAP_INPUT_CHAIN)


def nflog_group(uid: int) -> int:
    return vm_nflog_group(uid)


def log_rule_packets(payload, group: int | None = None) -> int:
    """Packets matched by the host-side log rules, from `nft -j list chain`.

    Ground truth for completeness: this is what the kernel handed to nflog,
    whatever userspace then managed to receive. `counter` and `log` are sibling
    expressions in one rule, so the group narrowing and the count come from the
    same object and cannot be mismatched.
    """
    total = 0
    for item in (payload or {}).get("nftables", []):
        rule = item.get("rule")
        if not rule:
            continue
        exprs = [e for e in rule.get("expr", []) if isinstance(e, dict)]
        logs = [e["log"] for e in exprs if "log" in e]
        if not logs:
            continue
        if group is not None and logs[0].get("group") != group:
            continue
        for expr in exprs:
            if "counter" in expr:
                total += expr["counter"].get("packets", 0)
    return total


def pcap_output_rule(uid: int, snaplen: int) -> str:
    """The outbound `log` rule, as nft would print it.

    Non-terminating and set-free: it cannot change accept/drop semantics, which
    is exactly what `--dry-run` exists to let an operator confirm before this
    goes into the security-critical table. `counter` is non-terminating too —
    see LOSS_NOTE for why it is the only way to know this capture is complete.
    """
    return (f"meta skuid {uid} counter log group {nflog_group(uid)} "
            f"snaplen {snaplen} continue")


def pcap_input_rule(uid: int, snaplen: int) -> str:
    """The inbound rule, selected by conntrack mark.

    A rule in the output hook never sees inbound packets, and `meta skuid`
    cannot help there — nftables has no input-side uid match at all (`socket
    uid` is a parse error). So attribution travels with the connection, set by
    the always-on `ct mark set` rule in the skeleton.

    That rule is guarded on the workload uid range, not on `@wl_filtered`: the
    mark is attribution, not policy, so an unfiltered VM and a container carry
    it too. Guarding it on set membership made this rule match nothing at all
    for every workload that is not filtered.

    Note the first inbound packet of an *unsolicited* connection — a published
    port nobody has replied on yet — arrives before any outbound packet has
    marked the conntrack entry, so it is missed. Everything from the reply
    onward is attributed.
    """
    return (f"ct mark and {CT_MARK_MASK:#x} == {CT_MARK_TAG:#x} "
            f"ct mark and {CT_MARK_UID_MASK:#x} == {uid} "
            f"counter log group {nflog_group(uid)} snaplen {snaplen} continue")


def pcap_rule_commands(uid: int, snaplen: int, direction: str) -> list[list[str]]:
    """`nft add rule` for the host vantage, in install order.

    Add only. There is deliberately no matching `delete rule` form, because
    **nft cannot delete a rule by its text** — deletion is by handle, and a
    text-shaped delete fails silently, leaving a log rule in the
    security-critical table with nothing owning it. Removal goes through
    pcap_delete_command(), which reads the live handles.

    Both chains are created on demand rather than living in the always-on
    skeleton: they exist only while something is capturing, an empty chain in
    that table is one more thing for `drift` to have to explain — and, the
    reason that matters rather than merely reads well, a chain the skeleton
    does not own is a chain the skeleton's `flush` cannot take out from under
    a running capture. `add chain` is create-if-absent, so a second workload
    starting a capture joins the existing chain instead of disturbing it.

    Nothing here appends to the skeleton's own `output` chain. See the
    PCAP_OUTPUT_CHAIN comment for why that was not a survivable place to put a
    rule.
    """
    table = NFT_TABLE.split()
    commands: list[list[str]] = []
    if direction in ("out", "inout"):
        commands.append([NFT_BIN, "add", "chain", *table, PCAP_OUTPUT_CHAIN,
                         "{ type filter hook output priority filter - 10; "
                         "policy accept; }"])
        commands.append([NFT_BIN, "add", "rule", *table, PCAP_OUTPUT_CHAIN,
                         *pcap_output_rule(uid, snaplen).split()])
    if direction in ("in", "inout"):
        commands.append([NFT_BIN, "add", "chain", *table, PCAP_INPUT_CHAIN,
                         "{ type filter hook input priority 0; "
                         "policy accept; }"])
        commands.append([NFT_BIN, "add", "rule", *table, PCAP_INPUT_CHAIN,
                         *pcap_input_rule(uid, snaplen).split()])
    return commands


def log_rule_handles(payload, group: int | None = None) -> list[int]:
    """Handles of `log` rules in one `nft -j -a list chain` document.

    Narrowed to one nflog group when given, so one workload's capture teardown
    cannot take a concurrent capture's rule with it.
    """
    handles: list[int] = []
    for item in (payload or {}).get("nftables", []):
        rule = item.get("rule")
        if not rule or "handle" not in rule:
            continue
        for expr in rule.get("expr", []):
            log = expr.get("log") if isinstance(expr, dict) else None
            if log is None:
                continue
            if group is None or log.get("group") == group:
                handles.append(rule["handle"])
            break
    return handles


def pcap_delete_command(chain: str, handle: int) -> list[str]:
    """Delete one rule by handle — the only form nft accepts."""
    return [NFT_BIN, "delete", "rule", *NFT_TABLE.split(), chain,
            "handle", str(handle)]


def tcpdump_argv(uid: int, snaplen: int, *, write: str | None = None,
                 packet_count: int | None = None, rotate_size: int | None = None,
                 file_count: int | None = None, rotate_seconds: int | None = None,
                 numeric: bool = False, bpf: list[str] | None = None,
                 tcpdump: str = "/usr/bin/tcpdump") -> list[str]:
    """The reader for the host vantage."""
    argv = [tcpdump, "-i", f"nflog:{nflog_group(uid)}", "-s", str(snaplen)]
    # Classic pcap, not pcapng. The design wanted pcapng so per-container
    # annotation stayed possible later, but tcpdump cannot write it —
    # `--pcap-ng` is not a tcpdump option at all (checked against 4.99.6; it
    # belongs to dumpcap/tshark). QEMU's filter-dump also writes classic pcap,
    # so both vantages agree on the format, which is what actually matters for
    # comparing two files. -U flushes per packet so a following reader sees
    # traffic as it happens rather than a block at a time.
    argv += ["-U"]
    if numeric:
        argv.append("-n")
    if write:
        argv += ["-w", write]
    if packet_count:
        argv += ["-c", str(packet_count)]
    if rotate_size:
        argv += ["-C", str(rotate_size)]
    if file_count:
        argv += ["-W", str(file_count)]
    if rotate_seconds:
        argv += ["-G", str(rotate_seconds)]
    if bpf:
        argv += list(bpf)
    return argv


# --- the guest-side vantage: filter-dump over QMP ---

def filter_dump_object(index: int, path: str, snaplen: int,
                       netdev: str = "net0") -> dict:
    """The QMP `object-add` payload for a VM's guest-side vantage.

    Synchronous in QEMU's datapath — lossless, but it backpressures the VM and
    accepts no BPF. `object-add`/`object-del` work at runtime and the capture
    stops when the object is removed; both were tested against a live passt
    netdev, and the pcap carries the guest's MAC, confirming the tap side.
    """
    return {
        "qom-type": "filter-dump",
        "id": filter_dump_id(index),
        "netdev": netdev,
        "file": path,
        "maxlen": QEMU_MAXLEN_UNLIMITED if snaplen == 0 else snaplen,
    }


def filter_dump_id(index: int) -> str:
    return f"wl-pcap-{index}"


def guest_staging_path(name: str) -> str:
    """Where a VM's guest-side capture is written before it is moved.

    QEMU cannot write wherever `-w` points. It runs as _wl-<name> and, since
    ADR 006 step 3, as svirt_t — so an ordinary operator path like
    /var/tmp/x/guest.pcap fails on plain DAC before SELinux even has an
    opinion, and it fails *silently*: `object-add` is accepted, the object
    exists, and no file ever appears.

    The workload's own runtime directory is the one place that already
    satisfies both — the workload user owns it and step 3 labelled it
    qemu_var_run_t precisely so a confined QEMU could create sockets there.
    The file is moved to the requested path on finalize, which costs nothing
    because the timestamp correction already requires a finalize step.
    """
    return f"/run/workload-vm/{name}/pcap-guest.pcap"


# --- ownership ---
#
# A try/finally handles Ctrl-C and nothing else — not a dropped session, not
# kill -9, not someone walking away. So the capture is owned by a transient
# unit whose ExecStopPost removes the nft rule and the QMP object. That one
# mechanism absorbs four worries: the duration bound is RuntimeMaxSec, teardown
# runs on timeout/failure/kill/reboot, --list and --stop are thin wrappers over
# systemctl, and sweeping leftovers on the next invocation becomes unnecessary
# rather than merely automated.

PCAP_UNIT_PREFIX = "workload-pcap-"
PCAP_HELPER = "/usr/libexec/workloadctl/workload-pcap"


def pcap_unit_name(name: str) -> str:
    """One unit per workload — which is also what refuses a second capture.

    Suffixing instead would let two captures double the rules and object ids,
    and a second invocation is almost always a forgotten first one.
    """
    return f"{PCAP_UNIT_PREFIX}{name}.service"


def systemd_run_argv(name: str, helper_args: list[str], *,
                     duration: int) -> list[str]:
    """The transient unit that owns the capture.

    ExecStopPost is what makes teardown real. The helper's own `finally` covers
    an ordinary exit, and covers nothing else — not `kill -9`, not an OOM kill,
    not the RuntimeMaxSec timeout landing between two of its statements. The
    unit runs this on every one of those, including a failed start.
    """
    argv = ["systemd-run", "--collect", f"--unit={pcap_unit_name(name)}",
            "--property=Type=exec",
            f"--property=ExecStopPost={PCAP_HELPER} cleanup {name}"]
    if duration:
        argv.append(f"--property=RuntimeMaxSec={duration}")
    return argv + [PCAP_HELPER, *helper_args]


# --- the plan ---

@dataclass
class PcapPlan:
    """What is about to happen, computed rather than templated.

    Real uid, real nflog group, real netdev, and only the vantages `-D` would
    report — so a vantage whose line cannot be computed is not in the plan and
    is not captured.
    """
    workload: str
    substrate: str
    uid: int
    vantages: list[str]
    snaplen: dict[str, int]
    direction: str
    write: str | None
    duration: int
    max_size: int
    steps: list[tuple[str, str, list[str]]] = field(default_factory=list)
    unit: str = ""
    # The podman container whose network namespace a container's guest-side
    # vantage enters. Resolved by the CLI, which is the only side that can:
    # the podman name is `workload-<name>` for a single-container workload and
    # `workload-<name>-<container>` for one member of a pod, and picking the
    # wrong one captures a sibling's traffic without saying so.
    podman_container: str | None = None
    # Whether this plan actually installs a QEMU filter-dump object. Not
    # derivable from `vantages` alone: a *container's* guest-side vantage is an
    # nsenter'd tcpdump with no QEMU anywhere near it, and a plan that promises
    # to remove an object it never added is not a promise.
    has_qemu_object: bool = False

    def to_json(self) -> dict:
        return {
            "workload": self.workload,
            "substrate": self.substrate,
            "uid": self.uid,
            "vantages": self.vantages,
            "snaplen": self.snaplen,
            "direction": self.direction,
            "write": self.write,
            "duration_sec": self.duration,
            "max_size_bytes": self.max_size,
            "unit": self.unit,
            "has_qemu_object": self.has_qemu_object,
            "podman_container": self.podman_container,
            "steps": [{"vantage": v, "summary": s, "commands": c}
                      for v, s, c in self.steps],
        }


def build_plan(config, *, vantages: list[str], snaplen: dict[str, int],
               direction: str, write: str | None, duration: int,
               max_size: int, bpf: list[str] | None = None,
               container: str | None = None) -> PcapPlan:
    """Assemble the plan both `--dry-run` and the helper work from."""
    uid = config.uid
    substrate = "VM, passt" if config.is_vm and config.vm_bridge is None else (
        f"VM, bridge {config.vm_bridge}" if config.is_vm
        else f"container, {config.get_network_mode()}")
    plan = PcapPlan(
        workload=config.name, substrate=substrate, uid=uid,
        vantages=list(vantages), snaplen=dict(snaplen), direction=direction,
        write=write, duration=duration, max_size=max_size,
        unit=pcap_unit_name(config.name),
        has_qemu_object=config.is_vm and VANTAGE_GUEST in vantages,
        podman_container=(None if config.is_vm
                          else config.podman_container_name(
                              container or config.name)),
    )
    detail = {v.name: v.detail for v in pcap_vantages(config)}

    for vantage in vantages:
        if vantage == VANTAGE_HOST:
            rules = [" ".join(cmd) for cmd in
                     pcap_rule_commands(uid, snaplen[vantage], direction)]
            reader = " ".join(tcpdump_argv(
                uid, snaplen[vantage],
                write=_vantage_path(write, vantage, len(vantages)), bpf=bpf))
            plan.steps.append((vantage, detail[vantage], rules + [reader]))
        else:
            path = _vantage_path(write, vantage, len(vantages)) or "(none)"
            if config.is_vm:
                staging = guest_staging_path(config.name)
                obj = filter_dump_object(0, staging, snaplen[vantage])
                commands = ["QMP object-add: " + repr(obj)]
                if path and path != "-":
                    commands.append(
                        f"on finalize: correct timestamps, then move to {path}")
                    commands.append(
                        "(QEMU writes into the workload's own runtime dir "
                        "because it runs confined, as this workload's user)")
                else:
                    commands.append("timestamps corrected on finalize")
                plan.steps.append((vantage, detail[vantage], commands))
            else:
                plan.steps.append((vantage, detail[vantage], [
                    f"nsenter into {plan.podman_container}'s network "
                    f"namespace, then tcpdump -s {snaplen[vantage]}"
                    + (f" -w {path}" if write else ""),
                ]))
    return plan


def _vantage_path(write: str | None, vantage: str, count: int) -> str | None:
    """With more than one vantage, -w PATH is a directory."""
    if not write or write == "-":
        return write
    return f"{write.rstrip('/')}/{vantage}.pcap" if count > 1 else write


def render_plan(plan: PcapPlan) -> str:
    """The preamble, in plain language, before anything happens.

    This is not only pedagogy: `pcap` is the one read-flavoured command that
    writes into the security-critical nftables table, so showing the exact rule
    before installing it makes `--dry-run` an audit step — an operator can
    confirm it is a non-terminating `log` rule that cannot change accept/drop
    semantics.
    """
    lines = [
        f"Capturing {plan.workload!r} ({plan.substrate}, uid {plan.uid}) "
        f"from {len(plan.vantages)} vantage"
        f"{'' if len(plan.vantages) == 1 else 's'}:",
        "",
    ]
    for vantage, detail, commands in plan.steps:
        lines.append(f"  {vantage:<6} {detail}")
        for command in commands:
            lines.append(f"         {command}")
        lines.append("")

    snaps = sorted(set(plan.snaplen[v] for v in plan.vantages))
    if snaps == [0]:
        lines.append("Keeping every byte of each packet.")
    elif len(snaps) == 1:
        lines.append(
            f"Keeping {snaps[0]} bytes of each packet — headers plus the start "
            f"of the payload, enough for a TLS SNI or an HTTP request line.")
    else:
        lines.append("Keeping " + ", ".join(
            f"{plan.snaplen[v]} bytes on {v}" for v in plan.vantages) + ".")

    bounds = []
    if plan.duration:
        bounds.append(_humanize_duration(plan.duration))
    if plan.max_size:
        bounds.append(_humanize_size(plan.max_size))
    if bounds:
        lines.append("")
        lines.append(
            f"Stopping after {' or '.join(bounds)}"
            f"{', whichever comes first' if len(bounds) > 1 else ''}."
            + (" All vantages stop together so the files cover the same "
               "window." if len(plan.vantages) > 1 else ""))

    lines.append("")
    # Name only what this plan actually installs. A container's guest-side
    # vantage has no QEMU object, and a guest-only capture installs no nftables
    # rule at all — claiming either would make the plan a worse promise than
    # saying nothing.
    installed = []
    if VANTAGE_HOST in plan.vantages:
        installed.append("the nftables rule")
    if plan.has_qemu_object:
        installed.append("the QEMU object")
    if installed:
        subject = " and ".join(installed)
        verb = "is" if len(installed) == 1 else "are"
        lines.append(
            f"Owned by {plan.unit}, so {subject} {verb} removed even if this "
            f"command is killed or your session drops.")
    else:
        lines.append(
            f"Owned by {plan.unit}, so the capture stops even if this command "
            f"is killed or your session drops.")
    return "\n".join(lines)


def _humanize_duration(seconds: int) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def _humanize_size(size: int) -> str:
    for unit, factor in (("G", 1000 ** 3), ("M", 1000 ** 2), ("K", 1000)):
        if size >= factor and size % factor == 0:
            return f"{size // factor}{unit}"
    return f"{size}B"


# --- validation of a requested capture ---

def validate_request(config, *, vantages: list[str], direction: str,
                     bpf: list[str] | None, write: str | None,
                     detach: bool, json_output: bool,
                     rotation: bool, tcpdump_present: bool | None = None,
                     container: str | None = None) -> list[str]:
    """Everything that makes a request incoherent, as error strings.

    Rejecting rather than resolving cleverly, in two places especially: a
    FILTER that cannot be applied to every selected vantage would produce two
    captures narrowed differently, which cannot be compared — and comparing
    them is the only reason to select two.
    """
    errors: list[str] = []
    table = {v.name: v for v in pcap_vantages(config)}

    # WORKLOAD/CONTAINER. Accepting the syntax and then ignoring the container
    # half would capture a sibling's namespace with nothing said about it,
    # which is worse than refusing the form outright.
    #
    # But it is only ever needed for ONE topology. The host vantage is
    # inherently whole-workload — every container of a workload runs as the
    # same `_wl-<name>` user, so `meta skuid` gathers all of them and a
    # container name would be meaningless there. Under `pod` mode the
    # containers share one network namespace by construction, so a guest-side
    # capture is whole-workload too and naming one member is ceremony that
    # changes nothing. Only `bridge` mode gives each container its own netns,
    # and only there does a capture have to say which it means.
    if container is not None:
        if config.is_vm:
            errors.append(
                f"{config.name}/{container}: a VM workload has no containers")
        elif container not in config.container_names():
            errors.append(
                f"{container!r} is not a container in {config.name} "
                f"({', '.join(config.container_names())})")
    elif (not config.is_vm and VANTAGE_GUEST in vantages
            and config.mode == "bridge"):
        errors.append(
            f"{config.name} runs in 'bridge' mode, where each container has "
            f"its own network namespace — name one as "
            f"{config.name}/<container> ({', '.join(config.container_names())}). "
            f"The host vantage needs no container: every container runs as the "
            f"same user, so it captures the whole workload at once")

    for vantage in vantages:
        if vantage not in table:
            errors.append(f"{vantage!r} is not a vantage "
                          f"({', '.join(VANTAGES)})")
            continue
        if not table[vantage].available:
            errors.append(f"vantage {vantage!r}: {table[vantage].detail}")

    known = [table[v] for v in vantages if v in table]
    if bpf:
        unfilterable = [v.name for v in known if not v.supports_filter]
        if unfilterable:
            reasons = []
            if VANTAGE_HOST in unfilterable:
                # Measured, and it is a hard error rather than a silent no-op:
                # tcpdump refuses to start with "NFLOG link-layer type
                # filtering not implemented". The design's capability table
                # says this vantage takes a filter; it does not.
                reasons.append(
                    "the host vantage reads an nflog pseudo-device, and "
                    "libpcap cannot compile a BPF filter for that link type "
                    "at all (tcpdump: \"NFLOG link-layer type filtering not "
                    "implemented\")")
            if VANTAGE_GUEST in unfilterable:
                reasons.append(
                    "a VM's guest side taps the netdev through QEMU's "
                    "filter-dump, which accepts only a file and a length")
            errors.append(
                f"a BPF filter cannot be applied to "
                f"{' or '.join(repr(v) for v in unfilterable)}: "
                + "; ".join(reasons)
                + ". Capture unfiltered and narrow on read "
                  "(tcpdump -r <file> is also unfiltered for nflog — decode "
                  "and grep), or use a container's guest vantage, which is a "
                  "real AF_PACKET capture and takes a full expression")
    if direction != DIRECTION_DEFAULT and any(
            not v.supports_direction for v in known):
        errors.append(
            f"-Q {direction} cannot be honored by every selected vantage "
            f"(a VM's guest side taps the netdev, so it is always inout)")
    if rotation and any(not v.supports_rotation for v in known):
        errors.append(
            "rotation (-C/-W/-G) cannot be honored by a VM's guest-side "
            "vantage")

    # Both claim stdout.
    if json_output and write == "-":
        errors.append("--json and -w - both claim stdout")
    # The packets ARE the output, so the capture would run and discard
    # everything it captured.
    if json_output and not write:
        errors.append("--json requires -w PATH — without it the packets are "
                      "the output, and there would be nothing to report")
    if detach and not write:
        errors.append("--detach requires -w PATH — detaching with no file "
                      "discards everything captured")
    if detach and write == "-":
        errors.append("--detach with -w - is meaningless: nothing is left "
                      "attached to read stdout")
    if len(vantages) > 1 and write and write != "-":
        # One file per vantage, so the destination has to be a directory.
        if not write.endswith("/") and "." in write.rsplit("/", 1)[-1]:
            errors.append(
                f"-w {write!r}: with more than one vantage this must be a "
                f"directory, not a file")
    # Injectable so the verdict logic is testable on a machine that happens
    # not to have tcpdump — which is most CI runners, and this check exists
    # precisely for the hosts that lack it.
    if tcpdump_present is None:
        tcpdump_present = shutil.which("tcpdump") is not None
    if not tcpdump_present and VANTAGE_HOST in vantages:
        errors.append("tcpdump is not installed, and the host vantage reads "
                      "the capture back through it")
    return errors
