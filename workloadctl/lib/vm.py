"""
VM-workload constants, helpers, and schema validation.

Everything specific to `[vm]` workloads: the uid-derived passt network identity,
OVMF firmware discovery, MAC derivation, memory parsing, and the [vm]-section
validator. Kept separate from the container path so the VM surface is legible
on its own.

Installed to /usr/libexec/workloadctl/vm.py.
"""

import hashlib
import ipaddress
import os
import re
from pathlib import Path

from workload_lib import UID_MAX, UID_MIN, parse_volume_spec


# --- VM constants ---

# Runtime socket directory for VM workloads: /run/workload-vm/{name}/
VM_SOCKET_DIR = Path("/run/workload-vm")

# virtio-serial port name qemu-guest-agent binds to inside the guest. Fixed by
# the agent, not by us — qemu-ga only attaches to a virtserialport with exactly
# this name, so both the generator's -device line and any host-side client have
# to agree on it.
VM_GUEST_AGENT_PORT = "org.qemu.guest_agent.0"

# UID/GID of the guest's primary interactive user. Cloud images assign the
# first user (cloud-init's default user) uid/gid 1000, and our default
# cloud-config pins it there explicitly. virtiofsd internally translates this
# guest id <-> the host workload uid so the guest user can write the share
# (which on the host is owned by _wl-<name>); see generate_virtiofs_service.
VM_GUEST_UID = 1000

# --- passt networking (ADR 006) ---
#
# VM workloads have no bridge. passt terminates the guest's stack in userspace
# and re-originates its traffic as ordinary host sockets owned by the workload's
# own uid, so THE WORKLOAD UID IS THE NETWORK IDENTITY — unforgeable by the
# guest, unique per workload with no allocation step, and matchable by nftables
# as `meta skuid`. Everything below derives from the uid; there is no registry.
#
# Load-bearing precondition: passt keeps its inherited uid ONLY because it is
# not started as root (conf.c:1007-1017 — started as root it warns once and
# drops to nobody, collapsing every workload into one uid while traffic keeps
# flowing). The generated unit's User= is what prevents that, which is why
# tests/test_vm_passt.py asserts it rather than assuming it.

# Base of the per-workload management address range. All of 127.0.0.0/8 is
# loopback and any address in it binds and connects with no configuration, so
# each workload gets its own address at a FIXED port rather than a shared
# address at an allocated port. 127.128.0.0 (not 127.0.1.0) avoids 127.0.1.1,
# which Debian conventionally puts in /etc/hosts for the system hostname.
# UID_MIN..UID_MAX is 10000-52948 = 42,949 values, comfortably inside both
# 127.128.0.0/9 and the 16-bit nflog group space.
VM_MGMT_ADDR_BASE = 0x7F800000  # 127.128.0.0

# Port passt forwards to the guest's sshd for `workloadctl exec` / `shell`.
# Fixed, never configurable, and bound only on the workload's own management
# address. It must stay above net.ipv4.ip_unprivileged_port_start (1024 by
# default) because passt binds it as the workload user, not as root — which is
# why this is 2222 and not 22.
VM_MGMT_SSH_PORT = 2222

# The advertised DNS address is derived at unit start, not here: the generator
# runs Before=basic.target, where there is no default route yet. See
# libexec/workload-vm-netdev and generate_vm_service.

# Exit code workload-vm-notify uses to report a guest *reboot* (as opposed to a
# poweroff, which exits 0). QEMU runs with -no-reboot, so both a guest reboot and
# a guest poweroff make QEMU exit 0 — only the QMP SHUTDOWN event's reason tells
# them apart. For [vm].restart = "on-reboot" the wrapper translates a reboot into
# this nonzero code so systemd's Restart=on-failure cycles the VM, while a
# poweroff (exit 0) leaves it down. Nonzero and outside QEMU's own 0/1 range.
VM_REBOOT_EXIT_CODE = 133

# OVMF firmware search order (distro paths differ)
OVMF_CODE_CANDIDATES = [
    "/usr/share/edk2/ovmf/OVMF_CODE.fd",
    "/usr/share/OVMF/OVMF_CODE.fd",
    "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd",
    "/usr/share/ovmf/OVMF.fd",
]
OVMF_VARS_CANDIDATES = [
    "/usr/share/edk2/ovmf/OVMF_VARS.fd",
    "/usr/share/OVMF/OVMF_VARS.fd",
    "/usr/share/edk2-ovmf/x64/OVMF_VARS.fd",
    "/usr/share/ovmf/OVMF_VARS.fd",
]


# --- VM helpers ---

def vm_guest_agent_socket(name: str) -> Path:
    """Host-side unix socket for this VM's qemu-guest-agent channel.

    Separate from the QMP monitors: this carries the *guest agent* protocol
    (qemu-ga inside the guest), not QEMU's own monitor protocol, so it can never
    contend with qmp.sock's ExecStop system_powerdown or the exporter's
    qmp-metrics.sock.
    """
    return VM_SOCKET_DIR / name / "ga.sock"


def vm_management_address(uid: int) -> str:
    """The workload's own loopback address for management inbound.

    `workloadctl exec`/`shell` reach the guest's sshd here, on
    VM_MGMT_SSH_PORT. Never routable, never configurable, and distinct from
    declared published ports ([vm.network].ports), which the operator binds
    where they choose — the two were conflated in early drafts and are
    genuinely different (ADR 006).

    Derived from the uid, so uniqueness is inherited from the uid allocator:
    no registry, no allocation step, and no collision. uid 10000 -> 127.128.0.0,
    uid 10003 -> 127.128.0.3.
    """
    if uid < UID_MIN or uid > UID_MAX:
        raise ValueError(
            f"UID {uid} is outside the workload range {UID_MIN}-{UID_MAX}; "
            f"no management address is derivable for it")
    return str(ipaddress.IPv4Address(VM_MGMT_ADDR_BASE + (uid - UID_MIN)))


def vm_nflog_group(uid: int) -> int:
    """The workload's nflog group, for per-workload host-side packet capture.

    Same derivation, same guarantee as vm_management_address: the offset into
    the workload uid range. `tcpdump -i nflog:<group>` then reads exactly this
    workload's traffic, which is the only mechanism that can produce a
    per-workload host-side capture at all — by the time a packet is on the wire
    the owning socket is not part of it, so only netfilter sees `meta skuid`.
    """
    if uid < UID_MIN or uid > UID_MAX:
        raise ValueError(
            f"UID {uid} is outside the workload range {UID_MIN}-{UID_MAX}; "
            f"no nflog group is derivable for it")
    return uid - UID_MIN


def vm_mac_address(name: str) -> str:
    """Derive a stable, locally-administered unicast MAC from the workload name."""
    h = hashlib.md5(f"wl-vm-{name}".encode(), usedforsecurity=False).digest()
    first = (h[0] & 0xFE) | 0x02  # locally administered, unicast
    return ":".join(f"{b:02x}" for b in [first, h[1], h[2], h[3], h[4], h[5]])


def vm_mac_collisions(name: str, other_names) -> list[str]:
    """Return the subset of other_names whose derived VM MAC equals name's.

    vm_mac_address hashes the name into a MAC with no allocation registry, so
    two distinct names can (rarely) collide. Under passt that is harmless —
    each guest is alone on its own link — but two VMs sharing an
    operator-provided LAN bridge ([vm.network].bridge) are on one segment and
    would fight over one address. This lets `validate` flag it up front.
    """
    mine = vm_mac_address(name)
    return sorted(other for other in set(other_names)
                  if other != name and vm_mac_address(other) == mine)


def find_ovmf_code() -> str | None:
    """Return the first existing OVMF_CODE path, or None."""
    for p in OVMF_CODE_CANDIDATES:
        if Path(p).exists():
            return p
    return None


def find_ovmf_vars() -> str | None:
    """Return the first existing OVMF_VARS path, or None."""
    for p in OVMF_VARS_CANDIDATES:
        if Path(p).exists():
            return p
    return None


def parse_memory_mib(value) -> int:
    """Parse memory in QEMU notation ("2048", "2048M", "4G") to MiB as int.

    Raises ValueError if the value is not a recognized form. Used by both
    [vm].memory validation and the systemd unit generator so they agree.
    """
    if isinstance(value, int):
        return value
    s = str(value).strip()
    if not s:
        raise ValueError("empty memory value")
    suffix = s[-1].upper()
    if suffix.isdigit():
        return int(s)
    n = int(s[:-1])
    if suffix == "M":
        return n
    if suffix == "G":
        return n * 1024
    if suffix == "K":
        # qemu accepts K but it's not useful for VM RAM
        return max(1, n // 1024)
    raise ValueError(f"unknown memory unit suffix {suffix!r} in {value!r}")


# --- Validation ---

# Published-port spec, following the container convention already in the schema
# ([network].ports = ["8080:80"]): an optional bind address, a host port, an
# optional guest port, an optional /proto. Parsed rather than passed through
# because passt spells the same thing differently (addr/host:guest, and TCP and
# UDP on separate netdev properties), so the generator has to take it apart.
# The bind-address branch must be a dotted quad or bracketed, never a bare run
# of digits — otherwise "8080:80" parses as address 8080, port 80.
VM_PORT_RE = re.compile(
    r"^(?:(?P<addr>\[[0-9a-fA-F:]+\]|\d{1,3}(?:\.\d{1,3}){3}):)?"
    r"(?P<host>\d+)"
    r"(?::(?P<guest>\d+))?"
    r"(?:/(?P<proto>tcp|udp))?$"
)


def parse_vm_port(spec: str) -> tuple[str | None, int, int, str]:
    """Parse a [vm.network].ports entry into (bind_addr, host, guest, proto).

    Raises ValueError on anything malformed. `bind_addr` is None when the
    operator did not pin one, in which case passt binds every address — the
    same meaning `-p 8080:80` has for podman.
    """
    m = VM_PORT_RE.match(spec.strip())
    if not m:
        raise ValueError(
            f"{spec!r} is not a port spec — use '8080:80', '8080', "
            f"'127.0.0.1:8080:80', or any of those with '/udp'")
    host = int(m.group("host"))
    guest = int(m.group("guest") or host)
    for label, port in (("host", host), ("guest", guest)):
        if not 1 <= port <= 65535:
            raise ValueError(f"{spec!r} has a {label} port out of range: {port}")
    addr = m.group("addr")
    if addr:
        addr = addr.strip("[]")
        try:
            ipaddress.ip_address(addr)
        except ValueError:
            raise ValueError(f"{spec!r} has an invalid bind address: {addr!r}")
    return (addr, host, guest, m.group("proto") or "tcp")


VM_EGRESS_MODES = ("filtered", "open")
VM_EGRESS_DEFAULT = "filtered"

# The uid-keyed egress layer (ADR 006 §4). One table shared by every VM;
# units manage set *elements* only, never rules.
NFT_BIN = "/usr/sbin/nft"
NFT_TABLE = "inet workload_filter"
NFT_SET_FILTERED = "wl_filtered"
NFT_SET_ALLOW4 = "wl_allow4"
NFT_SET_ALLOW6 = "wl_allow6"
NFT_SKELETON = "/usr/share/workloadctl/workload-filter.nft"


def vm_filter_elements(uid: int, allow: list[str]) -> dict[str, list[str]]:
    """Map set name -> element expressions for one workload.

    Returns only non-empty sets, so a caller can emit one `nft add element`
    per set and skip the rest. `wl_filtered` carries the bare uid — membership
    is the family-agnostic question "is this workload under policy at all?",
    and both the ct-mark and the drop are guarded on it.

    The allowlist splits by address family because in the inet family
    `ip daddr` matches v4 only and `ip6 daddr` v6 only; an entry in the wrong
    set would simply never match, which is a silent failure rather than a
    loud one.
    """
    elements: dict[str, list[str]] = {NFT_SET_FILTERED: [str(uid)]}
    v4: list[str] = []
    v6: list[str] = []
    for spec in allow:
        addr, port = parse_vm_allow(spec)
        (v6 if addr.version == 6 else v4).append(f"{uid} . {addr} . {port}")
    if v4:
        elements[NFT_SET_ALLOW4] = v4
    if v6:
        elements[NFT_SET_ALLOW6] = v6
    return elements


NFT_SETS = (NFT_SET_FILTERED, NFT_SET_ALLOW4, NFT_SET_ALLOW6)


# --- SELinux confinement (ADR 006 step 3) ---

# QEMU runs as svirt_t (alias qemu_t), the domain the shipped policy already
# maintains for a hypervisor process hosting an untrusted guest. We deliberately
# do NOT author a wl_vm_t: svirt_t is a virt_domain and an mcs_constrained_type
# that already declares the entrypoints this needs, including
#   allow svirt_t qemu_exec_t:file entrypoint;
#   allow svirt_t passt_exec_t:file { entrypoint execute ... };
#   allow svirt_t swtpm_exec_t:file { entrypoint execute ... };
# so passt and swtpm transition to passt_t/swtpm_t automatically the moment QEMU
# is svirt_t, with no rules of ours.
#
# s0 with no categories: svirt_t is mcs_constrained and libvirt allocates a
# category pair per VM because all of its VMs share one uid. Ours each run as
# their own _wl-<name>, so DAC already provides the inter-VM separation MCS
# would buy — and categories on files are invisible to `ls -l` and produce EPERM
# that looks like nothing is wrong, a failure mode this project has been bitten
# by before. Categories stay available if uid separation ever stops sufficing.
VM_QEMU_TYPE = "svirt_t"
VM_QEMU_CONTEXT = f"system_u:system_r:{VM_QEMU_TYPE}:s0"

# The host-global policy delta VM confinement needs: a domain for the virtiofsd
# sidecar, and one grant to svirt_t that only a QEMU-native passt netdev needs.
# Installed by the RPM rather than shipped through the per-workload
# [security].selinux_policy bundle: nothing in it is per-workload, and N
# identical copies would race semodule while gated on a flag that has nothing to
# do with whether virtiofs works. See security/workload-vm.cil.
VM_SELINUX_MODULE = "workload-vm"
VM_SELINUX_CIL = "/usr/share/workloadctl/workload-vm.cil"

# The transition needs a wrapper, and only a wrapper. `SELinuxContext=` in the
# unit does NOT work: systemd execs from init_t and the policy has no
# init_t -> svirt_t transition, deliberately — libvirt reaches svirt_t through
# its own virtqemud_t. But the domain VM units run in today may do it:
#   allow unconfined_service_t virt_domain:process transition;
# so `runcon <context> qemu-system-x86_64` from workload-vm-notify succeeds with
# no local policy at all.
#
# runcon rather than a setexeccon() call in Python, for two reasons. lib/ has no
# third-party dependencies and the stdlib has no SELinux binding, so the
# alternative is a new python3-libselinux Requires for one call. And runcon
# execs the target in its own process, which scopes the pending exec context to
# the child by construction — setexeccon() in the parent would leave it armed
# for whatever that process execs next.
#
# runcon must exec QEMU DIRECTLY. The entrypoint above is on qemu_exec_t; a
# shell in between is bin_t and the transition is refused.
VM_RUNCON_BIN = "/usr/bin/runcon"

# Presence means selinuxfs is mounted, i.e. SELinux is enabled. Enforcing vs
# permissive is not consulted: permissive is exactly the mode an AVC harvest
# runs in, so the transition has to happen there too or the harvest measures the
# wrong domain. Only a *disabled* host skips it, where setexeccon() would fail
# and take QEMU down with it.
SELINUX_ENFORCE_PATH = "/sys/fs/selinux/enforce"


def selinux_enabled(root: str = "") -> bool:
    """Whether SELinux is enabled on this host (selinuxfs mounted)."""
    return os.path.exists(root + SELINUX_ENFORCE_PATH)


def qemu_launch_argv(qemu_cmd: list[str], *, enabled: bool | None = None,
                     runcon: str = VM_RUNCON_BIN) -> list[str]:
    """`qemu_cmd`, prefixed with runcon so QEMU enters svirt_t.

    Returns `qemu_cmd` unchanged when SELinux is disabled or runcon is missing,
    so a non-SELinux host still boots VMs — unconfined, as it was before ADR 006
    step 3. It is `workloadctl diagnose` that reports the difference; failing
    the start here would turn "this host has no SELinux" into "VMs do not run".
    """
    if enabled is None:
        enabled = selinux_enabled()
    if not enabled or not os.path.exists(runcon):
        return list(qemu_cmd)
    return [runcon, VM_QEMU_CONTEXT, *qemu_cmd]


def vm_owned_elements(uid: int, elems) -> list[str]:
    """Element expressions in one set's `nft -j` output that belong to `uid`.

    Two shapes, because `wl_filtered` holds a bare uid while the allow sets
    hold concatenations:

        wl_filtered -> [10001, 10002]
        wl_allow4   -> [{"concat": [10001, "192.168.0.10", 22]}]

    Matching on the first component is what makes a purge possible at all:
    nft has no "delete every element whose first field is N", so the caller
    must enumerate, filter here, and delete by exact value.
    """
    owned: list[str] = []
    for elem in elems or []:
        if isinstance(elem, dict) and "concat" in elem:
            parts = elem["concat"]
            if parts and parts[0] == uid:
                owned.append(" . ".join(str(p) for p in parts))
        elif elem == uid:
            owned.append(str(uid))
    return owned


def nft_set_elements(payload) -> list:
    """The `elem` list from one `nft -j list set ...` document."""
    for item in (payload or {}).get("nftables", []):
        if "set" in item:
            return item["set"].get("elem", []) or []
    return []


def nft_drop_counter(payload) -> tuple[int, int] | None:
    """(packets, bytes) on the set-guarded drop rule, or None if absent.

    NOTE this counter is **host-wide across every filtered VM**, not
    per-workload: there is one drop rule and it is guarded on set membership,
    so every filtered workload's dropped packets land on the same counter.
    Callers must not present it as belonging to one workload.
    """
    for item in (payload or {}).get("nftables", []):
        rule = item.get("rule") if isinstance(item, dict) else None
        if not rule:
            continue
        exprs = rule.get("expr", [])
        if not any("drop" in e for e in exprs if isinstance(e, dict)):
            continue
        for expr in exprs:
            if isinstance(expr, dict) and "counter" in expr:
                counter = expr["counter"]
                return (counter.get("packets", 0), counter.get("bytes", 0))
    return None


def vm_filter_delete_command(set_name: str, entries: list[str]) -> list[str]:
    """argv deleting `entries` from `set_name` in one transaction."""
    return [NFT_BIN, "delete", "element", *NFT_TABLE.split(), set_name,
            "{ " + ", ".join(entries) + " }"]


def vm_filter_commands(uid: int, allow: list[str],
                       action: str) -> list[list[str]]:
    """argv lists that arm ("add") or disarm ("delete") one workload.

    Elements for a set go in a single command: nft applies each invocation as
    one atomic transaction, so a VM is never half-armed — the alternative,
    one command per entry, could leave a workload in `wl_filtered` with only
    part of its allowlist installed if a later command failed.
    """
    if action not in ("add", "delete"):
        raise ValueError(f"action must be 'add' or 'delete', got {action!r}")
    table = NFT_TABLE.split()
    commands = []
    for set_name, entries in vm_filter_elements(uid, allow).items():
        commands.append([NFT_BIN, action, "element", *table, set_name,
                         "{ " + ", ".join(entries) + " }"])
    return commands

# `<addr>:<port>` or `[<v6addr>]:<port>`. Addresses only, never hostnames: the
# allowlist becomes elements of an nftables set keyed on `ip daddr`/`ip6 daddr`,
# so a name would have to be resolved at unit start and would then be silently
# wrong for the life of the VM whenever the record changed. Hostname policy is
# the proxy's job (ADR 006 §4.4), and `allow` is for the non-HTTP exceptions
# the proxy cannot carry.
VM_ALLOW_RE = re.compile(
    r"^(?:\[(?P<v6>[0-9a-fA-F:]+)\]|(?P<v4>\d{1,3}(?:\.\d{1,3}){3})):"
    r"(?P<port>\d+)$")


def parse_vm_allow(spec: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    """Parse one [vm.network].allow entry into (address, port).

    Raises ValueError with an operator-readable message.
    """
    match = VM_ALLOW_RE.match(spec.strip())
    if not match:
        raise ValueError(
            f"{spec!r} is not '<addr>:<port>' (IPv6 as '[addr]:port'). "
            f"Addresses only — hostname policy belongs to the proxy")
    try:
        addr = ipaddress.ip_address(match.group("v6") or match.group("v4"))
    except ValueError:
        raise ValueError(f"{spec!r} does not contain a valid IP address") from None
    port = int(match.group("port"))
    if not 1 <= port <= 65535:
        raise ValueError(f"{spec!r}: port {port} out of range 1-65535")
    return addr, port


def _validate_egress(net: dict) -> list[str]:
    """Validate [vm.network].egress and .allow.

    `egress` defaults to "filtered" (ADR 006 §5.1): the usual argument for
    defaulting a new control off is protecting deployed workloads, and there
    are none — both VM bundles are templates. A secure default costs nothing
    now and is expensive to retrofit.

    The design pairs `filtered` with an implicit allow to the workload's own
    proxy, so an empty `allow` is still workable. That proxy is a later step,
    so until it exists `filtered` requires a non-empty `allow` — the same
    condition the design states ("validate errors on `filtered` with neither
    proxy nor allowlist"), evaluated in a world where the proxy is never
    present. The failure is loud on purpose: silently treating an
    un-allowlisted VM as open is the misreported-confinement bug this whole
    layer exists to prevent.
    """
    errors: list[str] = []

    egress = net.get("egress", VM_EGRESS_DEFAULT)
    if egress not in VM_EGRESS_MODES:
        errors.append(
            f"[vm.network].egress must be one of "
            f"{', '.join(repr(m) for m in VM_EGRESS_MODES)}, got {egress!r}")
        egress = VM_EGRESS_DEFAULT

    allow = net.get("allow", [])
    if not isinstance(allow, list):
        errors.append(
            f"[vm.network].allow must be an array of '<addr>:<port>' strings, "
            f"got {type(allow).__name__}")
        allow = []
    else:
        for spec in allow:
            if not isinstance(spec, str):
                errors.append(
                    f"[vm.network].allow entries must be strings, got {spec!r}")
                continue
            try:
                parse_vm_allow(spec)
            except ValueError as e:
                errors.append(f"[vm.network].allow: {e}")

    # §5.3: `bridge` means a real LAN identity, and nothing of ours is in that
    # guest's data path — no host socket, so no uid to match on.
    if "bridge" in net:
        for key in ("egress", "allow"):
            if key in net:
                errors.append(
                    f"[vm.network].{key} has no effect with .bridge set — a "
                    f"bridged VM sends from its own LAN address, not from a "
                    f"host socket owned by the workload user, so there is no "
                    f"uid for the filter to match")
        return errors

    if egress == "filtered" and not allow:
        errors.append(
            "[vm.network].egress is 'filtered' (the default) but .allow is "
            "empty, so this VM could reach nothing at all. List the "
            "destinations it needs as '<addr>:<port>', or set egress = "
            "'open' to opt out of filtering.")

    return errors


def validate_vm_network(net: dict) -> list[str]:
    """Validate [vm.network]. Returns a list of error strings.

    There is deliberately no `mode` key (ADR 006): `bridge` present means
    "attach to that operator-provided host bridge, take a real LAN identity,
    and be unfiltered"; absent means passt. That makes the contradictory
    combination unrepresentable rather than a validation rule.
    """
    errors: list[str] = []
    if not isinstance(net, dict):
        return ["[vm.network] must be a table"]

    # bridge — the unfiltered escape hatch. Optional now: its absence selects
    # passt, so unlike the pre-ADR-006 schema there is no default bridge name.
    if "bridge" in net:
        bridge = net["bridge"]
        if not isinstance(bridge, str) or not bridge:
            errors.append(
                f"[vm.network].bridge must be a non-empty string, got {bridge!r}")
        elif not re.match(r"^[a-zA-Z0-9_-]+$", bridge) or len(bridge) > 15:
            # Linux IFNAMSIZ is 16, max 15 visible chars.
            errors.append(
                f"[vm.network].bridge {bridge!r} is not a valid interface name "
                "(letters/digits/_/-, max 15 chars)")

    ports = net.get("ports", [])
    if not isinstance(ports, list):
        errors.append(
            f"[vm.network].ports must be an array of 'host:guest' strings, "
            f"got {type(ports).__name__}")
    else:
        for spec in ports:
            if not isinstance(spec, str):
                errors.append(f"[vm.network].ports entries must be strings, got {spec!r}")
                continue
            try:
                parse_vm_port(spec)
            except ValueError as e:
                errors.append(f"[vm.network].ports: {e}")
    if ports and "bridge" in net:
        # passt publishes ports by binding host sockets; a bridged guest has its
        # own LAN address and nothing of ours is in its data path to bind them.
        errors.append(
            "[vm.network].ports has no effect with .bridge set — a bridged VM "
            "has its own LAN address, so reach its services there directly")

    outbound_if = net.get("outbound_if")
    if outbound_if is not None:
        if not isinstance(outbound_if, str) or not outbound_if:
            errors.append(
                f"[vm.network].outbound_if must be a non-empty string, "
                f"got {outbound_if!r}")
        elif not re.match(r"^[a-zA-Z0-9_.-]+$", outbound_if) or len(outbound_if) > 15:
            errors.append(
                f"[vm.network].outbound_if {outbound_if!r} is not a valid "
                "interface name (letters/digits/_/./-, max 15 chars)")
        elif "bridge" in net:
            errors.append(
                "[vm.network].outbound_if has no effect with .bridge set — it "
                "binds passt's host-side sockets, and a bridged VM has none")

    resolver = net.get("resolver", "host")
    if resolver not in ("host", "none"):
        errors.append(
            f"[vm.network].resolver must be 'host' or 'none', got {resolver!r}")

    errors += _validate_egress(net)

    # ADR 002's host-level knobs went with the bridge that needed them.
    for removed in ("subnet", "dns"):
        if removed in net:
            errors.append(
                f"[vm.network].{removed} was managed-bridge configuration and "
                f"is gone with it (ADR 006). passt serves the guest DHCP/DNS "
                f"itself, derived from the host at start time.")

    return errors


def validate_vm_config(config: dict) -> list[str]:
    """Validate the [vm] section. Returns a list of error strings."""
    errors = []
    vm = config.get("vm", {})

    if "container" in config or "containers" in config:
        errors.append("[vm] and [container]/[[containers]] are mutually exclusive")

    sources = [bool(vm.get("image")), bool(vm.get("cloud_image_url")), bool(vm.get("local_image"))]
    if sum(sources) == 0:
        errors.append(
            "[vm] requires exactly one image source: "
            "vm.image (bootc ref), vm.cloud_image_url, or vm.local_image"
        )
    elif sum(sources) > 1:
        errors.append("[vm] must specify exactly one image source; got multiple")

    if vm.get("cloud_image_url") and not vm.get("cloud_image_checksum"):
        errors.append("[vm].cloud_image_checksum is required when cloud_image_url is set")

    checksum = vm.get("cloud_image_checksum", "")
    if checksum and not checksum.startswith("sha256:"):
        errors.append(f"[vm].cloud_image_checksum must start with 'sha256:', got {checksum!r}")

    memory = vm.get("memory", "")
    if memory:
        try:
            m = parse_memory_mib(memory)
            if m < 256:
                errors.append(f"[vm].memory must be at least 256 MiB, got {m}")
        except (ValueError, TypeError):
            errors.append(
                f"[vm].memory must be in QEMU notation (e.g. 2048, '2048M', '4G'), got {memory!r}"
            )

    vcpus = vm.get("vcpus", 1)
    if not isinstance(vcpus, int) or vcpus < 1:
        errors.append(f"[vm].vcpus must be a positive integer, got {vcpus!r}")

    rollback_keep = vm.get("rollback_keep", 2)
    if not isinstance(rollback_keep, int) or rollback_keep < 1:
        errors.append(f"[vm].rollback_keep must be a positive integer, got {rollback_keep!r}")

    # Restart policy for the VM service. "always" (default) treats a guest
    # reboot — which QEMU's -no-reboot turns into a clean exit — as a reason to
    # relaunch; "on-failure" keeps the VM down on a clean exit; "on-reboot" is
    # reserved for reason-aware restart (not implemented yet; falls back to
    # "always"). See generate_vm_service.
    restart = vm.get("restart", "always")
    if restart not in ("always", "on-failure", "on-reboot"):
        errors.append(
            "[vm].restart must be one of 'always', 'on-failure', 'on-reboot', "
            f"got {restart!r}"
        )

    errors.extend(validate_vm_network(vm.get("network", {})))

    # [vm.cloud_init] — optional override of the seed user-data.
    ci = vm.get("cloud_init", {})
    if ci:
        if not isinstance(ci, dict):
            errors.append("[vm.cloud_init] must be a table")
        else:
            ud = ci.get("user_data_file")
            if ud is not None and not isinstance(ud, str):
                errors.append(
                    f"[vm.cloud_init].user_data_file must be a string path, got {ud!r}"
                )
            tv = ci.get("template_vars", {})
            if not isinstance(tv, dict):
                errors.append("[vm.cloud_init].template_vars must be a table of strings")
            else:
                for k, v in tv.items():
                    if not isinstance(v, (str, int, float, bool)):
                        errors.append(
                            f"[vm.cloud_init].template_vars.{k} must be a scalar, got {type(v).__name__}"
                        )

    # Disk sizes are passed verbatim to `qemu-img create`/`resize`, which reads
    # a bare number as *bytes*. Require an explicit unit so a typo like "60"
    # isn't silently interpreted as a 60-byte disk (failing only at build time).
    for key in ("system_disk_size", "data_disk_size"):
        size = vm.get(key)
        if size is not None and (
            not isinstance(size, str)
            or not re.match(r"^\d+(\.\d+)?[KkMmGgTtPp]i?B?$", size)
        ):
            errors.append(
                f"[vm].{key} must be a size with a unit suffix "
                f"(e.g. '40G', '512M'), got {size!r}"
            )

    balloon = vm.get("balloon")
    if balloon is not None and not isinstance(balloon, bool):
        errors.append(f"[vm].balloon must be a boolean, got {balloon!r}")

    volumes = vm.get("volumes", [])
    if not isinstance(volumes, list):
        errors.append(
            f"[vm].volumes must be an array of 'host:guest[:opts]' strings, "
            f"got {type(volumes).__name__}"
        )
    else:
        for v in volumes:
            if not isinstance(v, str):
                errors.append(f"[vm].volumes entries must be strings, got {v!r}")
                continue
            host, guest, _ = parse_volume_spec(v)
            if not host or not guest:
                errors.append(
                    f"[vm].volumes entry {v!r} must have non-empty host and guest "
                    "paths (format 'host:guest[:opts]')"
                )

    return errors
