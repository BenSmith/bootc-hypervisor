"""
VM-workload constants, helpers, and schema validation.

Everything specific to `[vm]` workloads: the uid-derived passt network identity,
OVMF firmware discovery, MAC derivation, memory parsing, and the [vm]-section
validator. Kept separate from the container path so the VM surface is legible
on its own.

Installed to /usr/libexec/workloadctl/vm.py.
"""

import fnmatch
import hashlib
import ipaddress
import os
import re
import socket
from pathlib import Path
from typing import NamedTuple

from workload_lib import UID_MAX, UID_MIN, parse_volume_spec


# --- VM constants ---

# Runtime socket directory for VM workloads: /run/workload-vm/{name}/
VM_SOCKET_DIR = Path("/run/workload-vm")

# The SELinux type that directory must carry, and the fcontext pattern the RPM's
# %post registers to give it that type. A confined QEMU cannot create a socket
# under /run's default var_run_t, so without this the guest dies before it binds
# QMP and the only symptom is a timeout that names nothing SELinux.
#
# Two spellings, both needed. svirt_var_run_t is an ALIAS: it is what the rule
# is written with (and what the policy and every doc call it), but the kernel
# stores the real name, so getfattr, `ls -Z` and matchpathcon all report
# qemu_var_run_t. A label comparison that knows only one of them is wrong half
# the time, which is why the check below accepts either.
VM_SOCKET_SELINUX_TYPE = "svirt_var_run_t"
VM_SOCKET_SELINUX_TYPE_REAL = "qemu_var_run_t"
VM_SOCKET_FCONTEXT_PATTERN = f"{VM_SOCKET_DIR}(/.*)?"

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

# The guest login account when [vm].user is unset, and where cloud-init puts its
# home. Both halves matter to workload-ensure-user: it renders the account into
# the built-in cloud-config AND has to recognise a [vm].volumes share mounted at
# that home, which would otherwise hide the authorized_keys the CLI logs in with
# (seed_vm_home_share_ssh_key; docs/vm-virtiofs.md §8).
VM_DEFAULT_GUEST_USER = "workload"
VM_GUEST_HOME_BASE = "/home"

# --- passt networking (ADR 006) ---
#
# The inspector's listening addresses. The inspector cannot live on the
# workload's management address in 127/8: guest traffic is re-originated by
# passt toward a REMOTE address, so a DNAT to 127/8 is martian at the default
# and the packets vanish — making it work needs net.ipv4.conf.*.route_localnet=
# 1, a host-wide loosening of martian filtering. Instead the inspector binds a
# uid-derived address on the shared `workload-proxy` dummy link, in
# 198.18.0.0/16 (RFC 2544 benchmarking space, not routable), with an IPv6 twin
# in 2001:2::/48 (RFC 5180, the exact v6 counterpart). The address is on a
# dummy link and therefore local, so no sysctl is involved. The offset
# arithmetic is the same vm_management_address uses against 127.128.0.0.
#
# The base is 198.18.1.0 rather than 198.18.0.0 for the reason NFLOG_GROUP_BASE
# is 1000 rather than 0: a bare offset lands the *first* workload allocated on
# any host on the range's own network address, which is the value everything
# else defaults to. Harmless while each address is a /32 and a latent
# confusion the day anyone assigns or matches the range as a /16.
VM_INSPECT_ADDR_BASE = 0xC6120100  # 198.18.1.0

# The whole reservation, not just the allocated part — the range the filter's
# guards name. 42,949 workloads fit inside the /16's 65,536, so uniqueness is
# inherited from the uid allocator exactly as vm_management_address's is.
VM_INSPECT_NETWORK = ipaddress.ip_network("198.18.0.0/16")

# The v6 twin's prefix. The v4 address is embedded in its low 32 bits, so one
# derivation feeds both families and the two listener addresses carry the same
# number — an address in a log or a .nft element says which workload it is.
#
# No base/reservation split here the way the v4 side has: the v6 is derived by
# OR-ing the v4 into this prefix, so it inherits both the base offset and the
# whole-range boundary from the v4 and one prefix plays both roles.
VM_INSPECT_ADDR6_PREFIX = ipaddress.ip_network("2001:2::/48")

# The two listener ports, selected by the redirected connection's ORIGINAL port
# via the DNAT map rather than recovered by the inspector: a guest dial to 80
# lands here cleartext (the Host header carries the name) and one to 443 here
# under TLS (the SNI in the ClientHello). The socket that accepted the
# connection tells the inspector which it is, so SO_ORIGINAL_DST is not needed.
VM_INSPECT_PORT_CLEARTEXT = 8080
VM_INSPECT_PORT_TLS = 8443

# The two ORIGINAL ports the redirect matches and the map keys on: a guest dial
# to 80 or one to 443. Fixed by the redirect rules in workload-proxy.nft; they
# never appear in an element value, which is why the constants live beside the
# listener ports they select. 443 is spelled rather than aliased to
# VM_PROXY_PORT_HTTPS: that constant is tinyproxy's CONNECT restriction, and an
# alias would tie the redirect's key to a policy directive of a service it
# replaces (rung 2).
VM_INSPECT_ORIG_CLEARTEXT = 80
VM_INSPECT_ORIG_TLS = 443

# The inspector's listener binary, the socket unit's ExecStart. It does not
# exist yet (T5b); naming it here keeps the unit and the RPM one place apart.
VM_INSPECT_LISTENER_BIN = "/usr/libexec/workloadctl/workload-vm-inspect-listener"

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

# The whole reservation, not just the allocated part. `ports` may otherwise name
# any bind address, and one naming another workload's management address has
# passt publish a guest port where that workload's SSH listener belongs — with
# start order deciding the winner. The host-key pin stops that short of a session
# in the wrong guest, but a plane documented as never configurable should not be
# reachable from a config key.
#
# It is /9 rather than the /16 the management addresses actually occupy, and the
# extra bits are load-bearing rather than slack: everything else this design
# hangs on loopback is carved out of the same range (§9's synthesising responder
# is next), so a narrowing pass that "tidied" this to 127.128.0.0/16 would take
# the reservation away from planes that never had one of their own. The
# reservation is enforced through VM_RESERVED_PLANES, which is where a new plane
# is added — not by widening or narrowing this.
VM_MGMT_NETWORK = ipaddress.ip_network("127.128.0.0/9")

# Port passt forwards to the guest's sshd for `workloadctl exec` / `shell`.
# Fixed, never configurable, and bound only on the workload's own management
# address. It must stay above net.ipv4.ip_unprivileged_port_start (1024 by
# default) because passt binds it as the workload user, not as root — which is
# why this is 2222 and not 22.
VM_MGMT_SSH_PORT = 2222

# Base of the per-workload nflog group range, for the same reason the management
# addresses start at 127.128.0.0 rather than 127.0.0.0: a bare `uid - UID_MIN`
# lands the first workload on group 0, which is the netfilter default. See
# vm_nflog_group. 1000 + 42,948 = 43,948, inside the 16-bit group space.
NFLOG_GROUP_BASE = 1000

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


class VmInspectAddress(NamedTuple):
    """The inspector's listening addresses for one workload, one field per family.

    Both fields are str, the shape the .nft elements want.
    """
    v4: str
    v6: str


def vm_inspect_address(uid: int) -> VmInspectAddress:
    """The inspector's listening addresses, (IPv4, IPv6), for this workload.

    The transparent redirect rewrites a guest dial to 80 or 443 onto these. They
    are not loopback (unlike vm_management_address): the inspector binds them on
    the shared `workload-proxy` dummy link, in 198.18.0.0/16 and 2001:2::/48,
    because guest traffic re-originated by passt toward a remote address cannot
    be DNATed to 127/8 without a host-wide sysctl. The v6 twin embeds the v4
    address in its low 32 bits, so the two carry the same number.

    Derived from the uid, so uniqueness is inherited from the uid allocator:
    no registry, no allocation step, and no collision. uid 10000 -> 198.18.1.0 /
    2001:2::c612:100.
    """
    if uid < UID_MIN or uid > UID_MAX:
        raise ValueError(
            f"UID {uid} is outside the workload range {UID_MIN}-{UID_MAX}; "
            f"no inspector address is derivable for it")
    v4 = ipaddress.IPv4Address(VM_INSPECT_ADDR_BASE + (uid - UID_MIN))
    v6 = ipaddress.IPv6Address(
        int(VM_INSPECT_ADDR6_PREFIX.network_address) | int(v4))
    return VmInspectAddress(str(v4), str(v6))


def vm_nflog_group(uid: int) -> int:
    """The workload's nflog group, for per-workload host-side packet capture.

    Same derivation and same guarantee as vm_management_address — the offset
    into the workload uid range — but offset by a base, for the reason that one
    starts at 127.128.0.0 rather than at 127.0.0.0.

    A bare offset put the FIRST workload allocated on any host on group 0, which
    is iptables' `--nflog-group` default and the group stock ulogd
    configurations bind. Nothing crashes — 0 is a valid group — but the two
    consumers see each other's packets: a site's logged traffic lands in that
    workload's capture attributed to it, and the workload's traffic lands in the
    site's host-wide log. Neither side is told. The capture direction would not
    even warn, since report_completeness only speaks up when a file holds FEWER
    packets than the kernel counter matched, and this gives it more.

    Base 1000 clears the small numbers convention uses (0 for the iptables
    default, 1 and 2 in ulogd's shipped examples) by two orders of magnitude.
    The range becomes 1000-43948, still inside the 16-bit group space with
    21,587 to spare, and nothing else changes: the value is still a pure
    function of the uid, with no registry and no allocation step.
    """
    if uid < UID_MIN or uid > UID_MAX:
        raise ValueError(
            f"UID {uid} is outside the workload range {UID_MIN}-{UID_MAX}; "
            f"no nflog group is derivable for it")
    return NFLOG_GROUP_BASE + (uid - UID_MIN)


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

# What a filtered workload's redirected TLS connections get. `splice` is the
# whole of rung 2: the inspector reads the ClientHello's SNI, matches it against
# `hosts`, and then replays those exact bytes upstream — nothing is decrypted
# and no CA exists. `inspect` is named here rather than merely absent from the
# accepted set, so the refusal can say WHEN it arrives instead of listing valid
# values: a config asking for inspection is asking for a property, and a key
# that accepted the word and quietly spliced would be a config claiming a
# property it does not have.
VM_TLS_MODES = ("splice",)
VM_TLS_DEFAULT = "splice"
VM_TLS_UNBUILT = {"inspect": "rung 3, with the CA the guest has to trust"}

# Parents anyone can register a label under, where a wildcard in a host list
# authorises a name the *guest* chooses. Warning-only, deliberately: the list
# cannot be exhaustive, and a stale copy shipped in an RPM that hard-fails a
# valid config is worse than a line of output.
VM_REGISTRATION_DOMAIN_PARENTS = (
    "github.io", "gitlab.io", "pages.dev", "workers.dev", "netlify.app",
    "vercel.app", "herokuapp.com", "azurewebsites.net", "cloudfront.net",
    "web.app", "firebaseapp.com", "blogspot.com", "wordpress.com",
    "s3.amazonaws.com", "r2.dev", "ngrok.io", "trycloudflare.com",
)

# The uid-keyed egress layer (ADR 006 §4). One table shared by every VM;
# units manage set *elements* only, never rules.
NFT_BIN = "/usr/sbin/nft"
IP_BIN = "/usr/sbin/ip"
NFT_TABLE = "inet workload_filter"
NFT_SET_FILTERED = "wl_filtered"
NFT_SET_ALLOW4 = "wl_allow4"
NFT_SET_ALLOW6 = "wl_allow6"
# Internal destination prefixes the hostname proxy may not connect OUT to. The
# elements are constant and live in the skeleton, not here -- nothing in Python
# manages them. The names exist so tests can name the sets and so
# `vm_egress_check` can tell a loaded guard from a table that predates it,
# which it cannot infer from wl_filtered membership: nft state is kernel state
# until reboot, so a VM started before an upgrade keeps the older chain.
NFT_SET_INTERNAL4 = "wl_internal4"
NFT_SET_INTERNAL6 = "wl_internal6"
# The per-workload exceptions to those drops -- [[vm.network.internal]]. Per
# workload, so unlike the interval sets above these ARE managed from Python and
# are never flushed by the skeleton.
NFT_SET_INTERNAL_OK4 = "wl_internal_ok4"
NFT_SET_INTERNAL_OK6 = "wl_internal_ok6"

# The private ranges the skeleton's internal drop matches on, restated here so
# the arming path can refuse an element the drop would never have caught.
#
# Duplicating them is the lesser evil and the test is what makes it safe:
# tests/test_vm_egress.py asserts these against the elements the .nft actually
# arms, so a range added on one side and not the other fails rather than
# silently making the refusal wrong. Parsing the .nft at runtime was the
# alternative and it puts a parser on the start path of every VM to answer a
# question about a constant.
VM_INTERNAL_PREFIXES4 = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "255.255.255.255",
)
VM_INTERNAL_PREFIXES6 = (
    "::/128", "::1/128", "::ffff:0.0.0.0/96", "64:ff9b::/96",
    "64:ff9b:1::/48", "2002::/16", "fc00::/7", "fe80::/10",
)
# The inspector's listener-plane guard sets (§7.2/§7.2.1/§7.2.3). Elements are
# per workload and are armed by the same script that arms the DNAT maps, not
# by the filter helper: the dst sets hold the TRANSLATED tuple, which only the
# redirect's installer knows. The self sets carry a per-element counter —
# the load-bearing half, since it is what attributes a wrong-port self-dial to
# its workload instead of the range guard's shared number. None of the four
# is flushed in the skeleton; the two that hold per-workload state are never
# emptied by it.
NFT_SET_INSPECT_DST = "wl_inspect_dst"
NFT_SET_INSPECT_DST6 = "wl_inspect_dst6"
NFT_SET_INSPECT_SELF = "wl_inspect_self"
NFT_SET_INSPECT_SELF6 = "wl_inspect_self6"
NFT_SKELETON = "/usr/share/workloadctl/workload-filter.nft"


def vm_filter_elements(uid: int, allow: list[str],
                       resolved=None) -> dict[str, list[str]]:
    """Map set name -> element expressions for one workload.

    `resolved` is the output of vm_allow_resolved for this same `allow`, when
    the caller has one. It exists because the synthesising responder answers
    named `allow` destinations with the addresses that were ARMED, and a second
    independent resolution is a different question asked of the same name: a
    round-robin or a short-TTL record can answer differently a millisecond
    later, and the guest is then sent to an address that is not in the set --
    which presents as the guest hanging against the default-deny drop, not as a
    refusal. Passing one resolution to both consumers is what makes the
    host-side answer and the guest-side answer the same answer. Omitted, this
    resolves for itself, so every existing caller is unchanged.

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
    if resolved is None:
        resolved = vm_allow_resolved(allow)
    for entry, addresses in resolved:
        for addr in addresses:
            # The listener-plane refusal, applied on this side of the
            # resolution too. parse_vm_allow cannot make it for a name -- it
            # deliberately does not resolve -- so a name pointed at another
            # workload's inspector would otherwise arm the exact element the
            # address form is refused for.
            reserved = vm_allow_reserved_reason(addr)
            if reserved:
                where = f"{entry.host!r} resolves there — " if entry.host else ""
                raise ValueError(f"[vm.network].allow: {where}{reserved}")
            (v6 if addr.version == 6 else v4).append(
                f"{uid} . {addr} . {entry.port}")
    if v4:
        elements[NFT_SET_ALLOW4] = v4
    if v6:
        elements[NFT_SET_ALLOW6] = v6
    return elements


NFT_SETS = (NFT_SET_FILTERED, NFT_SET_ALLOW4, NFT_SET_ALLOW6)


# --- Hostname policy: the per-workload proxy (ADR 006 §4.4) ---
#
# Kernel rules match addresses; policy is written about names. Rather than
# resolve names to addresses at rule-install time — which races DNS, breaks on
# CDN churn, and opens everything sharing an address — an HTTP forward proxy
# reads `CONNECT host:443` in plaintext before any TLS handshake and allowlists
# the hostname directly, with no interception and no CA.
#
# One tinyproxy instance per workload, because tinyproxy's filter directives are
# instance-global. Each runs as _wl-<name>, so its own outbound traffic carries
# the same uid as the guest's and one `meta skuid` rule governs both the direct
# and the via-proxy path. The proxy is a policy layer, not a second trust domain.
#
# What binds it: a proxy alone is advisory, since a guest process that ignores
# HTTPS_PROXY simply does not use it. The default-deny output chain is what
# makes it mandatory — the uncooperative process has nowhere else to go.

# The address every guest is told to use. It is the same for every workload on
# purpose: the redirect is keyed on uid, so one advertised endpoint reaches N
# private listeners and every guest's cloud-init is identical. Two host
# addresses are ruled out by §3.5 — host loopback is unreachable by design, and
# the host's default-route address is structurally unreachable because passt
# assigns the guest that same address — so it has to be some other host address.
#
# TEST-NET-1 is reserved for documentation and can never be a destination a
# guest legitimately wants, and a dummy link keeps it off every real NIC and
# inert when nothing is running.
#
# Deliberately a constant rather than a schema key, which is a documented
# deviation from the design: the address belongs to a host-global interface, so
# a per-workload key would let two workloads disagree about a shared object —
# the last-write-wins hazard ADR 002 exists to describe and this design deleted
# along with the bridge. A site that genuinely uses TEST-NET-1 internally should
# use `allow` and skip hostname policy; see docs/workloads.md.
VM_PROXY_ADDR = "192.0.2.1"
VM_PROXY_PORT = 3128

# What [vm.cloud_init].seed_provides may name — the concerns a custom seed can
# declare it handles itself, suppressing the matching completeness check in
# build_cloud_init_iso.
SEED_PROVIDES_CHOICES = {"proxy", "mounts"}

# workload-ensure-user exits with this when a custom seed fails one of the
# contracts build_cloud_init_iso enforces (host key, proxy env, volume mounts).
# Distinct from a plain 1 so the caller can tell "the operator's seed is wrong,
# and the helper already said how" from "the helper broke": provisioning maps
# it to UsageError, which keeps the CLI's bug-report banner — and the traceback
# it prints — off an error the operator is expected to hit and can fix.
VM_SEED_CONTRACT_EXIT = 2


class SeedContractError(RuntimeError):
    """A custom [vm.cloud_init].user_data_file does not satisfy a contract the
    built-in seed would have satisfied. The message is written for the operator
    and names the fix."""

# Dummy link carrying the advertised address. Host-global and shared, created
# on demand and never torn down by a workload stop: it is refcount-free because
# it holds no per-workload state, costs nothing idle, and an orphan is inert.
VM_PROXY_IFACE = "workload-proxy"

VM_PROXY_BIN = "/usr/bin/tinyproxy"

# The proxy runs as the workload's own user by design, so `meta skuid` cannot
# separate its traffic from the guest's — and under default-deny the drop
# catches the proxy too, leaving hostname policy permitting nothing. The
# control group is the discriminator that survives the shared uid: systemd
# assigns it, a guest can neither enter nor forge it, and it widens no
# destination or port, so a guest that ignores the proxy and dials 443 directly
# is still dropped.
#
# The slice is pinned rather than taken from [resources].slice so the cgroup
# path is always exactly two components and the rule's `level 2` is exact. The
# proxy is not the payload; resource control belongs on the VM.
NFT_SET_PROXY_CG = "wl_proxy_cg"
VM_PROXY_SLICE = "workloads.slice"
NFT_PROXY_SKELETON = "/usr/share/workloadctl/workload-proxy.nft"
NFT_PROXY_TABLE = "inet workload_proxy"
NFT_PROXY_MAP = "wl_proxy_dest"

# The transparent redirect's objects (§7.1). The two maps carry one element per
# workload per redirected port, keyed uid . original port -> (listener address,
# listener port), one map per family because `dnat ip` and `dnat ip6` are
# different translations in the inet family; the set exempts the processes that
# re-originate workload-uid traffic so their own dials are not translated into
# the listener they are dialing past. All three live in table
# inet workload_proxy and are declared in workload-proxy.nft.
NFT_MAP_INSPECT4 = "wl_inspect4"
NFT_MAP_INSPECT6 = "wl_inspect6"
NFT_SET_INSPECT_CG = "wl_inspect_cg"

# tinyproxy's own client ACL. It must name the advertised address, not just
# loopback: the guest's packet is routed to 192.0.2.1 before it is translated,
# so the host picks that same address as the source and the proxy sees a client
# connecting *from* 192.0.2.1. Omit it and every request answers 403 while the
# listener, the redirect and the guest all look healthy — the failure logs only
# as tinyproxy's "Unauthorized connection from".
VM_PROXY_ALLOWED_CLIENTS = ("127.0.0.0/8", VM_PROXY_ADDR)

# The only port CONNECT may target. Without a ConnectPort directive tinyproxy
# permits CONNECT to any port, which would turn the proxy into a general TCP
# tunnel out of the guest and undo the egress policy it exists to express.
VM_PROXY_PORT_HTTPS = 443


def vm_proxy_hosts(net: dict) -> list[str]:
    """The hostname allowlist for one workload, or [] if it has none."""
    hosts = net.get("hosts", [])
    return list(hosts) if isinstance(hosts, list) else []


def vm_uses_proxy(config: dict) -> bool:
    """Whether this workload gets a proxy instance.

    Keyed on `hosts` being non-empty rather than on a separate enable flag, so
    the schema cannot express "proxy on, allowlist empty" — an instance that
    permits nothing, which is indistinguishable from a broken one. A bridged VM
    is outside all of this (§5.3): nothing of ours is in its data path, so there
    is no uid to key the redirect on.
    """
    vm_cfg = config.get("vm", {}) or {}
    net = vm_cfg.get("network", {}) or {}
    if not isinstance(net, dict) or net.get("bridge"):
        return False
    return bool(vm_proxy_hosts(net))


def vm_uses_inspect(config: dict) -> bool:
    """Whether this workload's egress is redirected into an inspector.

    The single source of the predicate that decides whether the inspect
    socket/service units exist at all: not bridged (a bridged guest has no
    host socket in its data path, so there is no uid to key the redirect on)
    and `egress` filtered (an unfiltered VM would be the one the redirect
    breaks — its dial to a port-443 service it is allowed to reach would be
    translated into a listener that would refuse it, having no policy naming
    it). `workload-vm-inspect`'s
    inspection_applies delegates here rather than re-stating it, so the
    generator and the helper cannot drift apart.

    A workload with no [vm] section is not a VM and is never inspected. That is
    tested here rather than left to the callers: every caller happens to be
    behind a VM-only branch today, so a container config reaching this returned
    True and nothing noticed. A predicate documented as the single source of a
    decision has to be right standing alone, or the next caller inherits a bug
    that reads as correct at its own call site.
    """
    if "vm" not in config:
        return False
    vm_cfg = config.get("vm", {}) or {}
    net = vm_cfg.get("network", {}) or {}
    if not isinstance(net, dict) or net.get("bridge"):
        return False
    return net.get("egress", VM_EGRESS_DEFAULT) == "filtered"


def vm_proxy_runtime_dir(name: str) -> str:
    """Where one instance's config, allowlist, log and pid file live."""
    return f"{VM_SOCKET_DIR}/{name}"


def vm_proxy_config(name: str, listen_addr: str, hosts: list[str]) -> str:
    """The tinyproxy.conf for one workload.

    FilterDefaultDeny is the whole point: without it the Filter file is a
    denylist and an unlisted host is permitted. FilterURLs stays off so the
    pattern matches the host, which is all a CONNECT carries anyway.
    """
    rt = vm_proxy_runtime_dir(name)
    lines = [
        f"# tinyproxy for workload {name} — generated by workloadctl, do not edit.",
        f"Listen {listen_addr}",
        f"Port {VM_PROXY_PORT}",
        "Timeout 600",
        f'PidFile "{rt}/tinyproxy.pid"',
        f'LogFile "{rt}/tinyproxy.log"',
        "LogLevel Info",
        "MaxClients 64",
        "DisableViaHeader Yes",
    ]
    lines += [f"Allow {client}" for client in VM_PROXY_ALLOWED_CLIENTS]
    lines += [
        f"ConnectPort {VM_PROXY_PORT_HTTPS}",
        f'Filter "{rt}/hosts.allow"',
        "FilterType fnmatch",
        "FilterURLs Off",
        "FilterDefaultDeny Yes",
        "",
    ]
    return "\n".join(lines)


def vm_proxy_filter_file(hosts: list[str]) -> str:
    """The hostname allowlist file. fnmatch patterns, one per line."""
    return "".join(f"{host}\n" for host in hosts)


# --- The inspector's policy document (§7.7.1, §13) ---
#
# The listener is socket-activated and long-lived, so it reads its lists once,
# at start, out of the workload's runtime directory — the same place and the
# same moment as tinyproxy's generated config, and for the same reason: /run
# does not exist when the boot generator runs, and writing at start is what
# makes an edited list take effect on a plain `systemctl restart` with no
# regeneration. §13 states that recovery property, and the inspect service's
# PartOf= on the VM is what enforces it; a listener that held its lists in a
# file written at generate time would keep enforcing the previous boot's policy.
#
# JSON rather than a bare line-per-pattern file like hosts.allow, because this
# document carries a mode as well as a list and will carry more of both.
VM_INSPECT_POLICY_FILE = "inspect.json"


def vm_inspect_policy_path(name: str) -> str:
    """Where one workload's inspector reads its lists from."""
    return f"{VM_SOCKET_DIR}/{name}/{VM_INSPECT_POLICY_FILE}"


VM_INSPECT_STATUS_FILE = "inspect-status.json"
VM_RESOLVE_STATUS_FILE = "resolve-status.json"


def vm_inspect_status_path(name: str) -> str:
    """Where one workload's inspector writes its counters.

    Two status files rather than one, and lib/vm_status.py carries the
    argument: the responder is a separate socket-activated process, and two
    processes atomically replacing one path leaves only the last writer's
    figures, silently.
    """
    return f"{VM_SOCKET_DIR}/{name}/{VM_INSPECT_STATUS_FILE}"


def vm_resolve_status_path(name: str) -> str:
    """Where one workload's responder writes its counters."""
    return f"{VM_SOCKET_DIR}/{name}/{VM_RESOLVE_STATUS_FILE}"


def vm_inspect_policy(net: dict) -> dict:
    """The inspector's policy document for one workload.

    `hosts` is the same list tinyproxy is given, deliberately: at this rung the
    two enforce the same patterns by two mechanisms, and generating them from
    one source is what keeps a redirected connection and a proxied one making
    the same decision.

    `internal` is carried and AUTHORISES NOTHING. An `internal` entry names a
    host that is already on a list (validation refuses one that is not), and it
    excepts the inspector's *upstream* leg from the internal drop rather than
    authorising a name. The listener never consults it to admit a connection:
    the kernel's wl_internal_ok4/6 elements are the one enforcement point, and a
    second one in userspace could disagree with them while both looked right.

    It is here so that a FAILED upstream dial to a private address can be
    attributed. An allowlisted name that resolved into private space with no
    entry is the wildcard trap firing; one WITH an entry is a host that is
    simply down. Those are the same OSError without this list, and telling them
    apart is the whole value of the internal-refusal counter.
    """
    return {
        "tls": net.get("tls", VM_TLS_DEFAULT),
        "hosts": vm_proxy_hosts(net),
        "internal": vm_internal_hosts(net),
    }


def vm_normalise_hostname(host: str) -> str:
    """A hostname in the one form every match in this design is made against.

    Lowercased and stripped of a single trailing root dot. Both halves matter:
    DNS names are case-insensitive, and `example.com.` and `example.com` are the
    same name — a guest that writes either spelling must get the same decision,
    or the spelling becomes the bypass.
    """
    host = host.strip().lower()
    return host[:-1] if host.endswith(".") and host != "." else host


def vm_hostname_match(host: str, patterns) -> bool:
    """Whether a hostname is authorised by a list of fnmatch patterns.

    `fnmatch.fnmatchcase`, not `fnmatch.fnmatch`. The plain form normalises its
    arguments through os.path.normcase, which is a no-op on Linux and lowercases
    on other platforms — so it is case-insensitive only by accident of platform,
    and the operators' patterns are the ones tinyproxy already matches. Both
    sides are normalised here instead, which is the same answer everywhere.

    The apex trap is preserved, not fixed: `*.example.com` does not authorise
    `example.com`. That is fnmatch's behaviour, it is what tinyproxy does with
    the same list today, and three tracked files document it. A rung that
    quietly widened it would silently grant every existing config a destination
    its operator did not write down.
    """
    host = vm_normalise_hostname(host)
    if not host:
        return False
    return any(fnmatch.fnmatchcase(host, vm_normalise_hostname(p))
               for p in patterns)


def vm_proxy_element(uid: int, listen_addr: str) -> str:
    """This workload's element in the uid -> listener map."""
    return f"{uid} : {listen_addr} . {VM_PROXY_PORT}"


def vm_proxy_map_command(uid: int, listen_addr: str, action: str) -> list[str]:
    """`nft add|delete element` for one workload's redirect."""
    return [NFT_BIN, action, "element", *NFT_PROXY_TABLE.split(), NFT_PROXY_MAP,
            "{ " + vm_proxy_element(uid, listen_addr) + " }"]


def vm_proxy_cgroup(name: str) -> str:
    """The control group path of one workload's proxy unit."""
    return f"{VM_PROXY_SLICE}/workload-{name}-proxy.service"


def vm_proxy_cgroup_command(name: str, action: str) -> list[str]:
    """`nft add|delete element` for one proxy's egress exemption.

    The element lives in the *filter* table, not the proxy table: the rule it
    feeds has to sit in the output chain ahead of the drop, and that chain is
    the filter skeleton's.
    """
    return [NFT_BIN, action, "element", *NFT_TABLE.split(), NFT_SET_PROXY_CG,
            '{ "' + vm_proxy_cgroup(name) + '" }']


def vm_proxy_cgroup_inspect_command(name: str, action: str) -> list[str]:
    """`nft add|delete element` putting one proxy's cgroup into the *nat* return set.

    The missing corner of the table vm_proxy_cgroup_command fills: same cgroup
    as that one, but in the *proxy* table's wl_inspect_cg — the opposite of
    vm_proxy_cgroup_command, the twin of vm_inspect_cgroup_command, whose other
    member names the proxy unit rather than the inspector's.

    wl_inspect_cg's name misleads: it is not "the inspector's cgroup". It is
    every workload-uid process that *re-originates* guest traffic rather than
    emitting it — during rung 1 there are two, the inspector and tinyproxy's
    upstream CONNECT leg. That leg is `tcp dport 443` from the workload uid, so
    without this element the transparent redirect rewrites it into the
    inspector's listener, and every proxied HTTPS request on every filtered VM
    breaks. Rung 2 removes tinyproxy and with it this element.

    The proxy unit's start applies both skeletons, so the table exists before
    the add; its ExecStopPost removes it, for the same cgroup-id reason the
    sibling delete in the filter table is owed by that unit's stop.
    """
    return [NFT_BIN, action, "element", *NFT_PROXY_TABLE.split(),
            NFT_SET_INSPECT_CG, '{ "' + vm_proxy_cgroup(name) + '" }']


# --- The transparent redirect's per-workload elements (§7.1, §7.2) ---
#
# Six objects, two per family, are what makes a redirected guest connection
# actually reach a working listener and nothing else: the two DNAT map elements
# (the redirect itself), the two accept-set elements (the redirected connection
# is admitted by its TRANSLATED tuple, because the filter hook runs after
# dstnat) and the two wrong-port drop-set elements (the per-element counter is
# what gives the guard its per-workload attribution). The maps live in
# inet workload_proxy, the sets in inet workload_filter: a helper that arms one
# table and not the other leaves a workload that looks configured and reaches
# nothing, so the builder returns both families' commands in one shape.

def vm_inspect_map_elements(uid: int) -> dict[str, list[str]]:
    """The DNAT map elements for one workload, map name -> element strings.

    Two per family, one per redirected port: the concatenated key is uid .
    ORIGINAL port, so the map itself selects the listener port and the socket
    that accepted the connection tells the inspector whether it is TLS or
    cleartext. The value is (listener address, listener port); the advertised
    address never appears in an element, for the reason
    vm_broker_element's carries.
    """
    addr = vm_inspect_address(uid)
    return {
        NFT_MAP_INSPECT4: [
            f"{uid} . {VM_INSPECT_ORIG_CLEARTEXT} : {addr.v4} . {VM_INSPECT_PORT_CLEARTEXT}",
            f"{uid} . {VM_INSPECT_ORIG_TLS} : {addr.v4} . {VM_INSPECT_PORT_TLS}",
        ],
        NFT_MAP_INSPECT6: [
            f"{uid} . {VM_INSPECT_ORIG_CLEARTEXT} : {addr.v6} . {VM_INSPECT_PORT_CLEARTEXT}",
            f"{uid} . {VM_INSPECT_ORIG_TLS} : {addr.v6} . {VM_INSPECT_PORT_TLS}",
        ],
    }


def vm_inspect_dst_elements(uid: int) -> dict[str, list[str]]:
    """The accept-set elements, holding the TRANSLATED tuple.

    Same shape as the maps but keyed on the destination the filter chain sees,
    which is the DNAT-rewritten one: an element naming the original 80/443 would
    match nothing (measured; §7.2) and the redirected connection would fall
    through to the default drop.
    """
    addr = vm_inspect_address(uid)
    return {
        NFT_SET_INSPECT_DST: [
            f"{uid} . {addr.v4} . {VM_INSPECT_PORT_CLEARTEXT}",
            f"{uid} . {addr.v4} . {VM_INSPECT_PORT_TLS}",
        ],
        NFT_SET_INSPECT_DST6: [
            f"{uid} . {addr.v6} . {VM_INSPECT_PORT_CLEARTEXT}",
            f"{uid} . {addr.v6} . {VM_INSPECT_PORT_TLS}",
        ],
    }


def vm_inspect_self_elements(uid: int) -> dict[str, list[str]]:
    """The wrong-port drop-set elements, one per family.

    Keyed on uid and listener address with NO port: their whole purpose is to
    catch dials to ports nothing serves, and naming a port would make exactly
    those unreachable. The rule is already in the skeleton; the element is per
    workload and is armed here, and it is what gives the guard's counter its
    per-workload attribution.
    """
    addr = vm_inspect_address(uid)
    return {
        NFT_SET_INSPECT_SELF: [f"{uid} . {addr.v4}"],
        NFT_SET_INSPECT_SELF6: [f"{uid} . {addr.v6}"],
    }


def vm_inspect_element_commands(uid: int, action: str) -> list[list[str]]:
    """argv lists arming ("add") or disarming ("delete") all six elements.

    Two families, three objects each, in a fixed order: both DNAT maps (in
    inet workload_proxy), both accept sets and both wrong-port sets (in inet
    workload_filter). One argv per object, because an object's elements belong
    to one table and one transaction, and the six span two tables.

    A helper that arms one table and not the other leaves a workload that looks
    configured and reaches nothing: the redirect without the accept set drops
    the redirected connection, the accept set without the redirect never
    matches. Both tables or neither, which is why the caller runs every argv it
    gets and fails the start if any one of them does not.
    """
    if action not in ("add", "delete"):
        raise ValueError(f"action must be 'add' or 'delete', got {action!r}")
    commands = []
    groups = (
        (NFT_PROXY_TABLE, vm_inspect_map_elements(uid)),
        (NFT_TABLE, vm_inspect_dst_elements(uid)),
        (NFT_TABLE, vm_inspect_self_elements(uid)),
    )
    for table, elements in groups:
        for set_name, entries in elements.items():
            commands.append([NFT_BIN, action, "element", *table.split(),
                             set_name, "{ " + ", ".join(entries) + " }"])
    return commands


def vm_internal_reserved_reason(
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Why this address may not be armed as an `internal` exemption, or None.

    The mirror of vm_allow_reserved_reason, and the same shape of foot-gun seen
    from the other side: arm only addresses the internal drop would actually
    have caught. An element for a public address excepts a drop that was never
    going to fire on it, so the accept it installs is pure widening -- it grants
    the inspector an all-ports path to an address for no reason anybody reading
    the config could reconstruct.

    It is not a hole (the accept is still cgroup-scoped to the inspector), which
    is what makes it a refusal rather than a panic. But an exemption that
    excepts nothing is an operator's belief about where a name points, written
    down and wrong, and the failure it produces later is the interesting one:
    the name moves into private space, the drop starts firing, and the element
    that was supposed to cover it is for the old address.
    """
    prefixes = (VM_INTERNAL_PREFIXES4 if addr.version == 4
                else VM_INTERNAL_PREFIXES6)
    for prefix in prefixes:
        if addr in ipaddress.ip_network(prefix):
            return None
    return (f"{addr} is not in any range the internal-destination drop matches "
            f"({', '.join(prefixes)}), so an exemption for it excepts a drop "
            f"that would never have fired -- it only widens what the inspector "
            f"may open. An `internal` entry is for a name that resolves into "
            f"PRIVATE space; this one does not")


def vm_internal_ok_elements(
        uid: int,
        addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
) -> dict[str, list[str]]:
    """Map set name -> element expressions for one workload's `internal` hosts.

    Keyed on (uid, address) and carrying NO PORT: the exemption is about where
    a name resolves to, not about a service. What keeps that safe is the cgroup
    match on the rule consulting these sets -- see the comment block on it in
    workload-filter.nft. Read them together or the missing port reads as an
    oversight.

    Returns only non-empty sets, like vm_filter_elements, so a caller emits one
    command per family that has entries.
    """
    v4: list[str] = []
    v6: list[str] = []
    for addr in addresses:
        reserved = vm_internal_reserved_reason(addr)
        if reserved:
            raise ValueError(f"[vm.network].internal: {reserved}")
        (v6 if addr.version == 6 else v4).append(f"{uid} . {addr}")
    elements: dict[str, list[str]] = {}
    if v4:
        elements[NFT_SET_INTERNAL_OK4] = v4
    if v6:
        elements[NFT_SET_INTERNAL_OK6] = v6
    return elements


def vm_internal_ok_commands(
        uid: int,
        addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
        action: str,
) -> list[list[str]]:
    """argv lists that arm ("add") or disarm ("delete") the exemptions."""
    if action not in ("add", "delete"):
        raise ValueError(f"action must be 'add' or 'delete', got {action!r}")
    return [[NFT_BIN, action, "element", *NFT_TABLE.split(), set_name,
             "{ " + ", ".join(entries) + " }"]
            for set_name, entries in vm_internal_ok_elements(uid, addresses).items()]


def vm_internal_hosts(net: dict) -> list[str]:
    """The host names in [[vm.network.internal]], in file order.

    Shape-tolerant on purpose: this runs at VM start, where validation has
    already refused a malformed entry, and a helper that raised on one would
    turn an operator's typo into a workload that does not boot.
    """
    entries = net.get("internal", [])
    if not isinstance(entries, list):
        return []
    return [e["host"].strip() for e in entries
            if isinstance(e, dict) and isinstance(e.get("host"), str)
            and e["host"].strip()]


def vm_internal_resolve(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve one `internal` host, or raise ValueError naming it.

    Separate from vm_allow_resolve despite the identical mechanics, because the
    two fail differently and the message is the whole value: an unresolvable
    `allow` name leaves a service unreachable, while an unresolvable `internal`
    name leaves an allowlisted host refused by a drop the entry existed to
    except -- which surfaces as a 403 naming an internal address, not as a
    missing element.
    """
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(
            f"[vm.network].internal names {host!r}, which does not resolve on "
            f"this host ({exc}). The exemption is armed per ADDRESS, so an "
            f"unresolvable name arms nothing and the host stays refused by the "
            f"internal-destination drop the entry existed to except") from None
    seen: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if addr not in seen:
            seen.append(addr)
    return seen


def vm_inspect_cgroup(name: str) -> str:
    """The control group path of one workload's inspector unit.

    Follows vm_proxy_cgroup's shape: the pinned slice plus the unit name, so
    the path is always two components and the rule's `level 2` is exact. The
    element resolves a *path*, so the unit name here must match the service
    unit the inspector actually runs as — a service named -inspect with a
    cgroup element naming -inspector is a `return` rule that matches nothing
    and an inspector whose own egress is dropped. The premise it rests on is
    wired by generate_vm_inspect_service: the service unit is named
    workload-<name>-inspect.service and pins Slice=workloads.slice, which is
    what makes this path exact. tests/test_vm_inspect_units.py asserts the pin
    as a whole line, since a nested slice satisfies a substring match and
    silently deepens this path past `level 2`.
    """
    return f"{VM_PROXY_SLICE}/workload-{name}-inspect.service"


def vm_inspect_cgroup_command(name: str, action: str) -> list[str]:
    """`nft add|delete element` for one inspector's redirect exemption.

    The element lives in the *proxy* table, not the filter table — the
    opposite of vm_proxy_cgroup_command. Backwards, it fails only at load
    time with `did you mean set 'wl_proxy_cg' in table inet
    'workload_filter'?`: nftables sets are table-scoped, and wl_inspect_cg is
    declared in workload-proxy.nft next to the `return` rule it feeds.

    Armed by the inspector's own unit (ExecStartPre adds, ExecStopPost
    removes), emitted by generate_vm_inspect_service: an element resolves to a
    cgroup id at add time and systemd makes a fresh cgroup on every start, so
    the add belongs to the unit that owns the cgroup, not to the arming
    helper.
    """
    return [NFT_BIN, action, "element", *NFT_PROXY_TABLE.split(),
            NFT_SET_INSPECT_CG, '{ "' + vm_inspect_cgroup(name) + '" }']


def vm_inspect_cgroup_filter_command(name: str, action: str) -> list[str]:
    """`nft add|delete element` for one inspector's egress exemption.

    The twin of vm_inspect_cgroup_command in the *filter* table: the
    inspector runs as _wl-<name>, a filtered uid, so without its cgroup in
    wl_proxy_cg its own upstream connections hit the default-deny drop and it
    reaches nothing. The twin is owed by the same unit's start and stop as
    vm_inspect_cgroup_command's: a helper that does one of the two and not
    the other produces an inspector that either reaches nothing (this one
    missing) or redirects its own dials into itself (the other missing).
    """
    return [NFT_BIN, action, "element", *NFT_TABLE.split(), NFT_SET_PROXY_CG,
            '{ "' + vm_inspect_cgroup(name) + '" }']


def vm_proxy_env(config: dict) -> dict[str, str]:
    """The proxy environment a guest is told to use, or {} if it has none.

    NO_PROXY carries the guest's own view of the host and localhost so guest-local
    traffic does not loop out through the proxy. It is an IP literal throughout,
    which is what makes the proxy path free of any DNS dependency — DNS being
    precisely what a compromised guest would attack to escape hostname policy.

    The advertised address is in NO_PROXY too, and it is load-bearing rather
    than tidiness. Everything at that address is one of the host's own endpoints
    for this guest — the proxy itself, and the broker on another port — and a
    client that honours proxy variables would otherwise ask the proxy to fetch
    the broker for it. The proxy's allowlist holds hostnames a guest may reach
    on the internet and will not contain this address, so it answers 403: a
    refusal that reads exactly like the broker rejecting the caller, for a
    request that never reached the broker at all.
    """
    if not vm_uses_proxy(config):
        return {}
    url = f"http://{VM_PROXY_ADDR}:{VM_PROXY_PORT}"
    bypass = f"localhost,127.0.0.1,::1,{VM_PROXY_ADDR}"
    return {
        "http_proxy": url,
        "https_proxy": url,
        "HTTP_PROXY": url,
        "HTTPS_PROXY": url,
        "no_proxy": bypass,
        "NO_PROXY": bypass,
    }


# --- The credential broker endpoint ---
#
# A host-side service that holds a provider API key and forwards to exactly one
# upstream, so a sandboxed agent inside a guest never receives a credential. The
# guest points its client at an advertised endpoint; the broker attaches the
# real key on the way out.
#
# workloadctl owns reachability and nothing else. It does not start the broker,
# ship it, or know what a credential is: it adds this workload's element to the
# redirect map and tells the guest where to dial. The broker is one host service
# with its own unit and its own lifecycle.
#
# The advertised address is the proxy's, distinguished by port. One dummy link,
# one host address, two services — a second address would need a second
# interface to hang it on and would buy nothing, since the redirect is keyed on
# uid either way.
VM_BROKER_PORT = 8081

# Where the broker actually listens. This is the value every element carries, so
# it has to agree with the defaults `libexec/agent-broker` applies when an
# operator sets neither `listen_address` nor `listen_port` in broker.toml. That
# used to be a cross-repo constant checked by neither side; the broker ships in
# this package now, and tests/test_vm_broker.py asserts the two agree. Keep it
# that way -- a mismatch shows up as a guest connection refused after
# translation, which looks identical to the broker being down.
VM_BROKER_LISTEN_ADDR = "127.0.0.1"
VM_BROKER_LISTEN_PORT = 8081

NFT_BROKER_SKELETON = "/usr/share/workloadctl/workload-broker.nft"
NFT_BROKER_TABLE = "inet workload_broker"
NFT_BROKER_MAP = "wl_broker_dest"

# What the guest is told. Deliberately neutral rather than a provider's own
# base-URL variable: there is no universal spelling of one -- Node and Python
# clients disagree, and providers disagree with each other -- so naming a
# specific client's variable here would make workloadctl wrong for every other
# client. The guest image maps this to whatever its agent reads, which is one
# line of cloud-init and belongs with the software that has an opinion.
VM_BROKER_ENV_VAR = "WORKLOAD_BROKER_URL"


def vm_uses_broker(config: dict) -> bool:
    """Whether this workload gets a broker map element.

    A bridged VM is outside this for the same reason it is outside egress
    policy and the proxy (§5.3): nothing of ours is in its data path, so there
    is no uid to key the redirect on and no advertised address it can reach.
    """
    vm_cfg = config.get("vm", {}) or {}
    net = vm_cfg.get("network", {}) or {}
    if not isinstance(net, dict) or net.get("bridge"):
        return False
    return bool(net.get("broker"))


def vm_broker_element(uid: int) -> str:
    """This workload's element in the uid -> broker listener map."""
    return f"{uid} : {VM_BROKER_LISTEN_ADDR} . {VM_BROKER_LISTEN_PORT}"


def vm_broker_map_command(uid: int, action: str) -> list[str]:
    """`nft add|delete element` for one workload's broker redirect."""
    return [NFT_BIN, action, "element", *NFT_BROKER_TABLE.split(), NFT_BROKER_MAP,
            "{ " + vm_broker_element(uid) + " }"]


def vm_broker_env(config: dict) -> dict[str, str]:
    """The broker endpoint a guest is told to use, or {} if it has none.

    An IP literal, like the proxy's, so reaching the broker never depends on
    DNS -- which is what a compromised guest would attack to escape policy.
    """
    if not vm_uses_broker(config):
        return {}
    return {VM_BROKER_ENV_VAR: f"http://{VM_PROXY_ADDR}:{VM_BROKER_PORT}"}


def ensure_advertised_interface(run) -> None:
    """Create the dummy link carrying the advertised address, idempotently.

    `run(argv)` is injected rather than imported so this module stays free of
    subprocess; the proxy, broker and inspect helpers each pass their own. They
    all need this and none can import the other -- libexec entrypoints have no
    extension, so they are not importable.

    Both steps tolerate "already exists" because two VMs starting concurrently
    race here -- there is no lock and deliberately no owning unit. Anything else
    is fatal: without the address the redirect's destination is unroutable and
    the guest's connection fails with no useful diagnostic.
    """
    result = run([IP_BIN, "link", "add", VM_PROXY_IFACE, "type", "dummy"])
    if result.returncode != 0 and "File exists" not in result.stderr:
        raise RuntimeError(
            f"could not create {VM_PROXY_IFACE}: {result.stderr.strip()}")

    # Query, then add. Not "add and tolerate the error": iproute2 answers a
    # duplicate address with "Address already assigned", not the "File exists"
    # the duplicate-link case produces, so a string match on the wrong phrase
    # fails only on the SECOND start of a workload — which is how this was
    # found, and not by any test.
    shown = run([IP_BIN, "-o", "addr", "show", "dev", VM_PROXY_IFACE])
    if VM_PROXY_ADDR not in shown.stdout:
        result = run([IP_BIN, "addr", "add", f"{VM_PROXY_ADDR}/32",
                      "dev", VM_PROXY_IFACE])
        if result.returncode != 0 and "xist" not in result.stderr \
                and "assigned" not in result.stderr:
            raise RuntimeError(
                f"could not add {VM_PROXY_ADDR} to {VM_PROXY_IFACE}: "
                f"{result.stderr.strip()}")

    result = run([IP_BIN, "link", "set", VM_PROXY_IFACE, "up"])
    if result.returncode != 0:
        raise RuntimeError(
            f"could not bring up {VM_PROXY_IFACE}: {result.stderr.strip()}")


def vm_inspect_link_address_commands(uid: int) -> tuple[list[str], list[str]]:
    """The `ip addr` argvs putting this workload's inspector addresses on the
    shared dummy link, (v4, v6).

    Both families or neither: the redirect is dual-stack from the first rung,
    and the address is on a dummy link and therefore local, so neither add
    touches a route or a sysctl.

    The v6 add carries `nodad`. A dummy link runs no DAD at all (measured
    2026-08-19: 0/5 tentative, 5/5 immediate binds), so the flag changes
    nothing today; it states the intent and stays correct if the address ever
    moves to a link type that does run DAD, where it would otherwise sit
    tentative through the router-solicitation window and the inspector's first
    connection on that family would time out.
    """
    addr = vm_inspect_address(uid)
    v4 = [IP_BIN, "addr", "add", f"{addr.v4}/32", "dev", VM_PROXY_IFACE]
    v6 = [IP_BIN, "addr", "add", f"{addr.v6}/128", "dev", VM_PROXY_IFACE,
          "nodad"]
    return v4, v6


def vm_inspect_link_delete_commands(uid: int) -> tuple[list[str], list[str]]:
    """The `ip addr del` argvs removing them again, (v4, v6).

    The per-workload addresses are removed on stop (unlike the shared link and
    the advertised address, which are never): an address on the link means an
    inspector that is supposed to be running, and a stopped workload leaving
    its listener address behind is exactly what `diagnose` cannot explain.
    """
    addr = vm_inspect_address(uid)
    v4 = [IP_BIN, "addr", "del", f"{addr.v4}/32", "dev", VM_PROXY_IFACE]
    v6 = [IP_BIN, "addr", "del", f"{addr.v6}/128", "dev", VM_PROXY_IFACE]
    return v4, v6


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
    """The `elem` list from one `nft -j list set|map ...` document.

    Both keys are accepted because a map renders under "map", not "set" —
    querying a map and matching only on "set" silently returns no elements, and
    a caller reading that as "nothing is armed" reports a working redirect as
    broken.
    """
    for item in (payload or {}).get("nftables", []):
        for kind in ("set", "map"):
            if kind in item:
                return item[kind].get("elem", []) or []
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


def nft_element_counter(payload, uid: int) -> tuple[int, int] | None:
    """(packets, bytes) on the element of a counted set belonging to `uid`.

    Unlike `nft_drop_counter`, which reads a rule and is therefore host-wide
    across every filtered workload, this reads one *element* and so is
    attributable to the workload that owns it -- which is the entire reason
    the wrong-port sets carry `counter` as a set flag.

    A counted set renders its elements differently from an uncounted one, and
    that difference is the trap here. Without the flag an element is
    `{"concat": [...]}`; with it, it is wrapped:

        {"elem": {"val": {"concat": [10000, "198.18.1.0"]},
                  "counter": {"packets": 12, "bytes": 720}}}

    So `vm_owned_elements`, which matches the unwrapped shape, finds nothing in
    these sets and would report a workload with 12 dropped self-dials as having
    none. Verified against nft 1.1.6 rather than assumed.

    None means the element is absent -- the workload's inspector has never been
    armed -- which is a different statement from a counter reading zero, and
    the caller must not collapse the two: zero is "armed and never hit", the
    healthy reading, while None on a workload that claims inspection is a
    missing guard.
    """
    for elem in nft_set_elements(payload):
        if not isinstance(elem, dict):
            continue
        inner = elem.get("elem")
        if not isinstance(inner, dict):
            continue
        val = inner.get("val")
        parts = val.get("concat") if isinstance(val, dict) else None
        if not parts or parts[0] != uid:
            continue
        counter = inner.get("counter")
        if not isinstance(counter, dict):
            return None
        return (counter.get("packets", 0), counter.get("bytes", 0))
    return None


CONNTRACK_COUNT_PATH = "/proc/sys/net/netfilter/nf_conntrack_count"
CONNTRACK_MAX_PATH = "/proc/sys/net/netfilter/nf_conntrack_max"

# At and above this fraction the table is close enough to full to be the
# explanation for transfers dying part-way. Not a hard threshold in the kernel
# -- there is none; entries are refused once the table is full and there is no
# warning before that -- so this is the point at which the number stops being
# background and starts being an answer.
CONNTRACK_PRESSURE = 0.9


def conntrack_occupancy(count_path=CONNTRACK_COUNT_PATH,
                        max_path=CONNTRACK_MAX_PATH) -> tuple[int, int] | None:
    """(count, max) from the kernel's conntrack table, or None if unreadable.

    Host-wide, and not the inspector's to report -- it is here because the
    egress guard's correctness DEPENDS on conntrack state. A reply is only
    distinguishable from a fresh connection because an entry exists, so an
    exhausted table reclassifies the inspector's replies as `direction
    original` and drops them mid-connection.

    What makes it worth reading at all is that nothing else moves when it
    happens: the accept counters are unchanged, the guard counter climbs for a
    reason that looks like the cross-workload case it was written for, and
    inside the guest it presents as transfers dying part-way. Nothing in the
    chain rescues it either -- the guards sit ahead of the shipped `oif lo
    accept`, so a reclassified reply is dropped several rules before the one
    rule that would have taken it on interface alone.

    None rather than an exception on every failure: the module is not loaded
    until something uses conntrack, and a missing figure must never turn a
    diagnose line into a traceback.
    """
    try:
        with open(count_path) as f:
            count = int(f.read().strip())
        with open(max_path) as f:
            maximum = int(f.read().strip())
    except (OSError, ValueError):
        return None
    if maximum <= 0:
        return None
    return (count, maximum)


def vm_filter_delete_command(set_name: str, entries: list[str]) -> list[str]:
    """argv deleting `entries` from `set_name` in one transaction."""
    return [NFT_BIN, "delete", "element", *NFT_TABLE.split(), set_name,
            "{ " + ", ".join(entries) + " }"]


def vm_filter_commands(uid: int, allow: list[str], action: str,
                       resolved=None) -> list[list[str]]:
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
    for set_name, entries in vm_filter_elements(uid, allow, resolved).items():
        commands.append([NFT_BIN, action, "element", *table, set_name,
                         "{ " + ", ".join(entries) + " }"])
    return commands

# --- `allow`: the address-scoped bypass, now a table with a reason ---
#
# Rung 2 widens `allow` from a bare `<addr>:<port>` string into a table carrying
# `address` and a required `reason` — the shape every other bypass in this
# schema has (`internal` below; `splice` and `http2` from rung 3). The bare
# string is refused rather than accepted alongside it, because premise 3 — no
# shipped release in which a guest can still choose the old terms — means there
# is no deployed config to migrate: a compatibility path would exist only to let
# the two shapes drift.
#
# The target is `<addr>:<port>` (`[<v6addr>]:<port>` for IPv6) **or a name with
# a port** (`git.local:2222`), resolved host-side once at start. Names were
# forbidden here for a real reason — a record that moved left the element
# silently wrong for the life of the VM — and what retires it is that the
# guest's own resolver is now a static map we serve (the inspector design, §9),
# so the host-side answer and the guest-side answer come from the same place.
VM_ALLOW_ADDR_RE = re.compile(
    r"^(?:\[(?P<v6>[0-9a-fA-F:]+)\]|(?P<v4>\d{1,3}(?:\.\d{1,3}){3})):"
    r"(?P<port>\d+)$")

# The name form. Deliberately narrow — hostname labels and a port, no scheme, no
# path, no userinfo, and no fnmatch metacharacters: an `allow` name is resolved,
# not matched, so a pattern here has nothing to expand against.
#
# One label. Loose at the tail on purpose — a trailing hyphen is not a legal
# label and this accepts it, because the check that matters is the resolution
# the arming path performs, and a regex that rejected `git.local-` while
# accepting `git.local` bought nothing an operator would ever notice.
_ALLOW_LABEL = r"[A-Za-z0-9][A-Za-z0-9_-]*"
VM_ALLOW_NAME_RE = re.compile(
    rf"^(?P<host>{_ALLOW_LABEL}(?:\.{_ALLOW_LABEL})*):(?P<port>\d+)$")


class VmAllowEntry(NamedTuple):
    """One parsed [[vm.network.allow]] entry.

    Exactly one of `address` and `host` is set: an entry either names an
    address, armed as written, or a name, which the arming path resolves once at
    start. The two are kept apart rather than resolved here so that validation —
    which runs long before the VM starts, and on hosts that may not resolve the
    name at all — can still refuse a malformed entry.
    """
    address: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    host: str | None
    port: int
    reason: str


def vm_allow_reserved_reason(
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Why this address may not appear in `allow`, or None if it may.

    The inspector's listener planes are the one destination range an `allow`
    entry must never name. `allow` is evaluated *first* in the filter chain,
    deliberately -- it is also the escape hatch for the internal-destination
    drop -- which puts it ahead of the guard rule whose whole job is to stop
    one workload reaching another workload's inspector. An element here is
    therefore not a bypass of the guard so much as a replacement for it: the
    connection is accepted, lands on a policy point that applies someone
    else's allowlist, and is re-originated as someone else's uid.

    It takes an operator to write one, which makes this a foot-gun rather than
    a hole -- and a refusal is what lets the chain keep `allow` at the front
    (HLD detail §3, §7.2.5).

    Both families, because the planes are derived from one number: refusing the
    v4 and not the v6 refuses half of every address, and the half that survives
    is the one clients try first.
    """
    if isinstance(addr, ipaddress.IPv4Address):
        network = VM_INSPECT_NETWORK
    else:
        network = VM_INSPECT_ADDR6_PREFIX
    if addr not in network:
        return None
    return (f"{addr} is inside {network}, the egress inspector's own listener "
            f"range. `allow` is matched ahead of the rule that stops one "
            f"workload reaching another's inspector, so an entry here lands on "
            f"a policy point enforcing a different workload's allowlist and "
            f"re-originates as a different workload's uid. Reach the service "
            f"through the inspector by name instead")


# The [vm.network] keys that are scalars rather than sub-tables. Used only to
# recognise one written in the wrong place; see parse_vm_allow.
VM_NETWORK_SCALARS = frozenset({
    "bridge", "ports", "resolver", "egress", "hosts", "tls",
})


def parse_vm_allow(entry, *, filtered: bool = True) -> VmAllowEntry:
    """Parse one [[vm.network.allow]] table into a VmAllowEntry.

    Raises ValueError with an operator-readable message.

    `filtered` says whether the workload owning this entry is under
    `egress = "filtered"`, which is the one condition the 80/443 refusal below
    depends on. It defaults to True because both callers that matter are that
    case: validation of a filtered workload, and the arming path, which runs
    for no other kind.
    """
    if isinstance(entry, str):
        # Named for what to type, not for what is wrong: this is the only error
        # in the file an operator hits by having written a *correct* config for
        # the previous release.
        raise ValueError(
            f"{entry!r} is the old bare-string form. `allow` is now a table "
            f"carrying the reason for the bypass:\n"
            f"    [[vm.network.allow]]\n"
            f"    address = \"{entry}\"\n"
            f"    reason  = \"why this destination skips inspection\"")
    if not isinstance(entry, dict):
        raise ValueError(
            f"entries are [[vm.network.allow]] tables with `address` and "
            f"`reason`, got {entry!r}")
    unknown = sorted(set(entry) - {"address", "reason"})
    if unknown:
        # An unknown key here is usually not a typo -- it is a [vm.network]
        # scalar written BELOW the first [[vm.network.allow]] table, which TOML
        # reads as part of the allow entry rather than of [vm.network]. The
        # file looks right and the key silently belongs to the wrong table, so
        # the message names the cause rather than only the symptom. It cannot
        # be fixed by re-opening [vm.network] further down -- TOML rejects a
        # table declared twice -- so the instruction is "move it up".
        misplaced = [k for k in unknown if k in VM_NETWORK_SCALARS]
        hint = ""
        if misplaced:
            hint = (f"\n{', '.join(misplaced)} belongs to [vm.network] itself. "
                    f"The [[vm.network.allow]] table above it ends that "
                    f"section, so move it ABOVE the first "
                    f"[[vm.network.allow]]; re-declaring [vm.network] lower "
                    f"down is not valid TOML.")
        raise ValueError(
            f"unknown key(s) {', '.join(unknown)}; an allow entry carries "
            f"`address` and `reason` only{hint}")
    spec = entry.get("address")
    if not isinstance(spec, str) or not spec.strip():
        raise ValueError(
            f"`address` must be '<addr>:<port>' ('[addr]:port' for IPv6) or "
            f"'<name>:<port>', got {spec!r}")
    spec = spec.strip()
    reason = entry.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        # Required, like every other bypass in this schema. The entry is a hole
        # somebody opened deliberately, and the person who has to decide whether
        # it is still needed is not the person who wrote it.
        raise ValueError(
            f"{spec!r} has no `reason`; every bypass in this schema carries "
            f"one, because the operator who later has to decide whether the "
            f"hole is still needed is not the one who opened it")

    addr = host = None
    match = VM_ALLOW_ADDR_RE.match(spec)
    if match:
        try:
            addr = ipaddress.ip_address(match.group("v6") or match.group("v4"))
        except ValueError:
            raise ValueError(
                f"{spec!r} does not contain a valid IP address") from None
    else:
        match = VM_ALLOW_NAME_RE.match(spec)
        if not match:
            raise ValueError(
                f"{spec!r} is not '<addr>:<port>' (IPv6 as '[addr]:port') or "
                f"'<name>:<port>'")
        host = match.group("host")
    port = int(match.group("port"))
    if not 1 <= port <= 65535:
        raise ValueError(f"{spec!r}: port {port} out of range 1-65535")

    # 80 and 443 are redirected into this workload's inspector before the filter
    # chain consults `allow` at all, so an element here is armed and never
    # matched -- and the operator believes a destination is exempt from
    # inspection when it is not.
    #
    # The design words this as an error "under tls = 'inspect'". That qualifier
    # is wrong: the redirect rules key on the uid and the ORIGINAL port and read
    # nothing else -- not `tls`, not the destination -- so the entry is
    # intercepted whatever `tls` says, and it is intercepted for the name form
    # exactly as for the address form, since a name resolves to an address that
    # is redirected anyway. `egress = "filtered"` is the real condition, because
    # that is what puts the workload in the redirect's key at all.
    if filtered and port in (VM_INSPECT_ORIG_CLEARTEXT, VM_INSPECT_ORIG_TLS):
        raise ValueError(
            f"{spec!r}: port {port} is redirected into this workload's egress "
            f"inspector before `allow` is consulted, so the element would be "
            f"armed and never matched. The redirect keys on the workload uid "
            f"and the port alone. Allowlist the hostname in .hosts, which is "
            f"where 80 and 443 are decided")

    # Checked here rather than beside the schema, because this is the single
    # funnel every allow entry passes through: `_validate_egress` calls it for
    # the operator-facing error and `vm_filter_elements` calls it on the arming
    # path, so the refusal cannot be reached around by a config that never met
    # validation. The design asks for it "in the helper as well as the schema";
    # one funnel is how both get it without two copies that can drift.
    #
    # The name form is checked where it is resolved (vm_filter_elements), not
    # here: this function deliberately does not resolve.
    if addr is not None:
        reserved = vm_allow_reserved_reason(addr)
        if reserved:
            raise ValueError(f"{spec!r}: {reserved}")
    return VmAllowEntry(address=addr, host=host, port=port,
                        reason=reason.strip())


def vm_allow_resolve(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve an `allow` entry's name, or raise ValueError naming it.

    A failure is an error and never a silently unarmed element. `allow` is the
    only path to a named service on a port no redirect touches, so an element
    that failed to arm does not present as a refusal -- it presents as the
    guest hanging against a default-deny drop, which is the failure mode that
    costs an operator an evening.
    """
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(
            f"[vm.network].allow names {host!r}, which does not resolve on "
            f"this host ({exc}). An `allow` name is resolved here once at "
            f"start, so an unresolvable one arms nothing and the guest hangs "
            f"against the default-deny drop instead of being refused") from None
    seen: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if addr not in seen:
            seen.append(addr)
    return seen


def vm_allow_resolved(allow):
    """Parse and resolve every `allow` entry once. [(VmAllowEntry, [addr...])].

    The single resolution the whole allow path gets, host-side and once at
    start (§9). Every address a name answers with is kept, not just the first:
    a dual-stack forge answers with both families, and taking half of it is the
    "works until it doesn't" failure the both-families-or-neither rule exists to
    stop.

    It is a function of its own rather than a loop inside vm_filter_elements
    because two consumers need the SAME answer -- the nftables elements and the
    responder's static map. See vm_filter_elements for what a second resolution
    costs.
    """
    out = []
    for spec in allow:
        entry = parse_vm_allow(spec)
        if entry.address is not None:
            addresses = [entry.address]
        else:
            addresses = vm_allow_resolve(entry.host)
        out.append((entry, addresses))
    return out


# --- §9: the synthesising responder ---
#
# The guest's only nameserver. Every A/AAAA, for any name, is answered with this
# workload's inspector address; everything else is NODATA. NOTHING IS FORWARDED
# -- there is no upstream socket in the program at all, which is what makes DNS
# exfiltration absent rather than filtered, and is the property to check first if
# anyone ever "adds a fallback".
#
# Base of the per-workload responder addresses. 127.130.0.0, by the same offset
# arithmetic vm_management_address uses against 127.128.0.0 -- and deliberately
# inside VM_MGMT_NETWORK (127.128.0.0/9), which is why there is no new
# ReservedPlane for it: the /9 was cut wide precisely so the planes hung on
# loopback after the management one would inherit the reservation rather than
# each need their own. `ports` already cannot bind here.
#
# Loopback and not the 198.18.0.0/16 advertised link, because the guest must not
# reach the responder directly: 127/8 is unreachable from the guest by
# construction (ADR 006 -- passt re-originates guest traffic as host sockets, and
# the guest's own 127/8 is its own), so the ONLY path to it is passt's
# --dns-forward interception. A responder on a reachable address is a resolver
# every other workload on the host can query.
VM_RESOLVE_ADDR_BASE = 0x7F820000  # 127.130.0.0

# Port 53, on the workload's own address. Fixed and never configurable, for the
# reason the management SSH port is: it is not a service an operator publishes,
# it is where passt is told to forward.
VM_RESOLVE_PORT = 53

# The one stated TTL. Long, because the inspector's address never moves: there
# is no upstream truth for a short TTL to track, and a long one collapses a
# guest's repeat lookups into its own cache instead of a syscall per request.
#
# Not a library default, and not "as large as the field allows" either: a TTL
# past a stub's own cache ceiling is silently clamped, and a stated constant
# that is not the constant in effect is worse than a smaller one that is.
VM_RESOLVE_TTL = 3600

VM_RESOLVE_POLICY_FILE = "resolve.json"
VM_RESOLVE_LISTENER_BIN = "/usr/libexec/workloadctl/workload-vm-resolve"


def vm_resolve_address(uid: int) -> str:
    """The workload's own loopback address for its synthesising responder.

    Derived from the uid, so uniqueness is inherited from the uid allocator:
    no registry, no allocation step, and no collision. uid 10000 -> 127.130.0.0,
    uid 10003 -> 127.130.0.3.

    There is no address-add helper to go with this, and writing one is the trap.
    The kernel treats all of 127/8 as local on `lo`, so binding 127.130.1.4
    succeeds with nothing assigned (verified 2026-08-19): a `workload-vm-resolve
    up` twin adding a /32 would be a no-op, and worse, it would invent an
    address whose absence the inspector's fail-at-bind argument would then
    appear to depend on.
    """
    if uid < UID_MIN or uid > UID_MAX:
        raise ValueError(
            f"UID {uid} is outside the workload range {UID_MIN}-{UID_MAX}; "
            f"no responder address is derivable for it")
    return str(ipaddress.IPv4Address(VM_RESOLVE_ADDR_BASE + (uid - UID_MIN)))


def vm_resolve_policy_path(name: str) -> str:
    """Where one workload's responder reads its answers from."""
    return f"{VM_SOCKET_DIR}/{name}/{VM_RESOLVE_POLICY_FILE}"


def vm_uses_resolve(config: dict) -> bool:
    """Whether this workload gets a synthesising responder.

    Everything vm_uses_inspect requires (a VM, not bridged, filtered) plus
    `resolver` not being "none". One knob, one meaning, in both places: a
    responder under `egress = "open"` would answer every name with an inspector
    address that nothing redirects to, and one under `resolver = "none"` would
    be a nameserver for a guest that asked for no nameserver -- and passt is
    told about it in the same breath, so a disagreement here is a guest pointed
    at a port with nothing behind it.
    """
    if not vm_uses_inspect(config):
        return False
    net = (config.get("vm", {}) or {}).get("network", {}) or {}
    return net.get("resolver", "host") != "none"


def vm_resolve_policy(net: dict, uid: int, resolved=None) -> dict:
    """The responder's answer document for one workload.

    `address`/`address6` are the inspector's, not the responder's: every
    synthesised A/AAAA points the guest at the listener its 80 and 443 are
    redirected to anyway, so a guest that ignores the redirect and one that does
    not both arrive at the same place.

    `static` is the `allow`-by-name map, and it lands WITH the responder rather
    than after it. Without it a synthesised answer sends every named non-80/443
    destination -- an SSH forge, a registry, an internal API -- to a port the
    inspector does not serve, which presents as a healthy-looking hang rather
    than as a refusal. The map wins over synthesis, which costs nothing on 80
    and 443 because the redirect is keyed on uid and port alone; a name in both
    `hosts` and `allow` is therefore legal.

    Addresses come from `resolved` when the caller has one, so the map holds the
    addresses that were ARMED -- see vm_filter_elements for why a second
    resolution is a different question.

    `hosts` changes NO answer this responder gives. Synthesis is unconditional
    by design: an unlisted name is answered like any other, and the refusal
    happens later, at the listener. The list is carried so the responder can
    COUNT queries for names on no list -- the tunnelling signature, since
    synthesis makes the channel absent rather than filtered, so a burst of
    unique unlisted names exfiltrates nothing and is still the cleanest
    evidence that something in the guest is trying. A responder that REFUSED
    those names would be a different design; this one only notices.
    """
    inspect = vm_inspect_address(uid)
    if resolved is None:
        resolved = vm_allow_resolved(net.get("allow", []) or [])
    static: dict[str, list[str]] = {}
    for entry, addresses in resolved:
        if entry.host is None:
            continue
        # Normalised on the way in, so the responder's lookup is one dict hit
        # against a name already in the form every match in this design is made
        # against -- and two spellings of one name cannot become two entries.
        key = vm_normalise_hostname(entry.host)
        for addr in addresses:
            text = str(addr)
            if text not in static.setdefault(key, []):
                static[key].append(text)
    return {
        "address": inspect.v4,
        "address6": inspect.v6,
        "ttl": VM_RESOLVE_TTL,
        "static": static,
        "hosts": vm_proxy_hosts(net),
    }



def _validate_egress(net: dict) -> list[str]:
    """Validate [vm.network].egress and .allow.

    `egress` defaults to "filtered" (ADR 006 §5.1): the usual argument for
    defaulting a new control off is protecting deployed workloads, and there
    are none — both VM bundles are templates. A secure default costs nothing
    now and is expensive to retrofit.

    `filtered` needs somewhere for the VM's traffic to go: either an address
    allowlist or a hostname allowlist served by its own proxy. Neither means a
    VM that can reach nothing at all, which is rejected. The failure is loud on
    purpose — silently treating an un-allowlisted VM as open is the
    misreported-confinement bug this whole layer exists to prevent.
    """
    errors: list[str] = []

    egress = net.get("egress", VM_EGRESS_DEFAULT)
    if egress not in VM_EGRESS_MODES:
        errors.append(
            f"[vm.network].egress must be one of "
            f"{', '.join(repr(m) for m in VM_EGRESS_MODES)}, got {egress!r}")
        egress = VM_EGRESS_DEFAULT

    allow = net.get("allow", [])
    allow_entries: list[VmAllowEntry] = []
    if not isinstance(allow, list):
        errors.append(
            f"[vm.network].allow must be an array of [[vm.network.allow]] "
            f"tables, got {type(allow).__name__}")
        allow = []
    else:
        for spec in allow:
            try:
                allow_entries.append(
                    parse_vm_allow(spec, filtered=egress == "filtered"))
            except ValueError as e:
                errors.append(f"[vm.network].allow: {e}")

    hosts = net.get("hosts", [])
    if not isinstance(hosts, list):
        errors.append(
            f"[vm.network].hosts must be an array of hostname patterns, got "
            f"{type(hosts).__name__}")
        hosts = []
    else:
        for pattern in hosts:
            errors.extend(f"[vm.network].hosts: {e}"
                          for e in _validate_proxy_host(pattern))

    tls = net.get("tls")
    if tls is not None:
        if tls in VM_TLS_UNBUILT:
            errors.append(
                f"[vm.network].tls = {tls!r} is not built yet — it lands in "
                f"{VM_TLS_UNBUILT[tls]}. Accepting the word now would splice "
                f"the connection while the config claimed it was inspected, "
                f"which is the misreported confinement this layer exists to "
                f"prevent. Use tls = 'splice' (the default) until then.")
        elif tls not in VM_TLS_MODES:
            errors.append(
                f"[vm.network].tls must be one of "
                f"{', '.join(repr(m) for m in VM_TLS_MODES)}, got {tls!r}")

    internal = net.get("internal", [])
    internal_hosts: list[str] = []
    if not isinstance(internal, list):
        errors.append(
            f"[vm.network].internal must be an array of "
            f"[[vm.network.internal]] tables, got {type(internal).__name__}")
        internal = []
    else:
        for item in internal:
            if not isinstance(item, dict):
                errors.append(
                    f"[vm.network].internal entries are tables with `host` and "
                    f"`reason`, got {item!r}")
                continue
            unknown = sorted(set(item) - {"host", "reason"})
            if unknown:
                errors.append(
                    f"[vm.network].internal: unknown key(s) "
                    f"{', '.join(unknown)}; an entry carries `host` and "
                    f"`reason` only")
            if "host" not in item:
                errors.append(
                    f"[vm.network].internal: entry {item!r} has no `host`")
                continue
            host = item.get("host")
            problems = _validate_proxy_host(host)
            if problems:
                errors.extend(f"[vm.network].internal: {p}" for p in problems)
                continue
            host = host.strip()
            internal_hosts.append(host)
            if not isinstance(item.get("reason"), str) or not item["reason"].strip():
                errors.append(
                    f"[vm.network].internal: {host!r} has no `reason`; it is a "
                    f"bypass of the internal-destination drop and carries one "
                    f"like `allow` does")
            # A dead entry here fails in the direction nobody notices until the
            # host is needed: the guest gets `403 <host> resolves to an internal
            # address` on the one destination the entry existed to permit. An
            # error, for the same reason an `allow` element that arms nothing is.
            if not any(host == pattern or fnmatch.fnmatch(host, pattern)
                       for pattern in hosts if isinstance(pattern, str)):
                errors.append(
                    f"[vm.network].internal: {host!r} is on no list — nothing "
                    f"in .hosts allowlists it, so the entry excepts a "
                    f"destination the guest is refused before the exception is "
                    f"reached. Add it to .hosts, or drop this entry")
    # NOT rejected under `tls = "splice"`, unlike `policy` will be, and the
    # asymmetry is deliberate rather than an oversight: the internal-destination
    # check lives on the inspector's UPSTREAM leg, which a spliced connection
    # still has. A later pass tidying these rules for symmetry would take the
    # exemption away from exactly the workloads that need it.

    # §5.3: `bridge` means a real LAN identity, and nothing of ours is in that
    # guest's data path — no host socket, so no uid to match on.
    if "bridge" in net:
        for key in ("egress", "allow", "tls", "internal"):
            if key in net:
                errors.append(
                    f"[vm.network].{key} has no effect with .bridge set — a "
                    f"bridged VM sends from its own LAN address, not from a "
                    f"host socket owned by the workload user, so there is no "
                    f"uid for the filter to match")
        if "hosts" in net:
            errors.append(
                "[vm.network].hosts has no effect with .bridge set — hostname "
                "policy is enforced by a proxy the guest is redirected to on "
                "the workload's own uid, and a bridged guest sends from its "
                "own LAN address with no host socket in the path")
        return errors

    if egress == "filtered" and not allow and not hosts:
        errors.append(
            "[vm.network].egress is 'filtered' (the default) but both .allow "
            "and .hosts are empty, so this VM could reach nothing at all. "
            "List the hostnames it needs as .hosts (HTTP/HTTPS, via its own "
            "proxy), non-HTTP destinations as .allow entries "
            "('<addr>:<port>'), or set egress = 'open' to opt out of "
            "filtering.")

    # The drop is what makes the allowlist binding — it leaves a guest that
    # ignores HTTPS_PROXY nowhere else to go. Under 'open' there is none, so the
    # allowlist binds only cooperative guests while the proxy still costs a
    # daemon parsing guest-controlled HTTP, its own SELinux domain, and an egress
    # exemption the guest's uid does not get.
    #
    # Refused, not silently skipped: a `hosts` list accepted and then ignored is
    # the misreported confinement this layer exists to prevent. Joins .hosts with
    # .bridge (no uid in the path) and .hosts = ["*"].
    if egress == "open" and hosts:
        errors.append(
            "[vm.network].hosts is set but .egress is 'open', so nothing "
            "requires the guest to use the proxy — a process that ignores "
            "HTTPS_PROXY reaches the internet directly and the allowlist binds "
            "only the guests that cooperate. Set egress = 'filtered' to make "
            "the hostname allowlist enforceable, or drop .hosts to run "
            "unfiltered without a proxy.")

    # `tls` and `internal` describe what happens to a redirected connection, and
    # under 'open' nothing is redirected. Refused rather than ignored, for the
    # same reason .hosts is: a key accepted and then not applied is a config
    # that reports a confinement it does not have.
    if egress != "filtered":
        for key in ("tls", "internal"):
            if key in net:
                errors.append(
                    f"[vm.network].{key} has no effect with .egress = "
                    f"{egress!r} — nothing is redirected into the egress "
                    f"inspector, so there is no intercepted connection for it "
                    f"to describe. Set egress = 'filtered' to use it.")

    # `resolver = "none"` kept its meaning and lost its coherence. Under the old
    # proxy posture a guest that could not resolve simply named hosts in a
    # CONNECT, which is why it was ECH-immune. Under a transparent redirect the
    # same guest can only dial literals, which reach the inspector with no name
    # to match and are dropped — so every name-based destination is unreachable
    # while the workload starts clean and reports healthy.
    #
    # An error only where the config itself contradicts it. A workload whose
    # destinations are all address-keyed `allow` elements needs no DNS, reaches
    # them through the filter chain without touching the inspector, and is
    # entitled to say so — that case is the warning in vm_network_warnings.
    if egress == "filtered" and net.get("resolver") == "none":
        named = []
        if hosts:
            named.append(".hosts")
        if internal_hosts:
            named.append(".internal")
        if any(e.host for e in allow_entries):
            # An `allow` entry written by name is in the same position: its
            # answer comes from the static map the responder serves, and
            # "none" is what turns the responder off.
            named.append("an .allow entry written by name")
        if named:
            errors.append(
                f"[vm.network].resolver = 'none' with {', '.join(named)} set — "
                f"a guest that cannot resolve can only dial literals, which "
                f"reach the inspector with no name and are dropped, so every "
                f"host named there is unreachable. Drop resolver = 'none', or "
                f"drop the host lists and reach the destinations as .allow "
                f"entries by address.")

    return errors


# Hostname patterns are matched by tinyproxy's fnmatch filter against the host
# alone (FilterURLs Off), so a pattern carrying a scheme, a path or a port never
# matches anything — a silent hole in an allowlist, which is the failure worth
# catching at validate time rather than at 3am.
_PROXY_HOST_RE = re.compile(r"^[A-Za-z0-9*?.\[\]!_-]+$")


def _validate_proxy_host(pattern) -> list[str]:
    """Validate one [vm.network].hosts pattern. Returns error strings."""
    if not isinstance(pattern, str):
        return [f"entries must be strings, got {pattern!r}"]
    text = pattern.strip()
    if not text:
        return ["entries must not be empty"]
    if "://" in text:
        return [f"{pattern!r} looks like a URL — patterns match the hostname "
                f"only, so drop the scheme"]
    if "/" in text:
        return [f"{pattern!r} contains a path — patterns match the hostname "
                f"only (FilterURLs is off), so a path never matches"]
    if ":" in text:
        return [f"{pattern!r} contains a port — the proxy allows CONNECT to "
                f"{VM_PROXY_PORT_HTTPS} only; use .allow for other ports"]
    if text == "*":
        return ["'*' matches every host, which is the same as egress = 'open' "
                "but harder to notice — set egress = 'open' if that is meant"]
    if not _PROXY_HOST_RE.match(text):
        return [f"{pattern!r} is not a hostname or fnmatch pattern"]
    return []


def _registration_domain_parent(pattern: str) -> str | None:
    """The registration-domain parent this pattern wildcards under, or None.

    Only a leading `*.` counts. `*.github.io` lets the GUEST pick the label, so
    the allowlist authorises a name it never saw and the inspector's own
    upstream lookup carries it to a nameserver somebody else controls — which
    is both the exfiltration channel §9's synthesis removes and the route by
    which an allowlisted name points inside the LAN. `pages.github.io` names one
    site and is fine.
    """
    if not pattern.startswith("*."):
        return None
    parent = pattern[2:]
    return parent if parent in VM_REGISTRATION_DOMAIN_PARENTS else None


def vm_network_warnings(net: dict) -> list[str]:
    """Non-fatal [vm.network] warnings, as message strings.

    The counterpart to validate_vm_network's errors, surfaced by
    `validate` through validation.collect_config_warnings. Everything here is a
    coherent thing to have written on purpose — which is exactly why silence
    would be wrong, since nothing else would ever report it.
    """
    warnings: list[str] = []
    if not isinstance(net, dict) or "bridge" in net:
        return warnings
    egress = net.get("egress", VM_EGRESS_DEFAULT)

    for key in ("hosts", "internal"):
        entries = net.get(key, [])
        if not isinstance(entries, list):
            continue
        for item in entries:
            pattern = item.get("host") if isinstance(item, dict) else item
            if not isinstance(pattern, str):
                continue
            parent = _registration_domain_parent(pattern.strip())
            if parent:
                warnings.append(
                    f"[vm.network].{key} pattern {pattern!r} wildcards under "
                    f"{parent}, where anyone can register a label — the guest "
                    f"picks the name, the allowlist authorises it, and the "
                    f"lookup reaches a nameserver somebody else controls. "
                    f"Name the hosts you need instead, if you can.")

    if egress == "filtered" and net.get("resolver") == "none":
        # The coherent case: address-keyed `allow` elements only, reached
        # through the filter chain without touching the inspector. Warned
        # anyway, because the same file read six months later looks like a
        # workload that simply lost DNS.
        warnings.append(
            "[vm.network].resolver = 'none' on a filtered workload: no "
            "hostname is resolvable, so only .allow entries written by "
            "address work. A guest that cannot resolve can only dial "
            "literals, and a literal reaches the inspector with no name to "
            "match and is dropped.")

    allow = net.get("allow", [])
    if isinstance(allow, list):
        for item in allow:
            if not isinstance(item, dict):
                continue
            spec = item.get("address")
            if not isinstance(spec, str) or not spec.strip().endswith(":53"):
                continue
            warnings.append(
                f"[vm.network].allow {spec.strip()!r} is a resolver the guest "
                f"can choose for itself, past the synthesising responder — "
                f"which returns both the ECHConfig that hides the name from "
                f"the inspector and the DNS exfiltration channel synthesis "
                f"exists to remove.")

    return warnings


class ReservedPlane(NamedTuple):
    """One host-side plane a [vm.network].ports entry may not bind into.

    `port` is None for a plane that owns a whole address range on every port,
    and a number for one that owns a single socket on an address operators
    otherwise use freely. The distinction is not cosmetic: 127.0.0.1:8080 is a
    normal thing to publish on and the management range is not a normal thing
    to publish on at all, so a check that treated the broker's address the way
    it treats the management range would refuse most of what `ports` is for.

    `what` is a sentence, not a label, because the four collisions want four
    different explanations and reciting the range explains none of them.
    """
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    port: int | None
    what: str


# Every plane `ports` may not bind, in both families.
#
# Before rung 1 there was one plane and the check was a single `in
# VM_MGMT_NETWORK` with a docstring committing to v4. Rung 1 added two listener
# planes and one of them is v6, so `ports = ["198.18.1.4:8443:22"]` validated
# and 2001:2::/48 was not checked at all by construction. Either produces one of
# two outcomes with nothing logged for either: a cross-workload denial of
# service on a security control (the inspector fails to bind, and the
# fail-at-bind path reports it as the address being missing), or workload B
# receiving workload A's intercepted traffic. Start order decides which.
#
# A list, so the answer to "is this reserved" is one lookup that a new plane
# joins rather than a chain of ifs each new plane has to remember to extend.
VM_RESERVED_PLANES = (
    ReservedPlane(
        VM_MGMT_NETWORK, None,
        "the per-workload management addresses `workloadctl exec` and `shell` "
        "reach a guest's sshd on. Publishing here puts a guest port where "
        "another workload's control plane belongs, and start order decides "
        "which of the two gets the bind"),
    ReservedPlane(
        VM_INSPECT_NETWORK, None,
        "the egress inspector's IPv4 listener plane. Every filtered VM's "
        "redirected 80 and 443 land on an address in it, so publishing here "
        "either takes the bind another workload's inspector needs — which "
        "fails as the address being missing, not as a conflict — or hands this "
        "guest another workload's intercepted traffic"),
    ReservedPlane(
        VM_INSPECT_ADDR6_PREFIX, None,
        "the egress inspector's IPv6 listener plane, the v6 twin of "
        "198.18.0.0/16 carrying the same numbers. Refusing one family and not "
        "the other refuses half of every address, and the half left open is "
        "the one clients try first"),
    ReservedPlane(
        ipaddress.ip_network(f"{VM_BROKER_LISTEN_ADDR}/32"),
        VM_BROKER_LISTEN_PORT,
        "the credential broker's listener, where the uid of the connecting "
        "socket is what selects a caller's credentials. Publishing a guest "
        "port there is a guest answering in a credential boundary's place, "
        "decided by start order"),
)


def vm_reserved_plane(addr: str, port: int | None = None) -> ReservedPlane | None:
    """The reserved plane this bind address and port fall in, or None.

    Both families. The v4-only version this replaces was correct when there was
    one plane and it was v4; it stopped being correct the moment a v6 plane
    existed, and it said so in a docstring rather than in a failing test —
    which is why the planes are a list now and this reads it.

    An unparseable address answers None: parse_vm_port has already rejected
    anything malformed, so there is nothing here to report.
    """
    try:
        address = ipaddress.ip_address(addr)
    except (ValueError, TypeError):
        return None
    for plane in VM_RESERVED_PLANES:
        if address.version != plane.network.version:
            continue
        if address not in plane.network:
            continue
        if plane.port is not None and port != plane.port:
            continue
        return plane
    return None


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
                bind_addr, host_port, _guest, _proto = parse_vm_port(spec)
            except ValueError as e:
                errors.append(f"[vm.network].ports: {e}")
                continue
            plane = vm_reserved_plane(bind_addr, host_port) if bind_addr else None
            if plane:
                # The remedy follows the plane's shape: a range-scoped plane is
                # not somewhere to publish at all, while a port-scoped one is a
                # single socket on an address that is otherwise fine.
                if plane.port is None:
                    where = f"binds into {plane.network}, which carries"
                    remedy = ("Bind 127.0.0.1, a LAN address, or omit the "
                              "address to publish on all of them")
                else:
                    where = f"binds {bind_addr}:{plane.port}, which is"
                    remedy = "Publish on another host port"
                errors.append(
                    f"[vm.network].ports: {spec!r} {where} {plane.what}. "
                    f"{remedy}")
    if ports and "bridge" in net:
        # passt publishes ports by binding host sockets; a bridged guest has its
        # own LAN address and nothing of ours is in its data path to bind them.
        errors.append(
            "[vm.network].ports has no effect with .bridge set — a bridged VM "
            "has its own LAN address, so reach its services there directly")

    if "broker" in net:
        broker = net["broker"]
        if not isinstance(broker, bool):
            errors.append(
                f"[vm.network].broker must be true or false, got {broker!r}")
        elif broker and "bridge" in net:
            # Same reasoning as .hosts and .egress: a bridged guest reaches the
            # LAN on its own address with nothing of ours in the path, so there
            # is no uid to key the redirect on and the advertised address is not
            # reachable from it. Silently ignoring the key would leave an
            # operator believing a credential boundary exists.
            errors.append(
                "[vm.network].broker has no effect with .bridge set — the "
                "redirect is keyed on the uid of a host socket, and a bridged "
                "VM has none. Drop .bridge to use the broker")

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
            # seed_provides opts a custom seed out of the seed-completeness
            # checks build_cloud_init_iso applies (proxy env, virtiofs mounts).
            # Validated against a closed set: the whole value of the check is
            # that it fires, and a typo'd opt-out would silently disable it —
            # which is the failure mode the check exists to prevent.
            sp = ci.get("seed_provides", [])
            if not isinstance(sp, list) or not all(isinstance(x, str) for x in sp):
                errors.append(
                    "[vm.cloud_init].seed_provides must be a list of strings"
                )
            else:
                unknown = sorted(set(sp) - SEED_PROVIDES_CHOICES)
                if unknown:
                    errors.append(
                        f"[vm.cloud_init].seed_provides has unknown entries "
                        f"{unknown}; valid: {sorted(SEED_PROVIDES_CHOICES)}"
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
