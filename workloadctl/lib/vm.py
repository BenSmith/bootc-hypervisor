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
import time
from pathlib import Path
from typing import NamedTuple

from workload_lib import (UID_MAX, UID_MIN, parse_volume_spec,
                          workload_root_dir)


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

# The SELinux context a virtiofs share covering the guest home must be mounted
# with, and the types that satisfy it.
#
# virtiofs carries no xattrs here (the sidecar gets no --xattr), so every file
# under such a share lands in the guest labelled bare `virtiofs_t` — a type
# sshd has no access to at all. `~/.ssh/authorized_keys` then becomes
# unreadable and key auth fails for a guest whose only account has no password.
# A `context=` mount option is the only fix: it labels the whole mount at once,
# which is also why the type has to be one sshd can read through to a home.
#
# BOTH HALVES MUST AGREE. workload-ensure-user emits this value into the
# built-in cloud-config (_virtiofs_mount_opts) and separately REFUSES a custom
# seed that does not carry one of these types (the seed contract in
# build_cloud_init_iso). A drift between the emitter and the check looks like
# the contract rejecting workloadctl's own output, which is what
# test_default_mode_emits_what_the_contract_demands pins.
#
# `ssh_home_t` is accepted alongside `user_home_t` because both carry the
# `user_home_type` attribute that stock policy grants sshd:
#   allow sshd_t user_home_type:file { getattr ioctl lock open read };
# An operator using some other locally-granted type opts out with
# [vm.cloud_init].seed_provides = ["home_context"].
VM_HOME_SELINUX_TYPES = ("user_home_t", "ssh_home_t")
VM_HOME_SELINUX_CONTEXT = "system_u:object_r:user_home_t:s0"

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
# listener ports they select.
#
# Until rung 2 these two numbers had a rival: tinyproxy's ConnectPort directive
# also named 443, and the two were deliberately NOT aliased so the redirect's
# key could not be changed by editing a policy directive of the service it was
# built to replace. That service is gone and these are now the only 80 and 443
# in the design; the note survives because the reason a constant was not shared
# is otherwise invisible once one of the two sharers is deleted.
VM_INSPECT_ORIG_CLEARTEXT = 80
VM_INSPECT_ORIG_TLS = 443

# The inspector's listener binary, the socket unit's ExecStart. Named here so
# the unit and the RPM stay one place apart.
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
# hangs on loopback is carved out of the same range, so a narrowing pass that
# "tidied" this to 127.128.0.0/16 would take the reservation away from planes
# that never had one of their own. The synthesising responder is the case that
# proved it — it sits at 127.130.0.0 + the same uid offset, and needs no
# ReservedPlane entry of its own precisely because this /9 already covers it.
# The reservation is enforced through VM_RESERVED_PLANES, which is where a plane
# OUTSIDE this range is added — not by widening or narrowing this.
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

# What a filtered workload's redirected TLS connections get.
#
# `splice` reads the ClientHello's SNI, matches it against `hosts`, and replays
# those exact bytes upstream. Nothing is decrypted; the guest's handshake is
# with the origin, and this host never holds a key to it.
#
# `inspect` terminates. The inspector completes the guest's handshake itself
# with a leaf minted by this workload's own CA, opens a separately verified
# session to the origin, and authorises every REQUEST inside. It is the default
# because the property the allowlist claims -- that the guest reaches these
# hosts and no others -- is only true per request under termination: under
# `splice` a name is checked once, at the front of a connection whose contents
# nothing can see.
#
# THE DEFAULT MOVED, AND IT IS NOT A FREE CHANGE. A terminated guest must trust
# the workload's CA, which reaches it through the seed, which cloud-init applies
# once per instance-id. An EXISTING filtered guest does not gain that trust by
# upgrading the RPM: it gets certificate errors on every HTTPS request until it
# is re-seeded. `tls = "splice"` is the answer for a guest that cannot be, and
# is still fully supported -- it is a weaker property, not a deprecated one.
#
# IT COSTS A SENTENCE. `splice` here is the widest bypass in this schema: every
# host, not a named one, and the three narrower hatches beside it (.allow,
# .internal, .splice, .http2) have each carried a written `reason` since they
# existed. So this one requires `tls_reason`, for the reason those do -- the
# person deciding whether a bypass is still needed is not the person who opened
# it, and "spliced because this guest cannot hold the CA" and "spliced because
# nobody tried" are the same two words in a config without it. The key is a
# sibling scalar rather than a table because `tls` is a mode, not a list: a
# polymorphic `tls` that was sometimes a string and sometimes a table would
# make the commonest line in the section the one hardest to read.
VM_TLS_MODES = ("splice", "inspect")
VM_TLS_DEFAULT = "inspect"

# Modes named but not built, mapped to when they arrive. Empty since rung 3 T5
# emptied it, and KEPT: the refusal it drives says WHEN a mode lands instead of
# listing valid values, which is the difference between "you asked for a
# property that is coming" and "you made a typo". A future mode belongs here
# from the moment it is written down, not from the moment it works, because a
# key that accepted the word and quietly did something weaker would be a config
# claiming a property it does not have.
VM_TLS_UNBUILT: dict[str, str] = {}

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
# Internal destination prefixes the egress inspector may not connect OUT to. The
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


# --- Hostname policy: what the guest is told, and what enforces it ---
#
# Kernel rules match addresses; policy is written about names. Through rung 1
# the resolution was an HTTP forward proxy: one tinyproxy per workload reading
# `CONNECT host:443` in plaintext and allowlisting the hostname directly, with
# the guest configured to use it through HTTPS_PROXY. That proxy is gone. Its
# weakness was never the filtering, it was the configuring: a proxy is advisory,
# so a guest process that ignores the variables simply does not use it, and the
# default-deny chain could only turn that into a failure — never into a
# filtered request. Every language runtime, every static binary and every
# vendored HTTP client was one more place the variables had to be honoured.
#
# What replaced it is transparent: the guest is told nothing, dials 80 and 443
# normally, and a uid-keyed DNAT lands it on this workload's own inspector,
# which reads the Host header or the SNI and applies the same `hosts` patterns.
# The guest's cooperation is no longer part of the enforcement path.
#
# The advertised address survives the proxy. It is still the address every
# guest is told to use — now for the credential broker alone — and still the
# same address for every workload on purpose: the broker redirect is keyed on
# uid, so one advertised endpoint reaches N private listeners and every guest's
# cloud-init is identical. Two host addresses are ruled out by §3.5 — host
# loopback is unreachable by design, and the host's default-route address is
# structurally unreachable because passt assigns the guest that same address —
# so it has to be some other host address.
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
VM_ADVERTISED_ADDR = "192.0.2.1"

# What [vm.cloud_init].seed_provides may name — the concerns a custom seed can
# declare it handles itself, suppressing the matching completeness check in
# build_cloud_init_iso.
#
# "proxy" was one of these and is not merely dropped: a seed that still declares
# it is REFUSED, by name, in validate_vm_config. Silently ignoring it would let
# a custom seed opt out of a check that no longer exists while never being told
# the check it now needs — the CA bundle the inspector's spliced connections
# will be presented under — and the operator would learn that at the first
# certificate error inside the guest rather than at validation.
#
# "home_context" is narrower than "mounts": a seed that mounts the home share
# itself but labels it by some means we cannot read from the seed text (an
# image-baked fstab entry, a local policy granting sshd another type) opts out
# of the SELinux check alone and keeps the mount check.
SEED_PROVIDES_CHOICES = {"ca", "mounts", "home_context"}

# The retired opt-out and what an operator should write instead. Kept as data
# rather than spelled into the error string so the accepted set and the message
# naming its replacement cannot drift.
SEED_PROVIDES_RETIRED = {
    "proxy": "ca",
}

# workload-ensure-user exits with this when a custom seed fails one of the
# contracts build_cloud_init_iso enforces (host key, CA bundle, volume mounts,
# home-share SELinux context).
# Distinct from a plain 1 so the caller can tell "the operator's seed is wrong,
# and the helper already said how" from "the helper broke": provisioning maps
# it to UsageError, which keeps the CLI's bug-report banner — and the traceback
# it prints — off an error the operator is expected to hit and can fix.
VM_SEED_CONTRACT_EXIT = 2


class SeedContractError(RuntimeError):
    """A custom [vm.cloud_init].user_data_file does not satisfy a contract the
    built-in seed would have satisfied. The message is written for the operator
    and names the fix."""

# Dummy link carrying the advertised address and every per-workload listener
# address. Host-global and shared, created on demand and never torn down by a
# workload stop: it is refcount-free because it holds no per-workload state,
# costs nothing idle, and an orphan is inert.
#
# The DEVICE name still reads "workload-proxy" after the proxy it was named for
# was deleted, and that is deliberate. A link name is an object that exists on
# running hosts: renaming it would leave the old link in place holding this
# workload's 127.128.x.y and 198.18.x.y addresses, with the new link claiming
# the same addresses — two links answering for one address is a routing
# ambiguity, and it would arrive on upgrade rather than on a fresh install.
VM_ADVERTISED_IFACE = "workload-proxy"

# The host-side process that re-originates a workload's egress — the egress
# inspector, and it alone; the synthesising responder re-originates nothing,
# see below — runs as the workload's own user, so `meta skuid` cannot separate
# its traffic from the guest's, and under default-deny the drop catches it too,
# leaving the workload's own enforcement path unable to reach anything. The control group is the discriminator that
# survives the shared uid: systemd assigns it, a guest can neither enter nor
# forge it, and it widens no destination or port, so a guest that dials 443
# past the inspector is still dropped.
#
# Named wl_egress_cg, not wl_proxy_cg. Through rung 1 its one member was the
# per-workload tinyproxy and the name was accurate; rung 2 deleted that service
# and left the set holding a member that is not a proxy at all -- the egress
# inspector, and only it. The synthesising responder is not a second member:
# it answers from memory and opens no socket, so there is no vm_resolve_cgroup
# and nothing arms one. Its twin in the nat table, wl_inspect_cg, exempts the
# same process from the REDIRECT; this one exempts it from the DROP. A process
# needs both or it either reaches nothing or loops into the listener it is
# dialling past.
#
# The slice is pinned rather than taken from [resources].slice so the cgroup
# path is always exactly two components and the rule's `level 2` is exact.
# These sidecars are not the payload; resource control belongs on the VM.
NFT_SET_EGRESS_CG = "wl_egress_cg"
VM_SIDECAR_SLICE = "workloads.slice"
NFT_PROXY_SKELETON = "/usr/share/workloadctl/workload-proxy.nft"
NFT_PROXY_TABLE = "inet workload_proxy"

# The transparent redirect's objects (§7.1). The two maps carry one element per
# workload per redirected port, keyed uid . original port -> (listener address,
# listener port), one map per family because `dnat ip` and `dnat ip6` are
# different translations in the inet family; the set exempts the ONE process
# that re-originates workload-uid traffic -- the inspector, on the same terms
# and for the same reason as wl_egress_cg above -- so its own dials are not
# translated into the listener it is dialing past. All three live in table
# inet workload_proxy and are declared in workload-proxy.nft.
NFT_MAP_INSPECT4 = "wl_inspect4"
NFT_MAP_INSPECT6 = "wl_inspect6"
NFT_SET_INSPECT_CG = "wl_inspect_cg"

def vm_allowed_hosts(net: dict) -> list[str]:
    """The hostname allowlist for one workload, or [] if it has none."""
    hosts = net.get("hosts", [])
    return list(hosts) if isinstance(hosts, list) else []


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


def vm_runtime_dir(name: str) -> str:
    """Where one instance's config, allowlist, log and pid file live."""
    return f"{VM_SOCKET_DIR}/{name}"


# --- The inspector's policy document (§7.7.1, §13) ---
#
# The listener is socket-activated and long-lived, so it reads its lists once,
# at start, out of the workload's runtime directory — written at start rather
# than at generate time for the reason the retired proxy's config was: /run
# does not exist when the boot generator runs, and writing at start is what
# makes an edited list take effect on a plain `systemctl restart` with no
# regeneration. §13 states that recovery property, and the inspect service's
# PartOf= on the VM is what enforces it; a listener that held its lists in a
# file written at generate time would keep enforcing the previous boot's policy.
#
# JSON rather than a bare line-per-pattern file — the shape the proxy's
# hosts.allow had — because this document carries a mode as well as a list and
# will carry more of both.
VM_INSPECT_POLICY_FILE = "inspect.json"


def vm_inspect_policy_path(name: str) -> str:
    """Where one workload's inspector reads its lists from."""
    return f"{VM_SOCKET_DIR}/{name}/{VM_INSPECT_POLICY_FILE}"


VM_INSPECT_STATUS_FILE = "inspect-status.json"
VM_RESOLVE_STATUS_FILE = "resolve-status.json"

# The `drop_reasons` keys `workloadctl diagnose` reads back out of the
# inspector's status document.
#
# SECOND DEFINITIONS OF STRINGS THE LISTENER OWNS, and stated here for the
# reason VM_BROKER_LISTEN_ADDR is: `libexec/workload-vm-inspect-listener` is an
# extension-less entrypoint, so nothing in lib/ can import it. A reader either
# restates the key or matches on a substring -- and a substring is worse, since
# `not HTTP` is a prefix of `not HTTP (policy entry)` and `host does not match
# the server name` is a prefix of its allowlisted twin. Both splits exist
# BECAUSE the two halves need different operator responses, so a reader that
# merges them by prefix reports the opposite of what the split was for.
#
# tests/test_vm_inspect_diagnose.py pins each of these against the listener's
# own constant. That pin is what makes restating them safe: a rename over there
# fails a test here, rather than turning a figure into a permanent zero that
# reads exactly like a refusal that never fired.
VM_DROP_MISDIRECTED = "host does not match the server name"
VM_DROP_MISDIRECTED_LISTED = "host does not match the server name (allowlisted)"
VM_DROP_NOT_HTTP = "not HTTP"
VM_DROP_NOT_HTTP_POLICY = "not HTTP (policy entry)"


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

    `hosts` is `[vm.network].hosts` unchanged. The key kept its name and its
    meaning across rung 2 deliberately: an operator's allowlist means what it
    meant when a proxy read it, and the only thing that changed is which
    process reads it and whether the guest has to cooperate for it to apply.

    `internal` is carried and AUTHORISES NOTHING. An `internal` entry names a
    host that is already on a list (validation refuses one that is not), and it
    excepts the inspector's *upstream* leg from the internal drop rather than
    authorising a name. The listener never consults it to admit a connection:
    the kernel's wl_internal_ok4/6 elements are the one enforcement point, and a
    second one in userspace could disagree with them while both looked right.

    `splice` is the [[vm.network.splice]] host patterns, and unlike `internal`
    it DOES decide something: a name it matches is spliced rather than
    terminated, on a workload whose `tls` is otherwise "inspect". It is carried
    even when tls is "splice", where it changes nothing, so that the document
    describes the file rather than the file filtered through the mode -- a
    listener restarted onto a different `tls` reads a document that already
    says what the per-host list was.

    `http2` is the [[vm.network.http2]] host patterns. Like `splice` it
    DECIDES something -- a name it matches is offered h2 on both legs and
    relayed at frame level rather than parsed -- and like `splice` it is
    carried even when tls is "splice", so the document describes the file.

    `policy` is the [[vm.network.policy]] entries, normalised. `methods` and
    `paths` are carried as null where the key was absent rather than as an
    empty list, because absent means ANY and empty would mean NONE -- and JSON
    has a word for the difference, so the document should use it rather than
    make the reader recover it from the schema.

    It is here so that a FAILED upstream dial to a private address can be
    attributed. An allowlisted name that resolved into private space with no
    entry is the wildcard trap firing; one WITH an entry is a host that is
    simply down. Those are the same OSError without this list, and telling them
    apart is the whole value of the internal-refusal counter.

    NO `reason` OF ANY KIND IS CARRIED -- not the per-host ones, not
    `tls_reason`. A reason is written for a person reviewing the config, and
    the listener decides nothing by it; putting it in the document would give
    a guest-facing process a field it must never echo and would invite a
    future reader to treat one as data rather than as prose.
    """
    return {
        "tls": net.get("tls", VM_TLS_DEFAULT),
        "hosts": vm_allowed_hosts(net),
        "internal": vm_internal_hosts(net),
        "splice": vm_splice_hosts(net),
        "http2": vm_http2_hosts(net),
        "policy": [{"host": e.host,
                    "methods": None if e.methods is None else list(e.methods),
                    "paths": None if e.paths is None else list(e.paths)}
                   for e in vm_policy_entries(net)],
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


def vm_hostname_control_character(host: str) -> str | None:
    """The first control character in a name, or None if it carries none.

    A name read off the wire — an SNI, a DNS label — is bytes a guest chose,
    and both readers of one decode ASCII rather than refusing it: a control
    character is ASCII. The name then reaches a `print()` whose destination is
    the journal, where a bare LF ends the record and the rest of the name
    becomes a SECOND entry, indistinguishable from one this program wrote. A
    guest that can write `evil.com\\nsplice plane=tls … host=github.com` can
    forge the evidence an operator reads a decision from. The same name is also
    carried into the status document that `workloadctl diagnose` renders.

    Refused, not escaped, and refused at the parse — the reason
    `_reject_controls` in the cleartext plane gives for the same character
    class: a field with a line ending inside it has no reading both ends share,
    and rewriting one into something harmless is picking a reading. No name
    that reaches a decision here needs one, so the parse is where it stops
    rather than every log site having to remember.

    Returns the character so the caller can name it in ITS own exception type
    and disposition: an unreadable hello and a malformed query are already
    counted differently, and a shared raise would flatten them.
    """
    for ch in host:
        if ch < " " or ch == "\x7f":
            return ch
    return None


def vm_hostname_match(host: str, patterns) -> bool:
    """Whether a hostname is authorised by a list of fnmatch patterns.

    `fnmatch.fnmatchcase`, not `fnmatch.fnmatch`. The plain form normalises its
    arguments through os.path.normcase, which is a no-op on Linux and lowercases
    on other platforms — so it is case-insensitive only by accident of platform,
    and the operators' patterns were written against fnmatch's case-sensitive
    behaviour. Both sides are normalised here instead, which is the same answer
    everywhere.

    The apex trap is preserved, not fixed: `*.example.com` does not authorise
    `example.com`. That is fnmatch's behaviour, it is what the proxy this
    replaced did with the same list, and three tracked files document it. A rung that
    quietly widened it would silently grant every existing config a destination
    its operator did not write down.
    """
    host = vm_normalise_hostname(host)
    if not host:
        return False
    return any(fnmatch.fnmatchcase(host, vm_normalise_hostname(p))
               for p in patterns)


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


def vm_internal_ok_list_commands() -> list[list[str]]:
    """argv lists that dump each `internal` exemption set as JSON, v4 then v6."""
    return [[NFT_BIN, "-j", "list", "set", *NFT_TABLE.split(), set_name]
            for set_name in (NFT_SET_INTERNAL_OK4, NFT_SET_INTERNAL_OK6)]


def vm_internal_ok_uid_elements(uid: int, payload, user_name=None) -> list[str]:
    """The element expressions in one dumped set that belong to `uid`.

    THIS IS THE HANDLE THE CONFIG IS NOT. The exemptions are armed from names,
    and a teardown that re-resolves those names to compute its deletes removes
    whatever the names mean NOW -- so a record that rotated while the VM ran
    leaves the OLD (uid, address) element armed, with no config line naming it
    and nothing to remove it before a reboot. The next start then adds the new
    address beside it, and the workload is exempted for an address its config
    stopped naming. The uid is the one key that cannot rotate: every element
    this workload ever armed carries it, so purging by uid removes exactly the
    set of them, resolvable or not.

    nft renders the uid half of the key as a NUMBER when it cannot name it and
    as a USERNAME when it can -- which on a real host, where `_wl-<name>`
    exists, is the usual case. Both are matched, plus the numeric string, so
    the purge does not silently no-op on precisely the hosts it runs on. The
    address half is passed through as nft rendered it, so it goes back exactly
    as it was read.
    """
    wanted = {uid, str(uid)}
    if user_name:
        wanted.add(user_name)
    out = []
    for elem in nft_set_elements(payload):
        if not isinstance(elem, dict):
            continue
        key = elem.get("concat")
        if not isinstance(key, list) or len(key) != 2:
            continue
        owner, address = key
        if owner in wanted:
            out.append(f"{owner} . {address}")
    return out


def vm_internal_ok_delete_commands(set_name: str,
                                   entries: list[str]) -> list[list[str]]:
    """argv lists deleting exactly `entries` from one exemption set."""
    if not entries:
        return []
    return [[NFT_BIN, "delete", "element", *NFT_TABLE.split(), set_name,
             "{ " + ", ".join(entries) + " }"]]


def vm_internal_hosts(net: dict) -> list[str]:
    """The host names in [[vm.network.internal]], in file order.

    Shape-tolerant, while vm_internal_resolve two functions down is fatal on
    the same key at the same moment. The two are not in tension, and the
    difference is which question is still open at start.

    SHAPE IS ALREADY SETTLED. validate_vm_network refuses a malformed entry --
    not a table, no `host`, no `reason`, an unknown key, a host on no list --
    and the boot generator SKIPS a workload whose config does not validate, so
    it emits no units at all. A malformed entry therefore cannot reach this
    function on the boot path: there is no VM for it to break. Raising here
    would restate a verdict already delivered, in a context that can only
    convert it into a start failure with a worse message.

    RESOLUTION IS NOT SETTLED, AND CANNOT BE. Whether a name answers is a fact
    about the host and the moment, not about the config -- `validate` warns on
    it precisely because it cannot decide it. So the check has to happen at
    start, and its failure is deliberately fatal: an exemption that silently
    did not arm leaves the guest refused by the very drop the entry existed to
    except. See workload-vm-inspect's internal_failure for what that failure
    then has to say for itself.

    So: tolerate what validation owns, fail loudly on what only start can know.
    """
    return _host_reason_hosts(net, "internal")


def vm_splice_hosts(net: dict) -> list[str]:
    """The host patterns in [[vm.network.splice]], in file order.

    HLD §11's second escape hatch: one host that must not be terminated,
    exempted on a plain restart. The third hatch -- `tls = "splice"` for the
    whole workload -- is a different key and this list is not consulted under
    it, because there everything is spliced already.

    Shape-tolerant for the reason vm_internal_hosts is: validate_vm_network
    owns the shape and the boot generator skips a workload that does not
    validate, so a malformed entry cannot reach here on the boot path.
    """
    return _host_reason_hosts(net, "splice")


def vm_http2_hosts(net: dict) -> list[str]:
    """The host patterns in [[vm.network.http2]], in file order.

    HLD §8's narrow opt-in: a host here is offered `h2` on both legs and
    relayed at the frame level, so its `:authority` goes unread and true
    fronting stays open on it. Every OTHER terminated host is offered
    `http/1.1` alone, which is what makes `paths`, `methods` and the
    Host-binding work without an HPACK decoder anywhere.

    So this is a bypass with a written reason, beside `allow`, `internal` and
    `splice` -- not a performance flag. What keeps it from meaning EXEMPT is
    the preface and frame check on the listener's side: a connection here must
    actually speak h2. Read that half before widening this one.

    Shape-tolerant for the reason vm_internal_hosts is.
    """
    return _host_reason_hosts(net, "http2")


def _host_reason_hosts(net: dict, key: str) -> list[str]:
    """The `host` of every well-formed [[vm.network.<key>]] entry, in order.

    One body for `internal`, `splice` and `http2`, which are the same table
    with the same two keys -- the mirror of _validate_host_reason_entries on
    the validating side, and shared for the same reason: three copies of this
    is three chances for one of them to start tolerating a shape the other two
    refuse, on a path where the difference is silent.
    """
    entries = net.get(key, [])
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

    The pinned slice plus the unit name, so the path is always two components
    and the rule's `level 2` is exact. The
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
    return f"{VM_SIDECAR_SLICE}/workload-{name}-inspect.service"


def vm_inspect_cgroup_command(name: str, action: str) -> list[str]:
    """`nft add|delete element` for one inspector's redirect exemption.

    The element lives in the *proxy* table, not the filter table — the
    opposite of vm_inspect_cgroup_filter_command. Backwards, it fails only at load
    time with `did you mean set 'wl_egress_cg' in table inet
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
    wl_egress_cg its own upstream connections hit the default-deny drop and it
    reaches nothing. The twin is owed by the same unit's start and stop as
    vm_inspect_cgroup_command's: a helper that does one of the two and not
    the other produces an inspector that either reaches nothing (this one
    missing) or redirects its own dials into itself (the other missing).
    """
    return [NFT_BIN, action, "element", *NFT_TABLE.split(), NFT_SET_EGRESS_CG,
            '{ "' + vm_inspect_cgroup(name) + '" }']


# Where the guest finds the CA whose certificates the inspector's spliced
# connections are presented under. A guest path, not a host path: the file
# arrives inside the seed and is written by cloud-init.
#
# /usr/local/share/ca-certificates is the directory `update-ca-certificates`
# consumes on Debian-family guests; Fedora's anchors live elsewhere. The five
# variables below name the FILE directly rather than relying on either, because
# the whole point of the block is to work in a guest whose distribution we do
# not choose.
VM_CA_BUNDLE_PATH = "/usr/local/share/ca-certificates/workloadctl-egress.crt"

# The environment variables that point a guest's HTTP clients at that bundle.
# Five, because there is no single one: OpenSSL reads SSL_CERT_FILE, Node reads
# NODE_EXTRA_CA_CERTS, python-requests reads REQUESTS_CA_BUNDLE, git reads
# GIT_SSL_CAINFO and pip reads PIP_CERT. A guest missing any one of them fails
# only in that ecosystem, which is the hardest kind of failure to attribute.
VM_CA_ENV_VARS = (
    "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "PIP_CERT",
)

# --- The guest's paravirtual clock (ptp_kvm) ---
#
# The guest-side half of the remedy whose host-side half is lib/vm_clock. Both
# exist for the same failure -- a vCPU pause is lost by the guest exactly and
# permanently, and NTP cannot repair it -- and they fail in opposite directions,
# which is why neither replaces the other. The host's check repairs a guest that
# has no idea anything happened, but only on a mint cache miss and only if the
# guest runs qemu-guest-agent. This repairs the guest on its own four-second
# poll with no agent and no host involvement, but only if the guest was seeded
# with it. A guest that has both is repaired before anything asks it to be.
#
# NOTHING IS NEEDED ON THE HOST. ptp_kvm is not a QEMU device and takes no
# argument: on x86_64 the guest driver issues a KVM hypercall (KVM_HC_CLOCK_
# PAIRING) that pairs its TSC with the host's realtime clock, and on aarch64 an
# equivalent SMCCC call. Everything it needs is already implied by the
# `-machine q35,accel=kvm -cpu host` the generator emits. That is the whole
# reason to prefer it over a host NTP server the guests dial: it is the only
# correction path that survives the egress filter, because it sends no packets.
#
# What IS required of the host is a condition rather than a setting, and it is
# the one that catches people: the host's own clocksource must be the TSC. KVM
# answers the clock-pairing hypercall EOPNOTSUPP otherwise, so on a host running
# hpet or acpi_pm the module refuses to load in every guest -- measured
# 2026-08-26 on a development host with no tsc in available_clocksource at all,
# where every piece of the seed below was correct and the device still never
# appeared. Such a guest keeps its stock time configuration and is covered by
# lib/vm_clock's host-side check alone.
#
# THREE PIECES, AND THE LEAST OBVIOUS ONE IS LOAD-BEARING
#
#   - the module, which no cloud image loads on its own;
#   - a stable name for the device. /dev/ptpN is allocation-ordered, so a guest
#     with a PTP-capable NIC or a passed-through device can put the KVM clock on
#     ptp1. The rule below selects on the driver's own clock_name, which is the
#     only selector that cannot be reordered;
#   - `makestep 1 -1`, which is the piece that actually fixes the bug. Fedora's
#     stock chrony.conf says `makestep 1.0 3`: step for the first three updates,
#     slew forever after. Slewing is capped near 83 us/s, so the two-hour rewind
#     measured in tests/manual/clock_rig.py would take months to walk off -- the
#     guest would spend all of it inside the window where new leaves fail to
#     validate. `-1` means "step whenever the offset exceeds a second, always",
#     which is right here and would be wrong on a public NTP client, where an
#     unconditional step is a thing an attacker can aim.
#
# The chrony half is written by runcmd rather than write_files BECAUSE IT IS
# CONDITIONAL. chronyd treats a refclock it cannot open as fatal, so a seed that
# unconditionally appends the refclock line would leave a guest on a host
# without ptp_kvm with no time service at all -- trading a clock that is wrong
# after a pause for a clock that is unmanaged always.
VM_PTP_KVM_MODULE = "ptp_kvm"
VM_PTP_KVM_CLOCK_NAME = "KVM virtual PTP"
VM_PTP_KVM_DEVICE = "/dev/ptp_kvm"
VM_PTP_KVM_MODULES_LOAD_PATH = "/etc/modules-load.d/ptp-kvm.conf"
VM_PTP_KVM_UDEV_RULE_PATH = "/etc/udev/rules.d/70-ptp-kvm.rules"
VM_PTP_KVM_CHRONY_PATH = "/etc/chrony.conf"

# The marker the runcmd block greps for before appending. Idempotence matters
# even though cloud-init runs runcmd once per instance id, because the id
# rotates whenever the seed's text changes -- so any later edit to the seed
# replays this block on a guest that already has the lines.
VM_PTP_KVM_CHRONY_MARKER = "# workloadctl: paravirtual clock"


def vm_ptp_kvm_seed_files() -> list[tuple[str, str, str]]:
    """(path, permissions, content) for the seed's write_files entries."""
    return [
        (VM_PTP_KVM_MODULES_LOAD_PATH, "0644", f"{VM_PTP_KVM_MODULE}\n"),
        (VM_PTP_KVM_UDEV_RULE_PATH, "0644",
         f'SUBSYSTEM=="ptp", ATTR{{clock_name}}=="{VM_PTP_KVM_CLOCK_NAME}", '
         f'SYMLINK+="{VM_PTP_KVM_DEVICE.removeprefix("/dev/")}"\n'),
    ]


def vm_ptp_kvm_runcmd_lines() -> list[str]:
    """The shell that loads the module and points chrony at it, if it is there.

    Returned as lines rather than spelled into the renderer so the built-in
    seed, the shipped reference seeds and the tests assert against one text.
    """
    return [
        "udevadm control --reload-rules || true",
        # The wait is bounded and only happens when the module actually loaded.
        # `udevadm settle` was here and is not enough on its own: it can return
        # before a just-queued uevent is visible, and the symptom of losing that
        # race is indistinguishable from the host not supporting ptp_kvm at all.
        # Gating on modprobe's exit status is also what keeps the wait off the
        # boot of a guest on a host that cannot offer the clock, where the
        # module fails immediately and no amount of waiting would help.
        f"if modprobe {VM_PTP_KVM_MODULE} 2>/dev/null; then",
        f"  for _ in 1 2 3 4 5; do [ -e {VM_PTP_KVM_DEVICE} ] && break;"
        f" sleep 1; done",
        "fi",
        # `-f` before the grep, and it is not belt-and-braces: grep on a
        # missing file exits 2, which `!` turns into true, so without it a
        # guest whose image ships no chrony at all gets a /etc/chrony.conf
        # CREATED here holding a refclock and nothing else -- a config file
        # for a service that is not installed, which reads to the next person
        # as a chrony that is configured and broken rather than absent.
        f"if [ -e {VM_PTP_KVM_DEVICE} ] && [ -f {VM_PTP_KVM_CHRONY_PATH} ] &&"
        f" ! grep -qF '{VM_PTP_KVM_CHRONY_MARKER}' {VM_PTP_KVM_CHRONY_PATH}; then",
        f"  printf '%s\\n' '{VM_PTP_KVM_CHRONY_MARKER}'"
        f" 'refclock PHC {VM_PTP_KVM_DEVICE} poll 2 dpoll -2 offset 0'"
        f" 'makestep 1 -1' >> {VM_PTP_KVM_CHRONY_PATH}",
        "  systemctl restart chronyd || true",
        "fi",
    ]

# --- The per-workload egress CA ---
#
# One CA per workload, generated like the SSH host keypair: idempotent, made
# once, NEVER churned, and created before the seed ISO that carries it.
#
# Per-workload scoping is what makes the key affordable. It lives in the
# workload's state directory owned by _wl-<name> -- the same uid QEMU runs as --
# and the only party trusting it is the guest that uid already owns, so a guest
# escape stealing it gains the ability to impersonate sites TO ITSELF. A single
# host-wide CA shared by every workload would be a genuine crown jewel.
#
# `backup` never captures state/, so the key is in no archive and needs no
# exclusion rule.

VM_CA_DIR_NAME = "ca"
VM_CA_KEY_NAME = "egress-ca.key"
VM_CA_CERT_NAME = "egress-ca.crt"

# The two leaf caches live beside the CA, under the same state directory, and
# their names are here rather than in vm_mint because the SELinux patterns
# below have to name the same three directories the minter creates. A drift
# between the two spellings is a mislabelled directory, which presents as the
# inspector failing to mint and not as a naming mistake.
VM_LEAF_DIR_NAME = "leaves"
VM_DENIAL_DIR_NAME = "leaves-denied"

# THE PKI SUBTREE HAS ITS OWN LABELS, AND THAT IS THE WHOLE POINT
#
# `wlinspect_t` is a separate domain from `svirt_t` so that the component
# terminating guest input cannot reach the workload's disks, volumes or state
# directory. Rung 3 gives the inspector a reason to read a private key and
# write a cache, and both live in that state directory beside the disk images.
# Granting the domain `svirt_image_t` would be one rule shorter, would work,
# and would hand the inspector the guest's disks — so the material moves
# instead: three directories with labels of their own, and the domain is
# granted those.
#
# Two types, not one, because the permissions genuinely differ. The CA is
# READ-ONLY to the inspector: an inspector that could rewrite it could replace
# the anchor the guest was seeded with, which is unrecoverable without a
# re-provision. The leaves are read-write because minting them is the job.
VM_CA_SELINUX_TYPE = "wlinspect_ca_t"
VM_LEAF_SELINUX_TYPE = "wlinspect_leaf_t"

# Ten years. The number follows from never rotating rather than from any threat
# estimate: a CA that expires is a CA that must be replaced, replacing it means
# re-provisioning the guest (cloud-init runs once per instance-id), so the
# validity is the real upper bound on a VM's life. Ten years puts that boundary
# beyond the hardware's, which is the point -- anything shorter schedules a
# total outage, every HTTPS request failing validation on a VM `diagnose` calls
# healthy, for a date nobody wrote down.
#
# Distance is not the same as invisibility: the CA report carries notAfter and
# `diagnose` warns inside the last year, so a workload that lives long enough
# to reach it gets a re-provision SCHEDULED rather than discovered.
VM_CA_VALIDITY_DAYS = 3650

# notBefore is backdated an hour for clock skew. Measured 2026-08-26: guest
# drift is ~10 ppm (about five minutes a year), so this covers roughly 1,200
# years of it -- and exactly ONE HOUR of a vCPU pause, which a guest loses
# permanently. The backdate is not what makes pauses survivable; the mint-time
# clock check is. See tests/manual/clock_rig.py.
VM_CA_BACKDATE_SECONDS = 3600


def vm_ca_dir(state_dir) -> Path:
    """Where this workload's egress CA lives, given its state directory."""
    return Path(state_dir) / VM_CA_DIR_NAME


def vm_ca_key_path(state_dir) -> Path:
    return vm_ca_dir(state_dir) / VM_CA_KEY_NAME


def vm_ca_cert_path(state_dir) -> Path:
    return vm_ca_dir(state_dir) / VM_CA_CERT_NAME


def vm_leaf_dir(state_dir) -> Path:
    """Where the working set of minted leaves lives."""
    return Path(state_dir) / VM_LEAF_DIR_NAME


def vm_denial_dir(state_dir) -> Path:
    """Where leaves minted under a refusal live -- a sibling of the working
    set, not a subdirectory, so a `rm -rf` of one cannot take the other."""
    return Path(state_dir) / VM_DENIAL_DIR_NAME


def vm_pki_fcontext_patterns(name: str) -> list[tuple[str, str]]:
    """(pattern, type) for every directory in one workload's PKI subtree.

    Registered in `file_contexts.local` beside the per-workload svirt_image_t
    rule, and more specific than it, which is the only reason these win: within
    ONE source most-specific-wins applies, and `.local` outranks the base file
    wholesale. A CIL `filecon` in the policy module lands in the base file and
    would be silently shadowed -- see shadowed_filecon_paths().
    """
    root = workload_root_dir(name)
    return [
        (f"{root}/state/{VM_CA_DIR_NAME}(/.*)?", VM_CA_SELINUX_TYPE),
        (f"{root}/state/{VM_LEAF_DIR_NAME}(/.*)?", VM_LEAF_SELINUX_TYPE),
        (f"{root}/state/{VM_DENIAL_DIR_NAME}(/.*)?", VM_LEAF_SELINUX_TYPE),
    ]


def vm_ca_subject(name: str) -> str:
    """The CA's subject. Names the workload, because an operator reading a
    certificate error inside a guest needs to know which CA it came from."""
    return f"/CN=workloadctl egress CA ({name})"


def vm_ca_openssl_argv(name: str, key_path, cert_path, *, now: float) -> list[str]:
    """One `openssl req -x509` invocation that mints the CA.

    THE THREE EXTENSIONS ARE NOT DECORATION. Measured 2026-08-16: Python 3.14's
    ssl (OpenSSL 3.5) rejects a chain whose CA lacks a Subject Key Identifier
    with `certificate verify failed: Missing Authority Key Identifier`, and
    then -- once that is added -- with `CA cert does not include key usage
    extension`. curl, Go and Node accept the same CA without any of them, so a
    CA missing them works everywhere until a Python client tries, and presents
    as a trust failure indistinguishable from "the guest never installed our
    CA". They are asserted by parsing the certificate, not by matching this
    argv: what matters is what OpenSSL emitted, not what we asked for.

    `-not_before` is used rather than letting notBefore default to now, so the
    hour of skew tolerance is a property of the certificate rather than of when
    the process happened to run. Requires OpenSSL 3.5, which is what Fedora 43
    and 44 ship.

    ECDSA P-256 to match the leaves: RSA-2048 minting is slow enough to be
    noticeable on a cold cache.
    """
    not_before = time.strftime(
        "%Y%m%d%H%M%SZ", time.gmtime(now - VM_CA_BACKDATE_SECONDS))
    return [
        "openssl", "req", "-x509",
        "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-noenc",
        "-keyout", str(key_path),
        "-out", str(cert_path),
        "-days", str(VM_CA_VALIDITY_DAYS),
        "-not_before", not_before,
        "-subj", vm_ca_subject(name),
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash",
    ]


# Whether there is a bundle at VM_CA_BUNDLE_PATH for those variables to name.
# TRUE SINCE RUNG 3 T3, which is the commit that mints the CA into the seed.
# The paragraphs below are kept as written rather than trimmed: they are the
# reason this flag exists at all, and they are the argument against anyone
# splitting the three changes it binds together back apart.
#
# THIS IS NOT CAUTION, IT IS THE DIFFERENCE BETWEEN WORKING AND BROKEN. Every
# one of those five variables REPLACES the runtime's default trust store rather
# than adding to it, and every one of them fails closed when the file it names
# does not exist: OpenSSL's SSL_CERT_FILE pointing at a missing path makes
# loading the default verify paths fail outright, and requests, git and pip
# raise on the open. Writing the block one rung early would take TLS
# verification down inside every filtered guest, for a certificate nothing is
# presenting yet -- a total outage in exchange for avoiding one seed migration.
#
# So the SEAM moves at rung 2 and the CONTENT at rung 3: the function, its call
# site, the variable names and the guest path are all settled and tested here,
# and rung 3 changes one boolean and adds the write_files entry. The cost is the
# one the flag is paying for: a workload with no broker loses its guest
# environment block at rung 2 and regains it at rung 3, which is a seed
# migration for those workloads. A guest that cannot verify certificates is
# worse than a guest re-seeded twice.
#
# THREE THINGS MOVE TOGETHER OR NONE OF THEM DO: this flag, the write_files
# entry in _render_default_user_data that puts the PEM at VM_CA_BUNDLE_PATH,
# and the seed contract in build_cloud_init_iso. Flipping this alone points
# five variables at a file nothing writes, which is the total outage described
# above -- so it is not a "safe" partial step, it is the worst of the three.
VM_CA_BUNDLE_AVAILABLE = True


def vm_ca_env(config: dict) -> dict[str, str]:
    """The CA environment a filtered guest is given, or {} if it has none.

    WHAT THIS REPLACED, AND WHY THE SEAM SURVIVED THE THING IN IT

    Through rung 1 this call wrote http_proxy/https_proxy/no_proxy at an
    advertised literal, and the guest's cooperation was load-bearing: a client
    that ignored the variables did not use the proxy, and the default-deny chain
    could only turn that into a dropped connection. Rung 2's redirect is
    transparent, so no variable in a guest can turn the filtering off or on —
    and none of those six variables is written any more. A guest that still sets
    https_proxy to the old literal now reaches a host address where nothing
    listens.

    The CALL is the same call at the same point, writing the same
    once-per-instance-id block into the same seed. That is deliberate: the seed
    has carried a guest environment block since rung 0, and a rung that deleted
    the block and a later rung that re-added it would be two migrations of the
    seed contract where one will do.

    THE VALUES ARE HERE, SINCE RUNG 3

    They were not, for one rung: the shape and the guest path moved first so
    that the variable names were settled before there was a certificate to put
    at the end of them. There is one now. This workload's own CA is minted into
    its state directory, written into the seed at VM_CA_BUNDLE_PATH, and named
    by these five variables -- and under the default `tls = "inspect"` the guest
    NEEDS it, because the leaf the inspector presents is signed by nothing else.

    ONCE PER INSTANCE ID, the same caveat the proxy block carried. cloud-init
    replays a seed only when the instance id changes, so editing this block on a
    running guest changes nothing until the VM is re-seeded — and an operator
    who switches egress mode on a live workload gets a guest whose environment
    still describes the previous mode.
    """
    if not vm_uses_inspect(config) or not VM_CA_BUNDLE_AVAILABLE:
        return {}
    return {var: VM_CA_BUNDLE_PATH for var in VM_CA_ENV_VARS}


# --- Leaves ---
#
# What the CA above signs, one per exact name the guest asks for.

# Thirty days. Short because nothing renews these -- the working-set cache
# re-mints inside 24 h of expiry and that is the whole rotation story -- and
# because a leaf that leaked is a leaf valid for one host, for a month, signed
# by a CA one guest trusts. Long enough that a VM which runs for a fortnight
# never re-mints its working set.
VM_LEAF_VALIDITY_DAYS = 30

# Re-mint once a leaf is inside this of notAfter. A day, so a long-running
# connection opened just under the wire still outlives its certificate by an
# order of magnitude.
VM_LEAF_RENEW_WITHIN_SECONDS = 86400


class LeafRefused(ValueError):
    """A name that will not be minted for, with the reason in the message.

    Raised BEFORE openssl is reached, which is the point: every character of
    the name below travels into an `-addext` argument, and `subjectAltName`
    takes a comma-separated list. A name carrying a comma would add extensions
    of the guest's choosing to a certificate the host signs. Nothing downstream
    of here re-checks, so this function is the boundary.
    """


# The longest a DNS name may be, and the longest one label may be (RFC 1035).
VM_LEAF_NAME_MAX = 253
VM_LEAF_LABEL_MAX = 63

_LEAF_LABEL_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz0123456789-_")


def vm_leaf_san(name: str) -> str:
    """The subjectAltName value for one name, or raise LeafRefused.

    ALLOWLIST, NOT DENYLIST. The obvious spelling of this check is to reject
    the characters that hurt -- comma, newline, `=` -- and it is the wrong
    shape: the set of characters that mean something to openssl's extension
    parser is openssl's to change, and a name is guest-chosen input reaching a
    subprocess argument. So the check names what is permitted and refuses the
    rest, which is a rule that cannot rot.

    An IP literal becomes an `IP:` SAN rather than a `DNS:` one. A `DNS:`
    entry holding an address does not match when a client connects to that
    address -- so minting one would produce a certificate that verifies
    nowhere, and the failure would present as an unexplained handshake error
    rather than as a refusal.

    `_` is permitted in a label though RFC 1035 forbids it: it is common in
    real service names, and every client this design faces resolves and
    validates such names. Refusing them would break traffic the allowlist
    authorised, which is the failure this whole rung exists to avoid.
    """
    name = vm_normalise_hostname(name)
    if not name:
        raise LeafRefused("empty name")

    try:
        return f"IP:{ipaddress.ip_address(name)}"
    except ValueError:
        pass

    if len(name) > VM_LEAF_NAME_MAX:
        raise LeafRefused(f"name longer than {VM_LEAF_NAME_MAX} characters")
    labels = name.split(".")
    for label in labels:
        if not label:
            raise LeafRefused(f"empty label in {name!r}")
        if len(label) > VM_LEAF_LABEL_MAX:
            raise LeafRefused(f"label longer than {VM_LEAF_LABEL_MAX} "
                              f"characters in {name!r}")
        bad = set(label) - _LEAF_LABEL_CHARS
        if bad:
            raise LeafRefused(
                f"character {sorted(bad)[0]!r} not permitted in a name")
    return f"DNS:{name}"


def vm_leaf_openssl_argv(name: str, ca_key_path, ca_cert_path,
                         key_path, cert_path, *, now: float) -> list[str]:
    """One `openssl req -x509 -CA` invocation that mints a leaf for `name`.

    A single process, not a CSR and a sign: `req -x509` takes `-CA`/`-CAkey`
    since OpenSSL 3.0 and does both, which halves the cost of the thing the
    token bucket exists to ration.

    THE SAN IS CRITICAL, AND THAT IS LOAD-BEARING. The subject is empty (there
    is no meaningful CN for a name the host does not own), and RFC 5280 says a
    certificate with an empty subject MUST mark subjectAltName critical.
    Measured 2026-08-26: without the flag, Python's ssl rejects the chain with
    `Subject empty and Subject Alt Name extension not critical` -- a verify
    failure whose message names neither the SAN value nor the CA, so it reads
    like a trust problem and sends a reader to the anchor.

    THE SAN CARRIES THE EXACT NAME, NEVER THE ALLOWLIST PATTERN THAT MATCHED.
    A `*.example.com` entry authorises the guest to reach names under it; a
    leaf minted for `*.example.com` would be a certificate the guest could use
    against any of them, including ones a later narrowing of the list removes.
    One name asked for, one name signed.

    notBefore is backdated by the same hour the CA is, for the same reason and
    with the same caveat -- see VM_CA_BACKDATE_SECONDS, and the mint-time clock
    check that is the actual remedy for a paused guest.
    """
    not_before = time.strftime(
        "%Y%m%d%H%M%SZ", time.gmtime(now - VM_CA_BACKDATE_SECONDS))
    return [
        "openssl", "req", "-x509",
        "-CA", str(ca_cert_path),
        "-CAkey", str(ca_key_path),
        "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-noenc",
        "-keyout", str(key_path),
        "-out", str(cert_path),
        "-days", str(VM_LEAF_VALIDITY_DAYS),
        "-not_before", not_before,
        "-subj", "/",
        "-addext", f"subjectAltName=critical,{vm_leaf_san(name)}",
        "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
        "-addext", "extendedKeyUsage=serverAuth",
        "-addext", "subjectKeyIdentifier=hash",
        "-addext", "authorityKeyIdentifier=keyid",
    ]


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
# The broker is now the ONLY thing at the advertised address. Through rung 1 it
# shared that address with the per-workload proxy, distinguished by port; rung 2
# deleted the proxy and left the port distinguishing the broker from nothing.
# The address is kept rather than collapsed into a bare port: it is what a
# guest's seed already names, and moving it would re-seed every workload to buy
# tidiness.
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
    policy and inspection (§5.3): nothing of ours is in its data path, so there
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

    An IP literal, so reaching the broker never depends on DNS -- which is what
    a compromised guest would attack to escape policy. It is also why the broker
    is advertised at an address and not a name: a name would be resolved by the
    synthesising responder, which answers for allowlisted hosts and would have
    to be taught about this one.
    """
    if not vm_uses_broker(config):
        return {}
    return {VM_BROKER_ENV_VAR: f"http://{VM_ADVERTISED_ADDR}:{VM_BROKER_PORT}"}


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
    result = run([IP_BIN, "link", "add", VM_ADVERTISED_IFACE, "type", "dummy"])
    if result.returncode != 0 and "File exists" not in result.stderr:
        raise RuntimeError(
            f"could not create {VM_ADVERTISED_IFACE}: {result.stderr.strip()}")

    # Query, then add. Not "add and tolerate the error": iproute2 answers a
    # duplicate address with "Address already assigned", not the "File exists"
    # the duplicate-link case produces, so a string match on the wrong phrase
    # fails only on the SECOND start of a workload — which is how this was
    # found, and not by any test.
    shown = run([IP_BIN, "-o", "addr", "show", "dev", VM_ADVERTISED_IFACE])
    if VM_ADVERTISED_ADDR not in shown.stdout:
        result = run([IP_BIN, "addr", "add", f"{VM_ADVERTISED_ADDR}/32",
                      "dev", VM_ADVERTISED_IFACE])
        if result.returncode != 0 and "xist" not in result.stderr \
                and "assigned" not in result.stderr:
            raise RuntimeError(
                f"could not add {VM_ADVERTISED_ADDR} to {VM_ADVERTISED_IFACE}: "
                f"{result.stderr.strip()}")

    result = run([IP_BIN, "link", "set", VM_ADVERTISED_IFACE, "up"])
    if result.returncode != 0:
        raise RuntimeError(
            f"could not bring up {VM_ADVERTISED_IFACE}: {result.stderr.strip()}")


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
    v4 = [IP_BIN, "addr", "add", f"{addr.v4}/32", "dev", VM_ADVERTISED_IFACE]
    v6 = [IP_BIN, "addr", "add", f"{addr.v6}/128", "dev", VM_ADVERTISED_IFACE,
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
    v4 = [IP_BIN, "addr", "del", f"{addr.v4}/32", "dev", VM_ADVERTISED_IFACE]
    v6 = [IP_BIN, "addr", "del", f"{addr.v6}/128", "dev", VM_ADVERTISED_IFACE]
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

# The inspector's and the responder's domains, installed the same way and for
# the same reason. Named here rather than only in the spec because `diagnose`
# compares each loaded module against the source the RPM shipped: a module
# missing from that list is a domain whose policy can drift out from under a
# running host with nothing saying so, which is the failure the check exists
# for. They replaced workload-proxy, which the RPM's %post now removes.
VM_INSPECT_SELINUX_MODULE = "workload-inspect"
VM_INSPECT_SELINUX_CIL = "/usr/share/workloadctl/workload-inspect.cil"
VM_RESOLVE_SELINUX_MODULE = "workload-resolve"
VM_RESOLVE_SELINUX_CIL = "/usr/share/workloadctl/workload-resolve.cil"

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
# schema has (`internal` below; `splice` and `http2` from rung 4). The bare
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
    "bridge", "ports", "resolver", "egress", "hosts", "tls", "tls_reason",
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

    `policy` is carried BESIDE `hosts` and for the same counting reason, not as
    a second thing to answer from. §3 lets a name be allowlisted by a
    [[vm.network.policy]] entry alone, so a workload whose whole allowlist is
    written as policy entries has an empty `hosts` and is perfectly valid --
    and a responder that knew only `hosts` would count every legitimate lookup
    it makes as unlisted. That fails in the direction that costs the most: the
    tunnelling signature reads loud and constant on a correct config, which is
    how a detector stops being read at all. Kept as its own key rather than
    merged into `hosts` because the document describes the FILE, and the two
    keys are two different statements about a name.
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
        "hosts": vm_allowed_hosts(net),
        "policy": [e.host for e in vm_policy_entries(net)],
    }



# The HTTP methods a [[vm.network.policy]] entry may name. Registered tokens
# only (IANA HTTP Method Registry), because §3 requires a method that is not one
# to be an ERROR rather than a rule that can never match: `["FETCH"]` and
# `["GET "]` are both far likelier to be a typo that silently denies than an
# intent, and a denial nobody can see is the failure this layer exists to
# prevent.
#
# CONNECT and PRI are registered and are deliberately NOT here. The inspector is
# transparent -- it is reached by a redirect, never by a proxy request -- so a
# guest has no CONNECT to send it and an entry permitting one describes a
# request that cannot arrive. PRI is the HTTP/2 connection preface's method,
# which is refused on a terminated host and checked as a preface on an `http2`
# one; permitting it by name would read as a way to allow h2 through `policy`,
# which is exactly the thing `http2` carries a written reason for.
VM_POLICY_METHODS = frozenset((
    "ACL", "BASELINE-CONTROL", "BIND", "CHECKIN", "CHECKOUT", "COPY", "DELETE",
    "GET", "HEAD", "LABEL", "LINK", "LOCK", "MERGE", "MKACTIVITY",
    "MKCALENDAR", "MKCOL", "MKREDIRECTREF", "MKWORKSPACE", "MOVE", "OPTIONS",
    "ORDERPATCH", "PATCH", "POST", "PROPFIND", "PROPPATCH", "PUT", "REBIND",
    "REPORT", "SEARCH", "TRACE", "UNBIND", "UNCHECKOUT", "UNLINK", "UNLOCK",
    "UPDATE", "UPDATEREDIRECTREF", "VERSION-CONTROL",
))

VM_POLICY_METHODS_REFUSED = {
    "CONNECT": "the inspector is transparent and is never sent a CONNECT; a "
               "guest reaches it by a redirect it cannot see",
    "PRI": "PRI is the HTTP/2 connection preface's method; h2 on a host is "
           "[[vm.network.http2]], which carries a written reason",
}


class VmPolicyEntry(NamedTuple):
    """One [[vm.network.policy]] entry, normalised.

    `methods` and `paths` are `None` where the key was absent, NOT an empty
    tuple, and the difference is the whole of §3's widening trap: absent means
    "any", empty would mean "none". Collapsing the two makes a single-entry
    host with no `paths` deny everything instead of permitting everything --
    the failure in the safe direction, which is why it survives review.
    """

    host: str
    methods: tuple | None
    paths: tuple | None

    def permits(self, method: str, path: str) -> bool:
        """Whether this entry permits one method on one path.

        `methods` and `paths` inside one entry are a CROSS PRODUCT: two of each
        permit all four combinations. An absent key is "any", per the shorthand
        §3 keeps for the single-entry case.
        """
        if self.methods is not None and method.upper() not in self.methods:
            return False
        if self.paths is not None and not any(
                fnmatch.fnmatchcase(path, pattern) for pattern in self.paths):
            return False
        return True


def vm_policy_entries(net: dict) -> list[VmPolicyEntry]:
    """The [[vm.network.policy]] entries, normalised, in file order.

    Shape-tolerant for the reason vm_internal_hosts is: validate_vm_network
    owns the shape and the boot generator skips a workload that does not
    validate.
    """
    entries: list[VmPolicyEntry] = []
    raw = net.get("policy", [])
    if not isinstance(raw, list):
        return entries
    for item in raw:
        if not isinstance(item, dict):
            continue
        host = item.get("host")
        if not isinstance(host, str) or not host.strip():
            continue
        entries.append(VmPolicyEntry(
            host=host.strip(),
            methods=_normalise_policy_list(item.get("methods"), upper=True),
            paths=_normalise_policy_list(item.get("paths"))))
    return entries


def _normalise_policy_list(value, *, upper: bool = False) -> tuple | None:
    """One `methods` or `paths` value as a tuple, or None where it was absent.

    None and () are different answers and the caller depends on it; see
    VmPolicyEntry.
    """
    if value is None:
        return None
    if not isinstance(value, list):
        return ()
    out = []
    for item in value:
        if not isinstance(item, str):
            continue
        # NOT stripped: validation refuses a padded token or path outright,
        # so nothing that reaches here needs it, and a strip in one of the two
        # places is how they come to disagree about what the file said.
        out.append(item.upper() if upper else item)
    return tuple(out)


def vm_policy_governs(host: str, entries) -> list[VmPolicyEntry]:
    """The entries governing one hostname, which may be none.

    §3's composition rule lives here and is the thing to get right: a host with
    any matching entry is governed by THOSE ENTRIES ALONE, and `hosts` is not
    consulted for it. The careless reading -- a `hosts` entry is a `policy`
    entry with no keys, so union them -- silently destroys the feature: one
    wildcard written for an unrelated reason contributes "any method, any path"
    to every host it happens to cover, and the diff that introduced it looks
    like it ADDED access rather than removing a restriction.

    Host patterns union among themselves, so `*.example.com` and
    `api.example.com` both govern `api.example.com` and neither overrides the
    other. That is the apex trap's sibling, and it is why `diagnose` will have
    to print the EFFECTIVE rules per host rather than the file's entries --
    owed, not built, so do not cite it to an operator as though it were.
    """
    return [e for e in entries if vm_hostname_match(host, (e.host,))]


def vm_policy_permits(host: str, method: str, path: str, entries) -> bool:
    """Whether the governing entries permit one request. Union, not precedence.

    Every entry either permits something or does nothing, so REORDERING THE
    FILE CANNOT CHANGE WHAT IS ALLOWED. Two consequences follow and both look
    like bugs: there is no way to subtract -- a narrower entry cannot carve an
    exception out of a wider one -- and a specific entry does not override a
    general one.

    The caller decides what an empty governing set means; this function is only
    asked about a host some entry governs.
    """
    return any(e.permits(method, path)
               for e in vm_policy_governs(host, entries))


def _patterns_overlap(a: str, b: str) -> bool:
    """Whether two fnmatch host patterns can name a host in common.

    Approximate, and deliberately approximate in the ACCEPTING direction: it
    answers yes when either pattern matches the other read as a literal, which
    is exact whenever at least one of the two carries no wildcard and is a
    good-enough over-approximation when both do. `*.a.example.com` and
    `*.b.example.com` overlap on nothing and this says so; `*.example.com` and
    `*.com` overlap and this says so too.

    Used for the "this entry matches no allowlisted name" rules, where the two
    sides are an entry's `host` and an allowlist pattern and only one of them is
    ordinarily a wildcard. Wrong in the accepting direction means a dead entry
    occasionally survives validation; wrong the other way would refuse a config
    that works, which is the expensive mistake for a rule whose whole job is to
    catch a typo.
    """
    a = vm_normalise_hostname(a)
    b = vm_normalise_hostname(b)
    if not a or not b:
        return False
    return (a == b or fnmatch.fnmatchcase(a, b) or fnmatch.fnmatchcase(b, a))


def _validate_host_reason_entries(entries, key: str, reason_clause: str):
    """Shape-check an array of [[vm.network.<key>]] `host`/`reason` tables.

    Returns (hosts, errors). `hosts` holds the stripped `host` of every entry
    whose host was well-formed, in file order, so a caller can apply the rule
    that is its own -- which for all three users of this helper is some form of
    "this entry matches nothing, and a dead bypass fails silently".

    Shared because `internal`, `splice` and `http2` are the same table with the
    same two keys and the same two failure directions, and three copies of this
    drifted in review before there was one. What is NOT shared is the sentence
    each key gives for a missing `reason` (`reason_clause`) or for a dead entry:
    those name what the operator was trying to do, which is the whole value of
    the message.
    """
    errors: list[str] = []
    hosts: list[str] = []
    if not isinstance(entries, list):
        errors.append(
            f"[vm.network].{key} must be an array of [[vm.network.{key}]] "
            f"tables, got {type(entries).__name__}")
        return hosts, errors
    for item in entries:
        if not isinstance(item, dict):
            errors.append(
                f"[vm.network].{key} entries are tables with `host` and "
                f"`reason`, got {item!r}")
            continue
        unknown = sorted(set(item) - {"host", "reason"})
        if unknown:
            errors.append(
                f"[vm.network].{key}: unknown key(s) {', '.join(unknown)}; an "
                f"entry carries `host` and `reason` only")
        if "host" not in item:
            errors.append(f"[vm.network].{key}: entry {item!r} has no `host`")
            continue
        host = item.get("host")
        problems = _validate_proxy_host(host)
        if problems:
            errors.extend(f"[vm.network].{key}: {p}" for p in problems)
            continue
        host = host.strip()
        hosts.append(host)
        if not isinstance(item.get("reason"), str) or not item["reason"].strip():
            errors.append(f"[vm.network].{key}: {host!r} has no `reason`; "
                          f"{reason_clause}")
    return hosts, errors


def _validate_policy_path(pattern) -> list[str]:
    """Validate one [[vm.network.policy]] `paths` pattern."""
    if not isinstance(pattern, str):
        return [f"`paths` entries must be strings, got {pattern!r}"]
    if not pattern.strip():
        return ["`paths` entries must not be empty"]
    if pattern != pattern.strip():
        return [f"path {pattern!r} is padded with whitespace, which a request "
                f"target never carries — matched as written it can never "
                f"match, and stripped it would hide the next one"]
    text = pattern
    if "://" in text:
        return [f"path {pattern!r} looks like a URL — `paths` matches the "
                f"path alone, so drop the scheme and the host"]
    if not text.startswith("/"):
        return [f"path {pattern!r} does not start with '/' — `paths` is "
                f"matched against the request target's path, which always "
                f"does, so this pattern can never match"]
    if "?" in text or "#" in text:
        return [f"path {pattern!r} carries a query or fragment — `paths` "
                f"matches the path ALONE, deliberately, so that "
                f"paths = ['/v1/messages'] still permits "
                f"'/v1/messages?stream=true'. A pattern that names one "
                f"never matches"]
    return []


def _validate_policy_methods(item, host: str) -> tuple[tuple | None, list[str]]:
    """Validate one entry's `methods`. Returns (normalised or None, errors)."""
    if "methods" not in item:
        return None, []
    value = item["methods"]
    if not isinstance(value, list):
        return (), [f"[vm.network].policy: {host!r} `methods` must be an "
                    f"array of HTTP method names, got "
                    f"{type(value).__name__}"]
    errors: list[str] = []
    out: list[str] = []
    for token in value:
        if not isinstance(token, str):
            errors.append(f"[vm.network].policy: {host!r} `methods` entries "
                          f"must be strings, got {token!r}")
            continue
        # Compared uppercase, so `["get"]` is accepted and normalised. What is
        # NOT accepted is `["GET "]`: stripping it would be the same kindness
        # applied to a different thing, since a method token cannot contain
        # whitespace and one that does is a typo -- and the strip that hid it
        # would leave the operator's next typo silently denying instead.
        if token != token.strip() or any(c.isspace() for c in token):
            errors.append(
                f"[vm.network].policy: {host!r} names the method {token!r}, "
                f"which carries whitespace. A method token cannot, so this is "
                f"a typo -- and accepting it by stripping would hide the next "
                f"one")
            continue
        name = token.upper()
        if name in VM_POLICY_METHODS_REFUSED:
            errors.append(
                f"[vm.network].policy: {host!r} names the method {token!r}, "
                f"which this inspector never sees — "
                f"{VM_POLICY_METHODS_REFUSED[name]}")
            continue
        if name not in VM_POLICY_METHODS:
            errors.append(
                f"[vm.network].policy: {host!r} names {token!r}, which is not "
                f"a registered HTTP method. A method that never matches denies "
                f"every request that would have used it, and nothing reports "
                f"that it was a typo")
            continue
        out.append(name)
    if not out and not errors:
        errors.append(
            f"[vm.network].policy: {host!r} has an empty `methods` list, which "
            f"permits no method at all. Omit the key to mean any method")
    return tuple(out), errors


def _validate_policy(net: dict, splice_hosts, http2_hosts, egress: str,
                     tls) -> tuple[list[VmPolicyEntry], list[str]]:
    """Validate [[vm.network.policy]]. Returns (entries, errors).

    NO `hosts` PARAMETER, and its absence is the decision rather than a rule
    left unwritten. `internal`, `splice` and `http2` each get a "this entry
    matches no allowlisted name" error, because each of them is an exception
    TO the allowlist and one naming a host that is not on it is dead. A
    `policy` entry is not: §3 makes it allowlist its own host, so an entry
    matching nothing in `.hosts` is the ordinary way to write one, and a rule
    borrowed from the three siblings for symmetry would refuse the
    configuration the schema documents.
    """
    errors: list[str] = []
    raw = net.get("policy", [])
    if not isinstance(raw, list):
        return [], [f"[vm.network].policy must be an array of "
                    f"[[vm.network.policy]] tables, got "
                    f"{type(raw).__name__}"]

    known = {"host", "methods", "paths"}
    # Rung 6 (ADR 007). Named rather than reported as an unknown key, for the
    # reason VM_TLS_UNBUILT gives: an operator who wrote `credential` should be
    # told when it arrives, not sent hunting for a typo that is not there.
    unbuilt = {
        "credential": "rung 6 (ADR 007), where the broker attaches it",
        "placeholder": "rung 6 (ADR 007), beside `credential`",
    }
    entries: list[VmPolicyEntry] = []
    for item in raw:
        if not isinstance(item, dict):
            errors.append(
                f"[vm.network].policy entries are tables with `host` and "
                f"optional `methods`/`paths`, got {item!r}")
            continue
        for key in sorted(set(item) & set(unbuilt)):
            errors.append(
                f"[vm.network].policy: `{key}` is not built yet — it lands in "
                f"{unbuilt[key]}. Accepting it now would give the request a "
                f"disposition the config did not ask for while the file "
                f"claimed a credential was attached")
        unknown = sorted(set(item) - known - set(unbuilt))
        if unknown:
            errors.append(
                f"[vm.network].policy: unknown key(s) {', '.join(unknown)}; an "
                f"entry carries `host`, `methods` and `paths`")
        if "host" not in item:
            errors.append(f"[vm.network].policy: entry {item!r} has no `host`")
            continue
        problems = _validate_proxy_host(item.get("host"))
        if problems:
            errors.extend(f"[vm.network].policy: {p}" for p in problems)
            continue
        host = item["host"].strip()
        methods, method_errors = _validate_policy_methods(item, host)
        errors.extend(method_errors)
        paths: tuple | None = None
        if "paths" in item:
            value = item["paths"]
            if not isinstance(value, list):
                errors.append(
                    f"[vm.network].policy: {host!r} `paths` must be an array "
                    f"of path patterns, got {type(value).__name__}")
                paths = ()
            else:
                paths = tuple(p for p in value if isinstance(p, str))
                for pattern in value:
                    errors.extend(f"[vm.network].policy: {host!r} {p}"
                                  for p in _validate_policy_path(pattern))
                if not value:
                    errors.append(
                        f"[vm.network].policy: {host!r} has an empty `paths` "
                        f"list, which permits no path at all. Omit the key to "
                        f"mean any path")
        entries.append(VmPolicyEntry(host=host, methods=methods, paths=paths))

    if not entries:
        return entries, errors

    if tls == "splice":
        errors.append(
            "[vm.network].policy with tls = 'splice' — a spliced connection is "
            "never decrypted, so there is no request for `methods` and `paths` "
            "to be applied to and the entries would be silently inert. Use "
            "tls = 'inspect' (the default), or drop the policy entries and "
            "keep the name allowlist in .hosts.")
    if egress != "filtered":
        errors.append(
            f"[vm.network].policy has no effect with .egress = {egress!r} — "
            f"nothing is redirected into the egress inspector, so no request "
            f"is ever read for it to govern. Set egress = 'filtered' to use "
            f"it.")

    # A name in both `splice` and `policy` is an error: the policy could never
    # run, and the file states two intentions that cannot both hold.
    for entry in entries:
        for spliced in splice_hosts:
            if _patterns_overlap(entry.host, spliced):
                errors.append(
                    f"[vm.network].policy: {entry.host!r} is also in .splice "
                    f"({spliced!r}) — a spliced connection is never decrypted, "
                    f"so the method and path rules could never run. Keep one: "
                    f"splice the host and drop the policy entry, or drop the "
                    f"splice entry and let the host be inspected")
                break

    # And a name in both `http2` and `policy`, which is the same failure one
    # key along and reads as the milder one. It is not milder: an h2 stream's
    # request headers are HPACK-compressed frames nothing here decodes, so
    # `methods` and `paths` have no text to match and the entry is inert in
    # exactly the way the splice case is. The difference is only that `splice`
    # looks like an exemption and `http2` looks like a protocol -- which is the
    # misreading HLD §8 corrected, and the reason this gets its own sentence
    # rather than being folded into the loop above.
    for entry in entries:
        for h2_host in http2_hosts:
            if _patterns_overlap(entry.host, h2_host):
                errors.append(
                    f"[vm.network].policy: {entry.host!r} is also in .http2 "
                    f"({h2_host!r}) — an h2 connection is relayed at the frame "
                    f"level with its headers left HPACK-compressed, so there "
                    f"is no request line for `methods` and `paths` to match "
                    f"and the rules could never run. Keep one: drop the "
                    f".http2 entry and let the host be inspected as HTTP/1.1, "
                    f"or drop the policy entry and accept that this host is "
                    f"enforced by name alone")
                break

    # §3's widening trap. Where more than one entry matches a host BY PATTERN,
    # every one of those entries must state both keys -- one entry omitting
    # `paths` permits every path on that host and silently defeats every
    # sibling that was carefully narrowed, while the file reads as if it were
    # more restrictive than it is.
    #
    # By pattern and not by identical `host` strings, which is the half that is
    # easy to implement wrongly: `*.example.com` and `api.example.com` are two
    # entries matching one name, and a check comparing literal hosts passes
    # exactly the file this rule exists to catch.
    for i, entry in enumerate(entries):
        siblings = [o for j, o in enumerate(entries)
                    if j != i and _patterns_overlap(entry.host, o.host)]
        if not siblings:
            continue
        missing = [k for k, v in (("methods", entry.methods),
                                  ("paths", entry.paths)) if v is None]
        if missing:
            errors.append(
                f"[vm.network].policy: {entry.host!r} shares a host with "
                f"{siblings[0].host!r} and omits "
                f"{' and '.join(f'`{k}`' for k in missing)}. Where entries "
                f"overlap, an omitted key means ANY -- so this entry permits "
                f"everything its siblings were narrowed to forbid, and the "
                f"file looks more restrictive than it is. State both keys on "
                f"every overlapping entry")

    # A copy-paste a reader will assume does something.
    seen: dict = {}
    for entry in entries:
        key = (vm_normalise_hostname(entry.host),
               None if entry.methods is None else tuple(sorted(set(entry.methods))),
               None if entry.paths is None else tuple(sorted(set(entry.paths))))
        if key in seen:
            errors.append(
                f"[vm.network].policy: {entry.host!r} appears twice with the "
                f"same `methods` and `paths`. Entries union, so the duplicate "
                f"permits nothing the first does not — which a reader will "
                f"assume it does. Drop one")
        seen[key] = entry

    return entries, errors


def _validate_apex_coverage(hosts, entries, key: str, consequence: str, *,
                            self_allowlisting: bool = False) -> list[str]:
    """§3's apex trap: an allowlisted apex that a wildcard entry leaves out.

    Patterns are fnmatch, not DNS suffix matching, so `*.example.com` requires
    something before the dot and does NOT cover the bare `example.com`. Neither
    existing rule catches this: the wildcard entry DOES match allowlisted names,
    just not the apex, so "an entry matching no allowlisted name is an error"
    never fires.

    `entries` is a list of host patterns. `consequence` names what the operator
    gets instead, which differs by key and is the whole value of the message.

    THE WILDCARD IS LOOKED FOR IN THE ENTRIES, NOT IN `.hosts`, and getting
    that backwards left the rule firing on the one spelling nobody writes.
    Requiring `*.apex` to appear in `.hosts` too catches only the REDUNDANT
    form -- a `policy` entry allowlists its own host, so the natural way to
    write the trap is `hosts = ["example.com"]` beside a lone `*.example.com`
    entry, with the wildcard nowhere in `.hosts` because it does not need to
    be. That shape was silent, on the one key that has no dead-entry rule to
    catch it instead.

    `self_allowlisting` says whether an entry naming something `.hosts` does
    not cover means anything on its own. It does for `policy` (§3) and it does
    not for `splice` and `http2`, where such an entry is ALREADY refused as
    dead -- so there the apex message is suppressed rather than stacked on top
    of one that says a different thing about the same line.
    """
    errors: list[str] = []
    literal = [h.strip() for h in hosts if isinstance(h, str) and h.strip()]
    named = [e for e in entries if e]
    for apex in literal:
        wildcard = f"*.{apex}"
        if not any(vm_normalise_hostname(e) == vm_normalise_hostname(wildcard)
                   for e in named):
            continue
        if not self_allowlisting and not any(
                _patterns_overlap(wildcard, pattern) for pattern in literal):
            continue
        if any(vm_hostname_match(apex, (e,)) for e in named):
            continue
        errors.append(
            f"[vm.network].{key}: {wildcard!r} does not cover the apex "
            f"{apex!r}, which .hosts also allowlists — patterns are fnmatch, "
            f"not DNS suffix matching, so `*.` requires a label before the "
            f"dot. {consequence} Add an entry for {apex!r} too, or drop it "
            f"from .hosts")
    return errors


def _validate_egress(net: dict) -> list[str]:
    """Validate [vm.network].egress and .allow.

    `egress` defaults to "filtered" (ADR 006 §5.1): the usual argument for
    defaulting a new control off is protecting deployed workloads, and there
    are none — both VM bundles are templates. A secure default costs nothing
    now and is expensive to retrofit.

    `filtered` needs somewhere for the VM's traffic to go: either an address
    allowlist or a hostname allowlist served by its own inspector. Neither means a
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
                f"{VM_TLS_UNBUILT[tls]}. Accepting the word now would give "
                f"the connection one of the modes that IS built while the "
                f"config claimed the property of one that is not, which is the "
                f"misreported confinement this layer exists to prevent. Use "
                f"one of "
                f"{', '.join(repr(m) for m in VM_TLS_MODES)} until then.")
        elif tls not in VM_TLS_MODES:
            errors.append(
                f"[vm.network].tls must be one of "
                f"{', '.join(repr(m) for m in VM_TLS_MODES)}, got {tls!r}")

    # ADR 008 decision 2: splicing is a named exemption carrying a written
    # reason, never a default and never implicit. The per-host hatch has
    # enforced that since rung 4; the whole-workload one did not, which left
    # the WIDEST bypass in the schema as the only one an operator could open
    # silently. Checked here rather than in _validate_host_reason_entries
    # because there is no host to hang it on -- the exemption is the workload.
    #
    # Ordered so a bad mode is reported alone: `tls = "splic"` is a typo, and
    # a second error telling the operator to justify a mode they did not ask
    # for is noise on top of the one line they need.
    tls_reason = net.get("tls_reason")
    has_reason = isinstance(tls_reason, str) and bool(tls_reason.strip())
    if tls == "splice" and not has_reason:
        errors.append(
            "[vm.network].tls = 'splice' has no `tls_reason` — this is the "
            "widest bypass in this schema: it splices EVERY host the workload "
            "reaches, not a named one, and .allow, .internal, .splice and "
            ".http2 have each carried a written reason since they existed. "
            "Without one, nothing in this file distinguishes a workload "
            "spliced because its guest cannot be re-seeded with the CA from "
            "one spliced because nobody tried. Add "
            "tls_reason = \"why this guest cannot be terminated\" beside it, "
            "or leave the workload on the default tls = 'inspect' and exempt "
            "only the hosts that need it with [[vm.network.splice]] entries, "
            "which is the narrower hatch and the one to reach for first.")
    elif tls_reason is not None and tls != "splice":
        # Not merely inert: the key asserts the workload is spliced whole, and
        # it is not. Refused in the direction the rest of this function
        # refuses -- a config that describes a confinement other than the one
        # it has, here by claiming a WEAKER one than is in force, which sends
        # a reviewer looking for an exposure that is not there.
        effective = tls if tls is not None else VM_TLS_DEFAULT
        errors.append(
            f"[vm.network].tls_reason is set but .tls is {effective!r} — the "
            f"key records why a WHOLE workload skips termination, and this "
            f"one does not skip it. Set tls = 'splice' if that was the "
            f"intent, or drop tls_reason and put the justification on the "
            f"[[vm.network.splice]] entries that carry `reason` per host.")

    internal_hosts, internal_errors = _validate_host_reason_entries(
        net.get("internal", []), "internal",
        "it is a bypass of the internal-destination drop and carries one "
        "like `allow` does")
    errors.extend(internal_errors)
    # Deferred until `policy` has been read: §3 says a name in `policy` need
    # not also appear in `hosts`, so an `internal` entry for such a name is on
    # a list and this rule must see both lists or it refuses a working config.
    internal_deferred = list(internal_hosts)
    # HLD §11 hatch 2. A host here is spliced on a workload that otherwise
    # terminates, which is the remedy every non-HTTP refusal names -- so the
    # key has to exist before the messages that tell an operator to type it.
    splice_hosts, splice_errors = _validate_host_reason_entries(
        net.get("splice", []), "splice",
        "it exempts a host from inspection and carries one like `allow` does")
    errors.extend(splice_errors)
    for host in splice_hosts:
        # A dead entry fails in the opposite direction to a dead `internal`
        # one, which is why the two rules are written out separately rather
        # than shared: an ignored `splice` line gets you inspection you did not
        # want, on the host you exempted precisely because it cannot take it.
        if not any(_patterns_overlap(host, pattern)
                   for pattern in hosts if isinstance(pattern, str)):
            errors.append(
                f"[vm.network].splice: {host!r} matches no allowlisted name — "
                f"nothing in .hosts covers it, so the entry exempts a host the "
                f"guest is refused before the exemption is reached. That is a "
                f"belief about what is reachable that the config contradicts. "
                f"Add it to .hosts, or drop this entry")

    # HLD §8's narrow opt-in, and the one bypass whose name does not look
    # like one. A host here keeps h2 and is relayed at the frame level, so its
    # `:authority` goes unread and true fronting stays open on it -- which is
    # why it carries a `reason` like every other hole rather than reading as a
    # performance flag.
    http2_hosts, http2_errors = _validate_host_reason_entries(
        net.get("http2", []), "http2",
        "it leaves the host enforced by server name alone and carries one "
        "like `allow` does")
    errors.extend(http2_errors)
    for host in http2_hosts:
        # Dead in the same direction a dead `splice` entry is: the host is
        # refused before the exemption is reached, so the operator's belief
        # about what is reachable is contradicted by the config.
        if not any(_patterns_overlap(host, pattern)
                   for pattern in hosts if isinstance(pattern, str)):
            errors.append(
                f"[vm.network].http2: {host!r} matches no allowlisted name — "
                f"nothing in .hosts covers it, so the entry keeps h2 for a "
                f"host the guest is refused before the connection is served. "
                f"Add it to .hosts, or drop this entry")
        for spliced in splice_hosts:
            # Both are exemptions and only one can apply: the listener asks
            # `splices()` first, so the connection is never terminated and the
            # h2 entry decides nothing. Refused rather than resolved silently
            # in splice's favour, because the two entries state different
            # beliefs about the host -- one that it cannot take our CA, one
            # that it can and speaks h2 -- and only the operator knows which.
            if _patterns_overlap(host, spliced):
                errors.append(
                    f"[vm.network].http2: {host!r} is also in .splice "
                    f"({spliced!r}) — a spliced connection is never "
                    f"terminated, so no ALPN of ours is offered on it and the "
                    f".http2 entry decides nothing. Keep one: splice the host "
                    f"and drop the .http2 entry, or drop the splice entry if "
                    f"the host can take this workload's CA")
                break

    policy_entries, policy_errors = _validate_policy(
        net, splice_hosts, http2_hosts, egress, tls)
    errors.extend(policy_errors)
    policy_hosts = [e.host for e in policy_entries]

    # §3's apex trap, for both keys that can fall into it, with the consequence
    # each one actually produces. They are not the same failure: a spliced apex
    # breaks as a TLS error on the host whose client cannot take the CA, while
    # an unconstrained apex is a security hole -- the operator believes a method
    # restriction is in force and it is not.
    errors.extend(_validate_apex_coverage(
        hosts, splice_hosts, "splice",
        "So the apex is INSPECTED, and a host spliced precisely because its "
        "client cannot take our CA breaks at the apex only, as a TLS error "
        "rather than as a policy message."))
    errors.extend(_validate_apex_coverage(
        hosts, policy_hosts, "policy",
        "So the apex is allowlisted and inspected with NO method or path rules "
        "applied — a restriction you believe is in force and is not.",
        self_allowlisting=True))
    errors.extend(_validate_apex_coverage(
        hosts, http2_hosts, "http2",
        "So the apex is offered `http/1.1` alone while the names under it keep "
        "h2, and a client that will not take the downgrade fails on the apex "
        "only — which presents as that one name being broken rather than as a "
        "protocol decision."))

    for host in internal_deferred:
        # A dead entry here fails in the direction nobody notices until the
        # host is needed: the guest gets `403 <host> resolves to an internal
        # address` on the one destination the entry existed to permit. An
        # error, for the same reason an `allow` element that arms nothing is.
        #
        # _patterns_overlap on BOTH halves, which is the same comparison the
        # `splice` and `http2` dead-entry rules make and for the same reason.
        # The obvious reading -- match the entry's `host` as a NAME against the
        # allowlist patterns -- gets the wildcard case backwards: an
        # `*.nas.example` entry justified by an allowlisted `a.nas.example` is
        # live, and a one-directional check calls it dead and refuses the
        # config. Wrong in the accepting direction leaves a dead entry
        # standing; wrong the other way refuses a config that works, which is
        # the expensive mistake for a rule whose whole job is to catch a typo.
        if not any(_patterns_overlap(host, pattern)
                   for pattern in hosts if isinstance(pattern, str)) \
                and not any(_patterns_overlap(host, pattern)
                            for pattern in policy_hosts):
            errors.append(
                f"[vm.network].internal: {host!r} is on no list — nothing "
                f"in .hosts allowlists it and no .policy entry names it, so "
                f"the entry excepts a destination the guest is refused before "
                f"the exception is reached. Add it to .hosts, or drop this "
                f"entry")

    # ACCEPTED, NOT WARNED, under tls = "splice", and the silence is the
    # decision. Every host is spliced there, so these entries ask for something
    # that is already true -- the config's intent is satisfied, not
    # contradicted, which is the test every other "key with no effect" refusal
    # in this function applies. And the mode they would fire under is HLD §11's
    # third hatch, reached in the middle of an incident by an operator whose
    # toolchain is broken: new output there is a cost with nothing to buy.
    #
    # `http2` is accepted there on the same terms as `splice`: no ALPN of ours
    # is offered on a connection that is never terminated, so the entry asks
    # for something already true rather than something contradicted.
    #
    # `internal` gets the same acceptance under `tls = "splice"` and for a
    # different reason, which is why they are written out rather than merged:
    # the internal-destination check lives on the inspector's UPSTREAM leg,
    # which a spliced connection still has, so a spliced host can resolve into
    # private space and still needs the exemption. `policy` is refused there,
    # because a spliced connection is never decrypted and there is no request
    # for it to govern. A later pass tidying the four for symmetry would take
    # the exemption away from exactly the workloads that need it.

    # §5.3: `bridge` means a real LAN identity, and nothing of ours is in that
    # guest's data path — no host socket, so no uid to match on.
    if "bridge" in net:
        for key in ("egress", "allow", "tls", "tls_reason", "internal",
                    "splice", "http2", "policy"):
            if key in net:
                errors.append(
                    f"[vm.network].{key} has no effect with .bridge set — a "
                    f"bridged VM sends from its own LAN address, not from a "
                    f"host socket owned by the workload user, so there is no "
                    f"uid for the filter to match")
        if "hosts" in net:
            errors.append(
                "[vm.network].hosts has no effect with .bridge set — hostname "
                "policy is enforced by redirecting the guest's own traffic on "
                "the workload's uid, and a bridged guest sends from its own "
                "LAN address with no host socket in the path")
        return errors

    # `policy` counts as somewhere to go: §3 says a name in `policy` need not
    # also appear in `hosts`, so a workload whose whole allowlist is written as
    # policy entries reaches those hosts and nothing else, which is a coherent
    # and rather good configuration.
    if egress == "filtered" and not allow and not hosts and not policy_hosts:
        errors.append(
            "[vm.network].egress is 'filtered' (the default) but both .allow "
            "and .hosts are empty, so this VM could reach nothing at all. "
            "List the hostnames it needs as .hosts (HTTP/HTTPS, via its own "
            "inspector), non-HTTP destinations as .allow entries "
            "('<addr>:<port>'), or set egress = 'open' to opt out of "
            "filtering.")

    # The redirect is what carries the guest's traffic to the inspector, and it
    # is armed only under 'filtered'. Under 'open' nothing is redirected at all:
    # the guest dials 443 and the packet leaves, so a `hosts` list would be read
    # by a process no connection ever reaches while the workload looked
    # configured.
    #
    # This was a sharper distinction under the proxy, and it is worth recording
    # why it stopped being one. There, 'open' left the allowlist binding on
    # cooperative guests only — the variables still pointed at a proxy that
    # still filtered — so the failure was partial confinement. Here it is total:
    # not a weaker enforcement of `hosts`, but none.
    #
    # Refused, not silently skipped: a `hosts` list accepted and then ignored is
    # the misreported confinement this layer exists to prevent. Joins .hosts with
    # .bridge (no uid in the path) and .hosts = ["*"].
    if egress == "open" and hosts:
        errors.append(
            "[vm.network].hosts is set but .egress is 'open', so nothing "
            "redirects this guest to its inspector — its traffic leaves "
            "directly and the hostname allowlist is never consulted. Set "
            "egress = 'filtered' to make the hostname allowlist enforceable, "
            "or drop .hosts to run unfiltered.")

    # `tls` and `internal` describe what happens to a redirected connection, and
    # under 'open' nothing is redirected. Refused rather than ignored, for the
    # same reason .hosts is: a key accepted and then not applied is a config
    # that reports a confinement it does not have.
    if egress != "filtered":
        for key in ("tls", "tls_reason", "internal", "splice", "http2"):
            # `policy` is not in this list: _validate_policy names it itself,
            # with a sentence about requests rather than about redirection.
            if key in net:
                errors.append(
                    f"[vm.network].{key} has no effect with .egress = "
                    f"{egress!r} — nothing is redirected into the egress "
                    f"inspector, so there is no intercepted connection for it "
                    f"to describe. Set egress = 'filtered' to use it.")

    # `resolver = "none"` kept its meaning and lost its coherence. Under the
    # retired proxy a guest that could not resolve simply named hosts in a
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
        if splice_hosts:
            named.append(".splice")
        if http2_hosts:
            named.append(".http2")
        if policy_hosts:
            named.append(".policy")
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


# Hostname patterns are matched by fnmatch against the host ALONE — the name the
# inspector read out of a Host header or an SNI, which carries no scheme, no
# path and no port. So a pattern carrying any of those never matches anything: a
# silent hole in an allowlist, which is the failure worth catching at validate
# time rather than at 3am.
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
                f"only, so a path never matches"]
    if ":" in text:
        return [f"{pattern!r} contains a port — hostname policy applies to the "
                f"redirected ports ({VM_INSPECT_ORIG_CLEARTEXT} and "
                f"{VM_INSPECT_ORIG_TLS}) only; use .allow for other ports"]
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

    for key in ("hosts", "internal", "splice", "http2", "policy"):
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
            # checks build_cloud_init_iso applies (CA bundle, virtiofs mounts).
            # Validated against a closed set: the whole value of the check is
            # that it fires, and a typo'd opt-out would silently disable it —
            # which is the failure mode the check exists to prevent.
            sp = ci.get("seed_provides", [])
            if not isinstance(sp, list) or not all(isinstance(x, str) for x in sp):
                errors.append(
                    "[vm.cloud_init].seed_provides must be a list of strings"
                )
            else:
                # A retired entry is refused BY NAME, ahead of the unknown-entry
                # message, and told what to write instead. Folding it into
                # "unknown entries ['proxy']" would be true and useless: the
                # operator's seed does provide something, the concern it
                # provides was renamed under them, and the generic message
                # would send them looking for a typo they did not make.
                for entry in sorted(set(sp) & set(SEED_PROVIDES_RETIRED)):
                    errors.append(
                        f"[vm.cloud_init].seed_provides = [{entry!r}] is no "
                        f"longer accepted: rung 2 replaced the per-workload "
                        f"proxy with a transparent redirect, so a guest is "
                        f"given no proxy environment for a seed to provide. "
                        f"Write {SEED_PROVIDES_RETIRED[entry]!r} instead if "
                        f"the seed installs and trusts the egress CA bundle "
                        f"itself, or drop the entry if it does not."
                    )
                unknown = sorted(set(sp) - SEED_PROVIDES_CHOICES
                                 - set(SEED_PROVIDES_RETIRED))
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
