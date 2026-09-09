#!/usr/bin/env python3
"""Every per-workload value this design derives from a workload uid.

Split out of vm.py because these are the BOTTOM of the VM stack and were
scattered across the top of it: the derivation and its bounds check near the
imports, three of the five rows beside the sections that consume them, and the
reserved-range table 4,000 lines below the ranges it is assembled from. A
reader asking "what does workloadctl allocate per workload, and what stops
`[vm.network].ports` binding it?" had to hold five places at once, and the
answer to the second half is derived from the first -- which only reads as a
guarantee when they are in one file.

Nothing here imports vm; vm imports this and re-exports every public name, so
no caller changed. That direction is the whole point: this module is what the
rest of the VM code is written against, and an import back up would be the
cycle tests/test_module_imports.py exists to catch.

Installed to /usr/libexec/workloadctl/workload_addr.py.
"""

import ipaddress
from typing import NamedTuple

from config_parser import INSPECT_ORIG_CLEARTEXT, INSPECT_ORIG_TLS


# The uid range every derivation below is bounded by. Reserved for workload
# users; the subordinate-id math in workload_lib is keyed on the same window.
UID_MIN = 10000
UID_MAX = 52948


# --- Uid-derived values ---
#
# Everything this design gives a workload of its own -- two loopback listeners,
# an inspector address in both families, an nflog group -- is the SAME
# derivation: bounds-check the uid, add its offset into the workload range to a
# base. There is no registry and no allocation step, so uniqueness is inherited
# from the uid allocator; the only thing a row needs to state is where it
# starts and, when it is an address, which reserved range covers it.
#
# A RESERVED RANGE is an address range this design owns -- 127.128.0.0/9,
# 198.18.0.0/16, 2001:2::/48 -- one address per workload, off limits to
# `[vm.network].ports`. Most of these rows sit in one; the nflog group is not
# an address and sits in none, which is why the reservation fields are
# optional. "Plane" is deliberately NOT the word for any of this: in this
# codebase a plane is which port a record arrived on (VM_INSPECT_RECORD_PLANES,
# and the user-visible `--plane tls`), and one word for two unrelated things
# is how a v6 range went unchecked for a whole rung.
#
# ROWS, BECAUSE THE RESERVATION IS THE PART THAT GOES WRONG. `ports` may name
# any bind address, and an address no range covers is not checked at all --
# an omission that is silent both ways, producing either a cross-workload
# denial of service on a security control (the inspector fails to bind, and the
# fail-at-bind path reports it as the address being missing) or workload B
# receiving workload A's intercepted traffic. Start order decides which, and
# nothing is logged for either. With the derivations as rows,
# VM_RESERVED_RANGES is DERIVED from them: a row whose reservation is one
# already listed adds nothing, and a row outside every listed range cannot be
# added without naming the reservation that covers it.


class RangeReservation(NamedTuple):
    """A range `[vm.network].ports` may not bind into, and why.

    `port` is None for a reservation that owns a whole range on every port, and
    a number for one that owns a single socket on an address operators
    otherwise use freely. The distinction is not cosmetic: 127.0.0.1:8080 is a
    normal thing to publish on and the management range is not a normal thing
    to publish on at all, so a check that treated an ordinary loopback socket
    the way it treats the management range would refuse most of what `ports`
    is for.

    `what` is a sentence, not a label, because the collisions want different
    explanations and reciting the range explains none of them.
    """
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    port: int | None
    what: str


class UidDerived(NamedTuple):
    """One per-workload value derived by offsetting the workload uid.

    `noun` is what the out-of-range error calls it, so the five raises are one
    raise. `base` is the value at UID_MIN. `reservation`/`reservation6` are the
    ranges that cover it, or None for a row that is not an address at all (the
    nflog group) -- and a row that IS an address and names no reservation is
    the shape test_vm_uid_derived.py refuses.
    """
    noun: str
    base: int
    reservation: RangeReservation | None = None
    reservation6: RangeReservation | None = None


def _uid_derived_value(derived: UidDerived, uid: int) -> int:
    """This row's value for one workload uid.

    The bounds check is here rather than in each caller because an unchecked
    offset does not fail -- it produces a plausible value belonging to some
    other workload, which is a collision nothing reports.
    """
    if uid < UID_MIN or uid > UID_MAX:
        raise ValueError(
            f"UID {uid} is outside the workload range {UID_MIN}-{UID_MAX}; "
            f"no {derived.noun} is derivable for it")
    return derived.base + (uid - UID_MIN)


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

VM_RESERVATION_INSPECT4 = RangeReservation(
    VM_INSPECT_NETWORK, None,
    "the egress inspector's IPv4 listener range. Every filtered VM's "
    "redirected 80 and 443 land on an address in it, so publishing here "
    "either takes the bind another workload's inspector needs — which fails "
    "as the address being missing, not as a conflict — or hands this guest "
    "another workload's intercepted traffic")

VM_RESERVATION_INSPECT6 = RangeReservation(
    VM_INSPECT_ADDR6_PREFIX, None,
    "the egress inspector's IPv6 listener range, the v6 twin of "
    "198.18.0.0/16 carrying the same numbers. Refusing one family and not the "
    "other refuses half of every address, and the half left open is the one "
    "clients try first")

# Both families on ONE row, because there is one derivation: the v6 address is
# the v4 OR-ed into the prefix, so a reservation for one family and not the
# other is not a narrower guard, it is half a guard.
VM_UID_INSPECT = UidDerived("inspector address", VM_INSPECT_ADDR_BASE,
                            VM_RESERVATION_INSPECT4, VM_RESERVATION_INSPECT6)

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
# Defined in workload_lib, because the container half of the design redirects
# the same two ports; re-exported here because every reader -- the listener,
# cmd_diagnose, the tests -- reaches them as `vm.VM_INSPECT_ORIG_*`.
VM_INSPECT_ORIG_CLEARTEXT = INSPECT_ORIG_CLEARTEXT
VM_INSPECT_ORIG_TLS = INSPECT_ORIG_TLS

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
# in the wrong guest, but a range documented as never configurable should not be
# reachable from a config key.
#
# It is /9 rather than the /16 the management addresses actually occupy, and the
# extra bits are load-bearing rather than slack: every other loopback range is
# carved out of the same range and names this reservation instead of one of its
# own, so a narrowing pass that "tidied" this to 127.128.0.0/16 would take the
# reservation away from the broker at 127.129.0.0 and the responder at
# 127.130.0.0 at once. An address OUTSIDE this range needs a RangeReservation of
# its own -- which VM_RESERVED_RANGES then picks up by derivation, not by
# anyone remembering to list it.
VM_MGMT_NETWORK = ipaddress.ip_network("127.128.0.0/9")

# The one reservation every loopback address names. The broker and the
# synthesising responder hang off the same /9 at their own bases, so each is
# covered by naming this rather than by an entry of its own -- which is the
# whole reason the /9 is wider than the /16 the management addresses occupy.
VM_RESERVATION_MGMT = RangeReservation(
    VM_MGMT_NETWORK, None,
    "the per-workload management addresses `workloadctl exec` and `shell` "
    "reach a guest's sshd on. Publishing here puts a guest port where another "
    "workload's management listener belongs, and start order decides which of "
    "two gets the bind")

VM_UID_MGMT = UidDerived("management address", VM_MGMT_ADDR_BASE,
                         VM_RESERVATION_MGMT)

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

# No reservation: a group is not an address, so there is nothing `ports` could
# bind into. The only row in the table for which that is true.
VM_UID_NFLOG = UidDerived("nflog group", NFLOG_GROUP_BASE)
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
    return str(ipaddress.IPv4Address(_uid_derived_value(VM_UID_MGMT, uid)))


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
    v4 = ipaddress.IPv4Address(_uid_derived_value(VM_UID_INSPECT, uid))
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
    return _uid_derived_value(VM_UID_NFLOG, uid)
# --- The credential broker endpoint ---
#
# There is no advertised endpoint and no host-side service: ADR 007 decision 6
# gives every workload ONE INSTANCE OF ITS OWN, bound to an address derived
# from that workload's uid.
#
# The guest is told nothing at all, which is the point: it dials the name it
# always wanted, the inspector recognises the host as credential-backed and
# sends that request to this workload's broker instead of to the origin. A
# guest that cannot name the broker cannot choose to use it, and cannot be
# pointed at somebody else's.

# Base of the per-workload broker listener addresses (ADR 007). 127.129.0.0, by
# the same offset arithmetic vm_management_address uses against 127.128.0.0 and
# the responder uses against 127.130.0.0 -- and, like the responder, deliberately
# inside VM_MGMT_NETWORK (127.128.0.0/9), which is why there is no ReservedRange
# of its own: the /9 was cut wide precisely so the ranges hung on loopback after
# the management one would inherit the reservation, and `ports` already cannot
# bind here.
#
# One address per workload is the whole of ADR 007 decision 6. A shared
# 127.0.0.1 with one listener would make caller identity a peer-uid lookup on a
# socket every workload can reach; here each instance answers on an address
# only its own inspector is told about, so a second
# workload dialling it reaches its OWN loopback and finds nothing.
VM_BROKER_ADDR_BASE = 0x7F810000  # 127.129.0.0

VM_UID_BROKER = UidDerived("broker listen address", VM_BROKER_ADDR_BASE,
                           VM_RESERVATION_MGMT)


def vm_broker_listen_address(uid: int) -> str:
    """The workload's own loopback address for its credential broker instance.

    Derived from the uid, so uniqueness is inherited from the uid allocator:
    no registry, no allocation step, and no collision. uid 10000 -> 127.129.0.0,
    uid 10003 -> 127.129.0.3.

    Never 127.0.0.1 and never 0.0.0.0. Both put one workload's broker where
    every other workload's inspector is dialling, which is how the hole ADR 007
    decision 6 closes grows back -- so the render gate asserts those two
    negatives explicitly rather than only asserting the positive.
    """
    return str(ipaddress.IPv4Address(_uid_derived_value(VM_UID_BROKER, uid)))
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
# ReservedRange for it: the /9 was cut wide precisely so the ranges hung on
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

VM_UID_RESOLVE = UidDerived("responder address", VM_RESOLVE_ADDR_BASE,
                            VM_RESERVATION_MGMT)

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
    succeeds with nothing assigned: a `workload-vm-resolve
    up` twin adding a /32 would be a no-op, and worse, it would invent an
    address whose absence the inspector's fail-at-bind argument would then
    appear to depend on.
    """
    return str(ipaddress.IPv4Address(_uid_derived_value(VM_UID_RESOLVE, uid)))

# Every uid-derived value this design allocates. Assembled here rather than
# inline because the rows sit beside the constants they derive from, in the
# sections that own them; test_vm_uid_derived.py refuses a UidDerived defined in
# this module and left out of this tuple, which is the one way a row can go
# missing.
VM_UID_DERIVED = (
    VM_UID_MGMT,
    VM_UID_BROKER,
    VM_UID_RESOLVE,
    VM_UID_INSPECT,
    VM_UID_NFLOG,
)


class ReservedRange(NamedTuple):
    """One host-side range a [vm.network].ports entry may not bind into.

    The shape vm_reserved_range answers in, kept distinct from
    RangeReservation because a caller wants the range that refused it and not
    the bookkeeping in VM_UID_DERIVED that produced the range.
    """
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    port: int | None
    what: str


def _reserved_ranges() -> tuple[ReservedRange, ...]:
    """The ranges VM_UID_DERIVED names, deduplicated, in table order.

    DERIVED, NOT LISTED, and that is the whole of this. A hand-written list is
    a second place to remember: the v6 listener range went unchecked in exactly
    that gap -- present in the design, absent from the list, and `ports =
    ["198.18.1.4:8443:22"]` validated. Here an address row cannot exist without
    naming the range that covers it, so the list cannot lag the rows.

    Deduplicated because three rows share the /9: the management addresses,
    the broker and the responder each hang off it at their own base, and the
    reservation is inherited rather than restated. An entry naming
    127.129.0.0/9 would restate the first one; one naming a single workload's
    address would need a uid this list does not have.
    """
    seen, ranges = [], []
    for derived in VM_UID_DERIVED:
        for reservation in (derived.reservation, derived.reservation6):
            if reservation is None or reservation in seen:
                continue
            seen.append(reservation)
            ranges.append(ReservedRange(reservation.network, reservation.port,
                                        reservation.what))
    return tuple(ranges)


VM_RESERVED_RANGES = _reserved_ranges()


def vm_reserved_range(addr: str, port: int | None = None) -> ReservedRange | None:
    """The reserved range this bind address and port fall in, or None.

    Both families, read off VM_RESERVED_RANGES rather than spelled out here,
    so a range added there is checked here without anyone remembering to.

    An unparseable address answers None: parse_vm_port has already rejected
    anything malformed, so there is nothing here to report.
    """
    try:
        address = ipaddress.ip_address(addr)
    except (ValueError, TypeError):
        return None
    for reserved in VM_RESERVED_RANGES:
        if address.version != reserved.network.version:
            continue
        if address not in reserved.network:
            continue
        if reserved.port is not None and port != reserved.port:
            continue
        return reserved
    return None


# --- The shared dummy link ---
#
# Dummy link carrying every per-workload listener address. Host-global and
# shared, created on demand and never torn down by a workload stop: it is
# refcount-free because it holds no per-workload state, costs nothing idle,
# and an orphan is inert.
#
# The DEVICE name still reads "workload-proxy" after the proxy it was named for
# was deleted, and that is deliberate. A link name is an object that exists on
# running hosts: renaming it would leave the old link in place holding this
# workload's 127.128.x.y and 198.18.x.y addresses, with the new link claiming
# the same addresses — two links answering for one address is a routing
# ambiguity, and it would arrive on upgrade rather than on a fresh install.
VM_ADVERTISED_IFACE = "workload-proxy"

IP_BIN = "/usr/sbin/ip"


def ensure_advertised_interface(run) -> None:
    """Create the dummy link the inspector's addresses hang on, idempotently.

    THE LINK ONLY. What it carries is each filtered workload's own inspector
    addresses, put on by vm_inspect_link_address_commands -- so this creates
    the object those `ip addr add`s need to exist and nothing more. No address
    of its own: there is no advertised endpoint, and the name is historical,
    like nftables/workload-proxy.nft's.

    `run(argv)` is injected rather than imported so this module stays free of
    subprocess; the inspect helper passes its own. libexec entrypoints have no
    extension, so they are not importable and cannot share one.

    Creation tolerates "already exists" because two VMs starting concurrently
    race here -- there is no lock and deliberately no owning unit. Anything else
    is fatal: without the link the inspector's addresses cannot be assigned and
    the redirect's destination is unroutable, which the guest sees as a
    connection that fails with no useful diagnostic.
    """
    result = run([IP_BIN, "link", "add", VM_ADVERTISED_IFACE, "type", "dummy"])
    if result.returncode != 0 and "File exists" not in result.stderr:
        raise RuntimeError(
            f"could not create {VM_ADVERTISED_IFACE}: {result.stderr.strip()}")

    result = run([IP_BIN, "link", "set", VM_ADVERTISED_IFACE, "up"])
    if result.returncode != 0:
        raise RuntimeError(
            f"could not bring up {VM_ADVERTISED_IFACE}: {result.stderr.strip()}")
