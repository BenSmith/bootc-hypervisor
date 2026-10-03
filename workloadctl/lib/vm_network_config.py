#!/usr/bin/env python3
"""Reading `[vm.network]`: what the operator wrote, parsed.

The allow-entry parser and its host-side resolution. The responder's
static map is built from that resolution in egress_policy. Whether what was
written is sayable is vm_validate's question; nothing here builds a unit, a command, a
certificate or a config file.

Installed to /usr/libexec/workloadctl/vm_network_config.py.
"""

import ipaddress
import re
import socket
from typing import NamedTuple

from moatery.egress_plane import CLEARTEXT, TLS
from workload_addr import allow_reserved_reason

# --- `allow`: the address-scoped bypass, now a table with a reason ---
#
# `allow` is a table carrying `address` and a required `reason` — the shape
# every other bypass in this schema has (`internal` below; `splice`).
# A bare `<addr>:<port>` string is REFUSED rather than accepted alongside it:
# there is no deployed config to migrate, so a compatibility path would exist
# only to let the two shapes drift.
#
# The target is `<addr>:<port>` (`[<v6addr>]:<port>` for IPv6) **or a name with
# a port** (`git.local:2222`), resolved host-side once at start. A name is safe
# here only because the guest's own resolver is a static map we serve (the
# inspector design, §9), so the host-side answer and the guest-side answer come
# from the same place; without that, a record that moved would leave the
# element silently wrong for the life of the VM.
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
    if filtered and port in (CLEARTEXT.guest_port, TLS.guest_port):
        raise ValueError(
            f"{spec!r}: port {port} is redirected into this workload's egress "
            f"inspector before `allow` is consulted, so the element would be "
            f"armed and never matched. The redirect keys on the workload uid "
            f"and the port alone. Allowlist the hostname in .hosts, which is "
            f"where 80 and 443 are decided")

    # Checked here rather than beside the schema, because this is the single
    # funnel every allow entry passes through: `validate_egress` (vm_egress_validate) calls it for
    # the operator-facing error and `vm_filter_elements` calls it on the arming
    # path, so the refusal cannot be reached around by a config that never met
    # validation. The design asks for it "in the helper as well as the schema";
    # one funnel is how both get it without two copies that can drift.
    #
    # The name form is checked where it is resolved (vm_filter_elements), not
    # here: this function deliberately does not resolve.
    if addr is not None:
        reserved = allow_reserved_reason(addr)
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


