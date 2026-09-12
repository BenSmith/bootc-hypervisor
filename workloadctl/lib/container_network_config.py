"""
The container [network] section: its scalars, its entries, and the
nft/inspector artefacts it renders to.

The container half of what lib/vm_network_config.py is for a VM. Read the same
way -- straight off the parsed table, no dedicated parse layer. Whether what
was read is sayable is container_validate's question.
"""
from typing import NamedTuple

from config_parser import (
    container_allow_resolve, container_allowed_hosts, container_policy_entries,
)
from egress_policy import INSPECT_GUEST_AGENT_KEY
from nft_constants import (
    NFT_BIN, NFT_SET_ALLOW4, NFT_SET_ALLOW6, NFT_SET_FILTERED, NFT_TABLE,
)
from workload_addr import allow_reserved_reason

# --- Container [network] scalars ---
#
# Read the same way as VM's vm_allowed_hosts()/net.get("tls")/etc.
# (lib/vm_defs.py) -- no dedicated parse function on that side either. `tls` is
# deliberately returned raw (None when absent), not defaulted here: unlike
# the VM's fixed default, the container's effective tls is *computed* from
# whether any policy entry is present, and that computation belongs to
# container_effective_tls_mode() below, not to parsing.

def container_tls_mode(net: dict) -> str | None:
    """The literal [network].tls value, or None if absent. Not defaulted --
    see module note above."""
    value = net.get("tls")
    return value if isinstance(value, str) and value.strip() else None


def container_tls_reason(net: dict) -> str | None:
    value = net.get("tls_reason")
    return value.strip() if isinstance(value, str) and value.strip() else None


def container_ca_delivery(net: dict) -> str | None:
    value = net.get("ca_delivery")
    return value.strip() if isinstance(value, str) and value.strip() else None


def container_ca_mount_path(net: dict) -> str | None:
    value = net.get("ca_mount_path")
    return value.strip() if isinstance(value, str) and value.strip() else None


# --- Container [[network.internal]] / [[network.splice]] ---
#
# Shape-tolerant, like the policy/credential pair in config_parser -- validation is
# validate_container_network()'s job, not parsing's. Unlike VM's
# _host_reason_hosts() (lib/egress_policy.py), `reason` is kept rather than
# discarded: every entry is required to carry a reason, and unlike
# the VM side -- where a malformed entry can never reach this code because
# the boot path already ran validate_vm_network() -- there is no such
# validator yet, so reporting code reading these tuples needs `reason`
# available rather than assumed-valid-elsewhere.

class ContainerHostReasonEntry(NamedTuple):
    """One [[network.internal]] or [[network.splice]] entry, normalised.
    Both arrays share this `{host, reason}` shape, same as the VM side's
    shared `_host_reason_hosts()` helper."""

    host: str
    reason: str | None


def container_internal_entries(net: dict) -> list[ContainerHostReasonEntry]:
    return _container_host_reason_entries(net, "internal")


def container_splice_entries(net: dict) -> list[ContainerHostReasonEntry]:
    return _container_host_reason_entries(net, "splice")


def _container_host_reason_entries(net: dict, key: str) -> list[ContainerHostReasonEntry]:
    raw = net.get(key, [])
    if not isinstance(raw, list):
        return []
    entries = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        host = item.get("host")
        if not isinstance(host, str) or not host.strip():
            continue
        reason = item.get("reason")
        reason = reason.strip() if isinstance(reason, str) and reason.strip() else None
        entries.append(ContainerHostReasonEntry(host=host.strip(), reason=reason))
    return entries


# --- The effective tls mode ---
#
# The parse functions above are deliberately shape-tolerant; every semantic
# rule lives in container_validate (lib/container_validate.py) or nowhere.

def container_effective_tls_mode(net: dict) -> str:
    """The tls mode actually in force: the literal key if the operator wrote
    one, else computed per the three-rung ladder -- no policy entries means
    splice, any policy entry means inspect. Meaningless on a workload with no
    trigger at all (no proxy exists for it to describe), but harmless to
    compute. Reporting code (doctor/rules/egress) must call this, not read
    `tls` directly, because the literal key may be absent while a proxy is
    still running in one mode or the other."""
    explicit = container_tls_mode(net)
    if explicit is not None:
        return explicit
    return "inspect" if container_policy_entries(net) else "splice"


# --- Container egress: nft element lifecycle (P1-7/P1-8) ---
#
# The low-level uid-keyed nft builders (element commands for the DNAT maps,
# the internal-destination exemptions, the cgroup exemptions) live in
# lib/nft_elements.py and take nothing but a uid and already-resolved addresses -- no
# VM-specific state -- so they are reused verbatim for containers (imported
# directly by lib/filter_arm.py and lib/inspect_arm.py). What
# differs, and what lives here, is
# resolving and shaping the CONTAINER schema's own entry types
# (ContainerAllowEntry keeps `host`/`address`/`port` apart, where VmAllowEntry
# packs them into one 'addr:port' string) into the inputs those builders take.

def container_allow_resolved(allow: list) -> list:
    """[(ContainerAllowEntry, [addr...])] for every [[network.allow]] entry,
    resolved once. Mirrors vm_allow_resolved."""
    return [(entry, container_allow_resolve(entry)) for entry in allow]


def container_filter_elements(uid: int, allow: list, resolved=None) -> dict:
    """Map set name -> element expressions for one container workload.

    Mirrors vm_filter_elements, but built from ContainerAllowEntry rather
    than VmAllowEntry. Reuses the shared set names and the reserved-range
    check (nft_constants.NFT_SET_FILTERED/ALLOW4/ALLOW6,
    workload_addr.allow_reserved_reason): both substrates share the one
    filter table (D3), so a container's would-be element in another workload's
    listener range is refused by the identical rule a VM's is.
    """
    if resolved is None:
        resolved = container_allow_resolved(allow)
    elements: dict[str, list[str]] = {NFT_SET_FILTERED: [str(uid)]}
    v4: list[str] = []
    v6: list[str] = []
    for entry, addresses in resolved:
        for addr in addresses:
            reserved = allow_reserved_reason(addr)
            if reserved:
                where = f"{entry.host!r} resolves there -- " if entry.host else ""
                raise ValueError(f"[network].allow: {where}{reserved}")
            (v6 if addr.version == 6 else v4).append(
                f"{uid} . {addr} . {entry.port}")
    if v4:
        elements[NFT_SET_ALLOW4] = v4
    if v6:
        elements[NFT_SET_ALLOW6] = v6
    return elements


def container_filter_commands(uid: int, allow: list, action: str, resolved=None) -> list:
    """argv lists that arm ('add') or disarm ('delete') one container
    workload's allowlist elements. Mirrors vm_filter_commands."""
    if action not in ("add", "delete"):
        raise ValueError(f"action must be 'add' or 'delete', got {action!r}")
    commands = []
    for set_name, entries in container_filter_elements(uid, allow, resolved).items():
        commands.append([NFT_BIN, action, "element", *NFT_TABLE.split(), set_name,
                         "{ " + ", ".join(entries) + " }"])
    return commands


def container_internal_resolve(host: str) -> list:
    """Resolve one [[network.internal]] host, or raise ValueError naming it.
    Mirrors vm_internal_resolve. Fatal by design (see that function and
    inspect_arm.internal_failure): an exemption armed for the wrong
    address, or not armed at all, leaves the host refused by the drop the
    entry existed to except.
    """
    import ipaddress
    import socket
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(
            f"[[network.internal]] names {host!r}, which does not resolve on "
            f"this host ({exc}). The exemption is armed per ADDRESS, so an "
            f"unresolvable name arms nothing and the host stays refused by "
            f"the internal-destination drop the entry existed to except") from None
    seen = []
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if addr not in seen:
            seen.append(addr)
    return seen


def container_inspect_policy(net: dict) -> dict:
    """The inspector's policy document for one container workload.

    Same JSON shape as vm_inspect_policy (lib/egress_policy.py) -- D6: the
    listener binary (workload-inspect-listener) does not change between
    substrates, so whichever wrote the file, it reads the same keys. `http2`
    is always empty: [[network.http2]] is deferred for containers (§5 of the
    build spec). `tls` is the EFFECTIVE mode (container_effective_tls_mode),
    not the literal key, since the container schema computes it per the
    three-rung ladder rather than defaulting it the way the VM schema does.

    `guest_agent` IS THE ONE KEY THIS RENDERER EMITS AND THE VM'S DOES NOT,
    and it states a fact about the substrate rather than an instruction. A
    container has no QEMU guest agent, so a remedy that works by asking one --
    the mint-time clock check -- cannot run here. Left unsaid, the listener
    wired that check for containers too, dialled a socket that has never
    existed on this substrate once per mint miss, and counted each attempt
    into `clock_unavailable`, whose exported meaning is "the mint-time clock
    remedy is INERT in this guest". On a container that reading was
    guaranteed and told an operator a remedy was broken rather than absent.

    A FACT, not `clock_remedy: false`, so the next thing that turns on "there
    is no agent to ask" reads this key instead of adding a second one. Emitted
    only here, so a VM's document is byte-identical to what it was and the
    drift comparison does not fire for every VM; a container's document DOES
    change once, and reports drift until it is re-armed.
    """
    return {
        "tls": container_effective_tls_mode(net),
        INSPECT_GUEST_AGENT_KEY: False,
        "hosts": container_allowed_hosts(net),
        "internal": [e.host for e in container_internal_entries(net)],
        "splice": [e.host for e in container_splice_entries(net)],
        "http2": [],
        "policy": [
            {"host": e.host,
             "methods": None if e.methods is None else list(e.methods),
             "paths": None if e.paths is None else list(e.paths),
             **({"credential": e.credential} if e.credential else {})}
            for e in container_policy_entries(net)],
    }


def container_inspect_policy_text(net: dict) -> str:
    """The policy document as the exact bytes that land on disk. Mirrors
    vm_inspect_policy_text -- same formatting, so a future drift/digest
    comparison cannot disagree with itself over which substrate rendered the
    file."""
    import json
    return json.dumps(container_inspect_policy(net), indent=2, sort_keys=True) + "\n"
