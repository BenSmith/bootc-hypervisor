"""
VM-workload constants, helpers, and schema validation.

Everything specific to `[vm]` workloads: the uid-derived passt network identity,
OVMF firmware discovery, MAC derivation, memory parsing, and the [vm]-section
validator. Kept separate from the container path so the VM surface is legible
on its own.

Installed to /usr/libexec/workloadctl/vm.py.
"""

import fnmatch
import ipaddress
import os
import re
import socket
import time
from pathlib import Path
from typing import NamedTuple

from config_parser import (BROKER_DEFAULT_AUTH_FORMAT,
                           BROKER_DEFAULT_AUTH_HEADER, INSPECT_ORIG_CLEARTEXT,
                           INSPECT_ORIG_TLS, container_credential_entries,
                           container_policy_entries, container_uses_inspect,
                           normalise_hostname, parse_credential_entries,
                           parse_policy_entries, parse_volume_spec,
                           patterns_overlap, validate_credential_entries,
                           validate_host_pattern, workload_root_dir)

# The uid-derived layer, re-exported so every existing `from vm import ...`
# keeps working. workload_addr does not import vm, and must not: it is the bottom of
# this stack, and an import back up is the cycle test_module_imports.py exists
# to catch. Listed by name rather than star-imported so that what vm's callers
# may rely on stays a written-down set.
from egress_policy import (VM_INSPECT_ORIG_CLEARTEXT, VM_INSPECT_ORIG_TLS,
                           VM_INSPECT_PORT_CLEARTEXT, VM_INSPECT_PORT_TLS)
from workload_addr import (IP_BIN, NFLOG_GROUP_BASE, RangeReservation,
                           ReservedRange, UID_MAX, UID_MIN, UidDerived,
                           VM_ADVERTISED_IFACE, VM_BROKER_ADDR_BASE,
                           VM_INSPECT_ADDR6_PREFIX,
                           VM_INSPECT_ADDR_BASE, VM_INSPECT_LISTENER_BIN,
                           VM_INSPECT_NETWORK, VM_MGMT_ADDR_BASE, VM_MGMT_NETWORK,
                           VM_MGMT_SSH_PORT, VM_RESERVATION_INSPECT4,
                           VM_RESERVATION_INSPECT6, VM_RESERVATION_MGMT,
                           VM_RESERVED_RANGES, VM_RESOLVE_ADDR_BASE,
                           VM_RESOLVE_LISTENER_BIN, VM_RESOLVE_POLICY_FILE,
                           VM_RESOLVE_PORT, VM_RESOLVE_TTL, VM_UID_BROKER,
                           VM_UID_DERIVED, VM_UID_INSPECT, VM_UID_MGMT, VM_UID_NFLOG,
                           VM_UID_RESOLVE, VmInspectAddress, _reserved_ranges,
                           _uid_derived_value, ensure_advertised_interface,
                           vm_broker_listen_address,
                           vm_inspect_address, vm_management_address, vm_nflog_group,
                           vm_reserved_range, vm_resolve_address)

# The SELinux confinement layer, re-exported on the same contract.
from egress_selinux import (SELINUX_ENFORCE_PATH, VM_INSPECT_SELINUX_CIL,
                            VM_INSPECT_SELINUX_MODULE, VM_QEMU_CONTEXT,
                            VM_QEMU_TYPE, VM_RESOLVE_SELINUX_CIL,
                            VM_RESOLVE_SELINUX_MODULE, VM_RUNCON_BIN,
                            VM_SELINUX_CIL, VM_SELINUX_MODULE, qemu_launch_argv,
                            selinux_enabled)

# The guest's paravirtual clock seed, re-exported on the same contract.
from vm_ptp import (VM_PTP_KVM_CHRONY_MARKER, VM_PTP_KVM_CHRONY_PATH,
                    VM_PTP_KVM_CLOCK_NAME, VM_PTP_KVM_DEVICE,
                    VM_PTP_KVM_MODULE, VM_PTP_KVM_MODULES_LOAD_PATH,
                    VM_PTP_KVM_UDEV_RULE_PATH, vm_ptp_kvm_runcmd_lines,
                    vm_ptp_kvm_seed_files)

# Netfilter readback, re-exported on the same contract.
from netfilter_state import (CONNTRACK_COUNT_PATH, CONNTRACK_MAX_PATH,
                             CONNTRACK_PRESSURE, conntrack_occupancy,
                             nft_drop_counter, nft_element_counter,
                             nft_set_elements, vm_owned_elements)

# The nftables vocabulary, re-exported on the same contract.
from nft_constants import (FamilyPair, NFT_BIN, NFT_MAP_INSPECT4,
                           NFT_MAP_INSPECT6, NFT_PAIR_ALLOW,
                           NFT_PAIR_INSPECT_DST, NFT_PAIR_INSPECT_LIVE,
                           NFT_PAIR_INSPECT_MAP, NFT_PAIR_INSPECT_SELF,
                           NFT_PAIR_INTERNAL, NFT_PAIR_INTERNAL_OK,
                           NFT_PROXY_SKELETON, NFT_PROXY_TABLE, NFT_SET_ALLOW4,
                           NFT_SET_ALLOW6, NFT_SET_EGRESS_CG, NFT_SETS,
                           NFT_SET_FILTERED, NFT_SET_INSPECT_CG,
                           NFT_SET_INSPECT_DST, NFT_SET_INSPECT_DST6,
                           NFT_SET_INSPECT_LIVE, NFT_SET_INSPECT_LIVE6,
                           NFT_SET_INSPECT_SELF, NFT_SET_INSPECT_SELF6,
                           NFT_SET_INTERNAL4, NFT_SET_INTERNAL6,
                           NFT_SET_INTERNAL_OK4, NFT_SET_INTERNAL_OK6,
                           NFT_SKELETON, NFT_TABLE, _both_families,
                           _split_by_family)

# The egress policy vocabulary, re-exported on the same contract: the TLS mode,
# the hostname rules, the parsed policy entries, the inspector's document and
# the words its per-request record is written in.
from egress_policy import (VM_DROP_BROKER_UNREACHABLE, VM_DROP_CEILING,
                           VM_DROP_CLIENT_CERT, VM_DROP_FOREIGN_CALLER,
                           VM_DROP_INTERNAL, VM_DROP_MINT_FAILED,
                           VM_DROP_MISDIRECTED, VM_DROP_MISDIRECTED_LISTED,
                           VM_DROP_NOT_ALLOWLISTED, VM_DROP_NOT_H2,
                           VM_DROP_NOT_HTTP, VM_DROP_NOT_HTTP_POLICY,
                           VM_DROP_NOT_PERMITTED, VM_DROP_NO_NAME,
                           VM_DROP_RELAY_FAILED, VM_DROP_THROTTLED,
                           VM_DROP_TIMED_OUT, VM_DROP_UNREACHABLE,
                           VM_DROP_UNREADABLE_REQUEST, VM_DROP_UNVERIFIED,
                           VM_INSPECT_DIGEST_KEY, VM_INSPECT_DIGEST_SHORT,
                           VM_INSPECT_LOG_ID_FIELD, VM_INSPECT_LOG_REQ_FIELD,
                           VM_INSPECT_ORIG_CLEARTEXT, VM_INSPECT_ORIG_TLS,
                           VM_INSPECT_POLICY_FILE, VM_INSPECT_PORT_CLEARTEXT,
                           VM_INSPECT_PORT_TLS, VM_INSPECT_RECORD_DECISIONS,
                           VM_INSPECT_RECORD_FIELDS, VM_INSPECT_RECORD_FILE,
                           VM_INSPECT_RECORD_MODES, VM_INSPECT_RECORD_PLANES,
                           VM_INSPECT_RECORD_REASONS, VM_INSPECT_RECORD_ROOT,
                           VM_INSPECT_STATUS_FILE, VM_LOG_BASE,
                           VM_POLICY_METHODS, VM_POLICY_METHODS_REFUSED,
                           VM_TLS_DEFAULT, VM_TLS_MODES, VmPolicyEntry,
                           _host_reason_hosts,
                           vm_hostname_control_character, vm_hostname_match,
                           vm_http2_hosts,
                           vm_inspect_digest_short, vm_inspect_logs_directory,
                           vm_inspect_policy, vm_inspect_policy_digest,
                           vm_inspect_policy_path, vm_inspect_policy_text,
                           vm_inspect_record_dir, vm_inspect_record_path,
                           vm_inspect_status_path, vm_internal_hosts,
                           vm_normalise_hostname, vm_policy_entries,
                           vm_policy_governs, vm_splice_hosts, vm_uses_inspect,
                           vm_uses_resolve)
from vm_defs import (OVMF_CODE_CANDIDATES,
                     OVMF_VARS_CANDIDATES, SEED_PROVIDES_CHOICES,
                     SEED_PROVIDES_RETIRED, SeedContractError,
                     VM_CA_ENV_VARS,
                     VM_DEFAULT_GUEST_USER, VM_EGRESS_DEFAULT, VM_EGRESS_MODES,
                     VM_GUEST_AGENT_PORT, VM_GUEST_HOME_BASE, VM_GUEST_UID,
                     VM_HOME_SELINUX_CONTEXT, VM_HOME_SELINUX_TYPES,
                     VM_INTERNAL_PREFIXES4, VM_INTERNAL_PREFIXES6, VM_PORT_RE,
                     VM_REBOOT_EXIT_CODE, VM_REGISTRATION_DOMAIN_PARENTS,
                     VM_RESERVED_GUEST_ENV, VM_SEED_CONTRACT_EXIT,
                     VM_SIDECAR_SLICE, VM_SOCKET_DIR,
                     VM_SOCKET_FCONTEXT_PATTERN, VM_SOCKET_SELINUX_TYPE,
                     VM_SOCKET_SELINUX_TYPE_REAL, VM_TLS_UNBUILT, find_ovmf_code, find_ovmf_vars, parse_memory_mib,
                     parse_vm_port, vm_allowed_hosts, vm_guest_agent_socket,
                     vm_mac_address, vm_mac_collisions, vm_runtime_dir)

from vm_network_config import (VM_ALLOW_ADDR_RE, VM_ALLOW_NAME_RE,
                               VM_BROKER_DEFAULT_AUTH_FORMAT,
                               VM_BROKER_DEFAULT_AUTH_HEADER,
                               VM_NETWORK_SCALARS, VmAllowEntry,
                               VmCredential, _ALLOW_LABEL,
                               _registration_domain_parent,
                               _validate_apex_coverage, _validate_credentials,
                               _validate_egress, _validate_host_reason_entries,
                               _validate_policy, _validate_policy_methods,
                               _validate_policy_path, _validate_proxy_host,
                               parse_vm_allow, validate_vm_config,
                               validate_vm_network, vm_allow_reserved_reason,
                               vm_allow_resolve, vm_allow_resolved,
                               vm_credential_entries, vm_network_warnings,
                               vm_policy_permits, vm_resolve_policy,
                               vm_resolve_policy_path)

# The generated broker instance, re-exported on the same contract.
from broker_config import (VM_BROKER_BIN, VM_BROKER_CONFIG_NAME,
                           VM_BROKER_INSTANCE_PORT,
                           VM_BROKER_RUNTIME_SUBDIR, _credential_named,
                           _toml_basic_string, broker_upstream_addresses,
                           container_broker_hosts,
                           container_broker_upstream_addresses,
                           container_uses_credentials,
                           render_broker_config,
                           render_container_broker_config,
                           render_vm_broker_config, vm_broker_config_dir,
                           vm_broker_config_path, vm_broker_credential,
                           vm_broker_hosts, vm_broker_runtime_directory,
                           vm_broker_upstream_addresses, vm_credential_env,
                           vm_host_resolver_addresses,
                           vm_inspect_link_address_commands,
                           vm_inspect_link_delete_commands,
                           vm_uses_credentials)


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

    The allowlist splits by address family through _split_by_family, which is
    where the reason for the split is written down.
    """
    if resolved is None:
        resolved = vm_allow_resolved(allow)
    allowed = []
    for entry, addresses in resolved:
        for addr in addresses:
            # The listener-range refusal, applied on this side of the
            # resolution too. parse_vm_allow cannot make it for a name -- it
            # deliberately does not resolve -- so a name pointed at another
            # workload's inspector would otherwise arm the exact element the
            # address form is refused for.
            reserved = vm_allow_reserved_reason(addr)
            if reserved:
                where = f"{entry.host!r} resolves there — " if entry.host else ""
                raise ValueError(f"[vm.network].allow: {where}{reserved}")
            allowed.append((addr, f"{uid} . {addr} . {entry.port}"))
    return {NFT_SET_FILTERED: [str(uid)],
            **_split_by_family(NFT_PAIR_ALLOW, allowed)}


VM_RESOLVE_STATUS_FILE = "resolve-status.json"


def vm_resolve_status_path(name: str) -> str:
    """Where one workload's responder writes its counters."""
    return f"{VM_SOCKET_DIR}/{name}/{VM_RESOLVE_STATUS_FILE}"


# The type the record subtree carries, and the pattern the CIL module's own
# filecon names.
#
# A `filecon` IS reachable here, unlike the PKI subtree's -- and the difference
# is worth stating, because vm_pki_fcontext_patterns()'s docstring says the
# opposite about a path that looks similar. file_contexts.local outranks the
# base file wholesale, so a module filecon is shadowed only under a prefix
# workloadctl has registered via semanage; LOCAL_FCONTEXT_ROOTS names those, and
# /var/log is not one of them. One glob also covers every workload, so unlike
# the PKI rules there is nothing per-workload to register or to remove at
# disable.
VM_INSPECT_RECORD_SELINUX_TYPE = "wlinspect_log_t"


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
    cleartext. The value is (listener address, listener port), and BOTH halves
    are per-workload: the address is derived from the uid, so the element is the
    only thing that says where this workload's listener is, and no shared
    literal appears in it. The advertised address that once did is gone with the
    broker redirect that was its last consumer.
    """
    return _both_families(NFT_PAIR_INSPECT_MAP, vm_inspect_address(uid), lambda a: [
        f"{uid} . {VM_INSPECT_ORIG_CLEARTEXT} : {a} . {VM_INSPECT_PORT_CLEARTEXT}",
        f"{uid} . {VM_INSPECT_ORIG_TLS} : {a} . {VM_INSPECT_PORT_TLS}",
    ])


def vm_inspect_dst_elements(uid: int) -> dict[str, list[str]]:
    """The accept-set elements, holding the TRANSLATED tuple.

    Same shape as the maps but keyed on the destination the filter chain sees,
    which is the DNAT-rewritten one: an element naming the original 80/443 would
    match nothing (measured; §7.2) and the redirected connection would fall
    through to the default drop.
    """
    return _both_families(NFT_PAIR_INSPECT_DST, vm_inspect_address(uid), lambda a: [
        f"{uid} . {a} . {VM_INSPECT_PORT_CLEARTEXT}",
        f"{uid} . {a} . {VM_INSPECT_PORT_TLS}",
    ])


def vm_inspect_self_elements(uid: int) -> dict[str, list[str]]:
    """The wrong-port drop-set elements, one per family.

    Keyed on uid and listener address with NO port: their whole purpose is to
    catch dials to ports nothing serves, and naming a port would make exactly
    those unreachable. The rule is already in the skeleton; the element is per
    workload and is armed here, and it is what gives the guard's counter its
    per-workload attribution.
    """
    return _both_families(NFT_PAIR_INSPECT_SELF, vm_inspect_address(uid),
                          lambda a: [f"{uid} . {a}"])


def vm_inspect_live_elements(uid: int) -> dict[str, list[str]]:
    """The cross-workload guard's elements: this workload's inspector address.

    A bare address per family, with NO uid and no port. The uid is deliberately
    absent because this set answers a question about the DESTINATION — "is this
    a live inspector?" — and the rule that reads it supplies the source
    qualifier itself (`meta skuid != 0`, so host tooling can still probe). A
    uid here would make the set say "workload X's own inspector", which is what
    wl_inspect_self already says one rule earlier and is the opposite of what
    the cross-workload guard needs to match.

    The port is absent for the reason it is absent from wl_inspect_self: the
    guard's job includes dials to ports nothing serves, and naming 8080/8443
    would let a cross-workload caller walk in on any other port.
    """
    return _both_families(NFT_PAIR_INSPECT_LIVE, vm_inspect_address(uid),
                          lambda a: [str(a)])


def vm_inspect_element_commands(uid: int, action: str) -> list[list[str]]:
    """argv lists arming ("add") or disarming ("delete") all eight elements.

    Two families, four objects each, in a fixed order: both DNAT maps (in
    inet workload_proxy), both accept sets, both wrong-port sets and both
    cross-workload guard sets (in inet workload_filter). One argv per object,
    because an object's elements belong to one table and one transaction, and
    the eight span two tables.

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
        (NFT_TABLE, vm_inspect_live_elements(uid)),
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
    exempt = []
    for addr in addresses:
        reserved = vm_internal_reserved_reason(addr)
        if reserved:
            raise ValueError(f"[vm.network].internal: {reserved}")
        exempt.append((addr, f"{uid} . {addr}"))
    return _split_by_family(NFT_PAIR_INTERNAL_OK, exempt)


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
            for set_name in NFT_PAIR_INTERNAL_OK]


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
# their names are here rather than in egress_mint because the SELinux patterns
# below have to name the same three directories the minter creates. A drift
# between the two spellings is a mislabelled directory, which presents as the
# inspector failing to mint and not as a naming mistake.
VM_LEAF_DIR_NAME = "leaves"
VM_DENIAL_DIR_NAME = "leaves-denied"

# THE PKI SUBTREE HAS ITS OWN LABELS, AND THAT IS THE WHOLE POINT
#
# `wlinspect_t` is a separate domain from `svirt_t` so that the component
# terminating guest input cannot reach the workload's disks, volumes or state
# directory. The inspector reads a private key and writes a leaf cache, and
# both live in that state directory beside the disk images.
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

# notBefore is backdated an hour for clock skew. Guest drift is ~10 ppm
# (about five minutes a year), so this covers roughly 1,200
# years of it -- and exactly ONE HOUR of a vCPU pause, which a guest loses
# permanently. The backdate is not what makes pauses survivable; the mint-time
# clock check is.
VM_CA_BACKDATE_SECONDS = 3600

# The window VM_CA_VALIDITY_DAYS' comment already promised: `diagnose` warns
# inside the last year. A year rather than a month because the remedy is a
# RE-PROVISION -- cloud-init runs once per instance-id, so the guest is rebuilt,
# not restarted -- and a month's notice for that is notice of an outage rather
# than of a decision.
VM_CA_EXPIRY_WARN_DAYS = 365


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

    THE THREE EXTENSIONS ARE NOT DECORATION. Python 3.14's ssl (OpenSSL 3.5)
    rejects a chain whose CA lacks a Subject Key Identifier
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
#
# THIS IS NOT CAUTION, IT IS THE DIFFERENCE BETWEEN WORKING AND BROKEN. Every
# one of those five variables REPLACES the runtime's default trust store rather
# than adding to it, and every one of them fails closed when the file it names
# does not exist: OpenSSL's SSL_CERT_FILE pointing at a missing path makes
# loading the default verify paths fail outright, and requests, git and pip
# raise on the open. So the block must never be written for a certificate
# nothing is presenting yet: that is a total outage inside every filtered
# guest, not a degraded mode.
#
# THREE THINGS MOVE TOGETHER OR NONE OF THEM DO: this flag, the write_files
# entry in _render_default_user_data that puts the PEM at VM_CA_BUNDLE_PATH,
# and the seed contract in build_cloud_init_iso. Flipping this alone points
# five variables at a file nothing writes, which is the total outage described
# above -- so it is not a "safe" partial step, it is the worst of the three.
VM_CA_BUNDLE_AVAILABLE = True


def vm_ca_env(config: dict) -> dict[str, str]:
    """The CA environment a filtered guest is given, or {} if it has none.

    NO PROXY VARIABLES. The redirect is transparent, so nothing a guest sets
    can turn the filtering off or on, and http_proxy/https_proxy/no_proxy are
    not written: a guest that still sets https_proxy to some literal of its own
    reaches a host address where nothing listens.

    This workload's own CA is minted into
    its state directory, written into the seed at VM_CA_BUNDLE_PATH, and named
    by these five variables -- and under the default `tls = "inspect"` the guest
    NEEDS it, because the leaf the inspector presents is signed by nothing else.

    ONCE PER INSTANCE ID, the same caveat the proxy block carried. cloud-init
    replays a seed only when the instance id changes, so editing this block on a
    running guest changes nothing until the VM is re-seeded — and an operator
    who switches egress mode on a live workload gets a guest whose environment
    still describes the previous mode.
    """
    # VM-only by construction: this is a cloud-init guest-env block. The
    # container equivalent would be env injection directly into the unit, and
    # it must not ship before a container CA exists -- these five variables
    # REPLACE the trust store (VM_RESERVED_GUEST_ENV), so an empty shape is
    # not inert, it is every TLS verification in the workload failing.
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
    Without the flag, Python's ssl rejects the chain with
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


# --- Writing nft's elements: the filter's add and delete commands ---

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
