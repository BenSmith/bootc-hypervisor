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
# The per-workload egress CA and the leaves it signs, re-exported on the same
# contract: the state-directory names, the two openssl argvs, the guest anchor
# path and the five variables that point the guest's clients at it.
from egress_ca import (LeafRefused, VM_CA_BACKDATE_SECONDS,
                       VM_CA_BUNDLE_AVAILABLE, VM_CA_BUNDLE_PATH,
                       VM_CA_CERT_NAME, VM_CA_DIR_NAME, VM_CA_ENV_VARS,
                       VM_CA_EXPIRY_WARN_DAYS, VM_CA_KEY_NAME,
                       VM_CA_SELINUX_TYPE, VM_CA_VALIDITY_DAYS,
                       VM_DENIAL_DIR_NAME, VM_LEAF_DIR_NAME, VM_LEAF_LABEL_MAX,
                       VM_LEAF_NAME_MAX, VM_LEAF_RENEW_WITHIN_SECONDS,
                       VM_LEAF_SELINUX_TYPE, VM_LEAF_VALIDITY_DAYS,
                       VM_RESERVED_GUEST_ENV, _LEAF_LABEL_CHARS,
                       vm_ca_cert_path, vm_ca_dir, vm_ca_env, vm_ca_key_path,
                       vm_ca_openssl_argv, vm_ca_subject, vm_denial_dir,
                       vm_leaf_dir, vm_leaf_openssl_argv, vm_leaf_san,
                       vm_pki_fcontext_patterns)
from vm_defs import (OVMF_CODE_CANDIDATES,
                     OVMF_VARS_CANDIDATES, SEED_PROVIDES_CHOICES,
                     SEED_PROVIDES_RETIRED, SeedContractError,
                     VM_DEFAULT_GUEST_USER, VM_EGRESS_DEFAULT, VM_EGRESS_MODES,
                     VM_GUEST_AGENT_PORT, VM_GUEST_HOME_BASE, VM_GUEST_UID,
                     VM_HOME_SELINUX_CONTEXT, VM_HOME_SELINUX_TYPES,
                     VM_INTERNAL_PREFIXES4, VM_INTERNAL_PREFIXES6, VM_PORT_RE,
                     VM_REBOOT_EXIT_CODE, VM_REGISTRATION_DOMAIN_PARENTS,
                     VM_SEED_CONTRACT_EXIT,
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
