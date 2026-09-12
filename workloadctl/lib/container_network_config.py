"""
Reading the container [network] section: its scalars and its entries.

The container half of what lib/vm_network_config.py is for a VM. Read the same
way -- straight off the parsed table, no dedicated parse layer. Whether what
was read is sayable is container_validate's question; the nft elements and
the inspector's policy document are rendered from it by nft_elements and
egress_policy, next to the VM's.
"""
import ipaddress
import socket
from typing import NamedTuple

from config_parser import (
    infer_workload_mode,
    parse_policy_entries,
    validate_host_pattern,
)
from credential_entries import parse_credential_entries

# --- Container [network] entries ---
#
# [[network.policy]] / [[network.credential]] / [[network.allow]], parsed by
# the shared loops in config_parser and credential_entries, shape-tolerant,
# with the real rules in container_validate. Deliberately its own small
# NamedTuple set rather than a reuse of VmPolicyEntry/VmCredential: those
# are keyed on `[vm.network]` specifically, and container topology has no
# `[vm]` section to key off of. Widening them instead would put a substrate
# branch inside a pair of structures whose whole job is to describe one
# substrate's table. Sharing the PARSE and not the TYPE is what keeps both
# of those true at once.

class ContainerPolicyEntry(NamedTuple):
    """One [[network.policy]] entry, normalised.

    `methods` and `paths` are `None` where the key was absent, not an empty
    tuple -- absent means "any", empty would mean "none". Same convention as
    VmPolicyEntry, for the same reason: collapsing the two would make a
    single-entry host with no `paths` deny everything instead of permitting
    everything.
    """

    host: str
    methods: tuple | None
    paths: tuple | None
    credential: str | None = None


def container_policy_entries(net: dict) -> list[ContainerPolicyEntry]:
    """The [[network.policy]] entries for one container's [network] table,
    normalised, in file order. Shape-tolerant; container_validate
    owns rejecting malformed entries."""
    return parse_policy_entries(net, ContainerPolicyEntry)


class ContainerCredential(NamedTuple):
    """One [[network.credential]] block, normalised. Same shape as
    broker_config.VmCredential and for the same reasons -- see that class's
    docstring for why `auth_header`/`auth_format` are optional and live here
    rather than on the policy entry."""

    name: str
    placeholder: str
    env: str
    auth_header: str | None = None
    auth_format: str | None = None


def container_credential_entries(net: dict) -> list[ContainerCredential]:
    """The [[network.credential]] blocks for one container's [network]
    table, normalised, in file order. Shape-tolerant; container_validate
    owns rejecting malformed entries."""
    return parse_credential_entries(net, ContainerCredential)


def container_allowed_hosts(net: dict) -> list[str]:
    """The [network].hosts allowlist, in file order. Shape-tolerant."""
    hosts = net.get("hosts", [])
    if not isinstance(hosts, list):
        return []
    return [h for h in hosts if isinstance(h, str) and h.strip()]


class ContainerAllowEntry(NamedTuple):
    """One [[network.allow]] entry, normalised. `host` and `address` are
    both surfaced raw (unlike VmAllowEntry, which resolves an address into
    an ipaddress object at parse time) -- that split is a validation
    decision (which regex matched, is it resolvable) this function does not
    make."""

    host: str | None
    address: str | None
    port: int | None
    reason: str | None


def container_allow_entries(net: dict) -> list[ContainerAllowEntry]:
    """The [[network.allow]] entries for one container's [network] table,
    normalised, in file order. Shape-tolerant."""
    entries: list[ContainerAllowEntry] = []
    raw = net.get("allow", [])
    if not isinstance(raw, list):
        return entries
    for item in raw:
        if not isinstance(item, dict):
            continue
        host = item.get("host")
        host = host.strip() if isinstance(host, str) and host.strip() else None
        address = item.get("address")
        address = address.strip() if isinstance(address, str) and address.strip() else None
        if host is None and address is None:
            continue
        port = item.get("port")
        port = port if isinstance(port, int) and not isinstance(port, bool) else None
        reason = item.get("reason")
        reason = reason.strip() if isinstance(reason, str) and reason.strip() else None
        entries.append(ContainerAllowEntry(host=host, address=address, port=port, reason=reason))
    return entries


def container_runs_on_host_network(config: dict) -> bool:
    """Whether this workload's containers really share the host netns.

    `[network].mode` is workload-level but it is NOT honoured in every
    topology. `single` passes it to `podman run --network=` and `pod` passes it
    to `podman pod create --network=`, so `mode = "host"` means host networking
    in both. `bridge` mode ignores it outright -- every member joins
    `workload-<name>-net` instead (see _network_args in container_run_args, which
    warns that workload-level [network].ports is ignored there for the same
    reason).

    So a bridge-mode workload carrying a leftover `mode = "host"` is not on the
    host network, its traffic IS re-originated by a pasta-equivalent host
    process owned by the workload uid, and uid attribution holds exactly as
    container_uses_inspect() describes for pasta. Refusing it would be refusing
    a workload for a key the generator never reads.
    """
    net = config.get("network", {})
    if not isinstance(net, dict) or net.get("mode") != "host":
        return False
    try:
        return infer_workload_mode(config) != "bridge"
    except ValueError:
        # An invalid workload.mode is somebody else's error to report; assume
        # the key is honoured rather than quietly waving the workload through.
        return True


def container_uses_inspect(config: dict) -> bool:
    """Whether this workload's egress is redirected into an inspector.

    Mirrors ``vm_uses_inspect()`` (lib/egress_policy.py) for the container
    substrate: the single source of the predicate (D2 in the container
    egress-parity build spec). ``ContainerSubstrate.uses_inspect()`` delegates here rather than
    restating the logic, and ``get_enabled_workloads()``
    (lib/exporter_collect.py) calls it directly on the raw parsed TOML --
    it reads config off disk and cannot build a WorkloadConfig/Substrate.
    """
    net = config.get("network", {})
    if not isinstance(net, dict):
        return False
    if container_runs_on_host_network(config):
        # Host mode is never inspected, and validate_container_network()
        # (lib/container_validate.py) rejects the combination outright --
        # this is the belt to that
        # braces, for a config already on disk when the rule landed.
        #
        # P0-1 measured it on hardware rather than assuming. Two findings,
        # only one of them the expected one:
        #   - the host's OWN traffic is not captured. Root and uid 1000 both
        #     matched no workload selector even with the netns shared, so
        #     host mode does not drag host sockets into a workload's policy.
        #   - but a container's processes do not share ONE uid. Under the
        #     default `userns = "keep-id"` exactly one in-container uid maps
        #     to the workload uid; in-container root and any other user map
        #     into the workload's 65536-wide subuid window. Measured: an
        #     image default matched `meta skuid <uid>`, while `user = "0"`
        #     and `user = "1000"` both left as subuids.
        # Every selector in workload-filter.nft is keyed on the single uid,
        # so filtering here would silently cover only bundles that happen to
        # run as the keep-id uid -- an image detail, not a policy decision.
        # Pasta and bridge mode are unaffected: their traffic is re-originated
        # by a host process owned by the workload uid, and all three arms
        # measured `exact-uid` there. Bridge mode is unaffected even when the
        # key IS written, because bridge mode never reads it -- which is what
        # container_runs_on_host_network() is for.
        return False
    # Any one of the three opt-in triggers, not policy alone: `hosts` and
    # `allow` are each triggers on their own (a hosts-only workload gets a
    # spliced proxy with no policy to speak of).
    return bool(container_allowed_hosts(net) or container_policy_entries(net)
                or container_allow_entries(net))


def _validate_container_host_pattern(pattern) -> list[str]:
    """Validate one hostname pattern (`hosts`, `policy.host`, or an
    `internal`/`splice` entry's `host`).

    The container half of validate_host_pattern: it exists to state the two
    sentences the container schema owns. There is no `egress` key here (R3), so
    an operator who wrote `*` is told to drop the table rather than to set a
    key that does not exist -- which is the one place the VM's wording would be
    actively wrong here.
    """
    return validate_host_pattern(
        pattern,
        allow_key="[[network.allow]]",
        star_remedy=("which filters nothing but looks configured -- drop the "
                     "[network] table entirely to run unfiltered"))


def container_allow_resolve(entry: ContainerAllowEntry) -> list:
    """Resolve one [[network.allow]] entry to concrete addresses.

    Mirrors vm_allow_resolve (lib/vm_network_config.py), adapted to
    ContainerAllowEntry's separate `address`/`host` fields. An address entry is
    returned as-is; a
    host entry is resolved here, once, at arm time. Not tolerant: an
    unresolvable name must arm nothing, and arming nothing silently is worse
    than failing loudly -- the workload then meets the default deny on that
    destination and hangs, with the drop landing on a host-wide counter that
    names neither it nor the entry.

    R3's "no default-deny for containers" is about the UNTRIGGERED case, and
    reading it as "a container is never default-denied" is a mistake this
    docstring used to make. A workload with any trigger is placed in
    `wl_filtered` by container_filter_elements() (lib/nft_elements.py), and
    nftables/workload-filter.nft's last output rule drops everything from a
    `wl_filtered` uid that no earlier rule accepted. What R3 rules out is an
    `egress` key that could default-deny a workload WITHOUT giving it an
    inspector; it does not exempt a triggered one from the drop.
    """
    if entry.address is not None:
        return [ipaddress.ip_address(entry.address)]
    try:
        infos = socket.getaddrinfo(entry.host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(
            f"[[network.allow]] names {entry.host!r}, which does not resolve "
            f"on this host ({exc}). It is resolved once at arm time, so an "
            f"unresolvable name arms nothing and the workload cannot reach "
            f"it") from None
    seen = []
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if addr not in seen:
            seen.append(addr)
    return seen


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
