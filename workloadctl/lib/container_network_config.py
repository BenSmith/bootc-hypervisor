"""
Reading the container [network] section: its scalars and its entries.

The container half of what lib/vm_network_config.py is for a VM. Read the same
way -- straight off the parsed table, no dedicated parse layer. Whether what
was read is sayable is container_validate's question; the nft elements and
the inspector's policy document are rendered from it by nft_elements and
egress_policy, next to the VM's.
"""
from typing import NamedTuple

from config_parser import container_policy_entries

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
