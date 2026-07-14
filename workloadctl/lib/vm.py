"""
VM-workload constants, helpers, and schema validation.

Everything specific to `[vm]` workloads: the managed-bridge network params,
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

from workload_lib import parse_volume_spec


# --- VM constants ---

# Runtime socket directory for VM workloads: /run/workload-vm/{name}/
VM_SOCKET_DIR = Path("/run/workload-vm")

# UID/GID of the guest's primary interactive user. Cloud images assign the
# first user (cloud-init's default user) uid/gid 1000, and our default
# cloud-config pins it there explicitly. virtiofsd internally translates this
# guest id <-> the host workload uid so the guest user can write the share
# (which on the host is owned by _wl-<name>); see generate_virtiofs_service.
VM_GUEST_UID = 1000

# Default bridge for VM workloads.  _workload-br is the workloadctl-managed
# isolated NAT bridge (auto-provisioned by workload-bridge.service). The name
# is deliberately distinctive (and reserved) so the always-manage bridge setup
# won't adopt an unrelated interface; it must stay <=15 chars (Linux IFNAMSIZ).
# Override to e.g. "br0" to attach VMs directly to a pre-existing LAN bridge.
VM_BRIDGE_NAME = "_workload-br"
# Managed-bridge network config is HOST-LEVEL, not per-VM (ADR 002): the bridge
# is one host-global refcounted resource, so its subnet/DNS can't coherently
# take per-VM overrides. Single source of truth = the subnet CIDR
# (WORKLOADCTL_VM_BRIDGE_SUBNET), from which the gateway IP, CIDR, and — the
# ADR-002 fix — the DHCP range are all DERIVED, so a relocated bridge hands
# guests addresses on its own subnet instead of a stale hardcoded window.
def managed_bridge_params(subnet_cidr: str) -> tuple[str, str, str, str]:
    """Derive (gateway_ip, gateway_cidr, normalized_subnet, dhcp_range) for the
    managed VM bridge from a single subnet CIDR.

    The gateway is the first host address; the DHCP window is offsets .100–.199
    within the subnet (reproducing the historical 192.168.200.100–199 range on
    the /24 default). On a subnet too small for that window the range falls
    back to the full usable span (first host after the gateway through the
    last host) instead of collapsing onto a single clamped address. Deriving
    the range from the subnet is the ADR-002 fix: the range used to be
    hardcoded, so a non-default subnet handed guests addresses off the wrong
    subnet. Raises ValueError if the subnet leaves no leasable address after
    the gateway (/31, /32).
    """
    net = ipaddress.ip_network(subnet_cidr, strict=False)
    gateway = net.network_address + 1
    first_usable = net.network_address + 2  # +1 is the gateway
    last_usable = net.broadcast_address - 1
    if last_usable < first_usable:
        raise ValueError(
            f"VM bridge subnet {net} has no leasable address after the "
            f"gateway; use a /30 or larger")
    dhcp_start = net.network_address + 100
    dhcp_end = min(net.network_address + 199, last_usable)
    if dhcp_start > dhcp_end:
        dhcp_start = first_usable
    return (str(gateway), f"{gateway}/{net.prefixlen}", str(net),
            f"{dhcp_start},{dhcp_end},12h")


VM_BRIDGE_IP, VM_BRIDGE_CIDR, VM_BRIDGE_SUBNET, VM_DHCP_RANGE = managed_bridge_params(
    os.environ.get("WORKLOADCTL_VM_BRIDGE_SUBNET", "192.168.200.0/24"))

# Exit code workload-vm-notify uses to report a guest *reboot* (as opposed to a
# poweroff, which exits 0). QEMU runs with -no-reboot, so both a guest reboot and
# a guest poweroff make QEMU exit 0 — only the QMP SHUTDOWN event's reason tells
# them apart. For [vm].restart = "on-reboot" the wrapper translates a reboot into
# this nonzero code so systemd's Restart=on-failure cycles the VM, while a
# poweroff (exit 0) leaves it down. Nonzero and outside QEMU's own 0/1 range.
VM_REBOOT_EXIT_CODE = 133
# Upstream DNS the bridge dnsmasq forwards guest queries to. Empty by default:
# the bridge service then lets dnsmasq inherit the host's own /etc/resolv.conf,
# so guests resolve exactly what the host does — including `.local` names via the
# host's mDNS resolver — instead of leaking to a hardcoded public resolver. Set
# WORKLOADCTL_VM_BRIDGE_DNS (comma-separated) to force specific upstreams.
VM_BRIDGE_DNS = [s.strip() for s in os.environ.get(
    "WORKLOADCTL_VM_BRIDGE_DNS", "").split(",") if s.strip()]
# dnsmasq for the bridge runs confined in the SELinux dnsmasq_t domain, which
# may only write its lease/pid files in dnsmasq-owned, dnsmasq_lease_t-labeled
# locations. /var/lib/workloads is labeled container_file_t (rootless podman),
# so dnsmasq_t can neither write nor traverse it — putting the lease there made
# dnsmasq fail to start on enforcing systems (the default), leaving VMs with no
# DHCP. /var/lib/dnsmasq ships with the dnsmasq package, already labeled
# dnsmasq_lease_t, and policy allows dnsmasq_t to create/write files there.
VM_DHCP_LEASE_FILE = Path("/var/lib/dnsmasq/workload-bridge.leases")
VM_DHCP_PIDFILE = Path("/var/lib/dnsmasq/workload-bridge.pid")

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

def vm_mac_address(name: str) -> str:
    """Derive a stable, locally-administered unicast MAC from the workload name."""
    h = hashlib.md5(f"wl-vm-{name}".encode(), usedforsecurity=False).digest()
    first = (h[0] & 0xFE) | 0x02  # locally administered, unicast
    return ":".join(f"{b:02x}" for b in [first, h[1], h[2], h[3], h[4], h[5]])


def vm_mac_collisions(name: str, other_names) -> list[str]:
    """Return the subset of other_names whose derived VM MAC equals name's.

    vm_mac_address hashes the name into a MAC with no allocation registry, so
    two distinct names can (rarely) collide on the shared VM bridge — two guests
    would then fight over one address. This lets `validate` flag it up front.
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

    # [vm.network].bridge — defaults to _workload-br (managed NAT bridge); set to e.g.
    # "br0" to attach to a pre-existing LAN bridge instead.
    bridge = vm.get("network", {}).get("bridge", VM_BRIDGE_NAME)
    if not isinstance(bridge, str) or not bridge:
        errors.append(f"[vm.network].bridge must be a non-empty string, got {bridge!r}")
    elif not re.match(r"^[a-zA-Z0-9_-]+$", bridge) or len(bridge) > 15:
        # Linux IFNAMSIZ is 16, max 15 visible chars.
        errors.append(
            f"[vm.network].bridge {bridge!r} is not a valid interface name "
            "(letters/digits/_/-, max 15 chars)"
        )

    # The managed bridge's subnet/DNS are HOST-LEVEL config (ADR 002), no longer
    # per-VM: reject the removed fields with a pointer to the host-level knob
    # rather than silently ignoring them.
    net_cfg = vm.get("network", {})
    for removed in ("subnet", "dns"):
        if removed in net_cfg:
            errors.append(
                f"[vm.network].{removed} is no longer a per-VM setting — the "
                f"managed bridge's subnet/DNS are host-level (set "
                f"WORKLOADCTL_VM_BRIDGE_SUBNET / WORKLOADCTL_VM_BRIDGE_DNS). "
                f"See ADR 002."
            )

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
