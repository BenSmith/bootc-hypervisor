"""vm_guest_reach: how the host reaches a VM's guest, and where the guest is.

The SSH endpoint and the command that dials it, the console socket and the
per-workload key, and the address cascade behind `addresses`: the guest
agent first, because it does not depend on host-side state, then the ARP
table on an operator-provided bridge. Under passt (ADR 006) a guest has no
LAN identity of its own, so its SSH endpoint is derived from the workload
uid rather than discovered; only a `[vm.network].bridge` VM is looked up.

Read by VMSubstrate for exec/shell/cp/addresses, and by vm_provision for the
first-boot probe on a bridged guest.
"""

from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path

from config_parser import SOCKET_DIR
from qmp import QMPClient
from vm_clock import GUEST_AGENT_TIMEOUT, guest_agent_sync
from vm_defs import mac_address, vm_guest_agent_socket
from workload_addr import MGMT_SSH_PORT, management_address
from workloadctl_core import WorkloadUserNotFound


def vm_console_sock(name: str) -> Path:
    return SOCKET_DIR / name / "console.sock"


def vm_ssh_key(config) -> Path:
    return config.home_dir / ".ssh" / "id_ed25519"


def vm_guest_user(config) -> str:
    return config.config.get("vm", {}).get("user", "workload")


def vm_ssh_endpoint(config) -> tuple[str, int] | None:
    """The (host, port) `workloadctl exec`/`shell` should ssh to, or None.

    Two topologies, two answers:

    - **passt** (no bridge): the workload's own management address at a fixed
      port. Derived from the uid, so it is known without asking the guest
      anything — there is no lease to wait for and no discovery that can fail.
      A VM is reachable here as soon as passt is listening and sshd is up.
    - **operator-provided bridge**: the guest's own LAN address on port 22,
      which the host has to infer. Returns None while nothing resolves it.
    """
    if config.vm_bridge is None:
        try:
            uid = config.uid
        except (WorkloadUserNotFound, ValueError):
            return None
        return (management_address(uid), MGMT_SSH_PORT)
    guest_ip = vm_guest_ip(config.name, config.vm_bridge)
    return (guest_ip, 22) if guest_ip else None


def vm_ssh_command(
    config,
    endpoint: tuple[str, int],
    exec_args: list[str] | None = None,
    connect_timeout: int | None = None,
) -> list[str]:
    """Build the ssh argv used to reach a VM workload's guest user."""
    key_path = vm_ssh_key(config)
    guest_user = vm_guest_user(config)
    known_hosts = config.home_dir / ".ssh" / "vm_known_hosts"
    guest_ip, port = endpoint
    cmd = [
        "ssh",
        *(["-t"] if sys.stdout.isatty() else []),
        "-p", str(port),
        "-i", str(key_path),
        # Host-key pinning (S1): verify the guest against the per-workload
        # known_hosts written at provisioning time, keyed by the stable
        # workload name via HostKeyAlias so address churn never invalidates the
        # pin. No trust-on-first-use, no MITM. The alias matters more under
        # passt than it did on the bridge: every workload's management address
        # is a loopback address, so without it ssh would key entries on
        # near-identical 127.128.x.y hosts.
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", f"HostKeyAlias={config.name}",
        "-o", "LogLevel=ERROR",
    ]
    if connect_timeout is not None:
        cmd += ["-o", f"ConnectTimeout={connect_timeout}"]
    cmd.append(f"{guest_user}@{guest_ip}")
    if exec_args:
        # One pre-quoted word, not the argv spread out. ssh concatenates its
        # trailing arguments with spaces and hands the result to the guest's
        # login shell, so passing them raw silently drops a level of quoting:
        # `exec <vm> -- sh -c 'mkfs -F /dev/vdb && …'` reached the guest as
        # `sh -c mkfs -F /dev/vdb && …`, and mkfs ran with no arguments at all.
        # The container substrate execs argv directly (podman exec), so without
        # this the same command line means two different things depending on the
        # substrate. Quoting here makes the VM path argv-faithful too.
        cmd += ["--", " ".join(shlex.quote(a) for a in exec_args)]
    return cmd


# The guest-agent timeout and the nonce handshake live in vm_clock, which owns
# the agent channel for the whole tree -- it grew a second caller at rung 3 (the
# mint-time clock check) and a duplicated client was the alternative.

def vm_guest_agent_addresses(name: str, mac: str) -> list[str]:
    """Addresses reported by qemu-guest-agent, best first; [] if unavailable.

    The only source that asks the *guest* rather than inferring from outside, so
    it is equally correct on the managed bridge and on a pre-existing LAN bridge,
    and it needs no DHCP lease, no ARP entry and no working mDNS. Best-effort by
    construction — an absent agent, a guest that hasn't opened the port, and a
    malformed reply are all ordinary states here, not errors, so every failure
    returns [] and lets the caller fall through to the host-side sources.

    **Only the NIC carrying the MAC we assigned this workload is trusted.** A
    guest routinely has interfaces the host cannot reach — a podman/docker
    bridge, a nested VM's bridge, a VPN tun — and the agent reports all of them.
    Returning one would be worse than returning nothing: a non-empty answer
    short-circuits the fallback chain, so `exec` would SSH at an unroutable
    address instead of trying the ARP source that would have found the real one.
    Falling through costs nothing by comparison, because the ARP and lease
    sources key off that same MAC and so cannot resolve a NIC this rejects
    either.

    Loopback and link-local addresses are dropped as unreachable (link-local
    needs a scope id the SSH path doesn't carry). IPv4 sorts ahead of IPv6 —
    both work over SSH, but the v4 address is the one an operator recognises
    from the lease and ARP paths.
    """
    sock_path = vm_guest_agent_socket(name)
    if not sock_path.exists():
        return []

    qga = QMPClient()
    try:
        qga.connect(sock_path, timeout=GUEST_AGENT_TIMEOUT,
                    recv_timeout=GUEST_AGENT_TIMEOUT)
        # No negotiate(): the guest agent protocol shares QMP's newline-JSON
        # framing but has no greeting and no qmp_capabilities — reading for one
        # would block until the recv timeout on every call.
        guest_agent_sync(qga)
        reply = qga.execute("guest-network-get-interfaces")
        interfaces = reply.get("return") or []
    except Exception:
        return []
    finally:
        qga.close()

    found = []
    for iface in interfaces:
        if not isinstance(iface, dict):
            continue
        if (iface.get("hardware-address") or "").lower() != mac.lower():
            continue
        for addr in iface.get("ip-addresses") or []:
            ip = addr.get("ip-address")
            if not ip or ip.startswith(("127.", "169.254.", "fe80:")) or ip == "::1":
                continue
            found.append((addr.get("ip-address-type") == "ipv6", ip))

    return [ip for _, ip in sorted(found)]


def vm_guest_ip(name: str, bridge: str | None = None) -> str | None:
    """The single best address for this VM, or None if nothing resolves it.

    Thin wrapper over vm_guest_addresses for the SSH paths, which need exactly
    one address.
    """
    addresses = vm_guest_addresses(name, bridge)
    return addresses[0] if addresses else None


def vm_guest_addresses(name: str, bridge: str | None = None) -> list[str]:
    """Resolve the VM's addresses, best source first.

    Under passt (`bridge` is None) a VM has no address of its own to find: the
    guest is assigned the *host's* address, and management traffic reaches it
    on the workload's own 127.128.x.y instead. See vm_ssh_endpoint, which is
    what the SSH paths actually use. This function then reports only what the
    guest itself says, for display.

    On an operator-provided bridge the guest does have its own LAN address, and
    the host has to infer it. Three sources, in descending order of authority:

    1. **qemu-guest-agent** — the guest's own answer, over virtio-serial. The
       only source that does not depend on host-side state going stale.
    2. **the host neighbour table**, matched on the MAC we assigned the VM.
       Passive: it can only report a guest the host has recently talked to, so
       a perfectly healthy long-idle VM drops out of it once the entry is
       garbage-collected. That gap is exactly what source 1 closes.
    3. **mDNS** ({name}.local), when avahi/nss-mdns are wired up on the host.

    The dnsmasq lease file that used to sit between 1 and 2 went with the
    managed bridge (ADR 006) — there is no dnsmasq of ours any more.

    Returns [] when nothing resolves — a runtime condition (not booted yet, no
    agent), not an error.
    """
    mac = mac_address(name)

    agent = vm_guest_agent_addresses(name, mac)
    if agent:
        return agent

    if bridge is None:
        # passt: nothing further to try. The neighbour table and mDNS both ask
        # "which host on this segment is the guest", and under passt there is
        # no segment and the answer would be the host itself.
        return []

    # Operator-provided bridge: look the guest up by the MAC we assigned it.
    try:
        result = subprocess.run(
            ["ip", "neigh", "show", "dev", bridge],
            capture_output=True, text=True,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            # `ip neigh show dev <iface>` omits the `dev <iface>` tokens it
            # prints in the unfiltered form, so the MAC's column isn't fixed
            # (`<ip> lladdr <mac> <state>` here vs `<ip> dev <iface> lladdr
            # <mac> <state>` unfiltered). Find it by the `lladdr` marker, which
            # is stable either way; parts[0] is always the IP.
            if "lladdr" in parts:
                mac_idx = parts.index("lladdr") + 1
                if mac_idx < len(parts) and parts[mac_idx].lower() == mac.lower():
                    return [parts[0]]
    except OSError:
        pass

    # mDNS fallback: works when avahi + nss-mdns are installed on the host.
    try:
        result = subprocess.run(
            ["getent", "hosts", f"{name}.local"],
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode == 0:
            parts = result.stdout.split()
            if parts:
                return [parts[0]]
    except (OSError, subprocess.TimeoutExpired):
        pass

    return []
