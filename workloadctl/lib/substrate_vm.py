"""
substrate_vm — the VM substrate.

Implements the Substrate port for workloads with a ``[vm]`` section: raw
QEMU/KVM networked with passt (ADR 006), reached over SSH (guest interior) and
QMP (QEMU monitor). A VM's SSH endpoint is derived from its workload uid rather
than discovered, unless it is pinned to an operator-provided bridge — see
``_vm_ssh_endpoint``.

Optional primitives implemented here: resource_usage, reprovision, addresses,
teardown, teardown_plan.
``endpoints`` uses the base-class NotApplicable default, and ``logs`` uses the
base default (the VM's QEMU service journal is on the host journal).
"""

from __future__ import annotations

import json
import os
import pwd
import random
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

from backup import backup_vm, backup_vm_crash
from cli_log import error, info
from qmp import QMPClient
from substrate import (
    LifecycleError,
    NotApplicable,
    ProvisionFailed,
    Substrate,
    service_active,
)
from vm import (
    VM_MGMT_SSH_PORT,
    VM_SOCKET_DIR,
    parse_memory_mib,
    vm_guest_agent_socket,
    vm_mac_address,
    vm_management_address,
)
from vm_metrics import get_vm_qmp_metrics
from workload_lib import workload_service_units
from workloadctl_core import WorkloadUserNotFound, format_size


def _vm_console_sock(name: str) -> Path:
    return VM_SOCKET_DIR / name / "console.sock"


def _vm_ssh_key(config) -> Path:
    return config.home_dir / ".ssh" / "id_ed25519"


def _vm_guest_user(config) -> str:
    return config.config.get("vm", {}).get("user", "workload")


def _vm_ssh_endpoint(config) -> tuple[str, int] | None:
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
        return (vm_management_address(uid), VM_MGMT_SSH_PORT)
    guest_ip = _vm_guest_ip(config.name, config.vm_bridge)
    return (guest_ip, 22) if guest_ip else None


def _vm_ssh_command(
    config,
    endpoint: tuple[str, int],
    exec_args: list[str] | None = None,
    connect_timeout: int | None = None,
) -> list[str]:
    """Build the ssh argv used to reach a VM workload's guest user."""
    key_path = _vm_ssh_key(config)
    guest_user = _vm_guest_user(config)
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


# How long to wait for qemu-guest-agent to answer. Every VM is wired with the
# agent channel (see generate_vm_service), but a guest that hasn't installed or
# started qemu-ga never opens its end — QEMU still accepts our connection, so a
# missing agent looks exactly like a slow one and can only be told apart by
# waiting. `exec` and `shell` sit behind this, so the budget is small: agent
# present means a local unix-socket round trip (milliseconds), and agent absent
# costs this once before falling through to the host-side sources.
GUEST_AGENT_TIMEOUT = 1.5


def _guest_agent_sync(qga: QMPClient, max_messages: int = 8) -> None:
    """Handshake that guarantees the next reply we read is the one we asked for.

    The channel is a stream that outlives any single client. If a previous
    lookup timed out after sending a command but before reading its reply — the
    GUEST_AGENT_TIMEOUT case, so not hypothetical — that reply is still queued
    in the port when the next connection opens, and a naive read would take it
    as the answer to a question it never asked. guest-sync carries a nonce, so
    anything ahead of the matching reply is provably stale and discarded.

    Raises (like any other agent failure) when the nonce never comes back; the
    caller treats that as "no agent" and falls through.
    """
    token = random.randint(1, 2**31)
    reply = qga.execute("guest-sync", {"id": token})
    for _ in range(max_messages):
        if reply.get("return") == token:
            return
        message = qga.next_message()
        if message is None:
            break
        reply = message
    raise ConnectionError("guest agent did not echo the sync token")


def _vm_guest_agent_addresses(name: str, mac: str) -> list[str]:
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
        _guest_agent_sync(qga)
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


def _vm_guest_ip(name: str, bridge: str | None = None) -> str | None:
    """The single best address for this VM, or None if nothing resolves it.

    Thin wrapper over _vm_guest_addresses for the SSH paths, which need exactly
    one address.
    """
    addresses = _vm_guest_addresses(name, bridge)
    return addresses[0] if addresses else None


def _vm_guest_addresses(name: str, bridge: str | None = None) -> list[str]:
    """Resolve the VM's addresses, best source first.

    Under passt (`bridge` is None) a VM has no address of its own to find: the
    guest is assigned the *host's* address, and management traffic reaches it
    on the workload's own 127.128.x.y instead. See _vm_ssh_endpoint, which is
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
    mac = vm_mac_address(name)

    agent = _vm_guest_agent_addresses(name, mac)
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


class VMSubstrate(Substrate):
    """Substrate for VM workloads ([vm] section in TOML).

    Overrides reprovision, resource_usage and addresses (see below); endpoints
    uses the base-class NotApplicable default, and logs uses the base default
    (the VM's QEMU service journal is on the host journal).
    """

    # Wall-clock gap between the two vCPU-time samples cpu_percent is derived
    # from. QMP reports cumulative CPU seconds, so a rate needs two reads.
    CPU_SAMPLE_SECONDS = 0.5

    # ── required primitives ───────────────────────────────────────────────────

    def liveness(self) -> dict:
        active, state = service_active(self.config.service_name)
        return {
            "service_active": active,
            "service_state": state or "unknown",
            "container_running": None,
            "container_status": None,
            "healthy": active,
        }

    # logs, endpoints: inherited base auto-raises NotApplicable.

    def _vm_stat_row(self) -> dict:
        """One STAT_ROW_KEYS row for this VM, sourced from QMP.

        Reads the dedicated read-only metrics monitor (qmp-metrics.sock), the
        same socket the Prometheus exporter scrapes — never the control socket,
        which serves one client at a time and whose ExecStop system_powerdown a
        competing reader could block.

        net/block I/O are None: QEMU would answer query-blockstats, but nothing
        collects it yet, and a zero here would read as an idle disk.
        """
        first = get_vm_qmp_metrics(self.config.name)
        if not first:
            raise NotApplicable(
                f"resource_usage: no QMP metrics socket for '{self.config.name}' "
                f"(is the VM running?)"
            )

        def _cpu_seconds(metrics: dict) -> float:
            return sum(v for k, v in metrics.items() if k.startswith("vcpu_"))

        time.sleep(self.CPU_SAMPLE_SECONDS)
        second = get_vm_qmp_metrics(self.config.name)

        cpu_percent = 0.0
        if second:
            delta = _cpu_seconds(second) - _cpu_seconds(first)
            cpu_percent = max(0.0, delta / self.CPU_SAMPLE_SECONDS * 100)

        mem_usage = (second or first).get("balloon_actual_bytes")
        try:
            mem_limit = parse_memory_mib(self.config.config["vm"].get("memory")) * 1024 * 1024
        except (KeyError, ValueError):
            mem_limit = None

        mem_percent = None
        if mem_usage is not None and mem_limit:
            mem_percent = mem_usage / mem_limit * 100

        return {
            "workload": self.config.name,
            "username": self.config.username,
            "container": None,
            "cpu_percent": cpu_percent,
            "mem_usage": mem_usage,
            "mem_limit": mem_limit,
            "mem_percent": mem_percent,
            "net_input": None,
            "net_output": None,
            "block_input": None,
            "block_output": None,
            "pids": None,
        }

    def resource_usage(
        self,
        target_names: list[str],
        *,
        no_stream: bool = True,
        json_out: bool = False,
        follow: bool = False,
    ):
        if follow:
            raise NotApplicable("resource_usage: --follow is not supported for VMs")

        row = self._vm_stat_row()
        if json_out:
            return [row]

        def _mem(v):
            return format_size(v) if v is not None else "--"

        print(f"{'WORKLOAD':<20} {'CPU %':>7}  {'MEM USAGE / LIMIT':<21} {'MEM %':>6}")
        mem = f"{_mem(row['mem_usage'])} / {_mem(row['mem_limit'])}"
        pct = f"{row['mem_percent']:.2f}%" if row["mem_percent"] is not None else "--"
        print(f"{row['workload']:<20} {row['cpu_percent']:>6.2f}%  {mem:<21} {pct:>6}")
        return None

    def capture(
        self,
        output: Path,
        *,
        consistency: str = "cold",
        quiet: bool = False,
    ) -> int:
        if consistency == "crash":
            return backup_vm_crash(self.config, output, quiet=quiet)
        # cold (default) — stop service, copy, restart.
        return backup_vm(self.config, output, quiet=quiet)

    def gating_units(self) -> list[str]:
        return workload_service_units(self.config, roles={"setup", "build"})

    def _guest_ip(self) -> tuple[str, int] | None:
        """The (host, port) the SSH paths need; None if not resolvable yet."""
        return _vm_ssh_endpoint(self.config)

    def _report_no_guest_ip(self) -> None:
        """Explain an unreachable guest in terms of what was actually tried.

        The two topologies fail for entirely different reasons, so a single
        fixed hint would be wrong half the time. Under passt the address is
        derived and cannot fail to resolve — only the *user* lookup can — so
        pointing at address discovery there would send someone chasing a
        problem they do not have.
        """
        name = self.config.name
        bridge = self.config.vm_bridge
        if bridge is None:
            error(f"Error: could not determine the management address for VM "
                  f"'{name}'")
            error(f"  It is derived from the workload user's uid, so this means "
                  f"the user '{self.config.username}' does not exist yet — run "
                  f"'sudo workloadctl enable {name}'.")
            error(f"  Console access always works: workloadctl shell {name} --console")
            return

        error(f"Error: could not determine IP for VM '{name}'")
        if not vm_guest_agent_socket(name).exists():
            # Two different states, and guessing between them would be wrong
            # half the time: a stopped VM has no socket, and so does a running
            # VM whose unit was generated before the agent channel existed —
            # which is every VM until it is next regenerated and restarted.
            error(f"  No guest agent channel. Either the VM is not running, or "
                  f"its unit predates the channel — 'workloadctl enable {name}' "
                  f"then restart the VM to add it.")
        else:
            error("  qemu-guest-agent did not answer; install and enable it in "
                  "the guest for address lookup that does not depend on the host.")
        error(f"  On bridge {bridge} (operator-provided) the guest leases from "
              f"that network's own DHCP, so the fallback is the host neighbour "
              f"table — which only lists a guest the host has talked to "
              f"recently.")
        error(f"  Console access always works: workloadctl shell {name}")

    def addresses(self) -> list[str]:
        """The guest's addresses, best first; empty until one resolves.

        More than one only when qemu-guest-agent answered — the host-side
        sources each yield a single address by construction.
        """
        return _vm_guest_addresses(self.config.name, self.config.vm_bridge)

    def exec(
        self,
        argv: list[str],
        *,
        container: str | None = None,
    ) -> int:
        endpoint = self._guest_ip()
        if not endpoint:
            self._report_no_guest_ip()
            raise LifecycleError(1)
        ssh_cmd = _vm_ssh_command(self.config, endpoint, exec_args=argv)
        return subprocess.run(ssh_cmd).returncode

    def open_shell(
        self,
        *,
        container: str | None = None,
        console: bool = False,
    ) -> None:
        # Prefer SSH so the guest tty inherits the host's window size and
        # signal handling. The serial console (socat below) is reserved as
        # an explicit recovery path when --console is passed or SSH can't
        # reach the VM (no lease, no network, sshd down).
        if not console:
            endpoint = self._guest_ip()
            if endpoint:
                ssh_cmd = _vm_ssh_command(self.config, endpoint, connect_timeout=5)
                result = subprocess.run(ssh_cmd)
                if result.returncode == 0:
                    return
                # 255 = ssh transport failure (host unreachable, auth, etc.), so
                # fall through to the console. Anything else came from the remote
                # shell and is the exit code the operator should see.
                if result.returncode != 255:
                    raise LifecycleError(result.returncode)
                error(
                    f"SSH to '{self.config.name}' failed; falling back to serial console.",
                )
            else:
                error(
                    f"No SSH endpoint for VM '{self.config.name}'; falling back "
                    f"to serial console.",
                )

        # Connect to the VM serial console via the socat multiplexer.
        console_sock = _vm_console_sock(self.config.name)
        if not console_sock.exists():
            error(f"Error: console socket not found: {console_sock}")
            error(f"Is workload '{self.config.name}' running?")
            raise LifecycleError(1)
        info(f"Connecting to {self.config.name} console (Ctrl-] to disconnect)...")
        info()
        os.execvp(
            "socat",
            ["socat", "STDIO,raw,echo=0,escape=0x1d", f"UNIX-CONNECT:{console_sock}"],
        )
        # execvp replaces the process; unreachable

    def lifecycle(self, action: str) -> None:
        """Unified lifecycle for VMs: start / stop / restart / reboot."""
        if action == "start":
            result = subprocess.run(["systemctl", "start", self.config.service_name])
            if result.returncode != 0:
                raise LifecycleError(result.returncode)
        elif action == "stop":
            result = subprocess.run(["systemctl", "stop", self.config.service_name])
            if result.returncode != 0:
                raise LifecycleError(result.returncode)
        elif action == "restart":
            # A power-cycle onto the existing disks and cloud-init seed. The setup
            # oneshot (RemainAfterExit=yes) is deliberately left alone: re-rendering
            # the seed from a changed TOML is reprovision(recreate=True)'s job, and
            # a bounce shouldn't silently re-seed the guest.
            result = subprocess.run(["systemctl", "restart", self.config.service_name])
            if result.returncode != 0:
                raise LifecycleError(result.returncode)
        elif action == "reboot":
            endpoint = self._guest_ip()
            if not endpoint:
                self._report_no_guest_ip()
                raise LifecycleError(1)
            # Fire the soft-reboot detached via systemd-run --no-block: a direct
            # `systemctl soft-reboot` tears down sshd mid-command, so the SSH
            # connection drops and ssh exits nonzero *even on success*. Running it
            # in a transient unit lets the SSH command return cleanly (0) before
            # teardown; --collect reaps the unit.
            ssh_cmd = _vm_ssh_command(
                self.config, endpoint,
                exec_args=[
                    "sudo", "systemd-run", "--collect", "--no-block",
                    "systemctl", "soft-reboot",
                ],
                connect_timeout=5,
            )
            result = subprocess.run(ssh_cmd)
            if result.returncode != 0:
                error("Error: could not initiate guest soft-reboot.")
                error(
                    "  Needs passwordless sudo and systemd 254+ in the guest. To "
                    "power-cycle the VM regardless of its init system (disk "
                    "preserved), run:",
                )
                error(f"    sudo systemctl restart {self.config.service_name}")
                raise LifecycleError(1)
            info(f"✓ VM '{self.config.name}' soft-reboot initiated (disk preserved)")
        else:
            raise ValueError(f"Unknown lifecycle action: {action!r}")

    def reprovision(self, *, force: bool = False, recreate: bool = False):
        if recreate:
            # recreate path: re-render cloud-init seed and restart QEMU.
            # For pet VMs this is safe — it does not touch system.qcow2.
            info(f"Recreating VM workload {self.config.name}...")
            for unit in (
                workload_service_units(self.config, roles={"setup"})[0],
                self.config.service_name,
            ):
                restart = subprocess.run(
                    ["systemctl", "restart", unit], check=False
                )
                if restart.returncode != 0:
                    error(f"  ✗ Restart failed for {unit}")
                    raise ProvisionFailed(f"restart failed for {self.config.name}")
            return None

        if self.config.lifecycle == "pet":
            # Pet VMs: do not rebuild or rotate system.qcow2 — the durable disk
            # is preserved.  Only restart QEMU so config-level changes (e.g.
            # memory, cpu) in the unit file are picked up.
            info(
                f"  ℹ {self.config.name} is a pet VM — skipping system disk rebuild "
                f"and generation rotation to preserve durable disk."
            )
            restart = subprocess.run(
                ["systemctl", "restart", self.config.service_name], check=False
            )
            if restart.returncode != 0:
                error(f"  ✗ Restart failed for {self.config.name}")
                raise ProvisionFailed(f"restart failed for {self.config.name}")
            info(f"  ✓ {self.config.name}: restarted (disk unchanged)")
            return None

        info(f"Updating VM workload {self.config.name}...")
        result = subprocess.run(
            [
                "/usr/libexec/workloadctl/workload-vm-build-disk",
                self.config.name, "--update",
            ],
            check=False,
        )
        if result.returncode != 0:
            error(f"  ✗ Disk rebuild failed for {self.config.name}")
            raise ProvisionFailed(f"disk rebuild failed for {self.config.name}")
        restart = subprocess.run(
            ["systemctl", "restart", self.config.service_name], check=False
        )
        if restart.returncode != 0:
            error(f"  ✗ Restart failed for {self.config.name}")
            raise ProvisionFailed(f"restart failed for {self.config.name}")
        info(f"  ✓ {self.config.name}: rebuilt and restarted")
        return None  # no verification phase for VMs

    @staticmethod
    def _generation_numbers(home_dir: Path, exclude: int | None = None) -> list:
        """Sorted generation numbers N of the `system.qcow2.gen-N` snapshots in
        `home_dir` (ascending; highest == newest), optionally omitting `exclude`."""
        return sorted(
            n
            for p in home_dir.glob("system.qcow2.gen-*")
            if (s := p.suffix[5:]).isdigit() and (n := int(s)) != exclude
        )

    def rollback_targets(self) -> list:
        """Return available VM rollback targets (system.qcow2.gen-N snapshots)."""
        home_dir = self.config.home_dir
        gens = self._generation_numbers(home_dir)
        return [
            {
                "label": f"system.qcow2.gen-{g}",
                "gen": g,
                "path": home_dir / f"system.qcow2.gen-{g}",
            }
            for g in gens
        ]

    @staticmethod
    def _prune_generations(home_dir: Path, keep: int, exempt: int) -> None:
        """Keep at most `keep` generations older than `exempt`, matching the
        update-path rotation (rotate_generations in workload-vm-build-disk):
        `exempt` (the freshly rotated-out disk) is always retained as the primary
        restore point, so `keep + 1` gen files survive in total."""
        gens = VMSubstrate._generation_numbers(home_dir, exclude=exempt)
        for gen_n in (gens[:-keep] if keep > 0 else gens):
            info(f"  Pruning old generation: system.qcow2.gen-{gen_n}")
            (home_dir / f"system.qcow2.gen-{gen_n}").unlink(missing_ok=True)

    def rollback_to(self, target: dict) -> None:
        """Apply a single VM rollback target from rollback_targets().

        Non-destructive (ADR 003): before swapping the target generation in,
        rotate the CURRENT system.qcow2 out to a new generation so the
        pre-rollback state survives and a roll-forward is possible — mirroring
        container rollback, which keeps both images. The rotated-out disk is
        pruned by rollback_keep like any other generation.
        """
        home_dir = self.config.home_dir
        system_disk = home_dir / "system.qcow2"
        gen_path = Path(target["path"])
        gen = target["gen"]
        rollback_keep = self.config.config.get("vm", {}).get("rollback_keep", 2)
        info(f"Rolling back VM '{self.config.name}':")
        # Stop the VM before swapping disks: QEMU holds the active qcow2 open,
        # and renaming a file out from under it leaves the running guest writing
        # to an unlinked inode while the new disk is mounted by the next start.
        subprocess.run(["systemctl", "stop", self.config.service_name], check=False)
        # Rotate the current disk out to a fresh generation (highest number =
        # newest) so rolling back is itself reversible.
        rotated_gen = None
        if system_disk.exists():
            existing = self._generation_numbers(home_dir)
            rotated_gen = (max(existing) + 1) if existing else 1
            rotated = home_dir / f"system.qcow2.gen-{rotated_gen}"
            info(f"  system.qcow2 → {rotated.name} (pre-rollback state preserved)")
            system_disk.rename(rotated)
        info(f"  system.qcow2.gen-{gen} → system.qcow2")
        try:
            gen_path.replace(system_disk)
        except OSError as e:
            # The current disk was already rotated out to `rotated`. If swapping
            # the target generation in fails now (ENOSPC, permissions, …),
            # system.qcow2 is missing and the VM has no active disk. Put the
            # pre-rollback disk back so the guest still boots, then surface a
            # clean failure instead of an unhandled traceback.
            if rotated_gen is not None and not system_disk.exists():
                rotated.rename(system_disk)
            error(f"Error: VM rollback failed swapping in generation {gen}: {e}")
            raise LifecycleError(1) from e
        if rotated_gen is not None:
            self._prune_generations(home_dir, rollback_keep, exempt=rotated_gen)
        subprocess.run(["systemctl", "start", self.config.service_name], check=True)
        info(f"✓ Rolled back {self.config.name} to generation {gen}")

    def control(self, argv: list[str]) -> int:
        """Send a QMP command to the QEMU monitor for this VM.

        The first token of ``argv`` is the QMP command name; remaining tokens
        must be ``key=value`` pairs that become the command arguments dict.
        The JSON reply is printed to stdout.  Follows the same pattern as
        ``libexec/workload-vm-qmp``.
        """
        if not argv:
            print("Error: incant requires a QMP command name", file=sys.stderr)
            return 2
        command = argv[0]
        arguments: dict = {}
        for kv in argv[1:]:
            if "=" in kv:
                k, _, v = kv.partition("=")
                arguments[k] = v
            else:
                print(
                    f"Error: VM incant arguments must be key=value pairs, got: {kv!r}",
                    file=sys.stderr,
                )
                return 2

        sock_path = VM_SOCKET_DIR / self.config.name / "qmp.sock"
        if not sock_path.exists():
            print(f"Error: QMP socket not found: {sock_path}", file=sys.stderr)
            print(f"Is workload '{self.config.name}' running?", file=sys.stderr)
            return 1

        qmp = QMPClient()
        try:
            qmp.connect(str(sock_path))
            qmp.negotiate()
            reply = qmp.execute(command, arguments or None)
            print(json.dumps(reply, indent=2))
            return 0 if "return" in reply else 1
        except (TimeoutError, ConnectionError, OSError) as exc:
            print(f"Error: QMP command failed: {exc}", file=sys.stderr)
            return 1
        finally:
            qmp.close()

    def rollback(self) -> None:
        """Roll back to the latest generation snapshot."""
        if self.config.lifecycle == "pet":
            error(
                f"Error: VM '{self.config.name}' is a pet — system.qcow2 is never "
                f"rotated, so there are no generation snapshots to roll back to.",
            )
            error(
                "  Use 'workloadctl update' to restart the VM without touching the disk.",
            )
            raise LifecycleError(1)
        targets = self.rollback_targets()
        if not targets:
            error(
                f"Error: No rollback generation found for VM '{self.config.name}'",
            )
            error(
                "  (generations are created automatically by 'workloadctl update')",
            )
            raise LifecycleError(1)
        # Apply the most recent (highest generation number) snapshot.
        latest = targets[-1]
        self.rollback_to(latest)


    def teardown(self, *, purge: bool) -> list[str]:
        """Remove what a VM workload owns beyond its generated files.

        On purge: the runtime socket dir (QMP + serial sockets, stale once the
        guest is stopped), and this workload's elements in the shared nftables
        sets. Retiring the managed bridge (ADR 006) removed the only host-global
        resource a VM shared with its siblings, and with it the refcount that
        decided when to stop it; passt runs inside each VM's own unit, as that
        workload's user, so it exits with the VM and leaves nothing behind.

        The nft sets are the one exception, and they are swept here rather than
        left to the unit because purge also deletes the workload user: once the
        uid is gone the elements can no longer be attributed to anything, and a
        later workload issued the same uid would inherit them.
        """
        failures: list[str] = []

        if purge:
            try:
                sock_dir = VM_SOCKET_DIR / self.config.name
                if sock_dir.exists():
                    shutil.rmtree(sock_dir, ignore_errors=True)
            except Exception as e:
                failures.append(f"remove VM socket dir: {e}")

            try:
                subprocess.run(
                    ["/usr/libexec/workloadctl/workload-vm-filter",
                     "down", self.config.name],
                    capture_output=True, timeout=30, check=False)
            except Exception as e:
                failures.append(f"clear egress filter elements: {e}")

            # The redirect needs its own helper. workload-vm-filter's purge
            # iterates NFT_SETS alone -- wl_filtered and the two allow sets --
            # so it does not touch a single object the inspector owns: the
            # wl_inspect4/6 DNAT maps (a different table entirely), the
            # wl_inspect_dst/dst6 and wl_inspect_self/self6 guards, the
            # wl_internal_ok4/6 exemptions, or the per-workload listener
            # address on the dummy link.
            #
            # Those are normally withdrawn by the inspect units' own
            # ExecStopPost, and normally that is enough. It is not enough here,
            # because purge also deletes the user: if the stop path never ran
            # (a hard kill, a failed stop, units unlinked before stop) the
            # elements survive keyed on a uid get_next_uid will hand out again,
            # and the next workload issued it -- one with `egress = "open"` and
            # no inspector at all -- has its 80/443 DNATed into a listener that
            # does not exist. It black-holes silently: vm_inspect_check returns
            # None for an unfiltered VM, so `status`, `vm_egress` and
            # `vm_inspect` all read correct while nothing reaches the network.
            #
            # Idempotent and best-effort, exactly like the filter sweep above:
            # `down` tolerates every element already being gone, which is the
            # expected state whenever the units did stop cleanly.
            try:
                subprocess.run(
                    ["/usr/libexec/workloadctl/workload-vm-inspect",
                     "down", self.config.name],
                    capture_output=True, timeout=30, check=False)
            except Exception as e:
                failures.append(f"clear inspect redirect elements: {e}")

        return failures

    def teardown_plan(self, *, purge: bool) -> list[str]:
        """Describe teardown, reporting only what is actually present."""
        lines = []
        if purge:
            sock_dir = VM_SOCKET_DIR / self.config.name
            if sock_dir.exists():
                lines.append(f"remove VM socket dir: {sock_dir}")
            lines.append(
                "clear egress filter elements from inet workload_filter")
            lines.append(
                "clear inspect redirect elements from inet workload_proxy")
            lines.append(
                "clear inspect guard and internal exemption elements "
                "from inet workload_filter")
            lines.append("remove the inspector's listener address")
        return lines
