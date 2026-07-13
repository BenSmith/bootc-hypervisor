"""
substrate_vm — the VM substrate.

Implements the Substrate port for workloads with a ``[vm]`` section: raw
QEMU/KVM on the shared ``_workload-br`` bridge, reached over SSH (guest
interior) and QMP (QEMU monitor).

Optional primitives implemented here: resource_usage, reprovision. ``endpoints``
uses the base-class NotApplicable default, and ``logs`` uses the base default
(the VM's QEMU service journal is on the host journal).
"""

from __future__ import annotations

import json
import os
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
    VM_BRIDGE_NAME,
    VM_DHCP_LEASE_FILE,
    VM_SOCKET_DIR,
    parse_memory_mib,
    vm_mac_address,
)
from vm_metrics import get_vm_qmp_metrics
from workload_lib import workload_service_units
from workloadctl_core import format_size


def _vm_console_sock(name: str) -> Path:
    return VM_SOCKET_DIR / name / "console.sock"


def _vm_ssh_key(config) -> Path:
    return config.home_dir / ".ssh" / "id_ed25519"


def _vm_guest_user(config) -> str:
    return config.config.get("vm", {}).get("user", "workload")


def _vm_ssh_command(
    config,
    guest_ip: str,
    exec_args: list[str] | None = None,
    connect_timeout: int | None = None,
) -> list[str]:
    """Build the ssh argv used to reach a VM workload's guest user."""
    key_path = _vm_ssh_key(config)
    guest_user = _vm_guest_user(config)
    known_hosts = config.home_dir / ".ssh" / "vm_known_hosts"
    cmd = [
        "ssh",
        *(["-t"] if sys.stdout.isatty() else []),
        "-i", str(key_path),
        # Host-key pinning (S1): verify the guest against the per-workload
        # known_hosts written at provisioning time, keyed by the stable
        # workload name via HostKeyAlias so DHCP/ARP/mDNS address churn never
        # invalidates the pin. No trust-on-first-use, no MITM on the shared
        # bridge.
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", f"HostKeyAlias={config.name}",
        "-o", "LogLevel=ERROR",
    ]
    if connect_timeout is not None:
        cmd += ["-o", f"ConnectTimeout={connect_timeout}"]
    cmd.append(f"{guest_user}@{guest_ip}")
    if exec_args:
        cmd += ["--", *exec_args]
    return cmd


def _vm_guest_ip(name: str, bridge: str = VM_BRIDGE_NAME) -> str | None:
    """Look up the VM's IP by hostname in dnsmasq leases, MAC via ARP, or mDNS.

    The dnsmasq lease file is only authoritative when workload-bridge.service
    actually manages a bridge it created (signalled by /run/workload-vm/
    bridge-managed). On a pre-existing LAN bridge (e.g. br0) no dnsmasq runs
    and any old lease entries are stale, so we go straight to ARP.

    Falls back to mDNS ({name}.local) when avahi/nss-mdns are available.
    """
    if Path("/run/workload-vm/bridge-managed").exists():
        lease_file = VM_DHCP_LEASE_FILE
        if lease_file.exists():
            try:
                for line in lease_file.read_text().splitlines():
                    parts = line.split()
                    # dnsmasq lease format: <timestamp> <mac> <ip> <hostname> <client-id>
                    if len(parts) >= 4 and parts[3] == name:
                        return parts[2]
            except OSError:
                pass

    # Pre-existing LAN bridge: no lease file.  Look up by the VM's stable MAC.
    mac = vm_mac_address(name)
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
                    return parts[0]
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
                return parts[0]
    except (OSError, subprocess.TimeoutExpired):
        pass

    return None


class VMSubstrate(Substrate):
    """Substrate for VM workloads ([vm] section in TOML).

    Overrides reprovision and resource_usage (see below); endpoints uses the
    base-class NotApplicable default, and logs uses the base default (the VM's
    QEMU service journal is on the host journal).
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

    def exec(
        self,
        argv: list[str],
        *,
        container: str | None = None,
    ) -> int:
        guest_ip = _vm_guest_ip(self.config.name, self.config.vm_bridge)
        if not guest_ip:
            error(
                f"Error: could not determine IP for VM '{self.config.name}'",
            )
            error(
                f"  Check {VM_DHCP_LEASE_FILE} or use "
                f"'workloadctl shell {self.config.name}' (console).",
            )
            raise LifecycleError(1)
        ssh_cmd = _vm_ssh_command(self.config, guest_ip, exec_args=argv)
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
            guest_ip = _vm_guest_ip(self.config.name, self.config.vm_bridge)
            if guest_ip:
                ssh_cmd = _vm_ssh_command(self.config, guest_ip, connect_timeout=5)
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
                    f"No IP found for VM '{self.config.name}'; falling back to serial console.",
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
            guest_ip = _vm_guest_ip(self.config.name, self.config.vm_bridge)
            if not guest_ip:
                error(
                    f"Error: could not determine IP for VM '{self.config.name}'",
                )
                error(
                    f"  Check {VM_DHCP_LEASE_FILE} or use "
                    f"'workloadctl shell {self.config.name}' (console).",
                )
                raise LifecycleError(1)
            # Fire the soft-reboot detached via systemd-run --no-block: a direct
            # `systemctl soft-reboot` tears down sshd mid-command, so the SSH
            # connection drops and ssh exits nonzero *even on success*. Running it
            # in a transient unit lets the SSH command return cleanly (0) before
            # teardown; --collect reaps the unit.
            ssh_cmd = _vm_ssh_command(
                self.config, guest_ip,
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
