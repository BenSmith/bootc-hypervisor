"""
substrate_vm — the VM substrate.

Implements the Substrate port for workloads with a ``[vm]`` section: raw
QEMU/KVM networked with passt (ADR 006), reached over SSH (guest interior) and
QMP (QEMU monitor). A VM's SSH endpoint is derived from its workload uid rather
than discovered, unless it is pinned to an operator-provided bridge — see
``vm_ssh_endpoint``.

Optional primitives implemented here: resource_usage, reprovision, addresses,
teardown, teardown_plan.
``endpoints`` uses the base-class NotApplicable default, and ``logs`` uses the
base default (the VM's QEMU service journal is on the host journal).
"""

from __future__ import annotations

import json
import os
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
    systemctl_or_raise,
)
from egress_policy import vm_uses_inspect
from config_parser import SOCKET_DIR
from vm_defs import parse_memory_mib, vm_guest_agent_socket
from vm_metrics import get_vm_qmp_metrics
from run_files import workload_service_units
from workloadctl_core import format_size
from vm_guest_reach import (
    vm_console_sock,
    vm_guest_addresses,
    vm_ssh_command,
    vm_ssh_endpoint,
)


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

    def uses_inspect(self) -> bool:
        return vm_uses_inspect(self.config.config)

    def _guest_ip(self) -> tuple[str, int] | None:
        """The (host, port) the SSH paths need; None if not resolvable yet."""
        return vm_ssh_endpoint(self.config)

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
        return vm_guest_addresses(self.config.name, self.config.vm_bridge)

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
        ssh_cmd = vm_ssh_command(self.config, endpoint, exec_args=argv)
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
                ssh_cmd = vm_ssh_command(self.config, endpoint, connect_timeout=5)
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
        console_sock = vm_console_sock(self.config.name)
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
            systemctl_or_raise("start", self.config.service_name)
        elif action == "stop":
            systemctl_or_raise("stop", self.config.service_name)
        elif action == "restart":
            # A power-cycle onto the existing disks and cloud-init seed. The setup
            # oneshot (RemainAfterExit=yes) is deliberately left alone: re-rendering
            # the seed from a changed TOML is reprovision(recreate=True)'s job, and
            # a bounce shouldn't silently re-seed the guest.
            systemctl_or_raise("restart", self.config.service_name)
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
            ssh_cmd = vm_ssh_command(
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
        update-path rotation (vm_disk_generations.rotate_generations):
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

        sock_path = SOCKET_DIR / self.config.name / "qmp.sock"
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
                sock_dir = SOCKET_DIR / self.config.name
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
            # does not exist. It black-holes silently: inspect_check returns
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
            sock_dir = SOCKET_DIR / self.config.name
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
