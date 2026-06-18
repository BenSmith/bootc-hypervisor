"""
substrate — substrate port for workloadctl.

Defines the Substrate ABC, ContainerSubstrate and VMSubstrate
implementations, and the router function get_substrate().

Design: workloadctl/docs/wip/substrate-dispatch.md

Usage pattern:
    substrate = get_substrate(config, manager)
    try:
        substrate.resource_usage(...)
    except NotApplicable as e:
        print(f"stats: not applicable — {e.reason}")
        sys.exit(0)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from abc import ABC, abstractmethod
from pathlib import Path

from workload_lib import (
    auto_detect_credentials,
    VM_BRIDGE_NAME,
    VM_DHCP_LEASE_FILE,
    VM_SOCKET_DIR,
    vm_mac_address,
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class NotApplicable(Exception):
    """Raised when a verb is not applicable to the current substrate.

    The caller is expected to print a clear message and exit 0
    (the verb is not broken; it simply doesn't apply here).
    """
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class ProvisionFailed(Exception):
    """Raised by reprovision() when a build or restart step fails.

    The caller is expected to print a diagnostic and either sys.exit(1)
    (single-workload path) or increment a failure counter (--all path).
    The error message has already been printed by the substrate method.
    """


# ---------------------------------------------------------------------------
# VM infrastructure helpers (module-level so they can be re-exported by
# cmd_interact for any callers that still import them from there)
# ---------------------------------------------------------------------------

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
    cmd = [
        "ssh",
        *(["-t"] if sys.stdout.isatty() else []),
        "-i", str(key_path),
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
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


def _interactive_exec_flags() -> list[str]:
    """Interactivity flags for `podman exec`: always keep stdin open (-i), but
    only allocate a pseudo-TTY (-t) when stdin is a real terminal.

    Passing -t without a TTY hangs on piped input. Without -t, scripted /
    non-interactive callers use a plain no-pty exec path, which is robust.
    """
    return ["-i", "-t"] if sys.stdin.isatty() else ["-i"]


# ---------------------------------------------------------------------------
# Rollback image tag (shared between ContainerSubstrate and cmd_update helpers)
# ---------------------------------------------------------------------------

def rollback_tag(name: str, container: str | None = None) -> str:
    """Return the rollback image tag for a workload (or one of its containers)."""
    suffix = f"-{container}" if container else ""
    return f"localhost/workload-rollback/{name}{suffix}:latest"


# ---------------------------------------------------------------------------
# Substrate ABC
# ---------------------------------------------------------------------------

class Substrate(ABC):
    """Per-substrate primitive port.

    All substrate-variant verbs (stats, health, backup, exec, shell, start,
    reboot, update, rollback, …) delegate their substrate-specific delta here.
    Substrate-invariant verbs (create, list, validate, secret, …) bypass
    this layer entirely.

    Step-2 design: one method per verb or verb-group, "almost verbatim" lift.
    Refine toward a narrower waist in step 3 once the shared scaffolding is
    visible across both substrates.
    """

    def __init__(self, config, manager):
        self.config = config
        self.manager = manager

    # ── already-landed primitives (step 1) ───────────────────────────────────

    @abstractmethod
    def liveness(self) -> dict:
        """Return a liveness snapshot for health / status checks.

        Keys guaranteed present:
            service_active  bool
            service_state   str   (systemctl is-active output)
            healthy         bool  (substrate-defined readiness)
        """
        ...

    @abstractmethod
    def resource_usage(
        self,
        target_names: list[str],
        *,
        no_stream: bool = True,
        json_out: bool = False,
        follow: bool = False,
    ):
        """Display or stream resource usage.

        For json_out, returns the raw subprocess result (CompletedProcess) for
        the caller to parse; otherwise streams to the terminal and returns None.

        Raises NotApplicable if the substrate does not expose resource metrics
        through this primitive.
        """
        ...

    @abstractmethod
    def capture(
        self,
        output: Path,
        *,
        no_stop: bool,
        quiet: bool = False,
    ) -> int:
        """Create a backup archive.  Returns archive size in bytes.

        Raises SystemExit on unsafe operations the substrate cannot handle
        (e.g. --no-stop on a VM with a live disk).
        """
        ...

    # ── step-2 primitives ────────────────────────────────────────────────────

    @abstractmethod
    def gating_units(self) -> list[str]:
        """Systemd units that must succeed before the main service starts.

        Empty for container substrates (setup is an ExecStartPre of the main
        unit). VMs use separate RemainAfterExit=yes setup and build units; a
        failure there is otherwise hidden behind a bland 'inactive' on the
        main service.
        """
        ...

    @abstractmethod
    def exec_command(
        self,
        argv: list[str],
        *,
        container: str | None = None,
    ) -> int:
        """Execute a command inside the workload.  Returns the exit code.

        For VMs: runs via SSH into the guest.
        For containers: runs via `podman exec` into the named (or default) container.
        """
        ...

    @abstractmethod
    def open_shell(
        self,
        *,
        container: str | None = None,
        console: bool = False,
    ) -> None:
        """Open an interactive shell in the workload.  Does not return on success.

        For VMs: prefers SSH; falls back to the serial console (or uses it
        directly when console=True).  ContainerSubstrate raises NotApplicable
        for console=True.
        For containers: `podman exec` into the named (or default) container.
        """
        ...

    @abstractmethod
    def start(self) -> None:
        """Start the workload service.

        Container substrates re-pin the runtime dir and tolerate start-limit
        thrash via restart_workload_service.  VM substrates issue a plain
        `systemctl start`.
        """
        ...

    @abstractmethod
    def soft_reboot(self) -> None:
        """Initiate a soft-reboot of the workload's init system.

        VMs: SSH + `systemd-run --no-block systemctl soft-reboot`.
        Containers: `podman exec systemctl soft-reboot` in the main container.
        """
        ...

    @abstractmethod
    def recreate(self) -> None:
        """Recreate the workload from current config/image.

        Assumes the caller has already re-run the generator and daemon-reloaded.
        VMs: restart the RemainAfterExit setup oneshot before the main service
        so config edits are re-rendered into a fresh cloud-init seed.
        Containers: use restart_workload_service to re-pin the runtime dir.
        """
        ...

    @abstractmethod
    def reprovision(self, *, force: bool = False):
        """Update / reprovision the workload to its latest version.

        Container substrates: pull image(s) and restart if any changed.
        Returns (config, old_ids) if an update was applied (so the caller can
        run the post-update verification+rollback phase), or None if already
        up to date.  Raises NotApplicable if all containers have pull=never.
        Raises ProvisionFailed if a pull or restart step fails.

        VM substrates: rebuild the system disk and restart.  Returns None
        (no verification phase).  Raises ProvisionFailed on build/restart error.
        """
        ...

    @abstractmethod
    def rollback(self) -> None:
        """Roll back the workload to its previous version.

        Container substrates: retag the saved rollback image as the working
        image and restart.  Raises SystemExit if no rollback image is found.
        VM substrates: swap the most recent system.qcow2.gen-N back as the
        live disk.  Raises SystemExit if no generation snapshot exists.
        """
        ...


# ---------------------------------------------------------------------------
# ContainerSubstrate
# ---------------------------------------------------------------------------

class ContainerSubstrate(Substrate):
    """Substrate for single / pod / bridge container workloads."""

    # ── step-1 primitives ────────────────────────────────────────────────────

    def liveness(self) -> dict:
        svc = subprocess.run(
            ["systemctl", "is-active", self.config.service_name],
            capture_output=True, text=True,
        )
        service_active = svc.returncode == 0
        service_state = svc.stdout.strip() or "unknown"

        container_running = False
        container_status_str = None
        if service_active and self.manager.user_exists(self.config):
            podman = self.manager.podman(self.config)
            names = self.config.container_names() if self.config.is_multi else [self.config.container_name]
            statuses = []
            for cname in names:
                status = podman.container_status(
                    f"workload-{self.config.name}-{cname}" if self.config.is_multi else cname
                )
                statuses.append(status)
            # For multi-container workloads, "running" means every named
            # container is up — a partially-down pod is not healthy. For a
            # single container, this collapses to that one's status.
            container_running = bool(statuses) and all(statuses)
            # Surface the first running container's status string for display.
            container_status_str = next((s for s in statuses if s), None)

        healthy = service_active and container_running
        return {
            "service_active": service_active,
            "service_state": service_state,
            "container_running": container_running,
            "container_status": container_status_str,
            "healthy": healthy,
        }

    def resource_usage(
        self,
        target_names: list[str],
        *,
        no_stream: bool = True,
        json_out: bool = False,
        follow: bool = False,
    ):
        podman = self.manager.podman(self.config)
        if json_out:
            # Return the raw result for the caller to parse/print.
            return podman.run(
                "stats", "--no-stream", "--format", "json",
                *target_names, capture_output=True,
            )
        elif follow:
            podman.run("stats", *target_names, check=True)
        else:
            podman.run("stats", "--no-stream", *target_names, check=True)
        return None

    def capture(
        self,
        output: Path,
        *,
        no_stop: bool,
        quiet: bool = False,
    ) -> int:
        return _backup_container(self.config, output, no_stop=no_stop, quiet=quiet)

    # ── step-2 primitives ────────────────────────────────────────────────────

    def gating_units(self) -> list[str]:
        return []

    def exec_command(
        self,
        argv: list[str],
        *,
        container: str | None = None,
    ) -> int:
        from workloadctl_core import resolve_container_target
        target = resolve_container_target(self.config, container, self.config.name)
        result = self.manager.run_podman_exec(
            self.config, [*_interactive_exec_flags(), target, *argv]
        )
        return result.returncode

    def open_shell(
        self,
        *,
        container: str | None = None,
        console: bool = False,
    ) -> None:
        if console:
            raise NotApplicable(
                "containers have no serial console; use 'shell' or 'exec' instead"
            )

        from workloadctl_core import resolve_container_target
        target = resolve_container_target(self.config, container, self.config.name)

        env = self.config.config.get("container", {}).get("environment", {})
        container_user = env.get("CONTAINER_USER")
        container_uid = env.get("CONTAINER_UID")

        exec_opts = _interactive_exec_flags()
        if container_user:
            uid = container_uid or "1000"
            home = f"/home/{container_user}"
            exec_opts.extend([
                "--user", container_user, "--workdir", home,
                "--env", f"HOME={home}",
                "--env", f"XDG_RUNTIME_DIR=/run/user/{uid}",
                "--env", f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
            ])
        elif container_uid:
            exec_opts.extend([
                "--user", container_uid,
                "--env", f"XDG_RUNTIME_DIR=/run/user/{container_uid}",
                "--env", f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{container_uid}/bus",
            ])

        print(f"Opening shell in {target}...")
        print()
        # Try bash first, fall back to sh only if bash isn't available in the image.
        # 127 = command not found; any other non-zero is propagated from the user's
        # last command (e.g. 130 after ^C), not a reason to relaunch.
        result = self.manager.run_podman_exec(self.config, [*exec_opts, target, "/bin/bash"])
        if result.returncode == 127:
            self.manager.run_podman_exec(self.config, [*exec_opts, target, "/bin/sh"], check=True)

    def start(self) -> None:
        from workloadctl_core import restart_workload_service
        # Containers: re-pin /run/user/<uid> and tolerate runtime-dir / start-limit
        # thrash (a bare `systemctl start` doesn't re-run the setup oneshot, so a
        # GC'd runtime dir fails ExecStart with 226/NAMESPACE, and a recycled unit
        # name may carry a start-limit lockout).
        if self.manager.user_exists(self.config):
            try:
                restart_workload_service(
                    self.config.uid, self.config.service_name, action="start"
                )
            except subprocess.CalledProcessError as e:
                sys.exit(e.returncode or 1)
        else:
            result = subprocess.run(["systemctl", "start", self.config.service_name])
            if result.returncode != 0:
                sys.exit(result.returncode)

    def soft_reboot(self) -> None:
        result = self.manager.run_podman_exec(
            self.config,
            [self.config.container_name, "systemctl", "soft-reboot"],
        )
        if result.returncode != 0:
            print("Error: soft-reboot failed. Is this a systemd container?", file=sys.stderr)
            sys.exit(1)
        print(f"✓ Workload '{self.config.name}' soft-rebooted (overlay preserved)")

    def recreate(self) -> None:
        from workloadctl_core import restart_workload_service
        if self.manager.user_exists(self.config):
            restart_workload_service(self.config.uid, self.config.service_name)
        else:
            subprocess.run(
                ["systemctl", "restart", self.config.service_name], check=True
            )

    def reprovision(self, *, force: bool = False):
        from workloadctl_core import restart_workload_service, ensure_runtime_dir
        from podman import PodmanError

        specs = self.config.container_specs()
        if all(pull == "never" for _, _, pull in specs):
            raise NotApplicable(
                f"{self.config.name} uses pull=never (local image) — build it manually"
            )

        print(f"Updating {self.config.name}...")

        if not self.manager.user_exists(self.config):
            print(f"  Skipping: user {self.config.username} does not exist (workload not enabled?)")
            return None

        pod = self.manager.podman(self.config)
        old_ids: dict[str, str] = {}
        changed = False

        for cname, image, pull in specs:
            old_id = pod.image_id(image)
            if not old_id:
                # A just-(re)started rootless store can transiently report an empty
                # inspect even though the image is present — re-pin and retry briefly
                # before giving up.
                ensure_runtime_dir(self.config.uid)
                for _ in range(10):
                    time.sleep(0.5)
                    old_id = pod.image_id(image)
                    if old_id:
                        break
            old_ids[cname] = old_id
            if pull == "never":
                continue
            try:
                pod.pull(image)
            except PodmanError as e:
                print(f"  ✗ Failed to pull {image}: {e.stderr}", file=sys.stderr)
                raise ProvisionFailed(f"pull failed for {image}")
            new_id = pod.image_id(image)
            if old_id != new_id:
                changed = True
                label = (
                    f"{self.config.name}/{cname}" if self.config.is_multi
                    else self.config.name
                )
                print(f"  {label}: {(old_id or 'none')[:12]} → {(new_id or 'unknown')[:12]}")

        if not changed and not force:
            print(f"  ✓ Already up to date")
            return None

        # Tag old images for rollback before restarting
        for cname, image, pull in specs:
            old_id = old_ids.get(cname)
            if old_id:
                pod.tag(
                    old_id,
                    rollback_tag(self.config.name, cname if self.config.is_multi else None),
                )

        restart_workload_service(self.config.uid, self.config.service_name)
        print(f"  ✓ {self.config.name}: restarted")

        return (self.config, old_ids)

    def rollback(self) -> None:
        from workloadctl_core import restart_workload_service
        from podman import PodmanError

        pod = self.manager.podman(self.config)

        plan = []
        have_any_tag = False
        for cname, image in self.config.container_images():
            tag = rollback_tag(
                self.config.name, cname if self.config.is_multi else None
            )
            rollback_id = pod.image_id(tag)
            if not rollback_id:
                continue
            have_any_tag = True
            current_id = pod.image_id(image)
            if current_id == rollback_id:
                continue
            label = (
                f"{self.config.name}/{cname}" if self.config.is_multi
                else self.config.name
            )
            plan.append((label, image, tag, current_id, rollback_id))

        if not have_any_tag:
            print(
                f"Error: No rollback image found for {self.config.name}",
                file=sys.stderr,
            )
            print(
                "  (rollback images are created automatically by 'workloadctl update')",
                file=sys.stderr,
            )
            sys.exit(1)

        if not plan:
            print(f"Already running the rollback image(s) for {self.config.name}")
            return

        for label, image, tag, current_id, rollback_id in plan:
            try:
                pod.tag(tag, image)
            except PodmanError as e:
                print(
                    f"Error: Failed to retag rollback image for {label}: {e.stderr}",
                    file=sys.stderr,
                )
                sys.exit(1)
            print(
                f"  {label}: {current_id[:12] if current_id else 'unknown'} → {rollback_id[:12]}"
            )

        restart_workload_service(self.config.uid, self.config.service_name)
        print(f"✓ Rolled back {self.config.name}")


# ---------------------------------------------------------------------------
# VMSubstrate
# ---------------------------------------------------------------------------

class VMSubstrate(Substrate):
    """Substrate for VM workloads ([vm] section in TOML)."""

    # ── step-1 primitives ────────────────────────────────────────────────────

    def liveness(self) -> dict:
        svc = subprocess.run(
            ["systemctl", "is-active", self.config.service_name],
            capture_output=True, text=True,
        )
        service_active = svc.returncode == 0
        service_state = svc.stdout.strip() or "unknown"
        return {
            "service_active": service_active,
            "service_state": service_state,
            "container_running": None,
            "container_status": None,
            "healthy": service_active,
        }

    def resource_usage(
        self,
        target_names: list[str],
        *,
        no_stream: bool = True,
        json_out: bool = False,
        follow: bool = False,
    ):
        raise NotApplicable(
            "VMs do not expose container-level resource metrics; "
            "check systemd cgroup stats or host monitoring tools instead"
        )

    def capture(
        self,
        output: Path,
        *,
        no_stop: bool,
        quiet: bool = False,
    ) -> int:
        if no_stop:
            print(
                "Error: --no-stop is unsafe for VM workloads. "
                "A live qcow2 copy may be internally inconsistent. "
                "Stop the workload first, or omit --no-stop.",
                file=sys.stderr,
            )
            sys.exit(1)
        return _backup_vm(self.config, output, quiet=quiet)

    # ── step-2 primitives ────────────────────────────────────────────────────

    def gating_units(self) -> list[str]:
        return [
            f"workload-{self.config.name}-setup.service",
            f"workload-{self.config.name}-build.service",
        ]

    def exec_command(
        self,
        argv: list[str],
        *,
        container: str | None = None,
    ) -> int:
        guest_ip = _vm_guest_ip(self.config.name, self.config.vm_bridge)
        if not guest_ip:
            print(
                f"Error: could not determine IP for VM '{self.config.name}'",
                file=sys.stderr,
            )
            print(
                f"  Check {VM_DHCP_LEASE_FILE} or use "
                f"'workloadctl shell {self.config.name}' (console).",
                file=sys.stderr,
            )
            sys.exit(1)
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
                # 255 = ssh transport failure (host unreachable, auth, etc.);
                # anything else came from the remote shell and should propagate.
                if result.returncode != 255:
                    sys.exit(result.returncode)
                print(
                    f"SSH to '{self.config.name}' failed; falling back to serial console.",
                    file=sys.stderr,
                )
            else:
                print(
                    f"No IP found for VM '{self.config.name}'; falling back to serial console.",
                    file=sys.stderr,
                )

        # Connect to the VM serial console via the socat multiplexer.
        console_sock = _vm_console_sock(self.config.name)
        if not console_sock.exists():
            print(f"Error: console socket not found: {console_sock}", file=sys.stderr)
            print(f"Is workload '{self.config.name}' running?", file=sys.stderr)
            sys.exit(1)
        print(f"Connecting to {self.config.name} console (Ctrl-] to disconnect)...")
        print()
        os.execvp(
            "socat",
            ["socat", "STDIO,raw,echo=0,escape=0x1d", f"UNIX-CONNECT:{console_sock}"],
        )
        # execvp replaces the process; unreachable

    def start(self) -> None:
        result = subprocess.run(["systemctl", "start", self.config.service_name])
        if result.returncode != 0:
            sys.exit(result.returncode)

    def soft_reboot(self) -> None:
        guest_ip = _vm_guest_ip(self.config.name, self.config.vm_bridge)
        if not guest_ip:
            print(
                f"Error: could not determine IP for VM '{self.config.name}'",
                file=sys.stderr,
            )
            print(
                f"  Check {VM_DHCP_LEASE_FILE} or use "
                f"'workloadctl shell {self.config.name}' (console).",
                file=sys.stderr,
            )
            sys.exit(1)
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
            print("Error: could not initiate guest soft-reboot.", file=sys.stderr)
            print(
                "  Needs passwordless sudo and systemd 254+ in the guest. To "
                "power-cycle the VM regardless of its init system (disk "
                "preserved), run:",
                file=sys.stderr,
            )
            print(f"    sudo systemctl restart {self.config.service_name}", file=sys.stderr)
            sys.exit(1)
        print(f"✓ VM '{self.config.name}' soft-reboot initiated (disk preserved)")

    def recreate(self) -> None:
        # The cloud-init ISO and nvram are built by the setup oneshot
        # (RemainAfterExit=yes), which a plain main-service restart does NOT
        # re-run. Restart it first so config edits (template_vars, volumes, …)
        # are re-rendered into a fresh seed before QEMU boots onto it.
        subprocess.run(
            ["systemctl", "restart", f"workload-{self.config.name}-setup.service"],
            check=True,
        )
        subprocess.run(["systemctl", "restart", self.config.service_name], check=True)

    def reprovision(self, *, force: bool = False):
        print(f"Updating VM workload {self.config.name}...")
        result = subprocess.run(
            [
                "/usr/libexec/workloadctl/workload-vm-build-disk",
                self.config.name, "--update",
            ],
            check=False,
        )
        if result.returncode != 0:
            print(f"  ✗ Disk rebuild failed for {self.config.name}", file=sys.stderr)
            raise ProvisionFailed(f"disk rebuild failed for {self.config.name}")
        restart = subprocess.run(
            ["systemctl", "restart", self.config.service_name], check=False
        )
        if restart.returncode != 0:
            print(f"  ✗ Restart failed for {self.config.name}", file=sys.stderr)
            raise ProvisionFailed(f"restart failed for {self.config.name}")
        print(f"  ✓ {self.config.name}: rebuilt and restarted")
        return None  # no verification phase for VMs

    def rollback(self) -> None:
        home_dir = self.config.home_dir
        system_disk = home_dir / "system.qcow2"
        gens = sorted(
            int(p.suffix[5:])
            for p in home_dir.glob("system.qcow2.gen-*")
            if p.suffix[5:].isdigit()
        )
        if not gens:
            print(
                f"Error: No rollback generation found for VM '{self.config.name}'",
                file=sys.stderr,
            )
            print(
                "  (generations are created automatically by 'workloadctl update')",
                file=sys.stderr,
            )
            sys.exit(1)
        latest_gen = max(gens)
        gen_path = home_dir / f"system.qcow2.gen-{latest_gen}"
        print(f"Rolling back VM '{self.config.name}':")
        print(f"  system.qcow2.gen-{latest_gen} → system.qcow2")
        # Stop the VM before swapping disks: QEMU holds the active qcow2 open,
        # and renaming a file out from under it leaves the running guest writing
        # to an unlinked inode while the new disk is mounted by the next start.
        subprocess.run(["systemctl", "stop", self.config.service_name], check=False)
        gen_path.replace(system_disk)
        subprocess.run(["systemctl", "start", self.config.service_name], check=True)
        print(f"✓ Rolled back {self.config.name} to generation {latest_gen}")


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

def get_substrate(config, manager) -> Substrate:
    """Resolve the Substrate implementation from the workload declaration."""
    if config.is_vm:
        return VMSubstrate(config, manager)
    return ContainerSubstrate(config, manager)


# ---------------------------------------------------------------------------
# Shared backup helpers
# ---------------------------------------------------------------------------

# Credentials directory (matches workload-ensure-user)
CREDSTORE_DIR = Path("/etc/credstore")

# Pattern for image-store exclude (shared with cmd_backup)
def _ignore_image_store(base_dir):
    target_parent = Path(base_dir) / ".local" / "share"
    def _ignore(src_dir, contents):
        if Path(src_dir) == target_parent:
            return {"containers"} & set(contents)
        return set()
    return _ignore


# VM rebuild artifacts that should not be backed up (they are regenerated
# by workload-vm-build-disk on next enable/update).
# Each entry is either an exact basename or a suffix matched with endswith().
# Prefix matches (e.g. "system.qcow2.gen-") use the "startswith:" convention.
_VM_REBUILD_PATTERNS = (
    "system.qcow2",            # exact
    "startswith:system.qcow2.gen-",
    "endswith:.image-cache",
)


def _ignore_vm_rebuild(base_dir):
    """copytree ignore callable that skips VM rebuild artifacts."""
    base = Path(base_dir)
    def _ignore(src_dir, contents):
        if Path(src_dir) != base:
            return set()
        skip = set()
        for name in contents:
            for pat in _VM_REBUILD_PATTERNS:
                if pat.startswith("startswith:") and name.startswith(pat[len("startswith:"):]):
                    skip.add(name)
                elif pat.startswith("endswith:") and name.endswith(pat[len("endswith:"):]):
                    skip.add(name)
                elif name == pat:
                    skip.add(name)
        return skip
    return _ignore


def _backup_container(config, output: Path, *, no_stop: bool, quiet: bool) -> int:
    """Backup a container workload.  Returns archive size in bytes."""
    _backup_impl(config, output, no_stop=no_stop, quiet=quiet, vm=False)
    size = output.stat().st_size
    if not quiet:
        _print_backup_size(output, size)
    return size


def _backup_vm(config, output: Path, *, quiet: bool) -> int:
    """Backup a VM workload (always stopped).  Returns archive size in bytes."""
    _backup_impl(config, output, no_stop=False, quiet=quiet, vm=True)
    size = output.stat().st_size
    if not quiet:
        _print_backup_size(output, size)
    return size


def _backup_impl(config, output: Path, *, no_stop: bool, quiet: bool, vm: bool) -> None:
    """Internal backup implementation shared by container and VM paths."""
    from workload_lib import WORKLOAD_CONFIG_DIR
    workload_dir = WORKLOAD_CONFIG_DIR
    name = config.name
    home_dir = config.home_dir
    config_path = workload_dir / f"{name}.toml"
    service_name = config.service_name

    service_was_active = subprocess.run(
        ["systemctl", "is-active", "--quiet", service_name],
    ).returncode == 0

    if service_was_active and not no_stop:
        if not quiet:
            print(f"  Stopping {service_name}...")
        subprocess.run(["systemctl", "stop", service_name], check=True)

    try:
        with tempfile.TemporaryDirectory() as staging:
            staging = Path(staging)

            shutil.copy2(config_path, staging / "workload.toml")

            creds = auto_detect_credentials(config.config)
            if creds:
                cred_dir = staging / "credentials"
                cred_dir.mkdir()
                for cred_name in sorted(creds):
                    cred_path = CREDSTORE_DIR / cred_name
                    if cred_path.exists():
                        shutil.copy2(cred_path, cred_dir / cred_path.name)
                    elif not quiet:
                        print(f"  Warning: Credential '{cred_name}' not found, skipping")

            if home_dir.is_dir():
                if vm:
                    ignore = _ignore_vm_rebuild(home_dir)
                else:
                    ignore = _ignore_image_store(home_dir)
                shutil.copytree(
                    home_dir, staging / "home",
                    symlinks=True, dirs_exist_ok=False,
                    ignore=ignore,
                )
            else:
                (staging / "home").mkdir()

            output.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["tar", "-C", str(staging), "-cf", str(output), "--zstd", "."],
                check=True,
            )
    finally:
        if service_was_active and not no_stop:
            if not quiet:
                print(f"  Starting {service_name}...")
            # Containers: re-pin the runtime dir and tolerate start-limit thrash
            # when bringing the workload back up after the cold-backup stop.
            # VMs have no /run/user/<uid>, so start them plainly.
            if vm:
                subprocess.run(["systemctl", "start", service_name])
            else:
                from workloadctl_core import restart_workload_service
                try:
                    restart_workload_service(config.uid, service_name, action="start")
                except subprocess.CalledProcessError:
                    pass


def _print_backup_size(output: Path, size: int) -> None:
    if size >= 1_000_000_000:
        size_str = f"{size / 1_000_000_000:.1f}G"
    elif size >= 1_000_000:
        size_str = f"{size / 1_000_000:.1f}M"
    elif size >= 1_000:
        size_str = f"{size / 1_000:.1f}K"
    else:
        size_str = f"{size}B"
    print(f"  Backup: {output} ({size_str})")
