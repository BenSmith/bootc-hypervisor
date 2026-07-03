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

Capability matrix
-----------------
Optional primitives have a base-class default. ``resource_usage`` and
``endpoints`` default to raising ``NotApplicable`` with a hand-written
reason; a concrete substrate that supports one overrides the method
directly. ``logs`` defaults to running the given journalctl argv (both
substrates' service journals land on the host journal), so it's optional
in the sense that a substrate *may* override it, not that it's normally
unsupported. ``reprovision`` is always overridden by both concrete
substrates (each has its own not-applicable conditions), so the base
implementation exists only as a documented contract.

Required primitives (always present, ``@abstractmethod``):
    liveness, gating_units, capture, exec, open_shell, lifecycle,
    rollback_targets, rollback_to

Optional primitives (base-class default, override to support):
    resource_usage, logs, endpoints, reprovision
"""

from __future__ import annotations

import datetime
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
    CREDSTORE_DIR,
    QMPClient,
    VM_BRIDGE_NAME,
    VM_DHCP_LEASE_FILE,
    VM_SOCKET_DIR,
    vm_mac_address,
    workload_service_units,
)
from service_runtime import ensure_runtime_dir, restart_workload_service


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


class BackupError(Exception):
    """Raised by capture() when a backup cannot be completed safely.

    Same contract as ProvisionFailed: the substrate method prints the
    diagnostic, then raises this so the caller can isolate the failure
    per-workload (a single bad workload must not abort a --all run) and
    exit nonzero at the end.
    """


class LifecycleError(Exception):
    """Raised by lifecycle() when a start/stop/restart/reboot step fails.

    Carries the returncode the caller should exit with — mirrors the exact
    exit code of the systemctl/podman invocation that failed, so the CLI
    layer's ``sys.exit(e.returncode)`` reproduces the pre-exception behavior
    of exiting directly from library code.
    """
    def __init__(self, returncode: int):
        self.returncode = returncode
        super().__init__(f"lifecycle action failed (exit {returncode})")


# ---------------------------------------------------------------------------
# Shared liveness primitive
# ---------------------------------------------------------------------------

def service_active(unit: str) -> tuple[bool, str]:
    """`systemctl is-active` for one unit, as (active, state).

    active — True iff systemctl exits 0. state — the raw is-active word it
    prints ('active' / 'inactive' / 'failed' / 'activating' / …), or '' when
    it prints nothing. This single call was hand-copied across every
    health/liveness/diagnose path; callers apply their own empty-state default
    ('unknown' for display, bare '' for diagnose's message).
    """
    r = subprocess.run(
        ["systemctl", "is-active", unit], capture_output=True, text=True
    )
    return r.returncode == 0, r.stdout.strip()


# ---------------------------------------------------------------------------
# VM infrastructure helpers
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

# ---------------------------------------------------------------------------
# Endpoint helpers (shared by ContainerSubstrate.endpoints() and cmd_inspect)
# ---------------------------------------------------------------------------

def _accessible_at_config(config) -> list:
    """Compute accessible host:port → container:port endpoint list from TOML ports.

    Returns a list of dicts with keys ``host`` (display string) and
    ``container`` (container port string or None for host-network workloads).
    """
    ports = config.get_ports()
    network_mode = config.get_network_mode()
    result: list[dict] = []
    if not ports:
        return result
    if network_mode == "host":
        for port_spec in ports:
            port = port_spec.split(":")[-1].split("/")[0]
            result.append({"host": f"localhost:{port}", "container": None})
    else:
        for port_spec in ports:
            parts = port_spec.split("/")[0].split(":")
            if len(parts) == 3:
                ip, host_port, container_port = parts
                host = ip or "localhost"
                host_disp = f"{host}:{host_port}" if host_port else f"{host}:(dynamic)"
                result.append({"host": host_disp, "container": container_port})
            elif len(parts) == 2:
                host_port, container_port = parts
                host_disp = f"localhost:{host_port}" if host_port else "localhost:(dynamic)"
                result.append({"host": host_disp, "container": container_port})
            else:
                result.append({"host": f"localhost:{parts[0]}", "container": None})
    return result


class Substrate(ABC):
    """Per-substrate primitive port (step-3 narrow waist).

    All substrate-variant verbs delegate their substrate-specific delta here.
    Substrate-invariant verbs (create, list, validate, secret, …) bypass
    this layer entirely.

    Required primitives (abstract, always present):
        liveness, gating_units, capture, exec, open_shell,
        lifecycle, rollback_targets, rollback_to, control

    Optional primitives (base-class default; override to support):
        resource_usage, logs, endpoints, reprovision
    """

    def __init__(self, config, manager):
        self.config = config
        self.manager = manager

    # ── required primitives (abstract) ───────────────────────────────────────

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
    def capture(
        self,
        output: Path,
        *,
        consistency: str = "cold",
        quiet: bool = False,
    ) -> int:
        """Create a backup archive.  Returns archive size in bytes.

        consistency: "cold" — stop service, copy, restart (always safe, default).
                     "crash" — live copy without stopping service.
                       Containers: copy while running (old --no-stop path).
                       VMs: pause vCPUs via QMP, copy, resume (crash-consistent).
        """
        ...

    @abstractmethod
    def gating_units(self) -> list[str]:
        """Systemd units that must succeed before the main service starts.

        Empty for container substrates: their setup unit is a hard
        Requires=/After= dependency of the main service, so a setup failure
        already surfaces as the main unit's own dependency failure. VMs use
        separate RemainAfterExit=yes setup and build units whose failure would
        otherwise hide behind a bland 'inactive' on the main service, so they
        are reported explicitly.
        """
        ...

    @abstractmethod
    def exec(
        self,
        argv: list[str],
        *,
        container: str | None = None,
    ) -> int:
        """Execute a command inside the workload.  Returns the exit code.

        For VMs: runs via SSH into the guest.
        For containers: runs via ``podman exec`` into the named (or default) container.
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
        For containers: ``podman exec`` into the named (or default) container.
        """
        ...

    @abstractmethod
    def lifecycle(self, action: str) -> None:
        """Unified lifecycle primitive: start / stop / restart / reboot.

        action must be one of: ``"start"``, ``"stop"``, ``"restart"``,
        ``"reboot"`` (soft-reboot the workload's init system).
        """
        ...

    @abstractmethod
    def rollback_targets(self) -> list:
        """Enumerate available rollback targets.

        Containers: list of ``{"label": ..., "tag": ..., "id": ...}`` dicts
            (one per container with a saved rollback image).
        VMs: list of ``{"label": ..., "gen": N, "path": ...}`` dicts
            (one per ``system.qcow2.gen-N`` snapshot found).

        Returns an empty list when no rollback is available.
        """
        ...

    @abstractmethod
    def rollback_to(self, target) -> None:
        """Apply a single rollback target returned by ``rollback_targets()``.

        For containers: retag the saved rollback image as the working image.
        For VMs: stop the VM, swap in the generation snapshot, restart.
        """
        ...

    @abstractmethod
    def rollback(self) -> None:
        """Roll back to the most recent rollback target and restart.

        Convenience over ``rollback_to(rollback_targets()[...])`` for the
        common "undo the last update" case.
        """
        ...

    @abstractmethod
    def control(self, argv: list[str]) -> int:
        """Send a raw command to the workload's runtime control plane.

        This is the ``incant`` escape hatch — it reaches the *manager* of the
        runtime (podman for containers, the QEMU monitor for VMs), not the
        workload interior.  The fiddly invocation (sudo env, QMP framing) is
        supplied automatically so callers never hand-build it.

        For containers: runs ``podman <argv>`` as ``_wl-<name>`` via the
            existing rootless-podman wrapper (correct XDG_RUNTIME_DIR/HOME).
        For VMs: sends the first token of ``argv`` as a QMP command name to
            the QEMU monitor (qmp.sock), with remaining ``key=value`` tokens
            parsed as command arguments.  Prints the JSON reply.

        Returns an exit code (0 on success).
        """
        ...

    # ── optional primitives (base default; override to support) ──────────────

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
        substrate_kind = "VMs" if self.config.is_vm else "containers"
        raise NotApplicable(
            f"resource_usage: not applicable for {substrate_kind} "
            f"(no resource_usage primitive)"
        )

    def logs(self, cmd_parts: list[str]) -> None:
        """Stream workload logs using the given journalctl argv.

        ``cmd_parts`` is the full ``journalctl`` command list already built by
        ``cmd_logs``.  Both substrates' service journals land on the host journal
        (a container's service *and* the VM's QEMU unit), so the default runs the
        command directly; a substrate only overrides this if it needs a wrapper.
        """
        subprocess.run(cmd_parts)

    def endpoints(self) -> list:
        """Return the list of host-accessible endpoint dicts for this workload.

        Each dict has at least ``{"host": "<host>:<port>", "container": <port or None>}``.
        Returns an empty list when no ports are published.

        Raises NotApplicable if the substrate cannot determine endpoints.
        """
        substrate_kind = "VMs" if self.config.is_vm else "containers"
        raise NotApplicable(
            f"endpoints: not applicable for {substrate_kind} "
            f"(no endpoints primitive)"
        )

    def reprovision(self, *, force: bool = False, recreate: bool = False):
        """Update / reprovision the workload to its latest version.

        Container substrates: pull image(s) and restart if any changed.
        Returns (config, old_ids) if an update was applied (so the caller can
        run the post-update verification+rollback phase), or None if already
        up to date.  Raises NotApplicable if all containers have pull=never.
        Raises ProvisionFailed if a pull or restart step fails.

        When ``recreate=True``: skip the pull phase, destroy and restart using
        the current image (containers: restart service to recreate overlay;
        VMs: re-render cloud-init seed and restart QEMU).

        VM substrates: rebuild the system disk and restart.  Returns None
        (no verification phase).  Raises ProvisionFailed on build/restart error.
        """
        # Both concrete substrates override this with their own
        # not-applicable conditions (e.g. pull=never); reaching the base
        # implementation is a programming error, not a runtime condition.
        raise NotImplementedError(f"{type(self).__name__} must override reprovision()")


# ---------------------------------------------------------------------------
# ContainerSubstrate
# ---------------------------------------------------------------------------

class ContainerSubstrate(Substrate):
    """Substrate for single / pod / bridge container workloads.

    Implements the optional primitives resource_usage, endpoints,
    reprovision (see the overrides below); logs uses the base default.
    """

    # ── required primitives ───────────────────────────────────────────────────

    def liveness(self) -> dict:
        active, state = service_active(self.config.service_name)
        service_state = state or "unknown"

        container_running = False
        container_status_str = None
        if active and self.manager.user_exists(self.config):
            podman = self.manager.podman(self.config)
            names = self.config.podman_targets()
            statuses = []
            for cname in names:
                status = podman.container_status(cname)
                statuses.append(status)
            # For multi-container workloads, "running" means every named
            # container is up — a partially-down pod is not healthy. For a
            # single container, this collapses to that one's status.
            container_running = bool(statuses) and all(statuses)
            # Surface the first running container's status string for display.
            container_status_str = next((s for s in statuses if s), None)

        healthy = active and container_running
        return {
            "service_active": active,
            "service_state": service_state,
            "container_running": container_running,
            "container_status": container_status_str,
            "healthy": healthy,
        }

    def container_liveness(self) -> list[dict]:
        """Per-container liveness rows in container_names() order.

        Each row: ``{container, podman_name, unit, service_active,
        service_state, status, running, healthy}``. Single-container workloads
        yield one row keyed on the main service and the bare container name;
        multi-container yield one row per member with its own
        ``workload-<name>-<ctr>.service`` unit. The running check needs the
        rootless podman store, so an absent workload user leaves every row
        not-running. This is the single source the per-container health and
        diagnose paths consume instead of re-deriving the name/unit math.
        """
        name = self.config.name
        if self.config.is_multi:
            rows_meta = [
                (c, self.config.podman_container_name(c),
                 f"workload-{name}-{c}.service")
                for c in self.config.container_names()
            ]
        else:
            rows_meta = [
                (name, self.config.container_name, self.config.service_name)
            ]

        podman = None
        if self.manager.user_exists(self.config):
            podman = self.manager.podman(self.config)

        rows = []
        for cname, podman_name, unit in rows_meta:
            active, state = service_active(unit)
            status = podman.container_status(podman_name) if podman else None
            running = bool(status)
            rows.append({
                "container": cname,
                "podman_name": podman_name,
                "unit": unit,
                "service_active": active,
                "service_state": state or "unknown",
                "status": status,
                "running": running,
                "healthy": active and running,
            })
        return rows

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
        consistency: str = "cold",
        quiet: bool = False,
    ) -> int:
        # cold → stop service before copy; crash → copy while running (no stop).
        no_stop = consistency == "crash"
        return _backup_container(self.config, output, no_stop=no_stop, quiet=quiet)

    # ── backup primitives ─────────────────────────────────────────────────────

    def gating_units(self) -> list[str]:
        return []

    def exec(
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

    def lifecycle(self, action: str) -> None:
        """Unified lifecycle for containers: start / stop / restart / reboot."""
        if action == "start":
            # Re-pin /run/user/<uid> and tolerate runtime-dir / start-limit
            # thrash (a bare `systemctl start` doesn't re-run the setup oneshot,
            # so a GC'd runtime dir fails ExecStart with 226/NAMESPACE, and a
            # recycled unit name may carry a start-limit lockout).
            if self.manager.user_exists(self.config):
                try:
                    restart_workload_service(
                        self.config.uid, self.config.service_name, action="start"
                    )
                except subprocess.CalledProcessError as e:
                    raise LifecycleError(e.returncode or 1)
            else:
                result = subprocess.run(["systemctl", "start", self.config.service_name])
                if result.returncode != 0:
                    raise LifecycleError(result.returncode)
        elif action == "stop":
            result = subprocess.run(["systemctl", "stop", self.config.service_name])
            if result.returncode != 0:
                raise LifecycleError(result.returncode)
        elif action == "restart":
            if self.manager.user_exists(self.config):
                restart_workload_service(self.config.uid, self.config.service_name)
            else:
                subprocess.run(
                    ["systemctl", "restart", self.config.service_name], check=True
                )
        elif action == "reboot":
            result = self.manager.run_podman_exec(
                self.config,
                [self.config.container_name, "systemctl", "soft-reboot"],
            )
            if result.returncode != 0:
                print("Error: soft-reboot failed. Is this a systemd container?", file=sys.stderr)
                raise LifecycleError(1)
            print(f"✓ Workload '{self.config.name}' soft-rebooted (overlay preserved)")
        else:
            raise ValueError(f"Unknown lifecycle action: {action!r}")

    def endpoints(self) -> list:
        """Return published port endpoints from the TOML declaration."""
        return _accessible_at_config(self.config)

    def _pet_snapshot_and_remove(self, pod, container_name: str) -> None:
        """Commit the pet container's overlay to a timestamped local snapshot,
        then remove the container so the next start rebuilds it from the image.

        The snapshot is saved under ``localhost/workload-snapshot/<name>`` with
        a UTC-timestamp tag so it is easy to identify and prune manually.
        A failure to commit (e.g. container not running / never started) is
        non-fatal — we log and continue so the destroy still proceeds.
        """
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        repo = f"localhost/workload-snapshot/{self.config.name}"
        snapshot_ref = f"{repo}:{ts}"
        committed = False
        try:
            pod.commit(container_name, snapshot_ref)
            committed = True
            print(f"  ✓ Pet snapshot saved: {snapshot_ref}")
        except Exception as exc:
            print(
                f"  ⚠ Pet snapshot failed (overlay may not exist yet): {exc}",
                file=sys.stderr,
            )
        # Bound the snapshot repository so deliberate rebuilds don't leak disk
        # forever (the VM path has rollback_keep; pets had no analog). Only
        # prune after a fresh commit succeeded — nothing new was added otherwise.
        if committed:
            self._prune_pet_snapshots(pod, repo, self.config.snapshot_keep)
        # Remove the container so the service's ExecStartPre=-podman create
        # runs fresh on next start, picking up the (possibly new) image.
        pod.run("rm", "-f", container_name)

    @staticmethod
    def _prune_pet_snapshots(pod, repo: str, keep: int) -> None:
        """Keep only the newest ``keep`` snapshots under ``repo``, remove the rest.

        Snapshot tags are UTC timestamps (``%Y%m%dT%H%M%SZ``) which sort
        lexicographically in chronological order, so the lexically largest tags
        are the most recent. Best-effort: every failure here is logged and
        swallowed so pruning can never block the destroy it follows.
        """
        try:
            listed = pod.run(
                "images", "--format", "{{.Tag}}", repo, capture_output=True,
            )
            if listed.returncode != 0:
                return
            tags = sorted(t for t in listed.stdout.split() if t)
            stale = tags[:-keep] if len(tags) > keep else []
            for tag in stale:
                ref = f"{repo}:{tag}"
                removed = pod.run("rmi", ref, capture_output=True)
                if removed.returncode == 0:
                    print(f"  ✓ Pruned old pet snapshot: {ref}")
        except Exception as exc:
            print(f"  ⚠ Pet snapshot prune skipped: {exc}", file=sys.stderr)

    def reprovision(self, *, force: bool = False, recreate: bool = False):
        from podman import PodmanError

        if recreate:
            # recreate path: skip pull, just restart to recreate the overlay.
            print(f"Recreating {self.config.name}...")
            # pet honoring is single-mode only — the generator falls back to
            # cattle units for pod/bridge, so the substrate must too (otherwise
            # we'd commit/rm a container name that doesn't exist for multi).
            if (self.config.lifecycle == "pet" and not self.config.is_multi
                    and self.manager.user_exists(self.config)):
                # For pet: snapshot the overlay then remove the container so the
                # next start re-creates it from the image.
                pod = self.manager.podman(self.config)
                self._pet_snapshot_and_remove(pod, self.config.container_name)
            if self.manager.user_exists(self.config):
                restart_workload_service(self.config.uid, self.config.service_name)
            else:
                subprocess.run(
                    ["systemctl", "restart", self.config.service_name], check=True
                )
            return None

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
            print("  ✓ Already up to date")
            return None

        # Tag old images for rollback before restarting
        for cname, image, pull in specs:
            old_id = old_ids.get(cname)
            if old_id:
                pod.tag(
                    old_id,
                    rollback_tag(self.config.name, cname if self.config.is_multi else None),
                )

        if self.config.lifecycle == "pet" and not self.config.is_multi:
            # Snapshot and remove the pet container so the restart picks up the
            # new image (ExecStartPre=-podman create rebuilds from the new pull).
            # Single-mode only, matching the generator's pet fallback.
            self._pet_snapshot_and_remove(pod, self.config.container_name)

        restart_workload_service(self.config.uid, self.config.service_name)
        print(f"  ✓ {self.config.name}: restarted")

        return (self.config, old_ids)

    def rollback_targets(self) -> list:
        """Return available container rollback targets (saved image tags)."""
        pod = self.manager.podman(self.config)
        targets = []
        for cname, image in self.config.container_images():
            tag = rollback_tag(
                self.config.name, cname if self.config.is_multi else None
            )
            rollback_id = pod.image_id(tag)
            if not rollback_id:
                continue
            current_id = pod.image_id(image)
            label = (
                f"{self.config.name}/{cname}" if self.config.is_multi
                else self.config.name
            )
            targets.append({
                "label": label,
                "tag": tag,
                "image": image,
                "current_id": current_id,
                "rollback_id": rollback_id,
            })
        return targets

    def rollback_to(self, target: dict) -> None:
        """Apply a single rollback target from rollback_targets()."""
        from podman import PodmanError
        pod = self.manager.podman(self.config)
        try:
            pod.tag(target["tag"], target["image"])
        except PodmanError as e:
            print(
                f"Error: Failed to retag rollback image for {target['label']}: {e.stderr}",
                file=sys.stderr,
            )
            raise LifecycleError(1)
        current_id = target.get("current_id")
        rollback_id = target["rollback_id"]
        print(
            f"  {target['label']}: {current_id[:12] if current_id else 'unknown'} → {rollback_id[:12]}"
        )

    def rollback(self) -> None:
        """Roll back all containers to their previous images and restart."""

        targets = self.rollback_targets()
        have_any_tag = bool(targets) or self._has_any_rollback_tag()

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

        if not targets:
            print(f"Already running the rollback image(s) for {self.config.name}")
            return

        for target in targets:
            self.rollback_to(target)

        restart_workload_service(self.config.uid, self.config.service_name)
        print(f"✓ Rolled back {self.config.name}")

    def control(self, argv: list[str]) -> int:
        """Run ``podman <argv>`` as the workload user via the rootless wrapper."""
        result = self.manager.run_podman(self.config, *argv)
        return result.returncode

    def _has_any_rollback_tag(self) -> bool:
        """Return True if any rollback tag exists (even if already applied)."""
        pod = self.manager.podman(self.config)
        for cname, _image in self.config.container_images():
            tag = rollback_tag(
                self.config.name, cname if self.config.is_multi else None
            )
            if pod.image_id(tag):
                return True
        return False


# ---------------------------------------------------------------------------
# VMSubstrate
# ---------------------------------------------------------------------------

class VMSubstrate(Substrate):
    """Substrate for VM workloads ([vm] section in TOML).

    Overrides reprovision (see below); resource_usage and endpoints use the
    base-class NotApplicable defaults (VMs implement neither), and logs uses
    the base default (the VM's QEMU service journal is on the host journal).
    """

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

    # resource_usage, logs, endpoints: inherited base auto-raises NotApplicable.

    def capture(
        self,
        output: Path,
        *,
        consistency: str = "cold",
        quiet: bool = False,
    ) -> int:
        if consistency == "crash":
            return _backup_vm_crash(self.config, output, quiet=quiet)
        # cold (default) — stop service, copy, restart.
        return _backup_vm(self.config, output, quiet=quiet)

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

    def lifecycle(self, action: str) -> None:
        """Unified lifecycle for VMs: start / stop / restart / reboot."""
        if action == "start":
            result = subprocess.run(["systemctl", "start", self.config.service_name])
            if result.returncode != 0:
                sys.exit(result.returncode)
        elif action == "stop":
            result = subprocess.run(["systemctl", "stop", self.config.service_name])
            if result.returncode != 0:
                sys.exit(result.returncode)
        elif action == "restart":
            # recreate: re-render cloud-init seed then restart QEMU.
            # The cloud-init ISO and nvram are built by the setup oneshot
            # (RemainAfterExit=yes), which a plain main-service restart does NOT
            # re-run. Restart it first so config edits (template_vars, volumes, …)
            # are re-rendered into a fresh seed before QEMU boots onto it.
            subprocess.run(
                ["systemctl", "restart", f"workload-{self.config.name}-setup.service"],
                check=True,
            )
            subprocess.run(["systemctl", "restart", self.config.service_name], check=True)
        elif action == "reboot":
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
        else:
            raise ValueError(f"Unknown lifecycle action: {action!r}")

    def reprovision(self, *, force: bool = False, recreate: bool = False):
        if recreate:
            # recreate path: re-render cloud-init seed and restart QEMU.
            # For pet VMs this is safe — it does not touch system.qcow2.
            print(f"Recreating VM workload {self.config.name}...")
            subprocess.run(
                ["systemctl", "restart", f"workload-{self.config.name}-setup.service"],
                check=True,
            )
            subprocess.run(["systemctl", "restart", self.config.service_name], check=True)
            return None

        if self.config.lifecycle == "pet":
            # Pet VMs: do not rebuild or rotate system.qcow2 — the durable disk
            # is preserved.  Only restart QEMU so config-level changes (e.g.
            # memory, cpu) in the unit file are picked up.
            print(
                f"  ℹ {self.config.name} is a pet VM — skipping system disk rebuild "
                f"and generation rotation to preserve durable disk."
            )
            restart = subprocess.run(
                ["systemctl", "restart", self.config.service_name], check=False
            )
            if restart.returncode != 0:
                print(f"  ✗ Restart failed for {self.config.name}", file=sys.stderr)
                raise ProvisionFailed(f"restart failed for {self.config.name}")
            print(f"  ✓ {self.config.name}: restarted (disk unchanged)")
            return None

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

    def rollback_targets(self) -> list:
        """Return available VM rollback targets (system.qcow2.gen-N snapshots)."""
        home_dir = self.config.home_dir
        gens = sorted(
            int(p.suffix[5:])
            for p in home_dir.glob("system.qcow2.gen-*")
            if p.suffix[5:].isdigit()
        )
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
        gens = sorted(
            int(p.suffix[5:])
            for p in home_dir.glob("system.qcow2.gen-*")
            if p.suffix[5:].isdigit() and int(p.suffix[5:]) != exempt
        )
        for gen_n in (gens[:-keep] if len(gens) > keep else []):
            print(f"  Pruning old generation: system.qcow2.gen-{gen_n}")
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
        print(f"Rolling back VM '{self.config.name}':")
        # Stop the VM before swapping disks: QEMU holds the active qcow2 open,
        # and renaming a file out from under it leaves the running guest writing
        # to an unlinked inode while the new disk is mounted by the next start.
        subprocess.run(["systemctl", "stop", self.config.service_name], check=False)
        # Rotate the current disk out to a fresh generation (highest number =
        # newest) so rolling back is itself reversible.
        rotated_gen = None
        if system_disk.exists():
            existing = [
                int(p.suffix[5:])
                for p in home_dir.glob("system.qcow2.gen-*")
                if p.suffix[5:].isdigit()
            ]
            rotated_gen = (max(existing) + 1) if existing else 1
            rotated = home_dir / f"system.qcow2.gen-{rotated_gen}"
            print(f"  system.qcow2 → {rotated.name} (pre-rollback state preserved)")
            system_disk.rename(rotated)
        print(f"  system.qcow2.gen-{gen} → system.qcow2")
        gen_path.replace(system_disk)
        if rotated_gen is not None:
            self._prune_generations(home_dir, rollback_keep, exempt=rotated_gen)
        subprocess.run(["systemctl", "start", self.config.service_name], check=True)
        print(f"✓ Rolled back {self.config.name} to generation {gen}")

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
            print(
                f"Error: VM '{self.config.name}' is a pet — system.qcow2 is never "
                f"rotated, so there are no generation snapshots to roll back to.",
                file=sys.stderr,
            )
            print(
                "  Use 'workloadctl update' to restart the VM without touching the disk.",
                file=sys.stderr,
            )
            sys.exit(1)
        targets = self.rollback_targets()
        if not targets:
            print(
                f"Error: No rollback generation found for VM '{self.config.name}'",
                file=sys.stderr,
            )
            print(
                "  (generations are created automatically by 'workloadctl update')",
                file=sys.stderr,
            )
            sys.exit(1)
        # Apply the most recent (highest generation number) snapshot.
        latest = targets[-1]
        self.rollback_to(latest)


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


def _backup_vm_crash(config, output: Path, *, quiet: bool) -> int:
    """Crash-consistent VM backup: pause vCPUs via QMP, copy, resume.

    If the VM service is not active, falls back to the cold copy (nothing to
    pause).  If QMP is unreachable, errors clearly rather than copying an
    unpaused live disk — a copy of an unpaused qcow2 is torn and not safe.

    The vCPUs are paused for the entire copy duration (simple first cut).
    A future improvement would use QMP 'drive-backup' / 'blockdev-backup' to
    issue a copy-on-write snapshot job so the pause window is just the initial
    COW setup, not the full copy — see docs/ideas.md for the drive-backup
    follow-up.

    RESUME SAFETY: the QMP 'cont' command is issued in a finally block so
    a failed or interrupted copy never leaves the guest permanently paused.
    """
    service_name = config.service_name
    service_was_active = subprocess.run(
        ["systemctl", "is-active", "--quiet", service_name],
    ).returncode == 0

    if not service_was_active:
        # Nothing running — fall back to cold copy (identical result, no QMP
        # needed).
        if not quiet:
            print(f"  VM '{config.name}' is not active; using cold backup path.")
        return _backup_vm(config, output, quiet=quiet)

    # VM is running — pause vCPUs, copy durable disk + home, then resume.
    sock_path = VM_SOCKET_DIR / config.name / "qmp.sock"
    if not sock_path.exists():
        print(
            f"Error: QMP socket not found at {sock_path}. "
            f"Cannot safely copy a live qcow2 without pausing vCPUs. "
            f"Use --consistency cold to stop the VM first.",
            file=sys.stderr,
        )
        raise BackupError(f"QMP socket not found for VM '{config.name}'")

    qmp = QMPClient()
    # The outer finally guarantees qmp.close() on every exit path — including a
    # failure in negotiate() after connect() already opened the socket — so an
    # error here can't leak the descriptor.
    try:
        try:
            qmp.connect(str(sock_path))
            qmp.negotiate()
        except (OSError, ValueError) as exc:
            # TimeoutError/ConnectionError are OSError subclasses; ValueError
            # covers a malformed JSON greeting from the monitor.
            print(
                f"Error: Could not connect to QMP for VM '{config.name}': {exc}. "
                f"Cannot safely copy a live qcow2 without pausing vCPUs. "
                f"Use --consistency cold to stop the VM first.",
                file=sys.stderr,
            )
            raise BackupError(f"QMP unreachable for VM '{config.name}': {exc}")

        if not quiet:
            print(f"  Pausing vCPUs for '{config.name}'...")
        try:
            stop_reply = qmp.execute("stop")
        except (OSError, ValueError) as exc:
            # A protocol/socket fault here means the vCPUs were never paused, so
            # there is nothing to resume — fail the backup cleanly.
            print(
                f"Error: QMP 'stop' failed for VM '{config.name}': {exc}. "
                f"Use --consistency cold to stop the VM first.",
                file=sys.stderr,
            )
            raise BackupError(f"QMP 'stop' failed for VM '{config.name}': {exc}")
        if "error" in stop_reply:
            print(
                f"Error: QMP 'stop' failed for VM '{config.name}': {stop_reply['error']}. "
                f"Use --consistency cold to stop the VM first.",
                file=sys.stderr,
            )
            raise BackupError(
                f"QMP 'stop' failed for VM '{config.name}': {stop_reply['error']}"
            )

        try:
            # no_stop=True: copy durable disk + home WITHOUT stopping the
            # systemd service (vCPUs are already paused by QMP above).
            _backup_impl(config, output, no_stop=True, quiet=quiet, vm=True)
        finally:
            # CRITICAL: always resume vCPUs, even if the copy raised.
            if not quiet:
                print(f"  Resuming vCPUs for '{config.name}'...")
            try:
                cont_reply = qmp.execute("cont")
                if "error" in cont_reply:
                    print(
                        f"Warning: QMP 'cont' failed for '{config.name}': {cont_reply['error']}. "
                        f"The VM may remain paused — check with 'workloadctl status {config.name}'.",
                        file=sys.stderr,
                    )
            except (OSError, ValueError) as exc:
                # OSError covers ConnectionError; ValueError covers a malformed
                # reply. Resume is best-effort — warn, never mask the backup or
                # escape un-isolated.
                print(
                    f"Warning: Failed to resume vCPUs for '{config.name}': {exc}. "
                    f"The VM may remain paused — check with 'workloadctl status {config.name}'.",
                    file=sys.stderr,
                )
    finally:
        qmp.close()

    size = output.stat().st_size
    if not quiet:
        _print_backup_size(output, size)
    return size


def _backup_impl(config, output: Path, *, no_stop: bool, quiet: bool, vm: bool) -> None:
    """Internal backup implementation shared by container and VM paths."""
    from workload_lib import workload_config_path
    name = config.name
    config_path = workload_config_path(name)
    service_name = config.service_name

    service_was_active = subprocess.run(
        ["systemctl", "is-active", "--quiet", service_name],
    ).returncode == 0

    if service_was_active and not no_stop:
        if not quiet:
            print(f"  Stopping {service_name}...")
        subprocess.run(["systemctl", "stop", service_name], check=True)

    try:
        with tempfile.TemporaryDirectory() as staging_name:
            staging = Path(staging_name)

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

            # Capture only the precious data/ subtree — for every substrate.
            # state/ (podman graphroot, VM system.qcow2 + gen snapshots,
            # .image-cache) is reconstructible from registries/Containerfiles
            # and is deliberately never in backup scope, so no exclude filtering
            # is needed: the archive is a straight copy of data/.
            data_dir = config.data_dir
            if data_dir.is_dir():
                shutil.copytree(
                    data_dir, staging / "data",
                    symlinks=True, dirs_exist_ok=False,
                )
            else:
                (staging / "data").mkdir()

            # Backups hold the precious data/ tree and credential blobs, so
            # keep them root-only. Lock the dir to 0700 *before* tar writes so
            # the archive (created with the default umask, typically 0644) is
            # never traversable by non-root during the write window, then pin
            # the archive itself to 0600.
            output.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(output.parent, 0o700)
            subprocess.run(
                ["tar", "-C", str(staging), "-cf", str(output), "--zstd", "."],
                check=True,
            )
            os.chmod(output, 0o600)
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
