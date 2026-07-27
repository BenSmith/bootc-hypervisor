"""
substrate — substrate port for workloadctl.

Defines the Substrate ABC, the exception vocabulary every substrate raises,
the primitives both of them share, and the router function get_substrate().
The implementations live in ``substrate_container`` and ``substrate_vm``;
callers reach them only through ``get_substrate()`` and this ABC.

Design: workloadctl/llms.txt, "Substrate dispatch"

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
    rollback_targets, rollback_to, rollback, control

Optional primitives (base-class default, override to support):
    resource_usage, logs, endpoints, address, reprovision
"""

from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from pathlib import Path

from workloadctl_core import parse_size_bytes


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
# Resource-usage rows
# ---------------------------------------------------------------------------

# The normalized shape every substrate's resource_usage(json_out=True) returns.
# Uniform across containers and VMs so `workloadctl stats --json` has one schema;
# a substrate with no source for a key reports None rather than 0.
STAT_ROW_KEYS = (
    "workload", "username", "container",
    "cpu_percent", "mem_usage", "mem_limit", "mem_percent",
    "net_input", "net_output", "block_input", "block_output", "pids",
)


def _stat_percent(v) -> float:
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return float(str(v).strip().rstrip("%"))
    except (ValueError, AttributeError):
        return 0.0


def _stat_io_pair(s) -> tuple[int, int]:
    parts = str(s).split(" / ")
    if len(parts) == 2:
        return parse_size_bytes(parts[0]), parse_size_bytes(parts[1])
    return 0, 0


def _stat_mem_pair(row: dict) -> tuple[int, int]:
    """(mem_usage_bytes, mem_limit_bytes) from a podman stats row.

    Handles both the combined 'X / Y' string format (older podman) and the
    separate numeric fields (newer podman).
    """
    raw = row.get("mem_usage") or row.get("MemUsage", "0")
    if isinstance(raw, str) and " / " in raw:
        return _stat_io_pair(raw)
    return (parse_size_bytes(raw),
            parse_size_bytes(row.get("mem_limit") or row.get("MemLimit", 0)))


def podman_stat_row(row: dict, config, target_names: list[str]) -> dict:
    """Normalize one raw `podman stats --format json` row into STAT_ROW_KEYS."""
    net_in, net_out = _stat_io_pair(row.get("net_io") or row.get("NetIO", "0 / 0"))
    blk_in, blk_out = _stat_io_pair(row.get("block_io") or row.get("BlockIO", "0 / 0"))
    mem_u, mem_l = _stat_mem_pair(row)
    return {
        "workload": config.name,
        "username": config.username,
        "container": row.get("name") or row.get("Name", target_names[0]),
        "cpu_percent": _stat_percent(row.get("cpu_percent") or row.get("CPU", 0)),
        "mem_usage": mem_u,
        "mem_limit": mem_l,
        "mem_percent": _stat_percent(row.get("mem_percent") or row.get("MemPerc", 0)),
        "net_input": net_in,
        "net_output": net_out,
        "block_input": blk_in,
        "block_output": blk_out,
        "pids": int(row.get("pids") or row.get("PIDs", 0)),
    }


# ---------------------------------------------------------------------------
# Rollback image tag (shared by ContainerSubstrate and cmd_update helpers)
# ---------------------------------------------------------------------------

def rollback_tag(name: str, container: str | None = None) -> str:
    """Return the rollback image tag for a workload (or one of its containers)."""
    suffix = f"-{container}" if container else ""
    return f"localhost/workload-rollback/{name}{suffix}:latest"


# ---------------------------------------------------------------------------
# Substrate ABC
# ---------------------------------------------------------------------------

class Substrate(ABC):
    """Per-substrate primitive port (step-3 narrow waist).

    All substrate-variant verbs delegate their substrate-specific delta here.
    Substrate-invariant verbs (create, list, validate, secret, …) bypass
    this layer entirely.

    Required primitives (abstract, always present):
        liveness, gating_units, capture, exec, open_shell,
        lifecycle, rollback_targets, rollback_to, rollback, control

    Optional primitives (base-class default; override to support):
        resource_usage, logs, endpoints, address, reprovision
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

        action must be one of: ``"start"``, ``"stop"``, ``"restart"`` (bounce the
        workload's main unit only), ``"reboot"`` (soft-reboot the workload's init
        system).

        ``"restart"`` is a *bounce*, not a re-provision: the container overlay,
        the VM's disks and its cloud-init seed all survive it, and nothing is
        re-rendered from the TOML.  Applying a config edit — dropping the overlay,
        rebuilding the seed — is ``reprovision(recreate=True)``.

        Raises LifecycleError carrying the returncode of the call that failed.
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

        With ``json_out``, returns a list of normalized stat rows (see
        STAT_ROW_KEYS) — one per target — so callers never have to know how the
        substrate got them.  A key the substrate has no source for is None, not
        0: a VM reports no block I/O because QEMU isn't asked for it, and
        reporting zero there would be a lie rather than a gap.

        Otherwise writes a human table to the terminal and returns None.

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

    def address(self) -> str | None:
        """Return the workload's own address on the host network, if it has one.

        Returns None when the substrate does have addresses but this workload's
        is not resolvable right now (not booted, no DHCP lease yet) — a runtime
        condition the caller reports, not an error.

        Raises NotApplicable where the substrate has no such notion at all: a
        rootless container shares the host's network stack, so there is no
        address to return and never will be.
        """
        raise NotApplicable(
            f"address: not applicable for {type(self).__name__} "
            f"(no address primitive)"
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
# Router
# ---------------------------------------------------------------------------

def get_substrate(config, manager) -> Substrate:
    """Resolve the Substrate implementation from the workload declaration."""
    # Imported here, not at module scope: both implementations import this
    # module for the ABC and the exception vocabulary, so a top-level import
    # either way round is a cycle. The router is the one place that has to know
    # both, and it only needs them at call time.
    from substrate_container import ContainerSubstrate
    from substrate_vm import VMSubstrate

    if config.is_vm:
        return VMSubstrate(config, manager)
    return ContainerSubstrate(config, manager)
