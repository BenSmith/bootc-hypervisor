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
from abc import ABC, abstractmethod
from pathlib import Path

from workload_lib import auto_detect_credentials


# ---------------------------------------------------------------------------
# NotApplicable — explicit "N/A cell" in the verb×substrate matrix
# ---------------------------------------------------------------------------

class NotApplicable(Exception):
    """Raised when a verb is not applicable to the current substrate.

    The caller is expected to print a clear message and exit 0
    (the verb is not broken; it simply doesn't apply here).
    """
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


# ---------------------------------------------------------------------------
# Substrate ABC
# ---------------------------------------------------------------------------

class Substrate(ABC):
    """Per-substrate primitive port.

    All substrate-variant verbs (stats, health, backup, …) delegate their
    substrate-specific delta here.  Substrate-invariant verbs (create, list,
    validate, secret, …) bypass this layer entirely.

    First-cut design: primitives are coarse (one per parity gap), not yet the
    narrow-waist ten.  Refine as duplication between substrates becomes visible.
    """

    def __init__(self, config, manager):
        self.config = config
        self.manager = manager

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


# ---------------------------------------------------------------------------
# ContainerSubstrate
# ---------------------------------------------------------------------------

class ContainerSubstrate(Substrate):
    """Substrate for single / pod / bridge container workloads."""

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


# ---------------------------------------------------------------------------
# VMSubstrate
# ---------------------------------------------------------------------------

class VMSubstrate(Substrate):
    """Substrate for VM workloads ([vm] section in TOML)."""

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
