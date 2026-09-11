"""
Per-workload metric sources for the Prometheus exporter: the container-side
half beside vm_metrics.

Each reader here answers one question about one workload -- its unit's state,
its containers' health, its cgroup's usage, its durable state's size -- and
returns a plain dict or scalar, with None or {} standing for "unavailable".
The exporter's passes (exporter_collect) decide which of these to ask per
workload; nothing here reads a workload config.
"""

import subprocess
import time
from pathlib import Path

from podman import Podman
from vm_metrics import find_vm_cgroup, systemd_show
from workload_lib import (
    workload_container_name,
    workload_service_name,
    workload_username,
)

# The `du` walk runs on the slow disk timer, well off the fast scrape, so it
# can afford a generous cap — a large durable-state dir (tens of GB) is worth
# waiting for rather than timing out to a missing series.
DISK_DU_TIMEOUT = 120


def get_workload_disk_bytes(home_dir):
    """Return total disk usage of home_dir in bytes, or None if unavailable."""
    try:
        result = subprocess.run(
            ["du", "-sb", str(home_dir)],
            capture_output=True, text=True, timeout=DISK_DU_TIMEOUT,
        )
        if result.returncode == 0:
            return int(result.stdout.split()[0])
    except Exception:
        pass
    return None


def get_service_metrics(name):
    """Get systemd service metrics for a workload."""
    service = workload_service_name(name)
    props = systemd_show(
        service,
        "ActiveState",
        "SubState",
        "NRestarts",
        "ActiveEnterTimestampMonotonic",
        "ExecMainStatus",
    )
    active_state = props.get("ActiveState", "inactive") if props else "inactive"

    metrics: dict[str, float] = {
        "active": 1 if active_state == "active" else 0,
        "failed": 1 if active_state == "failed" else 0,
        "restarts_total": int(props.get("NRestarts", 0)),
    }

    enter_mono = int(props.get("ActiveEnterTimestampMonotonic", 0))
    if enter_mono > 0 and active_state == "active":
        try:
            now_mono = time.monotonic_ns() // 1000  # convert ns to µs
            metrics["uptime_seconds"] = max(0, (now_mono - enter_mono) / 1_000_000)
        except Exception:
            pass

    return metrics


def get_container_healths(name, container_names):
    """Query podman health for a workload's containers in ONE inspect call.

    `container_names` are the podman --name values (per-container
    `workload-<name>-<container>` for pod/bridge workloads). Returns
    {podman_name: "healthy"|"unhealthy"|"starting"|None}; containers that
    don't exist are absent. Runs podman inspect as the workload user.
    """
    username = workload_username(name)
    try:
        import pwd as _pwd
        pw = _pwd.getpwnam(username)
        uid = pw.pw_uid
    except (KeyError, ImportError):
        return {}

    # Boundary note (B13): built from a raw pwd.getpwnam() lookup rather
    # than a WorkloadConfig/WorkloadManager (the exporter is a standalone
    # scrape loop with no manager instance) — but this still goes through
    # the typed Podman.for_user() constructor, not a hand-built subprocess
    # call, so the identity plumbing (user / XDG_RUNTIME_DIR / HOME) is the
    # same as every other caller — including the setuid-instead-of-sudo spawn
    # that keeps this loop from filling the audit log (see
    # Podman._compute_drop_privs; this timer is what motivated it).
    try:
        return Podman.for_user(
            username, uid, pw.pw_dir, timeout=5
        ).container_healths(container_names)
    except Exception:
        return {}


def get_container_health(name, container_name=None):
    """Single-container convenience over get_container_healths()."""
    target = container_name or workload_container_name(name)
    return get_container_healths(name, [target]).get(target)


def find_workload_cgroup(name):
    """Find the cgroup path for a workload's podman container.

    Under ADR 001 option 1b the user manager is placed in workloads.slice:
      /sys/fs/cgroup/workloads.slice/user@{uid}.service/.../libpod-*.scope
    Falls back to the pre-1b login-session path for rollback compatibility:
      /sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/.../libpod-*.scope
    """
    username = workload_username(name)
    try:
        import pwd
        pw = pwd.getpwnam(username)
        uid = pw.pw_uid
    except (KeyError, ImportError):
        return None

    candidates = [
        Path(f"/sys/fs/cgroup/workloads.slice/user@{uid}.service"),
        Path(f"/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service"),
    ]
    for user_service in candidates:
        if not user_service.is_dir():
            continue
        for scope in user_service.rglob("libpod-*.scope"):
            if scope.is_dir():
                return scope

    return None


def read_cgroup_metric(cgroup_path, filename):
    """Read a single value from a cgroup file."""
    try:
        content = (cgroup_path / filename).read_text().strip()
        if content == "max":
            return None
        return int(content)
    except (OSError, ValueError):
        return None


def read_cpu_usage(cgroup_path):
    """Read total CPU usage in seconds from cpu.stat."""
    try:
        content = (cgroup_path / "cpu.stat").read_text()
        for line in content.splitlines():
            if line.startswith("usage_usec"):
                return int(line.split()[1]) / 1_000_000  # µs → seconds
    except (OSError, ValueError):
        pass
    return None


def get_cgroup_metrics(name, is_vm=False):
    """Get resource metrics from cgroup v2 for a workload.

    For VMs the cgroup is the qemu service's own (host-side footprint of the
    hypervisor process); for containers it is the rootless podman scope.
    """
    cgroup = find_vm_cgroup(name) if is_vm else find_workload_cgroup(name)
    if not cgroup:
        return {}

    metrics = {}

    cpu = read_cpu_usage(cgroup)
    if cpu is not None:
        metrics["cpu_usage_seconds_total"] = cpu

    mem = read_cgroup_metric(cgroup, "memory.current")
    if mem is not None:
        metrics["memory_current_bytes"] = mem

    mem_max = read_cgroup_metric(cgroup, "memory.max")
    if mem_max is not None:
        metrics["memory_max_bytes"] = mem_max

    pids = read_cgroup_metric(cgroup, "pids.current")
    if pids is not None:
        metrics["pids_current"] = pids

    return metrics
