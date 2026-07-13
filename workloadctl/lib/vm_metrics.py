"""
VM metric collectors shared by the Prometheus exporter and the CLI.

get_vm_qmp_metrics() (guest-side stats over QMP) and find_vm_cgroup()
(host-side cgroup usage of the qemu process) are the two VM-specific metric
sources workload-exporter's fast collection pass uses; kept here, importable,
so other callers (e.g. lib/substrate.py) can reuse them too.
"""

import os
import subprocess
from pathlib import Path

from qmp import QMPClient
from vm import VM_SOCKET_DIR
from workload_lib import workload_service_name

# Unified cgroup v2 mount. A module constant so tests can redirect it.
CGROUP_ROOT = Path("/sys/fs/cgroup")


def systemd_show(service, *properties):
    """Query systemd properties for a service. Returns dict."""
    props = ",".join(properties)
    try:
        result = subprocess.run(
            ["systemctl", "show", service, f"--property={props}"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return {}
        out = {}
        for line in result.stdout.strip().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
        return out
    except Exception:
        return {}


def get_vm_qmp_metrics(name):
    """Query QMP for VM-specific metrics. Returns dict, empty if unavailable.

    Collects:
      balloon_actual_bytes   — guest physical memory after balloon inflation
      vcpu_{N}_cpu_seconds_total — per-vCPU CPU time (user+sys) from /proc/<tid>/stat
    """
    # Use the dedicated read-only metrics monitor, never the control socket
    # (qmp.sock). A QMP monitor serves one client at a time, so scraping the
    # control socket every 15s could block the ExecStop system_powerdown and
    # force an unclean SIGKILL shutdown.
    sock_path = VM_SOCKET_DIR / name / "qmp-metrics.sock"
    if not sock_path.exists():
        return {}

    metrics = {}
    qmp = QMPClient()
    try:
        qmp.connect(sock_path, timeout=2.0, recv_timeout=3.0)
        qmp.negotiate()

        # Balloon: actual guest physical memory in use
        balloon = qmp.execute("query-balloon")
        if "return" in balloon and "actual" in balloon["return"]:
            metrics["balloon_actual_bytes"] = balloon["return"]["actual"]

        # Per-vCPU CPU time via thread IDs + /proc/<tid>/stat
        cpus = qmp.execute("query-cpus-fast")
        if "return" in cpus:
            clk_tck = os.sysconf("SC_CLK_TCK")
            for cpu in cpus["return"]:
                idx = cpu.get("cpu-index", 0)
                tid = cpu.get("thread-id")
                if tid is None:
                    continue
                try:
                    stat = Path(f"/proc/{tid}/stat").read_text().split()
                    utime = int(stat[13])
                    stime = int(stat[14])
                    metrics[f"vcpu_{idx}_cpu_seconds_total"] = (utime + stime) / clk_tck
                except (OSError, ValueError, IndexError):
                    pass
    except Exception:
        pass
    finally:
        qmp.close()

    return metrics


def find_vm_cgroup(name):
    """Find the cgroup for a VM workload's QEMU process.

    Unlike a container (whose podman runs under the rootless user manager and
    lands in a libpod-*.scope), a VM's qemu is the main process of the
    system-level workload-<name>.service, so its cgroup is the service's own.
    Resolved via systemd's ControlGroup property so a custom resources.slice is
    honoured. Returns the absolute cgroup Path, or None if not active.
    """
    props = systemd_show(workload_service_name(name), "ControlGroup")
    cgroup = props.get("ControlGroup", "")
    if not cgroup:
        return None
    path = CGROUP_ROOT / cgroup.lstrip("/")
    return path if path.is_dir() else None
