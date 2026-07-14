"""
cmd_health — the liveness verdict for one workload: service active, user
present, containers up, health check passing, published ports reachable.
Exits non-zero when unhealthy, so it is usable as a probe.
"""

import json
import socket
import subprocess
import sys
from typing import Any

from service_runtime import manager_active
from substrate import get_substrate, service_active
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    parse_workload_ref,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _publish_host_port(port_spec: str) -> str | None:
    """Return the host-side port from a podman `--publish` spec, or None when
    there is no single fixed host port to probe.

    Publish specs are `[[ip:]hostPort:]containerPort[/proto]`. The host port is
    the field before the container port; a bare `containerPort` (podman picks a
    random host port), an empty host field (`ip::containerPort`), and port
    *ranges* all have no single deterministic host port and return None.
    """
    spec = port_spec.split('/', 1)[0]  # drop /proto
    # Strip a bracketed IPv6 bind address so its inner colons don't confuse the split.
    if spec.startswith('['):
        _, _, spec = spec.partition(']')
        spec = spec.lstrip(':')
    parts = spec.split(':')
    if len(parts) < 2:
        return None  # only a container port — host port is ephemeral
    host = parts[-2]
    if not host or '-' in host:
        return None  # random host port, or a range we can't probe as one port
    return host

def _multi_container_health(config, manager, only_container):
    """Per-container health summary for a multi-container workload.

    `only_container` restricts the report to one container (for NAME/CTR);
    None reports every container. Returns (data_dict, all_healthy)."""
    names = config.container_names()
    if only_container is not None and only_container not in names:
        print(f"Error: container '{only_container}' not in workload "
              f"'{config.name}'. Available: {', '.join(names)}", file=sys.stderr)
        sys.exit(2)

    rows = get_substrate(config, manager).container_liveness()
    if only_container is not None:
        rows = [r for r in rows if r["container"] == only_container]

    all_healthy = all(r["healthy"] for r in rows)
    containers = [{
        "container": r["container"],
        "healthy": r["healthy"],
        "service_state": r["service_state"],
        "running": r["running"],
    } for r in rows]
    return {
        "workload": config.name,
        "overall": "HEALTHY" if all_healthy else "UNHEALTHY",
        "containers": containers,
    }, all_healthy

# ---------------------------------------------------------------------------
# cmd_health
# ---------------------------------------------------------------------------

def cmd_health(args, manager: WorkloadManager):
    """Check workload health"""
    workload, container = parse_workload_ref(args.workload)
    config = WorkloadConfig(workload)

    # VMs have no container layer — health = service active + user exists.
    if config.is_vm:
        substrate = get_substrate(config, manager)
        liveness = substrate.liveness()
        svc_active = liveness["service_active"]
        service_state = liveness["service_state"]
        user_exists = manager.user_exists(config)
        all_healthy = svc_active and user_exists
        health_data: dict[str, Any] = {
            "workload": config.name,
            "overall": "HEALTHY" if all_healthy else "UNHEALTHY",
            "checks": [
                {
                    "check": "service_status",
                    "healthy": svc_active,
                    "message": "Service active" if svc_active else f"Service {service_state}",
                    "details": {"state": service_state},
                },
                {
                    "check": "user_exists",
                    "healthy": user_exists,
                    "message": f"User {config.username} exists" if user_exists
                               else f"User {config.username} does not exist",
                },
            ],
        }
        if args.json:
            print(json.dumps(health_data, indent=2))
        else:
            print(f"Workload: {health_data['workload']}")
            print(f"Overall: {health_data['overall']}")
            print()
            for check in health_data["checks"]:
                symbol = "✓" if check["healthy"] else "✗"
                print(f"{symbol} {check['message']}")
        sys.exit(0 if all_healthy else 1)

    if config.is_multi:
        data, all_healthy = _multi_container_health(config, manager, container)
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            print(f"Workload: {data['workload']}")
            print(f"Overall: {data['overall']}")
            print()
            for c in data["containers"]:
                symbol = "✓" if c["healthy"] else "✗"
                run = "running" if c["running"] else "not running"
                print(f"{symbol} {c['container']}: service {c['service_state']}, {run}")
        sys.exit(0 if all_healthy else 1)

    health_data = {
        "workload": config.name,
        "overall": "UNKNOWN",
        "checks": []
    }

    all_healthy = True

    # Check 1: Service status
    svc_active, svc_state = service_active(config.service_name)
    service_state = svc_state or "unknown"

    health_data["checks"].append({
        "check": "service_status",
        "healthy": svc_active,
        "message": "Service active and running" if svc_active else f"Service {service_state}",
        "details": {"state": service_state}
    })
    if not svc_active:
        all_healthy = False

    # Check 2: User exists
    user_exists = manager.user_exists(config)
    health_data["checks"].append({
        "check": "user_exists",
        "healthy": user_exists,
        "message": f"User {config.username} exists" if user_exists else f"User {config.username} does not exist"
    })
    if not user_exists:
        all_healthy = False

    # Check 3: User manager placement (only if user exists)
    # Slice= only takes effect when user@<uid>.service (re)starts; if the user
    # manager was already running before the drop-in existed it may be under
    # user.slice rather than workloads.slice, in which case no cap binds.
    if user_exists:
        uid = config.uid
        expected_slice = config.config.get("resources", {}).get("slice", "workloads.slice")
        if manager_active(uid):
            r2 = subprocess.run(
                ["systemctl", "show", f"user@{uid}.service", "-p", "Slice", "--value"],
                capture_output=True, text=True,
            )
            actual_slice = r2.stdout.strip()
            placement_ok = actual_slice == expected_slice
            if not placement_ok:
                health_data["checks"].append({
                    "check": "user_manager_placement",
                    "healthy": False,
                    "message": (
                        f"user@{uid}.service is in {actual_slice!r}, expected {expected_slice!r} — "
                        f"run: systemctl stop workload-{config.name}.service && "
                        f"systemctl restart user@{uid}.service"
                    ),
                    "details": {"actual_slice": actual_slice, "expected_slice": expected_slice},
                })
                all_healthy = False
            else:
                health_data["checks"].append({
                    "check": "user_manager_placement",
                    "healthy": True,
                    "message": f"user@{uid}.service in {actual_slice}",
                    "details": {"slice": actual_slice},
                })

    # Check 4: Container running (only if user exists)
    container_running = False
    container_status = "unknown"
    if user_exists:
        ps_status = manager.podman(config).container_status(config.container_name)
        if ps_status:
            container_running = True
            container_status = ps_status
            health_data["checks"].append({
                "check": "container_running",
                "healthy": True,
                "message": "Container running",
                "details": {"status": container_status}
            })
        else:
            health_data["checks"].append({
                "check": "container_running",
                "healthy": False,
                "message": "Container not running"
            })
            all_healthy = False

    # Check 5: Container health check (if configured and container running)
    if container_running and config.has_health_check():
        health_status = manager.podman(config).container_health(config.container_name)
        if health_status:
            is_healthy = health_status == "healthy"
            health_data["checks"].append({
                "check": "container_health",
                "healthy": is_healthy,
                "message": f"Container health: {health_status}",
                "details": {"status": health_status}
            })
            if not is_healthy:
                all_healthy = False
        else:
            health_data["checks"].append({
                "check": "container_health",
                "healthy": False,
                "message": "Container health check not available",
            })
            all_healthy = False

    # Check 6: Port accessibility (if ports defined, container running, and network exposes to host)
    ports = config.get_ports()
    network_mode = config.get_network_mode()
    if ports and container_running and network_mode in ("pasta", "host"):
        for port_spec in ports:
            # Probe the host-side published port, not the container port.
            port = _publish_host_port(port_spec)
            if port is None:
                continue  # no single fixed host port to probe
            try:
                port_num = int(port)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                rc = sock.connect_ex(('localhost', port_num))
                sock.close()

                port_accessible = rc == 0
                health_data["checks"].append({
                    "check": "port_accessibility",
                    "healthy": port_accessible,
                    "message": f"Port {port} accessible" if port_accessible else f"Port {port} not accessible",
                    "details": {"port": port}
                })
                if not port_accessible:
                    all_healthy = False
            except ValueError:
                pass  # Skip invalid port numbers

    # Check 7: Uptime (if service active)
    if svc_active:
        result = subprocess.run(
            ["systemctl", "show", config.service_name,
             "--property=ActiveEnterTimestamp", "--value"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            active_since = result.stdout.strip()
            health_data["checks"].append({
                "check": "uptime",
                "healthy": True,
                "message": f"Running since {active_since}",
                "details": {"active_since": active_since}
            })

    # Determine overall health
    health_data["overall"] = "HEALTHY" if all_healthy else "UNHEALTHY"

    # Output
    if args.json:
        print(json.dumps(health_data, indent=2))
        sys.exit(0 if all_healthy else 1)

    # Human-readable output
    print(f"Workload: {config.name}")
    print(f"Overall: {health_data['overall']}")
    print()

    for check in health_data["checks"]:
        symbol = "✓" if check["healthy"] else "✗"
        print(f"{symbol} {check['message']}")

    sys.exit(0 if all_healthy else 1)
