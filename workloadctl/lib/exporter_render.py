"""
The exposition text: what a collected pass looks like on the wire.

format_metrics() lays out the fast producer's textfile and
format_disk_metrics() the slow one's, each from the plain tuples
exporter_collect returns. Nothing here reads a host; a rendered body is a
pure function of its input plus the timestamp on the generated-at line.
"""

import time

from inspect_figures import FIGURES

def format_metrics(all_metrics, inspect_metrics=()):
    """Format metrics in Prometheus exposition format.

    `inspect_metrics` is collect_inspect()'s output and defaults to empty so a
    caller that only has the fast metrics still renders."""
    lines = [
        "# Workload metrics collected by workload-exporter",
        f"# Generated at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        "",
    ]

    type_defs = [
        ("workload_active", "gauge", "Whether the workload service is active (1) or not (0)"),
        ("workload_failed", "gauge", "Whether the workload service is in failed state (1) or not (0)"),
        ("workload_restarts_total", "counter", "Total number of service restarts"),
        ("workload_uptime_seconds", "gauge", "Seconds since the service entered active state"),
        ("workload_cpu_usage_seconds_total", "counter", "Total CPU time consumed in seconds"),
        ("workload_memory_current_bytes", "gauge", "Current memory usage in bytes"),
        ("workload_memory_max_bytes", "gauge", "Memory limit in bytes"),
        ("workload_pids_current", "gauge", "Current number of processes"),
        ("workload_health", "gauge", "Container health check status (1=healthy, 0=unhealthy)"),
    ]

    for metric_name, metric_type, help_text in type_defs:
        lines.append(f"# HELP {metric_name} {help_text}")
        lines.append(f"# TYPE {metric_name} {metric_type}")

        if metric_name == "workload_health":
            # Per-container: svc_metrics["health"] is {local_container_name:
            # 0/1}, one entry per container that has a health check (pod/bridge
            # workloads can have several; single-container workloads have one,
            # keyed by the workload name).
            for workload_name, svc_metrics, _cgroup, _vm in all_metrics:
                for container, value in svc_metrics.get("health", {}).items():
                    if container == workload_name:
                        # Single-container workloads key health by the workload
                        # name; keep their historical label-less series so
                        # existing dashboards/alerts keep matching.
                        lines.append(
                            f'workload_health{{workload="{workload_name}"}} {value}'
                        )
                    else:
                        lines.append(
                            f'workload_health{{workload="{workload_name}",container="{container}"}} {value}'
                        )
            lines.append("")
            continue

        for workload_name, svc_metrics, cgroup_metrics, _vm_metrics in all_metrics:
            key = metric_name.replace("workload_", "")
            if key in svc_metrics:
                value = svc_metrics[key]
                if isinstance(value, float):
                    lines.append(f'{metric_name}{{workload="{workload_name}"}} {value:.2f}')
                else:
                    lines.append(f'{metric_name}{{workload="{workload_name}"}} {value}')
            elif key in cgroup_metrics:
                value = cgroup_metrics[key]
                if isinstance(value, float):
                    lines.append(f'{metric_name}{{workload="{workload_name}"}} {value:.6f}')
                else:
                    lines.append(f'{metric_name}{{workload="{workload_name}"}} {value}')

        lines.append("")

    # VM-specific metrics (only emitted for workloads with a [vm] section)
    lines.append("# HELP workload_vm_balloon_actual_bytes Guest physical memory in use after balloon inflation")
    lines.append("# TYPE workload_vm_balloon_actual_bytes gauge")
    for workload_name, _svc, _cgroup, vm_metrics in all_metrics:
        if "balloon_actual_bytes" in vm_metrics:
            lines.append(f'workload_vm_balloon_actual_bytes{{workload="{workload_name}"}} {vm_metrics["balloon_actual_bytes"]}')
    lines.append("")

    lines.append("# HELP workload_vm_vcpu_cpu_seconds_total Total CPU time consumed by a vCPU thread in seconds")
    lines.append("# TYPE workload_vm_vcpu_cpu_seconds_total counter")
    for workload_name, _svc, _cgroup, vm_metrics in all_metrics:
        for key, value in vm_metrics.items():
            if key.startswith("vcpu_") and key.endswith("_cpu_seconds_total"):
                vcpu_idx = key.split("_")[1]
                lines.append(f'workload_vm_vcpu_cpu_seconds_total{{workload="{workload_name}",vcpu="{vcpu_idx}"}} {value:.6f}')
    lines.append("")

    lines.extend(_inspect_metric_lines(inspect_metrics))

    lines.append("# HELP workload_enabled_total Total number of enabled workloads")
    lines.append("# TYPE workload_enabled_total gauge")
    lines.append(f"workload_enabled_total {len(all_metrics)}")
    lines.append("")

    lines.append("# HELP workload_metrics_last_collect_timestamp_seconds Unix timestamp of last metrics collection")
    lines.append("# TYPE workload_metrics_last_collect_timestamp_seconds gauge")
    lines.append(f"workload_metrics_last_collect_timestamp_seconds {time.time():.0f}")
    lines.append("")

    return "\n".join(lines)


def _inspect_metric_lines(inspect_metrics):
    """The inspector's series, walking FIGURES rather than a list written here.

    One family at a time across all workloads, which Prometheus requires: a
    HELP/TYPE header followed by every sample of that family. Figures with an
    empty `metric` are skipped — see Figure's docstring on why a sum belongs to
    the query language and not to the wire.
    """
    lines = []
    if not inspect_metrics:
        return lines

    lines.append("# HELP workload_vm_inspect_status_present Whether the egress "
                 "inspector has written a status document (1) or has not been "
                 "dialled since the VM started (0)")
    lines.append("# TYPE workload_vm_inspect_status_present gauge")
    for name, payload in inspect_metrics:
        lines.append(f'workload_vm_inspect_status_present{{workload="{name}"}} '
                     f'{payload["status_present"]}')
    lines.append("")

    for fig in FIGURES:
        if not fig.metric:
            continue
        samples = [(name, payload["figures"][fig.key])
                   for name, payload in inspect_metrics
                   if fig.key in payload["figures"]]
        if not samples:
            # The group is absent on every workload (no minter anywhere, no
            # resolver anywhere). Emitting a bare HELP/TYPE with no samples is
            # legal but publishes a family that never has one.
            continue
        lines.append(f"# HELP {fig.metric} {fig.help}")
        lines.append(f"# TYPE {fig.metric} {fig.kind}")
        for name, value in samples:
            lines.append(f'{fig.metric}{{workload="{name}"}} {value}')
        lines.append("")

    reason_samples = [(name, reason, count)
                      for name, payload in inspect_metrics
                      for reason, count in sorted(payload["drop_reasons"].items())]
    if reason_samples:
        lines.append("# HELP workload_vm_inspect_drop_events_total Drop events "
                     "by reason. One connection can raise several, so this is "
                     "not a count of dropped connections")
        lines.append("# TYPE workload_vm_inspect_drop_events_total counter")
        for name, reason, count in reason_samples:
            # The reasons are listener constants, not guest input — no guest
            # string reaches this label. Quotes and backslashes are escaped
            # anyway: the exposition format has no way to say "trust me", and a
            # reason worded with an apostrophe one rung from now would produce a
            # file node_exporter drops in full rather than one bad line.
            safe = reason.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'workload_vm_inspect_drop_events_total'
                         f'{{workload="{name}",reason="{safe}"}} {count}')
        lines.append("")
    return lines


def format_disk_metrics(disk_metrics):
    """Format the disk-usage textfile (its own producer, own drop file)."""
    lines = [
        "# Workload disk metrics collected by workload-exporter --disk",
        f"# Generated at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        "",
        "# HELP workload_disk_bytes Total disk usage of the workload durable-state directory in bytes",
        "# TYPE workload_disk_bytes gauge",
    ]
    for name, disk_bytes in disk_metrics:
        if disk_bytes is not None:
            lines.append(f'workload_disk_bytes{{workload="{name}"}} {disk_bytes}')
    lines.append("")
    lines.append("# HELP workload_disk_last_collect_timestamp_seconds Unix timestamp of last disk-usage collection")
    lines.append("# TYPE workload_disk_last_collect_timestamp_seconds gauge")
    lines.append(f"workload_disk_last_collect_timestamp_seconds {time.time():.0f}")
    lines.append("")
    return "\n".join(lines)
