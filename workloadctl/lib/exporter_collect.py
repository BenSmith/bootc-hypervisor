"""
What the exporter collects: which workloads are enabled, and one pass per
producer over them.

get_enabled_workloads() is the only reader of workload TOML in the exporter;
it answers with the four facts the passes need and nothing else. collect_all()
and collect_inspect() feed the fast textfile, collect_disk() the slow one;
each returns plain tuples for exporter_render to lay out, so a pass can be
exercised without writing a file and rendered without a host.
"""

from pathlib import Path

import tomllib
from config_parser import workload_root_dir
from container_network_config import container_uses_inspect
from egress_policy import vm_uses_inspect
from inspect_figures import (
    drop_reasons,
    figures,
    read_inspect_status,
    read_resolve_status,
)
from vm_metrics import get_vm_qmp_metrics
from workload_lib import (
    ENABLED_MARKER_NAME,
    iter_workloads,
    normalize_containers,
    workload_config_dir,
    workload_podman_container_name,
)
from workload_metrics import (
    get_cgroup_metrics,
    get_container_healths,
    get_service_metrics,
    get_workload_disk_bytes,
)


def get_enabled_workloads():
    """Read all enabled workload configs from config directory.

    Returns list of (name, health_targets, is_vm, uses_inspect) tuples, where
    health_targets
    is a list of (local_container_name, podman_container_name) pairs — one per
    container that declares a health check. The podman name comes from the
    shared workload_podman_container_name() helper (single source of the
    single-vs-multi formula, also backing WorkloadConfig.podman_container_name);
    this function reads raw TOML and can't build a WorkloadConfig. An empty list
    means no health checks (falsy, like the old bool).
    """
    workloads: list[tuple] = []
    if not workload_config_dir().is_dir():
        return workloads

    for _, toml_path in iter_workloads():
        try:
            if toml_path.resolve() == Path("/dev/null"):
                continue
        except OSError:
            continue

        # Enabled-ness is the marker file beside the config.
        if not (toml_path.parent / ENABLED_MARKER_NAME).exists():
            continue

        try:
            with open(toml_path, "rb") as f:
                config = tomllib.load(f)
            name = config.get("workload", {}).get("name", "")
            is_vm = bool(config.get("vm"))
            # Derived here because this is where the TOML is already parsed.
            # The alternative — deciding from the presence of the runtime
            # directory — cannot tell a filtered VM that has not started this
            # boot from an unfiltered one, and those two owe opposite output:
            # zeros for the first, nothing at all for the second. G11 in the
            # container egress-parity build spec: this function reads raw
            # TOML and can't build a WorkloadConfig/Substrate, so it calls
            # each substrate's pure predicate directly rather than through
            # get_substrate().
            uses_inspect = (
                vm_uses_inspect(config) if is_vm else container_uses_inspect(config)
            )
            is_multi = "containers" in config
            health_targets = []
            if not is_vm:
                for ctr in normalize_containers(config):
                    if not ctr.get("container", {}).get("health", {}).get("cmd", ""):
                        continue
                    local_name = ctr.get("name", name)
                    podman_name = workload_podman_container_name(
                        name, local_name, is_multi=is_multi
                    )
                    health_targets.append((local_name, podman_name))
            if name:
                workloads.append((name, health_targets, is_vm, uses_inspect))
        except Exception:
            continue

    return workloads


# Collection-scaling note: collection is synchronous — one `sudo -u _wl-<name>
# podman` round-trip per enabled workload, serialised within a single run. At
# ~50 workloads the wall-clock latency is measurable but acceptable for a 30s
# timer interval. If it becomes a bottleneck, collecting workloads concurrently
# (one thread per rootless-podman round-trip) is the natural next step.
def collect_all():
    """Collect fast metrics for every enabled workload.

    Returns the list of (name, svc, cgroup, vm) tuples that format_metrics()
    renders. Disk usage is deliberately not collected here — it is a slow walk
    handled by the separate --disk producer (collect_disk).
    """
    all_metrics = []
    for name, health_targets, is_vm, _uses_inspect in get_enabled_workloads():
        svc = get_service_metrics(name) or {}
        cgroup = get_cgroup_metrics(name, is_vm)
        if health_targets:
            health_by_container = {}
            healths = get_container_healths(
                name, [p for _local, p in health_targets])
            for local_name, podman_name in health_targets:
                health = healths.get(podman_name)
                if health is not None:
                    health_by_container[local_name] = 1 if health == "healthy" else 0
            if health_by_container:
                svc["health"] = health_by_container
        vm = get_vm_qmp_metrics(name) if is_vm else {}
        all_metrics.append((name, svc, cgroup, vm))
    return all_metrics


def collect_inspect():
    """[(name, payload)] for every enabled workload with an inspected egress.

    Rung 5 T9, and it computes nothing: every figure comes from
    `inspect_figures`, which `doctor` reads the same way. Decision 9's whole
    point is that this file must not be the place a figure gets a second
    definition, and a Prometheus label is exactly the convenience that invites
    one — so the drop breakdown is passed through as the document carries it
    and the totals over it are left to `sum by`, never added up here.

    A SEPARATE COLLECTOR, not a fifth element on collect_all()'s tuple, because
    it is a different producer over a different source: collect_all() reads
    systemd, cgroups and podman, this reads two JSON documents in /run. The
    cost is one extra parse of each workload's TOML per run, which is noise
    beside the podman round-trip collect_all() already makes per workload.
    """
    out = []
    for name, _health_targets, _is_vm, uses_inspect in get_enabled_workloads():
        if not uses_inspect:
            # Nothing, not zeros. A series for an unfiltered workload asserts
            # that a filter exists and is idle, which is a different and false
            # claim from "this workload has no filter".
            continue
        status = read_inspect_status(name)
        out.append((name, {
            # Zeros ARE emitted for a filtered workload whose inspector has not
            # been dialled yet, so the series exists from the first scrape:
            # `record_failures == 0` is only alertable if the absence of data
            # and the value zero are distinguishable, and this gauge is what
            # distinguishes them.
            "status_present": 1 if status is not None else 0,
            "figures": figures(status, read_resolve_status(name)),
            "drop_reasons": drop_reasons(status),
        }))
    return out


def collect_disk():
    """Collect disk usage for every enabled workload (the slow --disk pass).

    Returns a list of (name, disk_bytes) tuples; disk_bytes is None when the
    `du` walk fails or times out.
    """
    return [
        (name, get_workload_disk_bytes(workload_root_dir(name)))
        for name, _health_targets, _is_vm, _ins in get_enabled_workloads()
    ]
