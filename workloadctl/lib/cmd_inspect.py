"""
cmd_inspect — the workload state overview: `list` (every workload, one row
each) and `status` (one workload, in depth). Same view at two scopes, so
they share the state derivation and `status` falls back to `list` when no
workload is named.
"""

import json
import subprocess

import deployment
from workload_lib import (
    HOST_USERNS_OPT_IN,
    units_outdated,
    units_from_other_build,
    WORKLOADCTL_VERSION,
    workload_config_dir,
    workload_root_dir,
    workload_service_units,
)
from validation import uses_host_userns
from service_runtime import parse_active_since, systemctl_show
from substrate import get_substrate
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    WorkloadUserNotFound,
)
from cmd_lifecycle import _effective_state


# ---------------------------------------------------------------------------
# cmd_list
# ---------------------------------------------------------------------------

def cmd_list(args, manager: WorkloadManager):
    """List all available workloads"""
    configs = manager.get_all_configs()

    if args.json:
        workloads = []
        for config in configs:
            try:
                uid = config.uid
            except WorkloadUserNotFound:
                uid = None

            # Get runtime state for enabled workloads
            state = None
            if config.enabled:
                state, _ = _effective_state(config)

            # Get image ID if user exists
            image_id = None
            try:
                if manager.user_exists(config):
                    image_id = manager.get_image_id(config)
            except Exception:
                # Gracefully handle any errors (e.g., no sudo access)
                pass

            if config.is_vm:
                vm_cfg = config.config.get("vm", {})
                primary_image = (vm_cfg.get("cloud_image_url") or vm_cfg.get("local_image")
                                 or vm_cfg.get("image") or None)
            elif config.is_multi:
                images = [img for _, img in config.container_images()]
                primary_image = images[0] if images else None
            else:
                primary_image = config.image
            workloads.append({
                "name": config.name,
                "kind": config.kind,
                "enabled": config.enabled,
                "state": state,
                "mode": config.mode,
                "containers": 0 if config.is_vm else len(config.container_names()),
                "image": primary_image,
                "image_id": image_id,
                "ports": config.get_ports(),
                "username": config.username,
                "uid": uid
            })
        print(json.dumps({"workloads": workloads}, indent=2))
        return

    print(f"Available workloads in {workload_config_dir()}:")
    print()

    if not configs:
        print("  No workload configs found")
        return

    # Size the NAME column to fit the longest name, within sensible bounds.
    # Names longer than the cap are elided with an ellipsis.
    NAME_MIN = 18
    NAME_MAX = 28
    longest = max((len(c.name) for c in configs), default=0)
    name_w = max(NAME_MIN, min(longest, NAME_MAX))

    # Print header
    print(f"  {'NAME':<{name_w}} {'STATUS':<10} {'STATE':<12} {'IMAGE_ID':<14} {'PORTS':<20} {'IMAGE':<30}")
    print(f"  {'-'*name_w} {'-'*10} {'-'*12} {'-'*14} {'-'*20} {'-'*30}")

    failed_workloads = []
    for config in configs:
        status = "enabled" if config.enabled else "disabled"

        # Get runtime state for enabled workloads. _effective_state surfaces a
        # failed VM setup/build helper as 'failed' instead of a bland 'inactive'.
        if config.enabled:
            state, failed_unit = _effective_state(config)
            if failed_unit:
                failed_workloads.append((config.name, failed_unit))
        else:
            state = "-"

        # Get image ID (short hash) if user exists
        image_id = "-"
        try:
            if manager.user_exists(config) and not config.is_multi:
                full_id = manager.get_image_id(config)
                if full_id:
                    image_id = full_id[:12]  # Show first 12 chars like docker
        except Exception:
            # Gracefully handle any errors (e.g., no sudo access)
            pass

        # Get ports
        ports = config.get_ports()
        ports_str = ", ".join(ports) if ports else "-"
        if len(ports_str) > 20:
            ports_str = ports_str[:17] + "..."

        # Image column: VM / multi-container / single
        if config.is_vm:
            vm_cfg = config.config.get("vm", {})
            image = (vm_cfg.get("cloud_image_url") or vm_cfg.get("local_image")
                     or vm_cfg.get("image") or "[vm]")
        elif config.is_multi:
            image = f"({len(config.container_names())} containers, {config.mode})"
        else:
            image = config.image
        if len(image) > 30:
            image = image[:27] + "..."

        # Elide long workload names so the column never overflows
        name = config.name
        if len(name) > name_w:
            name = name[:name_w - 3] + "..."

        print(f"  {name:<{name_w}} {status:<10} {state:<12} {image_id:<14} {ports_str:<20} {image:<30}")

    print()
    print("  Use 'workloadctl status <name>' for details on a specific workload.")

    if failed_workloads:
        print()
        for name, unit in failed_workloads:
            print(f"  WARNING: '{name}' is not running — {unit} failed.")
        print("           Run 'workloadctl status <name>' or "
              "'sudo journalctl -u <unit>' to see why.")

# ---------------------------------------------------------------------------
# cmd_status
# ---------------------------------------------------------------------------

def cmd_status(args, manager: WorkloadManager):
    """Show workload service status"""
    if not args.workload:
        cmd_list(args, manager)
        return

    config = WorkloadConfig(args.workload)

    if args.json:
        UINT64_MAX = 18446744073709551615
        props = systemctl_show(
            config.service_name,
            ["ActiveState", "UnitFileState", "MainPID", "MemoryCurrent",
             "TasksCurrent", "Result", "ActiveEnterTimestamp"],
            extra_args=["--timestamp=unix"],
        )

        def _int_or_null(v):
            if not v or v == "[n/a]":
                return None
            try:
                n = int(v)
                return None if n == UINT64_MAX else n
            except ValueError:
                return None

        enabled_result = subprocess.run(
            ["systemctl", "is-enabled", config.service_name],
            capture_output=True, text=True
        )
        out = {
            "workload": config.name,
            "service": config.service_name,
            "state": props.get("ActiveState") or None,
            "enabled": enabled_result.returncode == 0,
            "active_since": parse_active_since(props.get("ActiveEnterTimestamp", "")),
            "main_pid": _int_or_null(props.get("MainPID", "")),
            "memory_current": _int_or_null(props.get("MemoryCurrent", "")),
            "tasks_current": _int_or_null(props.get("TasksCurrent", "")),
            "result": props.get("Result") or None,
            "config_stale": units_outdated(config.name),
            "units_generated_by": units_from_other_build(config.name)
                                  or WORKLOADCTL_VERSION,
            "host_userns": uses_host_userns(config.config),
            # Which ostree deployment last provisioned this workload's /var.
            # Null off ostree and before the workload's first start. Distinct
            # from units_generated_by: that names the workloadctl build, this
            # names the OS deployment whose /etc the state was created under —
            # the axis `cleanup` uses to tell a deleted TOML from a rollback.
            "state_deployment": (deployment.read_marker(workload_root_dir(config.name))
                                 or {}).get("deployment"),
        }
        if config.is_multi:
            out["mode"] = config.mode
            sub = []
            for cname, unit in zip(config.container_names(), config.sub_service_names()):
                sp = systemctl_show(unit, ["ActiveState", "Result"])
                sub.append({"name": cname, "service": unit,
                            "state": sp.get("ActiveState") or None,
                            "result": sp.get("Result") or None})
            out["containers"] = sub
        print(json.dumps(out, indent=2))
        return

    if units_outdated(config.name):
        # flush before the systemctl subprocess writes to the same fd, else the
        # hint (block-buffered when stdout is piped) lands after / behind it.
        print(f"⚠  config edited since last enable — units are stale. Run "
              f"'sudo workloadctl enable {config.name}' to apply "
              f"(daemon-reload does not regenerate units).\n", flush=True)

    other_build = units_from_other_build(config.name)
    if other_build:
        # Same buffering reason as above. Distinct from the staleness warning:
        # that one is "your TOML moved", this one is "workloadctl moved".
        print(f"⚠  units were generated by {other_build}, not the running "
              f"{WORKLOADCTL_VERSION}. Run "
              f"'sudo workloadctl enable {config.name}' to regenerate.\n",
              flush=True)

    if uses_host_userns(config.config):
        # Surface the elevated trust: host userns dissolves the per-workload
        # isolation boundary. flush for the same buffering reason as above.
        print(f'⚠  elevated trust: security.userns="host" in effect '
              f'({HOST_USERNS_OPT_IN}=true) — per-workload isolation boundary '
              f'dissolved.\n', flush=True)

    if config.is_multi:
        units = workload_service_units(config)
        subprocess.run(["systemctl", "status", "--no-pager"] + units)
        return

    gating = get_substrate(config, None).gating_units()
    if gating:
        # Show setup/build units alongside the main one: when a workload fails
        # to start the cause is often in a gating unit, and the main unit only
        # reports a bland 'dependency failed'.
        units = gating + [config.service_name]
        subprocess.run(["systemctl", "status", "--no-pager"] + units)
        return

    subprocess.run(["systemctl", "status", config.service_name])
