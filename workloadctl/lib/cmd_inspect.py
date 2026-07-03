"""
cmd_inspect — workload inspection/status commands:
list, status, info, network, images, health, stats.
"""

import datetime
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
from typing import Any

from workload_lib import (
    QMPClient,
    USERNAME_PREFIX,
    VM_SOCKET_DIR,
    units_outdated,
    workload_config_dir,
    workload_service_units,
)
from podman import Podman
from service_runtime import manager_active
from substrate import NotApplicable, get_substrate, service_active
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    WorkloadUserNotFound,
    created_unix,
    format_created,
    format_size,
    parse_size_bytes,
    parse_workload_ref,
    require_root,
)
from cmd_lifecycle import _effective_state


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _systemctl_show(unit: str, properties: list[str], extra_args: list[str] | None = None) -> dict[str, str]:
    """Run `systemctl show` and return a {key: value} dict."""
    r = subprocess.run(
        ["systemctl", "show", unit, f"--property={','.join(properties)}"] + (extra_args or []),
        capture_output=True, text=True,
    )
    result = {}
    for line in r.stdout.splitlines():
        key, _, value = line.partition("=")
        if key:
            result[key] = value
    return result


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _parse_active_since(ts_raw: str):
    """Parse a `systemctl show --timestamp=unix` ActiveEnterTimestamp value
    (`@<epoch>`, or empty/`[n/a]` when never active) into a unix-epoch int,
    or None if unset/unparseable."""
    if not ts_raw or not ts_raw.startswith("@"):
        return None
    try:
        return int(float(ts_raw[1:]))
    except ValueError:
        return None


def _read_subid(username: str, path: str) -> tuple:
    """Return (start, count) from /etc/subuid or /etc/subgid, or (None, None)."""
    try:
        with open(path) as f:
            for line in f:
                if line.startswith(f"{username}:"):
                    parts = line.strip().split(":")
                    if len(parts) == 3:
                        return int(parts[1]), int(parts[2])
    except (FileNotFoundError, ValueError):
        pass
    return None, None


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
        props = _systemctl_show(
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
            "active_since": _parse_active_since(props.get("ActiveEnterTimestamp", "")),
            "main_pid": _int_or_null(props.get("MainPID", "")),
            "memory_current": _int_or_null(props.get("MemoryCurrent", "")),
            "tasks_current": _int_or_null(props.get("TasksCurrent", "")),
            "result": props.get("Result") or None,
            "config_stale": units_outdated(config.name),
        }
        if config.is_multi:
            out["mode"] = config.mode
            sub = []
            for cname, unit in zip(config.container_names(), config.sub_service_names()):
                sp = _systemctl_show(unit, ["ActiveState", "Result"])
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


# ---------------------------------------------------------------------------
# cmd_images
# ---------------------------------------------------------------------------

def cmd_images(args, manager: WorkloadManager):
    """Show images used by workloads or prune unused images"""
    if args.subcommand == "prune":
        require_root()
        print("Pruning unused images from all workloads...")
        print()

        pruned = False
        for entry in pwd.getpwall():
            if entry.pw_name.startswith(USERNAME_PREFIX):
                print(f"Pruning images for {entry.pw_name}...")
                try:
                    # Authoritative $HOME from passwd (the state/ subdir), matching
                    # what the workload service and exporter use. Do NOT reconstruct
                    # WORKLOADS_BASE/<name> — that's the root, one level above the
                    # real podman graphroot, so the prune would hit an empty store.
                    home = entry.pw_dir
                    result = Podman.for_user(
                        entry.pw_name, entry.pw_uid, home
                    ).run("image", "prune", "-f", capture_output=True)
                    if result.returncode == 0 and result.stdout.strip():
                        pruned = True
                except Exception:
                    continue

        if pruned:
            print()
            print("✓ Image pruning complete")
        else:
            print("No images to prune")
    else:
        # List images
        configs = manager.get_all_configs()
        images_data: list[dict[str, Any]] = []

        for config in configs:
            if not manager.user_exists(config):
                continue
            # VM workloads have no OCI images — container_specs() returns the
            # qcow2 download URL as the "image", which would blow up
            # `podman inspect --type=image` ("invalid reference format") and
            # abort the whole listing. Skip them.
            if config.is_vm:
                continue

            podman = manager.podman(config)
            # Iterate every container's image so multi-container (pod/bridge)
            # workloads list each image instead of crashing on the absent
            # top-level [container] block.
            for cname, image, _pull in config.container_specs():
                info = podman.image_info(image)
                if info:
                    size_bytes = info.get("Size") or 0
                    images_data.append({
                        "workload": config.name,
                        "container": cname,
                        "image": image,
                        "size_bytes": size_bytes,
                        "created": created_unix(info.get("Created"))
                    })

        if args.json:
            print(json.dumps({"images": images_data, "total": len(images_data)}, indent=2))
            return

        # Human-readable output
        print(f"{'WORKLOAD':<20} {'CONTAINER':<16} {'IMAGE':<50} {'SIZE':<10} {'PULLED':<15}")
        print("-" * 112)

        for img in images_data:
            image = img["image"]
            if len(image) > 50:
                image = image[:47] + "..."
            size_str = format_size(img["size_bytes"]) if img["size_bytes"] else "unknown"
            pulled_str = format_created(img["created"])
            print(f"{img['workload']:<20} {img['container']:<16} {image:<50} {size_str:<10} {pulled_str:<15}")

        print()
        if len(images_data) == 0:
            print("No workload images found")
        else:
            print(f"Total: {len(images_data)} workload image(s)")


# ---------------------------------------------------------------------------
# _vm_qmp_status / cmd_info
# ---------------------------------------------------------------------------

def _vm_qmp_status(name: str) -> str | None:
    """Return the QMP running status string, or None if unavailable."""
    sock_path = VM_SOCKET_DIR / name / "qmp.sock"
    if not sock_path.exists():
        return None
    qmp = QMPClient()
    try:
        qmp.connect(sock_path, timeout=3.0, recv_timeout=3.0)
        qmp.negotiate()
        reply = qmp.execute("query-status")
        if "return" in reply:
            return reply["return"].get("status", "unknown")
        return None
    except Exception:
        return None
    finally:
        qmp.close()


def _collect_control_files(config) -> list[dict]:
    """Merged view of a workload's bundle control files (build.sh, Containerfile,
    policy.cil, setup.sh, …).

    Unions the files actually present in the override tree
    (`/etc/workloads.d/<name>/`) with those in the shipped bundle tree
    (`/usr/.../workloads/<bundle>/`), plus any relative `[host].setup` the TOML
    names (surfaced even when missing, so a declared-but-absent dependency
    shows). For each, resolves the winning source — "etc" (override), "usr"
    (shipped default), or "abs" (a verbatim absolute path) — and whether the
    resolved file exists. `workload.toml` is
    excluded: the authoritative declaration is `/etc/workloads.d/<name>/workload.toml`,
    never an override target.
    """
    names: set[str] = set()
    for d in (config.override_dir, config.bundle_dir):
        if d.is_dir():
            # Recurse: a build context can carry subdirectories, and `edit`
            # accepts nested relpaths, so a nested override must be visible here
            # too (else it silently shadows without showing in the merged view).
            for p in d.rglob("*"):
                if p.is_file() and p.name != "workload.toml":
                    names.add(p.relative_to(d).as_posix())
    setup = config.config.get("host", {}).get("setup", "")
    if setup and not Path(setup).is_absolute():
        names.add(setup)

    files = []
    for name in sorted(names):
        try:
            path, source = config.resolve_control_file_with_source(name)
        except ValueError as e:
            # A traversal-laden [host].setup name can't be resolved to a path;
            # surface it as an invalid entry rather than crashing this read-only
            # merged view (the chokepoint fails closed on the build/enable path).
            files.append({
                "file": name, "source": "invalid", "path": f"({e})",
                "exists": False,
            })
            continue
        files.append({
            "file": name,
            "source": source,
            "path": str(path),
            "exists": path.exists(),
        })
    return files


def _print_control_files(config, json_mode=False):
    """Render the `info --files` merged view (systemd `systemctl cat` analogue)."""
    files = _collect_control_files(config)
    if json_mode:
        print(json.dumps({
            "workload": config.name,
            "bundle": config.bundle,
            "override_dir": str(config.override_dir),
            "bundle_dir": str(config.bundle_dir),
            "control_files": files,
        }, indent=2))
        return

    print(f"Control files for {config.name}  (bundle: {config.bundle})")
    print(f"  override dir: {config.override_dir}")
    print(f"  bundle dir:   {config.bundle_dir}")
    print()
    if not files:
        print("  No control files (bundle ships none, no overrides).")
        return

    fw = max((len(f["file"]) for f in files), default=4)
    print(f"  {'FILE':<{fw}}  {'SOURCE':<9}  PATH")
    for f in files:
        if f["source"] == "etc":
            src = "override"
        elif f["source"] == "abs":
            src = "absolute"
        elif f["source"] == "invalid":
            src = "invalid"
        else:
            src = "shipped" if f["exists"] else "missing"
        print(f"  {f['file']:<{fw}}  {src:<9}  {f['path']}")
    print()
    print("  override = /etc copy wins · shipped = /usr default · "
          "absolute = verbatim path · missing = declared but absent")
    print(f"  Edit a control file:  sudo workloadctl edit {config.name} <file>")


def cmd_info(args, manager: WorkloadManager):
    """Show detailed workload information"""
    from substrate import _vm_guest_ip
    import grp as _grp
    config = WorkloadConfig(args.workload)

    # --files: the merged control-file view (the discoverability answer to lazy
    # override). Generic across VM/container, so handle it before the kind split.
    if getattr(args, "files", False):
        _print_control_files(config, json_mode=args.json)
        return

    user_exists = manager.user_exists(config)

    if config.is_vm:
        vm_cfg = config.config.get("vm", {})
        home_dir = config.home_dir

        # Disk info — system.qcow2 is reconstructible (state/); data.qcow2 is
        # precious and lives in the backup-captured data/ subtree.
        system_disk = home_dir / "system.qcow2"
        data_disk = config.data_dir / "data.qcow2"
        gens = sorted(
            int(p.suffix[5:])
            for p in home_dir.glob("system.qcow2.gen-*")
            if p.suffix[5:].isdigit()
        ) if home_dir.exists() else []

        # Guest IP from DHCP leases
        guest_ip = _vm_guest_ip(config.name, config.vm_bridge)

        # QMP status
        qmp_status = _vm_qmp_status(config.name)

        # User identity
        vm_uid = None
        if user_exists:
            try:
                vm_uid = config.uid
            except Exception:
                pass
        vm_subuid_start, vm_subuid_count = _read_subid(config.username, "/etc/subuid") if user_exists else (None, None)
        vm_subgid_start, vm_subgid_count = _read_subid(config.username, "/etc/subgid") if user_exists else (None, None)

        # Service state
        svc_props = _systemctl_show(
            config.service_name, ["ActiveState", "ActiveEnterTimestamp"],
            extra_args=["--timestamp=unix"],
        )
        service_state = svc_props.get("ActiveState", "") or "inactive"
        active_since = _parse_active_since(svc_props.get("ActiveEnterTimestamp", ""))

        vm_info = {
            "workload": {"name": config.name,
                         "config_path": str(config.path), "enabled": config.enabled},
            "vm": {
                "memory": vm_cfg.get("memory", "1024M"),
                "vcpus": vm_cfg.get("vcpus", 1),
                "image_source": (vm_cfg.get("cloud_image_url") or vm_cfg.get("local_image")
                                 or vm_cfg.get("image") or "(none)"),
                "data_disk_size": vm_cfg.get("data_disk_size", ""),
                "system_disk": str(system_disk) if system_disk.exists() else None,
                "data_disk": str(data_disk) if data_disk.exists() else None,
                "rollback_generations": gens,
                "guest_ip": guest_ip,
                "qmp_status": qmp_status,
            },
            "user": {
                "name": config.username,
                "uid": vm_uid,
                "exists": user_exists,
                "subuid": {"start": vm_subuid_start, "count": vm_subuid_count},
                "subgid": {"start": vm_subgid_start, "count": vm_subgid_count},
            },
            "service": {"name": config.service_name, "state": service_state,
                        "active_since": active_since},
        }

        if args.json:
            print(json.dumps(vm_info, indent=2))
            return

        print(f"Workload: {config.name}  [VM]")
        print(f"Config:   {config.path}")
        print(f"Status:   {'enabled' if config.enabled else 'disabled'}")
        print()
        print("VM:")
        print(f"  Memory: {vm_cfg.get('memory', '1024M')}  vCPUs: {vm_cfg.get('vcpus', 1)}")
        src = (vm_cfg.get("cloud_image_url") or vm_cfg.get("local_image")
               or vm_cfg.get("image") or "(none)")
        print(f"  Source: {src}")
        if system_disk.exists():
            print(f"  System disk: {system_disk}")
        if data_disk.exists():
            print(f"  Data disk:   {data_disk}")
        if gens:
            print(f"  Rollback generations: {', '.join(f'gen-{g}' for g in gens)}")
        if guest_ip:
            print(f"  Guest IP:   {guest_ip}")
        if qmp_status:
            print(f"  QMP status: {qmp_status}")
        print()
        print("User:")
        print(f"  Name: {config.username}")
        if user_exists:
            if vm_uid is not None:
                print(f"  UID:    {vm_uid}")
            if vm_subuid_start is not None:
                print(f"  SubUID: {vm_subuid_start} ({vm_subuid_count} IDs)")
            if vm_subgid_start is not None:
                print(f"  SubGID: {vm_subgid_start} ({vm_subgid_count} IDs)")
        print()
        print("Service:")
        print(f"  Name: {config.service_name}")
        if service_state == "active" and active_since is not None:
            since_str = datetime.datetime.fromtimestamp(active_since).strftime("%Y-%m-%d %H:%M:%S")
            print(f"  Active: active (running) since {since_str}")
        else:
            print(f"  Active: {service_state}")
        print()
        print("Quick commands:")
        print(f"  Console:  workloadctl shell {config.name}")
        if guest_ip:
            print(f"  SSH:      workloadctl exec {config.name} -- bash")
        print(f"  Logs:     workloadctl logs -f {config.name}")
        print(f"  Update:   sudo workloadctl update {config.name}")
        print(f"  Rollback: sudo workloadctl rollback {config.name}")
        return

    # Container(s)
    if config.is_multi:
        per_container = []
        for cname, img in config.container_images():
            iid = None
            if user_exists:
                try:
                    iid = manager.podman(config).image_id(img)
                except Exception:
                    iid = None
            per_container.append({
                "name": cname,
                "podman_name": config.podman_container_name(cname),
                "image": img,
                "image_id": iid,
            })
        image_id = None
    else:
        image_id = manager.get_image_id(config) if user_exists else None
        per_container = None

    # User
    uid = None
    user_home = None
    groups = None
    if user_exists:
        try:
            uid = config.uid
        except Exception:
            pass
        try:
            pw = pwd.getpwnam(config.username)
            user_home = pw.pw_dir
            groups = [_grp.getgrgid(gid).gr_name for gid in os.getgrouplist(config.username, pw.pw_gid)]
        except (KeyError, OSError):
            pass
    subuid_start, subuid_count = _read_subid(config.username, "/etc/subuid") if user_exists else (None, None)
    subgid_start, subgid_count = _read_subid(config.username, "/etc/subgid") if user_exists else (None, None)

    # Storage
    storage_home = None
    storage_exists = None
    storage_size = None
    if user_exists:
        home_path = config.home_dir
        storage_home = str(home_path)
        storage_exists = home_path.exists()
        if storage_exists:
            du = subprocess.run(["du", "-sh", str(home_path)], capture_output=True, text=True)
            storage_size = du.stdout.split()[0] if du.returncode == 0 else None

    # Service state + active_since in one call
    svc_props = _systemctl_show(
        config.service_name, ["ActiveState", "ActiveEnterTimestamp"],
        extra_args=["--timestamp=unix"],
    )
    service_state = svc_props.get("ActiveState", "") or "inactive"
    active_since = _parse_active_since(svc_props.get("ActiveEnterTimestamp", ""))

    info_data: dict[str, Any] = {
        "workload": {
            "name": config.name,
            "config_path": str(config.path),
            "enabled": config.enabled,
            "mode": config.mode,
        },
        "container": None if config.is_multi else {
            "name": config.container_name,
            "image": config.image,
            "image_id": image_id
        },
        "containers": per_container,
        "user": {
            "name": config.username,
            "uid": uid,
            "exists": user_exists,
            "home": user_home,
            "groups": groups,
            "subuid": {"start": subuid_start, "count": subuid_count},
            "subgid": {"start": subgid_start, "count": subgid_count},
        },
        "network": {
            "mode": config.get_network_mode(),
            "ports": config.get_ports(),
            "accessible_at": get_substrate(config, manager).endpoints(),
        },
        "storage": {
            "home": storage_home,
            "exists": storage_exists,
            "size": storage_size
        },
        "service": {
            "name": config.service_name,
            "state": service_state,
            "active_since": active_since
        }
    }

    if args.json:
        print(json.dumps(info_data, indent=2))
        return

    # Human-readable output
    print(f"Workload: {config.name}")
    print(f"Config:   {config.path}")
    print(f"Status:   {'enabled' if config.enabled else 'disabled'}")
    print()

    if config.is_multi:
        assert per_container is not None
        print(f"Containers ({config.mode} mode):")
        for c in per_container:
            print(f"  - {c['name']}: {c['image']}"
                  + (f" (sha256:{c['image_id'][:12]}...)" if c["image_id"] else ""))
        print()
    else:
        print("Container:")
        print(f"  Name:   {config.container_name}")
        print(f"  Image:  {config.image}")
        if image_id:
            print(f"  ID:     sha256:{image_id[:12]}...")
        print()

    print("User:")
    print(f"  Name:   {config.username}")
    if user_exists:
        if uid is not None:
            print(f"  UID:    {uid}")
        if user_home is not None:
            print(f"  Home:   {user_home}")
        if groups is not None:
            print(f"  Groups: {','.join(groups)}")
        if subuid_start is not None:
            print(f"  SubUID: {subuid_start} ({subuid_count} IDs)")
        if subgid_start is not None:
            print(f"  SubGID: {subgid_start} ({subgid_count} IDs)")
    else:
        print("  (User not created - workload not enabled)")
    print()

    print("Network:")
    print(f"  Mode:   {info_data['network']['mode']}")
    if info_data["network"]["ports"]:
        print(f"  Ports:  {', '.join(info_data['network']['ports'])}")
        accessible = info_data["network"]["accessible_at"]
        if accessible:
            print("  Accessible at:")
            for ep in accessible:
                if ep["container"]:
                    print(f"    {ep['host']} → container:{ep['container']}")
                else:
                    print(f"    {ep['host']}")
    print()

    print("Storage:")
    if storage_home is not None:
        if storage_exists:
            print(f"  Home:   {storage_home} ({storage_size or 'unknown'} used)")
        else:
            print(f"  Home:   {storage_home} (not created)")
    print()

    print("Service:")
    print(f"  Name:   {config.service_name}")
    if service_state == "active" and active_since is not None:
        since_str = datetime.datetime.fromtimestamp(active_since).strftime("%Y-%m-%d %H:%M:%S")
        print(f"  Active: active (running) since {since_str}")
    else:
        print(f"  Active: {service_state}")
    print()

    print("Quick commands:")
    print(f"  Shell:    workloadctl shell {config.name}")
    print(f"  Logs:     workloadctl logs -f {config.name}")
    print(f"  Recreate: workloadctl recreate {config.name}")


# ---------------------------------------------------------------------------
# stats helpers + cmd_stats
# ---------------------------------------------------------------------------

def _stats_parse_percent(v) -> float:
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return float(str(v).strip().rstrip("%"))
    except (ValueError, AttributeError):
        return 0.0


def _stats_parse_io(s: str) -> tuple[int, int]:
    parts = str(s).split(" / ")
    if len(parts) == 2:
        return parse_size_bytes(parts[0]), parse_size_bytes(parts[1])
    return 0, 0


def _stats_parse_mem(row: dict) -> tuple[int, int]:
    """Return (mem_usage_bytes, mem_limit_bytes) from a podman stats row.

    Handles both the combined 'X / Y' string format (older podman) and
    separate numeric fields (newer podman).
    """
    raw = row.get("mem_usage") or row.get("MemUsage", "0")
    if isinstance(raw, str) and " / " in raw:
        return _stats_parse_io(raw)
    return (parse_size_bytes(raw),
            parse_size_bytes(row.get("mem_limit") or row.get("MemLimit", 0)))


def _stats_parse_row(row: dict, config, target_names: list[str]) -> dict:
    """Build one `workloadctl stats --json` row from a raw podman stats row."""
    net_in, net_out = _stats_parse_io(row.get("net_io") or row.get("NetIO", "0 / 0"))
    blk_in, blk_out = _stats_parse_io(row.get("block_io") or row.get("BlockIO", "0 / 0"))
    mem_u, mem_l = _stats_parse_mem(row)
    return {
        "workload": config.name,
        "username": config.username,
        "container": row.get("name") or row.get("Name", target_names[0]),
        "cpu_percent": _stats_parse_percent(row.get("cpu_percent") or row.get("CPU", 0)),
        "mem_usage": mem_u,
        "mem_limit": mem_l,
        "mem_percent": _stats_parse_percent(row.get("mem_percent") or row.get("MemPerc", 0)),
        "net_input": net_in,
        "net_output": net_out,
        "block_input": blk_in,
        "block_output": blk_out,
        "pids": int(row.get("pids") or row.get("PIDs", 0)),
    }


def _stats_one(config, manager, target_names, *, json_out, follow):
    """Run podman stats for one workload's containers via ContainerSubstrate."""
    substrate = get_substrate(config, manager)
    try:
        return substrate.resource_usage(
            target_names, json_out=json_out, follow=follow,
        )
    except NotApplicable as e:
        print(f"stats: not applicable for {config.name} — {e.reason}", file=sys.stderr)
        return None


def cmd_stats(args, manager: WorkloadManager):
    """Show resource usage statistics"""
    if args.json and args.follow:
        print("Error: --json is incompatible with --follow", file=sys.stderr)
        sys.exit(1)

    if args.workload:
        config = WorkloadConfig(args.workload)

        # VM workloads always get NotApplicable — check before user_exists so
        # an unprovisioned VM doesn't hide the "not applicable" message.
        substrate = get_substrate(config, manager)
        if config.is_vm:
            try:
                substrate.resource_usage([])
            except NotApplicable as e:
                print(f"stats: not applicable for {config.name} — {e.reason}")
                sys.exit(0)

        if not manager.user_exists(config):
            print("Error: Workload user not found. Is workload enabled?", file=sys.stderr)
            sys.exit(1)

        # substrate already resolved above
        target_names = config.podman_targets()

        try:
            result = substrate.resource_usage(
                target_names, json_out=args.json, follow=args.follow,
            )
        except NotApplicable as e:
            print(f"stats: not applicable for {config.name} — {e.reason}")
            sys.exit(0)

        if args.json:
            stats_list = []
            if result is not None and result.returncode == 0 and result.stdout.strip():
                raw = json.loads(result.stdout)
                for row in (raw if isinstance(raw, list) else [raw]):
                    stats_list.append(_stats_parse_row(row, config, target_names))
            print(json.dumps({"stats": stats_list}, indent=2))
    else:
        configs = manager.get_all_configs(enabled_only=True)

        def _running_targets(c):
            if c.is_vm or not manager.user_exists(c):
                return []
            names = c.podman_targets()
            return [n for n in names if manager.podman(c).container_exists(n)]

        running = [(c, names) for c in configs for names in [_running_targets(c)] if names]

        if args.json:
            stats_list = []
            for config, target_names in running:
                substrate = get_substrate(config, manager)
                try:
                    result = substrate.resource_usage(target_names, json_out=True)
                except NotApplicable:
                    continue
                if result is not None and result.returncode == 0 and result.stdout.strip():
                    raw = json.loads(result.stdout)
                    for row in (raw if isinstance(raw, list) else [raw]):
                        stats_list.append(_stats_parse_row(row, config, target_names))
            print(json.dumps({"stats": stats_list}, indent=2))
            return

        if not running:
            print("No running workload containers found")
            return

        for config, target_names in running:
            substrate = get_substrate(config, manager)
            try:
                if args.follow:
                    print(f"Note: --follow with multiple workloads shows only {config.name}")
                    substrate.resource_usage(target_names, follow=True)
                    return
                substrate.resource_usage(target_names)
            except NotApplicable:
                continue
            print()


# ---------------------------------------------------------------------------
# _multi_container_health / cmd_health
# ---------------------------------------------------------------------------

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
            # Extract port number
            port = port_spec.split(':')[-1].split('/')[0]
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
