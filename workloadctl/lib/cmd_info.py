"""
cmd_info — the deep single-workload dump: identity, image(s), user + subid
ranges, network, storage, service state, and (with --files) the merged
control-file view.
"""

import datetime
import json
import os
from pathlib import Path
import pwd
import subprocess
from typing import Any

from vm import VM_SOCKET_DIR
from qmp import QMPClient
from service_runtime import parse_active_since, systemctl_show
from substrate import get_substrate
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
)


# ---------------------------------------------------------------------------
# Helpers
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

# ---------------------------------------------------------------------------
# cmd_info
# ---------------------------------------------------------------------------

def cmd_info(args, manager: WorkloadManager):
    """Show detailed workload information"""
    from substrate_vm import _vm_guest_ip
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
        svc_props = systemctl_show(
            config.service_name, ["ActiveState", "ActiveEnterTimestamp"],
            extra_args=["--timestamp=unix"],
        )
        service_state = svc_props.get("ActiveState", "") or "inactive"
        active_since = parse_active_since(svc_props.get("ActiveEnterTimestamp", ""))

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
    svc_props = systemctl_show(
        config.service_name, ["ActiveState", "ActiveEnterTimestamp"],
        extra_args=["--timestamp=unix"],
    )
    service_state = svc_props.get("ActiveState", "") or "inactive"
    active_since = parse_active_since(svc_props.get("ActiveEnterTimestamp", ""))

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
