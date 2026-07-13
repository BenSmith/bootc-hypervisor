"""
cmd_create — scaffold a new workload config from CLI arguments.

Writes the TOML, validates it, and unlinks it again if it doesn't pass: a
config that was never valid should not be left on disk to be found later.
"""
import argparse
import sys

from workload_lib import workload_config_path
from validation import validate_workload_name
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    require_root,
    toml_string,
)
from cmd_enable import cmd_enable
from cmd_validate import validate_single


def cmd_create(args, manager: WorkloadManager):
    """Create a new workload configuration"""
    require_root()

    name = args.name
    image = args.image

    try:
        validate_workload_name(name)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Check if config already exists
    config_path = workload_config_path(name)
    if config_path.parent.exists():
        print(f"Error: Workload config already exists: {config_path}", file=sys.stderr)
        print(f"Use 'workloadctl edit {name}' to modify it", file=sys.stderr)
        sys.exit(1)

    config_path.parent.mkdir()

    # Build configuration
    config_lines = [
        "[workload]",
        f"name = {toml_string(name)}",
    ]

    config_lines.extend([
        "",
        "[container]",
        f"image = {toml_string(image)}",
    ])

    if args.systemd:
        config_lines.append(f"systemd = {toml_string(args.systemd)}")

    # Add optional sections
    if args.groups:
        groups_list = ", ".join([toml_string(g) for g in args.groups])
        config_lines.extend([
            "",
            "[security]",
            f"extra_groups = [{groups_list}]",
        ])

    # Devices section - add if any devices specified
    if args.device or args.gpu or args.input or args.audio or args.virtualization:
        config_lines.extend(["", "[devices]"])

        # Generic device passthrough
        if args.device:
            devices_list = ", ".join([toml_string(d) for d in args.device])
            config_lines.append(f"devices = [{devices_list}]")

        # Convenience flags
        if args.gpu:
            config_lines.append(f"gpu = {toml_string(args.gpu)}")

        if args.input:
            config_lines.append("input = true")

        if args.audio:
            config_lines.append("audio = true")

        if args.virtualization:
            config_lines.append("virtualization = true")

    if args.network or args.ports:
        config_lines.extend(["", "[network]"])

        if args.network:
            config_lines.append(f"mode = {toml_string(args.network)}")
        elif args.ports:
            # If ports specified but no mode, default to pasta
            config_lines.append('mode = "pasta"')

        # Add ports if specified and mode supports them (not host or none)
        if args.ports:
            mode = args.network if args.network else "pasta"
            if mode not in ["host", "none"]:
                ports_list = ", ".join([toml_string(p) for p in args.ports])
                config_lines.append(f"ports = [{ports_list}]")

    if args.volumes:
        volumes_list = ", ".join([toml_string(v) for v in args.volumes])
        config_lines.extend([
            "",
            "[storage]",
            f"volumes = [{volumes_list}]",
        ])

    has_resources = any([
        args.cpu_quota, args.cpu_weight, args.memory_max, args.memory_high,
        args.memory_swap_max, args.io_weight, args.tasks_max, args.shm_size
    ])

    if has_resources:
        config_lines.extend(["", "[resources]"])

        if args.shm_size:
            config_lines.append(f"shm_size = {toml_string(args.shm_size)}")

        if args.cpu_quota:
            config_lines.append(f"cpu_quota = {toml_string(args.cpu_quota)}")

        if args.cpu_weight:
            config_lines.append(f"cpu_weight = {args.cpu_weight}")

        if args.memory_max:
            config_lines.append(f"memory_max = {toml_string(args.memory_max)}")

        if args.memory_high:
            config_lines.append(f"memory_high = {toml_string(args.memory_high)}")

        if args.memory_swap_max:
            config_lines.append(f"memory_swap_max = {toml_string(args.memory_swap_max)}")

        if args.io_weight:
            config_lines.append(f"io_weight = {args.io_weight}")

        if args.tasks_max:
            config_lines.append(f"tasks_max = {args.tasks_max}")

    # Write config file
    config_content = "\n".join(config_lines) + "\n"

    print(f"Creating workload: {name}")
    print(f"  Config: {config_path}")
    print(f"  Image:  {image}")
    print(f"  User:   _wl-{name} (UID assigned on first enable)")
    print()

    config_path.write_text(config_content)
    print(f"✓ Created {config_path}")

    # Validate the new config
    print()
    print("Validating configuration...")
    print()
    try:
        config = WorkloadConfig(name)
        result = validate_single(config, manager, json_mode=False)
        if not result["passed"]:
            print()
            print("Warning: Validation found issues. Fix them before enabling.", file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        print(f"Error: Failed to validate config: {e}", file=sys.stderr)
        config_path.unlink()
        sys.exit(1)

    if args.enable:
        print()
        print("Enabling workload...")
        enable_args = argparse.Namespace(workload=name)
        cmd_enable(enable_args, manager)
    else:
        print()
        print("Next steps:")
        print(f"  Edit config:  workloadctl edit {name}")
        print(f"  Enable:       workloadctl enable {name}")

