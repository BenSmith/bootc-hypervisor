"""
cmd_admin — workload admin commands: create, edit, validate, diagnose.
"""

import argparse
import grp
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

from workload_lib import (
    expand_volume_path,
    GENERATOR_OWNED_DIRECTIVES,
    parse_memory_mib,
    selinux_module_name,
    selinux_type_name,
    units_outdated,
    validate_workload_config,
    validate_workload_name,
    workload_config_path,
    workload_service_units,
)
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    WorkloadUserNotFound,
    require_root,
    toml_string,
)
from service_runtime import restart_workload_service
from substrate import service_active


# ---------------------------------------------------------------------------
# validate_single (shared by create, edit, validate)
# ---------------------------------------------------------------------------

def validate_single(config: WorkloadConfig, manager: WorkloadManager, json_mode=False) -> dict:
    """Validate a single workload config. Returns dict with validation results."""
    errors = 0
    warnings = 0
    checks = []

    checks.append({
        "check": "required_fields",
        "passed": True,
        "severity": "ok",
        "message": f"Required fields present: name={config.name}"
    })

    # Schema validation — the same checks the boot generator runs, surfaced here
    # so `validate`/`install` catch config errors before a boot rather than after.
    schema_errors = validate_workload_config(config.config)
    if schema_errors:
        for msg in schema_errors:
            checks.append({
                "check": "schema",
                "passed": False,
                "severity": "error",
                "message": msg,
            })
            errors += 1
    else:
        checks.append({
            "check": "schema",
            "passed": True,
            "severity": "ok",
            "message": "Schema valid"
        })

    username_len = len(config.username)
    if username_len >= 32:
        checks.append({
            "check": "username_length",
            "passed": False,
            "severity": "error",
            "message": f"Username too long: {config.username} ({username_len} chars, max 31)",
            "fix": "Use shorter workload name"
        })
        errors += 1
    else:
        checks.append({
            "check": "username_length",
            "passed": True,
            "severity": "ok",
            "message": f"Username length OK ({username_len} chars)"
        })

    # Check if UID has been assigned
    try:
        uid = config.uid
        if uid < 10000 or uid > 52948:
            checks.append({
                "check": "uid_range",
                "passed": False,
                "severity": "error",
                "message": f"UID out of range: {uid} (should be 10000-52948)"
            })
            errors += 1
        else:
            checks.append({
                "check": "uid_range",
                "passed": True,
                "severity": "ok",
                "message": f"UID in valid range: {uid} (10000-52948)"
            })
    except WorkloadUserNotFound:
        checks.append({
            "check": "uid_assigned",
            "passed": True,
            "severity": "ok",
            "message": "UID not yet assigned (will be assigned on first enable)"
        })

    # Check name uniqueness (workload names must be unique)
    all_configs = manager.get_all_configs()
    conflicts = [c for c in all_configs
                 if c.name == config.name and c.path != config.path]
    if conflicts:
        checks.append({
            "check": "name_uniqueness",
            "passed": False,
            "severity": "error",
            "message": f"Name conflict: '{config.name}' also used in {conflicts[0].path}"
        })
        errors += 1
    else:
        checks.append({
            "check": "name_uniqueness",
            "passed": True,
            "severity": "ok",
            "message": "Name is unique"
        })

    _valid_lifecycles = {"pet", "cattle"}
    if config.lifecycle not in _valid_lifecycles:
        checks.append({
            "check": "lifecycle",
            "passed": False,
            "severity": "error",
            "message": (
                f"Invalid lifecycle value: {config.lifecycle!r}. "
                f"Must be one of: {', '.join(sorted(_valid_lifecycles))}"
            ),
            "fix": 'Set [workload] lifecycle = "pet" or "cattle" (or omit for the default "cattle")'
        })
        errors += 1
    else:
        checks.append({
            "check": "lifecycle",
            "passed": True,
            "severity": "ok",
            "message": f"Lifecycle policy: {config.lifecycle}"
        })

    # snapshot_keep bounds the pet overlay snapshot repository. Only the
    # explicit field is checked; omitting it uses the default (3).
    raw_snapshot_keep = config.config.get("workload", {}).get("snapshot_keep")
    if raw_snapshot_keep is not None and (
        not isinstance(raw_snapshot_keep, int)
        or isinstance(raw_snapshot_keep, bool)
        or raw_snapshot_keep < 1
    ):
        checks.append({
            "check": "snapshot_keep",
            "passed": False,
            "severity": "error",
            "message": (
                f"[workload].snapshot_keep must be a positive integer, "
                f"got {raw_snapshot_keep!r}"
            ),
            "fix": "Set [workload] snapshot_keep to a positive integer (or omit for the default 3)",
        })
        errors += 1

    # `bundle` goes straight into a /usr/share/workloadctl/workloads/<bundle>/
    # path for control-file lookups, so reject anything that isn't a plain
    # workload-style name before any path is built. Only the explicit field is
    # checked; the default (the workload name) is validated on its own.
    raw_bundle = config.config.get("workload", {}).get("bundle")
    if raw_bundle is not None:
        try:
            validate_workload_name(raw_bundle)
            checks.append({
                "check": "bundle",
                "passed": True,
                "severity": "ok",
                "message": f"Bundle: {config.bundle}",
            })
        except ValueError as e:
            checks.append({
                "check": "bundle",
                "passed": False,
                "severity": "error",
                "message": f"Invalid bundle {raw_bundle!r}: {e}",
                "fix": "bundle is a directory name (lowercase letters, digits, hyphens)",
            })
            errors += 1

    # `selinux_policy` is now boolean-only. A leftover string from the old form
    # is truthy, so it silently enables policy keyed on `[workload] bundle`
    # (default = name) — NOT the directory the string named. Surface it.
    raw_selinux = config.config.get("security", {}).get("selinux_policy")
    if isinstance(raw_selinux, str):
        checks.append({
            "check": "selinux_policy_string",
            "passed": False,
            "severity": "warning",
            "message": f"selinux_policy = {raw_selinux!r} is a string; the field "
                       f"is now boolean-only and this is treated as `true` with "
                       f"the CIL sourced from bundle '{config.bundle}', not "
                       f"'{raw_selinux}'.",
            "fix": f'Set selinux_policy = true and, if the policy lives elsewhere, '
                   f'[workload] bundle = "{raw_selinux}".',
        })
        warnings += 1

    # [build] section: the containerfile names a file *inside* the build
    # context, so it must be a plain relative path (no traversal). Only checked
    # when the section is present.
    if config.config.get("build"):
        cf = config.build_containerfile
        if Path(cf).is_absolute() or ".." in Path(cf).parts:
            checks.append({
                "check": "build_containerfile",
                "passed": False,
                "severity": "error",
                "message": f"Invalid [build] containerfile {cf!r}: must be a "
                           f"relative path inside the build context (no '..')",
                "fix": 'e.g. containerfile = "Containerfile"',
            })
            errors += 1
        else:
            summary = f"containerfile={cf}"
            if config.build_script:
                summary = f"script={config.build_script}"
            checks.append({
                "check": "build",
                "passed": True,
                "severity": "ok",
                "message": f"Build: {summary}",
            })

    required_file_paths = {e["path"] for e in config.get_required_files()}
    workload_root = str(config.home_dir.parent)
    for vol in config.get_volumes():
        expanded_vol = expand_volume_path(vol, str(config.home_dir))
        host_path = expanded_vol.split(':')[0]
        if Path(host_path).exists():
            checks.append({
                "check": "volume_path",
                "passed": True,
                "severity": "ok",
                "message": f"Volume path exists: {host_path}",
                "path": host_path
            })
        elif host_path in required_file_paths:
            checks.append({
                "check": "volume_path",
                "passed": True,
                "severity": "ok",
                "message": f"Volume path listed in required_files (setup needed): {host_path}",
                "path": host_path
            })
        elif host_path.startswith(workload_root + "/"):
            checks.append({
                "check": "volume_path",
                "passed": True,
                "severity": "ok",
                "message": f"Volume path will be created on enable: {host_path}",
                "path": host_path
            })
        else:
            checks.append({
                "check": "volume_path",
                "passed": False,
                "severity": "error",
                "message": f"Volume path does not exist: {host_path}",
                "path": host_path,
                "fix": f"mkdir -p {host_path}"
            })
            errors += 1

    for group in config.get_extra_groups():
        try:
            grp.getgrnam(group)
            checks.append({
                "check": "group_exists",
                "passed": True,
                "severity": "ok",
                "message": f"Group exists: {group}",
                "group": group
            })
        except KeyError:
            checks.append({
                "check": "group_exists",
                "passed": False,
                "severity": "error",
                "message": f"Group does not exist: {group}",
                "group": group
            })
            errors += 1

    # vm.memory in 'K' notation truncates via integer division to MiB
    # (parse_memory_mib rounds down: qemu accepts K but it's not a useful VM
    # RAM unit) — surface the precision loss so an operator doesn't silently
    # end up with a smaller VM than the config implies.
    vm_memory = config.config.get("vm", {}).get("memory")
    if isinstance(vm_memory, str) and vm_memory.strip().upper().endswith("K"):
        try:
            n = int(vm_memory.strip()[:-1])
            mib = parse_memory_mib(vm_memory)
        except (ValueError, TypeError):
            pass  # malformed value is already reported by the schema check above
        else:
            if n % 1024 != 0:
                checks.append({
                    "check": "vm_memory_precision",
                    "passed": True,
                    "severity": "warning",
                    "message": f"vm.memory = {vm_memory!r} is not an exact number "
                               f"of MiB; truncated to {mib}M.",
                    "fix": f'memory = "{mib}M"',
                })
                warnings += 1

    # Warn if custom_directives overrides something the generator already sets.
    custom_directives = config.config.get("resources", {}).get("custom_directives", {})
    for directive in custom_directives:
        if directive in GENERATOR_OWNED_DIRECTIVES:
            checks.append({
                "check": "custom_directives_conflict",
                "passed": True,
                "severity": "warning",
                "message": f"custom_directives overrides '{directive}' which is managed by the generator — may have no effect or cause unexpected behaviour",
            })
            warnings += 1

    passed = errors == 0
    result = {
        "workload": config.name,
        "passed": passed,
        "errors": errors,
        "warnings": warnings,
        "checks": checks
    }

    # Human-readable output if not JSON mode
    if not json_mode:
        print(f"Validating: {config.name}")
        print()

        for check in checks:
            severity = check.get("severity", "ok" if check["passed"] else "error")
            if severity == "error":
                symbol = "✗"
            elif severity == "warning":
                symbol = "⚠"
            else:
                symbol = "✓"
            print(f"{symbol} {check['message']}")
            if "fix" in check:
                print(f"  Suggested fix: {check['fix']}")

        print()
        if passed:
            if warnings == 0:
                print("✓ Validation passed")
            else:
                print(f"⚠ Validation passed with {warnings} warning(s)")
        else:
            print(f"✗ Validation failed with {errors} error(s) and {warnings} warning(s)")
            print("  Fix errors before enabling workload")

    return result


# ---------------------------------------------------------------------------
# cmd_create
# ---------------------------------------------------------------------------

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
        # Import here to avoid circular; cmd_lifecycle imports cmd_admin
        from cmd_lifecycle import cmd_enable
        enable_args = argparse.Namespace(workload=name)
        cmd_enable(enable_args, manager)
    else:
        print()
        print("Next steps:")
        print(f"  Edit config:  workloadctl edit {name}")
        print(f"  Enable:       workloadctl enable {name}")


# ---------------------------------------------------------------------------
# cmd_validate
# ---------------------------------------------------------------------------

def _load_config_or_exit(name: str, json_mode: bool = False) -> WorkloadConfig:
    """Load a single WorkloadConfig for a report verb (validate/diagnose).

    These verbs exist to *report* on a config, so a broken or absent one (bad
    name/dir, malformed TOML, missing file, masked) is a normal negative result
    — not a workloadctl bug. Construction failures are surfaced as a clean
    nonzero exit rather than escaping to the top-level "this looks like a bug"
    traceback handler. Mirrors the load-failure tolerance in
    WorkloadManager.get_all_configs.
    """
    try:
        return WorkloadConfig(name)
    except Exception as e:
        if json_mode:
            print(json.dumps({"workload": name, "passed": False, "error": str(e)}, indent=2))
        else:
            print(f"Error: cannot load workload '{name}': {e}", file=sys.stderr)
        sys.exit(1)


def cmd_validate(args, manager: WorkloadManager):
    """Validate workload configuration"""
    if args.all:
        configs = manager.get_all_configs()
        results = []
        success = True
        for config in configs:
            result = validate_single(config, manager, json_mode=args.json)
            results.append(result)
            if not result["passed"]:
                success = False
            if not args.json:
                print()

        if args.json:
            print(json.dumps({"validation_results": results, "all_passed": success}, indent=2))
        sys.exit(0 if success else 1)
    else:
        if not args.workload:
            print("Error: Workload name required (or use --all)", file=sys.stderr)
            sys.exit(1)
        config = _load_config_or_exit(args.workload, json_mode=args.json)
        result = validate_single(config, manager, json_mode=args.json)

        if args.json:
            print(json.dumps(result, indent=2))
        sys.exit(0 if result["passed"] else 1)


# ---------------------------------------------------------------------------
# cmd_diagnose
# ---------------------------------------------------------------------------

def collect_diagnose_checks(config, manager: WorkloadManager):
    """Run the diagnose check battery and return (checks, passed).

    checks is the ordered list of {check, passed, message[, fix]} dicts;
    passed is True iff every check passed. Pure collection — no root
    check, no printing, no exit — shared by cmd_diagnose and doctor.
    """
    checks = []
    linger_enabled = False  # set by Check 3; referenced by the session/runtime checks

    def _check(name, passed, message, fix=None):
        entry = {"check": name, "passed": passed, "message": message}
        if fix:
            entry["fix"] = fix
        checks.append(entry)

    # Check 1: User exists
    user_exists = manager.user_exists(config)
    if user_exists:
        _check("user_exists", True, f"User exists: {config.username} (UID {config.uid})")
    else:
        _check("user_exists", False, f"User does not exist: {config.username}",
               fix="sudo workloadctl enable " + config.name)

    # Check 2: Subuid/subgid configured
    if user_exists:
        subuid_exists = False
        subgid_exists = False
        try:
            with open("/etc/subuid", "r") as f:
                if any(line.startswith(f"{config.username}:") for line in f):
                    subuid_exists = True
        except FileNotFoundError:
            pass
        try:
            with open("/etc/subgid", "r") as f:
                if any(line.startswith(f"{config.username}:") for line in f):
                    subgid_exists = True
        except FileNotFoundError:
            pass

        if subuid_exists and subgid_exists:
            _check("subid_configured", True, "Subuid/subgid configured")
        else:
            _check("subid_configured", False, "Subuid/subgid not configured",
                   fix=f"sudo /usr/libexec/workloadctl/workload-ensure-user {config.name}")

    # Check 3: Linger enabled
    if user_exists:
        linger_result = subprocess.run(
            ["loginctl", "show-user", str(config.uid), "--property=Linger", "--value"],
            capture_output=True, text=True
        )
        linger_enabled = linger_result.returncode == 0 and linger_result.stdout.strip() == "yes"
        if linger_enabled:
            _check("linger_enabled", True, "Linger enabled")
        else:
            _check("linger_enabled", False, "Linger not enabled",
                   fix=f"sudo loginctl enable-linger {config.uid}")

    # Check 3b: User manager session live. Rootless workloads need user@<uid> up
    # (linger keeps it alive) for the user D-Bus that crun's cgroup manager talks
    # to. If linger is on but the session is dead, the safe fix is to RESTART the
    # user manager — never `loginctl terminate-user`, which also tears down
    # /run/user/<uid> and leaves workloads failing with 226/NAMESPACE.
    if user_exists and linger_enabled:
        session_active = subprocess.run(
            ["systemctl", "is-active", f"user@{config.uid}.service"],
            capture_output=True, text=True,
        ).returncode == 0
        if session_active:
            _check("user_session", True, f"User manager session active: user@{config.uid}.service")
        else:
            _check("user_session", False,
                   f"User manager session not active despite linger: user@{config.uid}.service",
                   fix=f"sudo systemctl restart user@{config.uid}.service  "
                       f"(do NOT use 'loginctl terminate-user' — it removes /run/user/{config.uid} "
                       f"→ 226/NAMESPACE)")

    # Check: per-workload SELinux module loaded (only if the workload ships one)
    if config.selinux_policy:
        module = selinux_module_name(config.name)
        if not shutil.which("semodule"):
            _check("selinux_module", False,
                   "SELinux tooling (semodule) not found",
                   fix="sudo dnf install policycoreutils")
        else:
            loaded = subprocess.run(["semodule", "-l"], capture_output=True, text=True)
            if module in loaded.stdout.split():
                _check("selinux_module", True,
                       f"SELinux module loaded: {module} "
                       f"(type {selinux_type_name(config.name)})")
            else:
                _check("selinux_module", False,
                       f"SELinux module not loaded: {module}",
                       fix=f"sudo workloadctl enable {config.name}")

    # Check 4: Runtime directory exists
    if user_exists:
        runtime_dir = Path(f"/run/user/{config.uid}")
        if runtime_dir.exists():
            _check("runtime_dir", True, f"Runtime directory exists: {runtime_dir}")
        elif linger_enabled:
            # Linger is on but the dir is gone — the classic `terminate-user`
            # aftermath. Restarting the user manager recreates it.
            _check("runtime_dir", False, f"Runtime directory missing: {runtime_dir}",
                   fix=f"sudo systemctl restart user@{config.uid}.service "
                       f"(linger is on; do NOT 'loginctl terminate-user')")
        else:
            _check("runtime_dir", False, f"Runtime directory missing: {runtime_dir}",
                   fix=f"sudo loginctl enable-linger {config.uid} (creates the runtime directory)")

    # Check 5: Home directory exists
    if user_exists:
        home_dir = config.home_dir
        if home_dir.exists():
            _check("home_dir", True, f"Home directory exists: {home_dir}")
        else:
            _check("home_dir", False, f"Home directory missing: {home_dir}",
                   fix=f"sudo /usr/libexec/workloadctl/workload-ensure-user {config.name}")

    # Check 6: Image(s) exist locally
    if user_exists:
        if config.is_vm:
            # VM workloads have no container image to inventory — the disk is
            # provisioned by the substrate, not pulled. `config.image` is the
            # sentinel "(vm)" and get_image_id() would pointlessly shell out to
            # `podman image inspect "(vm)"`, so skip the container-image check.
            pass
        elif config.is_multi:
            for cname, img in config.container_images():
                iid = manager.podman(config).image_id(img)
                if iid:
                    _check(f"image_available[{cname}]", True,
                           f"Image available for {cname}: {img} ({iid[:12]})")
                else:
                    _check(f"image_available[{cname}]", False,
                           f"Image not available for {cname}: {img}",
                           fix="Image will be pulled on first start")
        else:
            image_id = manager.get_image_id(config)
            if image_id:
                _check("image_available", True, f"Image available: {config.image} ({image_id[:12]})")
            else:
                pull_policy = config.config.get("container", {}).get("pull", "missing")
                if pull_policy == "never":
                    try:
                        build_script = config.resolve_control_file("build.sh")
                        fix = (f"Build it: {build_script}" if build_script.exists()
                               else f"Build or provide: {config.image}")
                    except ValueError as e:
                        # Malformed [workload] bundle: report it as the fix-text
                        # rather than letting it crash the whole diagnose run.
                        fix = f"Fix [workload] bundle: {e}"
                else:
                    fix = "Image will be pulled on first start"
                _check("image_available", False, f"Image not available: {config.image}", fix=fix)

    # Check 7: Service file(s) exist
    service_file = Path(f"/run/systemd/system/{config.service_name}")
    if service_file.exists():
        _check("service_file", True, f"Service file exists: {service_file}")
    else:
        _check("service_file", False, f"Service file missing: {service_file}",
               fix="sudo systemctl daemon-reload")

    if config.is_multi:
        for unit in config.sub_service_names():
            sub_file = Path(f"/run/systemd/system/{unit}")
            if sub_file.exists():
                _check(f"service_file[{unit}]", True, f"Sub-service file exists: {unit}")
            else:
                _check(f"service_file[{unit}]", False, f"Sub-service file missing: {unit}",
                       fix="sudo systemctl daemon-reload")

    # Check 7b: Config not edited since the units were last generated. Editing
    # the workload.toml + `daemon-reload` does NOT regenerate per-workload units
    # (only `enable` runs the unit-writer), a common foot-gun.
    if service_file.exists():
        if units_outdated(config.name):
            _check("config_current", False,
                   "Config edited since last enable — generated units are stale",
                   fix=f"sudo workloadctl enable {config.name}  "
                       f"(daemon-reload does not regenerate units; see `drift` for the diff)")
        else:
            _check("config_current", True, "Generated units match current config (by mtime)")

    # Check 8: Service enabled
    result = subprocess.run(
        ["systemctl", "is-enabled", config.service_name],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        _check("service_enabled", True, "Service enabled")
    else:
        _check("service_enabled", False, "Service not enabled",
               fix="Service should be auto-enabled via generator")

    # Check 9: Service active
    svc_active, service_state = service_active(config.service_name)
    if svc_active:
        _check("service_active", True, f"Service active: {service_state}")
    else:
        fix = (f"Check logs: sudo journalctl -u {config.service_name} -n 50"
               if config.enabled else "Workload is disabled in config")
        _check("service_active", False, f"Service not active: {service_state}", fix=fix)

    # Check 10: Container(s) running
    if user_exists:
        if config.is_multi:
            for cname in config.container_names():
                pn = config.podman_container_name(cname)
                cs = manager.podman(config).container_status(pn)
                if cs:
                    _check(f"container_running[{cname}]", True,
                           f"Container running: {pn} ({cs})")
                else:
                    _check(f"container_running[{cname}]", False,
                           f"Container not running: {pn}",
                           fix=f"Check logs: sudo journalctl -u workload-{config.name}-{cname}.service -n 50")
        else:
            container_status = manager.podman(config).container_status(config.container_name)
            if container_status:
                _check("container_running", True, f"Container running: {container_status}")
            else:
                _check("container_running", False, "Container not running",
                       fix=f"Check logs: sudo journalctl -u {config.service_name} -n 50")

    # Check 11: Volume paths exist
    volumes = config.get_volumes()
    if volumes:
        missing_volumes = []
        for vol_spec in volumes:
            expanded_spec = expand_volume_path(vol_spec, str(config.home_dir))
            host_path = expanded_spec.split(':')[0]
            if not Path(host_path).exists():
                missing_volumes.append(host_path)

        if not missing_volumes:
            _check("volume_paths", True, f"All volume paths exist ({len(volumes)} volumes)")
        else:
            _check("volume_paths", False,
                   f"Missing volume paths: {', '.join(missing_volumes)}",
                   fix="sudo mkdir -p " + " ".join(missing_volumes))

    # Check 12: UID mapping (for userns=host)
    userns_mode = config.config.get("security", {}).get("userns", "keep-id")
    if userns_mode == "host" and user_exists:
        try:
            with open("/etc/subuid", "r") as f:
                for line in f:
                    if line.startswith(f"{config.username}:"):
                        parts = line.strip().split(':')
                        if len(parts) == 3:
                            subuid_start = int(parts[1])
                            subuid_count = int(parts[2])
                            subuid_end = subuid_start + subuid_count - 1
                            _check("uid_mapping", True,
                                   f"UID mapping configured: container UIDs 1-{subuid_count} → host UIDs {subuid_start}-{subuid_end}")
                            break
                else:
                    _check("uid_mapping", False, "Cannot calculate UID mapping (subuid not found)",
                           fix="Check /etc/subuid configuration")
        except Exception as e:
            _check("uid_mapping", False, f"Error reading subuid: {e}")

    return checks, all(c["passed"] for c in checks)


def cmd_diagnose(args, manager: WorkloadManager):
    """Diagnose workload runtime setup (user, subids, linger, SELinux)"""
    require_root()
    config = _load_config_or_exit(args.workload, json_mode=args.json)

    checks, passed = collect_diagnose_checks(config, manager)
    checks_passed = sum(1 for c in checks if c["passed"])
    checks_total = len(checks)

    if args.json:
        print(json.dumps({
            "workload": config.name,
            "passed": passed,
            "checks_passed": checks_passed,
            "checks_total": checks_total,
            "checks": checks
        }, indent=2))
        sys.exit(0 if passed else 1)

    print(f"Diagnosing workload: {config.name}")
    print()
    for c in checks:
        symbol = "✓" if c["passed"] else "✗"
        print(f"{symbol} {c['message']}")
        if "fix" in c and not c["passed"]:
            print(f"  Fix: {c['fix']}")

    print()
    print(f"Checks: {checks_passed}/{checks_total} passed")
    print()

    if not passed:
        print("Issues found:")
        for i, c in enumerate((c for c in checks if not c["passed"]), 1):
            print(f"  {i}. {c['message']}")
            if "fix" in c:
                print(f"     {c['fix']}")
        print()
        sys.exit(1)
    else:
        print("✓ All checks passed - workload is healthy")
        sys.exit(0)


# ---------------------------------------------------------------------------
# cmd_edit
# ---------------------------------------------------------------------------

def _ask_yes_no(prompt: str) -> bool:
    """Prompt for y/N. Treat EOF (non-interactive stdin) as 'no' rather than
    crashing with `EOFError: EOF when reading a line`."""
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        print()
        return False


def _validate_control_file_name(rel: str) -> None:
    """Reject anything that isn't a safe relative path under the override dir.

    Blocks absolute paths and `..` traversal so `edit <name> <file>` can never
    write outside `/etc/workloads.d/<name>/`. Nested names (e.g. `rootfs/x`) are
    allowed — the build context may have subdirectories.
    """
    if not rel or not rel.strip():
        raise ValueError("empty control-file name")
    p = Path(rel)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError("must be a relative path with no '..' components")


def _assert_no_symlink_escape(base: Path, target: Path) -> None:
    """Reject if any component from `base` down to `target` is a symlink.

    `..`/absolute are already blocked, but a relpath like `sub/file` could still
    escape `/etc/workloads.d/<name>/` if a component (`sub`, or the file itself)
    was pre-planted as a symlink. Walk the chain and refuse any symlinked
    component so a write can never follow a link out of the override tree.
    """
    if base.is_symlink():
        raise ValueError(f"override dir is a symlink: {base}")
    cur = base
    for part in target.relative_to(base).parts:
        cur = cur / part
        if cur.is_symlink():
            raise ValueError(f"refusing to write through symlink: {cur}")


def _cleanup_override_dir(config: WorkloadConfig, override: Path) -> None:
    """Remove now-empty override dirs from `override` up to override_dir.

    Keeps the override tree free of empty `<name>/` (and any seeded subdirs)
    after a lazy-cleanup removal, so the dir's existence stays meaningful.
    """
    base = config.override_dir
    d = override.parent
    while True:
        try:
            d.rmdir()
        except OSError:
            break
        if d == base:
            break
        d = d.parent


def _print_control_file_next_steps(config: WorkloadConfig, rel: str) -> None:
    """Print how to apply a just-edited control file (it isn't auto-applied)."""
    base = Path(rel).name
    setup = config.config.get("host", {}).get("setup", "")
    # Files that drive an image build: the conventional names plus whatever this
    # workload actually declares ([build].containerfile / [build].script), so a
    # `Containerfile.gpu` edit still gets the rebuild hint, not the generic one.
    build_files = {"build.sh", "Containerfile",
                   Path(config.build_containerfile).name}
    if config.build_script:
        build_files.add(Path(config.build_script).name)
    print()
    print("  Next steps:")
    if base == "policy.cil":
        print(f"    Reload SELinux policy:  sudo workloadctl enable {config.name}")
    elif base in build_files:
        print(f"    Rebuild image:          sudo workloadctl build {config.name}")
        print(f"    Apply to running:       sudo workloadctl recreate {config.name}")
    elif rel == setup:
        print(f"    Re-runs on next enable: sudo workloadctl enable {config.name}")
    else:
        print(f"    Apply changes:          sudo workloadctl recreate {config.name}")
    print(f"    Revert to shipped:      sudo rm {config.override_dir / rel}")


def _editor_argv() -> list:
    """Return the argv for the user's $EDITOR.

    Split so a value carrying flags (e.g. "code --wait", "emacs -nw") is honored
    instead of being treated as one impossible argv[0]. Falls back to nano if
    $EDITOR is unset/empty, or malformed (unbalanced quotes make shlex.split
    raise ValueError) rather than crashing `workloadctl edit`.
    """
    try:
        return shlex.split(os.environ.get("EDITOR", "") or "nano") or ["nano"]
    except ValueError:
        print("Warning: $EDITOR is malformed; falling back to nano", file=sys.stderr)
        return ["nano"]


def _edit_control_file(args, manager: WorkloadManager):
    """Edit a bundle control file, seeding an /etc override copy-on-write.

    The lazy-override ergonomic (systemd `systemctl edit`): on first edit, seed
    `/etc/workloads.d/<name>/<file>` from the resolved `/usr` default (or an
    empty file if the bundle ships none), then open `$EDITOR`. If the result is
    byte-identical to the shipped default — or an untouched empty new file — the
    override is dropped so it never freezes upgrade-tracking.
    """
    name = args.workload
    rel = args.file

    config_path = workload_config_path(name)
    if not config_path.exists():
        print(f"Error: Workload config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    try:
        _validate_control_file_name(rel)
    except ValueError as e:
        print(f"Error: invalid control-file name {rel!r}: {e}", file=sys.stderr)
        sys.exit(1)

    config = WorkloadConfig(name)
    override = config.override_dir / rel
    default = config.bundle_dir / rel

    # Containment: even with `..` blocked, a pre-planted symlink component could
    # redirect the write outside the override tree. Check before creating dirs.
    try:
        _assert_no_symlink_escape(config.override_dir, override)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    seeded = False
    if not override.exists():
        override.parent.mkdir(parents=True, exist_ok=True)
        if default.exists():
            shutil.copy2(default, override)
            print(f"  Seeded override from shipped default: {default}")
        else:
            override.touch()
            if rel.endswith(".sh"):
                override.chmod(0o755)
            print(f"  No shipped default — created a new control file: {override}")
        seeded = True

    editor_argv = _editor_argv()
    result = subprocess.run([*editor_argv, str(override)])
    if result.returncode != 0:
        print(f"Editor exited with error code {result.returncode}", file=sys.stderr)
        # Don't leave a half-seeded override behind on editor failure.
        if seeded:
            override.unlink(missing_ok=True)
            _cleanup_override_dir(config, override)
        sys.exit(1)

    # Lazy-override cleanup. An override byte-identical to the shipped default is
    # redundant and would freeze upgrade-tracking, so drop it; likewise an
    # untouched empty new file. Mirrors `systemctl edit` discarding a no-op.
    if default.exists() and override.read_bytes() == default.read_bytes():
        override.unlink()
        _cleanup_override_dir(config, override)
        print(f"  No change from the shipped default — no override kept "
              f"(still tracks {default}).")
        return
    if not default.exists() and override.stat().st_size == 0:
        override.unlink()
        _cleanup_override_dir(config, override)
        print("  Empty file — nothing created.")
        return

    # A freshly authored control file with a shebang should be executable even
    # when it isn't named *.sh (a hook with no extension). copy2 already
    # preserves a shipped default's mode, so only touch newly seeded files.
    if seeded and not default.exists():
        try:
            with open(override, "rb") as fh:
                if fh.read(2) == b"#!":
                    override.chmod(override.stat().st_mode | 0o111)
        except OSError:
            pass

    print(f"✓ Override saved: {override}")
    _print_control_file_next_steps(config, rel)


def cmd_edit(args, manager: WorkloadManager):
    """Edit config and apply changes"""
    require_root()

    if getattr(args, "file", None):
        _edit_control_file(args, manager)
        return

    config_path = workload_config_path(args.workload)
    if not config_path.exists():
        print(f"Error: Workload config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    # Create backup using mkstemp to avoid TOCTOU race
    backup_fd, backup_str = tempfile.mkstemp(prefix=f"workload-{args.workload}-", suffix=".toml")
    os.close(backup_fd)
    backup_path = Path(backup_str)
    shutil.copy2(config_path, backup_path)

    # Open editor
    editor_argv = _editor_argv()
    result = subprocess.run(editor_argv + [str(config_path)])
    if result.returncode != 0:
        print(f"Editor exited with error code {result.returncode}", file=sys.stderr)
        backup_path.unlink()
        sys.exit(1)

    # Check if file changed
    if config_path.read_text() == backup_path.read_text():
        print("No changes made")
        backup_path.unlink()
        return

    print()
    print("Config changed. Validating...")
    print()

    try:
        config = WorkloadConfig(args.workload)
        validation = validate_single(config, manager, json_mode=False)
        if not validation["passed"]:
            print()
            if _ask_yes_no("Validation failed. Restore backup? [y/N] "):
                shutil.copy2(backup_path, config_path)
                print("Backup restored")
            else:
                print("Config saved with errors - fix before enabling")
            backup_path.unlink()
            sys.exit(1)
    except Exception as e:
        print(f"Error loading config: {e}", file=sys.stderr)
        if _ask_yes_no("Restore backup? [y/N] "):
            shutil.copy2(backup_path, config_path)
            print("Backup restored")
        backup_path.unlink()
        sys.exit(1)

    print()
    print("Validation passed. Changes:")
    print()
    subprocess.run(["diff", "-u", str(backup_path), str(config_path)])
    print()

    if config.enabled:
        if getattr(args, "yes", False):
            print("Apply changes and restart workload? [y/N] y")
            apply = True
        else:
            apply = _ask_yes_no("Apply changes and restart workload? [y/N] ")
        if apply:
            # daemon-reload alone won't regenerate per-workload unit files —
            # only the systemd shell-generator re-runs, and it just emits a
            # oneshot that doesn't fire until next boot. Run workload-generate
            # explicitly so [container.environment] and other inlined values
            # actually take effect.
            subprocess.run(
                ["/usr/libexec/workloadctl/workload-generate", "/run/systemd/system"],
                check=True,
            )
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            if config.is_vm:
                # VM cloud-init/nvram are built by the setup oneshot
                # (RemainAfterExit=yes); restart it so edits to [vm.cloud_init]
                # / template_vars are re-rendered into a fresh seed before the
                # main service reboots QEMU onto it.
                subprocess.run(
                    ["systemctl", "restart",
                     workload_service_units(config, roles={"setup"})[0]],
                    check=True,
                )
                subprocess.run(["systemctl", "restart", config.service_name], check=True)
            elif manager.user_exists(config):
                # Container: self-healing restart (re-pin runtime dir + clear
                # start-limit thrash) rather than a bare systemctl restart.
                restart_workload_service(config.uid, config.service_name)
            else:
                subprocess.run(["systemctl", "restart", config.service_name], check=True)
            print("✓ Changes applied and service restarted")
        else:
            print(f"Changes saved but not applied. Run 'sudo workloadctl recreate {args.workload}' to apply.")
    else:
        print("✓ Changes saved (workload is disabled)")

    backup_path.unlink()


