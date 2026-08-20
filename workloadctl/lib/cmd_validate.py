"""
cmd_validate — check a workload config before anything acts on it.

validate_single() is the check battery: it is the one place that decides whether
a TOML is fit to enable, and create, edit and the catalog verbs all route
through it rather than re-deriving their own idea of "valid". Reporting only —
it never mutates a workload.
"""
import grp
import json
from pathlib import Path
import sys
from typing import NoReturn

from workload_lib import (
    CREDSTORE_DIR,
    expand_volume_path,
    GENERATOR_OWNED_DIRECTIVES,
)
from provisioning import shadowed_filecon_paths
from vm import parse_memory_mib, vm_mac_address, vm_mac_collisions
from validation import (
    collect_config_warnings,
    validate_workload_config,
    validate_workload_name,
)
from secrets_template import auto_detect_credentials, find_inlined_secrets
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    WorkloadUserNotFound,
)
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

    # Credential validation — `${SECRET:name}` references are resolved by
    # substituting a file's contents at container-start time, so a typo or a
    # never-created secret otherwise surfaces as a cryptic namespace/ExecStart
    # failure well after boot. Cross-check what the config demands against
    # what's actually in the credstore so it's a named, config-time error
    # instead. /etc/credstore.encrypted is root-only (0700) and `validate`
    # doesn't require root, so a permission failure here means "can't tell"
    # rather than "missing" — report that as a warning, not false errors.
    demanded = auto_detect_credentials(config.config)
    if not demanded:
        checks.append({
            "check": "credentials",
            "passed": True,
            "severity": "ok",
            "message": "No credential references"
        })
    else:
        try:
            missing = sorted(name for name in demanded if not (CREDSTORE_DIR / name).exists())
        except OSError:
            checks.append({
                "check": "credentials",
                "passed": True,
                "severity": "warning",
                "message": "Cannot verify credentials as non-root; re-run with sudo"
            })
            warnings += 1
        else:
            if missing:
                for name in missing:
                    checks.append({
                        "check": "credentials",
                        "passed": False,
                        "severity": "error",
                        "message": f"Missing credential: {name}",
                        "fix": f"sudo workloadctl secret create {name}"
                    })
                    errors += 1
            else:
                checks.append({
                    "check": "credentials",
                    "passed": True,
                    "severity": "ok",
                    "message": f"Credentials present: {', '.join(sorted(demanded))}"
                })

    # Inlined secrets — the mirror of the check above. That one asks "does the
    # credstore hold what this config references"; this one asks "did someone
    # skip the credstore and type the key in". Nothing sets a mode on
    # /etc/workloads.d/*/workload.toml, so it carries root's umask and is
    # normally world-readable: a pasted key is exposed to every uid on the host,
    # other workloads' users included. A warning rather than an error because it
    # is a prefix heuristic — it cannot be sure, and blocking `enable` on a
    # guess is how a check gets routed around.
    inlined = find_inlined_secrets(config.config)
    if inlined:
        for where, kind in inlined:
            checks.append({
                "check": "inlined_secrets",
                "passed": False,
                "severity": "warning",
                # The path, never the value: validate output gets pasted around.
                "message": f"Possible {kind} inlined at {where}",
                "fix": "sudo workloadctl secret create <name>, then reference it as ${SECRET:<name>}",
            })
            warnings += 1
    else:
        checks.append({
            "check": "inlined_secrets",
            "passed": True,
            "severity": "ok",
            "message": "No credential-shaped literals in config"
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

    # A `filecon` in a bundle's policy.cil under a path workloadctl registers
    # with semanage is inert: the module's entry lands in the base
    # file_contexts, and file_contexts.local outranks that file wholesale. The
    # module loads clean, nothing errors, and the label is simply never applied
    # — invisible unless someone runs matchpathcon, which is why validate says
    # it. (This is also why the per-workload VM rule is semanage and not CIL.)
    if config.selinux_policy:
        try:
            cil_text = config.resolve_control_file("policy.cil").read_text()
        except OSError:
            cil_text = ""   # a missing template is apply_selinux_policy's error
        shadowed = shadowed_filecon_paths(cil_text)
        if shadowed:
            paths = ", ".join(shadowed)
            checks.append({
                "check": "selinux_filecon_shadowed",
                "passed": False,
                "severity": "warning",
                "message": f"policy.cil declares filecon for {paths}, which "
                           f"workloadctl registers in file_contexts.local. "
                           f".local outranks the base file_contexts wholesale, "
                           f"so the module's rule is never consulted and the "
                           f"label is silently not applied.",
                "fix": "Drop the filecon; label that tree with semanage "
                       "instead (VM workloads already get svirt_image_t at "
                       "enable). filecon is fine outside these paths.",
            })
            warnings += 1

    # [build] / [containers.build]: a containerfile names a file *inside* the
    # build context, so it must be a plain relative path (no traversal). Checked
    # for the top-level section (when present) and every per-container override.
    build_cfs: list[tuple[str, str]] = []   # (label, containerfile)
    if config.config.get("build"):
        build_cfs.append(("[build]", config.build_containerfile))
    if config.is_multi:
        # A name-less container is already a schema error above; don't let the
        # missing key crash the linter here — fall back to the index for the label.
        for i, c in enumerate(config.config["containers"]):
            cf = (c.get("build") or {}).get("containerfile")
            if cf is not None:
                build_cfs.append(
                    (f"[containers.build] ({c.get('name', f'containers[{i}]')})", cf))
    build_cf_invalid = False
    for label, cf in build_cfs:
        if Path(cf).is_absolute() or ".." in Path(cf).parts:
            checks.append({
                "check": "build_containerfile",
                "passed": False,
                "severity": "error",
                "message": f"Invalid {label} containerfile {cf!r}: must be a "
                           f"relative path inside the build context (no '..')",
                "fix": 'e.g. containerfile = "Containerfile"',
            })
            errors += 1
            build_cf_invalid = True
    if build_cfs and not build_cf_invalid:
        summary = ", ".join(f"{label} {cf}" for label, cf in build_cfs)
        if config.build_script:
            summary = f"script={config.build_script}"
        checks.append({
            "check": "build",
            "passed": True,
            "severity": "ok",
            "message": f"Build: {summary}",
        })

    # Containers sharing a pull=never image must resolve identical build inputs;
    # build_jobs() refuses the ambiguity, so report it here as a lint error
    # rather than letting `build` crash on it.
    if config.is_multi:
        try:
            config.build_jobs()
        except ValueError as e:
            checks.append({
                "check": "build_conflict",
                "passed": False,
                "severity": "error",
                "message": str(e),
                "fix": "Align the [containers.build] blocks of containers that "
                       "share an image, or give them distinct image tags",
            })
            errors += 1
        except KeyError:
            # A name-less container can't be resolved into build jobs; it's
            # already reported as a schema error above — don't crash the linter.
            pass

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

    # Non-fatal generator warnings (invalid userns, bridge-mode ports ignored,
    # pet-in-multi fallback, unknown requires/after). The boot generator only
    # logs these to kmsg, where nobody sees them; surface them here so a config
    # mistake shows at edit/deploy time. all_configs (fetched above for the
    # uniqueness check) is the fleet view the requires/after check needs.
    known_workload_names = {c.name for c in all_configs}
    for msg in collect_config_warnings(config.config, known_workload_names):
        checks.append({
            "check": "generator_warning",
            "passed": True,
            "severity": "warning",
            "message": msg,
        })
        warnings += 1

    # VM MACs are hash-derived with no allocation registry, so distinct names
    # can rarely collide on the shared bridge — two guests fighting one address.
    # Flag it against the current VM fleet so a rename fixes it before deploy.
    if config.config.get("vm"):
        vm_names = [c.name for c in all_configs if c.config.get("vm")]
        collisions = vm_mac_collisions(config.name, vm_names)
        if collisions:
            checks.append({
                "check": "vm_mac_collision",
                "passed": False,
                "severity": "warning",
                "message": f"VM MAC {vm_mac_address(config.name)} collides with "
                           f"workload(s): {', '.join(collisions)}",
                "fix": "Rename one of the colliding VM workloads.",
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


def load_config_or_exit(name: str, json_mode: bool = False) -> WorkloadConfig:
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
        report_config_load_failure(name, e, json_mode=json_mode)


def report_config_load_failure(name: str, exc: BaseException,
                               *, json_mode: bool = False) -> NoReturn:
    """Report a config that would not load, then exit 1. Never returns.

    Split out of load_config_or_exit so a caller that has already caught the
    failure itself can report it *with the exception it actually saw* instead
    of re-loading to provoke a second one. cmd_doctor is that caller: it has to
    handle WorkloadMasked on its own terms first, so it cannot delegate the
    whole load. Re-loading would be both a wasted read and a lie whenever the
    two attempts fail differently.
    """
    if json_mode:
        print(json.dumps({"workload": name, "passed": False, "error": str(exc)}, indent=2))
    else:
        print(f"Error: cannot load workload '{name}': {exc}", file=sys.stderr)
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
        config = load_config_or_exit(args.workload, json_mode=args.json)
        result = validate_single(config, manager, json_mode=args.json)

        if args.json:
            print(json.dumps(result, indent=2))
        sys.exit(0 if result["passed"] else 1)

