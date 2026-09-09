"""
cmd_validate — check a workload config before anything acts on it.

validate_single() is the check battery: it is the one place that decides whether
a TOML is fit to enable, and create, edit and the catalog verbs all route
through it rather than re-deriving their own idea of "valid". Reporting only —
it never mutates a workload.
"""
import grp
import json
import threading
from pathlib import Path
import sys
from typing import NoReturn

from config_parser import container_credential_entries, container_uses_inspect
from workload_lib import (
    container_internal_entries,
    CREDSTORE_DIR,
    expand_volume_path,
    GENERATOR_OWNED_DIRECTIVES,
)
from provisioning import shadowed_filecon_paths
from egress_policy import vm_internal_hosts, vm_uses_inspect
from broker_config import vm_credential_entries
from vm import (
    parse_memory_mib, vm_internal_reserved_reason, vm_internal_resolve, vm_mac_address,
    vm_mac_collisions, )
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
# How long `validate` will wait for ONE [[vm.network.internal]] name, in
# seconds. It resolves each entry so an operator learns at edit time that a
# name would fail the VM's start -- but `validate` is a fast, read-only command
# an operator runs while fixing something, quite possibly the resolver itself,
# and getaddrinfo on a host whose nameserver is black-holing takes the
# resolver's own retry budget (five seconds per nameserver by default, twice
# over) with nothing on screen. Bounded here so a broken resolver costs a
# warning per entry rather than the command.
INTERNAL_RESOLVE_TIMEOUT = 2.0


def _resolve_within(host: str, timeout: float):
    """vm_internal_resolve, with a wall-clock bound on the lookup.

    getaddrinfo takes no timeout and does not honour the socket default -- it
    is a blocking call in libc -- so the only bound available without a
    resolver of our own is to stop WAITING for it. The thread is a daemon and
    is left running: it holds nothing this process needs, and it ends when the
    resolver's own retries do or when the command exits, whichever comes first.

    A lookup that does not finish in time is reported as a name that cannot be
    armed right now, which is what a name that cannot be looked up right now
    means for the check this feeds. The check is a warning either way, and
    warns in BOTH directions already -- DNS at validate time is not DNS at boot
    time -- so a slow resolver produces the same advice a failing one does.
    """
    box = {}

    def run():
        try:
            box["ok"] = vm_internal_resolve(host)
        except BaseException as exc:              # reported, never raised here
            box["err"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout)
    if "err" in box:
        raise box["err"]
    if "ok" not in box:
        raise ValueError(
            f"the lookup did not answer within {timeout:g}s, so whether it "
            f"would resolve at start is unknown from here")
    return box["ok"]


def validate_single(config: WorkloadConfig, manager: WorkloadManager, json_mode=False) -> dict:
    """Validate a single workload config. Returns dict with validation results."""
    checks = []

    # `severity` decides whether a check blocks (`error`) and what symbol it
    # prints; `passed` says whether the check found a problem. They are not the
    # same axis, and only warnings can disagree. So _warn takes `passed` as a
    # keyword and will not guess it.
    #
    # THE RULE IS: `passed=True` on a warning means THE CHECK COULD NOT RUN.
    # Both spellings of it here are "cannot verify credentials as non-root" --
    # the credstore is root-only and validate does not require root, so the
    # check looked at nothing and found nothing. Every other warning found
    # something and says `passed=False`.
    #
    # It was stated as "found nothing" until 2026-09-07, and three checks had
    # drifted under the looser wording: vm_memory_precision (the memory WAS
    # truncated), custom_directives_conflict (a directive IS overridden) and
    # generator_warning (the generator DID complain). Each is a finding about
    # the config, reported and then flagged as if nothing were found -- so a
    # consumer filtering --json for `passed == false` was silently missing
    # them. Nothing in workloadctl reads the field (the totals derive from
    # `severity`, the top-level `passed` is `errors == 0`), which is why it
    # could drift with the suite green.
    #
    # "Could not run" is the sharper test and the one to apply at a new call
    # site: it is a question about this process's ability to look, not a
    # judgement about the config. tests/test_cmd_validate.py pins every site.
    #
    # The counts are derived from `checks` below rather than incremented beside
    # each append. There are forty-one appends, each of which used to carry its
    # own `errors += 1` or `warnings += 1`; a check added without one would be
    # reported and then not counted, which is an error that leaves `passed`
    # True.
    def _record(name, passed, severity, message, fix=None, **extra):
        entry = {"check": name, "passed": passed, "severity": severity,
                 "message": message}
        if fix:
            entry["fix"] = fix
        entry.update(extra)
        checks.append(entry)

    def _ok(name, message, **extra):
        _record(name, True, "ok", message, **extra)

    def _error(name, message, fix=None, **extra):
        _record(name, False, "error", message, fix=fix, **extra)

    def _warn(name, message, *, passed, fix=None, **extra):
        _record(name, passed, "warning", message, fix=fix, **extra)

    _ok("required_fields", f"Required fields present: name={config.name}")

    # Schema validation — the same checks the boot generator runs, surfaced here
    # so `validate`/`install` catch config errors before a boot rather than after.
    schema_errors = validate_workload_config(config.config)
    if schema_errors:
        for msg in schema_errors:
            _error("schema", msg)
    else:
        _ok("schema", "Schema valid")

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
        _ok("credentials", "No credential references")
    else:
        try:
            missing = sorted(name for name in demanded if not (CREDSTORE_DIR / name).exists())
        except OSError:
            _warn("credentials",
                  "Cannot verify credentials as non-root; re-run with sudo",
                  passed=True)
        else:
            if missing:
                for name in missing:
                    _error("credentials",
                           f"Missing credential: {name}",
                           fix=f"sudo workloadctl secret create {name}")
            else:
                _ok("credentials",
                    f"Credentials present: {', '.join(sorted(demanded))}")

    # Broker credentials, the same question one subtree down. They cannot be
    # reached by the check above and never will be: a `${SECRET:}` reference
    # cannot name the scoped path (SECRET_PATTERN has no `/`), which is exactly
    # what keeps broker material out of workload env -- so auto_detect_credentials
    # returns nothing for them by construction.
    #
    # This is the actionable half of a gap `backup` leaves on purpose.
    # lib/backup.py copies the credentials a config DEMANDS, and the demanded
    # set is those same `${SECRET:}` occurrences -- so a workload backed up and
    # restored comes back without its provider keys. `backup` warns per missing
    # credential at backup time; RESTORE says nothing, because the restored
    # config demands no `${SECRET:}` the archive lacks. This check is what fires
    # on the restored host and names the material, which is why the docs
    # sentence about that gap can point at a command rather than only state a
    # fact. Broker material is deliberately not carried by `backup`: its blast
    # radius is a live provider account, and stating that is better than
    # quietly widening it.
    #
    # Both substrates. A container declaring [[network.credential]] gets the
    # same broker instance from the same generator, so it fails the same way
    # with nothing sealed -- and the failure is a 502 per request, not a start
    # failure, so nothing else on the host says the material is missing.
    vm_net = ((config.config.get("vm") or {}).get("network") or {})
    container_net = config.config.get("network") or {}
    broker_creds = (vm_credential_entries(vm_net)
                    if isinstance(vm_net, dict) else [])
    if not broker_creds and isinstance(container_net, dict):
        broker_creds = container_credential_entries(container_net)
    if broker_creds:
        workload_name = config.config.get("workload", {}).get("name", config.name)
        try:
            missing = sorted(
                c.name for c in broker_creds
                if not (CREDSTORE_DIR / "broker" / workload_name / c.name).exists())
        except OSError:
            _warn("broker-credentials",
                  "Cannot verify broker credentials as non-root; "
                  "re-run with sudo",
                  passed=True)
        else:
            if missing:
                for name in missing:
                    _error("broker-credentials",
                           f"Missing broker credential: {name} — this "
                           f"workload's broker will refuse every "
                           f"request for the host that selects it",
                           fix=f"sudo workloadctl secret create "
                           f"broker/{workload_name}/{name}")
            else:
                _ok("broker-credentials",
                    f"Broker credentials present: "
                    f"{', '.join(sorted(c.name for c in broker_creds))}")

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
            _warn("inlined_secrets",
                  f"Possible {kind} inlined at {where}",
                  passed=False,
                  fix="sudo workloadctl secret create <name>, then reference it as ${SECRET:<name>}")
    else:
        _ok("inlined_secrets", "No credential-shaped literals in config")

    username_len = len(config.username)
    if username_len >= 32:
        _error("username_length",
               f"Username too long: {config.username} ({username_len} chars, max 31)",
               fix="Use shorter workload name")
    else:
        _ok("username_length", f"Username length OK ({username_len} chars)")

    # Check if UID has been assigned
    try:
        uid = config.uid
        if uid < 10000 or uid > 52948:
            _error("uid_range",
                   f"UID out of range: {uid} (should be 10000-52948)")
        else:
            _ok("uid_range", f"UID in valid range: {uid} (10000-52948)")
    except WorkloadUserNotFound:
        _ok("uid_assigned",
            "UID not yet assigned (will be assigned on first enable)")

    # Check name uniqueness (workload names must be unique)
    all_configs = manager.get_all_configs()
    conflicts = [c for c in all_configs
                 if c.name == config.name and c.path != config.path]
    if conflicts:
        _error("name_uniqueness",
               f"Name conflict: '{config.name}' also used in {conflicts[0].path}")
    else:
        _ok("name_uniqueness", "Name is unique")

    _valid_lifecycles = {"pet", "cattle"}
    if config.lifecycle not in _valid_lifecycles:
        _error("lifecycle",
               f"Invalid lifecycle value: {config.lifecycle!r}. "
               f"Must be one of: {', '.join(sorted(_valid_lifecycles))}",
               fix='Set [workload] lifecycle = "pet" or "cattle" (or omit for the default "cattle")')
    else:
        _ok("lifecycle", f"Lifecycle policy: {config.lifecycle}")

    # snapshot_keep bounds the pet overlay snapshot repository. Only the
    # explicit field is checked; omitting it uses the default (3).
    raw_snapshot_keep = config.config.get("workload", {}).get("snapshot_keep")
    if raw_snapshot_keep is not None and (
        not isinstance(raw_snapshot_keep, int)
        or isinstance(raw_snapshot_keep, bool)
        or raw_snapshot_keep < 1
    ):
        _error("snapshot_keep",
               f"[workload].snapshot_keep must be a positive integer, "
               f"got {raw_snapshot_keep!r}",
               fix="Set [workload] snapshot_keep to a positive integer (or omit for the default 3)")

    # `bundle` goes straight into a /usr/share/workloadctl/workloads/<bundle>/
    # path for control-file lookups, so reject anything that isn't a plain
    # workload-style name before any path is built. Only the explicit field is
    # checked; the default (the workload name) is validated on its own.
    raw_bundle = config.config.get("workload", {}).get("bundle")
    if raw_bundle is not None:
        try:
            validate_workload_name(raw_bundle)
            _ok("bundle", f"Bundle: {config.bundle}")
        except ValueError as e:
            _error("bundle",
                   f"Invalid bundle {raw_bundle!r}: {e}",
                   fix="bundle is a directory name (lowercase letters, digits, hyphens)")

    # `selinux_policy` is now boolean-only. A leftover string from the old form
    # is truthy, so it silently enables policy keyed on `[workload] bundle`
    # (default = name) — NOT the directory the string named. Surface it.
    raw_selinux = config.config.get("security", {}).get("selinux_policy")
    if isinstance(raw_selinux, str):
        _warn("selinux_policy_string",
              f"selinux_policy = {raw_selinux!r} is a string; the field "
              f"is now boolean-only and this is treated as `true` with "
              f"the CIL sourced from bundle '{config.bundle}', not "
              f"'{raw_selinux}'.",
              passed=False,
              fix=f'Set selinux_policy = true and, if the policy lives elsewhere, '
              f'[workload] bundle = "{raw_selinux}".')

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
            _warn("selinux_filecon_shadowed",
                  f"policy.cil declares filecon for {paths}, which "
                  f"workloadctl registers in file_contexts.local. "
                  f".local outranks the base file_contexts wholesale, "
                  f"so the module's rule is never consulted and the "
                  f"label is silently not applied.",
                  passed=False,
                  fix="Drop the filecon; label that tree with semanage "
                  "instead (VM workloads already get svirt_image_t at "
                  "enable). filecon is fine outside these paths.")

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
            _error("build_containerfile",
                   f"Invalid {label} containerfile {cf!r}: must be a "
                   f"relative path inside the build context (no '..')",
                   fix='e.g. containerfile = "Containerfile"')
            build_cf_invalid = True
    if build_cfs and not build_cf_invalid:
        summary = ", ".join(f"{label} {cf}" for label, cf in build_cfs)
        if config.build_script:
            summary = f"script={config.build_script}"
        _ok("build", f"Build: {summary}")

    # Containers sharing a pull=never image must resolve identical build inputs;
    # build_jobs() refuses the ambiguity, so report it here as a lint error
    # rather than letting `build` crash on it.
    if config.is_multi:
        try:
            config.build_jobs()
        except ValueError as e:
            _error("build_conflict",
                   str(e),
                   fix="Align the [containers.build] blocks of containers that "
                   "share an image, or give them distinct image tags")
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
            _ok("volume_path",
                f"Volume path exists: {host_path}",
                path=host_path)
        elif host_path in required_file_paths:
            _ok("volume_path",
                f"Volume path listed in required_files (setup needed): {host_path}",
                path=host_path)
        elif host_path.startswith(workload_root + "/"):
            _ok("volume_path",
                f"Volume path will be created on enable: {host_path}",
                path=host_path)
        else:
            _error("volume_path",
                   f"Volume path does not exist: {host_path}",
                   fix=f"mkdir -p {host_path}",
                   path=host_path)

    for group in config.get_extra_groups():
        try:
            grp.getgrnam(group)
            _ok("group_exists", f"Group exists: {group}", group=group)
        except KeyError:
            _error("group_exists",
                   f"Group does not exist: {group}",
                   group=group)

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
                _warn("vm_memory_precision",
                      f"vm.memory = {vm_memory!r} is not an exact number "
                      f"of MiB; truncated to {mib}M.",
                      passed=False,
                      fix=f'memory = "{mib}M"')

    # Warn if custom_directives overrides something the generator already sets.
    custom_directives = config.config.get("resources", {}).get("custom_directives", {})
    for directive in custom_directives:
        if directive in GENERATOR_OWNED_DIRECTIVES:
            _warn("custom_directives_conflict",
                  f"custom_directives overrides '{directive}' which is managed by the generator — may have no effect or cause unexpected behaviour",
                  passed=False)

    # Non-fatal generator warnings (invalid userns, bridge-mode ports ignored,
    # pet-in-multi fallback, unknown requires/after). The boot generator only
    # logs these to kmsg, where nobody sees them; surface them here so a config
    # mistake shows at edit/deploy time. all_configs (fetched above for the
    # uniqueness check) is the fleet view the requires/after check needs.
    known_workload_names = {c.name for c in all_configs}
    for msg in collect_config_warnings(config.config, known_workload_names):
        _warn("generator_warning", msg, passed=False)

    # [[vm.network.internal]] names are resolved at VM START, by the inspect
    # socket's ExecStartPre, and one that does not resolve there fails that
    # prestart -- which the VM Requires=, so the guest does not boot. That is
    # deliberate (see workload-vm-inspect's internal_failure), but it means a
    # name that is merely wrong costs the whole workload at the worst moment,
    # on a host where the operator is not watching.
    #
    # So resolve them here too, where the answer is free and the fix is an
    # edit. A WARNING and not an error, in both directions: DNS at validate
    # time is not DNS at boot time, so a name that fails here may well be fine
    # then (a resolver still coming up, a split-horizon zone), and a name that
    # passes here can fail then. This says "this entry would stop the guest
    # booting right now", which is worth knowing and is not a verdict.
    if config.config.get("vm") and vm_uses_inspect(config.config):
        net = config.config.get("vm", {}).get("network", {}) or {}
        for host in vm_internal_hosts(net):
            problem = None
            try:
                addresses = _resolve_within(host, INTERNAL_RESOLVE_TIMEOUT)
            except ValueError as e:
                problem = str(e)
            else:
                # Resolving is half of it: the exemption is armed only for
                # addresses the internal drop would actually match, and a name
                # that answers with a public address is refused at start by
                # vm_internal_ok_elements rather than here.
                for addr in addresses:
                    reserved = vm_internal_reserved_reason(addr)
                    if reserved:
                        problem = f"[vm.network].internal: {reserved}"
                        break
            if problem:
                _warn("vm_internal_unresolvable",
                      f"[[vm.network.internal]] names {host!r}, which "
                      f"cannot be armed on this host right now, and "
                      f"that fails the VM's start rather than only the "
                      f"exemption: {problem}",
                      passed=False,
                      fix=f"Make {host} resolve to a private address on the "
                      f"VM host, or remove the entry (it authorises "
                      f"nothing on its own; the guest simply loses reach "
                      f"to that host).")

    # Container counterpart (G9 in the container egress-parity build spec):
    # same validate-time resolve, sourced from [network].internal, and the
    # SAME start-time consequence as the VM side now that P1-7..P1-11 have
    # landed. This comment used to say the container inspector did not exist
    # yet and that an unresolvable name therefore cost nothing at start; that
    # expired in this same branch. workload-container-inspect's `up()` raises
    # internal_failure() on a name it cannot resolve, it is the inspect
    # socket's ExecStartPre with no `-` prefix, and the workload Requires=
    # that socket -- so the workload does not start at all. The message below
    # has to say so, exactly as the VM one does, or it warns about losing one
    # exemption when what is actually at stake is the next restart.
    if not config.config.get("vm") and container_uses_inspect(config.config):
        net = config.config.get("network", {}) or {}
        for entry in container_internal_entries(net):
            problem = None
            try:
                addresses = _resolve_within(entry.host, INTERNAL_RESOLVE_TIMEOUT)
            except ValueError as e:
                problem = str(e)
            else:
                for addr in addresses:
                    reserved = vm_internal_reserved_reason(addr)
                    if reserved:
                        problem = f"[network.internal]: {reserved}"
                        break
            if problem:
                _warn("container_internal_unresolvable",
                      f"[[network.internal]] names {entry.host!r}, "
                      f"which cannot be armed on this host right "
                      f"now, and that fails the workload's start "
                      f"rather than only the exemption -- arming "
                      f"runs as the inspect socket's ExecStartPre "
                      f"and the workload requires that socket: "
                      f"{problem}",
                      passed=False,
                      fix=f"Make {entry.host} resolve to a private address "
                      f"on the container host, or remove the entry (it "
                      f"authorises nothing on its own; the workload "
                      f"simply loses reach to that host).")

    # VM MACs are hash-derived with no allocation registry, so distinct names
    # can rarely collide on the shared bridge — two guests fighting one address.
    # Flag it against the current VM fleet so a rename fixes it before deploy.
    if config.config.get("vm"):
        vm_names = [c.name for c in all_configs if c.config.get("vm")]
        collisions = vm_mac_collisions(config.name, vm_names)
        if collisions:
            _warn("vm_mac_collision",
                  f"VM MAC {vm_mac_address(config.name)} collides with "
                  f"workload(s): {', '.join(collisions)}",
                  passed=False,
                  fix="Rename one of the colliding VM workloads.")

    errors = sum(1 for c in checks if c["severity"] == "error")
    warnings = sum(1 for c in checks if c["severity"] == "warning")
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

