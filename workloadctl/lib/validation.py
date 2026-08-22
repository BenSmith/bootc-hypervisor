"""
Workload config schema validation.

The hard-error schema checks (`validate_workload_config` and friends) plus the
non-fatal `collect_config_warnings` heads-up that `validate` surfaces at
edit/deploy time. The host-userns gate lives here too, so the security-relevant
acknowledgement check is in one place. VM-section validation is delegated to
vm.validate_vm_config.

Installed to /usr/libexec/workloadctl/validation.py.
"""

import re

from workload_lib import (
    MAX_CONTAINER_NAME_LENGTH,
    CONTAINER_NAME_PATTERN,
    MAX_NAME_LENGTH,
    NAME_PATTERN,
    HOST_USERNS_OPT_IN,
    WORKLOAD_TOKEN_NAMES,
    WORKLOAD_TOKEN_PATTERN,
    _LIFTED_CONTAINER_KEYS,
    infer_workload_kind,
    infer_workload_mode,
    normalize_containers,
)
from vm import validate_vm_config, vm_network_warnings


def validate_container_name(name: str):
    """Validate a per-container name. Raises ValueError on invalid names."""
    if len(name) > MAX_CONTAINER_NAME_LENGTH:
        raise ValueError(
            f"Container name too long: {len(name)} (max {MAX_CONTAINER_NAME_LENGTH})"
        )
    if not CONTAINER_NAME_PATTERN.match(name):
        raise ValueError(f"Invalid container name: {name!r}")


def _control_char_in(value: str) -> str | None:
    """Return the first disallowed control character in `value`, or None.

    Tab is allowed (systemd keeps it through quote handling and it's a
    legitimate separator); every other C0 control plus DEL is rejected. The one
    that matters is the raw newline: a single directive value is one line, so an
    embedded newline in any string that gets spliced into the generated unit —
    an ExecStart token (image, command, --user/--cap-add/--device/env value,
    volume spec) or a [resources.custom_directives] value emitted verbatim —
    would terminate the directive and let the tail parse as a *following*
    directive. NUL terminates C strings similarly.
    """
    for ch in value:
        o = ord(ch)
        if (o < 32 and ch != "\t") or o == 127:
            return ch
    return None


def _reject_control_chars(node, path: str, errors: list[str]):
    """Recursively flag control characters in any string within `node`.

    Walks the whole config so every string that can reach the unit is covered
    (and stays covered as fields are added), rather than escaping each injection
    site by hand. Config values are never legitimately multi-line — with the one
    exception `_vm_scannable` prunes away — so this is a hard error: fail the
    config loudly at validate/boot instead of emitting a malformed or
    directive-injected unit.
    """
    if isinstance(node, str):
        bad = _control_char_in(node)
        if bad is not None:
            where = path or "value"
            errors.append(
                f"{where} contains a disallowed control character {bad!r}; "
                f"control characters corrupt the generated systemd unit"
            )
    elif isinstance(node, dict):
        for k, v in node.items():
            child = f"{path}.{k}" if path else str(k)
            _reject_control_chars(v, child, errors)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _reject_control_chars(v, f"{path}[{i}]", errors)


# Config paths whose values get expand_workload_tokens() applied, as produced by
# the _reject_* walkers: "security.security_opt[0]" in single mode,
# "containers[0].security.security_opt[0]" in pod/bridge mode. Widening token
# expansion to another field means adding it here, or validate will reject the
# very syntax the generator just learned to honor.
_TOKEN_EXPANDING_PATH = re.compile(r'(?:^|\.)security\.security_opt\[\d+\]$')


def _reject_bad_workload_tokens(node, path: str, errors: list[str]):
    """Recursively flag ${WORKLOAD_*} tokens that will not be expanded.

    Two failure modes, both of which otherwise surface far from their cause:

      - a misspelled token in a field that *does* expand — the generator drops
        the whole option and warns into the journal at boot, which is a long
        way from the person who typed it;
      - a correct token in a field that does not expand — it reaches podman as
        a literal "${WORKLOAD_DATA_DIR}" path that can never resolve.

    Catching both at validate time is the point: the bug this guards against
    validated clean and failed halfway through host setup.
    """
    if isinstance(node, str):
        for m in WORKLOAD_TOKEN_PATTERN.finditer(node):
            token = m.group(1)
            where = path or "value"
            if token not in WORKLOAD_TOKEN_NAMES:
                errors.append(
                    f"{where}: unknown token ${{{token}}} "
                    f"(known: {', '.join(sorted(WORKLOAD_TOKEN_NAMES))})"
                )
            elif not _TOKEN_EXPANDING_PATH.search(path):
                errors.append(
                    f"{where}: ${{{token}}} is not expanded here "
                    f"(only security_opt expands ${{WORKLOAD_*}} tokens); "
                    f"it would reach podman as a literal string"
                )
    elif isinstance(node, dict):
        for k, v in node.items():
            child = f"{path}.{k}" if path else str(k)
            _reject_bad_workload_tokens(v, child, errors)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _reject_bad_workload_tokens(v, f"{path}[{i}]", errors)


def _vm_scannable(config: dict) -> dict:
    """A copy of a VM config with [vm.cloud_init].template_vars pruned.

    template_vars are substituted into the cloud-init user-data YAML, never into
    a unit directive, and a multi-line value there is legitimate (a script, a
    key). Everything else in a VM config gets the control-char guard, because it
    can reach a generated unit: [resources].slice is spliced into the VM
    service's Slice=, and a [vm].volumes host path into the virtiofsd ExecStart
    (dq() is no defense — systemd ends a directive at a newline no matter how
    it's quoted).
    """
    ci = config.get("vm", {}).get("cloud_init")
    if not isinstance(ci, dict) or "template_vars" not in ci:
        return config
    vm = dict(config["vm"])
    vm["cloud_init"] = {k: v for k, v in ci.items() if k != "template_vars"}
    return {**config, "vm": vm}


def validate_workload_config(config: dict) -> list[str]:
    """Run schema-level checks. Returns a list of error strings (empty = OK)."""
    errors = []

    kind = infer_workload_kind(config)

    if kind == "vm":
        _reject_control_chars(_vm_scannable(config), "", errors)
        # No VM field expands tokens, so any ${WORKLOAD_*} here is a mistake —
        # the walker's own path check reports it as such.
        _reject_bad_workload_tokens(_vm_scannable(config), "", errors)
        errors.extend(validate_vm_config(config))
        return errors

    # --- container validation ---
    _reject_control_chars(config, "", errors)
    _reject_bad_workload_tokens(config, "", errors)

    has_container = "container" in config
    has_containers = "containers" in config

    if has_container and has_containers:
        errors.append("config has both [container] and [[containers]]; use one or the other")

    if has_containers:
        ctrs = config["containers"]
        if not isinstance(ctrs, list) or not ctrs:
            errors.append("[[containers]] must be a non-empty array")
        else:
            seen = set()
            for i, c in enumerate(ctrs):
                if "name" not in c:
                    errors.append(f"containers[{i}] missing required 'name' field")
                    continue
                try:
                    validate_container_name(c["name"])
                except ValueError as e:
                    errors.append(f"containers[{i}]: {e}")
                if c["name"] in seen:
                    errors.append(f"duplicate container name: {c['name']!r}")
                seen.add(c["name"])
                if "container" not in c or "image" not in c.get("container", {}):
                    errors.append(f"containers[{c['name']}].container.image is required")
                # environment/health may live at either nesting depth, but not
                # both — normalize_containers lifts the sibling form, and
                # ambiguity would make precedence implementation-defined.
                for key in _LIFTED_CONTAINER_KEYS:
                    if key in c and key in c.get("container", {}):
                        errors.append(
                            f"containers[{c['name']}]: '{key}' set both as "
                            f"[containers.{key}] and [containers.container.{key}]; "
                            f"use one form"
                        )

    try:
        infer_workload_mode(config)
    except ValueError as e:
        errors.append(str(e))

    # Keep the shape (is_multi = "containers" in config) and the topology
    # (mode) in lockstep so `is_multi <=> mode != "single"` holds. The generator
    # emits per-container units on mode, while ~30 call sites read is_multi as
    # the same discriminator; an explicit mode that contradicts the block shape
    # would desync them (orphaned units, dropped containers).
    explicit_mode = config.get("workload", {}).get("mode")
    if explicit_mode in ("pod", "bridge") and not has_containers:
        errors.append(
            f"workload.mode = {explicit_mode!r} requires [[containers]] "
            f"(a single [container] block is always 'single' mode)"
        )
    if explicit_mode == "single" and has_containers:
        errors.append(
            "workload.mode = 'single' is incompatible with [[containers]]; "
            "use [container] for a single-container workload"
        )

    # [workload].requires / .after — must be lists of valid workload name strings
    wl = config.get("workload", {})
    for key in ("requires", "after"):
        val = wl.get(key)
        if val is None:
            continue
        if not isinstance(val, list) or not all(isinstance(n, str) for n in val):
            errors.append(f"[workload].{key} must be a list of workload name strings")
        else:
            for n in val:
                try:
                    validate_workload_name(n)
                except ValueError as e:
                    errors.append(f"[workload].{key}: {e}")

    # Host userns is gated: it dissolves the per-workload escape boundary, so
    # refuse to generate units for it unless the operator explicitly
    # acknowledges the elevated trust. The generator runs this same check (and
    # skips workloads with errors), so an un-acknowledged host-userns workload
    # is hard-blocked at boot, not merely warned in kmsg.
    if uses_host_userns(config) and not host_userns_acknowledged(config):
        errors.append(
            f'security.userns = "host" dissolves the per-workload isolation '
            f'boundary (container root maps to the workload user in the host '
            f'user namespace). Set [security] {HOST_USERNS_OPT_IN} = true to '
            f'acknowledge the elevated trust, or use '
            f'userns = "keep-id:uid=0,gid=0" for container root in a private '
            f'namespace.'
        )

    return errors


def uses_host_userns(config: dict) -> bool:
    """True if the workload requests ``userns = "host"`` anywhere.

    Host userns dissolves the per-workload isolation boundary (container root
    maps to the workload user *in the host's* user namespace), so it is gated
    behind an explicit opt-in (see validate_workload_config / HOST_USERNS_OPT_IN).
    Reads userns where build_userns_args does: per-container
    [containers.security] for bridge mode, workload-level [security] otherwise.
    VMs never use userns.
    """
    if infer_workload_kind(config) == "vm":
        return False
    try:
        mode = infer_workload_mode(config)
    except ValueError:
        return False
    if mode == "bridge":
        values = [c.get("security", {}).get("userns")
                  for c in normalize_containers(config)]
    else:  # single, pod
        values = [config.get("security", {}).get("userns")]
    return any(v == "host" for v in values)


def host_userns_acknowledged(config: dict) -> bool:
    """True if the workload opted in to host userns via [security]."""
    return bool(config.get("security", {}).get(HOST_USERNS_OPT_IN))


def valid_userns_mode(mode: str) -> bool:
    """True if `mode` is a userns value the generator accepts.

    Accepts "host", "keep-id", or "keep-id" with uid/gid parameters
    (e.g. "keep-id:uid=1000,gid=1000"). Single source shared by the boot
    generator (build_userns_args) and `validate` (collect_config_warnings).
    """
    if mode in ("keep-id", "host"):
        return True
    if not mode.startswith("keep-id:"):
        return False
    params = mode[len("keep-id:"):].split(",")
    valid_keys = {"uid", "gid"}
    seen = set()
    for param in params:
        if "=" not in param:
            return False
        key, value = param.split("=", 1)
        if key not in valid_keys or key in seen or not value.isdigit():
            return False
        seen.add(key)
    return len(seen) > 0


def collect_config_warnings(config: dict, known_workload_names=None) -> list[str]:
    """Non-fatal config warnings, as message strings (empty list = none).

    The boot generator emits these to /dev/kmsg, where they're effectively
    invisible. This reproduces them read-only so `validate` can surface the
    same mistakes at edit/deploy time. The generator stays authoritative at
    boot (it also applies each safe fallback); this is only the early heads-up,
    mirroring how validate_workload_config mirrors the generator's schema checks.

    `known_workload_names`, when provided, enables the requires/after
    cross-reference check; it is skipped when None (the caller lacks the fleet
    view — e.g. validating a config in isolation).
    """
    warnings: list[str] = []
    wl = config.get("workload", {})

    # requires/after must name workloads that actually exist. (Shape/name
    # validity is a hard error handled by validate_workload_config; here we only
    # flag well-formed names that don't resolve.)
    if known_workload_names is not None:
        known = set(known_workload_names)
        for key in ("requires", "after"):
            val = wl.get(key)
            if not isinstance(val, list):
                continue
            for dep in val:
                if isinstance(dep, str) and dep not in known:
                    warnings.append(
                        f"[workload].{key} references unknown workload {dep!r}")

    # The remaining checks are container-topology specific; VMs don't use them —
    # but [vm.network] has warnings of its own, and this is the channel that
    # surfaces them at edit/deploy time rather than in the generator's kmsg.
    if infer_workload_kind(config) == "vm":
        warnings.extend(
            vm_network_warnings(config.get("vm", {}).get("network", {})))
        return warnings
    try:
        mode = infer_workload_mode(config)
    except ValueError:
        # A mode contradiction is a hard schema error (reported by
        # validate_workload_config); don't also flag it as a warning.
        return warnings

    # userns must be an accepted form or the generator falls back to keep-id.
    # Read it where build_userns_args does: the workload-level [security] block
    # for single/pod, per-container [containers.security] for bridge.
    if mode == "bridge":
        userns_sites = [
            (c.get("name"), c.get("security", {}).get("userns"))
            for c in normalize_containers(config)
        ]
    else:  # single, pod
        userns_sites = [(None, config.get("security", {}).get("userns"))]
    for cname, userns in userns_sites:
        if userns is None:
            continue
        if not isinstance(userns, str) or not valid_userns_mode(userns):
            where = f" for container {cname!r}" if cname else ""
            warnings.append(
                f"invalid userns mode {userns!r}{where}; the generator "
                f"falls back to 'keep-id'")

    # lifecycle=pet is single-mode only; pod/bridge fall back to cattle.
    if wl.get("lifecycle") == "pet" and mode != "single":
        warnings.append(
            f"lifecycle=pet is only supported in single mode (mode={mode!r}); "
            f"the generator falls back to cattle")

    # bridge mode ignores workload-level [network].ports.
    if mode == "bridge" and config.get("network", {}).get("ports"):
        warnings.append(
            "workload-level [network].ports is ignored in bridge mode; publish "
            "ports per container under [containers.network]")

    return warnings


def validate_workload_name(name: str):
    """Validate a workload name. Raises ValueError on invalid names."""
    if len(name) > MAX_NAME_LENGTH:
        raise ValueError(
            f"Workload name too long: {len(name)} chars (max {MAX_NAME_LENGTH})"
        )
    if not NAME_PATTERN.match(name):
        raise ValueError(
            "Workload name must start with a letter and contain only "
            "lowercase letters, numbers, and hyphens"
        )
