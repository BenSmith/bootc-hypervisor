"""The shape a `[vm]` declaration must have.

validate_vm_config is the front door validation calls for a VM workload; it
checks the section itself -- image source, restart, memory, disks, seed,
virtiofs mounts -- and hands `[vm.network]` to validate_vm_network, which
checks the section's own shape (bridge, ports, resolver, outbound interface)
and then hands the egress declaration to vm_egress_validate. vm_network_warnings
is the soft half, what is legal but probably not meant. Nothing here renders
a unit, an nft element or a policy document.

Installed to /usr/libexec/workloadctl/vm_validate.py.
"""

import re

from config_parser import parse_volume_spec
from vm_defs import (
    EGRESS_DEFAULT,
    REGISTRATION_DOMAIN_PARENTS,
    SEED_PROVIDES_CHOICES,
    SEED_PROVIDES_RETIRED,
    parse_memory_mib,
    parse_vm_port,
)
from vm_egress_validate import validate_egress
from workload_addr import reserved_range


def _registration_domain_parent(pattern: str) -> str | None:
    """The registration-domain parent this pattern wildcards under, or None.

    Only a leading `*.` counts. `*.github.io` lets the GUEST pick the label, so
    the allowlist authorises a name it never saw and the inspector's own
    upstream lookup carries it to a nameserver somebody else controls — which
    is both the exfiltration channel §9's synthesis removes and the route by
    which an allowlisted name points inside the LAN. `pages.github.io` names one
    site and is fine.
    """
    if not pattern.startswith("*."):
        return None
    parent = pattern[2:]
    return parent if parent in REGISTRATION_DOMAIN_PARENTS else None


def vm_network_warnings(net: dict) -> list[str]:
    """Non-fatal [vm.network] warnings, as message strings.

    The counterpart to validate_vm_network's errors, surfaced by
    `validate` through validation.collect_config_warnings. Everything here is a
    coherent thing to have written on purpose — which is exactly why silence
    would be wrong, since nothing else would ever report it.
    """
    warnings: list[str] = []
    if not isinstance(net, dict) or "bridge" in net:
        return warnings
    egress = net.get("egress", EGRESS_DEFAULT)

    for key in ("hosts", "internal", "splice", "http2", "policy"):
        entries = net.get(key, [])
        if not isinstance(entries, list):
            continue
        for item in entries:
            pattern = item.get("host") if isinstance(item, dict) else item
            if not isinstance(pattern, str):
                continue
            parent = _registration_domain_parent(pattern.strip())
            if parent:
                warnings.append(
                    f"[vm.network].{key} pattern {pattern!r} wildcards under "
                    f"{parent}, where anyone can register a label — the guest "
                    f"picks the name, the allowlist authorises it, and the "
                    f"lookup reaches a nameserver somebody else controls. "
                    f"Name the hosts you need instead, if you can.")

    if egress == "filtered" and net.get("resolver") == "none":
        # The coherent case: address-keyed `allow` elements only, reached
        # through the filter chain without touching the inspector. Warned
        # anyway, because the same file read six months later looks like a
        # workload that simply lost DNS.
        warnings.append(
            "[vm.network].resolver = 'none' on a filtered workload: no "
            "hostname is resolvable, so only .allow entries written by "
            "address work. A guest that cannot resolve can only dial "
            "literals, and a literal reaches the inspector with no name to "
            "match and is dropped.")

    allow = net.get("allow", [])
    if isinstance(allow, list):
        for item in allow:
            if not isinstance(item, dict):
                continue
            spec = item.get("address")
            if not isinstance(spec, str) or not spec.strip().endswith(":53"):
                continue
            warnings.append(
                f"[vm.network].allow {spec.strip()!r} is a resolver the guest "
                f"can choose for itself, past the synthesising responder — "
                f"which returns both the ECHConfig that hides the name from "
                f"the inspector and the DNS exfiltration channel synthesis "
                f"exists to remove.")

    return warnings


def validate_vm_network(net: dict) -> list[str]:
    """Validate [vm.network]. Returns a list of error strings.

    There is deliberately no `mode` key (ADR 006): `bridge` present means
    "attach to that operator-provided host bridge, take a real LAN identity,
    and be unfiltered"; absent means passt. That makes the contradictory
    combination unrepresentable rather than a validation rule.
    """
    errors: list[str] = []
    if not isinstance(net, dict):
        return ["[vm.network] must be a table"]

    # bridge — the unfiltered escape hatch. Optional now: its absence selects
    # passt, so unlike the pre-ADR-006 schema there is no default bridge name.
    if "bridge" in net:
        bridge = net["bridge"]
        if not isinstance(bridge, str) or not bridge:
            errors.append(
                f"[vm.network].bridge must be a non-empty string, got {bridge!r}")
        elif not re.match(r"^[a-zA-Z0-9_-]+$", bridge) or len(bridge) > 15:
            # Linux IFNAMSIZ is 16, max 15 visible chars.
            errors.append(
                f"[vm.network].bridge {bridge!r} is not a valid interface name "
                "(letters/digits/_/-, max 15 chars)")

    ports = net.get("ports", [])
    if not isinstance(ports, list):
        errors.append(
            f"[vm.network].ports must be an array of 'host:guest' strings, "
            f"got {type(ports).__name__}")
    else:
        for spec in ports:
            if not isinstance(spec, str):
                errors.append(f"[vm.network].ports entries must be strings, got {spec!r}")
                continue
            try:
                bind_addr, host_port, _guest, _proto = parse_vm_port(spec)
            except ValueError as e:
                errors.append(f"[vm.network].ports: {e}")
                continue
            reserved = reserved_range(bind_addr, host_port) if bind_addr else None
            if reserved:
                # The remedy follows its shape: a range-scoped reservation is
                # not somewhere to publish at all, while a port-scoped one is a
                # single socket on an address that is otherwise fine.
                if reserved.port is None:
                    where = f"binds into {reserved.network}, which carries"
                    remedy = ("Bind 127.0.0.1, a LAN address, or omit the "
                              "address to publish on all of them")
                else:
                    where = f"binds {bind_addr}:{reserved.port}, which is"
                    remedy = "Publish on another host port"
                errors.append(
                    f"[vm.network].ports: {spec!r} {where} {reserved.what}. "
                    f"{remedy}")
    if ports and "bridge" in net:
        # passt publishes ports by binding host sockets; a bridged guest has its
        # own LAN address and nothing of ours is in its data path to bind them.
        errors.append(
            "[vm.network].ports has no effect with .bridge set — a bridged VM "
            "has its own LAN address, so reach its services there directly")

    if "broker" in net:
        # A HARD ERROR, AND NOT A DEPRECATION (ADR 007 decision 11, premise 3).
        # The key used to mean "add this workload's uid to a redirect map so the
        # guest can dial one host-wide broker at an advertised literal". Every
        # object in that sentence is gone: the map, the table, the literal and
        # the single listener. Accepting the key and ignoring it would leave an
        # operator believing a credential boundary exists where there is none,
        # which is the same failure the old .bridge check above was written to
        # prevent -- so it fails, by name, and names the replacement.
        #
        # The two are not a rename. `broker = true` was a reachability switch
        # that said nothing about WHICH credential or WHICH host; `credential`
        # is per policy entry and is the authority for both. So the message
        # points at the pair of tables an operator now writes rather than
        # offering a one-line substitution that does not exist.
        errors.append(
            "[vm.network].broker was removed: there is no host-wide credential "
            "broker and no advertised endpoint for a guest to dial. Each "
            "workload now gets its own broker instance, and which hosts it "
            "serves is stated per policy entry -- declare the material in a "
            "[[vm.network.credential]] table and name it with `credential = "
            "\"<name>\"` on the [[vm.network.policy]] entries it applies to. "
            "See docs/agent-broker.md")

    outbound_if = net.get("outbound_if")
    if outbound_if is not None:
        if not isinstance(outbound_if, str) or not outbound_if:
            errors.append(
                f"[vm.network].outbound_if must be a non-empty string, "
                f"got {outbound_if!r}")
        elif not re.match(r"^[a-zA-Z0-9_.-]+$", outbound_if) or len(outbound_if) > 15:
            errors.append(
                f"[vm.network].outbound_if {outbound_if!r} is not a valid "
                "interface name (letters/digits/_/./-, max 15 chars)")
        elif "bridge" in net:
            errors.append(
                "[vm.network].outbound_if has no effect with .bridge set — it "
                "binds passt's host-side sockets, and a bridged VM has none")

    resolver = net.get("resolver", "host")
    if resolver not in ("host", "none"):
        errors.append(
            f"[vm.network].resolver must be 'host' or 'none', got {resolver!r}")

    errors += validate_egress(net)

    # ADR 002's host-level knobs went with the bridge that needed them.
    for removed in ("subnet", "dns"):
        if removed in net:
            errors.append(
                f"[vm.network].{removed} was managed-bridge configuration and "
                f"is gone with it (ADR 006). passt serves the guest DHCP/DNS "
                f"itself, derived from the host at start time.")

    return errors


def validate_vm_config(config: dict) -> list[str]:
    """Validate the [vm] section. Returns a list of error strings."""
    errors = []
    vm = config.get("vm", {})

    if "container" in config or "containers" in config:
        errors.append("[vm] and [container]/[[containers]] are mutually exclusive")

    sources = [bool(vm.get("image")), bool(vm.get("cloud_image_url")), bool(vm.get("local_image"))]
    if sum(sources) == 0:
        errors.append(
            "[vm] requires exactly one image source: "
            "vm.image (bootc ref), vm.cloud_image_url, or vm.local_image"
        )
    elif sum(sources) > 1:
        errors.append("[vm] must specify exactly one image source; got multiple")

    if vm.get("cloud_image_url") and not vm.get("cloud_image_checksum"):
        errors.append("[vm].cloud_image_checksum is required when cloud_image_url is set")

    checksum = vm.get("cloud_image_checksum", "")
    if checksum and not checksum.startswith("sha256:"):
        errors.append(f"[vm].cloud_image_checksum must start with 'sha256:', got {checksum!r}")

    memory = vm.get("memory", "")
    if memory:
        try:
            m = parse_memory_mib(memory)
            if m < 256:
                errors.append(f"[vm].memory must be at least 256 MiB, got {m}")
        except (ValueError, TypeError):
            errors.append(
                f"[vm].memory must be in QEMU notation (e.g. 2048, '2048M', '4G'), got {memory!r}"
            )

    vcpus = vm.get("vcpus", 1)
    if not isinstance(vcpus, int) or vcpus < 1:
        errors.append(f"[vm].vcpus must be a positive integer, got {vcpus!r}")

    rollback_keep = vm.get("rollback_keep", 2)
    if not isinstance(rollback_keep, int) or rollback_keep < 1:
        errors.append(f"[vm].rollback_keep must be a positive integer, got {rollback_keep!r}")

    # Restart policy for the VM service. "always" (default) treats a guest
    # reboot — which QEMU's -no-reboot turns into a clean exit — as a reason to
    # relaunch; "on-failure" keeps the VM down on a clean exit; "on-reboot" is
    # reserved for reason-aware restart (not implemented yet; falls back to
    # "always"). See generate_vm_service.
    restart = vm.get("restart", "always")
    if restart not in ("always", "on-failure", "on-reboot"):
        errors.append(
            "[vm].restart must be one of 'always', 'on-failure', 'on-reboot', "
            f"got {restart!r}"
        )

    errors.extend(validate_vm_network(vm.get("network", {})))

    # [vm.cloud_init] — optional override of the seed user-data.
    ci = vm.get("cloud_init", {})
    if ci:
        if not isinstance(ci, dict):
            errors.append("[vm.cloud_init] must be a table")
        else:
            ud = ci.get("user_data_file")
            if ud is not None and not isinstance(ud, str):
                errors.append(
                    f"[vm.cloud_init].user_data_file must be a string path, got {ud!r}"
                )
            # seed_provides opts a custom seed out of the seed-completeness
            # checks build_cloud_init_iso applies (CA bundle, virtiofs mounts).
            # Validated against a closed set: the whole value of the check is
            # that it fires, and a typo'd opt-out would silently disable it —
            # which is the failure mode the check exists to prevent.
            sp = ci.get("seed_provides", [])
            if not isinstance(sp, list) or not all(isinstance(x, str) for x in sp):
                errors.append(
                    "[vm.cloud_init].seed_provides must be a list of strings"
                )
            else:
                # A retired entry is refused BY NAME, ahead of the unknown-entry
                # message, and told what to write instead. Folding it into
                # "unknown entries ['proxy']" would be true and useless: the
                # operator's seed does provide something, the concern it
                # provides was renamed under them, and the generic message
                # would send them looking for a typo they did not make.
                for entry in sorted(set(sp) & set(SEED_PROVIDES_RETIRED)):
                    errors.append(
                        f"[vm.cloud_init].seed_provides = [{entry!r}] is no "
                        f"longer accepted: the per-workload proxy was "
                        f"replaced with a transparent redirect, so a guest is "
                        f"given no proxy environment for a seed to provide. "
                        f"Write {SEED_PROVIDES_RETIRED[entry]!r} instead if "
                        f"the seed installs and trusts the egress CA bundle "
                        f"itself, or drop the entry if it does not."
                    )
                unknown = sorted(set(sp) - SEED_PROVIDES_CHOICES
                                 - set(SEED_PROVIDES_RETIRED))
                if unknown:
                    errors.append(
                        f"[vm.cloud_init].seed_provides has unknown entries "
                        f"{unknown}; valid: {sorted(SEED_PROVIDES_CHOICES)}"
                    )
            tv = ci.get("template_vars", {})
            if not isinstance(tv, dict):
                errors.append("[vm.cloud_init].template_vars must be a table of strings")
            else:
                for k, v in tv.items():
                    if not isinstance(v, (str, int, float, bool)):
                        errors.append(
                            f"[vm.cloud_init].template_vars.{k} must be a scalar, got {type(v).__name__}"
                        )

    # Disk sizes are passed verbatim to `qemu-img create`/`resize`, which reads
    # a bare number as *bytes*. Require an explicit unit so a typo like "60"
    # isn't silently interpreted as a 60-byte disk (failing only at build time).
    for key in ("system_disk_size", "data_disk_size"):
        size = vm.get(key)
        if size is not None and (
            not isinstance(size, str)
            or not re.match(r"^\d+(\.\d+)?[KkMmGgTtPp]i?B?$", size)
        ):
            errors.append(
                f"[vm].{key} must be a size with a unit suffix "
                f"(e.g. '40G', '512M'), got {size!r}"
            )

    balloon = vm.get("balloon")
    if balloon is not None and not isinstance(balloon, bool):
        errors.append(f"[vm].balloon must be a boolean, got {balloon!r}")

    volumes = vm.get("volumes", [])
    if not isinstance(volumes, list):
        errors.append(
            f"[vm].volumes must be an array of 'host:guest[:opts]' strings, "
            f"got {type(volumes).__name__}"
        )
    else:
        for v in volumes:
            if not isinstance(v, str):
                errors.append(f"[vm].volumes entries must be strings, got {v!r}")
                continue
            host, guest, _ = parse_volume_spec(v)
            if not host or not guest:
                errors.append(
                    f"[vm].volumes entry {v!r} must have non-empty host and guest "
                    "paths (format 'host:guest[:opts]')"
                )

    # Host paths whose .mount unit each virtiofsd sidecar is ordered After=.
    # For a filesystem mounted UNDER a share, which RequiresMountsFor= on the
    # share root does not reach -- see generate_virtiofs_service.
    after_mounts = vm.get("after_mounts", [])
    if not isinstance(after_mounts, list):
        errors.append(
            f"[vm].after_mounts must be an array of host paths, "
            f"got {type(after_mounts).__name__}"
        )
    else:
        for p in after_mounts:
            if not isinstance(p, str) or not p:
                errors.append(
                    f"[vm].after_mounts entries must be non-empty strings, got {p!r}"
                )
            elif not (p.startswith("/") or p.startswith("./")
                      or p.startswith("@/") or p.split("/", 1)[0] in ("data", "state")):
                # A bare relative path would be expanded against the workload
                # home and produce an ordering edge on a plausible-looking unit
                # name that names no mount -- which systemd accepts in silence.
                errors.append(
                    f"[vm].after_mounts entry {p!r} must be an absolute path or "
                    "use a workload anchor ('./', '@/', 'data/', 'state/')"
                )

    announce_submounts = vm.get("announce_submounts")
    if announce_submounts is not None and not isinstance(announce_submounts, bool):
        errors.append(
            f"[vm].announce_submounts must be a boolean, got {announce_submounts!r}"
        )

    return errors
