"""
The rules a container `[network]` section must satisfy.

validate_container_network is called from validation.validate_config once the
workload is known to be a container. The scalars and entries it checks are
read by container_network_config; the shared rules are the ones
vm_egress_validate applies to a VM's `[vm.network]`, and every divergence is
one the two schemas actually have -- no `egress` key here (presence of a
trigger is the whole statement), no bridge escape hatch, and `mode = "host"`
special-cased because a host-mode container's processes span the workload's
whole subuid window rather than its single uid, which is what every selector
in workload-filter.nft is keyed on. See container_uses_inspect().

Installed to /usr/libexec/workloadctl/container_validate.py.
"""
from customs.inspect_document import patterns_overlap
from container_network_config import (
    ContainerCredential,
    ContainerPolicyEntry,
    _validate_container_host_pattern,
    container_ca_delivery,
    container_ca_mount_path,
    container_effective_tls_mode,
    container_runs_on_host_network,
    container_tls_mode,
    container_tls_reason,
)
from credential_entries import validate_credential_entries
from guest_ca import RESERVED_GUEST_ENV
from egress_policy import POLICY_METHODS, POLICY_METHODS_REFUSED
from customs.inspect_document import hostname_match


# The alphabet a podman publish spec may contain:
# `[[ip:]hostPort:]containerPort[/proto]` -- numeric ports and ranges, IPv4
# dots, IPv6 in brackets, the colons and a slash for the protocol. Nothing
# else: podman accepts no character outside this set (the publish host is an
# IP, not a name), so there is nothing it accepts that this rejects.
#
# WHY CHECK AT ALL. A publish spec is spliced raw into the generated unit's
# ExecStart -- the builders do not dq() it, because a valid spec needs no
# quoting and configs are trusted. But that rawness is exactly why an
# *invalid* one matters: a space would split the ExecStart token in two, a
# double quote would end the systemd argument early, and `%`/`$` would be
# expanded by systemd at unit load. The control-char walker already blocks
# the only injection vector (a newline); this closes the "silently corrupts
# the unit" class for the one raw-interpolated field that had no check of
# its own.
PUBLISH_SPEC_ALPHABET = frozenset(
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ":.[]-/"
)


def validate_publish_ports(ports, where: str) -> list[str]:
    """Validate one list of podman publish specs. Returns error strings.

    `where` names the config path for the message (e.g. "[network].ports" or
    "containers[proxy].network.ports"). Both call sites -- the workload-level
    [network] table and a bridge-mode container's own [containers.network] --
    feed their ports through here, because both are spliced raw into the
    generated unit by the same `--publish {port}` builder. Absent (None) is
    clean; a non-list or a spec carrying a character outside podman's alphabet
    is an error.
    """
    errors = []
    if ports is None:
        return []
    if not isinstance(ports, list):
        return [f"{where} must be an array of publish specs, "
                f"got {type(ports).__name__}"]
    for i, spec in enumerate(ports):
        if not isinstance(spec, str) or not spec.strip():
            errors.append(f"{where}[{i}] must be a non-empty string")
            continue
        bad = {c for c in spec if c not in PUBLISH_SPEC_ALPHABET}
        if bad:
            shown = ", ".join(repr(c) for c in sorted(bad))
            errors.append(
                f"{where}[{i}] {spec!r} contains {shown}, which cannot "
                f"appear in a podman publish spec "
                f"(`[[ip:]hostPort:]containerPort[/proto]`); a value with "
                f"these would corrupt the generated unit's ExecStart")
    return errors


def validate_container_network(net: dict, config: dict | None = None) -> list[str]:
    """Validate [network] on a container workload. Returns a list of error
    strings. Implements every numbered rule in the container egress-parity
    build spec's validation section, V13 being the refusal of a
    [[network.http2]] array, plus the mode="host" delta (§6 delta 2),
    settled by the P0-1 hardware spike -- see the module note above.

    `config` is the whole parsed TOML, and it is optional only so that the
    hundreds of tests exercising one [network] table need not build one. It is
    what decides whether `mode = "host"` is honoured at all: in bridge mode it
    is not, and refusing there would refuse a workload for a key the generator
    never reads. Passed by the one production caller
    (validation.validate_workload_config); absent means "assume it is
    honoured", which is the conservative reading."""
    errors: list[str] = []
    if not isinstance(net, dict):
        return ["[network] must be a table"]

    # --- [network].ports -- the one raw-interpolated field with no check ---
    # (The egress rules below are validated to the letter; publish specs are
    # spliced into --publish without dq(), so they get their own alphabet
    # check. Runs before the host-mode branch: a malformed port is a typo in
    # any mode, even one that ignores ports.)
    errors.extend(validate_publish_ports(net.get("ports"), "[network].ports"))

    # V13. Refused by name, as [[vm.network.http2]] is: the table is not
    # read, and one accepted without a word reads as h2 kept for the host.
    if "http2" in net:
        errors.append(
            "[[network.http2]] is not accepted: the egress inspector relays "
            "no HTTP/2, so a terminated host is offered http/1.1 alone. A "
            "host that must keep h2 is spliced: move the entry, with its "
            "reason, to [[network.splice]], and it is not decrypted. Drop "
            "the entry if the host takes HTTP/1.1.")

    # --- The mode = "host" delta (build spec §6 delta 2) ---
    # First, and on its own: every other rule below describes how to spell an
    # egress policy, and under host mode none of them can be honoured. Naming
    # the keys the workload actually set keeps the message actionable when a
    # bundle sets several.
    on_host_network = (container_runs_on_host_network(config)
                       if config is not None else net.get("mode") == "host")
    if on_host_network:
        named = [key for key in ("hosts", "policy", "allow", "internal",
                                 "splice", "tls", "ca_delivery", "credential")
                 if net.get(key)]
        if named:
            keys = ", ".join(f"[network].{k}" for k in named)
            errors.append(
                f'[network]: mode = "host" cannot be combined with egress '
                f'inspection ({keys}). A host-mode container shares the host '
                f'network namespace, so its processes appear on the wire as '
                f'host sockets spanning this workload\'s whole subuid range '
                f'-- not as the single uid every egress rule selects on, so '
                f'the policy would apply only to whichever containers happen '
                f'to run as the keep-id uid. Remove mode = "host" to get '
                f'egress inspection, or remove {keys} to keep host '
                f'networking.')
            # Nothing below can be satisfied under host mode; reporting the
            # shape of a policy that will never be armed is noise.
            return errors

    raw_hosts = net.get("hosts", [])
    if not isinstance(raw_hosts, list):
        errors.append(
            f"[network].hosts must be an array of hostname patterns, got "
            f"{type(raw_hosts).__name__}")
        raw_hosts = []
    else:
        for pattern in raw_hosts:
            errors.extend(f"[network].hosts: {e}"
                          for e in _validate_container_host_pattern(pattern))
    hosts = [h.strip() for h in raw_hosts if isinstance(h, str) and h.strip()]

    # --- [[network.allow]] -- shape + reason (V14) ---
    raw_allow = net.get("allow", [])
    if not isinstance(raw_allow, list):
        errors.append(
            f"[network].allow must be an array of [[network.allow]] tables, "
            f"got {type(raw_allow).__name__}")
        raw_allow = []
    for item in raw_allow:
        if not isinstance(item, dict):
            errors.append(f"[network].allow entries are tables with `host` "
                          f"or `address`, `port` and `reason`, got {item!r}")
            continue
        host = item.get("host")
        host = host.strip() if isinstance(host, str) and host.strip() else None
        address = item.get("address")
        address = address.strip() if isinstance(address, str) and address.strip() else None
        label = host or address or repr(item)
        if host is None and address is None:
            errors.append(
                f"[network].allow: entry {item!r} has neither `host` nor "
                f"`address`")
            continue
        if host is not None and address is not None:
            errors.append(
                f"[network].allow: {label!r} has both `host` and `address` "
                f"-- an entry names one destination one way")
            continue
        port = item.get("port")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            errors.append(
                f"[network].allow: {label!r} `port` must be an integer "
                f"1-65535, got {port!r}")
        elif port in (80, 443):
            # R5/§5: 80 and 443 are redirected into the inspector before this
            # allowlist is ever consulted -- an element here for either would
            # be armed and never matched, reporting a destination as exempt
            # from inspection that is inspected regardless.
            errors.append(
                f"[network].allow: {label!r} names port {port}, which is "
                f"always redirected to this workload's inspector -- "
                f"[[network.allow]] is for non-80/443 destinations only "
                f"(use .hosts or [[network.policy]] for HTTP/HTTPS)")
        if not isinstance(item.get("reason"), str) or not item["reason"].strip():
            errors.append(  # V14
                f"[network].allow: {label!r} has no `reason`; it is a "
                f"bypass of the internal-destination drop and carries one "
                f"like [[network.internal]] does")

    # --- [[network.internal]] / [[network.splice]] -- shape + reason (V14) ---
    def _validate_host_reason_array(key: str, bypass_clause: str) -> list[str]:
        out_hosts: list[str] = []
        out_errors: list[str] = []
        raw = net.get(key, [])
        if not isinstance(raw, list):
            return [], [f"[network].{key} must be an array of "
                        f"[[network.{key}]] tables, got {type(raw).__name__}"]
        for item in raw:
            if not isinstance(item, dict):
                out_errors.append(f"[network].{key} entries are tables with "
                                  f"`host` and `reason`, got {item!r}")
                continue
            if "host" not in item:
                out_errors.append(f"[network].{key}: entry {item!r} has no "
                                  f"`host`")
                continue
            problems = _validate_container_host_pattern(item.get("host"))
            if problems:
                out_errors.extend(f"[network].{key}: {p}" for p in problems)
                continue
            host = item["host"].strip()
            out_hosts.append(host)
            if not isinstance(item.get("reason"), str) or not item["reason"].strip():
                out_errors.append(  # V14
                    f"[network].{key}: {host!r} has no `reason`; {bypass_clause}")
        return out_hosts, out_errors

    internal_hosts, internal_errors = _validate_host_reason_array(
        "internal",
        "it is a bypass of the internal-destination drop and carries one "
        "like [[network.allow]] does")
    errors.extend(internal_errors)

    splice_hosts, splice_errors = _validate_host_reason_array(
        "splice",
        "it exempts a host from inspection and carries one like "
        "[[network.allow]] does")
    errors.extend(splice_errors)
    for host in splice_hosts:
        # V12: dead-entry check. Splice only excepts from the allowlist -- a
        # policy entry already allowlists its own host (V1), so unlike
        # `internal` below this does not also check policy_hosts: exempting a
        # host from inspection that a policy entry intends to inspect is a
        # contradiction, not redundancy, and is refused with the policy
        # entries below.
        if not any(patterns_overlap(host, pattern) for pattern in hosts):
            errors.append(
                f"[network].splice: {host!r} matches no allowlisted name -- "
                f"nothing in .hosts covers it, so the entry exempts a host "
                f"the workload is refused before the exemption is reached. "
                f"Add it to .hosts, or drop this entry")

    # --- [[network.credential]] -- shape (feeds V7/V10) ---
    #
    # The same blocks the VM schema carries, validated by the same function.
    # This was a port of it and was missing five of its rules; the two
    # arguments below are all that ever actually differed.
    credentials, credential_errors = validate_credential_entries(
        net, table="network", noun="container",
        credential_cls=ContainerCredential, reserved_env=RESERVED_GUEST_ENV)
    errors.extend(credential_errors)
    credential_names = {c.name for c in credentials}

    # --- [[network.policy]] -- shape + V1-V11 ---
    raw_policy = net.get("policy", [])
    vm_policy_entries: list[ContainerPolicyEntry] = []
    if not isinstance(raw_policy, list):
        errors.append(
            f"[network].policy must be an array of [[network.policy]] "
            f"tables, got {type(raw_policy).__name__}")
        raw_policy = []
    for item in raw_policy:
        if not isinstance(item, dict):
            errors.append(f"[network].policy entries are tables with `host` "
                          f"and optional `methods`/`paths`/`credential`, got "
                          f"{item!r}")
            continue
        # The same sweep the VM entry gets, and for the reason a typo needs
        # one: an unrecognised key is silently dropped, so `pathes = [...]`
        # leaves the entry permitting every path on its host and the file
        # reads as if it narrowed one.
        unknown = sorted(set(item) - {"host", "methods", "paths", "credential"})
        if unknown:
            errors.append(
                f"[network].policy: unknown key(s) {', '.join(unknown)}; an "
                f"entry carries `host`, `methods`, `paths` and `credential`")
        if "host" not in item:
            errors.append(f"[network].policy: entry {item!r} has no `host`")
            continue
        problems = _validate_container_host_pattern(item.get("host"))
        if problems:
            errors.extend(f"[network].policy: {p}" for p in problems)
            continue
        host = item["host"].strip()

        methods: tuple | None = None
        if "methods" in item:
            value = item["methods"]
            if not isinstance(value, list):
                errors.append(f"[network].policy: {host!r} `methods` must "
                              f"be an array of HTTP method names, got "
                              f"{type(value).__name__}")
                methods = ()
            else:
                out = []
                for token in value:
                    if not isinstance(token, str) or token != token.strip() \
                            or any(c.isspace() for c in token):
                        errors.append(
                            f"[network].policy: {host!r} `methods` names "
                            f"{token!r}, which is not a usable HTTP method "
                            f"token")
                        continue
                    name = token.upper()
                    if name in POLICY_METHODS_REFUSED:  # V5
                        errors.append(
                            f"[network].policy: {host!r} names the method "
                            f"{token!r}, which this inspector never sees -- "
                            f"{POLICY_METHODS_REFUSED[name]}")
                        continue
                    if name not in POLICY_METHODS:  # V5
                        errors.append(
                            f"[network].policy: {host!r} names {token!r}, "
                            f"which is not a registered HTTP method")
                        continue
                    out.append(name)
                if not out and value:
                    pass  # per-token errors already reported above
                elif not out:
                    errors.append(
                        f"[network].policy: {host!r} has an empty `methods` "
                        f"list, which permits no method at all. Omit the key "
                        f"to mean any method")
                methods = tuple(out)

        paths: tuple | None = None
        if "paths" in item:
            value = item["paths"]
            if not isinstance(value, list):
                errors.append(f"[network].policy: {host!r} `paths` must be "
                              f"an array of path patterns, got "
                              f"{type(value).__name__}")
                paths = ()
            else:
                out = []
                for pattern in value:
                    if not isinstance(pattern, str) or not pattern.strip():
                        errors.append(f"[network].policy: {host!r} `paths` "
                                      f"entries must be non-empty strings, "
                                      f"got {pattern!r}")
                        continue
                    if not pattern.startswith("/") or "?" in pattern or "#" in pattern:
                        errors.append(  # V6
                            f"[network].policy: {host!r} path {pattern!r} "
                            f"must start with '/' and carry no query or "
                            f"fragment -- `paths` matches the path alone")
                        continue
                    out.append(pattern)
                if not value:
                    errors.append(
                        f"[network].policy: {host!r} has an empty `paths` "
                        f"list, which permits no path at all. Omit the key "
                        f"to mean any path")
                paths = tuple(out)

        credential = None
        if "credential" in item:
            value = item.get("credential")
            if not isinstance(value, str) or not value.strip():
                errors.append(f"[network].policy: {host!r} `credential` "
                              f"must be the name of a [[network.credential]] "
                              f"block, got {value!r}")
            else:
                credential = value.strip()
                if credential not in credential_names:  # V7
                    errors.append(
                        f"[network].policy: {host!r} selects credential "
                        f"{credential!r}, which no [[network.credential]] "
                        f"block declares")
                if credential and "*" in host:  # V8
                    errors.append(
                        f"[network].policy: {host!r} selects credential "
                        f"{credential!r}, but a credential is attached per "
                        f"exact host -- the broker's table has no patterns, "
                        f"so every request matching this wildcard would be "
                        f"authorised here and refused there. Name the exact "
                        f"host this credential belongs to")

        vm_policy_entries.append(ContainerPolicyEntry(
            host=host, methods=methods, paths=paths, credential=credential))

    # A credential nothing selects.
    for cred in credentials:
        if not any(e.credential == cred.name for e in vm_policy_entries):
            errors.append(
                f"[network].credential: {cred.name!r} is declared but no "
                f"[[network.policy]] entry selects it, so it is sealed, "
                f"loaded and attached to nothing")

    policy_hosts = [e.host for e in vm_policy_entries]

    for host in internal_hosts:
        # V12, deferred until policy_hosts exists: a name in `policy` need
        # not also appear in `hosts` (V1), so an `internal` entry for such a
        # name is live even though `hosts` alone does not cover it.
        if not any(patterns_overlap(host, pattern) for pattern in hosts) \
                and not any(patterns_overlap(host, pattern) for pattern in policy_hosts):
            errors.append(
                f"[network].internal: {host!r} is on no list -- nothing in "
                f".hosts allowlists it and no .policy entry names it, so the "
                f"entry excepts a destination the workload is refused before "
                f"the exception is reached. Add it to .hosts, or drop this "
                f"entry")

    if vm_policy_entries:
        # V9: tls = "splice" plus any policy entry.
        explicit_tls = container_tls_mode(net)
        if explicit_tls == "splice":
            errors.append(
                "[network].policy with tls = 'splice' -- a spliced "
                "connection is never decrypted, so there is no request for "
                "`methods` and `paths` to be applied to and the entries "
                "would be silently inert. Drop tls = 'splice' (inspect is "
                "computed automatically once a policy entry exists), or "
                "drop the policy entries and keep the name allowlist in "
                ".hosts")

        # A name in both `splice` and `policy`: the policy could never run,
        # and the file states two intentions that cannot both hold. The
        # inspector refuses the rendered document for the same reason, so
        # this is where the operator hears it rather than at the restart.
        for entry in vm_policy_entries:
            for spliced in splice_hosts:
                if patterns_overlap(entry.host, spliced):
                    errors.append(
                        f"[network].policy: {entry.host!r} is also in "
                        f".splice ({spliced!r}) -- a spliced connection is "
                        f"never decrypted, so the method and path rules "
                        f"could never run. Keep one: splice the host and "
                        f"drop the policy entry, or drop the splice entry "
                        f"and let the host be inspected")
                    break

        # V3: where more than one entry matches a host by pattern, every one
        # of those entries must state both `methods` and `paths`.
        for i, entry in enumerate(vm_policy_entries):
            siblings = [o for j, o in enumerate(vm_policy_entries)
                       if j != i and patterns_overlap(entry.host, o.host)]
            if not siblings:
                continue
            missing = [k for k, v in (("methods", entry.methods),
                                      ("paths", entry.paths)) if v is None]
            if missing:
                errors.append(
                    f"[network].policy: {entry.host!r} shares a host with "
                    f"{siblings[0].host!r} and omits "
                    f"{' and '.join(f'`{k}`' for k in missing)}. Where "
                    f"entries overlap, an omitted key means ANY -- state "
                    f"both keys on every overlapping entry")

        # V4: apex trap. A wildcard entry beneath an allowlisted apex leaves
        # the apex allowlisted and inspected with no rules applied.
        for apex in hosts:
            wildcard = f"*.{apex}"
            if not any(e.host.strip().lower() == wildcard.lower() for e in vm_policy_entries):
                continue
            if any(hostname_match(apex, (e.host,)) for e in vm_policy_entries):
                continue
            errors.append(
                f"[network].policy: {wildcard!r} does not cover the apex "
                f"{apex!r}, which .hosts also allowlists -- patterns are "
                f"fnmatch, not DNS suffix matching, so the apex is "
                f"allowlisted and inspected with NO method or path rules "
                f"applied. Add an entry for {apex!r} too, or drop it from "
                f".hosts")

    # --- The `tls` scalar itself, and its `tls_reason` interlock ---
    #
    # Both of these are rules the VM side has and the first port of this
    # function did not, which is a shape worth naming: a value that is only
    # ever COMPUTED needs no domain check, and `tls` is computed for almost
    # every workload -- so the branch where an operator writes it by hand was
    # the one nothing constrained. An unrecognised literal is the worse of the
    # two. It is not merely accepted: container_effective_tls_mode() returns it
    # verbatim, so `tls = "inspct"` is an effective mode of "inspct", which is
    # neither "inspect" (so V16 never asks for ca_delivery) nor "splice" (so
    # V18 never fires), and the workload validates clean, starts clean, and
    # runs with a policy naming a mode the inspector does not implement.
    explicit_tls = container_tls_mode(net)
    if explicit_tls is not None and explicit_tls not in ("inspect", "splice"):
        errors.append(
            f"[network].tls must be 'inspect' or 'splice', got "
            f"{explicit_tls!r}. It is normally omitted -- the mode is computed "
            f"from whether any [[network.policy]] entry is present")

    tls_reason = container_tls_reason(net)
    if explicit_tls == "splice" and tls_reason is None:
        # Same rule as the VM's, for the same reason: this is the widest bypass
        # in the schema (every host, not a named one), and every narrower one
        # -- allow, internal, splice entries -- has carried a written reason
        # since it existed.
        errors.append(
            "[network].tls = 'splice' requires tls_reason. Writing it "
            "explicitly gives up per-request policy on EVERY host, which is "
            "wider than any [[network.splice]] entry; the person deciding "
            "months from now whether the bypass is still needed is not the one "
            "opening it. (Reaching splice by simply having no policy entries "
            "needs no reason -- nothing narrower was given up.)")
    if tls_reason is not None and explicit_tls != "splice":
        errors.append(
            "[network].tls_reason is set but tls = 'splice' is not written "
            "explicitly -- a reason recording a bypass that was never chosen "
            "sends a reviewer looking for an exposure that is not there")

    # V16/V18: the interlock between the computed tls mode and ca_delivery.
    effective_tls = container_effective_tls_mode(net)
    ca_delivery = container_ca_delivery(net)
    ca_mount_path = container_ca_mount_path(net)
    is_triggered = bool(hosts or vm_policy_entries or net.get("allow"))
    if is_triggered and effective_tls == "inspect":
        if ca_delivery is None:  # V16
            errors.append(
                "[network]: this workload's effective tls mode is 'inspect' "
                "(a policy entry is present, or tls = 'inspect' was written "
                "explicitly), which needs a trust-delivery route -- "
                "ca_delivery is required. Set it to 'env', 'mount', or "
                "'image'")
        elif ca_delivery not in ("env", "mount", "image"):
            errors.append(
                f"[network].ca_delivery must be one of 'env', 'mount', "
                f"'image', got {ca_delivery!r}")
        elif ca_delivery == "mount" and not ca_mount_path:
            errors.append(
                "[network].ca_delivery = 'mount' requires ca_mount_path -- "
                "the in-container path the CA bundle is mounted at")
        # ca_delivery = "image" asserts the image was built trusting this
        # workload's CA, which can only be true of a bundle with its own
        # Containerfile (R9) -- but this function sees only [network], not
        # the bundle directory, so that check belongs to whichever caller
        # loads the whole workload (a TODO for P1-2's caller, not a gap in
        # this function's contract).
    if ca_mount_path and ca_delivery != "mount":
        errors.append(
            "[network].ca_mount_path is set but ca_delivery is not "
            "'mount' -- the path is only meaningful when workloadctl is "
            "the one bind-mounting the bundle")

    for host in splice_hosts:
        # V18: a per-host splice entry when the whole workload is already on
        # rung 2 (splice) exempts nothing, and V14 just made the operator
        # write a `reason` for a hole they did not open.
        if effective_tls == "splice":
            errors.append(
                f"[network].splice: {host!r} is redundant -- this "
                f"workload's effective tls mode is already 'splice', so "
                f"every host is spliced and this entry exempts nothing. "
                f"Drop it, or add a [[network.policy]] entry to move the "
                f"workload to rung 3 first")

    return errors


