"""
The container [network] section: its scalars, its entries, its validation, and
the nft/inspector artefacts it renders to.

The container half of what lib/vm_network_config.py and lib/vm_validate.py are for a VM. Read the same
way -- straight off the parsed table, no dedicated parse layer -- and validated
by the same rules where the substrates share them.
"""
from typing import NamedTuple

from config_parser import (
    ContainerCredential, ContainerPolicyEntry,
    _validate_container_host_pattern, container_allow_resolve,
    container_allowed_hosts, container_policy_entries,
    container_runs_on_host_network,
    patterns_overlap, validate_credential_entries,
)
from egress_ca import RESERVED_GUEST_ENV
from egress_policy import (
    INSPECT_GUEST_AGENT_KEY, POLICY_METHODS, POLICY_METHODS_REFUSED,
    hostname_match,
)
from nft_constants import (
    NFT_BIN, NFT_SET_ALLOW4, NFT_SET_ALLOW6, NFT_SET_FILTERED, NFT_TABLE,
)
from workload_addr import allow_reserved_reason

# --- Container [network] scalars ---
#
# Read the same way as VM's vm_allowed_hosts()/net.get("tls")/etc.
# (lib/vm_defs.py) -- no dedicated parse function on that side either. `tls` is
# deliberately returned raw (None when absent), not defaulted here: unlike
# the VM's fixed default, the container's effective tls is *computed* from
# whether any policy entry is present, and that computation belongs to
# validate_container_network(), not to parsing.

def container_tls_mode(net: dict) -> str | None:
    """The literal [network].tls value, or None if absent. Not defaulted --
    see module note above."""
    value = net.get("tls")
    return value if isinstance(value, str) and value.strip() else None


def container_tls_reason(net: dict) -> str | None:
    value = net.get("tls_reason")
    return value.strip() if isinstance(value, str) and value.strip() else None


def container_ca_delivery(net: dict) -> str | None:
    value = net.get("ca_delivery")
    return value.strip() if isinstance(value, str) and value.strip() else None


def container_ca_mount_path(net: dict) -> str | None:
    value = net.get("ca_mount_path")
    return value.strip() if isinstance(value, str) and value.strip() else None


# --- Container [[network.internal]] / [[network.splice]] ---
#
# Shape-tolerant, like the policy/credential pair in config_parser -- validation is
# validate_container_network()'s job, not parsing's. Unlike VM's
# _host_reason_hosts() (lib/egress_policy.py), `reason` is kept rather than
# discarded: every entry is required to carry a reason, and unlike
# the VM side -- where a malformed entry can never reach this code because
# the boot path already ran validate_vm_network() -- there is no such
# validator yet, so reporting code reading these tuples needs `reason`
# available rather than assumed-valid-elsewhere.

class ContainerHostReasonEntry(NamedTuple):
    """One [[network.internal]] or [[network.splice]] entry, normalised.
    Both arrays share this `{host, reason}` shape, same as the VM side's
    shared `_host_reason_hosts()` helper."""

    host: str
    reason: str | None


def container_internal_entries(net: dict) -> list[ContainerHostReasonEntry]:
    return _container_host_reason_entries(net, "internal")


def container_splice_entries(net: dict) -> list[ContainerHostReasonEntry]:
    return _container_host_reason_entries(net, "splice")


def _container_host_reason_entries(net: dict, key: str) -> list[ContainerHostReasonEntry]:
    raw = net.get(key, [])
    if not isinstance(raw, list):
        return []
    entries = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        host = item.get("host")
        if not isinstance(host, str) or not host.strip():
            continue
        reason = item.get("reason")
        reason = reason.strip() if isinstance(reason, str) and reason.strip() else None
        entries.append(ContainerHostReasonEntry(host=host.strip(), reason=reason))
    return entries


# --- Container [network] validation ---
#
# The parse functions above are deliberately shape-tolerant; every semantic
# rule lives here or nowhere. Mirrors validate_vm_network (lib/vm_validate.py)
# and validate_egress (lib/vm_egress_validate.py) where the two schemas share
# a rule. Diverges where the container
# schema has no `egress` key (presence of a trigger is the whole statement)
# and no bridge escape hatch. `mode = "host"` IS special-cased below:
# a host-mode container's processes span the workload's whole subuid window
# rather than its single uid, which is what every selector in
# workload-filter.nft is keyed on. See container_uses_inspect().

def container_effective_tls_mode(net: dict) -> str:
    """The tls mode actually in force: the literal key if the operator wrote
    one, else computed per the three-rung ladder -- no policy entries means
    splice, any policy entry means inspect. Meaningless on a workload with no
    trigger at all (no proxy exists for it to describe), but harmless to
    compute. Reporting code (doctor/rules/egress) must call this, not read
    `tls` directly, because the literal key may be absent while a proxy is
    still running in one mode or the other."""
    explicit = container_tls_mode(net)
    if explicit is not None:
        return explicit
    return "inspect" if container_policy_entries(net) else "splice"


def validate_container_network(net: dict, config: dict | None = None) -> list[str]:
    """Validate [network] on a container workload. Returns a list of error
    strings. Implements every numbered rule in the container egress-parity
    build spec's validation section except V13 (reserved for a deferred
    [[network.http2]] array), plus the mode="host" delta (§6 delta 2),
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
        # contradiction, not redundancy.
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


# --- Container egress: nft element lifecycle (P1-7/P1-8) ---
#
# The low-level uid-keyed nft builders (element commands for the DNAT maps,
# the internal-destination exemptions, the cgroup exemptions) live in
# lib/nft_elements.py and take nothing but a uid and already-resolved addresses -- no
# VM-specific state -- so they are reused verbatim for containers (imported
# directly by lib/filter_arm.py and lib/inspect_arm.py). What
# differs, and what lives here, is
# resolving and shaping the CONTAINER schema's own entry types
# (ContainerAllowEntry keeps `host`/`address`/`port` apart, where VmAllowEntry
# packs them into one 'addr:port' string) into the inputs those builders take.

def container_allow_resolved(allow: list) -> list:
    """[(ContainerAllowEntry, [addr...])] for every [[network.allow]] entry,
    resolved once. Mirrors vm_allow_resolved."""
    return [(entry, container_allow_resolve(entry)) for entry in allow]


def container_filter_elements(uid: int, allow: list, resolved=None) -> dict:
    """Map set name -> element expressions for one container workload.

    Mirrors vm_filter_elements, but built from ContainerAllowEntry rather
    than VmAllowEntry. Reuses the shared set names and the reserved-range
    check (nft_constants.NFT_SET_FILTERED/ALLOW4/ALLOW6,
    workload_addr.allow_reserved_reason): both substrates share the one
    filter table (D3), so a container's would-be element in another workload's
    listener range is refused by the identical rule a VM's is.
    """
    if resolved is None:
        resolved = container_allow_resolved(allow)
    elements: dict[str, list[str]] = {NFT_SET_FILTERED: [str(uid)]}
    v4: list[str] = []
    v6: list[str] = []
    for entry, addresses in resolved:
        for addr in addresses:
            reserved = allow_reserved_reason(addr)
            if reserved:
                where = f"{entry.host!r} resolves there -- " if entry.host else ""
                raise ValueError(f"[network].allow: {where}{reserved}")
            (v6 if addr.version == 6 else v4).append(
                f"{uid} . {addr} . {entry.port}")
    if v4:
        elements[NFT_SET_ALLOW4] = v4
    if v6:
        elements[NFT_SET_ALLOW6] = v6
    return elements


def container_filter_commands(uid: int, allow: list, action: str, resolved=None) -> list:
    """argv lists that arm ('add') or disarm ('delete') one container
    workload's allowlist elements. Mirrors vm_filter_commands."""
    if action not in ("add", "delete"):
        raise ValueError(f"action must be 'add' or 'delete', got {action!r}")
    commands = []
    for set_name, entries in container_filter_elements(uid, allow, resolved).items():
        commands.append([NFT_BIN, action, "element", *NFT_TABLE.split(), set_name,
                         "{ " + ", ".join(entries) + " }"])
    return commands


def container_internal_resolve(host: str) -> list:
    """Resolve one [[network.internal]] host, or raise ValueError naming it.
    Mirrors vm_internal_resolve. Fatal by design (see that function and
    inspect_arm.internal_failure): an exemption armed for the wrong
    address, or not armed at all, leaves the host refused by the drop the
    entry existed to except.
    """
    import ipaddress
    import socket
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(
            f"[[network.internal]] names {host!r}, which does not resolve on "
            f"this host ({exc}). The exemption is armed per ADDRESS, so an "
            f"unresolvable name arms nothing and the host stays refused by "
            f"the internal-destination drop the entry existed to except") from None
    seen = []
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if addr not in seen:
            seen.append(addr)
    return seen


def container_inspect_policy(net: dict) -> dict:
    """The inspector's policy document for one container workload.

    Same JSON shape as vm_inspect_policy (lib/egress_policy.py) -- D6: the
    listener binary (workload-inspect-listener) does not change between
    substrates, so whichever wrote the file, it reads the same keys. `http2`
    is always empty: [[network.http2]] is deferred for containers (§5 of the
    build spec). `tls` is the EFFECTIVE mode (container_effective_tls_mode),
    not the literal key, since the container schema computes it per the
    three-rung ladder rather than defaulting it the way the VM schema does.

    `guest_agent` IS THE ONE KEY THIS RENDERER EMITS AND THE VM'S DOES NOT,
    and it states a fact about the substrate rather than an instruction. A
    container has no QEMU guest agent, so a remedy that works by asking one --
    the mint-time clock check -- cannot run here. Left unsaid, the listener
    wired that check for containers too, dialled a socket that has never
    existed on this substrate once per mint miss, and counted each attempt
    into `clock_unavailable`, whose exported meaning is "the mint-time clock
    remedy is INERT in this guest". On a container that reading was
    guaranteed and told an operator a remedy was broken rather than absent.

    A FACT, not `clock_remedy: false`, so the next thing that turns on "there
    is no agent to ask" reads this key instead of adding a second one. Emitted
    only here, so a VM's document is byte-identical to what it was and the
    drift comparison does not fire for every VM; a container's document DOES
    change once, and reports drift until it is re-armed.
    """
    return {
        "tls": container_effective_tls_mode(net),
        INSPECT_GUEST_AGENT_KEY: False,
        "hosts": container_allowed_hosts(net),
        "internal": [e.host for e in container_internal_entries(net)],
        "splice": [e.host for e in container_splice_entries(net)],
        "http2": [],
        "policy": [
            {"host": e.host,
             "methods": None if e.methods is None else list(e.methods),
             "paths": None if e.paths is None else list(e.paths),
             **({"credential": e.credential} if e.credential else {})}
            for e in container_policy_entries(net)],
    }


def container_inspect_policy_text(net: dict) -> str:
    """The policy document as the exact bytes that land on disk. Mirrors
    vm_inspect_policy_text -- same formatting, so a future drift/digest
    comparison cannot disagree with itself over which substrate rendered the
    file."""
    import json
    return json.dumps(container_inspect_policy(net), indent=2, sort_keys=True) + "\n"
