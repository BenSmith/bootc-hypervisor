"""The rules a `[vm]` declaration must satisfy.

validate_vm_config is the front door validation calls for a VM workload; it
checks the section itself -- image source, restart, memory, disks, seed,
virtiofs mounts -- and hands `[vm.network]` to validate_vm_network, which
checks the shape of the section and then everything a filtered or inspected
VM may say about its egress: `hosts`, `internal`, `splice`, `http2`,
`policy`, `credential`, `allow`, and every way those contradict each other or
the substrate. vm_network_warnings is the soft half, what is legal but
probably not meant. The entries themselves are parsed by vm_network_config;
nothing here renders a unit, an nft element or a policy document.

Installed to /usr/libexec/workloadctl/vm_validate.py.
"""

import re

from broker_config import VmCredential
from config_parser import (
    normalise_hostname,
    parse_volume_spec,
    patterns_overlap,
    validate_credential_entries,
    validate_host_pattern,
)
from egress_ca import RESERVED_GUEST_ENV
from egress_policy import (
    POLICY_METHODS,
    POLICY_METHODS_REFUSED,
    TLS_DEFAULT,
    TLS_MODES,
    VmPolicyEntry,
    hostname_match,
)
from vm_defs import (
    EGRESS_DEFAULT,
    EGRESS_MODES,
    REGISTRATION_DOMAIN_PARENTS,
    SEED_PROVIDES_CHOICES,
    SEED_PROVIDES_RETIRED,
    TLS_UNBUILT,
    parse_memory_mib,
    parse_vm_port,
)
from vm_network_config import VmAllowEntry, parse_vm_allow
from workload_addr import reserved_range


def _validate_host_reason_entries(entries, key: str, reason_clause: str):
    """Shape-check an array of [[vm.network.<key>]] `host`/`reason` tables.

    Returns (hosts, errors). `hosts` holds the stripped `host` of every entry
    whose host was well-formed, in file order, so a caller can apply the rule
    that is its own -- which for all three users of this helper is some form of
    "this entry matches nothing, and a dead bypass fails silently".

    Shared because `internal`, `splice` and `http2` are the same table with the
    same two keys and the same two failure directions, and three copies of this
    drifted in review before there was one. What is NOT shared is the sentence
    each key gives for a missing `reason` (`reason_clause`) or for a dead entry:
    those name what the operator was trying to do, which is the whole value of
    the message.
    """
    errors: list[str] = []
    hosts: list[str] = []
    if not isinstance(entries, list):
        errors.append(
            f"[vm.network].{key} must be an array of [[vm.network.{key}]] "
            f"tables, got {type(entries).__name__}")
        return hosts, errors
    for item in entries:
        if not isinstance(item, dict):
            errors.append(
                f"[vm.network].{key} entries are tables with `host` and "
                f"`reason`, got {item!r}")
            continue
        unknown = sorted(set(item) - {"host", "reason"})
        if unknown:
            errors.append(
                f"[vm.network].{key}: unknown key(s) {', '.join(unknown)}; an "
                f"entry carries `host` and `reason` only")
        if "host" not in item:
            errors.append(f"[vm.network].{key}: entry {item!r} has no `host`")
            continue
        host = item.get("host")
        problems = _validate_proxy_host(host)
        if problems:
            errors.extend(f"[vm.network].{key}: {p}" for p in problems)
            continue
        host = host.strip()
        hosts.append(host)
        if not isinstance(item.get("reason"), str) or not item["reason"].strip():
            errors.append(f"[vm.network].{key}: {host!r} has no `reason`; "
                          f"{reason_clause}")
    return hosts, errors


def _validate_policy_path(pattern) -> list[str]:
    """Validate one [[vm.network.policy]] `paths` pattern."""
    if not isinstance(pattern, str):
        return [f"`paths` entries must be strings, got {pattern!r}"]
    if not pattern.strip():
        return ["`paths` entries must not be empty"]
    if pattern != pattern.strip():
        return [f"path {pattern!r} is padded with whitespace, which a request "
                f"target never carries — matched as written it can never "
                f"match, and stripped it would hide the next one"]
    text = pattern
    if "://" in text:
        return [f"path {pattern!r} looks like a URL — `paths` matches the "
                f"path alone, so drop the scheme and the host"]
    if not text.startswith("/"):
        return [f"path {pattern!r} does not start with '/' — `paths` is "
                f"matched against the request target's path, which always "
                f"does, so this pattern can never match"]
    if "?" in text or "#" in text:
        return [f"path {pattern!r} carries a query or fragment — `paths` "
                f"matches the path ALONE, deliberately, so that "
                f"paths = ['/v1/messages'] still permits "
                f"'/v1/messages?stream=true'. A pattern that names one "
                f"never matches"]
    return []


def _validate_policy_methods(item, host: str) -> tuple[tuple | None, list[str]]:
    """Validate one entry's `methods`. Returns (normalised or None, errors)."""
    if "methods" not in item:
        return None, []
    value = item["methods"]
    if not isinstance(value, list):
        return (), [f"[vm.network].policy: {host!r} `methods` must be an "
                    f"array of HTTP method names, got "
                    f"{type(value).__name__}"]
    errors: list[str] = []
    out: list[str] = []
    for token in value:
        if not isinstance(token, str):
            errors.append(f"[vm.network].policy: {host!r} `methods` entries "
                          f"must be strings, got {token!r}")
            continue
        # Compared uppercase, so `["get"]` is accepted and normalised. What is
        # NOT accepted is `["GET "]`: stripping it would be the same kindness
        # applied to a different thing, since a method token cannot contain
        # whitespace and one that does is a typo -- and the strip that hid it
        # would leave the operator's next typo silently denying instead.
        if token != token.strip() or any(c.isspace() for c in token):
            errors.append(
                f"[vm.network].policy: {host!r} names the method {token!r}, "
                f"which carries whitespace. A method token cannot, so this is "
                f"a typo -- and accepting it by stripping would hide the next "
                f"one")
            continue
        name = token.upper()
        if name in POLICY_METHODS_REFUSED:
            errors.append(
                f"[vm.network].policy: {host!r} names the method {token!r}, "
                f"which this inspector never sees — "
                f"{POLICY_METHODS_REFUSED[name]}")
            continue
        if name not in POLICY_METHODS:
            errors.append(
                f"[vm.network].policy: {host!r} names {token!r}, which is not "
                f"a registered HTTP method. A method that never matches denies "
                f"every request that would have used it, and nothing reports "
                f"that it was a typo")
            continue
        out.append(name)
    if not out and not errors:
        errors.append(
            f"[vm.network].policy: {host!r} has an empty `methods` list, which "
            f"permits no method at all. Omit the key to mean any method")
    return tuple(out), errors


def _validate_credentials(net: dict) -> tuple[list[VmCredential], list[str]]:
    """Validate [[vm.network.credential]]. Returns (credentials, errors).

    The VM half of validate_credential_entries: it names the table this
    substrate spells the block under, the noun its messages use for the thing
    the placeholder is seeded into, and the variables workloadctl already puts
    there.
    """
    return validate_credential_entries(
        net, table="vm.network", noun="guest", credential_cls=VmCredential,
        reserved_env=RESERVED_GUEST_ENV)


def _validate_policy(net: dict, splice_hosts, http2_hosts, egress: str,
                     tls, credentials=()) -> tuple[list[VmPolicyEntry], list[str]]:
    """Validate [[vm.network.policy]]. Returns (entries, errors).

    NO `hosts` PARAMETER, and its absence is the decision rather than a rule
    left unwritten. `internal`, `splice` and `http2` each get a "this entry
    matches no allowlisted name" error, because each of them is an exception
    TO the allowlist and one naming a host that is not on it is dead. A
    `policy` entry is not: §3 makes it allowlist its own host, so an entry
    matching nothing in `.hosts` is the ordinary way to write one, and a rule
    borrowed from the three siblings for symmetry would refuse the
    configuration the schema documents.
    """
    errors: list[str] = []
    raw = net.get("policy", [])
    if not isinstance(raw, list):
        return [], [f"[vm.network].policy must be an array of "
                    f"[[vm.network.policy]] tables, got "
                    f"{type(raw).__name__}"]

    known = {"host", "methods", "paths", "credential"}
    # `placeholder` was on the entry in the design's §3 draft and moved onto the
    # [[vm.network.credential]] block when the guest variable name had to land
    # somewhere too. Named rather than reported as an unknown key, for the reason
    # TLS_UNBUILT gives: an operator who wrote it followed a document that
    # said to, and should be told where it went rather than sent hunting for a
    # typo that is not there.
    misplaced = {
        "placeholder": (
            "it is a property of the CREDENTIAL, not of the entry -- two "
            "entries selecting one credential cannot disagree about it if "
            "there is nowhere for them to disagree. Put it on the "
            "[[vm.network.credential]] block that declares the name this "
            "entry selects"),
    }
    credential_names = {c.name for c in credentials}
    entries: list[VmPolicyEntry] = []
    for item in raw:
        if not isinstance(item, dict):
            errors.append(
                f"[vm.network].policy entries are tables with `host` and "
                f"optional `methods`/`paths`, got {item!r}")
            continue
        for key in sorted(set(item) & set(misplaced)):
            errors.append(
                f"[vm.network].policy: `{key}` does not belong on an entry — "
                f"{misplaced[key]}")
        unknown = sorted(set(item) - known - set(misplaced))
        if unknown:
            errors.append(
                f"[vm.network].policy: unknown key(s) {', '.join(unknown)}; an "
                f"entry carries `host`, `methods`, `paths` and `credential`")
        if "host" not in item:
            errors.append(f"[vm.network].policy: entry {item!r} has no `host`")
            continue
        problems = _validate_proxy_host(item.get("host"))
        if problems:
            errors.extend(f"[vm.network].policy: {p}" for p in problems)
            continue
        host = item["host"].strip()
        methods, method_errors = _validate_policy_methods(item, host)
        errors.extend(method_errors)
        paths: tuple | None = None
        if "paths" in item:
            value = item["paths"]
            if not isinstance(value, list):
                errors.append(
                    f"[vm.network].policy: {host!r} `paths` must be an array "
                    f"of path patterns, got {type(value).__name__}")
                paths = ()
            else:
                paths = tuple(p for p in value if isinstance(p, str))
                for pattern in value:
                    errors.extend(f"[vm.network].policy: {host!r} {p}"
                                  for p in _validate_policy_path(pattern))
                if not value:
                    errors.append(
                        f"[vm.network].policy: {host!r} has an empty `paths` "
                        f"list, which permits no path at all. Omit the key to "
                        f"mean any path")
        credential = None
        if "credential" in item:
            value = item["credential"]
            if not isinstance(value, str) or not value.strip():
                errors.append(
                    f"[vm.network].policy: {host!r} `credential` must be the "
                    f"name of a [[vm.network.credential]] block, got "
                    f"{value!r}")
            else:
                credential = value.strip()
                if credential not in credential_names:
                    # Not a warning and not silently inert. An entry naming a
                    # credential that does not exist is a host the operator
                    # believes is brokered and is not: the request goes
                    # straight to the provider carrying the guest's own
                    # placeholder, and the provider answers 401 on a request
                    # this layer considers fully authorised.
                    errors.append(
                        f"[vm.network].policy: {host!r} selects credential "
                        f"{credential!r}, which no [[vm.network.credential]] "
                        f"block declares. Declare it with `name`, "
                        f"`placeholder` and `env`, or drop the key and let "
                        f"the guest reach this host with whatever it holds")
        if credential and "*" in host:
            # The broker's table is keyed by the EXACT Host a request carries
            # (ADR 007 decision 3, and normalise_host does not glob), so a
            # wildcard entry that selects a credential brokers nothing: the
            # inspector authorises the request against this pattern, dials the
            # broker, and the broker finds no row for the concrete name and
            # refuses it. Refused here rather than left to produce that 403,
            # because the 403 arrives on a request every other layer agreed to
            # and names a host the file appears to cover.
            errors.append(
                f"[vm.network].policy: {host!r} selects credential "
                f"{credential!r}, but a credential is attached per exact Host "
                f"— the broker's table has no patterns in it, so every request "
                f"matching this entry would be authorised here and refused "
                f"there. Name the host this credential belongs to in an entry "
                f"of its own, and keep the wildcard entry for the hosts that "
                f"take no credential")
        entries.append(VmPolicyEntry(host=host, methods=methods, paths=paths,
                                     credential=credential))

    # A block nothing selects is material sealed, loaded into a broker instance
    # and never attached to anything -- which reads, in the file and in
    # `diagnose`, as a credential that IS in use. The reverse of the rule above
    # and refused on the same terms.
    for cred in credentials:
        if not any(e.credential == cred.name for e in entries):
            errors.append(
                f"[vm.network].credential: {cred.name!r} is declared but no "
                f"[[vm.network.policy]] entry selects it, so it is sealed, "
                f"loaded and attached to nothing while the file reads as "
                f"though a host were brokered. Add `credential = "
                f"{cred.name!r}` to the entry for the host it belongs to, or "
                f"drop the block")

    if not entries:
        return entries, errors

    if tls == "splice" and any(e.credential for e in entries):
        # Reported ALONGSIDE the entries-are-inert message below, not instead of
        # it, and the redundancy is the point: that message tells the operator
        # `methods` and `paths` cannot run, which is a lost restriction. This one
        # tells them the credential is not attached, which is a lost REQUEST --
        # the guest reaches the provider holding a placeholder and gets a 401 it
        # cannot explain. An operator who read only the first message would fix
        # the wrong half.
        errors.append(
            "[vm.network].policy: `credential` with tls = 'splice' — a spliced "
            "connection is never decrypted, so there is no request for the "
            "broker to attach a credential to and the guest reaches the "
            "provider carrying its placeholder. Set tls = 'inspect' (the "
            "default) for this workload and exempt only the hosts that cannot "
            "take the CA with [[vm.network.splice]] entries, or drop the "
            "credential and give the guest a real key.")
    if tls == "splice":
        errors.append(
            "[vm.network].policy with tls = 'splice' — a spliced connection is "
            "never decrypted, so there is no request for `methods` and `paths` "
            "to be applied to and the entries would be silently inert. Use "
            "tls = 'inspect' (the default), or drop the policy entries and "
            "keep the name allowlist in .hosts.")
    if egress != "filtered":
        errors.append(
            f"[vm.network].policy has no effect with .egress = {egress!r} — "
            f"nothing is redirected into the egress inspector, so no request "
            f"is ever read for it to govern. Set egress = 'filtered' to use "
            f"it.")

    # A name in both `splice` and `policy` is an error: the policy could never
    # run, and the file states two intentions that cannot both hold.
    for entry in entries:
        for spliced in splice_hosts:
            if patterns_overlap(entry.host, spliced):
                errors.append(
                    f"[vm.network].policy: {entry.host!r} is also in .splice "
                    f"({spliced!r}) — a spliced connection is never decrypted, "
                    f"so the method and path rules could never run. Keep one: "
                    f"splice the host and drop the policy entry, or drop the "
                    f"splice entry and let the host be inspected")
                break

    # And a name in both `http2` and `policy`, which is the same failure one
    # key along and reads as the milder one. It is not milder: an h2 stream's
    # request headers are HPACK-compressed frames nothing here decodes, so
    # `methods` and `paths` have no text to match and the entry is inert in
    # exactly the way the splice case is. The difference is only that `splice`
    # looks like an exemption and `http2` looks like a protocol -- which is the
    # misreading HLD §8 corrected, and the reason this gets its own sentence
    # rather than being folded into the loop above.
    for entry in entries:
        for h2_host in http2_hosts:
            if patterns_overlap(entry.host, h2_host):
                errors.append(
                    f"[vm.network].policy: {entry.host!r} is also in .http2 "
                    f"({h2_host!r}) — an h2 connection is relayed at the frame "
                    f"level with its headers left HPACK-compressed, so there "
                    f"is no request line for `methods` and `paths` to match "
                    f"and the rules could never run. Keep one: drop the "
                    f".http2 entry and let the host be inspected as HTTP/1.1, "
                    f"or drop the policy entry and accept that this host is "
                    f"enforced by name alone")
                break

    # The per-host twins of the two rules above, for the credential rather than
    # for the rules. Kept separate for the same reason: the sibling messages
    # name a lost restriction, and what is lost here is the request itself.
    for entry in entries:
        if not entry.credential:
            continue
        for spliced in splice_hosts:
            if patterns_overlap(entry.host, spliced):
                errors.append(
                    f"[vm.network].policy: {entry.host!r} selects credential "
                    f"{entry.credential!r} and is also in .splice "
                    f"({spliced!r}) — a spliced connection is never "
                    f"decrypted, so nothing can be attached to the request "
                    f"and the guest reaches the provider carrying its "
                    f"placeholder. Drop the splice entry so the host is "
                    f"inspected, or drop the credential")
                break
        for h2_host in http2_hosts:
            # ADR 007's decision 4, which neither the design's validation list
            # nor the ADR names -- both name the splice case, which is this
            # one's exact twin. An h2 host is relayed at the frame level with
            # its headers left HPACK-compressed, so there is no `Host`, no
            # method and no path; and (uid, Host) is the ENTIRE dispatch key of
            # a broker instance, which is an HTTP/1.1 server. A credential here
            # cannot be attached at all, not merely attached less precisely.
            if patterns_overlap(entry.host, h2_host):
                errors.append(
                    f"[vm.network].policy: {entry.host!r} selects credential "
                    f"{entry.credential!r} and is also in .http2 "
                    f"({h2_host!r}) — an h2 connection is relayed at the frame "
                    f"level with its headers HPACK-compressed, so there is no "
                    f"`Host` for the broker to dispatch on and no request for "
                    f"it to attach a credential to. Drop the .http2 entry for "
                    f"this host and let it be inspected as HTTP/1.1, or move "
                    f"the credential to a host that is not relayed")
                break

    # §3's widening trap. Where more than one entry matches a host BY PATTERN,
    # every one of those entries must state both keys -- one entry omitting
    # `paths` permits every path on that host and silently defeats every
    # sibling that was carefully narrowed, while the file reads as if it were
    # more restrictive than it is.
    #
    # By pattern and not by identical `host` strings, which is the half that is
    # easy to implement wrongly: `*.example.com` and `api.example.com` are two
    # entries matching one name, and a check comparing literal hosts passes
    # exactly the file this rule exists to catch.
    for i, entry in enumerate(entries):
        siblings = [o for j, o in enumerate(entries)
                    if j != i and patterns_overlap(entry.host, o.host)]
        if not siblings:
            continue
        missing = [k for k, v in (("methods", entry.methods),
                                  ("paths", entry.paths)) if v is None]
        if missing:
            errors.append(
                f"[vm.network].policy: {entry.host!r} shares a host with "
                f"{siblings[0].host!r} and omits "
                f"{' and '.join(f'`{k}`' for k in missing)}. Where entries "
                f"overlap, an omitted key means ANY -- so this entry permits "
                f"everything its siblings were narrowed to forbid, and the "
                f"file looks more restrictive than it is. State both keys on "
                f"every overlapping entry")

    # The credential's own widening trap, and it is TWO rules because the two
    # shapes need different remedies.
    #
    # Entries union, so where several match one name every one of them governs
    # it -- and the broker attaches at most one credential to a request. Two
    # entries naming DIFFERENT credentials for one host make which key goes
    # upstream a function of match order, which the file does not state; and one
    # entry naming a credential beside one that does not means a request the
    # narrow entry would have brokered can be admitted by the wide one and leave
    # unbrokered. Both fail in the same silent direction: the guest's own
    # placeholder reaches the provider and the 401 comes back from a request
    # this layer considers fully authorised.
    for i, entry in enumerate(entries):
        siblings = [o for j, o in enumerate(entries)
                    if j != i and patterns_overlap(entry.host, o.host)]
        if not siblings:
            continue
        # Reported from the EARLIER entry of the pair only (`j > i`), so a
        # disagreement produces one message rather than one per participant --
        # the same pair read from both ends is the same finding.
        disagreeing = [o for j, o in enumerate(entries)
                       if j > i and patterns_overlap(entry.host, o.host)
                       and o.credential and entry.credential
                       and o.credential != entry.credential]
        if disagreeing:
            errors.append(
                f"[vm.network].policy: {entry.host!r} selects credential "
                f"{entry.credential!r} and {disagreeing[0].host!r} selects "
                f"{disagreeing[0].credential!r}, and the two patterns match "
                f"the same host. Entries union and at most one credential is "
                f"attached, so which key goes upstream depends on match order "
                f"rather than on this file. Give the overlapping entries one "
                f"credential, or narrow their `host` patterns so they do not "
                f"cover the same name")
        unbrokered = [o for o in siblings if not o.credential]
        if entry.credential and unbrokered:
            # THE REMEDY THAT IS NOT ONE is named explicitly, because it is the
            # first thing a reader reaches for: adding the credential to the
            # wider entry does not narrow anything -- it brokers every request
            # the wide entry admits, which is the opposite of what the narrow
            # entry was written to do.
            errors.append(
                f"[vm.network].policy: {entry.host!r} selects credential "
                f"{entry.credential!r} but {unbrokered[0].host!r} matches the "
                f"same host and selects none. Entries union, so a request the "
                f"wider entry admits leaves unbrokered carrying the guest's "
                f"placeholder, and the file reads as though the host were "
                f"brokered. Demote the unbrokered entry to a .hosts pattern if "
                f"it exists only to allowlist the name, or narrow its `host` "
                f"so it no longer covers this one. Adding the credential to it "
                f"as well is NOT a fix: that brokers everything the wide entry "
                f"admits, which is what the narrow entry exists to avoid")

    # A copy-paste a reader will assume does something.
    seen: dict = {}
    for entry in entries:
        key = (normalise_hostname(entry.host),
               None if entry.methods is None else tuple(sorted(set(entry.methods))),
               None if entry.paths is None else tuple(sorted(set(entry.paths))),
               entry.credential)
        if key in seen:
            errors.append(
                f"[vm.network].policy: {entry.host!r} appears twice with the "
                f"same `methods`, `paths` and `credential`. Entries union, so "
                f"the duplicate "
                f"permits nothing the first does not — which a reader will "
                f"assume it does. Drop one")
        seen[key] = entry

    return entries, errors


def _validate_apex_coverage(hosts, entries, key: str, consequence: str, *,
                            self_allowlisting: bool = False) -> list[str]:
    """§3's apex trap: an allowlisted apex that a wildcard entry leaves out.

    Patterns are fnmatch, not DNS suffix matching, so `*.example.com` requires
    something before the dot and does NOT cover the bare `example.com`. Neither
    existing rule catches this: the wildcard entry DOES match allowlisted names,
    just not the apex, so "an entry matching no allowlisted name is an error"
    never fires.

    `entries` is a list of host patterns. `consequence` names what the operator
    gets instead, which differs by key and is the whole value of the message.

    THE WILDCARD IS LOOKED FOR IN THE ENTRIES, NOT IN `.hosts`, and getting
    that backwards left the rule firing on the one spelling nobody writes.
    Requiring `*.apex` to appear in `.hosts` too catches only the REDUNDANT
    form -- a `policy` entry allowlists its own host, so the natural way to
    write the trap is `hosts = ["example.com"]` beside a lone `*.example.com`
    entry, with the wildcard nowhere in `.hosts` because it does not need to
    be. That shape was silent, on the one key that has no dead-entry rule to
    catch it instead.

    `self_allowlisting` says whether an entry naming something `.hosts` does
    not cover means anything on its own. It does for `policy` (§3) and it does
    not for `splice` and `http2`, where such an entry is ALREADY refused as
    dead -- so there the apex message is suppressed rather than stacked on top
    of one that says a different thing about the same line.
    """
    errors: list[str] = []
    literal = [h.strip() for h in hosts if isinstance(h, str) and h.strip()]
    named = [e for e in entries if e]
    for apex in literal:
        wildcard = f"*.{apex}"
        if not any(normalise_hostname(e) == normalise_hostname(wildcard)
                   for e in named):
            continue
        if not self_allowlisting and not any(
                patterns_overlap(wildcard, pattern) for pattern in literal):
            continue
        if any(hostname_match(apex, (e,)) for e in named):
            continue
        errors.append(
            f"[vm.network].{key}: {wildcard!r} does not cover the apex "
            f"{apex!r}, which .hosts also allowlists — patterns are fnmatch, "
            f"not DNS suffix matching, so `*.` requires a label before the "
            f"dot. {consequence} Add an entry for {apex!r} too, or drop it "
            f"from .hosts")
    return errors


def _validate_egress(net: dict) -> list[str]:
    """Validate [vm.network].egress and .allow.

    `egress` defaults to "filtered" (ADR 006 §5.1): the usual argument for
    defaulting a new control off is protecting deployed workloads, and there
    are none — both VM bundles are templates. A secure default costs nothing
    now and is expensive to retrofit.

    `filtered` needs somewhere for the VM's traffic to go: either an address
    allowlist or a hostname allowlist served by its own inspector. Neither means a
    VM that can reach nothing at all, which is rejected. The failure is loud on
    purpose — silently treating an un-allowlisted VM as open is the
    misreported-confinement bug this whole layer exists to prevent.
    """
    errors: list[str] = []

    egress = net.get("egress", EGRESS_DEFAULT)
    if egress not in EGRESS_MODES:
        errors.append(
            f"[vm.network].egress must be one of "
            f"{', '.join(repr(m) for m in EGRESS_MODES)}, got {egress!r}")
        egress = EGRESS_DEFAULT

    allow = net.get("allow", [])
    allow_entries: list[VmAllowEntry] = []
    if not isinstance(allow, list):
        errors.append(
            f"[vm.network].allow must be an array of [[vm.network.allow]] "
            f"tables, got {type(allow).__name__}")
        allow = []
    else:
        for spec in allow:
            try:
                allow_entries.append(
                    parse_vm_allow(spec, filtered=egress == "filtered"))
            except ValueError as e:
                errors.append(f"[vm.network].allow: {e}")

    hosts = net.get("hosts", [])
    if not isinstance(hosts, list):
        errors.append(
            f"[vm.network].hosts must be an array of hostname patterns, got "
            f"{type(hosts).__name__}")
        hosts = []
    else:
        for pattern in hosts:
            errors.extend(f"[vm.network].hosts: {e}"
                          for e in _validate_proxy_host(pattern))

    tls = net.get("tls")
    if tls is not None:
        if tls in TLS_UNBUILT:
            errors.append(
                f"[vm.network].tls = {tls!r} is not built yet — it lands in "
                f"{TLS_UNBUILT[tls]}. Accepting the word now would give "
                f"the connection one of the modes that IS built while the "
                f"config claimed the property of one that is not, which is the "
                f"misreported confinement this layer exists to prevent. Use "
                f"one of "
                f"{', '.join(repr(m) for m in TLS_MODES)} until then.")
        elif tls not in TLS_MODES:
            errors.append(
                f"[vm.network].tls must be one of "
                f"{', '.join(repr(m) for m in TLS_MODES)}, got {tls!r}")

    # ADR 008 decision 2: splicing is a named exemption carrying a written
    # reason, never a default and never implicit. The per-host hatches enforce
    # it; the whole-workload one did not, which left the WIDEST bypass in the
    # schema as the only one an operator could open silently. Checked here rather than in _validate_host_reason_entries
    # because there is no host to hang it on -- the exemption is the workload.
    #
    # Ordered so a bad mode is reported alone: `tls = "splic"` is a typo, and
    # a second error telling the operator to justify a mode they did not ask
    # for is noise on top of the one line they need.
    tls_reason = net.get("tls_reason")
    has_reason = isinstance(tls_reason, str) and bool(tls_reason.strip())
    if tls == "splice" and not has_reason:
        errors.append(
            "[vm.network].tls = 'splice' has no `tls_reason` — this is the "
            "widest bypass in this schema: it splices EVERY host the workload "
            "reaches, not a named one, and .allow, .internal, .splice and "
            ".http2 have each carried a written reason since they existed. "
            "Without one, nothing in this file distinguishes a workload "
            "spliced because its guest cannot be re-seeded with the CA from "
            "one spliced because nobody tried. Add "
            "tls_reason = \"why this guest cannot be terminated\" beside it, "
            "or leave the workload on the default tls = 'inspect' and exempt "
            "only the hosts that need it with [[vm.network.splice]] entries, "
            "which is the narrower hatch and the one to reach for first.")
    elif tls_reason is not None and tls != "splice":
        # Not merely inert: the key asserts the workload is spliced whole, and
        # it is not. Refused in the direction the rest of this function
        # refuses -- a config that describes a confinement other than the one
        # it has, here by claiming a WEAKER one than is in force, which sends
        # a reviewer looking for an exposure that is not there.
        effective = tls if tls is not None else TLS_DEFAULT
        errors.append(
            f"[vm.network].tls_reason is set but .tls is {effective!r} — the "
            f"key records why a WHOLE workload skips termination, and this "
            f"one does not skip it. Set tls = 'splice' if that was the "
            f"intent, or drop tls_reason and put the justification on the "
            f"[[vm.network.splice]] entries that carry `reason` per host.")

    internal_hosts, internal_errors = _validate_host_reason_entries(
        net.get("internal", []), "internal",
        "it is a bypass of the internal-destination drop and carries one "
        "like `allow` does")
    errors.extend(internal_errors)
    # Deferred until `policy` has been read: §3 says a name in `policy` need
    # not also appear in `hosts`, so an `internal` entry for such a name is on
    # a list and this rule must see both lists or it refuses a working config.
    internal_deferred = list(internal_hosts)
    # HLD §11 hatch 2. A host here is spliced on a workload that otherwise
    # terminates, which is the remedy every non-HTTP refusal names -- so the
    # key has to exist before the messages that tell an operator to type it.
    splice_hosts, splice_errors = _validate_host_reason_entries(
        net.get("splice", []), "splice",
        "it exempts a host from inspection and carries one like `allow` does")
    errors.extend(splice_errors)
    for host in splice_hosts:
        # A dead entry fails in the opposite direction to a dead `internal`
        # one, which is why the two rules are written out separately rather
        # than shared: an ignored `splice` line gets you inspection you did not
        # want, on the host you exempted precisely because it cannot take it.
        if not any(patterns_overlap(host, pattern)
                   for pattern in hosts if isinstance(pattern, str)):
            errors.append(
                f"[vm.network].splice: {host!r} matches no allowlisted name — "
                f"nothing in .hosts covers it, so the entry exempts a host the "
                f"guest is refused before the exemption is reached. That is a "
                f"belief about what is reachable that the config contradicts. "
                f"Add it to .hosts, or drop this entry")

    # HLD §8's narrow opt-in, and the one bypass whose name does not look
    # like one. A host here keeps h2 and is relayed at the frame level, so its
    # `:authority` goes unread and true fronting stays open on it -- which is
    # why it carries a `reason` like every other hole rather than reading as a
    # performance flag.
    http2_hosts, http2_errors = _validate_host_reason_entries(
        net.get("http2", []), "http2",
        "it leaves the host enforced by server name alone and carries one "
        "like `allow` does")
    errors.extend(http2_errors)
    for host in http2_hosts:
        # Dead in the same direction a dead `splice` entry is: the host is
        # refused before the exemption is reached, so the operator's belief
        # about what is reachable is contradicted by the config.
        if not any(patterns_overlap(host, pattern)
                   for pattern in hosts if isinstance(pattern, str)):
            errors.append(
                f"[vm.network].http2: {host!r} matches no allowlisted name — "
                f"nothing in .hosts covers it, so the entry keeps h2 for a "
                f"host the guest is refused before the connection is served. "
                f"Add it to .hosts, or drop this entry")
        for spliced in splice_hosts:
            # Both are exemptions and only one can apply: the listener asks
            # `splices()` first, so the connection is never terminated and the
            # h2 entry decides nothing. Refused rather than resolved silently
            # in splice's favour, because the two entries state different
            # beliefs about the host -- one that it cannot take our CA, one
            # that it can and speaks h2 -- and only the operator knows which.
            if patterns_overlap(host, spliced):
                errors.append(
                    f"[vm.network].http2: {host!r} is also in .splice "
                    f"({spliced!r}) — a spliced connection is never "
                    f"terminated, so no ALPN of ours is offered on it and the "
                    f".http2 entry decides nothing. Keep one: splice the host "
                    f"and drop the .http2 entry, or drop the splice entry if "
                    f"the host can take this workload's CA")
                break

    # Before `policy`, because a policy entry selects a credential by name and
    # the "no block declares it" rule needs the blocks.
    credentials, credential_errors = _validate_credentials(net)
    errors.extend(credential_errors)

    vm_policy_entries, policy_errors = _validate_policy(
        net, splice_hosts, http2_hosts, egress, tls, credentials)
    errors.extend(policy_errors)
    policy_hosts = [e.host for e in vm_policy_entries]

    # §3's apex trap, for both keys that can fall into it, with the consequence
    # each one actually produces. They are not the same failure: a spliced apex
    # breaks as a TLS error on the host whose client cannot take the CA, while
    # an unconstrained apex is a security hole -- the operator believes a method
    # restriction is in force and it is not.
    errors.extend(_validate_apex_coverage(
        hosts, splice_hosts, "splice",
        "So the apex is INSPECTED, and a host spliced precisely because its "
        "client cannot take our CA breaks at the apex only, as a TLS error "
        "rather than as a policy message."))
    errors.extend(_validate_apex_coverage(
        hosts, policy_hosts, "policy",
        "So the apex is allowlisted and inspected with NO method or path rules "
        "applied — a restriction you believe is in force and is not.",
        self_allowlisting=True))
    errors.extend(_validate_apex_coverage(
        hosts, http2_hosts, "http2",
        "So the apex is offered `http/1.1` alone while the names under it keep "
        "h2, and a client that will not take the downgrade fails on the apex "
        "only — which presents as that one name being broken rather than as a "
        "protocol decision."))

    for host in internal_deferred:
        # A dead entry here fails in the direction nobody notices until the
        # host is needed: the guest gets `403 <host> resolves to an internal
        # address` on the one destination the entry existed to permit. An
        # error, for the same reason an `allow` element that arms nothing is.
        #
        # _patterns_overlap on BOTH halves, which is the same comparison the
        # `splice` and `http2` dead-entry rules make and for the same reason.
        # The obvious reading -- match the entry's `host` as a NAME against the
        # allowlist patterns -- gets the wildcard case backwards: an
        # `*.nas.example` entry justified by an allowlisted `a.nas.example` is
        # live, and a one-directional check calls it dead and refuses the
        # config. Wrong in the accepting direction leaves a dead entry
        # standing; wrong the other way refuses a config that works, which is
        # the expensive mistake for a rule whose whole job is to catch a typo.
        if not any(patterns_overlap(host, pattern)
                   for pattern in hosts if isinstance(pattern, str)) \
                and not any(patterns_overlap(host, pattern)
                            for pattern in policy_hosts):
            errors.append(
                f"[vm.network].internal: {host!r} is on no list — nothing "
                f"in .hosts allowlists it and no .policy entry names it, so "
                f"the entry excepts a destination the guest is refused before "
                f"the exception is reached. Add it to .hosts, or drop this "
                f"entry")

    # ACCEPTED, NOT WARNED, under tls = "splice", and the silence is the
    # decision. Every host is spliced there, so these entries ask for something
    # that is already true -- the config's intent is satisfied, not
    # contradicted, which is the test every other "key with no effect" refusal
    # in this function applies. And the mode they would fire under is HLD §11's
    # third hatch, reached in the middle of an incident by an operator whose
    # toolchain is broken: new output there is a cost with nothing to buy.
    #
    # `http2` is accepted there on the same terms as `splice`: no ALPN of ours
    # is offered on a connection that is never terminated, so the entry asks
    # for something already true rather than something contradicted.
    #
    # `internal` gets the same acceptance under `tls = "splice"` and for a
    # different reason, which is why they are written out rather than merged:
    # the internal-destination check lives on the inspector's UPSTREAM leg,
    # which a spliced connection still has, so a spliced host can resolve into
    # private space and still needs the exemption. `policy` is refused there,
    # because a spliced connection is never decrypted and there is no request
    # for it to govern. A later pass tidying the four for symmetry would take
    # the exemption away from exactly the workloads that need it.

    # §5.3: `bridge` means a real LAN identity, and nothing of ours is in that
    # guest's data path — no host socket, so no uid to match on.
    if "bridge" in net:
        for key in ("egress", "allow", "tls", "tls_reason", "internal",
                    "splice", "http2", "policy", "credential"):
            if key in net:
                errors.append(
                    f"[vm.network].{key} has no effect with .bridge set — a "
                    f"bridged VM sends from its own LAN address, not from a "
                    f"host socket owned by the workload user, so there is no "
                    f"uid for the filter to match")
        if "hosts" in net:
            errors.append(
                "[vm.network].hosts has no effect with .bridge set — hostname "
                "policy is enforced by redirecting the guest's own traffic on "
                "the workload's uid, and a bridged guest sends from its own "
                "LAN address with no host socket in the path")
        return errors

    # `policy` counts as somewhere to go: §3 says a name in `policy` need not
    # also appear in `hosts`, so a workload whose whole allowlist is written as
    # policy entries reaches those hosts and nothing else, which is a coherent
    # and rather good configuration.
    if egress == "filtered" and not allow and not hosts and not policy_hosts:
        errors.append(
            "[vm.network].egress is 'filtered' (the default) but both .allow "
            "and .hosts are empty, so this VM could reach nothing at all. "
            "List the hostnames it needs as .hosts (HTTP/HTTPS, via its own "
            "inspector), non-HTTP destinations as .allow entries "
            "('<addr>:<port>'), or set egress = 'open' to opt out of "
            "filtering.")

    # The redirect is what carries the guest's traffic to the inspector, and it
    # is armed only under 'filtered'. Under 'open' nothing is redirected at all:
    # the guest dials 443 and the packet leaves, so a `hosts` list would be read
    # by a process no connection ever reaches while the workload looked
    # configured.
    #
    # This was a sharper distinction under the proxy, and it is worth recording
    # why it stopped being one. There, 'open' left the allowlist binding on
    # cooperative guests only — the variables still pointed at a proxy that
    # still filtered — so the failure was partial confinement. Here it is total:
    # not a weaker enforcement of `hosts`, but none.
    #
    # Refused, not silently skipped: a `hosts` list accepted and then ignored is
    # the misreported confinement this layer exists to prevent. Joins .hosts with
    # .bridge (no uid in the path) and .hosts = ["*"].
    if egress == "open" and hosts:
        errors.append(
            "[vm.network].hosts is set but .egress is 'open', so nothing "
            "redirects this guest to its inspector — its traffic leaves "
            "directly and the hostname allowlist is never consulted. Set "
            "egress = 'filtered' to make the hostname allowlist enforceable, "
            "or drop .hosts to run unfiltered.")

    # `tls` and `internal` describe what happens to a redirected connection, and
    # under 'open' nothing is redirected. Refused rather than ignored, for the
    # same reason .hosts is: a key accepted and then not applied is a config
    # that reports a confinement it does not have.
    if egress != "filtered":
        for key in ("tls", "tls_reason", "internal", "splice", "http2"):
            # `policy` is not in this list: _validate_policy names it itself,
            # with a sentence about requests rather than about redirection.
            # `credential` is not either, and for a stronger version of the same
            # reason: a credential block is unusable without a policy entry
            # selecting it, so the entry's own message has already fired and a
            # second one about redirection would describe the wrong layer.
            if key in net:
                errors.append(
                    f"[vm.network].{key} has no effect with .egress = "
                    f"{egress!r} — nothing is redirected into the egress "
                    f"inspector, so there is no intercepted connection for it "
                    f"to describe. Set egress = 'filtered' to use it.")

    # `resolver = "none"` kept its meaning and lost its coherence. Under the
    # retired proxy a guest that could not resolve simply named hosts in a
    # CONNECT, which is why it was ECH-immune. Under a transparent redirect the
    # same guest can only dial literals, which reach the inspector with no name
    # to match and are dropped — so every name-based destination is unreachable
    # while the workload starts clean and reports healthy.
    #
    # An error only where the config itself contradicts it. A workload whose
    # destinations are all address-keyed `allow` elements needs no DNS, reaches
    # them through the filter chain without touching the inspector, and is
    # entitled to say so — that case is the warning in vm_network_warnings.
    if egress == "filtered" and net.get("resolver") == "none":
        named = []
        if hosts:
            named.append(".hosts")
        if internal_hosts:
            named.append(".internal")
        if splice_hosts:
            named.append(".splice")
        if http2_hosts:
            named.append(".http2")
        if policy_hosts:
            named.append(".policy")
        if any(e.host for e in allow_entries):
            # An `allow` entry written by name is in the same position: its
            # answer comes from the static map the responder serves, and
            # "none" is what turns the responder off.
            named.append("an .allow entry written by name")
        if named:
            errors.append(
                f"[vm.network].resolver = 'none' with {', '.join(named)} set — "
                f"a guest that cannot resolve can only dial literals, which "
                f"reach the inspector with no name and are dropped, so every "
                f"host named there is unreachable. Drop resolver = 'none', or "
                f"drop the host lists and reach the destinations as .allow "
                f"entries by address.")

    return errors


# Hostname patterns are matched by fnmatch against the host ALONE — the name the
# inspector read out of a Host header or an SNI, which carries no scheme, no
# path and no port. So a pattern carrying any of those never matches anything: a
# silent hole in an allowlist, which is the failure worth catching at validate
# time rather than at 3am.
def _validate_proxy_host(pattern) -> list[str]:
    """Validate one [vm.network].hosts pattern. Returns error strings.

    The VM half of validate_host_pattern: it exists to state the two sentences
    the VM schema owns. `egress = "open"` is one of them, and it is a key only
    this substrate has.
    """
    return validate_host_pattern(
        pattern,
        allow_key=".allow",
        star_remedy=("which is the same as egress = 'open' but harder to "
                     "notice — set egress = 'open' if that is meant"))


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

    errors += _validate_egress(net)

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
