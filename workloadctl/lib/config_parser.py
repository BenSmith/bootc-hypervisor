"""
Where a workload's config lives, and how it parses into validated records.

The bottom of the layering, next to credential_entries and egress_plane.
Both substrates read the same TOML grammar, so the parse loops and the
hostname normalisation live below the shared plane rather than in either
substrate's module -- a second copy is how two spellings of the same rule
come to disagree. The credential block has its own module, credential_entries,
for the same reason.

Installed to /usr/libexec/workloadctl/config_parser.py.
"""

import fnmatch
import re
from pathlib import Path
from typing import NamedTuple
from credential_entries import parse_credential_entries
from egress_plane import CLEARTEXT, TLS


# Persistent workload data directory
WORKLOADS_BASE = Path("/var/lib/workloads")

# Per-instance runtime directory, /run/workload-vm/<name>/, for BOTH
# substrates: a VM keeps its QMP and guest-agent sockets there, and any
# workload with an egress inspector -- container or VM -- keeps the
# inspector's policy and status documents there. The path keeps the name it
# shipped with; it is an SELinux fcontext pattern and live state on deployed
# hosts, not just a string.
SOCKET_DIR = Path("/run/workload-vm")


VALID_WORKLOAD_MODES = ("single", "pod", "bridge")


def parse_volume_spec(vol_spec: str) -> tuple[str, str, str]:
    """Parse a "host:guest[:opts]" volume spec, returning (host, guest, opts).

    A bare token (no ':') is treated as host == guest. opts defaults to "rw".
    Only the first two ':' delimit fields, so opts may itself contain a colon
    (e.g. mount options). This is the single source of truth for the grammar;
    expand_volume_path builds on it.
    """
    parts = vol_spec.split(":", 2)
    host = parts[0]
    guest = parts[1] if len(parts) > 1 else parts[0]
    opts = parts[2] if len(parts) > 2 else "rw"
    return host, guest, opts


def workload_root_dir(name: str) -> Path:
    """Per-workload durable-state root: /var/lib/workloads/<name>.

    Spans both the reconstructible state/ subtree and the precious data/ subtree;
    use this for writable-path grants and containment checks.
    """
    return WORKLOADS_BASE / name


def runtime_dir(name: str) -> str:
    """Where one instance's config, allowlist, log and pid file live."""
    return f"{SOCKET_DIR}/{name}"


# --- Validation ---

def infer_workload_mode(config: dict) -> str:
    """Return 'single', 'pod', or 'bridge'. Validates the value if explicit."""
    mode = config.get("workload", {}).get("mode")
    if mode is not None:
        if mode not in VALID_WORKLOAD_MODES:
            raise ValueError(
                f"Invalid workload.mode {mode!r}; must be one of {VALID_WORKLOAD_MODES}"
            )
        return mode
    return "pod" if "containers" in config else "single"


# --- Shared policy parsing ---
#
# One parse loop per table, shared by both substrates. The TYPES stay
# separate -- see the ContainerPolicyEntry note below for why -- but the
# loops that fill them do not: they were verbatim copies of each other, and
# a copy is how the two come to disagree about what a malformed entry means
# after only one of them is fixed. The entry class is the parameter, so a
# substrate keeps its own vocabulary and shares the shape-tolerance rules.
#
# Every function here is shape-tolerant on purpose. Real validation lives in
# the per-substrate validate_* functions, and the boot generator skips a
# workload that does not validate.

def normalise_policy_list(value, *, upper: bool = False) -> tuple | None:
    """One `methods` or `paths` value as a tuple, or None where it was absent.

    None and () are different answers and the caller depends on it; see
    egress_policy.VmPolicyEntry and ContainerPolicyEntry below.
    """
    if value is None:
        return None
    if not isinstance(value, list):
        return ()
    out = []
    for item in value:
        if not isinstance(item, str):
            continue
        # NOT stripped: validation refuses a padded token or path outright,
        # so nothing that reaches here needs it, and a strip in one of the two
        # places is how they come to disagree about what the file said.
        out.append(item.upper() if upper else item)
    return tuple(out)


def parse_policy_entries(net: dict, entry_cls) -> list:
    """The `policy` entries of one network table, normalised, in file order.

    `entry_cls` is VmPolicyEntry or ContainerPolicyEntry -- field-identical
    by construction, and the only thing that differs between the substrates.
    """
    entries = []
    raw = net.get("policy", [])
    if not isinstance(raw, list):
        return entries
    for item in raw:
        if not isinstance(item, dict):
            continue
        host = item.get("host")
        if not isinstance(host, str) or not host.strip():
            continue
        credential = item.get("credential")
        if not isinstance(credential, str) or not credential.strip():
            credential = None
        else:
            credential = credential.strip()
        entries.append(entry_cls(
            host=host.strip(),
            methods=normalise_policy_list(item.get("methods"), upper=True),
            paths=normalise_policy_list(item.get("paths")),
            credential=credential))
    return entries


# --- Shared hostname matching ---
#
# The one normalisation every hostname decision in this design is made under.
# Both substrates use it: a validator that normalised with `.rstrip(".")`
# would strip a doubled trailing dot the enforcer keeps, and then disagree
# with the listener about what a name is. It lives at the bottom of the
# layering because everything above matches against it and nothing here
# needs anything above.


def normalise_hostname(host: str) -> str:
    """A hostname in the one form every match in this design is made against.

    Lowercased and stripped of a single trailing root dot. Both halves matter:
    DNS names are case-insensitive, and `example.com.` and `example.com` are the
    same name -- a workload that writes either spelling must get the same
    decision, or the spelling becomes the bypass.
    """
    host = host.strip().lower()
    return host[:-1] if host.endswith(".") and host != "." else host


def patterns_overlap(a: str, b: str) -> bool:
    """Whether two fnmatch host patterns can name a host in common.

    Approximate, and deliberately approximate in the ACCEPTING direction: it
    answers yes when either pattern matches the other read as a literal, which
    is exact whenever at least one of the two carries no wildcard and is a
    good-enough over-approximation when both do. `*.a.example.com` and
    `*.b.example.com` overlap on nothing and this says so; `*.example.com` and
    `*.com` overlap and this says so too.

    Used for the "this entry matches no allowlisted name" rules, where the two
    sides are an entry's `host` and an allowlist pattern and only one of them is
    ordinarily a wildcard. Wrong in the accepting direction means a dead entry
    occasionally survives validation; wrong the other way would refuse a config
    that works, which is the expensive mistake for a rule whose whole job is to
    catch a typo.
    """
    a = normalise_hostname(a)
    b = normalise_hostname(b)
    if not a or not b:
        return False
    return a == b or fnmatch.fnmatchcase(a, b) or fnmatch.fnmatchcase(b, a)


HOST_PATTERN_RE = re.compile(r"^[A-Za-z0-9*?.\[\]!_-]+$")


def validate_host_pattern(pattern, *, allow_key: str,
                          star_remedy: str) -> list[str]:
    """Validate one hostname pattern. Returns error strings, unprefixed --
    every caller prefixes them with the table and key it read them from.

    The two keyword arguments are the whole of what the two substrates disagree
    about: which array carries a destination that names a port, and what an
    operator who wrote `*` should do instead. Everything else -- a scheme, a
    path, a port, the character class -- is a property of an fnmatch hostname
    pattern and not of the substrate matching it, which is why this was worth
    stating once. It was stated twice for as long as this module could not
    import vm.py, and both copies were called only from functions that already
    import vm.py lazily, so the constraint never actually bound.
    """
    if not isinstance(pattern, str):
        return [f"entries must be strings, got {pattern!r}"]
    text = pattern.strip()
    if not text:
        return ["entries must not be empty"]
    if "://" in text:
        return [f"{pattern!r} looks like a URL -- patterns match the hostname "
                f"only, so drop the scheme"]
    if "/" in text:
        return [f"{pattern!r} contains a path -- patterns match the hostname "
                f"only, so a path never matches"]
    if ":" in text:
        return [f"{pattern!r} contains a port -- hostname policy applies to "
                f"the redirected ports ({CLEARTEXT.guest_port} and "
                f"{TLS.guest_port}) only; use {allow_key} for other ports"]
    if text == "*":
        return [f"'*' matches every host, {star_remedy}"]
    if not HOST_PATTERN_RE.match(text):
        return [f"{pattern!r} is not a hostname or fnmatch pattern"]
    return []


# --- Container egress policy/credential schema ---
#
# [network.policy] / [network.credential], parsed BY the shared loops above
# and for the same reason as [[vm.network.policy]] / [[vm.network.credential]]
# in lib/egress_policy.py and lib/broker_config.py: shape-tolerant here, with
# real validation living in a separate validate_* function (not yet written --
# there is no container inspector to validate against yet). Deliberately its
# own small NamedTuple pair rather
# than reuse of VmPolicyEntry/VmCredential: those are keyed on `[vm.network]`
# specifically, and container topology has no `[vm]` section to key off of.
# Widening them instead would put a substrate branch inside a pair of
# structures whose whole job is to describe one substrate's table. Sharing the
# PARSE and not the TYPE is what keeps both of those true at once.

class ContainerPolicyEntry(NamedTuple):
    """One [[network.policy]] entry, normalised.

    `methods` and `paths` are `None` where the key was absent, not an empty
    tuple -- absent means "any", empty would mean "none". Same convention as
    VmPolicyEntry, for the same reason: collapsing the two would make a
    single-entry host with no `paths` deny everything instead of permitting
    everything.
    """

    host: str
    methods: tuple | None
    paths: tuple | None
    credential: str | None = None


def container_policy_entries(net: dict) -> list[ContainerPolicyEntry]:
    """The [[network.policy]] entries for one container's [network] table,
    normalised, in file order. Shape-tolerant; a future validate function
    owns rejecting malformed entries."""
    return parse_policy_entries(net, ContainerPolicyEntry)


class ContainerCredential(NamedTuple):
    """One [[network.credential]] block, normalised. Same shape as
    broker_config.VmCredential and for the same reasons -- see that class's
    docstring for why `auth_header`/`auth_format` are optional and live here
    rather than on the policy entry."""

    name: str
    placeholder: str
    env: str
    auth_header: str | None = None
    auth_format: str | None = None


def container_credential_entries(net: dict) -> list[ContainerCredential]:
    """The [[network.credential]] blocks for one container's [network]
    table, normalised, in file order. Shape-tolerant; a future validate
    function owns rejecting malformed entries."""
    return parse_credential_entries(net, ContainerCredential)


def container_allowed_hosts(net: dict) -> list[str]:
    """The [network].hosts allowlist, in file order. Shape-tolerant."""
    hosts = net.get("hosts", [])
    if not isinstance(hosts, list):
        return []
    return [h for h in hosts if isinstance(h, str) and h.strip()]


class ContainerAllowEntry(NamedTuple):
    """One [[network.allow]] entry, normalised. `host` and `address` are
    both surfaced raw (unlike VmAllowEntry, which resolves an address into
    an ipaddress object at parse time) -- that split is a validation
    decision (which regex matched, is it resolvable) this function does not
    make."""

    host: str | None
    address: str | None
    port: int | None
    reason: str | None


def container_allow_entries(net: dict) -> list[ContainerAllowEntry]:
    """The [[network.allow]] entries for one container's [network] table,
    normalised, in file order. Shape-tolerant."""
    entries: list[ContainerAllowEntry] = []
    raw = net.get("allow", [])
    if not isinstance(raw, list):
        return entries
    for item in raw:
        if not isinstance(item, dict):
            continue
        host = item.get("host")
        host = host.strip() if isinstance(host, str) and host.strip() else None
        address = item.get("address")
        address = address.strip() if isinstance(address, str) and address.strip() else None
        if host is None and address is None:
            continue
        port = item.get("port")
        port = port if isinstance(port, int) and not isinstance(port, bool) else None
        reason = item.get("reason")
        reason = reason.strip() if isinstance(reason, str) and reason.strip() else None
        entries.append(ContainerAllowEntry(host=host, address=address, port=port, reason=reason))
    return entries


def container_runs_on_host_network(config: dict) -> bool:
    """Whether this workload's containers really share the host netns.

    `[network].mode` is workload-level but it is NOT honoured in every
    topology. `single` passes it to `podman run --network=` and `pod` passes it
    to `podman pod create --network=`, so `mode = "host"` means host networking
    in both. `bridge` mode ignores it outright -- every member joins
    `workload-<name>-net` instead (see _network_args in container_run_args, which
    warns that workload-level [network].ports is ignored there for the same
    reason).

    So a bridge-mode workload carrying a leftover `mode = "host"` is not on the
    host network, its traffic IS re-originated by a pasta-equivalent host
    process owned by the workload uid, and uid attribution holds exactly as
    container_uses_inspect() describes for pasta. Refusing it would be refusing
    a workload for a key the generator never reads.
    """
    net = config.get("network", {})
    if not isinstance(net, dict) or net.get("mode") != "host":
        return False
    try:
        return infer_workload_mode(config) != "bridge"
    except ValueError:
        # An invalid workload.mode is somebody else's error to report; assume
        # the key is honoured rather than quietly waving the workload through.
        return True


def container_uses_inspect(config: dict) -> bool:
    """Whether this workload's egress is redirected into an inspector.

    Mirrors ``vm_uses_inspect()`` (lib/egress_policy.py) for the container
    substrate: the single source of the predicate (D2 in the container
    egress-parity build spec). ``ContainerSubstrate.uses_inspect()`` delegates here rather than
    restating the logic, and ``get_enabled_workloads()``
    (lib/exporter_collect.py) calls it directly on the raw parsed TOML --
    it reads config off disk and cannot build a WorkloadConfig/Substrate.
    """
    net = config.get("network", {})
    if not isinstance(net, dict):
        return False
    if container_runs_on_host_network(config):
        # Host mode is never inspected, and validate_container_network()
        # (lib/container_validate.py) rejects the combination outright --
        # this is the belt to that
        # braces, for a config already on disk when the rule landed.
        #
        # P0-1 measured it on hardware rather than assuming. Two findings,
        # only one of them the expected one:
        #   - the host's OWN traffic is not captured. Root and uid 1000 both
        #     matched no workload selector even with the netns shared, so
        #     host mode does not drag host sockets into a workload's policy.
        #   - but a container's processes do not share ONE uid. Under the
        #     default `userns = "keep-id"` exactly one in-container uid maps
        #     to the workload uid; in-container root and any other user map
        #     into the workload's 65536-wide subuid window. Measured: an
        #     image default matched `meta skuid <uid>`, while `user = "0"`
        #     and `user = "1000"` both left as subuids.
        # Every selector in workload-filter.nft is keyed on the single uid,
        # so filtering here would silently cover only bundles that happen to
        # run as the keep-id uid -- an image detail, not a policy decision.
        # Pasta and bridge mode are unaffected: their traffic is re-originated
        # by a host process owned by the workload uid, and all three arms
        # measured `exact-uid` there. Bridge mode is unaffected even when the
        # key IS written, because bridge mode never reads it -- which is what
        # container_runs_on_host_network() is for.
        return False
    # Any one of the three opt-in triggers, not policy alone: `hosts` and
    # `allow` are each triggers on their own (a hosts-only workload gets a
    # spliced proxy with no policy to speak of).
    return bool(container_allowed_hosts(net) or container_policy_entries(net)
                or container_allow_entries(net))


def _validate_container_host_pattern(pattern) -> list[str]:
    """Validate one hostname pattern (`hosts`, `policy.host`, or an
    `internal`/`splice` entry's `host`).

    The container half of validate_host_pattern: it exists to state the two
    sentences the container schema owns. There is no `egress` key here (R3), so
    an operator who wrote `*` is told to drop the table rather than to set a
    key that does not exist -- which is the one place the VM's wording would be
    actively wrong here.
    """
    return validate_host_pattern(
        pattern,
        allow_key="[[network.allow]]",
        star_remedy=("which filters nothing but looks configured -- drop the "
                     "[network] table entirely to run unfiltered"))


def container_allow_resolve(entry: ContainerAllowEntry) -> list:
    """Resolve one [[network.allow]] entry to concrete addresses.

    Mirrors vm_allow_resolve (lib/vm_network_config.py), adapted to
    ContainerAllowEntry's separate `address`/`host` fields. An address entry is
    returned as-is; a
    host entry is resolved here, once, at arm time. Not tolerant: an
    unresolvable name must arm nothing, and arming nothing silently is worse
    than failing loudly -- the workload then meets the default deny on that
    destination and hangs, with the drop landing on a host-wide counter that
    names neither it nor the entry.

    R3's "no default-deny for containers" is about the UNTRIGGERED case, and
    reading it as "a container is never default-denied" is a mistake this
    docstring used to make. A workload with any trigger is placed in
    `wl_filtered` by container_filter_elements() (lib/nft_elements.py), and
    nftables/workload-filter.nft's last output rule drops everything from a
    `wl_filtered` uid that no earlier rule accepted. What R3 rules out is an
    `egress` key that could default-deny a workload WITHOUT giving it an
    inspector; it does not exempt a triggered one from the drop.
    """
    import ipaddress
    import socket
    if entry.address is not None:
        return [ipaddress.ip_address(entry.address)]
    try:
        infos = socket.getaddrinfo(entry.host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(
            f"[[network.allow]] names {entry.host!r}, which does not resolve "
            f"on this host ({exc}). It is resolved once at arm time, so an "
            f"unresolvable name arms nothing and the workload cannot reach "
            f"it") from None
    seen = []
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if addr not in seen:
            seen.append(addr)
    return seen
