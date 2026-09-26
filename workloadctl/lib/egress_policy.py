#!/usr/bin/env python3
"""What a filtered workload is allowed to reach, as workloadctl renders it.

One subsystem, one file, on the WRITING side of the inspector's document:
the predicates that decide whether a workload is inspected at all, the
parsed `[[network.policy]]` entries, the JSON document the listener reads,
and where the listener's documents live. The vocabulary that document is
written IN -- the hostname rule, the TLS modes, the entry type and how a set
of entries governs a request, the digest -- is inspect_document, one rung
down, and the listener imports THAT and never this: the document is the
interface, and the listener has no reason to know the config grammar that
produced it. The `Policy` the listener reads it back into is inspect_policy.

Every path here is spelled at least twice -- once by the code that renders
or arms, once by the code that reads back -- which is the reason a constant
here is a constant rather than a literal: a drift between the two turns a
real refusal into a figure that reads zero, which is indistinguishable from
a refusal that never fired. What the listener refuses WITH, and the record
it writes, are egress_record's.

Both substrates. The `vm_`/`VM_` prefixes record which one came first, not who
is served -- containers adopted the same listener and the same document.

Below workload_lib and below the substrate facade: this module imports
config_parser, inspect_document and vm_defs and nothing above them. The
policy document's digest is a pure function of the rendered text, and the
render is a pure function of the TOML, which is what lets
`collect_policy_drift()` compare bytes.

Installed to /usr/libexec/workloadctl/egress_policy.py.
"""

import json
from pathlib import Path

from config_parser import infer_workload_mode, parse_policy_entries, SOCKET_DIR
from container_network_config import (
    container_allowed_hosts,
    container_effective_tls_mode,
    container_internal_entries,
    container_policy_entries,
    container_splice_entries,
    container_uses_inspect,
)
from customs.inspect_document import (
    TLS_DEFAULT, VmPolicyEntry, normalise_hostname,
)
from vm_defs import EGRESS_DEFAULT, vm_allowed_hosts
from workload_addr import RESOLVE_STATIC_FILE


def vm_uses_inspect(config: dict) -> bool:
    """Whether this workload's egress is redirected into an inspector.

    The single source of the predicate that decides whether the inspect
    socket/service units exist at all: not bridged (a bridged guest has no
    host socket in its data path, so there is no uid to key the redirect on)
    and `egress` filtered (an unfiltered VM would be the one the redirect
    breaks — its dial to a port-443 service it is allowed to reach would be
    translated into a listener that would refuse it, having no policy naming
    it). inspect_arm's VM substrate names this as its `applies` rather than
    re-stating it, so the generator and the helper cannot drift apart.

    A workload with no [vm] section is not a VM and is never inspected. That is
    tested here rather than left to the callers: every caller happens to be
    behind a VM-only branch today, so a container config reaching this returned
    True and nothing noticed. A predicate documented as the single source of a
    decision has to be right standing alone, or the next caller inherits a bug
    that reads as correct at its own call site.
    """
    if "vm" not in config:
        return False
    vm_cfg = config.get("vm", {}) or {}
    net = vm_cfg.get("network", {}) or {}
    if not isinstance(net, dict) or net.get("bridge"):
        return False
    return net.get("egress", EGRESS_DEFAULT) == "filtered"


# --- The responder knob, and [[vm.network.policy]] as parsed entries ---
def vm_uses_resolve(config: dict) -> bool:
    """Whether this workload gets a synthesising responder.

    Everything vm_uses_inspect requires (a VM, not bridged, filtered) plus
    `resolver` not being "none". One knob, one meaning, in both places: a
    responder under `egress = "open"` would answer every name with an inspector
    address that nothing redirects to, and one under `resolver = "none"` would
    be a nameserver for a guest that asked for no nameserver -- and passt is
    told about it in the same breath, so a disagreement here is a guest pointed
    at a port with nothing behind it.
    """
    if not vm_uses_inspect(config):
        return False
    net = (config.get("vm", {}) or {}).get("network", {}) or {}
    return net.get("resolver", "host") != "none"


def container_uses_resolve(config: dict) -> bool:
    """Whether this container workload gets a synthesising responder.

    Everything container_uses_inspect requires, on a network pasta carries:
    single or pod topology with `[network].mode` pasta, the default. pasta is
    what the responder is reached through -- podman starts it with
    `--dns-forward`, and container_pasta_network adds `--dns-host` pointing
    that address at the responder -- so a network pasta is not on has no way
    to it. A bridge-mode workload resolves through aardvark-dns, which
    forwards to the host's nameservers and takes no such option.

    There is no `resolver` knob on this side. A container that needs a name
    answered with its real address says so in `[[network.allow]]`, which the
    static map serves.
    """
    if not container_uses_inspect(config):
        return False
    try:
        if infer_workload_mode(config) == "bridge":
            return False
    except ValueError:
        return False
    return container_network_mode(config) == "pasta"


def container_network_mode(config: dict) -> str:
    """`[network].mode` without pasta's options: "pasta" for "pasta:..."."""
    net = config.get("network", {})
    mode = net.get("mode", "pasta") if isinstance(net, dict) else "pasta"
    return str(mode).split(":", 1)[0]


# The HTTP methods a [[vm.network.policy]] entry may name. Registered tokens
# only (IANA HTTP Method Registry), because §3 requires a method that is not one
# to be an ERROR rather than a rule that can never match: `["FETCH"]` and
# `["GET "]` are both far likelier to be a typo that silently denies than an
# intent, and a denial nobody can see is the failure this layer exists to
# prevent.
#
# CONNECT and PRI are registered and are deliberately NOT here. The inspector is
# transparent -- it is reached by a redirect, never by a proxy request -- so a
# guest has no CONNECT to send it and an entry permitting one describes a
# request that cannot arrive. PRI is the HTTP/2 connection preface's method,
# which is refused on every terminated host: the inspector relays no HTTP/2,
# and permitting it by name would read as a way to allow h2 through `policy`.
POLICY_METHODS = frozenset((
    "ACL", "BASELINE-CONTROL", "BIND", "CHECKIN", "CHECKOUT", "COPY", "DELETE",
    "GET", "HEAD", "LABEL", "LINK", "LOCK", "MERGE", "MKACTIVITY",
    "MKCALENDAR", "MKCOL", "MKREDIRECTREF", "MKWORKSPACE", "MOVE", "OPTIONS",
    "ORDERPATCH", "PATCH", "POST", "PROPFIND", "PROPPATCH", "PUT", "REBIND",
    "REPORT", "SEARCH", "TRACE", "UNBIND", "UNCHECKOUT", "UNLINK", "UNLOCK",
    "UPDATE", "UPDATEREDIRECTREF", "VERSION-CONTROL",
))


POLICY_METHODS_REFUSED = {
    "CONNECT": "the inspector is transparent and is never sent a CONNECT; a "
               "guest reaches it by a redirect it cannot see",
    "PRI": "PRI is the HTTP/2 connection preface's method, and the "
           "inspector relays no HTTP/2; a host that must keep h2 is "
           "[[vm.network.splice]]",
}


def vm_policy_entries(net: dict) -> list[VmPolicyEntry]:
    """The [[vm.network.policy]] entries, normalised, in file order.

    Shape-tolerant for the reason internal_hosts is: validate_vm_network
    owns the shape and the boot generator skips a workload that does not
    validate.
    """
    return parse_policy_entries(net, VmPolicyEntry)


# --- The inspector's policy document (§7.7.1, §13) ---
#
# The listener is socket-activated and long-lived, so it reads its lists once,
# at start, out of the workload's runtime directory — written at start rather
# than at generate time for the reason the retired proxy's config was: /run
# does not exist when the boot generator runs, and writing at start is what
# makes an edited list take effect on a plain `systemctl restart` with no
# regeneration. §13 states that recovery property, and the inspect service's
# PartOf= on the VM is what enforces it; a listener that held its lists in a
# file written at generate time would keep enforcing the previous boot's policy.
#
# JSON rather than a bare line-per-pattern file — the shape the proxy's
# hosts.allow had — because this document carries a mode as well as a list and
# will carry more of both.
INSPECT_POLICY_FILE = "inspect.json"


def inspect_policy_path(name: str) -> str:
    """Where one workload's inspector reads its lists from."""
    return f"{SOCKET_DIR}/{name}/{INSPECT_POLICY_FILE}"


def resolve_static_path(name: str) -> str:
    """Where one workload's responder reads its static map from."""
    return f"{SOCKET_DIR}/{name}/{RESOLVE_STATIC_FILE}"


def resolve_static(resolved) -> dict[str, list[str]]:
    """The responder's static map for one workload: name to addresses.

    The `allow`-by-name entries, which customs-resolve answers from this map
    instead of with the inspector's address. Without it a synthesised answer
    sends every named non-80/443 destination -- an SSH forge, a registry, an
    internal API -- to a port the inspector does not serve, which presents as
    a healthy-looking hang rather than as a refusal. The map wins over
    synthesis, which costs nothing on 80 and 443 because the redirect is
    keyed on uid and port alone; a name in both `hosts` and `allow` is
    therefore legal.

    `resolved` is the arming path's own resolution, (entry, [addr...]) with
    either substrate's `allow` entry, so the map holds the addresses that were
    ARMED -- see vm_filter_elements for why a second resolution is a
    different question.
    """
    static: dict[str, list[str]] = {}
    for entry, addresses in resolved:
        if entry.host is None:
            continue
        # Normalised on the way in, so two spellings of one name cannot
        # become two entries.
        key = normalise_hostname(entry.host)
        for addr in addresses:
            text = str(addr)
            if text not in static.setdefault(key, []):
                static[key].append(text)
    return static


INSPECT_STATUS_FILE = "inspect-status.json"


def inspect_status_path(name: str) -> str:
    """Where one workload's inspector writes its counters.

    Two status files rather than one, and customs' egress_status carries the
    argument: the responder is a separate socket-activated process, and two
    processes atomically replacing one path leaves only the last writer's
    figures, silently.
    """
    return f"{SOCKET_DIR}/{name}/{INSPECT_STATUS_FILE}"


# WHERE THE PER-REQUEST RECORD GOES, and why it is not in the journal and not
# under the workload tree.
#
# NOT THE JOURNAL. The inspector's unit sets StandardOutput=journal, so a record
# written with its ordinary logging lands in a sink readable by root,
# `systemd-journal` and `adm` -- every sudo-capable login on the host -- rotated
# by nothing this project owns and forwarded off-box by whatever the host's
# journald is configured to do. A URL path is evidence of what a sandboxed agent
# was doing, and a query string can carry a credential outright. The decision
# lines STAY in the journal, which is the right sink for a message whose job is
# to tell an operator what to fix; the record is a different document with a
# different reader. A LogNamespace= was the leading alternative and gives
# rotation and isolation for free -- but a namespace journal is still readable
# by `systemd-journal` and `adm`, which is the wrong ACL on a host where sudo
# does not stay passwordless.
#
# NOT THE WORKLOAD TREE either. state/ is svirt_image_t, the label
# pki_fcontext_patterns() exists to move material OUT of -- an audit record
# does not belong in the same tree as the guest's disks. data/ is worse: `./`
# volume anchors resolve into it, so a guest with a virtiofs volume at the data
# root would read its own audit log.
#
# So /var/log, where logrotate is expected to look and where the record survives
# a rollback of the state tree. The MODES are the access decision:
#
#   /var/log/workloadctl/               root:root  0755
#   /var/log/workloadctl/egress/        root:root  0711
#   /var/log/workloadctl/egress/<name>/ _wl-<name> 0700
#   .../requests.log                    _wl-<name> 0600
#
# Root and the workload uid, nobody else -- strictly tighter than any journal
# option. The per-workload directory is owned by the workload rather than by
# root because the listener recreates the file itself after a rotation (see the
# logrotate snippet's `nocreate`), and a process running as _wl-<name> cannot
# create a name in a directory root owns at 0700.
#
# egress/ is 0711 and NOT 0700, which is the same distinction: the listener has
# to traverse it as _wl-<name> to reach its own leaf at all. It was 0700 until
# a KVM host measured what that costs -- EACCES on every record write, silent,
# because the write may never raise. The search bit grants no read, so the ACL
# argument one level up is intact: the directory still cannot be listed.
INSPECT_RECORD_ROOT = Path("/var/log/workloadctl/egress")
INSPECT_RECORD_FILE = "requests.log"


# The per-workload directory is a systemd LogsDirectory=, whose names are
# relative to /var/log. Stated once so the generator and the readers cannot
# drift: a LogsDirectory= that named a different path than the listener writes
# to would give the unit a writable directory nobody uses and a write that
# fails EROFS under ProtectSystem=strict -- which the leaf caches already
# taught us is swallowed by the per-connection OSError handler and reads as a
# network fault.
LOG_BASE = Path("/var/log")


def inspect_record_dir(name: str) -> Path:
    """Where one workload's per-request record lives."""
    return INSPECT_RECORD_ROOT / name


def inspect_record_path(name: str) -> Path:
    """The record file itself."""
    return inspect_record_dir(name) / INSPECT_RECORD_FILE


def inspect_logs_directory(name: str) -> str:
    """The LogsDirectory= value for one workload's inspect service."""
    return str(inspect_record_dir(name).relative_to(LOG_BASE))


def vm_inspect_policy(net: dict) -> dict:
    """The inspector's policy document for one workload.

    `hosts` is `[vm.network].hosts` unchanged.

    `internal` is carried and AUTHORISES NOTHING. An `internal` entry names a
    host that is already on a list (validation refuses one that is not), and it
    excepts the inspector's *upstream* leg from the internal drop rather than
    authorising a name. The listener never consults it to admit a connection:
    the kernel's wl_internal_ok4/6 elements are the one enforcement point, and a
    second one in userspace could disagree with them while both looked right.

    `splice` is the [[vm.network.splice]] host patterns, and unlike `internal`
    it DOES decide something: a name it matches is spliced rather than
    terminated, on a workload whose `tls` is otherwise "inspect". It is carried
    even when tls is "splice", where it changes nothing, so that the document
    describes the file rather than the file filtered through the mode -- a
    listener restarted onto a different `tls` reads a document that already
    says what the per-host list was.

    `http2` is always empty. The inspector relays no HTTP/2 and refuses a
    list that names a host; the key stays so that the document, and so its
    digest, is the one every inspected workload already has.

    `policy` is the [[vm.network.policy]] entries, normalised. `methods` and
    `paths` are carried as null where the key was absent rather than as an
    empty list, because absent means ANY and empty would mean NONE -- and JSON
    has a word for the difference, so the document should use it rather than
    make the reader recover it from the schema.

    It is here so that a FAILED upstream dial to a private address can be
    attributed. An allowlisted name that resolved into private space with no
    entry is the wildcard trap firing; one WITH an entry is a host that is
    simply down. Those are the same OSError without this list, and telling them
    apart is the whole value of the internal-refusal counter.

    `credential` is the credstore NAME of the material a request to this host
    is brokered with, and it is carried ONLY on the entries that set one --
    an entry without a credential emits no key at all rather than a null.
    That sparseness is load-bearing, not tidiness: the document is byte-compared
    by `collect_policy_drift()` and digested for `diagnose`, so a `"credential":
    null` on every entry would change the digest of every filtered VM on the
    fleet and report drift on all of them at upgrade -- which is how a drift
    signal stops being read. A missing key and a null mean the same thing to the
    listener (`entry.get("credential")`), so the cheaper side of the trade is
    the reader's.

    NO ADDRESS is carried with it. The generator derives the broker's
    endpoint from the workload's uid, which it already has, and writes it
    into the listener's unit as a flag (gen_egress.inspect_listener_command);
    putting it here would make the document non-deterministic w.r.t. the
    TOML and break the byte comparison and the digest. `placeholder` and `env` are not carried either -- they are
    seed-time and broker-command facts, and the listener decides nothing by them.

    NO `reason` OF ANY KIND IS CARRIED -- not the per-host ones, not
    `tls_reason`. A reason is written for a person reviewing the config, and
    the listener decides nothing by it; putting it in the document would give
    a guest-facing process a field it must never echo and would invite a
    future reader to treat one as data rather than as prose.
    """
    return {
        "tls": net.get("tls", TLS_DEFAULT),
        "hosts": vm_allowed_hosts(net),
        "internal": internal_hosts(net),
        "splice": splice_hosts(net),
        "http2": [],
        "policy": [
            {"host": e.host,
             "methods": None if e.methods is None else list(e.methods),
             "paths": None if e.paths is None else list(e.paths),
             **({"credential": e.credential} if e.credential else {})}
            for e in vm_policy_entries(net)],
    }


def vm_inspect_policy_text(net: dict) -> str:
    """The policy document as the exact bytes that land on disk.

    THE ONE RENDERER. inspect_arm.write_policy writes
    what this returns, and `collect_policy_drift()` compares against it, so the
    two cannot disagree about a separator, a key order or a trailing newline.
    A second `json.dumps` with its own arguments would not be a cosmetic
    duplicate: drift is a byte comparison, so an indent that differed by one
    would report every inspected workload as drifted forever, which is how a
    signal stops being read.

    sort_keys because the document has to be a pure function of the TOML and
    dict order is not; the trailing newline because a text file ends in one and
    a diff of a file that does not says `\\ No newline at end of file` on
    every hunk.
    """
    return json.dumps(vm_inspect_policy(net), indent=2, sort_keys=True) + "\n"


def container_inspect_policy(net: dict) -> dict:
    """The inspector's policy document for one container workload.

    Same JSON shape as vm_inspect_policy (lib/egress_policy.py) -- D6: the
    listener binary (customs-inspect) does not change between
    substrates, so whichever wrote the file, it reads the same keys. `http2`
    is always empty, as it is for a VM. `tls` is the EFFECTIVE mode (container_effective_tls_mode),
    not the literal key, since the container schema computes it per the
    three-rung ladder rather than defaulting it the way the VM schema does.

    NOTHING HERE SAYS WHAT SUBSTRATE THIS IS, and for one release something
    did: a `guest_agent: false` the listener read to keep its per-mint clock
    resync from dialling a QEMU socket a container has never had. The resync
    left the inspector for the clock keeper (workload-<name>-clock.timer, a
    VM's own unit), so the listener has nothing left to branch on and the key
    went with it -- a container's document changes once more, and reports
    drift until it is re-armed, the same as when the key arrived.
    """
    return {
        "tls": container_effective_tls_mode(net),
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
    return json.dumps(container_inspect_policy(net), indent=2, sort_keys=True) + "\n"


def internal_hosts(net: dict) -> list[str]:
    """The host names in [[vm.network.internal]], in file order.

    Shape-tolerant, while vm_internal_resolve two functions down is fatal on
    the same key at the same moment. The two are not in tension, and the
    difference is which question is still open at start.

    SHAPE IS ALREADY SETTLED. validate_vm_network refuses a malformed entry --
    not a table, no `host`, no `reason`, an unknown key, a host on no list --
    and the boot generator SKIPS a workload whose config does not validate, so
    it emits no units at all. A malformed entry therefore cannot reach this
    function on the boot path: there is no VM for it to break. Raising here
    would restate a verdict already delivered, in a context that can only
    convert it into a start failure with a worse message.

    RESOLUTION IS NOT SETTLED, AND CANNOT BE. Whether a name answers is a fact
    about the host and the moment, not about the config -- `validate` warns on
    it precisely because it cannot decide it. So the check has to happen at
    start, and its failure is deliberately fatal: an exemption that silently
    did not arm leaves the guest refused by the very drop the entry existed to
    except. See inspect_arm.internal_failure for what that failure
    then has to say for itself.

    So: tolerate what validation owns, fail loudly on what only start can know.
    """
    return _host_reason_hosts(net, "internal")


def splice_hosts(net: dict) -> list[str]:
    """The host patterns in [[vm.network.splice]], in file order.

    HLD §11's second escape hatch: one host that must not be terminated,
    exempted on a plain restart. The third hatch -- `tls = "splice"` for the
    whole workload -- is a different key and this list is not consulted under
    it, because there everything is spliced already.

    Shape-tolerant for the reason internal_hosts is: validate_vm_network
    owns the shape and the boot generator skips a workload that does not
    validate, so a malformed entry cannot reach here on the boot path.
    """
    return _host_reason_hosts(net, "splice")


def _host_reason_hosts(net: dict, key: str) -> list[str]:
    """The `host` of every well-formed [[vm.network.<key>]] entry, in order.

    One body for `internal` and `splice`, which are the same table with the
    same two keys -- the mirror of _validate_host_reason_entries on the
    validating side, and shared for the same reason: two copies of this is a
    chance for one of them to start tolerating a shape the other refuses, on
    a path where the difference is silent.
    """
    entries = net.get(key, [])
    if not isinstance(entries, list):
        return []
    return [e["host"].strip() for e in entries
            if isinstance(e, dict) and isinstance(e.get("host"), str)
            and e["host"].strip()]
