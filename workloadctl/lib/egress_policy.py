#!/usr/bin/env python3
"""What a filtered workload is allowed to reach.

One subsystem, one file: the TLS mode, the hostname-matching rule, the parsed
`[[network.policy]]` entries, the JSON document the listener reads, the
`Policy` it reads it back into, and where the listener's documents live. Every name here is spelled at least twice --
once by the code that renders or arms, once by the code that reads back --
which is the reason a constant here is a constant rather than a literal: a
drift between the two turns a real refusal into a figure that reads zero,
which is indistinguishable from a refusal that never fired. What the listener
refuses WITH, and the record it writes, are egress_record's.

Both substrates. The `vm_`/`VM_` prefixes record which one came first, not who
is served -- containers adopted the same listener and the same document.

Below workload_lib and below the substrate facade: this module imports
config_parser and vm_defs and nothing above them. The policy document's
digest is a pure function of the rendered text, and the render is a pure
function of the TOML, which is what lets `collect_policy_drift()` compare
bytes.

Installed to /usr/libexec/workloadctl/egress_policy.py.
"""

import fnmatch
import hashlib
import json
from pathlib import Path
from typing import NamedTuple

from config_parser import normalise_hostname, parse_policy_entries, SOCKET_DIR
from container_network_config import (
    container_allowed_hosts,
    container_effective_tls_mode,
    container_internal_entries,
    container_policy_entries,
    container_splice_entries,
)
from vm_defs import EGRESS_DEFAULT, vm_allowed_hosts


# --- The two TLS modes, and the hostname rules every list is matched by ---
# What a filtered workload's redirected TLS connections get.
#
# `splice` reads the ClientHello's SNI, matches it against `hosts`, and replays
# those exact bytes upstream. Nothing is decrypted; the guest's handshake is
# with the origin, and this host never holds a key to it.
#
# `inspect` terminates. The inspector completes the guest's handshake itself
# with a leaf minted by this workload's own CA, opens a separately verified
# session to the origin, and authorises every REQUEST inside. It is the default
# because the property the allowlist claims -- that the guest reaches these
# hosts and no others -- is only true per request under termination: under
# `splice` a name is checked once, at the front of a connection whose contents
# nothing can see.
#
# THE DEFAULT MOVED, AND IT IS NOT A FREE CHANGE. A terminated guest must trust
# the workload's CA, which reaches it through the seed, which cloud-init applies
# once per instance-id. An EXISTING filtered guest does not gain that trust by
# upgrading the RPM: it gets certificate errors on every HTTPS request until it
# is re-seeded. `tls = "splice"` is the answer for a guest that cannot be, and
# is still fully supported -- it is a weaker property, not a deprecated one.
#
# IT COSTS A SENTENCE. `splice` here is the widest bypass in this schema: every
# host, not a named one, and the three narrower hatches beside it (.allow,
# .internal, .splice, .http2) have each carried a written `reason` since they
# existed. So this one requires `tls_reason`, for the reason those do -- the
# person deciding whether a bypass is still needed is not the person who opened
# it, and "spliced because this guest cannot hold the CA" and "spliced because
# nobody tried" are the same two words in a config without it. The key is a
# sibling scalar rather than a table because `tls` is a mode, not a list: a
# polymorphic `tls` that was sometimes a string and sometimes a table would
# make the commonest line in the section the one hardest to read.
TLS_MODES = ("splice", "inspect")
TLS_DEFAULT = "inspect"


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


# --- Hostname vocabulary: one normalisation, one refusal, one comparison ---
#
# Both substrates and three entrypoints ask the same questions of a name, and a
# second answer to "what is this name" is a name the guest can spell twice.

# The normalisation itself is config_parser.normalise_hostname, imported above.
# It lives one rung down rather than being copied when the container half needed
# it too, for that reason: a second answer would let the guest pick which
# normalisation it got by how it spelled the host. Callers import it from
# config_parser, not from here -- this module used to re-export it, and a name
# with two homes is the thing this section exists to prevent.


def hostname_control_character(host: str) -> str | None:
    """The first control character in a name, or None if it carries none.

    A name read off the wire — an SNI, a DNS label — is bytes a guest chose,
    and both readers of one decode ASCII rather than refusing it: a control
    character is ASCII. The name then reaches a `print()` whose destination is
    the journal, where a bare LF ends the record and the rest of the name
    becomes a SECOND entry, indistinguishable from one this program wrote. A
    guest that can write `evil.com\\nsplice plane=tls … host=github.com` can
    forge the evidence an operator reads a decision from. The same name is also
    carried into the status document that `workloadctl diagnose` renders.

    Refused, not escaped, and refused at the parse — the reason
    `_reject_controls` in the cleartext plane gives for the same character
    class: a field with a line ending inside it has no reading both ends share,
    and rewriting one into something harmless is picking a reading. No name
    that reaches a decision here needs one, so the parse is where it stops
    rather than every log site having to remember.

    Returns the character so the caller can name it in ITS own exception type
    and disposition: an unreadable hello and a malformed query are already
    counted differently, and a shared raise would flatten them.
    """
    for ch in host:
        if ch < " " or ch == "\x7f":
            return ch
    return None


def hostname_match(host: str, patterns) -> bool:
    """Whether a hostname is authorised by a list of fnmatch patterns.

    `fnmatch.fnmatchcase`, not `fnmatch.fnmatch`. The plain form normalises its
    arguments through os.path.normcase, which is a no-op on Linux and lowercases
    on other platforms — so it is case-insensitive only by accident of platform,
    and the operators' patterns were written against fnmatch's case-sensitive
    behaviour. Both sides are normalised here instead, which is the same answer
    everywhere.

    The apex trap is preserved, not fixed: `*.example.com` does not authorise
    `example.com`. That is fnmatch's behaviour, it is what the proxy this
    replaced did with the same list, and three tracked files document it. A rung that
    quietly widened it would silently grant every existing config a destination
    its operator did not write down.
    """
    host = normalise_hostname(host)
    if not host:
        return False
    return any(fnmatch.fnmatchcase(host, normalise_hostname(p))
               for p in patterns)


# --- The responder knob, and [[vm.network.policy]] as parsed entries ---
def uses_resolve(config: dict) -> bool:
    """Whether this workload gets a synthesising responder.

    Everything vm_uses_inspect requires (a VM, not bridged, filtered) plus
    `resolver` not being "none". One knob, one meaning, in both places: a
    responder under `egress = "open"` would answer every name with an inspector
    address that nothing redirects to, and one under `resolver = "none"` would
    be a nameserver for a guest that asked for no nameserver -- and passt is
    told about it in the same breath, so a disagreement here is a guest pointed
    at a port with nothing behind it.
    """
    # VM-only, and not an omission: a container resolves through the
    # host/podman resolver rather than a per-workload nameserver, so there is
    # no container analogue to extend this to.
    if not vm_uses_inspect(config):
        return False
    net = (config.get("vm", {}) or {}).get("network", {}) or {}
    return net.get("resolver", "host") != "none"


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
# which is refused on a terminated host and checked as a preface on an `http2`
# one; permitting it by name would read as a way to allow h2 through `policy`,
# which is exactly the thing `http2` carries a written reason for.
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
    "PRI": "PRI is the HTTP/2 connection preface's method; h2 on a host is "
           "[[vm.network.http2]], which carries a written reason",
}


class VmPolicyEntry(NamedTuple):
    """One [[vm.network.policy]] entry, normalised.

    `methods` and `paths` are `None` where the key was absent, NOT an empty
    tuple, and the difference is the whole of §3's widening trap: absent means
    "any", empty would mean "none". Collapsing the two makes a single-entry
    host with no `paths` deny everything instead of permitting everything --
    the failure in the safe direction, which is why it survives review.
    """

    host: str
    methods: tuple | None
    paths: tuple | None
    credential: str | None = None

    def permits(self, method: str, path: str) -> bool:
        """Whether this entry permits one method on one path.

        `methods` and `paths` inside one entry are a CROSS PRODUCT: two of each
        permit all four combinations. An absent key is "any", per the shorthand
        §3 keeps for the single-entry case.
        """
        if self.methods is not None and method.upper() not in self.methods:
            return False
        if self.paths is not None and not any(
                fnmatch.fnmatchcase(path, pattern) for pattern in self.paths):
            return False
        return True


def vm_policy_entries(net: dict) -> list[VmPolicyEntry]:
    """The [[vm.network.policy]] entries, normalised, in file order.

    Shape-tolerant for the reason internal_hosts is: validate_vm_network
    owns the shape and the boot generator skips a workload that does not
    validate.
    """
    return parse_policy_entries(net, VmPolicyEntry)


def policy_governs(host: str, entries) -> list[VmPolicyEntry]:
    """The entries governing one hostname, which may be none.

    §3's composition rule lives here and is the thing to get right: a host with
    any matching entry is governed by THOSE ENTRIES ALONE, and `hosts` is not
    consulted for it. The careless reading -- a `hosts` entry is a `policy`
    entry with no keys, so union them -- silently destroys the feature: one
    wildcard written for an unrelated reason contributes "any method, any path"
    to every host it happens to cover, and the diff that introduced it looks
    like it ADDED access rather than removing a restriction.

    Host patterns union among themselves, so `*.example.com` and
    `api.example.com` both govern `api.example.com` and neither overrides the
    other. That is the apex trap's sibling, and it is why `diagnose` will have
    to print the EFFECTIVE rules per host rather than the file's entries --
    owed, not built, so do not cite it to an operator as though it were.
    """
    return [e for e in entries if hostname_match(host, (e.host,))]


def policy_permits(host: str, method: str, path: str, entries) -> bool:
    """Whether the governing entries permit one request. Union, not precedence.

    Every entry either permits something or does nothing, so REORDERING THE
    FILE CANNOT CHANGE WHAT IS ALLOWED. Two consequences follow and both look
    like bugs: there is no way to subtract -- a narrower entry cannot carve an
    exception out of a wider one -- and a specific entry does not override a
    general one.

    The caller decides what an empty governing set means; this function is only
    asked about a host some entry governs.
    """
    return any(e.permits(method, path)
               for e in policy_governs(host, entries))


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


INSPECT_STATUS_FILE = "inspect-status.json"


def inspect_status_path(name: str) -> str:
    """Where one workload's inspector writes its counters.

    Two status files rather than one, and lib/egress_status.py carries the
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

    `http2` is the [[vm.network.http2]] host patterns. Like `splice` it
    DECIDES something -- a name it matches is offered h2 on both legs and
    relayed at frame level rather than parsed -- and like `splice` it is
    carried even when tls is "splice", so the document describes the file.

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

    NO ADDRESS is carried with it. The listener derives the broker's address
    from its own uid, which it already has; putting it here would make the
    document non-deterministic w.r.t. the TOML and break the byte comparison
    and the digest. `placeholder` and `env` are not carried either -- they are
    seed-time and broker-config facts, and the listener decides nothing by them.

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
        "http2": http2_hosts(net),
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
    return json.dumps(container_inspect_policy(net), indent=2, sort_keys=True) + "\n"


# How much of the digest an operator is shown. Twelve hex characters is enough
# to tell two documents apart by eye in a diagnostic line and short enough to
# sit inside one; the full value stays in the status file, where the comparison
# is actually made.
INSPECT_DIGEST_SHORT = 12


# The key the listener echoes its loaded document's digest under. Named here
# rather than spelled at both ends: the writer is the listener and the reader
# is `diagnose`, and a typo in either would read as "an older listener that
# does not report a digest", which is the one state the check treats as
# silence.
INSPECT_DIGEST_KEY = "policy_digest"

# Whether this workload has a QEMU guest agent to ask. Named here for the same
# reason as the digest key above -- the writer is container_inspect_policy and
# the reader is the listener, two processes that never see each other's source,
# and a typo in either reads as "absent", which means "there IS an agent". A
# container would then go back to dialling a socket it does not have, silently.
#
# NOT `VM_`-prefixed, unlike its neighbour, and deliberately: this key exists
# to describe a CONTAINER, so the prefix would be false on the one substrate
# that writes it. The prefix is a claim about who a symbol serves, not a
# naming convention to match the line above.
INSPECT_GUEST_AGENT_KEY = "guest_agent"


def inspect_policy_digest(text: str) -> str:
    """The digest of one rendered policy document.

    THE ONE PRODUCER, for the same reason vm_inspect_policy_text is: the
    listener digests the bytes it loaded and `diagnose` digests the bytes on
    disk, and the two are compared for equality. A hashlib call at each end
    would be two definitions of that comparison, and the failure mode of a
    disagreement is not a missed alarm -- it is a PERMANENT one, on every
    inspected workload on the host, which is how a signal stops being read.

    Over the text rather than over the parsed document, because the text is
    what both sides have: the listener holds the string it read, and the
    reader holds the file. Digesting a re-parsed structure would also make the
    value depend on this Python's dict ordering rather than on the file.
    """
    return hashlib.sha256(text.encode()).hexdigest()


def inspect_digest_short(digest: str | None) -> str:
    """A digest as it is shown to a person, or `unknown` for a missing one."""
    return digest[:INSPECT_DIGEST_SHORT] if digest else "unknown"


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


def http2_hosts(net: dict) -> list[str]:
    """The host patterns in [[vm.network.http2]], in file order.

    HLD §8's narrow opt-in: a host here is offered `h2` on both legs and
    relayed at the frame level, so its `:authority` goes unread and true
    fronting stays open on it. Every OTHER terminated host is offered
    `http/1.1` alone, which is what makes `paths`, `methods` and the
    Host-binding work without an HPACK decoder anywhere.

    So this is a bypass with a written reason, beside `allow`, `internal` and
    `splice` -- not a performance flag. What keeps it from meaning EXEMPT is
    the preface and frame check on the listener's side: a connection here must
    actually speak h2. Read that half before widening this one.

    Shape-tolerant for the reason internal_hosts is.
    """
    return _host_reason_hosts(net, "http2")


def _host_reason_hosts(net: dict, key: str) -> list[str]:
    """The `host` of every well-formed [[vm.network.<key>]] entry, in order.

    One body for `internal`, `splice` and `http2`, which are the same table
    with the same two keys -- the mirror of _validate_host_reason_entries on
    the validating side, and shared for the same reason: three copies of this
    is three chances for one of them to start tolerating a shape the other two
    refuse, on a path where the difference is silent.
    """
    entries = net.get(key, [])
    if not isinstance(entries, list):
        return []
    return [e["host"].strip() for e in entries
            if isinstance(e, dict) and isinstance(e.get("host"), str)
            and e["host"].strip()]


# --- the document as the listener holds it ---


class Policy(NamedTuple):
    """One workload's inspection lists, as read at start.

    `hosts` is a tuple, not a list, because nothing may edit it after load: the
    recovery contract is that an edited list applies on a RESTART, and a
    listener that could mutate its own policy would make the restart optional
    and the running policy unknowable from the file.

    `internal` is the [[vm.network.internal]] host names, and it admits
    nothing. The kernel's wl_internal_ok4/6 elements are the one enforcement
    point; this copy exists so a failed dial into private space can be
    attributed to the wildcard trap rather than to a host that is down. See
    vm_inspect_policy.
    """

    tls: str
    hosts: tuple
    internal: tuple = ()
    splice: tuple = ()
    http2: tuple = ()
    policy: tuple = ()
    # The digest of the document text this was parsed from, echoed into the
    # status file so `diagnose` can tell a listener enforcing the file on disk
    # from one enforcing an older one it still holds in memory. Defaulted so
    # every Policy() a test constructs by hand keeps working; the empty string
    # reads downstream as "this listener does not report a digest", which is a
    # state the check is required to pass over in silence anyway.
    digest: str = ""
    # Whether this workload has a QEMU guest agent to ask. DEFAULTS TRUE, and
    # the default is the load-bearing half: a document written before the key
    # existed is a VM's, and reading absence as "no agent" would silently
    # switch off a working clock remedy on every VM until each was re-armed.
    # A container's renderer states the false explicitly. See
    # container_inspect_policy.
    guest_agent: bool = True

    @property
    def summary(self) -> str:
        return (f"tls={self.tls} hosts={len(self.hosts)} "
                f"internal={len(self.internal)} splice={len(self.splice)} "
                f"http2={len(self.http2)} policy={len(self.policy)}")

    def admits(self, host: str) -> bool:
        """Whether this name is on a list at all -- the CONNECTION question.

        Asked at the front of a TLS connection, where there is no request yet
        and the only thing known is the name in the ClientHello. A `policy`
        entry allowlists its own host (§3: a name in `policy` need not also
        appear in `hosts`), so a workload whose entire allowlist is written as
        policy entries has to be admitted here -- otherwise the connection dies
        before the request the rules were written about ever exists, and the
        operator sees `not allowlisted` for a host their file plainly names.
        """
        return (hostname_match(host, self.hosts)
                or bool(policy_governs(host, self.policy)))

    def permits(self, host: str, method: str, path: str) -> bool:
        """Whether one request is authorised -- §3's composition rule.

        A host ANY policy entry matches is governed by those entries alone and
        `hosts` is not consulted for it; a host no entry matches is allowed by
        `hosts` with no method or path constraint. The rule is not "union the
        two lists", and the difference is the whole feature: under the union
        reading one wildcard in `hosts` written for an unrelated reason
        contributes "any method, any path" to every host it covers, silently
        removing the restriction somebody wrote a policy entry for.
        """
        governing = policy_governs(host, self.policy)
        if governing:
            return any(e.permits(method, path) for e in governing)
        return hostname_match(host, self.hosts)

    def governs(self, host: str) -> bool:
        """Whether ANY policy entry names this host.

        Not "whether the request was permitted" -- this is asked where there is
        no request to permit, about a connection that turned out not to carry
        HTTP at all. It answers the operator's question instead: are there
        `methods` and `paths` here that never got to run?
        """
        return bool(policy_governs(host, self.policy))

    def splices(self, host: str) -> bool:
        """Whether this host is exempt from termination.

        True on the whole-workload mode as well as the per-host list, so that
        every caller asks one question. Splitting it -- `tls == "splice"` in one
        place and a list check in another -- is how a path gets one of the two
        and reads correct: the connection is spliced by the mode and terminated
        by the list, or the reverse, depending on which branch it took.
        """
        return self.tls == "splice" or hostname_match(host, self.splice)

    def speaks_h2(self, host: str) -> bool:
        """Whether this host is offered h2 and relayed at the frame level.

        Asked only of a host that is being TERMINATED, and it does not ask
        about the mode: under `tls = "splice"` no ALPN of ours is offered on
        any connection, so a listener that consulted this there would be
        answering a question nothing had asked. Validation accepts `http2`
        entries under that mode for the same reason it accepts `splice` ones --
        they ask for something already true -- so this list is populated and
        inert, and the one caller reaches it only past a `splices()` check.
        """
        return hostname_match(host, self.http2)

    def credential_for(self, host: str):
        """The credstore NAME this host's requests are brokered with, or None.

        Asked once per authorised request, and it decides only WHERE the
        request is sent -- to this workload's broker instance instead of to the
        origin. Nothing about the credential itself is known here and nothing
        needs to be: ADR 007 decision 9 keys the broker's table by `(uid,
        Host)`, so the name travels on no wire and exists in this process for
        one purpose, which is naming the credential in the record and the
        figures.

        THE FIRST governing entry that carries one, not a merge. `validate`
        already refuses two entries that match the same host and disagree about
        `credential`, so on a document written by the generator there is at most
        one answer -- but this reads a FILE, which an operator can edit, and a
        reader that raised or picked arbitrarily on a hand-edited document would
        turn an editing mistake into a dead workload. First-match is
        deterministic and matches the order the file states.
        """
        for entry in policy_governs(host, self.policy):
            if entry.credential:
                return entry.credential
        return None


def load_policy(path):
    """Read the policy document, or raise.

    Deliberately without a default: a missing or unreadable document must fail
    the start. The tempting fallback — an empty policy — is the worst of the
    options, because an empty `hosts` list is a valid configuration (a workload
    reachable only through `allow`), so the listener could not tell "the
    operator allowed nothing" from "the file was not there" and would enforce
    the strictest reading of a policy it never read.
    """
    with open(path) as f:
        text = f.read()
    # Digested from the TEXT THIS PARSED, never from a re-read of the path.
    # The whole value of the figure is that it says what this process is
    # enforcing; a second open() would report the file as it is now, so a
    # rewrite landing between the two would give a listener that advertises the
    # new document's digest while enforcing the old one -- green on the one
    # case the comparison exists for.
    digest = inspect_policy_digest(text)
    doc = json.loads(text)
    if not isinstance(doc, dict):
        raise ValueError(f"{path}: expected a JSON object, got {type(doc).__name__}")
    hosts = doc.get("hosts") or []
    if not isinstance(hosts, list):
        raise ValueError(f"{path}: 'hosts' is not a list")
    internal = doc.get("internal") or []
    if not isinstance(internal, list):
        raise ValueError(f"{path}: 'internal' is not a list")
    # Tolerated absent, unlike `hosts`: a policy document written before this
    # key existed is a policy with no internal entries, which is the common
    # case and not an error. `hosts` gets no such tolerance because there the
    # empty reading and the missing reading are different configurations.
    splice = doc.get("splice") or []
    if not isinstance(splice, list):
        raise ValueError(f"{path}: 'splice' is not a list")
    # NOT normalised here, unlike `internal`: these are fnmatch PATTERNS and
    # hostname_match normalises both sides at the point of comparison.
    # Normalising a pattern early is harmless today and would silently stop
    # being so the moment a pattern could carry something a hostname cannot.
    http2 = doc.get("http2") or []
    if not isinstance(http2, list):
        raise ValueError(f"{path}: 'http2' is not a list")
    # Unnormalised, like `splice` and for the same reason: these are fnmatch
    # PATTERNS, and hostname_match normalises both sides where they are
    # compared.
    entries = doc.get("policy") or []
    if not isinstance(entries, list):
        raise ValueError(f"{path}: 'policy' is not a list")
    policy = []
    for item in entries:
        if not isinstance(item, dict) or not isinstance(item.get("host"), str):
            raise ValueError(f"{path}: a 'policy' entry is not a table with a "
                             f"host: {item!r}")
        # None and [] are DIFFERENT and the document distinguishes them, so
        # this must too: absent means any, empty would mean none. A `or ()`
        # here would turn every unconstrained entry into one permitting
        # nothing, which fails closed and therefore quietly -- the workload
        # reaches nothing and every unit test still passes.
        #
        # Uppercased and string-filtered HERE as well as in
        # vm_policy_entries, which is the convention this file already holds
        # for `internal` and the responder holds for its static map: the
        # writer normalises, and the reader normalises again so that a
        # hand-edited document cannot introduce a rule that never matches.
        # `methods` is the one that needs it -- VmPolicyEntry.permits compares
        # `method.upper()` against these, so a document carrying `["get"]`
        # would deny every GET on that host while the file reads as
        # permitting it. Fails closed, and therefore in silence.
        methods = item.get("methods")
        paths = item.get("paths")
        # `.get`, not `[...]`: the document emits the key only on the entries
        # that carry one (vm_inspect_policy explains why the sparseness is
        # load-bearing there), so absent and null mean the same thing here and
        # the reader is the side that pays for it. A non-string is dropped to
        # None rather than refused -- the value's only use is as a name, and a
        # document that named a number would otherwise fail the listener's
        # START, which is a worse outcome than one brokered host reaching the
        # origin unbrokered and saying so in the record.
        credential = item.get("credential")
        if not isinstance(credential, str) or not credential.strip():
            credential = None
        else:
            credential = credential.strip()
        policy.append(VmPolicyEntry(
            host=item["host"],
            methods=None if methods is None else tuple(
                m.upper() for m in methods if isinstance(m, str)),
            paths=None if paths is None else tuple(
                p for p in paths if isinstance(p, str)),
            credential=credential))
    # `is not False` rather than `.get(..., True)`: the only value that turns
    # the remedy off is a literal false written by the container renderer, so
    # a document carrying a malformed value keeps the VM behaviour instead of
    # disabling a remedy on the strength of a typo.
    guest_agent = doc.get(INSPECT_GUEST_AGENT_KEY) is not False
    return Policy(tls=doc.get("tls") or TLS_DEFAULT, hosts=tuple(hosts),
                  internal=tuple(normalise_hostname(h) for h in internal),
                  splice=tuple(splice), http2=tuple(http2),
                  policy=tuple(policy), digest=digest,
                  guest_agent=guest_agent)
