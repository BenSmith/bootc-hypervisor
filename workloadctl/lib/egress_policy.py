#!/usr/bin/env python3
"""What a filtered workload is allowed to reach, and the words its inspector
answers in.

One subsystem, one file: the TLS mode, the hostname-matching rule, the parsed
`[[network.policy]]` entries, the JSON document the listener reads, and the
vocabulary of the per-request record it writes. Every name here is spelled at
least twice -- once by the code that renders or arms, once by the code that
reads back -- and several a third time by `libexec/workload-vm-inspect-listener`,
which is extension-less and so cannot be imported from lib/ at all. That third
spelling is the reason a constant here is a constant rather than a literal:
a drift between the two files turns a real refusal into a figure that reads
zero, which is indistinguishable from a refusal that never fired.

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

from config_parser import (INSPECT_ORIG_CLEARTEXT, INSPECT_ORIG_TLS,
                           normalise_hostname, parse_policy_entries)
from vm_defs import VM_EGRESS_DEFAULT, VM_SOCKET_DIR, vm_allowed_hosts


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
    it). `workload-vm-inspect`'s
    inspection_applies delegates here rather than re-stating it, so the
    generator and the helper cannot drift apart.

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
    return net.get("egress", VM_EGRESS_DEFAULT) == "filtered"


# --- Hostname vocabulary: one normalisation, one refusal, one comparison ---
#
# Both substrates and three entrypoints ask the same questions of a name, and a
# second answer to "what is this name" is a name the guest can spell twice.

# config_parser.normalise_hostname, under the name the listener, egress_mint and
# the tests already import. It lives one rung down rather than being copied when
# the container half needed it too, for that reason: the guest would pick which
# normalisation it got by how it spelled the host.
normalise_hostname = normalise_hostname


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


# --- The ports: the two the listener answers on, the two it is dialled at ---
# The two listener ports, selected by the redirected connection's ORIGINAL port
# via the DNAT map rather than recovered by the inspector: a guest dial to 80
# lands here cleartext (the Host header carries the name) and one to 443 here
# under TLS (the SNI in the ClientHello). The socket that accepted the
# connection tells the inspector which it is, so SO_ORIGINAL_DST is not needed.
INSPECT_PORT_CLEARTEXT = 8080
INSPECT_PORT_TLS = 8443


# The two ORIGINAL ports the redirect matches and the map keys on: a guest dial
# to 80 or one to 443. Fixed by the redirect rules in workload-proxy.nft; they
# never appear in an element value, which is why the constants live beside the
# listener ports they select.
#
# Defined in config_parser, because the container half of the design redirects
# the same two ports and the parse layer is below both; aliased here so that a
# reader of this file finds the redirect's two ends -- the port dialled and the
# port answered -- next to each other rather than one rung apart.
INSPECT_ORIG_CLEARTEXT = INSPECT_ORIG_CLEARTEXT
INSPECT_ORIG_TLS = INSPECT_ORIG_TLS


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
    return f"{VM_SOCKET_DIR}/{name}/{INSPECT_POLICY_FILE}"


INSPECT_STATUS_FILE = "inspect-status.json"


# The `drop_reasons` keys `workloadctl diagnose` reads back out of the
# inspector's status document.
#
# SECOND DEFINITIONS OF STRINGS THE LISTENER OWNS, and stated here for the
# reason broker_listen_address's twin is: `libexec/workload-vm-inspect-listener` is an
# extension-less entrypoint, so nothing in lib/ can import it. A reader either
# restates the key or matches on a substring -- and a substring is worse, since
# `not HTTP` is a prefix of `not HTTP (policy entry)` and `host does not match
# the server name` is a prefix of its allowlisted twin. Both splits exist
# BECAUSE the two halves need different operator responses, so a reader that
# merges them by prefix reports the opposite of what the split was for.
#
# tests/test_vm_inspect_diagnose.py pins each of these against the listener's
# own constant. That pin is what makes restating them safe: a rename over there
# fails a test here, rather than turning a figure into a permanent zero that
# reads exactly like a refusal that never fired.
VM_DROP_MISDIRECTED = "host does not match the server name"
VM_DROP_MISDIRECTED_LISTED = "host does not match the server name (allowlisted)"
VM_DROP_NOT_HTTP = "not HTTP"
VM_DROP_NOT_HTTP_POLICY = "not HTTP (policy entry)"


# The two field names that tie one of the inspector's journal lines to the
# per-request record written beside it. Second definitions for the same reason
# the four keys above are, and pinned the same way by
# tests/test_vm_inspect_record.py, which asserts each against the listener's
# own LOG_ID_FIELD/LOG_REQ_FIELD.
#
# `id` is per CONNECTION and `req` is the ordinal within it, so a reader
# selecting on `id` alone gets every decision taken on one connection in order.
# Neither can be replaced by `peer=`, which the listener also logs: a source
# port repeats across the requests on one keep-alive connection and is reused
# by the kernel after close, so it groups the wrong lines together and splits
# the right ones apart.
INSPECT_LOG_ID_FIELD = "id"
INSPECT_LOG_REQ_FIELD = "req"


# The per-request record's field names, and the vocabularies of two of them.
# MORE SECOND DEFINITIONS OF LISTENER STRINGS, for the reason the VM_DROP_*
# keys above are: the record is written by an extension-less entrypoint nothing
# in lib/ can import, and the reader that renders it lives here. Restating them
# is safe only because tests/test_vm_inspect_record.py pins each against the
# listener's own constant -- without that pin a renamed field turns a column
# into a permanent blank, which reads exactly like a guest that did nothing.
#
# `credential` is the NAME of the credstore material the request was brokered
# with, or null on a request that was not brokered -- never the material, and
# never an address. It is here because `upstream` is honestly the broker's
# address on a brokered request: `upstream` is documented as the address
# actually dialled, and recording the origin there instead would put a second,
# false definition of "what this request touched" into the one document that
# exists to be evidence. What makes the honest value readable is
# this field naming which credential rode along, so `host` says where the
# request went and `credential` says why `upstream` is a loopback address.
INSPECT_RECORD_FIELDS = (
    INSPECT_LOG_ID_FIELD, INSPECT_LOG_REQ_FIELD, "ts", "plane", "mode",
    "host", "method", "path", "query", "http", "decision", "reason", "status",
    "upstream", "credential", "duration_ms",
)


# `forward` and `drop`, the journal's own verbs, and deliberately no third
# value for "refused with an answer": whether the guest was told is carried
# exactly by `status` being non-null, and a second spelling of one fact is free
# to disagree with it.
INSPECT_RECORD_DECISIONS = ("forward", "drop")


# What the listener was doing with the connection, which is not the question
# `plane` answers. `splice` and `h2` are the two connection-level records --
# the paths that carry requests this design never decodes.
INSPECT_RECORD_MODES = ("forward", "terminate", "splice", "h2")


# The two planes a record can have arrived on, which is the port the guest
# dialled and not what the listener then did with the connection.
INSPECT_RECORD_PLANES = ("tls", "cleartext")


# Every value the record's `reason` field can carry -- the listener's own
# DROP_REASONS, restated whole rather than the four VM_DROP_* keys `diagnose`
# happened to need.
#
# THE WHOLE SET, because `workloadctl egress --reason` validates against it.
# A closed set is the point: a reason value that matches nothing renders
# identically to a guest that never hit that refusal, so `--reason
# "not allowed"` for `not allowlisted` would print an empty report and an
# operator would conclude the denial never happened. Validated, it is an
# argparse error naming the valid values instead.
#
# This matters more since the guest-facing refusal body was made generic: the
# guest is told nothing about WHY, so `reason` here is the only place a
# not-allowlisted denial is distinguishable from a not-permitted one.
#
# tests/test_cmd_egress.py pins this against the listener's DROP_REASONS in both
# directions -- a reason the listener writes and this omits is a filter that
# cannot select a real refusal, and one this carries that the listener never
# writes is a filter that always returns nothing.
VM_DROP_NOT_ALLOWLISTED = "not allowlisted"
VM_DROP_NO_NAME = "no readable name"
VM_DROP_UNREADABLE_REQUEST = "unreadable request"
VM_DROP_UNREACHABLE = "upstream unreachable"
VM_DROP_INTERNAL = "internal destination"
VM_DROP_CEILING = "connection ceiling reached"
# Connection-level like the ceiling, and refused before any byte is read: the
# caller's uid is not this workload's. The listener identifies callers through
# lib/peer_identity.py; `workload_filter` is the primary control and this is
# the layer behind it.
VM_DROP_FOREIGN_CALLER = "caller is not this workload"
VM_DROP_RELAY_FAILED = "relay failed"
VM_DROP_TIMED_OUT = "timed out"
VM_DROP_UNVERIFIED = "upstream certificate unverified"
VM_DROP_CLIENT_CERT = "upstream wants a client certificate"
VM_DROP_THROTTLED = "mint rationed"
VM_DROP_MINT_FAILED = "could not mint a leaf"
VM_DROP_NOT_H2 = "not HTTP/2"
VM_DROP_NOT_PERMITTED = "not permitted by policy"
# NOT VM_DROP_UNREACHABLE. "the provider is down" and "this workload's
# credential broker is down" need different operator responses -- the first is
# somebody else's outage, the second is a unit on this host that failed to
# start, or an SELinux rule missing from security/workload-inspect.cil, which
# is the failure that module's own "THE UPSTREAM DIAL" block records as "a
# policy gap wearing a network error's clothes". Merged into the generic
# reason, such an AVC is indistinguishable from a provider outage, and
# `workloadctl egress --reason` -- which validates against this closed set --
# would have no filter that selects it.
VM_DROP_BROKER_UNREACHABLE = "credential broker unreachable"


INSPECT_RECORD_REASONS = (
    VM_DROP_NOT_ALLOWLISTED,
    VM_DROP_NO_NAME,
    VM_DROP_UNREADABLE_REQUEST,
    VM_DROP_UNREACHABLE,
    VM_DROP_INTERNAL,
    VM_DROP_CEILING,
    VM_DROP_FOREIGN_CALLER,
    VM_DROP_RELAY_FAILED,
    VM_DROP_TIMED_OUT,
    VM_DROP_UNVERIFIED,
    VM_DROP_CLIENT_CERT,
    VM_DROP_MISDIRECTED,
    VM_DROP_MISDIRECTED_LISTED,
    VM_DROP_THROTTLED,
    VM_DROP_MINT_FAILED,
    VM_DROP_NOT_HTTP,
    VM_DROP_NOT_HTTP_POLICY,
    VM_DROP_NOT_H2,
    VM_DROP_NOT_PERMITTED,
    VM_DROP_BROKER_UNREACHABLE,
)


def inspect_status_path(name: str) -> str:
    """Where one workload's inspector writes its counters.

    Two status files rather than one, and lib/egress_status.py carries the
    argument: the responder is a separate socket-activated process, and two
    processes atomically replacing one path leaves only the last writer's
    figures, silently.
    """
    return f"{VM_SOCKET_DIR}/{name}/{INSPECT_STATUS_FILE}"


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

    THE ONE RENDERER. `write_policy()` in libexec/workload-vm-inspect writes
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
# that writes it. tests/vm_prefixed_symbols.txt is the record of how many
# shared names already carry that prefix wrongly; this is not becoming one of
# them for the sake of matching the line above it.
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
    except. See workload-vm-inspect's internal_failure for what that failure
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
