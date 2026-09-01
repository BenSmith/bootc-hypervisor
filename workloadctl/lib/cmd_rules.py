"""
cmd_rules — what the inspector's policy document actually says about a host.

Rung 5 T6. `vm_policy_governs()`'s docstring has owed this report since rung 3,
in those words: because host patterns union among themselves, `*.example.com`
and `api.example.com` both govern `api.example.com` and neither overrides the
other, so the file's entries are not the effective rules and reading the file is
not the same as knowing what applies.

IT CALLS THE SHIPPED MATCHER; IT DOES NOT REIMPLEMENT ONE. `vm_policy_governs`
and `vm_hostname_match` are already pure and already free of runtime state, so
this runs on a host where the inspector is not running, and — more to the point
— a report with its own copy of the composition rule could disagree with the
listener while both looked right. §3's rule is that a host any policy entry
matches is governed by THOSE ENTRIES ALONE, with `hosts` not consulted for it;
the careless union reading silently destroys the feature, and a report that
merged the two lists would print exactly that error on the screen an operator
opens in order to check it has not happened.

TWO FORMS, NOT ONE, because there is no host set to iterate. `hosts`, `splice`,
`http2` and `policy[].host` are all fnmatch patterns, so "the effective rules
per host" has nothing to loop over:

  * the QUERY form (`rules <workload> <host>`) names a host and gets what
    applies. It is the form that answers "why was this denied", it works for a
    name the file does not mention at all, and it is a direct call to the
    matcher.
  * the ENUMERATION form (`rules <workload>`) walks every non-wildcard name
    appearing anywhere in the document and gives each one the query form's
    verdict. The literals are a finite set, and this is the form that catches
    the trap above: both patterns are listed against the one name.

Pattern subsumption — which patterns overlap which — is deliberately NOT built.
It is the only form that would be real logic rather than a call, and the two
above answer the operator's question without it. The enumeration says out loud
how many wildcards it did not expand, so an empty literal set reads as "this
document is all wildcards" rather than as "there are no rules".

WHAT IT REPORTS IS THE DOCUMENT, NOT THE PROCESS. The listener's loaded document
is T4's business (`policy_digest` in the status file, compared by `diagnose`);
the difference between the document on disk and a re-render of the TOML is T3's
(`workloadctl drift`). This reads the file, says which file it read, and points
at those two rather than guessing at either.
"""

import argparse
import json
import os
from pathlib import Path

import cli_log
from cmd_validate import load_config_or_exit
from vm import (
    VM_TLS_DEFAULT,
    VM_TLS_MODES,
    VmPolicyEntry,
    vm_hostname_match,
    vm_inspect_policy,
    vm_inspect_policy_path,
    vm_policy_governs,
    vm_uses_inspect,
)

# The fnmatch metacharacters. A name carrying any of them names no host, so it
# cannot be enumerated -- it can only be shown as a contributor to the literals
# it covers. `[` is in the set because fnmatch honours character classes even
# though no schema example uses one; leaving it out would enumerate `a[bc].x`
# as though it were a literal and then report it as matching nothing.
_WILDCARD_CHARS = "*?["

# The keys of the policy document whose values are host patterns, and the label
# each gets in the report. Driven by a table rather than by four hand-written
# blocks so that a key added to vm_inspect_policy() and not to this one shows up
# as an absent column rather than as a silently narrower report.
_PATTERN_KEYS = (
    ("hosts", "hosts"),
    ("internal", "internal"),
    ("splice", "splice"),
    ("http2", "http2"),
)


def _is_wildcard(pattern: str) -> bool:
    return any(c in pattern for c in _WILDCARD_CHARS)


def _entries(doc: dict) -> list:
    """The document's `policy` array as the matcher's own type.

    `methods` and `paths` come back as null where the key was absent, and null
    is carried through as None rather than as an empty tuple: absent means ANY,
    empty would mean NONE, and collapsing the two makes a single-entry host deny
    everything instead of permitting everything. VmPolicyEntry's docstring calls
    that the whole of §3's widening trap, and it fails in the safe direction,
    which is exactly why a reader that got it wrong would survive review.
    """
    out = []
    for raw in doc.get("policy") or []:
        if not isinstance(raw, dict) or not str(raw.get("host", "")).strip():
            continue
        methods = raw.get("methods")
        paths = raw.get("paths")
        out.append(VmPolicyEntry(
            host=str(raw.get("host", "")),
            methods=None if methods is None else tuple(methods),
            paths=None if paths is None else tuple(paths),
        ))
    return out


def unreadable_entries(doc: dict) -> int:
    """How many `policy` elements this reader could not turn into an entry.

    Never zero silently. An element with no `host`, or one that is not a table
    at all, is skipped by `_entries` -- and a skipped entry makes the report
    NARROWER than the file, which is the dangerous direction: a host whose only
    governing entry was dropped reads as "no entry governs this host — the
    allowlist alone applies: any method, any path", i.e. as permitting strictly
    more than the file does.

    It cannot happen through the shipped renderer, and that is exactly why it is
    counted rather than assumed away: this reader parses with `json.load` and
    performs none of the listener's validation (decision 5), so the one state it
    can be handed that the listener would refuse is a document some other writer
    produced -- and being quietly wrong about that document is worse than
    refusing to read it.
    """
    raw = doc.get("policy") or []
    if not isinstance(raw, list):
        return 0
    return len(raw) - len(_entries(doc))


def load_document(name: str, config) -> tuple:
    """(document, origin, path) for one workload, preferring what is on disk.

    Two origins, and the report names which one it got, because they answer
    different questions and an operator who cannot tell them apart is exactly
    the reader this whole rung exists for:

      * "disk" -- /run/workload-vm/<name>/inspect.json, written by
        `workload-vm-inspect up` at the last listener start. This is what the
        listener was GIVEN. It is the truthful answer for a running workload,
        and it is the one that can differ from the TOML.
      * "config" -- rendered here from `[vm.network]` via the one renderer,
        for a workload that has not started this boot. A stopped VM has no
        document, and that is its ordinary state, not a fault -- `drift` makes
        the same distinction and for the same reason.

    Neither is "what the listener is enforcing right now". A listener started
    before an edit holds the previous document in memory with both files
    agreeing; that door is T4's digest, and `diagnose` is where it is checked.
    """
    path = Path(vm_inspect_policy_path(name))
    try:
        text = path.read_text()
    except FileNotFoundError:
        net = (config.config.get("vm") or {}).get("network") or {}
        return vm_inspect_policy(net), "config", None
    except PermissionError:
        # The remedy, not just the errno. The document is 0640 root:_wl-<name>
        # by write_policy(), so an operator who is neither is refused -- and a
        # bare "Permission denied" sends them to look at the file rather than at
        # their own uid. `egress` says the same thing about the record for the
        # same reason. Not a fall-back to the TOML render: that would silently
        # answer a different question than the one asked.
        raise RuntimeError(
            f"cannot read {path} as uid {os.geteuid()} — the policy document is "
            f"readable by root and the workload user only. Re-run as root."
        ) from None
    except OSError as exc:
        raise RuntimeError(f"could not read {path}: {exc}") from None
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        # Loud, not skipped, and not silently re-rendered from the TOML either.
        # A document the listener could not parse is a document the listener did
        # not load, and answering the operator's question from the TOML instead
        # would describe rules that are provably not in force.
        raise RuntimeError(f"{path} is not valid JSON: {exc}") from None
    if not isinstance(doc, dict):
        raise RuntimeError(f"{path} is not a policy document")
    return doc, "disk", str(path)


def explain(doc: dict, host: str) -> dict:
    """Everything the document says about one hostname.

    `admitted` mirrors the listener's `Policy.admits()` and not just the
    allowlist: a `policy` entry allowlists its own host (§3 -- a name in
    `policy` need not also appear in `hosts`), so a workload whose entire
    allowlist is written as policy entries is admitted. A report that checked
    `hosts` alone would print `not allowlisted` for a host the operator's file
    plainly names.
    """
    matched = {key: [p for p in (doc.get(key) or [])
                     if vm_hostname_match(host, (p,))]
               for key, _label in _PATTERN_KEYS}
    governing = vm_policy_governs(host, _entries(doc))
    return {
        "host": host,
        "matched": matched,
        "governing": governing,
        "admitted": bool(matched["hosts"] or governing),
        "tls": doc.get("tls", VM_TLS_DEFAULT),
    }


def tls_treatment(view: dict) -> str:
    """One sentence for what happens to this host's TLS, from `explain`'s view.

    Mirrors the listener's own parenthesisation, which is load-bearing:
    `if inspect and not (allowed and splices(host))`. THE ALLOWLIST DECISION
    COMES FIRST, so a name on the splice list and on no allowlist is refused
    rather than spliced -- and a `splice` pattern can cover names `hosts` does
    not, which validation cannot catch because the pattern does match the
    allowlisted ones. That case gets its own sentence here because it is the
    one an operator misreads as "I spliced it, why is it being terminated".
    """
    spliced_by = view["matched"]["splice"]
    # ADMISSION IS ANSWERED FIRST, in both TLS modes, because the listener
    # answers it first in both. Under `tls = "inspect"` an unadmitted host takes
    # the terminating branch and is refused there; under `tls = "splice"` it
    # reaches `if not allowed` and is dropped. Reporting either as "terminated
    # and parsed" or as "spliced" describes a treatment the connection never
    # gets, which is the same class of error as the union reading: a sentence
    # about a code path that does not run.
    if not view["admitted"]:
        if spliced_by:
            return (f"refused — {', '.join(spliced_by)} would splice it, but no "
                    "`hosts` pattern and no policy entry admits it, and the "
                    "allowlist decision comes first")
        return "refused — the connection never reaches a TLS treatment"
    if view["tls"] not in VM_TLS_MODES:
        # A mode this report does not know is not "terminated and parsed". The
        # fall-through below is written for `inspect`, and VM_TLS_UNBUILT exists
        # precisely because a third mode is expected -- so the default arm would
        # start describing it, wrongly and confidently, the day it lands.
        return (f"unknown — [vm.network].tls = {view['tls']!r} is not a mode "
                f"this report knows ({', '.join(VM_TLS_MODES)}); what the "
                f"listener does with it is not described here")
    if view["tls"] == "splice":
        return ('spliced — [vm.network].tls = "splice" splices every admitted '
                "connection, and the per-host splice list changes nothing")
    if spliced_by:
        return f"spliced, by: {', '.join(spliced_by)}"
    return "terminated and parsed"


def literal_names(doc: dict) -> list:
    """Every non-wildcard name in the document, sorted, deduplicated."""
    names = set()
    for key, _label in _PATTERN_KEYS:
        names.update(p for p in (doc.get(key) or []) if not _is_wildcard(p))
    names.update(e.host for e in _entries(doc) if not _is_wildcard(e.host))
    return sorted(n for n in names if n)


def wildcard_patterns(doc: dict) -> list:
    """(pattern, label) for every wildcard, so the enumeration can say what it
    left out. A document that is all wildcards enumerates nothing, and printing
    an empty report for it would read as "no rules" — which is the opposite of
    what an all-wildcard document means."""
    out = []
    for key, label in _PATTERN_KEYS:
        out.extend((p, label) for p in (doc.get(key) or []) if _is_wildcard(p))
    out.extend((e.host, "policy") for e in _entries(doc) if _is_wildcard(e.host))
    return sorted(set(out))


def _field(values) -> str:
    """One entry field, rendering the absent/empty distinction as words.

    None is "any" and an empty list is "(none)", and they must not render alike:
    absent means any, empty would mean none, and a report that printed both as a
    blank would hide the widening trap VmPolicyEntry's docstring is built
    around. An empty list cannot come from the schema today -- it is refused --
    which is precisely why the renderer must not assume it away.
    """
    if values is None:
        return "any"
    return ", ".join(values) or "(none)"


def _entry_lines(entries) -> list:
    """The governing entries as an aligned table.

    Aligned, and the alignment is not decoration: the reason the entries are
    printed together at all is that they are compared against each other --
    neither overrides the other, so the operator has to read the union off the
    page. Ragged columns turn that comparison into three unrelated sentences.
    """
    width = max((len(e.host) for e in entries), default=0)
    return [f"{e.host.ljust(width)}   methods: {_field(e.methods)}   "
            f"paths: {_field(e.paths)}" for e in entries]


def _source_line(origin: str, path, name: str) -> str:
    if origin == "disk":
        return (f"document   {path}\n"
                f"           written at the last listener start; "
                f"`workloadctl drift` compares it against the TOML")
    return (f"document   none on disk — {name} has not started this boot.\n"
            f"           Rendered here from [vm.network]; this is what a start "
            f"would write.")


def _unreadable_line(doc: dict) -> list:
    """A warning line, or nothing. Printed by BOTH forms, because a narrowed
    report is wrong in the same direction whichever way it is being read."""
    count = unreadable_entries(doc)
    if not count:
        return []
    return [f"  WARNING    {count} `policy` element"
            f"{'' if count == 1 else 's'} in this document could not be read "
            f"(no `host`,\n             or not a table). The rules below are "
            f"NARROWER than the file."]


def render_query(view: dict, doc: dict, origin: str, path, name: str) -> list:
    """The query form, as lines."""
    lines = [view["host"], "  " + _source_line(origin, path, name).replace(
        "\n", "\n  ")] + _unreadable_line(doc)
    matched = view["matched"]
    if matched["hosts"]:
        lines.append(f"  allowlist  matched by: {', '.join(matched['hosts'])}")
    elif view["governing"]:
        lines.append("  allowlist  no `hosts` pattern matches — admitted by its "
                     "policy entries alone (§3)")
    else:
        lines.append("  allowlist  no `hosts` pattern and no policy entry "
                     "matches — every connection\n             to this host is "
                     "refused. (`internal`, `splice` and `http2`\n             "
                     "admit nothing on their own.)")
    lines.append(f"  tls        {tls_treatment(view)}")
    if matched["http2"]:
        lines.append(f"  http2      matched by: {', '.join(matched['http2'])} — "
                     "this host must select h2, or the connection is refused")
    if matched["internal"]:
        lines.append(f"  internal   matched by: {', '.join(matched['internal'])} "
                     "— excepts the inspector's upstream leg from the internal "
                     "drop. It authorises nothing.")
    if view["governing"]:
        lines.append(f"  policy     {len(view['governing'])} entr"
                     f"{'y' if len(view['governing']) == 1 else 'ies'} govern"
                     f"{'s' if len(view['governing']) == 1 else ''} this host, "
                     f"and the allowlist is NOT consulted for it:")
        for line in _entry_lines(view["governing"]):
            lines.append(f"               {line}")
        lines.append("             A request is permitted if ANY of them permits "
                     "it. Entries do not")
        lines.append("             override one another, so reordering the file "
                     "cannot change what is allowed.")
    elif view["admitted"]:
        lines.append("  policy     no entry governs this host — the allowlist "
                     "alone applies: any method, any path")
    else:
        lines.append("  policy     —")
    return lines


def render_enumeration(doc: dict, origin: str, path, name: str) -> list:
    """The literal enumeration, as lines."""
    literals = literal_names(doc)
    wildcards = wildcard_patterns(doc)
    lines = ([f"{name} — {len(literals)} literal name"
              f"{'' if len(literals) == 1 else 's'} in the policy document",
              "  " + _source_line(origin, path, name).replace("\n", "\n  ")]
             + _unreadable_line(doc) + [""])
    for host in literals:
        view = explain(doc, host)
        governing = view["governing"]
        lines.append(f"  {host}")
        if not view["admitted"]:
            # No tls clause for an unadmitted host: `tls_treatment` would say
            # "refused" a second time, and a verdict that states its own reason
            # twice reads as two findings rather than one.
            lines.append("      REFUSED — neither `hosts` nor `policy` names it")
            continue
        if governing:
            verdict = (f"{len(governing)} policy entr"
                       f"{'y' if len(governing) == 1 else 'ies'}")
        else:
            verdict = "allowlisted, any method and path"
        lines.append(f"      {verdict}; tls: {tls_treatment(view)}")
    if not literals:
        lines.append("  (none — every pattern in this document is a wildcard)")
    if wildcards:
        lines.append("")
        lines.append(f"  {len(wildcards)} wildcard pattern"
                     f"{'' if len(wildcards) == 1 else 's'} cannot be enumerated "
                     f"— a wildcard names no host:")
        for pattern, label in wildcards:
            lines.append(f"      {pattern}   ({label})")
        lines.append("  Query a name directly to see which of them cover it.")
    return lines


def _json_view(view: dict) -> dict:
    """`explain`'s view as JSON, with the matcher's tuples spelled out."""
    return {
        "host": view["host"],
        "admitted": view["admitted"],
        "tls": view["tls"],
        "tls_treatment": tls_treatment(view),
        "matched": view["matched"],
        "governing": [{"host": e.host,
                       "methods": None if e.methods is None else list(e.methods),
                       "paths": None if e.paths is None else list(e.paths)}
                      for e in view["governing"]],
    }


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """`rules`'s arguments. HOST is optional, and which form runs turns on it."""
    parser.add_argument("workload", help="Workload name")
    parser.add_argument("host", nargs="?", metavar="HOST",
                        help="A hostname to ask about. Omit to enumerate every "
                             "non-wildcard name in the document")
    parser.add_argument("--json", action="store_true",
                        help="Print the report as a JSON object")


def cmd_rules(args, manager):
    """Report the effective egress rules for one workload."""
    json_mode = bool(getattr(args, "json", False))
    workload = str(args.workload)
    config = load_config_or_exit(workload, json_mode=json_mode)

    if not vm_uses_inspect(config.config):
        cli_log.error(
            f"{workload} has no inspected egress, so there is no policy "
            "document. Egress filtering is [vm.network].egress = \"filtered\" "
            "on a VM workload without a bridge.")
        return 1

    try:
        doc, origin, path = load_document(workload, config)
    except RuntimeError as exc:
        cli_log.error(str(exc))
        return 1

    host = getattr(args, "host", None)
    if json_mode:
        payload = {"workload": workload, "origin": origin, "path": path,
                   "unreadable_policy_elements": unreadable_entries(doc)}
        if host:
            payload["query"] = _json_view(explain(doc, host))
        else:
            payload["literals"] = [_json_view(explain(doc, n))
                                   for n in literal_names(doc)]
            payload["wildcards"] = [{"pattern": p, "key": k}
                                    for p, k in wildcard_patterns(doc)]
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    if host:
        lines = render_query(explain(doc, host), doc, origin, path, workload)
    else:
        lines = render_enumeration(doc, origin, path, workload)
    print("\n".join(lines))
    return 0
