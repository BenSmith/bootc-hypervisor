"""
vm_inspect_figures — the inspector's counters, derived once, rendered by two.

Rung 5 T8/T9, and decision 9 is the whole of its shape: T8 and T9 RENDER, they
do not compute. `doctor` prints these figures for a person and the exporter
publishes them for Prometheus, and both read them from here, so there is
exactly one definition of what `connections_total` means. The erosion risk
decision 9 names is T9's: a Prometheus label makes a second definition
convenient — `drops_total{reason=...}` is one series, and summing it in the
exporter while `doctor` sums it separately is two answers to one question that
agree only until someone edits one of them.

THE TABLE IS THE MECHANISM, not documentation of it. A figure is one FIGURES
row carrying its source path, its metric name, its type, its help text and its
human label together, and both renderers walk the same table — so a figure
added for the exporter appears in `doctor` in the same commit, and one added
for `doctor` gets a metric name chosen deliberately rather than never. Four
hand-written blocks in two files is how the second definition gets in.

WHAT IS AND IS NOT HERE. This module reads the two runtime status documents
(`inspect-status.json`, `resolve-status.json`) and nothing else. It renders no
verdict, and `doctor` adds none: every figure here is a COUNT OF EVENTS, and
the fault-shaped conditions in the inspector already have verdicts in
`vm_inspect_check`, which `doctor` already aggregates through
`collect_diagnose_checks`. A second, weaker pass/fail over the same document
would be precisely the second definition decision 9 forbids — and a `doctor`
that reported UNHEALTHY because a guest was denied 147 times would be teaching
an operator that the filter working is a fault, which is how a report stops
being read. If a figure deserves a verdict it belongs in `vm_inspect_check`,
beside the digest and CA comparisons.

ABSENT GROUPS ARE OMITTED, NOT ZEROED. A workload under `tls = "splice"` has no
minter, so its status document has no `mint` block: reporting `mint_mints 0`
for it would assert a minter exists and is idle, which is a different and false
statement. Same for the resolver's figures on a workload with no synthesising
resolver. Within a group that IS present, a missing key reads 0 -- the listener
pre-zeroes both `dispositions` and `drop_reasons` for the reason this module
inherits ([[counter-with-no-writer-reads-zero]] is the opposite hazard, and the
answer to both is that presence and value are separate questions).
"""

import json
from dataclasses import dataclass
from typing import Callable

from vm import (
    VM_INSPECT_DIGEST_KEY,
    vm_inspect_status_path,
    vm_resolve_status_path,
)

# Group keys. A group is present or absent as a whole, because what makes it
# absent is one missing block in the document rather than one missing counter.
CONNECTIONS = "connections"
CERTIFICATES = "certificates"
NAMES = "names"
EVIDENCE = "evidence"

GROUP_LABELS = {
    CONNECTIONS: "Connections",
    CERTIFICATES: "Certificates minted for the guest",
    NAMES: "Names answered for the guest",
    EVIDENCE: "Evidence integrity",
}


@dataclass(frozen=True)
class Figure:
    """One figure, and every fact both renderers need about it.

    `path` walks the status document; `derive` computes from the whole document
    instead, for the two totals that are sums rather than stored counters. One
    or the other, never both -- a figure with a stored counter AND a derivation
    is two definitions in a single row, which is the shape this table exists to
    make impossible.

    AN EMPTY `metric` MEANS PROMETHEUS DOES NOT GET IT, and both figures marked
    that way are sums. `connections_total` is the four dispositions added up and
    `drops_total` is the reason breakdown added up -- and Prometheus computes a
    sum from its parts far better than an exporter can, `sum by (workload)` over
    series it already has. Publishing the total as its own series would put a
    second definition of it on the wire, free to disagree with the parts the
    moment a disposition is added to one and not the other. A person reading
    `doctor` cannot run a query, so the same sum is computed once, here, for
    them.
    """

    key: str
    group: str
    metric: str          # "" for a figure Prometheus must NOT be given
    kind: str            # "counter" or "gauge", as Prometheus means them
    label: str           # for a person
    help: str            # for Prometheus
    path: tuple = ()
    derive: Callable | None = None


def _sum_ints(mapping) -> int:
    if not isinstance(mapping, dict):
        return 0
    return sum(v for v in mapping.values() if isinstance(v, int))


FIGURES = (
    # --- connections ---------------------------------------------------
    Figure("connections_total", CONNECTIONS,
           "", "counter",
           "connections seen",
           "Connections the egress inspector has handled",
           derive=lambda doc: _sum_ints(doc.get("dispositions"))),
    Figure("spliced", CONNECTIONS, "workload_vm_inspect_spliced_total",
           "counter", "spliced (passed through by name, not parsed)",
           "Connections passed through on SNI without being terminated",
           path=("dispositions", "spliced")),
    Figure("terminated", CONNECTIONS, "workload_vm_inspect_terminated_total",
           "counter", "terminated and parsed",
           "Connections terminated so their requests could be inspected",
           path=("dispositions", "terminated")),
    Figure("forwarded", CONNECTIONS, "workload_vm_inspect_forwarded_total",
           "counter", "forwarded in cleartext",
           "Cleartext connections forwarded to the upstream",
           path=("dispositions", "forwarded")),
    Figure("dropped", CONNECTIONS, "workload_vm_inspect_dropped_total",
           "counter", "dropped",
           "Connections the inspector refused, for any reason",
           path=("dispositions", "dropped")),
    Figure("drops_total", CONNECTIONS, "", "counter",
           "drop events across all reasons",
           "Drop events summed over every reason. Not equal to the dropped "
           "connection count: one connection can raise several",
           derive=lambda doc: _sum_ints(doc.get("drop_reasons"))),
    Figure("open", CONNECTIONS, "workload_vm_inspect_open", "gauge",
           "open right now",
           "Connections live in the inspector at the last status write",
           path=("concurrency", "open")),
    Figure("ceiling_refused", CONNECTIONS,
           "workload_vm_inspect_ceiling_refused_total", "counter",
           "turned away at the connection ceiling",
           "Connections refused because the per-process ceiling was full",
           path=("concurrency", "refused")),
    Figure("internal_refusals", CONNECTIONS,
           "workload_vm_inspect_internal_refusals_total", "counter",
           "refused for naming an internal destination",
           "Connections refused for resolving to an internal address",
           path=("internal_refusals_total",)),
    # --- credentials (rung 6; zero on a workload that brokers nothing) ---
    #
    # IN `connections` RATHER THAN A GROUP OF THEIR OWN, deliberately. A group
    # is present or absent as a whole and its absence asserts something -- no
    # minter, no synthesising resolver. These figures reading 0 asserts nothing
    # false: a workload with no [[vm.network.credential]] block genuinely
    # brokered nothing, and the listener writes the keys either way. Adding a
    # group and gating it would make "this workload has no credentials" and
    # "this workload's inspector has never run" look the same, which is the
    # confusion _GROUP_GATE exists to create only where it is true.
    #
    # THE PER-HOST AND PER-CREDENTIAL BREAKDOWNS ARE NOT HERE, and that is the
    # same choice `internal_refusals` made one row up: the table carries
    # scalars, the status document carries the maps, and `doctor` renders the
    # maps from the document. A Figure per host is not expressible and a
    # Prometheus label per credential name would put the name in a series an
    # exporter publishes -- bounded, but published far more widely than the
    # 0600 status file, for a breakdown an operator reads while holding the
    # workload's own TOML.
    Figure("credentialed", CONNECTIONS,
           "workload_vm_inspect_credentialed_total", "counter",
           "requests sent through the credential broker",
           "Requests forwarded to this workload's credential broker rather "
           "than to the origin",
           path=("credentialed",)),
    Figure("credential_unauthorized", CONNECTIONS,
           "workload_vm_inspect_credential_unauthorized_total", "counter",
           "brokered requests the origin answered 401/403",
           "Brokered requests the origin refused for want of authorisation. "
           "NON-ZERO MEANS EVERY LAYER HERE SUCCEEDED AND THE PROVIDER SAID NO "
           "— the usual cause is a placeholder whose shape the provider does "
           "not accept, or material it has retired",
           path=("credential_unauthorized",)),

    # --- certificates (present only where the listener terminates) ------
    Figure("mints", CERTIFICATES, "workload_vm_inspect_mints_total", "counter",
           "leaves minted",
           "Leaf certificates signed by this workload's egress CA",
           path=("mint", "mints")),
    Figure("hits", CERTIFICATES, "workload_vm_inspect_mint_hits_total",
           "counter", "served from cache",
           "Leaf lookups served from a cache instead of signing",
           path=("mint", "hits")),
    Figure("denied_mints", CERTIFICATES,
           "workload_vm_inspect_denied_mints_total", "counter",
           "of those mints, for hosts that were then denied",
           "Subset of mints for a host the policy went on to deny. A SUBSET, "
           "not a disjoint class",
           path=("mint", "denied_mints")),
    Figure("denied_hits", CERTIFICATES,
           "workload_vm_inspect_denied_mint_hits_total", "counter",
           "of those hits, for hosts that were then denied",
           "Subset of cache hits for a host the policy went on to deny",
           path=("mint", "denied_hits")),
    Figure("throttled", CERTIFICATES,
           "workload_vm_inspect_mint_throttled_total", "counter",
           "mints refused by the rate limit",
           "Mints refused because the token bucket was empty. The only figure "
           "that says why a guest under sustained abuse stopped getting "
           "readable refusals",
           path=("mint", "throttled")),
    Figure("mint_failed", CERTIFICATES,
           "workload_vm_inspect_mint_failed_total", "counter",
           "mints that failed",
           "Mint attempts that raised rather than returning a leaf",
           path=("mint", "failed")),
    Figure("working_set", CERTIFICATES, "workload_vm_inspect_working_set",
           "gauge", "leaves in the working set",
           "Live size of the allowed-host leaf cache",
           path=("mint", "working_set")),
    Figure("denial_leaves", CERTIFICATES, "workload_vm_inspect_denial_leaves",
           "gauge", "leaves in the denial cache",
           "Live size of the denied-host leaf cache, which cannot evict the "
           "working set",
           path=("mint", "denials")),
    Figure("clock_resyncs", CERTIFICATES,
           "workload_vm_inspect_clock_resyncs_total", "counter",
           "guest clock resyncs driven from a mint",
           "Times a mint miss found the guest clock skewed and resynced it",
           path=("mint", "clock_resyncs")),
    Figure("clock_unavailable", CERTIFICATES,
           "workload_vm_inspect_clock_unavailable_total", "counter",
           "clock checks with no guest agent to ask",
           "Mint-time clock checks that found no guest agent. Non-zero means "
           "the mint-time clock remedy is INERT in this guest",
           path=("mint", "clock_unavailable")),
    Figure("clock_failed", CERTIFICATES,
           "workload_vm_inspect_clock_failed_total", "counter",
           "clock checks that errored",
           "Mint-time clock checks that reached the agent and failed",
           path=("mint", "clock_failed")),

    # --- names (the synthesising resolver beside the inspector) ---------
    Figure("synthesised", NAMES, "workload_vm_resolve_synthesised_total",
           "counter", "answered with a synthetic address",
           "Queries answered with the inspector's address",
           path=("queries", "synthesised")),
    Figure("static", NAMES, "workload_vm_resolve_static_total", "counter",
           "answered from a static entry",
           "Queries answered from a [[vm.network.allow]] entry",
           path=("queries", "static")),
    Figure("nodata", NAMES, "workload_vm_resolve_nodata_total", "counter",
           "answered NODATA",
           "Queries for a listed name with nothing to return",
           path=("queries", "nodata")),
    Figure("malformed", NAMES, "workload_vm_resolve_malformed_total", "counter",
           "malformed queries refused",
           "Queries the resolver could not parse",
           path=("queries", "malformed")),
    Figure("unlisted", NAMES, "workload_vm_resolve_unlisted_total", "counter",
           "for names on no list",
           "Queries for a name this workload's lists do not carry",
           path=("unlisted",)),

    # --- evidence integrity --------------------------------------------
    Figure("record_failures", EVIDENCE,
           "workload_vm_inspect_record_failures_total", "counter",
           "records the sink could not take",
           "Per-request records that could not be written. NON-ZERO MEANS THE "
           "RECORD IS INCOMPLETE — read it before concluding a guest made no "
           "requests",
           path=("record_failures",)),
    Figure("h2_unrecorded", EVIDENCE,
           "workload_vm_inspect_h2_unrecorded_total", "counter",
           "HTTP/2 sessions whose requests were not decoded",
           "Spliced h2 sessions recorded as one connection with no per-request "
           "detail",
           path=("h2_unrecorded",)),
    Figure("bumped", EVIDENCE, "workload_vm_inspect_bumped_total", "counter",
           "connections bumped",
           "Connections whose TLS was terminated and re-originated",
           path=("bumped",)),
    Figure("ech_seen", EVIDENCE, "workload_vm_inspect_ech_seen_total",
           "counter", "ClientHellos offering ECH",
           "ClientHellos carrying an encrypted-client-hello extension",
           path=("ech", "seen")),
    Figure("ech_alarm", EVIDENCE, "workload_vm_inspect_ech_alarm_total",
           "counter", "ECH alarms raised",
           "ECH offers that reached the alarm condition — the name was not "
           "readable from the handshake",
           path=("ech", "alarm")),
)

FIGURES_BY_KEY = {f.key: f for f in FIGURES}

# The document key that decides a group is present at all. CONNECTIONS and
# EVIDENCE ride the status document itself, so they are present whenever it is.
_GROUP_GATE = {CERTIFICATES: "mint"}


def _read(path: str):
    """One status document, or None. Never distinguishes why.

    The same silence `cmd_diagnose._inspect_status` chose and for the same
    reason: the inspector is socket-activated, so a guest that has dialled
    nothing has never written this file, and a VM that has not started has no
    runtime directory. Neither is a fault, and a report that manufactured one
    out of a missing diagnostic would fire on every healthy workload between
    boot and the guest's first connection.
    """
    try:
        with open(path) as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def read_inspect_status(name: str):
    return _read(vm_inspect_status_path(name))


def read_resolve_status(name: str):
    return _read(vm_resolve_status_path(name))


def _dig(doc, path: tuple) -> int:
    cur = doc
    for step in path:
        if not isinstance(cur, dict):
            return 0
        cur = cur.get(step)
    return cur if isinstance(cur, int) and not isinstance(cur, bool) else 0


def present_groups(status, resolve=None) -> set:
    """Which figure groups this pair of documents can honestly report."""
    groups = set()
    if isinstance(status, dict):
        groups.update({CONNECTIONS, EVIDENCE})
        for group, gate in _GROUP_GATE.items():
            if isinstance(status.get(gate), dict):
                groups.add(group)
    if isinstance(resolve, dict):
        groups.add(NAMES)
    return groups


def figures(status, resolve=None) -> dict:
    """Every figure the given documents support, as {key: int}.

    Keys for absent groups are OMITTED rather than zeroed -- see the module
    docstring. A caller iterating this dict therefore never has to know which
    groups exist; it renders what it is given.
    """
    groups = present_groups(status, resolve)
    out = {}
    for fig in FIGURES:
        if fig.group not in groups:
            continue
        doc = resolve if fig.group == NAMES else status
        out[fig.key] = (fig.derive(doc) if fig.derive
                        else _dig(doc, fig.path))
    return out


def drop_reasons(status) -> dict:
    """The drop counters by reason, as the document carries them.

    Passed through rather than summed here: the sum is `drops_total`, which is
    one FIGURES row with one definition, and a caller that wants the breakdown
    wants the reasons -- not a second opportunity to add them up differently.
    """
    reasons = (status or {}).get("drop_reasons")
    if not isinstance(reasons, dict):
        return {}
    return {k: v for k, v in reasons.items()
            if isinstance(v, int) and not isinstance(v, bool)}


def policy_digest(status) -> str:
    value = (status or {}).get(VM_INSPECT_DIGEST_KEY)
    return value if isinstance(value, str) else ""


def figure_lines(figs: dict, reasons: dict | None = None) -> list:
    """The figures as indented lines for a person, grouped, in table order.

    Groups with nothing to show are still printed with their zeros. A zero here
    is a reading, not noise: "the guest dialled nothing" and "the inspector is
    not seeing the guest's traffic" are the two things an operator is choosing
    between, and an absent line makes them look alike. Absent GROUPS are the
    ones that stay silent, and they are absent because the feature is off.
    """
    lines = []
    for group in (CONNECTIONS, CERTIFICATES, NAMES, EVIDENCE):
        rows = [f for f in FIGURES if f.group == group and f.key in figs]
        if not rows:
            continue
        lines.append(f"  {GROUP_LABELS[group]}")
        width = max(len(str(figs[f.key])) for f in rows)
        for fig in rows:
            lines.append(f"    {str(figs[fig.key]).rjust(width)}  {fig.label}")
        if group == CONNECTIONS and reasons:
            lines.extend(_reason_lines(reasons))
    return lines


def _reason_lines(reasons: dict) -> list:
    """The non-zero drop reasons, busiest first, and a count of the silent ones.

    THE SILENT COUNT IS PRINTED, because the listener pre-zeroes every reason it
    knows: without it, a document from an older listener that carries six
    reasons and a current one that carries eighteen render identically when all
    are zero, and "this reason was never measured" reads as "this reason never
    fired".
    """
    hot = sorted(((n, r) for r, n in reasons.items() if n),
                 key=lambda pair: (-pair[0], pair[1]))
    if not hot:
        return [f"      ({len(reasons)} drop reason"
                f"{'' if len(reasons) == 1 else 's'} measured, all zero)"]
    width = max(len(str(n)) for n, _ in hot)
    lines = [f"      {str(n).rjust(width)}  {reason}" for n, reason in hot]
    quiet = len(reasons) - len(hot)
    if quiet:
        lines.append(f"      ({quiet} other reason"
                     f"{'' if quiet == 1 else 's'} measured, all zero)")
    return lines
