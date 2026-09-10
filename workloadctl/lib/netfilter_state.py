#!/usr/bin/env python3
"""Reading netfilter's state back: nft's JSON output, and conntrack pressure.

Split out of vm.py, where it was neither VM-specific nor about anything the
rest of that file does. Nothing here builds a rule or an element; it parses
what the kernel says when asked. `workloadctl diagnose` and the metrics
exporter are the callers, on both substrates.

Two neighbours rather than one topic, and deliberately one module: nftables
element JSON and the conntrack sysctls are read for the same reason, by the
same callers, at the same moment -- "why did that transfer die part-way" is
answered by one or the other -- and neither is large enough that separating
them would tell a reader something the docstrings do not.

Nothing here imports vm; vm imports this and re-exports every public name, so
no caller changed.

Installed to /usr/libexec/workloadctl/netfilter_state.py.
"""

def owned_elements(uid: int, elems) -> list[str]:
    """Element expressions in one set's `nft -j` output that belong to `uid`.

    Two shapes, because `wl_filtered` holds a bare uid while the allow sets
    hold concatenations:

        wl_filtered -> [10001, 10002]
        wl_allow4   -> [{"concat": [10001, "192.168.0.10", 22]}]

    Matching on the first component is what makes a purge possible at all:
    nft has no "delete every element whose first field is N", so the caller
    must enumerate, filter here, and delete by exact value.
    """
    owned: list[str] = []
    for elem in elems or []:
        if isinstance(elem, dict) and "concat" in elem:
            parts = elem["concat"]
            if parts and parts[0] == uid:
                owned.append(" . ".join(str(p) for p in parts))
        elif elem == uid:
            owned.append(str(uid))
    return owned


def nft_set_elements(payload) -> list:
    """The `elem` list from one `nft -j list set|map ...` document.

    Both keys are accepted because a map renders under "map", not "set" —
    querying a map and matching only on "set" silently returns no elements, and
    a caller reading that as "nothing is armed" reports a working redirect as
    broken.
    """
    for item in (payload or {}).get("nftables", []):
        for kind in ("set", "map"):
            if kind in item:
                return item[kind].get("elem", []) or []
    return []


def nft_drop_counter(payload) -> tuple[int, int] | None:
    """(packets, bytes) on the set-guarded drop rule, or None if absent.

    NOTE this counter is **host-wide across every filtered VM**, not
    per-workload: there is one drop rule and it is guarded on set membership,
    so every filtered workload's dropped packets land on the same counter.
    Callers must not present it as belonging to one workload.
    """
    for item in (payload or {}).get("nftables", []):
        rule = item.get("rule") if isinstance(item, dict) else None
        if not rule:
            continue
        exprs = rule.get("expr", [])
        if not any("drop" in e for e in exprs if isinstance(e, dict)):
            continue
        for expr in exprs:
            if isinstance(expr, dict) and "counter" in expr:
                counter = expr["counter"]
                return (counter.get("packets", 0), counter.get("bytes", 0))
    return None


def nft_element_counter(payload, uid: int) -> tuple[int, int] | None:
    """(packets, bytes) on the element of a counted set belonging to `uid`.

    Unlike `nft_drop_counter`, which reads a rule and is therefore host-wide
    across every filtered workload, this reads one *element* and so is
    attributable to the workload that owns it -- which is the entire reason
    the wrong-port sets carry `counter` as a set flag.

    A counted set renders its elements differently from an uncounted one, and
    that difference is the trap here. Without the flag an element is
    `{"concat": [...]}`; with it, it is wrapped:

        {"elem": {"val": {"concat": [10000, "198.18.1.0"]},
                  "counter": {"packets": 12, "bytes": 720}}}

    So `owned_elements`, which matches the unwrapped shape, finds nothing in
    these sets and would report a workload with 12 dropped self-dials as having
    none. Verified against nft 1.1.6 rather than assumed.

    None means the element is absent -- the workload's inspector has never been
    armed -- which is a different statement from a counter reading zero, and
    the caller must not collapse the two: zero is "armed and never hit", the
    healthy reading, while None on a workload that claims inspection is a
    missing guard.
    """
    for elem in nft_set_elements(payload):
        if not isinstance(elem, dict):
            continue
        inner = elem.get("elem")
        if not isinstance(inner, dict):
            continue
        val = inner.get("val")
        parts = val.get("concat") if isinstance(val, dict) else None
        if not parts or parts[0] != uid:
            continue
        counter = inner.get("counter")
        if not isinstance(counter, dict):
            return None
        return (counter.get("packets", 0), counter.get("bytes", 0))
    return None


CONNTRACK_COUNT_PATH = "/proc/sys/net/netfilter/nf_conntrack_count"
CONNTRACK_MAX_PATH = "/proc/sys/net/netfilter/nf_conntrack_max"

# At and above this fraction the table is close enough to full to be the
# explanation for transfers dying part-way. Not a hard threshold in the kernel
# -- there is none; entries are refused once the table is full and there is no
# warning before that -- so this is the point at which the number stops being
# background and starts being an answer.
CONNTRACK_PRESSURE = 0.9


def conntrack_occupancy(count_path=CONNTRACK_COUNT_PATH,
                        max_path=CONNTRACK_MAX_PATH) -> tuple[int, int] | None:
    """(count, max) from the kernel's conntrack table, or None if unreadable.

    Host-wide, and not the inspector's to report -- it is here because the
    egress guard's correctness DEPENDS on conntrack state. A reply is only
    distinguishable from a fresh connection because an entry exists, so an
    exhausted table reclassifies the inspector's replies as `direction
    original` and drops them mid-connection.

    What makes it worth reading at all is that nothing else moves when it
    happens: the accept counters are unchanged, the guard counter climbs for a
    reason that looks like the cross-workload case it was written for, and
    inside the guest it presents as transfers dying part-way. Nothing in the
    chain rescues it either -- the guards sit ahead of the shipped `oif lo
    accept`, so a reclassified reply is dropped several rules before the one
    rule that would have taken it on interface alone.

    None rather than an exception on every failure: the module is not loaded
    until something uses conntrack, and a missing figure must never turn a
    diagnose line into a traceback.
    """
    try:
        with open(count_path) as f:
            count = int(f.read().strip())
        with open(max_path) as f:
            maximum = int(f.read().strip())
    except (OSError, ValueError):
        return None
    if maximum <= 0:
        return None
    return (count, maximum)
