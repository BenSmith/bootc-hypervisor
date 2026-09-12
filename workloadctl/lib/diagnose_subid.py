"""
diagnose_subid — is a workload's subordinate id range the one it should have?

Pure verdicts over what the battery read out of /etc/subuid and /etc/subgid;
the range arithmetic they compare against lives in lib/workload_uid.py.
subid_derived_check is the load-bearing one and subid_overlap_check its
corroboration — each docstring says why.
"""


def subid_derived_check(
    entries: list[tuple[str, tuple[int, int] | None]],
    expected: tuple[int, int],
    uid: int,
) -> tuple[bool, str, str | None]:
    """Verdict: does each subid file's main range equal the derived one?

    `entries` is [(file, (start, count) | None), …]; a None (no entry at all) is
    subid_configured's business, not this one.

    Why this can't self-heal: `configure_subuid_subgid` grandfathers any
    existing entry — deliberately, because shifting a UID mapping under a
    running container corrupts its namespace. Correct behaviour, but it makes
    drift permanent *and* invisible: every later enable leaves the old range
    alone and reports success. Nothing else in the tree compares the two, which
    is why three of six workload users on a lab host sat on pre-derivation
    ranges for months.

    This is the load-bearing half of the pair, for a reason worth stating
    because it is not the one originally filed. `useradd` refuses to allocate
    over an entry it can see in /etc/subuid (measured — see
    subid_overlap_check), but `append_subid_entries` has no such courtesy: it
    writes the derived range without consulting anything. Collision safety
    therefore comes entirely from the derivation putting workload ranges above
    the territory `useradd` allocates in. A range off the formula is a range
    that has left the only guarantee there is.

    It also predicts (per claim_uid) a re-created workload adopting the old UID
    and grandfathering the wrong range straight back in.
    """
    off = [(f, e) for f, e in entries if e is not None and e != expected]
    if not off:
        return (True,
                f"Subid ranges match the derived range "
                f"({expected[0]}:{expected[1]})", None)
    detail = ", ".join(f"{f} has {s}:{c}" for f, (s, c) in off)
    return (False,
            f"Subid range is not the derived range for UID {uid}: expected "
            f"{expected[0]}:{expected[1]}, {detail}",
            "Remapping is manual and must be done with the workload stopped: "
            "rewrite the entry in /etc/subuid and /etc/subgid, then chown "
            "state/ from the old range to the new one. Scope the chown to "
            "state/ — every file in data/ is owned by the workload UID itself, "
            "so only the reconstructible graphroot needs remapping")


def subid_overlap_check(
    entries: list[tuple[str, tuple[int, int] | None]],
    window: tuple[int, int],
) -> tuple[bool, str, str | None]:
    """Verdict: does any main range sit inside `useradd`'s allocation window?

    **`useradd` is not the naive allocator this was originally filed against.**
    Measured on Fedora 44: park `_wl-caddy:589824:65536` in /etc/subuid where
    the next allocation would land, and successive `useradd`s take 524288 and
    then *655360* — they skip the parked range rather than overlapping it. Fill
    the window so the only candidate would straddle an existing entry and
    `useradd` refuses outright ("Can't get unique subordinate UID range"). So a
    range inside the window is not, on its own, the two-namespaces-in-one
    hazard this check was first justified by; that framing was wrong and this
    docstring is the correction.

    What it still catches is an **ordering** hazard, because the protection is
    one-directional. `useradd` defends itself against entries it can see in
    /etc/subuid. Nothing defends *us*: `append_subid_entries` writes the derived
    range without consulting existing entries, so a workload provisioned after
    a colliding human range would write straight over it. Living above the
    window is what makes that unreachable — which is why subid_derived is the
    load-bearing one and this check is its corroboration, not the reverse.

    And `useradd` can only skip what it can see. /etc is per-deployment on a
    bootc host while /etc/subuid entries accrue at runtime, so a rollback can
    boot a deployment whose /etc/subuid never listed a workload enabled later,
    while /var still holds files owned out of that range. A `useradd` there
    allocates it legitimately. Same /etc-vs-/var asymmetry as claim_uid.

    Scope is ranges starting strictly below SUB_UID_MAX. A range starting *at*
    SUB_UID_MAX — which on stock Fedora is also SUBID_BASE, since the two
    windows abut — cannot be taken while the entry is listed, per the refusal
    measured above, so it is not reported.
    """
    sub_uid_min, sub_uid_max = window
    inside = [(f, e) for f, e in entries if e is not None and e[0] < sub_uid_max]
    if not inside:
        return (True,
                f"Subid ranges are clear of useradd's window "
                f"({sub_uid_min}-{sub_uid_max})", None)
    detail = ", ".join(f"{f} at {s}:{c}" for f, (s, c) in inside)
    return (False,
            f"Subid range sits inside the window useradd allocates from "
            f"({sub_uid_min}-{sub_uid_max}): {detail} — useradd skips ranges "
            f"it can see in /etc/subuid, but nothing protects this range if it "
            f"is provisioned after a colliding one, or if a rollback boots an "
            f"/etc/subuid that never listed it",
            "Remap onto the derived range (see subid_derived's fix). Not "
            "urgent on its own — check `/etc/subuid` for a human user's range "
            "that already overlaps this one, which is the case that has "
            "already gone wrong rather than one that might")
