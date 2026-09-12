"""
The workload uid: its allocation, and the subordinate range derived from it.

One flock, SUBID_LOCK, guards both. Every participant that allocates a uid or
rewrites /etc/subuid and /etc/subgid -- the boot generator, workload-ensure-user,
enable, disable/purge, cleanup -- goes through this module, so the lock is
always the same path and the `username:start:count` format has one parser.
"""
import contextlib
import fcntl
import pwd
from pathlib import Path

from workload_addr import UID_MAX, UID_MIN
from workload_lib import (
    RUN_SYSTEMD_SYSTEM, replace_file_atomically,
    workload_data_dir, workload_state_dir,
)

# Where enable stages a workload's sysusers .conf to apply immediately (the
# generator writes its copy into RUN_SYSTEMD_SYSTEM). Both are scanned by
# _reserved_uids_in_pending_sysusers to spot pinned-but-uncreated UIDs.
RUN_SYSUSERS_D = Path("/run/sysusers.d")

# Subordinate-id range derivation. The base places every workload range above
# the window Fedora's own `useradd` allocates subids from (SUB_UID_MAX=600100000
# in /etc/login.defs). A lower base overlaps that window at low UIDs, which
# would let a useradd-created *human* user share subordinate ids with a workload
# container — each inside the other's user namespace. Documented in
# docs/workloads.md.
SUBID_BASE = 600100000
SUBID_COUNT = 65536


# Flock guarding the subuid/subgid UID-allocation critical section (#4). Must be
# the identical path across every participant (workload-ensure-user,
# workload-generate, cmd_enable, cmd_disable/purge, cmd_cleanup) or the flock
# stops mutexing. Prefer the remove_/append_subid_entries() helpers below, which
# take the lock themselves, over hand-rolling a read-modify-write here.
SUBID_LOCK = Path("/run/lock/workload-subid.lock")

# Reentrancy state for subid_lock(): the enable path holds the lock across
# allocation *through* the sysusers write, and get_next_uid() (called inside
# that span) now takes the lock too. Nesting on a single cached fd makes the
# inner acquire a no-op instead of a same-process deadlock (a second fd's
# flock() would block against the outer hold). Single-threaded by design —
# both callers (the boot generator, the CLI) run one allocation at a time.
_subid_lock_fd = None
_subid_lock_depth = 0


@contextlib.contextmanager
def subid_lock():
    """Hold SUBID_LOCK for the UID/subid allocation critical section.

    Reentrant within a process (see _subid_lock_depth): only the outermost
    acquire flocks, only the outermost release unlocks. Cross-process this is a
    plain exclusive flock, so a boot-time generate and a concurrent
    `workloadctl enable` can't hand out the same UID.

    Best-effort *only* for a permission failure: if the caller can't open the
    root-owned lock (an unprivileged caller — /run/lock is root-owned) the body
    runs unlocked rather than blocking. Any other OSError (a transient flock
    EINTR, ENOSPC, EIO …) propagates so allocation fails loudly instead of
    silently running without the mutex — the isolation stakes are too high to
    swallow those. Both real callers run as root where the open+flock succeed,
    so the guarantee holds where allocation actually happens; the permission
    escape hatch only keeps the exit-0 boot generator (whose per-workload loop
    already logs-and-continues) from being the thing that trips.
    """
    global _subid_lock_fd, _subid_lock_depth
    if _subid_lock_depth == 0:
        try:
            SUBID_LOCK.parent.mkdir(parents=True, exist_ok=True)
            _subid_lock_fd = open(SUBID_LOCK, "w")
            fcntl.flock(_subid_lock_fd.fileno(), fcntl.LOCK_EX)
        except OSError as e:
            # Drop any half-open fd first (the finally below never runs — we
            # raise before _subid_lock_depth is incremented — so clean up here).
            if _subid_lock_fd is not None:
                _subid_lock_fd.close()
            _subid_lock_fd = None
            # Permission failure → unprivileged caller can't take the root-owned
            # lock; degrade to unlocked. Anything else is a real fault.
            if not isinstance(e, PermissionError):
                raise
    _subid_lock_depth += 1
    try:
        yield
    finally:
        _subid_lock_depth -= 1
        if _subid_lock_depth == 0 and _subid_lock_fd is not None:
            fcntl.flock(_subid_lock_fd.fileno(), fcntl.LOCK_UN)
            _subid_lock_fd.close()
            _subid_lock_fd = None


# The two files the subid lock exists to protect. Named here for the same reason
# every other path this module owns is: so no caller has to spell them, and so
# the read/parse/mutate helpers below are the only implementations of the
# `username:start:count` format.
SUBUID_FILE = Path("/etc/subuid")
SUBGID_FILE = Path("/etc/subgid")


def derived_subid_range(uid: int) -> tuple[int, int]:
    """The (start, count) subordinate range a workload UID must map to.

    The single implementation of the derivation: `workload-ensure-user` writes
    it, `doctor`/`diagnose` assert against it. Deriving rather than recording it
    is deliberate (see claim_uid) — recovering a UID recovers the range, so a
    second copy in a file could only ever go stale.

    Raises ValueError for a UID outside the workload range, or one whose range
    would not fit in uint32.
    """
    if uid < UID_MIN:
        raise ValueError(f"UID {uid} is below minimum workload UID {UID_MIN}")
    start = SUBID_BASE + (uid - UID_MIN) * SUBID_COUNT
    if start + SUBID_COUNT - 1 > 4294967295:
        raise ValueError(
            f"Subuid range for UID {uid} would overflow uint32 "
            f"({start}+{SUBID_COUNT}-1 > 4294967295). "
            f"UID must be in range {UID_MIN}-{UID_MAX}."
        )
    return start, SUBID_COUNT


def login_defs_subid_window(
    path: Path | str = "/etc/login.defs",
) -> tuple[int, int] | None:
    """(SUB_UID_MIN, SUB_UID_MAX) from login.defs — where `useradd` allocates.

    Returns None if the file is unreadable or either key is absent, so a caller
    can tell "no overlap" apart from "could not check". No default is invented:
    the whole point of reading it is that the host's value is what a future
    `useradd` will honour, and a guess would assert against a window that may
    not be the one in force.
    """
    values: dict[str, int] = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) == 2 and parts[0] in ("SUB_UID_MIN", "SUB_UID_MAX"):
                    try:
                        values[parts[0]] = int(parts[1])
                    except ValueError:
                        return None
    except (FileNotFoundError, PermissionError, OSError):
        return None
    if "SUB_UID_MIN" not in values or "SUB_UID_MAX" not in values:
        return None
    return values["SUB_UID_MIN"], values["SUB_UID_MAX"]


def subuid_file() -> Path:
    """Call-time reader for SUBUID_FILE. Same rationale as
    workload_config_dir(): `from workload_uid import SUBUID_FILE` binds a copy,
    so a single patch.object(workload_uid, "SUBUID_FILE", tmp) would not reach
    it. Callers go through this and are redirected together."""
    return SUBUID_FILE


def subgid_file() -> Path:
    """Call-time reader for SUBGID_FILE. See subuid_file()."""
    return SUBGID_FILE


def subid_files() -> tuple[Path, Path]:
    """Both subid files, resolved at call time."""
    return (subuid_file(), subgid_file())


def read_subid_entry(username: str, path: Path | str) -> tuple[int, int] | None:
    """Return (start, count) for username's main range in path, else None.

    Selected by *shape*, not position. A user can hold several entries — the
    main range, plus one `username:<gid>:1` per extra_groups GID — and
    `configure_subuid_subgid` gives no ordering guarantee between them across
    hosts provisioned by older builds. Taking the first matching line was
    therefore a coin flip, and losing it reported a supplementary single-GID
    entry as the main range: measured on a lab host, a workload whose derived
    range was present and correct failed both subid diagnose checks, and was
    handed a remediation (rewrite the entry, chown state/) that would have
    broken the mapping it was wrongly accused of having.

    `count == 1` is what marks a supplementary entry; the main range is
    SUBID_COUNT wide. Skipping count-1 entries rather than matching SUBID_COUNT
    exactly is deliberate: a *drifted* main range is the entire point of the
    caller, and a pre-derivation range can carry the wrong count as well as the
    wrong start, so it must still come back for subid_derived_check to fail on.

    With nothing but supplementary entries the first of them is returned rather
    than None. The main range really is missing in that case, and returning it
    lets subid_derived_check say so — None would drop the check silently, and
    the presence check upstream would still call the user configured.

    A malformed line for this user returns None instead of being skipped: the
    callers are read-only reporters, and stepping over corruption to nominate
    some later line as the main range is worse than declining to answer.
    """
    supplementary: tuple[int, int] | None = None
    try:
        with open(path) as f:
            for line in f:
                if not line.startswith(f"{username}:"):
                    continue
                parts = line.strip().split(":")
                if len(parts) != 3:
                    continue
                try:
                    entry = (int(parts[1]), int(parts[2]))
                except ValueError:
                    return None
                if entry[1] != 1:
                    return entry
                if supplementary is None:
                    supplementary = entry
    except (FileNotFoundError, PermissionError, OSError):
        return None
    return supplementary


def subid_files_with_entries(username: str) -> list[Path]:
    """Which of the subid files currently carry any entry for username.

    Used by the disable/cleanup dry-run reporting, so it answers "is there
    something to remove" without taking the lock — a stale answer only affects
    a preview line, and remove_subid_entries() re-reads under the lock anyway.
    """
    found = []
    for path in subid_files():
        try:
            text = path.read_text()
        except (FileNotFoundError, PermissionError, OSError):
            continue
        if any(line.startswith(f"{username}:") for line in text.splitlines()):
            found.append(path)
    return found




def _rewrite_subid_file(path: Path, lines: list[str]) -> None:
    """Replace path's contents with lines, atomically.

    Atomicity is not optional here: podman and newuidmap read /etc/subuid and
    /etc/subgid WITHOUT taking SUBID_LOCK, so cooperating writers alone can't
    make a truncate-then-write safe, and a crash mid-write would lose every
    workload's mapping rather than just the one being removed.
    """
    replace_file_atomically(path, "\n".join(lines) + ("\n" if lines else ""))


def remove_subid_entries(username: str) -> list[Path]:
    """Drop every subuid/subgid entry for username. Returns the files changed.

    Takes SUBID_LOCK itself and holds it across the whole read-filter-write of
    both files, which is what makes this safe to call concurrently with an
    enable that is appending under the same lock. Callers must NOT hand-roll
    this: a read and a write that each take the lock separately is not an
    atomic read-modify-write, and drops a range appended in between.
    """
    changed = []
    with subid_lock():
        for path in subid_files():
            try:
                text = path.read_text()
            except (FileNotFoundError, PermissionError, OSError):
                continue
            kept = [line for line in text.splitlines()
                    if not line.startswith(f"{username}:")]
            if len(kept) != len(text.splitlines()):
                _rewrite_subid_file(path, kept)
                changed.append(path)
    return changed


def append_subid_entries(path: Path | str, entries: list[str]) -> None:
    """Append entries (`username:start:count` strings) to path under the lock.

    Append rather than rewrite on purpose: O_APPEND adds only this workload's
    lines and can never drop another's, so it stays correct even against a
    writer that skipped the lock.
    """
    if not entries:
        return
    with subid_lock():
        with open(path, "a") as f:
            for entry in entries:
                f.write(entry + "\n")


# Per-run tracking set: `get_next_uid` records UIDs allocated during this
# process invocation so multiple workloads enabled in the same run don't race.
_allocated_uids: set[int] = set()


def _reserved_uids_in_pending_sysusers() -> set[int]:
    """UIDs handed out in pending sysusers configs but not yet in /etc/passwd.

    Between allocation and `systemd-sysusers` creating the user, a workload's
    UID lives only in its sysusers .conf: the boot generator writes it into
    /run/systemd/system and defers user creation to the workload's setup
    service, potentially much later. During that gap the UID is invisible to
    `pwd.getpwall()`, so a concurrent allocator would re-hand-out the slot.
    get_next_uid() unions these in — provided every allocator writes its .conf
    while still holding SUBID_LOCK — to close that window. /run is tmpfs (no
    cross-boot staleness) and disable removes the conf, so this set tracks
    live allocations.

    /run/sysusers.d is scanned too even though nothing of ours writes there:
    it is the standard drop-in directory, so a conf placed by hand or by a
    future caller pins its UID the same way. Today that half always reads
    empty.
    """
    reserved: set[int] = set()
    for d in (RUN_SYSTEMD_SYSTEM, RUN_SYSUSERS_D):
        try:
            confs = list(d.glob("workload-*.conf"))
        except OSError:
            continue
        for conf in confs:
            try:
                text = conf.read_text()
            except OSError:
                continue
            for line in text.splitlines():
                # sysusers user line: `u <name> <uid|uid:gid> "gecos" <home>`.
                fields = line.split()
                if len(fields) >= 3 and fields[0] == "u":
                    try:
                        reserved.add(int(fields[2].split(":", 1)[0]))
                    except ValueError:
                        pass
    return reserved


def _used_uids() -> set[int]:
    """Every workload-range UID that is spoken for right now.

    The live /etc/passwd snapshot, plus UIDs already allocated in this process
    invocation, plus UIDs pinned in pending sysusers configs (see
    _reserved_uids_in_pending_sysusers — slots handed out but not yet created).
    Callers must hold SUBID_LOCK: the set is only meaningful for as long as no
    other allocator can move.
    """
    used = set(_allocated_uids)
    used |= _reserved_uids_in_pending_sysusers()
    try:
        for pw in pwd.getpwall():
            if UID_MIN <= pw.pw_uid <= UID_MAX:
                used.add(pw.pw_uid)
    except Exception:
        pass
    return used


def get_next_uid() -> int:
    """Return the next free UID in the workload range [UID_MIN, UID_MAX].

    Takes SUBID_LOCK itself so every caller — including the boot generator,
    which used to allocate unlocked — is mutexed against a concurrent allocator
    picking the same free slot. Reentrant, so the enable path can keep the lock
    held across the subsequent sysusers write.
    """
    with subid_lock():
        used = _used_uids()
        for uid in range(UID_MIN, UID_MAX + 1):
            if uid not in used:
                _allocated_uids.add(uid)
                return uid
        raise RuntimeError(f"No free UIDs in range {UID_MIN}-{UID_MAX}")


def state_owner_uid(name: str) -> int | None:
    """The workload-range UID owning `name`'s existing /var tree, if any.

    Reads data/ then state/ — the two directories workload-ensure-user chowns.
    The root above them can legitimately stay root-owned, so it is not consulted.
    Returns None when nothing is there, when the owner is outside the workload
    range (root-owned, or a stray non-workload UID), or when /var is unreadable.

    Read-only by design: the boot generator calls this, and the generate step is
    read-only with respect to /var.
    """
    for d in (workload_data_dir(name), workload_state_dir(name)):
        try:
            uid = d.stat().st_uid
        except OSError:
            continue
        if UID_MIN <= uid <= UID_MAX:
            return uid
    return None


def claim_uid(name: str) -> tuple[int, str]:
    """Allocate `name`'s UID, adopting the owner of pre-existing state.

    Returns (uid, reason) where reason is one of:

      "fresh"     — no adoptable /var tree; next free UID.
      "adopted"   — /var already belongs to a workload UID; reused it.
      "collision" — /var belongs to a UID that is now someone else's; fell back
                    to a fresh one, leaving the old tree stranded. Callers must
                    surface this: it is the one case nothing here can repair.

    Why adopt at all. `workload-ensure-user` already grandfathers the subid
    range whenever the user has an /etc/subuid entry, because shifting a UID
    mapping under a running container corrupts its namespace. That covers every
    case except passwd-absent-but-/var-present, which is the rollback case: boot
    an older deployment, and _wl-<name> is gone from /etc/passwd while
    /var/lib/workloads/<name> survives. Allocating a fresh UID there re-points a
    *derived* subordinate range (600100000 + (uid - UID_MIN) * 65536) onto a tree
    still owned by the old one, and ensure-user only chowns the tops of state/
    and data/, not their contents — so the workload comes up unable to read its
    own data.

    Adopting the UID rather than repairing ownership is the point: files written
    from inside the container are owned out of the subordinate range, and
    recovering the same UID recovers the same range, so every one of them is
    correct again with no traversal. No chown could achieve that.

    Deliberately derived rather than recorded. The owning UID *is* the answer and
    is one stat away, so putting it in the deployment marker would add a second
    source of truth competing with /etc/subuid — one that can go stale.
    """
    with subid_lock():                      # reentrant; get_next_uid re-takes it
        adopted = state_owner_uid(name)
        if adopted is None:
            return get_next_uid(), "fresh"
        if adopted in _used_uids():
            return get_next_uid(), "collision"
        # Record it so a later allocation in this same run cannot hand out the
        # slot we just took out of sequence.
        _allocated_uids.add(adopted)
        return adopted, "adopted"
