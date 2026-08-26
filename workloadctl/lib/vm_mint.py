"""
vm_mint — minting leaf certificates for a filtered VM's egress inspector.

The back half of bump-then-403. The inspector reads a name out of a ClientHello
without answering it, decides what the name deserves, and then -- for both
dispositions -- completes the handshake with a certificate this workload's own
CA signed, because a guest that gets a certificate ERROR learns nothing, while a
guest that gets a clean TLS session and a `403` learns exactly which host was
refused and why.

WHAT IS IN HERE AND WHY IT IS THREE THINGS RATHER THAN ONE

Minting is a subprocess (~20 ms, against ~0.1 ms in-process -- but `lib/` has no
third-party dependencies and stdlib cannot sign a certificate, so `openssl` it
is; tests/test_stdlib_only.py enforces the constraint). That cost is what shapes
everything else:

- A WORKING-SET CACHE, persisted, so a guest's usual hosts cost one mint each
  ever, not one per connection and not one per listener restart.
- A SEPARATE DENIAL-ONLY CACHE, so a guest hammering invented names cannot
  evict the working set that its legitimate traffic depends on. Two bounded
  LRUs, never one shared one -- with a shared cache, "flood the cache" is a
  denial of service against the workload's real destinations, spelled in
  ordinary traffic.
- A TOKEN BUCKET over all minting, because a cache miss is attacker-reachable by
  construction: the guest picks the names.

WHAT IS NOT VIABLE, RECORDED BECAUSE IT IS THE OBVIOUS FIRST IDEA

One shared certificate for every denial, minted once. The client validates the
SAN against the name it asked for and aborts on mismatch, so the guest gets a
certificate error instead of the `403` -- which is the entire benefit
bump-then-403 exists to buy. The denials must each be minted for their own name,
which is why they need a cache and a bucket of their own rather than a constant.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import subprocess
import tempfile
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import NamedTuple

from vm import (
    LeafRefused, VM_DENIAL_DIR_NAME, VM_LEAF_DIR_NAME,
    VM_LEAF_RENEW_WITHIN_SECONDS, VM_LEAF_VALIDITY_DAYS,
    vm_ca_cert_path, vm_ca_key_path, vm_leaf_openssl_argv,
    vm_normalise_hostname,
)
from vm_clock import CLOCK_FAILED, CLOCK_RESYNCED, CLOCK_UNAVAILABLE

# Which clock_check outcomes get a counter, and which counter each lands in.
# CLOCK_OK deliberately has none: it is what every healthy mint returns, so a
# figure tracking it would track the mint count and say nothing further. The
# other three each describe a different thing being wrong, and one of them --
# CLOCK_UNAVAILABLE -- describes the remedy itself not being present.
_CLOCK_STATS = {
    CLOCK_RESYNCED: "clock_resyncs",
    CLOCK_UNAVAILABLE: "clock_unavailable",
    CLOCK_FAILED: "clock_failed",
}

# --- sizes ---
#
# Module-local: nothing outside this file needs to agree on them, and vm.py
# holds only what two programs must.

# The working set. 1024 exact names is far above any guest's real destination
# count (a browsing session is tens; a build reaching a package index and a
# registry is fewer) and the entries are small, so the bound is a guard against
# unbounded growth rather than a budget anything is expected to press against.
LEAF_CACHE_MAX = 1024

# The denial set, deliberately a quarter the size. It is the one an adversary
# controls the fill rate of, and nothing depends on a denial staying cached --
# a miss costs one mint, which is exactly what the bucket below rations.
#
# THE FLOOR IS NOT AESTHETIC: A CACHE MUST HOLD MORE ENTRIES THAN THERE CAN BE
# CONNECTIONS IN FLIGHT. Eviction unlinks the victim's PEM, and a leaf is a
# file the caller opens AFTER this class has handed it over -- so if the
# least-recently-used entry can be one a live connection is still holding, a
# flood can delete a certificate out from under a handshake that was about to
# use it. With N connection slots, N distinct names can be checked out at once,
# and only the N+1'th insert can evict something nobody holds.
#
# This was 128, which is exactly workload-vm-inspect-listener's MAX_CONNECTIONS
# and therefore exactly one entry short of the invariant: 128 concurrent
# denials for distinct names could evict the oldest of themselves. The failure
# was a handshake that died on a missing file and was reported as the guest not
# trusting the CA -- a wrong diagnosis pointing at a re-provision. Doubled, so
# the margin is a factor rather than an off-by-one, and asserted against the
# listener's ceiling by tests/test_vm_mint.py, since the two numbers live in
# different files and nothing else makes them meet. The working set was always
# clear of this (1024 against 128) and is unchanged.
DENIAL_CACHE_MAX = 256

# The bucket. 256 tokens refilling at 1/s: a cold VM contacting fifty hosts
# spends fifty tokens at once and refills in under a minute, while a guest
# minting continuously is held to one name a second.
MINT_BUCKET_CAPACITY = 256
MINT_BUCKET_REFILL_PER_SECOND = 1.0

# How long an ALLOWLISTED mint waits for a token before giving up. Denials do
# not wait at all -- see Minter.leaf.
MINT_WAIT_SECONDS = 5.0

# Where the persisted working set lives, under the workload's state directory
# beside the CA that signed it -- and the denial set's, a sibling rather than a
# subdirectory so a `rm -rf` of one cannot take the other with it.
#
# Both names come from vm.py rather than being spelled here, because the
# SELinux fcontext patterns registered at enable have to name the same three
# directories this module creates. Two spellings of "leaves" is a mislabelled
# directory, and a mislabelled directory presents as the inspector failing to
# mint rather than as a naming mistake.
LEAF_DIR_NAME = VM_LEAF_DIR_NAME
DENIAL_DIR_NAME = VM_DENIAL_DIR_NAME


class MintThrottled(Exception):
    """The token bucket was empty. Carries which disposition was refused.

    A type of its own rather than a `None` return, because the two callers do
    opposite things with it -- an allowlisted name that cannot be minted for is
    an incident to log, a denied one is the connection closing -- and a caller
    that forgets to check a sentinel gets a certificate-shaped `None` instead of
    an error.
    """

    def __init__(self, name: str, *, denied: bool):
        self.name = name
        self.denied = denied
        super().__init__(
            f"mint rate limit reached for {name!r} "
            f"({'denied' if denied else 'allowlisted'})")


class MintFailed(Exception):
    """openssl refused to sign, with its own words in the message."""


class Leaf(NamedTuple):
    """One minted leaf: where it is, and when it stops being usable.

    `path` holds the certificate AND its private key in one PEM file, which is
    what `ssl.SSLContext.load_cert_chain(path)` takes with no keyfile argument.
    One file rather than two so eviction is one unlink and cannot half-succeed.
    """
    name: str
    path: Path
    not_after: float

    def due_for_renewal(self, now: float) -> bool:
        return now >= self.not_after - VM_LEAF_RENEW_WITHIN_SECONDS


class TokenBucket:
    """A refilling bucket, thread-safe, with an optional bounded wait.

    The clock is injected rather than read directly so a test can assert the
    refill rate without spending the wall-clock time it describes. `monotonic`,
    not `time.time`: a host clock stepped backwards -- by the very resync this
    rung added -- would otherwise freeze the bucket for the size of the step.
    """

    def __init__(self, capacity: float = MINT_BUCKET_CAPACITY,
                 refill_per_second: float = MINT_BUCKET_REFILL_PER_SECOND,
                 *, clock=time.monotonic, sleep=time.sleep):
        self.capacity = float(capacity)
        self.refill_per_second = float(refill_per_second)
        self._clock = clock
        self._sleep = sleep
        self._tokens = float(capacity)
        self._last = clock()
        self._lock = threading.Lock()

    def _refill_locked(self) -> None:
        now = self._clock()
        elapsed = max(0.0, now - self._last)
        self._last = now
        self._tokens = min(self.capacity,
                           self._tokens + elapsed * self.refill_per_second)

    @property
    def tokens(self) -> float:
        with self._lock:
            self._refill_locked()
            return self._tokens

    def take(self) -> bool:
        """One token if there is one, without waiting."""
        with self._lock:
            self._refill_locked()
            if self._tokens < 1.0:
                return False
            self._tokens -= 1.0
            return True

    def wait(self, timeout: float) -> bool:
        """One token, waiting up to `timeout` seconds for it.

        Polls rather than sleeping for the computed shortfall: several threads
        waiting would each compute the same instant and wake together, and the
        poll interval is small against a five-second budget.
        """
        deadline = self._clock() + timeout
        while True:
            if self.take():
                return True
            if self._clock() >= deadline:
                return False
            self._sleep(min(0.05, self.refill_per_second and
                            1.0 / self.refill_per_second or 0.05))


class LeafCache:
    """A bounded LRU of leaves, optionally backed by a directory.

    Bounded by COUNT, not by age: an entry that ages out is handled by
    `due_for_renewal` at lookup time instead, so a cache full of valid-but-idle
    entries never re-mints and a cache holding one about to expire never serves
    it.

    The PEMs survive a restart, which is the point -- the listener is
    socket-activated and `PartOf=` the VM, so it restarts more often than the
    guest does, and re-minting the entire working set each time would put the
    cold-start cost on every VM restart.

    EVERY CACHE OWNS A DIRECTORY, AND THAT IS WHAT MAKES THE TWO SETS SEPARATE.
    A leaf is a file, because completing a handshake means handing openssl-signed
    PEM to `ssl.SSLContext.load_cert_chain` -- so "memory-only" is not available
    to the denial set, and the separation has to be structural instead: eviction
    unlinks a path this cache minted, and two caches sharing a directory would
    make a flood of refusals evict the working set by deleting its files. Two
    directories, and the class cannot be constructed without one.
    """

    def __init__(self, capacity: int, directory: Path):
        self.capacity = capacity
        self.directory = Path(directory)
        self._entries: OrderedDict[str, Leaf] = OrderedDict()
        self._lock = threading.RLock()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._trim_directory()

    def _trim_directory(self) -> None:
        """Delete the oldest PEMs on disk down to `capacity`.

        The in-memory LRU starts empty on every restart, so eviction alone
        cannot bound the directory across restarts -- files evicted in a
        previous process were never in this one's LRU to evict. Oldest-first by
        mtime is a coarse stand-in for least-recently-used and only ever runs at
        construction, where being coarse costs a re-mint and nothing else.
        """
        try:
            pems = sorted(self.directory.glob("*.pem"),
                          key=lambda p: p.stat().st_mtime)
        except OSError:
            return
        for stale in pems[:max(0, len(pems) - self.capacity)]:
            stale.unlink(missing_ok=True)

    def path_for(self, name: str) -> Path:
        """Where `name`'s PEM lives on disk.

        Hashed, not the name itself: a name is up to 253 characters of
        guest-chosen input and this is a filesystem path. The hash also makes
        every filename the same shape and length, so nothing about the guest's
        destinations is legible from a directory listing.
        """
        digest = hashlib.sha256(name.encode()).hexdigest()
        return self.directory / f"{digest}.pem"

    def get(self, name: str, *, now: float) -> Leaf | None:
        """A usable leaf for `name`, or None. Renewal-due counts as a miss."""
        with self._lock:
            leaf = self._entries.get(name)
            if leaf is None:
                leaf = self._adopt(name, now=now)
                if leaf is None:
                    return None
            if leaf.due_for_renewal(now) or not leaf.path.exists():
                self._drop(name)
                return None
            self._entries.move_to_end(name)
            return leaf

    def _adopt(self, name: str, *, now: float) -> Leaf | None:
        """Take a PEM this process did not mint, left by a previous one.

        Adoption on a miss rather than a scan at startup: reading 1024 PEMs to
        recover their expiry would put a subprocess-per-file on the listener's
        first connection, and the names are hashed so the mapping cannot be
        recovered from the directory anyway. A miss already costs a mint, so
        checking one path first is free by comparison.
        """
        path = self.path_for(name)
        if not path.exists():
            return None
        not_after = _pem_not_after(path)
        if not_after is None:
            path.unlink(missing_ok=True)
            return None
        leaf = Leaf(name=name, path=path, not_after=not_after)
        self._insert(leaf)
        return leaf

    def put(self, leaf: Leaf) -> None:
        with self._lock:
            self._insert(leaf)

    def _insert(self, leaf: Leaf) -> None:
        self._entries[leaf.name] = leaf
        self._entries.move_to_end(leaf.name)
        while len(self._entries) > self.capacity:
            _name, evicted = self._entries.popitem(last=False)
            evicted.path.unlink(missing_ok=True)

    def _drop(self, name: str) -> None:
        leaf = self._entries.pop(name, None)
        if leaf is not None:
            leaf.path.unlink(missing_ok=True)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def __contains__(self, name: str) -> bool:
        with self._lock:
            return name in self._entries


def _pem_fingerprint(path: Path) -> str | None:
    """The SHA-256 fingerprint of the certificate in a PEM, or None.

    Decoded here rather than shelled out to openssl. A fingerprint is a hash of
    the DER, the DER is what the base64 between the PEM markers decodes to, and
    hashlib is already imported -- so the subprocess this would otherwise cost
    on every status write buys nothing. Formatted in the colon-separated
    uppercase hex `openssl x509 -fingerprint -sha256` prints, because the value
    exists to be compared against that output by eye.

    Only the FIRST certificate in the file, which for a CA PEM is the CA.
    """
    try:
        text = path.read_text()
    except OSError:
        return None
    marker = "-----BEGIN CERTIFICATE-----"
    start = text.find(marker)
    end = text.find("-----END CERTIFICATE-----", start + 1)
    if start == -1 or end == -1:
        return None
    body = text[start + len(marker):end]
    try:
        der = base64.b64decode("".join(body.split()), validate=True)
    except (ValueError, binascii.Error):
        return None
    if not der:
        return None
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def _pem_not_after(path: Path) -> float | None:
    """The notAfter of the certificate in a PEM, as a unix timestamp.

    `ssl.cert_time_to_seconds` on the text openssl prints, rather than parsing
    DER by hand. Returns None on anything unreadable, which the caller treats
    as "not cached" -- a corrupt PEM must cost a re-mint, never an exception on
    a connection path.
    """
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", str(path), "-noout", "-enddate"],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    _, _, when = result.stdout.strip().partition("=")
    try:
        import ssl
        return float(ssl.cert_time_to_seconds(when))
    except (ValueError, OSError):
        return None


class Minter:
    """Leaves for one workload, cached, rationed, and clock-checked.

    `clock_check` HAS NO DEFAULT ON PURPOSE. It is the seam the mint-time clock
    remedy hangs on, and a remedy that covers every pause path by being
    demand-driven is worth nothing if a caller can construct a Minter without
    one. Passing `lambda: None` is a decision a reader can see; an omitted
    keyword argument is not.
    """

    def __init__(self, name: str, state_dir, *, clock_check,
                 clock=time.time, runner=subprocess.run,
                 bucket: TokenBucket | None = None):
        self.name = name
        self.state_dir = Path(state_dir)
        self._clock_check = clock_check
        self._clock = clock
        self._runner = runner
        self.bucket = bucket if bucket is not None else TokenBucket()
        self.working_set = LeafCache(
            LEAF_CACHE_MAX, self.state_dir / LEAF_DIR_NAME)
        # Its own directory, which is what keeps the two sets unable to evict
        # each other. See the class docstring on LeafCache.
        self.denials = LeafCache(
            DENIAL_CACHE_MAX, self.state_dir / DENIAL_DIR_NAME)
        # THE DENIAL FIGURES ARE SUBSETS, not a second dimension: `mints` and
        # `hits` count both caches, and `denied_mints`/`denied_hits` count the
        # denial-only half of the same events. Reporting them as disjoint pairs
        # would make the total a sum an operator has to compute; reporting only
        # the totals loses the split, and the SPLIT IS THE SIGNAL -- legitimate
        # traffic mints a handful of working-set leaves and then lives on hits,
        # while a guest driving the minter shows up almost entirely in the
        # denial half. Same number, two very different workloads.
        self.stats = {
            "mints": 0, "denied_mints": 0,
            "hits": 0, "denied_hits": 0,
            "throttled": 0, "refused": 0, "failed": 0,
            # Four outcomes, not one. `clock_unavailable` is the one that
            # matters: it means this guest has no agent to ask, so the
            # mint-time clock remedy is INERT here -- the failure it exists to
            # prevent is still possible and nothing else says so. It is read
            # from the inspector's status document (`mint.clock_unavailable`),
            # which is where every figure in here surfaces; `diagnose` does not
            # read that document at all yet, and gains a reader at rung 5.
            "clock_resyncs": 0, "clock_unavailable": 0, "clock_failed": 0,
        }
        self._lock = threading.Lock()
        self._ca_identity = None

    def _bump(self, *names: str) -> None:
        """Add one to each named counter, under the lock `snapshot` reads with.

        `d[k] += 1` is a read and a write rather than one operation, and every
        call site here runs on a per-connection thread. Unlocked, increments are
        lost under exactly the concurrency the figures exist to describe -- a
        workload under sustained abuse is read by `throttled` and
        `denied_mints`, and those are the counters a flood drives in parallel.
        The lock was already taken by `snapshot`; it simply was not taken by
        anything that WROTE, which made it a lock over nothing.

        Several names at once because the pairs are subsets, not dimensions:
        `denied_mints` counts the denial-only half of `mints`. Bumping them in
        one critical section is what stops a reader seeing a total that has not
        yet been told about its own subset.
        """
        with self._lock:
            for name in names:
                self.stats[name] += 1

    def leaf(self, server_name: str, *, denied: bool) -> Leaf:
        """A leaf for one exact name. Raises rather than returning a sentinel.

        The name arrives already normalised by the caller's parse; normalising
        again is idempotent and costs nothing, and it means this function's
        contract does not depend on a promise made two modules away.

        THE TWO DISPOSITIONS DIFFER ONLY ON AN EMPTY BUCKET, and that is the
        part worth getting right. A denial does not wait: under a flood the
        refusals degrade to closing the connection, which is the behaviour this
        design rejects as a DEFAULT and accepts as an overflow, because it is
        unreachable in normal operation. An allowlisted name waits up to
        MINT_WAIT_SECONDS, because legitimate traffic never empties the bucket
        and losing it is the outcome the whole rung exists to avoid.
        """
        name = vm_normalise_hostname(server_name)
        cache = self.denials if denied else self.working_set
        now = self._clock()

        cached = cache.get(name, now=now)
        if cached is not None:
            self._bump(*(("hits", "denied_hits") if denied else ("hits",)))
            return cached

        if denied:
            if not self.bucket.take():
                self._bump("throttled")
                raise MintThrottled(name, denied=True)
        else:
            if not self.bucket.wait(MINT_WAIT_SECONDS):
                self._bump("throttled")
                raise MintThrottled(name, denied=False)

        # On a miss only, and after the bucket: a guest cannot make this run
        # more often than it can make us mint.
        outcome = self._clock_check()
        if outcome in _CLOCK_STATS:
            self._bump(_CLOCK_STATS[outcome])

        try:
            leaf = self._mint(name, cache, denied=denied)
        except LeafRefused:
            # COUNTED HERE OR NOWHERE. `refused` and `failed` are two different
            # facts -- a name this design will never mint for, against a mint
            # that broke -- and only the first is guest-chosen. Left uncounted,
            # `refused` was a figure structurally incapable of moving: nothing
            # in this module raised it, so it read 0 on a workload being
            # driven at the one boundary that exists to hold a guest off.
            # The listener's own drop counter merges both under
            # DROP_MINT_FAILED, which is right for an operator reading drops
            # and wrong for anyone asking which of the two happened.
            self._bump("refused")
            raise
        cache.put(leaf)
        return leaf

    def ca_identity(self) -> dict:
        """This workload's CA, as the two facts an operator can act on.

        The SHA-256 fingerprint over the DER, spelled the way `openssl x509
        -fingerprint -sha256` spells it, so it can be compared by eye against
        the anchor installed in the guest -- which is rung 5's comparison, but
        this is the only place the value has a producer, because this is what
        mints with it.

        `notAfter` is here for one reason: a ten-year validity is invisible
        until something prints the date it ends on. Distant is not the same as
        safe, and an operator who can see 2036 can decide whether that is what
        they meant.

        Read once and remembered. The CA does not rotate -- decision 4 of ADR
        008 -- so re-reading it per status write would be a syscall per tick to
        confirm a constant. Every failure degrades to None rather than raising:
        this runs on the status path, and a status file is never worth a
        connection.
        """
        if self._ca_identity is None:
            cert = vm_ca_cert_path(self.state_dir)
            self._ca_identity = {
                "sha256": _pem_fingerprint(cert),
                "not_after": _pem_not_after(cert),
            }
        return dict(self._ca_identity)

    def snapshot(self) -> dict:
        """Everything this minter reports, counters and live sizes together.

        The sizes are read here rather than counted as they change: a cache
        that evicts on insert would need every eviction mirrored into a counter
        to stay honest, and the length IS the honest figure.
        """
        with self._lock:
            out = dict(self.stats)
        out["working_set"] = len(self.working_set)
        out["denials"] = len(self.denials)
        out["tokens"] = round(self.bucket.tokens, 2)
        out["ca"] = self.ca_identity()
        return out

    def _mint(self, name: str, cache: LeafCache, *, denied: bool) -> Leaf:
        """Sign one leaf and land it as a single PEM, atomically.

        Minted into a temporary directory and moved into place, so a reader that
        finds the PEM finds a whole one. `os.replace` on the same filesystem is
        the atomic step; the temp directory is inside the cache directory to
        guarantee that.
        """
        # The certificate a denial gets is identical to the one an allow gets --
        # same name, same CA -- and the disposition lives in what the inspector
        # does AFTER the handshake. What differs is which cache owns the file,
        # so the same name minted under both dispositions lands twice, once per
        # directory. That duplication IS the isolation.
        target = cache.path_for(name)
        argv_dir = cache.directory

        now = self._clock()
        # EVERY filesystem step is inside this, and the reason is measured. A
        # cache directory the process cannot write raises OSError from the
        # TemporaryDirectory below -- which used to be OUTSIDE any handler here,
        # so it left as an OSError, and the inspector's per-connection handler
        # swallows OSError by design. On a KVM host on 2026-08-26 that produced
        # the worst failure shape this component has had: the guest's
        # connection reset, no journal line, no counter, and a warm cache hiding
        # it entirely -- the first request to a host failed and the second
        # succeeded. MintFailed is logged, counted and named; an OSError
        # escaping this function is not.
        try:
            with tempfile.TemporaryDirectory(dir=argv_dir) as tmp:
                key_path = Path(tmp) / "leaf.key"
                cert_path = Path(tmp) / "leaf.crt"
                argv = vm_leaf_openssl_argv(
                    name, vm_ca_key_path(self.state_dir),
                    vm_ca_cert_path(self.state_dir),
                    key_path, cert_path, now=now)
                try:
                    result = self._runner(argv, capture_output=True, text=True,
                                          timeout=30)
                except (OSError, subprocess.SubprocessError) as exc:
                    self._bump("failed")
                    raise MintFailed(f"could not run openssl: {exc}") from exc
                if result.returncode != 0:
                    self._bump("failed")
                    # Both streams: openssl splits its diagnostics across them
                    # and which half carries the cause varies by subcommand.
                    detail = ((result.stderr or "")
                              + (result.stdout or "")).strip()
                    raise MintFailed(
                        f"openssl refused to mint a leaf for {name!r}: {detail}")
                staged = Path(tmp) / "leaf.pem"
                staged.write_text(cert_path.read_text() + key_path.read_text())
                os.chmod(staged, 0o600)
                os.replace(staged, target)
        except OSError as exc:
            self._bump("failed")
            raise MintFailed(
                f"could not write a leaf for {name!r} into {argv_dir}: "
                f"{exc}") from exc

        self._bump(*(("mints", "denied_mints") if denied else ("mints",)))
        not_after = _pem_not_after(target)
        if not_after is None:
            # A leaf we just minted and cannot read back is not a leaf.
            target.unlink(missing_ok=True)
            self._bump("failed")
            raise MintFailed(f"minted leaf for {name!r} is unreadable")
        return Leaf(name=name, path=target, not_after=not_after)


__all__ = [
    "DENIAL_CACHE_MAX", "DENIAL_DIR_NAME", "LEAF_CACHE_MAX",
    "LEAF_DIR_NAME",
    "MINT_BUCKET_CAPACITY", "MINT_BUCKET_REFILL_PER_SECOND",
    "MINT_WAIT_SECONDS", "Leaf", "LeafCache", "LeafRefused", "MintFailed",
    "MintThrottled", "Minter", "TokenBucket", "VM_LEAF_VALIDITY_DAYS",
]
