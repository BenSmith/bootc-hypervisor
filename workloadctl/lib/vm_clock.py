"""
vm_clock — the guest's clock, read and repaired over the QEMU guest agent.

WHY THIS MODULE EXISTS AT ALL, WHICH IS NOT OBVIOUS FROM ITS SIZE

A vCPU pause is lost by the guest exactly and permanently: a 120.035 s QMP
`stop` moves the guest by 119.998 s, and it stays flat at that offset
afterwards. Nothing inside puts it back -- NTP is dead in a filtered guest by
construction (chronyd stays `active` while `chronyc tracking` reports
`Stratum 0` and a 1970 reference time), because this design closed the UDP path
it needs.

A skewed guest breaks TLS, and it breaks it worst where the egress inspector
mints. A leaf carries `notBefore = mint_time - 1h`; a guest rewound by more
than an hour asks whether its own clock is past that and gets `no`. The failure
is narrower than "TLS stops working" and much worse to diagnose for it: leaves
already in the working-set cache keep validating, so the guest reaches its usual
hosts and fails only on names it has not visited yet, while every host-side
figure reads healthy. A guest with no inspector at all has the same problem
against real certificates, just with a wider margin and nothing to count it.

THE REMEDY IS NOT A HOOK ON THE PATHS THAT PAUSE, AND THAT IS THE DESIGN

The obvious shape is a hook on each path that pauses vCPUs. It was drafted and
rejected: `backup --consistency crash` is one such path, a host that suspends or
hibernates is a second with no hook available (no `system-sleep` hook ships and
none exists), `workloadctl incant <vm> stop` is a third,
and the fourth arrives in five years with no hook and the same silent failure.
Enumerating callers is a remedy that decays.

So the remedy runs on the guest's behalf without knowing why it is needed, in
two places that between them cover every path that can ever pause a vCPU:

  * The clock keeper (libexec/workload-vm-clock, on workload-<name>-clock.timer)
    asks once a minute and repairs past the threshold. It runs whether or not
    the workload has an inspector, so the plain-egress case above is covered,
    and it needs nothing from any pause path -- a timer catches up on resume.
  * The inspector's pre-mint remedy asks on a mint cache miss, which is the
    one moment the skew is about to matter, and closes the window the timer's
    period leaves. The inspector does not know this is about clocks: it takes
    a callable from its launcher and counts what the callable said (see
    egress_mint's REMEDY_* and the translation in
    libexec/workload-inspect-listener).

`backup` additionally resyncs right after its own unpause, at a threshold of a
second: it is the one pause path that knows it is one.

THE GUEST HAS A HALF OF THIS TOO, AND IT IS NOT A SUBSTITUTE

Every seed workloadctl renders wires the guest to `ptp_kvm`: it reads the host's
realtime clock over a KVM hypercall, needs nothing on the host side and sends no
packets, so unlike NTP it survives the egress filter. The two halves fail in
opposite directions, which is why both ship. This one repairs a guest that was
never configured for anything and does not know it was paused -- but only once
a minute or on a mint cache miss, and only if the guest runs qemu-guest-agent.
That one repairs the guest on its own four-second poll with no agent and no
host involvement --
but only if the guest was seeded with it, which a custom
[vm.cloud_init].user_data_file may not have been. See vm_ptp.py for
what the seed carries and tests/test_vm_ptp_kvm.py for what each piece is for.

TWO FACTS ABOUT THE PROTOCOL THAT COST MEASUREMENT TO LEARN

- `guest-set-time` with NO ARGUMENT does not work on these guests and does not
  hang. It reads the guest's RTC, and that read fails:
  `child process has failed to set hardware clock to system time: hwclock:
  select() to /dev/rtc0 to wait for clock tick timed out`. An earlier note
  recorded it as "issued and did not return", which invites a retry with a
  longer timeout that will never succeed. Only the explicit-nanoseconds form is
  used here, and it works because its `hwclock --systohc` WRITE succeeds where
  the other form's READ failed.
- There is NO `negotiate()` on the guest-agent channel. It shares QMP's
  newline-JSON framing but has no greeting and no `qmp_capabilities`, so reading
  for one blocks until the recv timeout on every single call.
"""

from __future__ import annotations

import random
import time

from qmp import QMPClient
from vm_defs import vm_guest_agent_socket

# What a clock check concluded. Three outcomes matter separately to every
# caller: the clock was fine, it was wrong and is now right, and there was no
# agent to ask -- which is the state that silently keeps the old broken
# behaviour, and the one a caller most needs to be able to see. This is the
# clock's own vocabulary; the inspector's launcher translates it into the
# minter's (egress_mint.REMEDY_*) at the seam, so the inspector never learns
# the word "clock" and this module never learns the word "mint".
CLOCK_OK = "ok"
CLOCK_RESYNCED = "resynced"
CLOCK_UNAVAILABLE = "unavailable"
CLOCK_FAILED = "failed"

# How long to wait for qemu-guest-agent to answer. Every VM is wired with the
# agent channel, but a guest that hasn't installed or started qemu-ga never
# opens its end -- QEMU still accepts our connection, so a missing agent looks
# exactly like a slow one and can only be told apart by waiting. The budget is
# small because callers sit in front of user-visible latency: agent present is a
# local unix-socket round trip, agent absent costs this once.
GUEST_AGENT_TIMEOUT = 1.5

# How far the guest's clock may be from the host's before the keeper or the
# mint path repairs it. Five minutes: well inside the one-hour backdate, so it
# fires long before anything breaks, and far outside ordinary drift, which was
# measured at ~10 ppm and would need about a year to reach it. A pause -- the
# case this exists for -- clears it immediately, since a pause short enough to
# stay under five minutes is also short enough to be harmless.
CLOCK_SKEW_THRESHOLD_SECONDS = 300.0

# The keeper: one tick of resync_guest_clock_if_skewed per VM per minute, from
# workload-<name>-clock.timer, while the VM is up. A minute is the window a
# resumed guest can spend skewed before this half of the remedy reaches it
# (ptp_kvm's four seconds and the pre-mint remedy both cut it shorter where
# they apply), against a cost of one local unix-socket round trip -- or one
# 1.5 s timeout on a guest with no agent. Neither number is worth tuning.
CLOCK_KEEPER_PERIOD_SECONDS = 60
VM_CLOCK_KEEPER_BIN = "/usr/libexec/workloadctl/workload-vm-clock"


def guest_agent_sync(qga: QMPClient, max_messages: int = 8) -> None:
    """Handshake that guarantees the next reply we read is the one we asked for.

    The channel is a stream that outlives any single client. If a previous
    lookup timed out after sending a command but before reading its reply -- the
    GUEST_AGENT_TIMEOUT case, so not hypothetical -- that reply is still queued
    in the port when the next connection opens, and a naive read would take it
    as the answer to a question it never asked. guest-sync carries a nonce, so
    anything ahead of the matching reply is provably stale and discarded.

    Raises (like any other agent failure) when the nonce never comes back; the
    caller treats that as "no agent" and falls through.
    """
    token = random.randint(1, 2**31)
    reply = qga.execute("guest-sync", {"id": token})
    for _ in range(max_messages):
        if reply.get("return") == token:
            return
        message = qga.next_message()
        if message is None:
            break
        reply = message
    raise ConnectionError("guest agent did not echo the sync token")


def _connect(name: str) -> QMPClient | None:
    """An agent channel for one workload, synced, or None if there isn't one.

    None rather than an exception for every failure mode, because from a
    caller's side "no agent" and "agent broken" have the same disposition and
    neither is an error: a guest whose image lacks qemu-guest-agent is a
    supported configuration that simply cannot be repaired this way.

    THAT IT IS UNREPAIRABLE IS REPORTED, and reported is what makes never
    failing a mint the right call -- but be precise about where. The minter
    counts it as `remedy_unavailable` and the inspector writes that into its
    status document (`mint.remedy_unavailable` in
    /run/workload-vm/<name>/inspect-status.json), which `doctor` and the
    exporter read. The keeper says nothing about it on its own: a guest with
    no agent would make it say so once a minute, forever.
    """
    sock_path = vm_guest_agent_socket(name)
    if not sock_path.exists():
        return None
    qga = QMPClient()
    try:
        qga.connect(sock_path, timeout=GUEST_AGENT_TIMEOUT,
                    recv_timeout=GUEST_AGENT_TIMEOUT)
        guest_agent_sync(qga)
        return qga
    except Exception:
        qga.close()
        return None


def guest_clock_offset(name: str) -> float | None:
    """Seconds the guest's clock is ahead of the host's, or None if unknowable.

    Bracketed, then reported as the midpoint. The guest reads its clock
    somewhere inside our own round trip, so the honest answer is an interval;
    the interval is a local unix-socket round trip wide (milliseconds) against a
    threshold of five minutes, so collapsing it to the midpoint cannot change
    any decision made from it.

    `guest-get-time` rather than an `exec` of `date`: it is the same answer
    without needing a working login, a working shell, or the SSH path that a
    skewed guest may itself have broken.
    """
    qga = _connect(name)
    if qga is None:
        return None
    try:
        t0 = time.time()
        reply = qga.execute("guest-get-time")
        t1 = time.time()
    except Exception:
        return None
    finally:
        qga.close()
    guest_ns = reply.get("return")
    if not isinstance(guest_ns, int):
        return None
    return guest_ns / 1_000_000_000 - (t0 + t1) / 2


def set_guest_time(name: str, *, now: float | None = None) -> bool:
    """Set the guest's clock from the host's. True if the guest confirmed it.

    THE EXPLICIT FORM ONLY -- see the module docstring. The no-argument form is
    measured to fail on exactly the guests this applies to, and its failure
    looks like a timeout.
    """
    qga = _connect(name)
    if qga is None:
        return False
    try:
        when = time.time() if now is None else now
        reply = qga.execute("guest-set-time",
                            {"time": int(when * 1_000_000_000)})
    except Exception:
        return False
    finally:
        qga.close()
    return "error" not in reply and reply.get("return") == {}


def keep_guest_clock(
        name: str, *,
        threshold: float = CLOCK_SKEW_THRESHOLD_SECONDS,
) -> tuple[str, float | None]:
    """Repair the guest's clock if it has drifted past `threshold`, and say
    by how much it was out: (outcome, offset), offset None when unknowable.

    The keeper's tick and the mint path's remedy, one function. Costs one
    local round trip and returns CLOCK_OK without a second one in the
    overwhelmingly common case, which is what makes it affordable once a
    minute and on every cache miss.

    Never raises. A mint that fails because its clock check failed would convert
    a guest with no agent -- a supported configuration -- into a guest with no
    egress, which is strictly worse than the skew this repairs.
    """
    offset = guest_clock_offset(name)
    if offset is None:
        return CLOCK_UNAVAILABLE, None
    if abs(offset) <= threshold:
        return CLOCK_OK, offset
    return (CLOCK_RESYNCED if set_guest_time(name) else CLOCK_FAILED), offset


def resync_guest_clock_if_skewed(
        name: str, *,
        threshold: float = CLOCK_SKEW_THRESHOLD_SECONDS) -> str:
    """keep_guest_clock for a caller that wants the outcome and not the
    number: the pre-mint remedy counts words, and backup prints one."""
    return keep_guest_clock(name, threshold=threshold)[0]
