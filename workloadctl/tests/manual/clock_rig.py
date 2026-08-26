#!/usr/bin/env python3
"""clock_rig.py — what a vCPU pause does to a guest's clock, and whether the
QEMU guest agent can put it back.

Run this ON a KVM host with the workloadctl RPM installed. It boots ONE
throwaway filtered VM workload with its egress inspector on, and measures its
clock across a pause -- and then measures whether a guest whose clock is wrong
can still be handed a certificate it will accept.

WHY THIS RIG EXISTS

Rung 3 mints short-lived leaf certificates for the guest to validate, which
puts the guest's clock on the critical path for all of its traffic. Two
measurements already exist (detail doc §6, §16 item 5):

  drift    ~10 ppm -- 3.7 s over 4 days 10 hours. Four orders of magnitude
           inside a 30-day leaf's window, and the 1-hour notBefore backdate
           covers roughly 1,200 years of it. A non-issue.
  pause    a 127.668 s vCPU stop moved the guest by 127.670 s and it never
           came back. The backdate covers exactly ONE HOUR of this.

Past the backdate every freshly-minted leaf has a notBefore in the guest's
future, so validation fails on EVERY request to a new name while `diagnose`
reports a healthy VM -- §6's rotation trap arriving through the clock.

**And one of the two paths that reaches it is ours.** `workloadctl backup
--consistency crash` issues QMP `stop`, copies the qcow2, and `cont`s in a
`finally`. It resyncs nothing, so the guest is left behind by the copy
duration, permanently -- bounded by disk size and storage speed rather than by
any check. The other path needs no feature of ours: a host that suspends.

WHAT THIS RIG DECIDES

§16 item 5 says in as many words that rung 3 has to choose a remedy, and names
`guest-set-time` as the obvious one while recording that it is UNPROVEN here:
the no-argument form was issued once and did not return, and the
explicit-nanoseconds form is untested. Those two are measurements 4 and 5
below, and they are the whole reason this rig is not just a re-run of the
pause.

Measurement 6 is the one that closes the loop, and it arrived after T5 wired the
remedy in: everything above measures a clock, and 6 measures what the clock was
on the critical path OF. A guest pushed two hours behind -- past the leaf's
1-hour notBefore backdate, so a stale clock CANNOT validate a fresh leaf by
accident -- still reaches a name it has never reached, because the mint path
repairs it on the cache miss before signing. The corroborating half matters as
much as the pass: the guest's offset comes back and `clock_resyncs` moves.
Without those two, the same green is produced by a backdate quietly widened to
cover two hours.

WHAT ONLY A REAL BOOT CAN SHOW

All of it. A paused vCPU is not a thing a unit test has, the guest agent is a
process inside a running guest, and the failure being ruled out is one where
every host-side counter reads healthy. The rig deliberately uses a FILTERED
workload rather than an open one, so chrony is dead exactly as it is in
production -- an open guest would silently resync over NTP and measure nothing.
"""

import argparse
import json
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

BASE_IMAGE = Path("/var/lib/broker-rig/base.qcow2")
DNS_ALLOW = "1.1.1.1:53"
NAME = "wlrc-clock"

# What the guest is allowed to reach over HTTPS, and therefore what measurement
# 6 dials. Two names, because that measurement needs a name it has NEVER minted
# for -- a cache HIT does not run the clock check, so re-dialling the first one
# would prove nothing and look like a pass.
REACHABLE_HOSTS = ["example.com", "example.org"]

# How far back measurement 6 pushes the guest's clock. Past the leaf's 1-hour
# notBefore backdate, which is the whole point: inside the backdate a stale
# clock validates anyway and the assertion cannot fail for the right reason.
# Two hours, set with the explicit-nanoseconds guest-set-time measurement 5
# proves works -- a rig that reached this by PAUSING for two hours is a rig
# nobody runs.
SKEW_SECONDS = 7200
SOCKET_DIR = Path("/run/workload-vm")
STATUS_FILE = "inspect-status.json"

# How long the vCPUs are stopped. The point is that the step EQUALS the pause,
# not that it crosses the 1-hour backdate -- proving equality at 120 s proves
# it at 3600 s, and a rig that actually paused for an hour would be a rig
# nobody runs. Long enough to be far outside the measurement's own noise
# (~1 s), short enough to keep the whole run under ten minutes.
PAUSE_SECONDS = 120

# How long to wait for one guest-agent reply. The no-argument guest-set-time is
# the specific unknown here -- it was issued once before and did not return --
# so a timeout is a RESULT and must be recorded as one rather than crashing the
# rig.
GA_TIMEOUT = 15

RESULTS = []


def say(msg):
    print(msg, flush=True)


def record(label, ok, detail):
    RESULTS.append((label, ok, detail))
    say(f"  [{'ok' if ok else 'FAIL'}] {label}: {detail}")


def run(argv, check=True, timeout=120):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        sys.exit(f"{' '.join(argv)} failed: {p.stderr.strip() or p.stdout.strip()}")
    return p


def guest(script, timeout=90):
    return subprocess.run(
        ["workloadctl", "exec", NAME, "--", "bash", "-lc", script],
        capture_output=True, text=True, timeout=timeout)


# --- QMP, spoken directly ---
#
# lib/backup.py uses the async `qmp` library; a rig wants neither an event loop
# nor a dependency, and stop/cont are two lines of JSON. Same socket backup
# uses, deliberately: this rig is measuring the operation backup performs.

def qmp(commands, timeout=30):
    path = SOCKET_DIR / NAME / "qmp.sock"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(path))
    f = s.makefile("rwb")
    f.readline()                       # the greeting
    replies = []
    for cmd in ["qmp_capabilities"] + commands:
        f.write((json.dumps({"execute": cmd}) + "\n").encode())
        f.flush()
        while True:
            line = json.loads(f.readline())
            if "event" in line:        # events interleave; they are not replies
                continue
            replies.append(line)
            break
    f.close()
    s.close()
    return replies[1:]


# --- the guest agent, also spoken directly ---
#
# The 0xff resync byte and guest-sync-delimited are the documented way to get a
# known-good stream: the agent may have a partial request buffered from a
# previous client, and without the delimiter there is no way to tell its reply
# to that from the reply to ours.

def ga(command, arguments=None, timeout=GA_TIMEOUT):
    """(reply dict, None) or (None, reason) -- a timeout is a result, not a crash."""
    path = SOCKET_DIR / NAME / "ga.sock"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(str(path))
        token = int(time.time() * 1000) & 0xffffffff
        s.sendall(b"\xff")
        s.sendall((json.dumps({"execute": "guest-sync-delimited",
                               "arguments": {"id": token}}) + "\n").encode())
        buf = b""
        while b"\xff" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                return None, "agent closed the connection during sync"
            buf += chunk
        buf = buf.split(b"\xff", 1)[1]
        while b"\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                return None, "agent closed the connection after sync"
            buf += chunk
        line, buf = buf.split(b"\n", 1)
        sync = json.loads(line)
        if sync.get("return") != token:
            return None, f"sync token mismatch: {sync!r}"

        payload = {"execute": command}
        if arguments is not None:
            payload["arguments"] = arguments
        s.sendall((json.dumps(payload) + "\n").encode())
        while b"\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                return None, "agent closed the connection without replying"
            buf += chunk
        return json.loads(buf.split(b"\n", 1)[0]), None
    except socket.timeout:
        return None, f"no reply within {timeout}s"
    except OSError as exc:
        return None, f"{type(exc).__name__}: {exc}"
    finally:
        s.close()


# --- the measurement ---

def offset_once():
    """(low, high) bounds on guest_clock - true_time, in seconds.

    The guest's clock is read somewhere inside [t0, t1], so the offset is
    bracketed rather than known. Reporting an interval instead of a number is
    what keeps `workloadctl exec`'s latency out of the answer -- and the
    interval's WIDTH is that latency, which is why it is printed.
    """
    t0 = time.time()
    r = guest("date +%s.%N", timeout=60)
    t1 = time.time()
    if r.returncode != 0:
        return None
    try:
        g = float(r.stdout.strip())
    except ValueError:
        return None
    return (g - t1, g - t0)


def offset(label, samples=3):
    got = []
    for _ in range(samples):
        o = offset_once()
        if o is not None:
            got.append(o)
    if not got:
        return None
    for lo, hi in got:
        say(f"    {label}: offset in [{lo:+.3f}, {hi:+.3f}]  (width {hi - lo:.3f})")
    # The UPPER bound is the stable one -- the lower tracks the round-trip --
    # so the true offset sits near max(hi). Same reading the §6 measurement made.
    return max(hi for _, hi in got)


def _status():
    """The inspector's whole status document, or None if it cannot be read.

    Never raises. The counters are corroboration for measurement 6, not its
    verdict -- a rig that died reading a diagnostic would lose the measurement
    the diagnostic was describing.
    """
    try:
        raw = (SOCKET_DIR / NAME / STATUS_FILE).read_text()
        return json.loads(raw)
    except (OSError, ValueError):
        return None


def mint_counts():
    """The `mint` block, with the tick it was written at."""
    doc = _status()
    if doc is None:
        return None
    counts = dict(doc.get("mint") or {})
    counts["_written_at"] = doc.get("written_at")
    return counts


def mint_counts_after(before):
    """The `mint` block from a tick STRICTLY LATER than `before`'s.

    The status file is rewritten on a timer, not on an event. Reading it
    straight after the request under test returns the tick that was already
    there, so both snapshots come from ONE write and every counter difference is
    zero -- which reads exactly like a counter that does not work. Measured
    2026-08-26: this is what failed the last assertion of an otherwise green
    run, and the remedy it seemed to indict was working perfectly.
    """
    if before is None:
        return None
    deadline = time.time() + 90
    while time.time() < deadline:
        now = mint_counts()
        if now is not None and now.get("_written_at") != before.get("_written_at"):
            return now
        time.sleep(2)
    return None


def toml_for():
    return "\n".join([
        f"# {NAME} — generated by clock_rig.py. Throwaway; safe to purge.",
        "[workload]",
        f'name = "{NAME}"',
        "enabled = false",
        "",
        "[vm]",
        f'local_image = "{BASE_IMAGE}"',
        "vcpus = 1",
        'memory = "768M"',
        'user = "workload"',
        "rollback_keep = 1",
        "",
        "[vm.network]",
        # Filtered on purpose: an open guest resyncs over NTP and measures
        # nothing. See the module docstring.
        'egress = "filtered"',
        # `hosts` is what turns the INSPECTOR on, and the inspector is what
        # mints. Without it measurement 6 has no mint path to drive and the rig
        # measures the clock without ever measuring what the clock breaks.
        f'hosts = {json.dumps(REACHABLE_HOSTS)}',
        "",
        "[[vm.network.allow]]",
        f'address = "{DNS_ALLOW}"',
        'reason  = "the rig\'s guest needs a resolver to reach at all"',
    ]) + "\n"


def preflight():
    if not Path("/dev/kvm").exists():
        sys.exit("no /dev/kvm — this rig needs a KVM host")
    if not BASE_IMAGE.exists():
        sys.exit(f"no base image at {BASE_IMAGE}")
    if not shutil.which("workloadctl"):
        sys.exit("workloadctl is not on PATH — install the RPM")


def deploy():
    say("== deploying one guest ==")
    d = Path("/etc/workloads.d") / NAME
    d.mkdir(parents=True, exist_ok=True)
    (d / "workload.toml").write_text(toml_for())
    p = run(["workloadctl", "enable", NAME], check=False, timeout=900)
    if p.returncode != 0:
        say(p.stdout[-3000:])
        say(p.stderr[-3000:])
        sys.exit("enable failed")
    say("  waiting for the guest to answer ssh (first boot: cloud-init) ...")
    deadline = time.time() + 600
    while time.time() < deadline:
        r = guest("echo UP", timeout=60)
        if r.returncode == 0 and "UP" in r.stdout:
            say("  up")
            return
        time.sleep(10)
    subprocess.run(["journalctl", "-u", f"workload-{NAME}.service",
                    "-n", "40", "--no-pager"])
    sys.exit("guest never became reachable")


def teardown():
    say("== teardown ==")
    subprocess.run(["workloadctl", "disable", NAME, "--purge"],
                   capture_output=True, text=True, timeout=300)
    shutil.rmtree(Path("/etc/workloads.d") / NAME, ignore_errors=True)
    say(f"  purged {NAME}")


def measure():
    # 1. NTP is dead. Recorded rather than assumed: it is the premise the whole
    #    question rests on, and it is invisible from the host because chronyd
    #    stays `active` while never synchronising.
    say("== 1. is NTP actually dead in there ==")
    r = guest("chronyc tracking 2>&1 | head -4 || echo 'no chronyc'")
    say("    " + r.stdout.strip().replace("\n", "\n    "))
    dead = ("Reach" not in r.stdout) or ("1970" in r.stdout) or \
           ("Stratum" in r.stdout and "Stratum         : 0" in r.stdout)
    record("ntp is dead in a filtered guest", dead, r.stdout.strip().split("\n")[0]
           if r.stdout.strip() else "no output")

    # 2. Baseline.
    say("== 2. baseline offset ==")
    base = offset("baseline")
    if base is None:
        record("baseline offset readable", False, "no reading")
        return
    record("baseline offset readable", True, f"{base:+.3f}s")

    # 3. The pause. This is the operation `backup --consistency crash`
    #    performs, against the same socket, in the same order.
    say(f"== 3. stopping vCPUs for {PAUSE_SECONDS}s (this is what backup does) ==")
    t_stop = time.time()
    qmp(["stop"])
    time.sleep(PAUSE_SECONDS)
    qmp(["cont"])
    paused = time.time() - t_stop
    say(f"    paused {paused:.3f}s wall")
    time.sleep(5)                      # let the guest's shell settle
    after = offset("after resume")
    if after is None:
        record("guest survives the pause", False, "unreachable after cont")
        return
    step = base - after
    record("guest survives the pause", True, f"offset {after:+.3f}s")
    # The claim is the STEP equals the PAUSE. 2 s of slack covers the two
    # bracketed reads and the settle.
    record("the clock step equals the pause", abs(step - paused) < 2.0,
           f"step {step:.3f}s vs pause {paused:.3f}s (delta {step - paused:+.3f}s)")
    record("nothing puts it back on its own", abs(step) > 1.0,
           f"still {after:+.3f}s behind after resume")

    # 4. The unknown: does the no-argument form return? Recorded either way --
    #    §16 says it was issued once and did not return, and one observation is
    #    not a result.
    say("== 4. guest-set-time, NO ARGUMENT (reads the host RTC) ==")
    ping, err = ga("guest-sync", {"id": 1})
    if err:
        record("the guest agent answers at all", False, err)
        say("    -> no agent: measurements 4 and 5 cannot run. Is "
            "qemu-guest-agent installed in the base image?")
        return
    record("the guest agent answers at all", True, "guest-sync returned")

    # MEASURED 2026-08-26, twice on one host: the no-argument form FAILS, with
    # `child process has failed to set hardware clock to system time: hwclock:
    # select() to /dev/rtc0 to wait for clock tick timed out`. That is now the
    # expectation rather than an open question, and it is why the remedy uses
    # the explicit form -- so this is recorded as an OBSERVATION, not asserted
    # either way. Asserting the failure would make a fixed guest agent look like
    # a regression; asserting the success would fail every run on a host where
    # the documented behaviour holds. What DOES get asserted is measurement 5:
    # the form the code actually uses.
    reply, err = ga("guest-set-time")
    if err:
        say(f"  [obs] guest-set-time (no argument): {err}")
    elif "error" in reply:
        say(f"  [obs] guest-set-time (no argument) errored, as expected since "
            f"2026-08-26: {reply['error'].get('desc', reply['error'])}")
    else:
        say(f"  [obs] guest-set-time (no argument) RETURNED: {reply!r} -- this "
            f"host disagrees with the 2026-08-26 measurement; the explicit form "
            f"below is still what the code uses")
        noarg = offset("after no-arg set-time")
        if noarg is not None:
            say(f"  [obs] the no-argument form left the guest {noarg:+.3f}s out")

    # 5. The untested one. This is the form a remedy would actually use, since
    #    it does not depend on the guest's RTC being right.
    say("== 5. guest-set-time, EXPLICIT nanoseconds ==")
    now_ns = int(time.time() * 1_000_000_000)
    reply, err = ga("guest-set-time", {"time": now_ns})
    if err:
        record("guest-set-time (explicit ns) returns", False, err)
        return
    if "error" in reply:
        record("guest-set-time (explicit ns) returns", False,
               f"error: {reply['error'].get('desc', reply['error'])}")
        return
    record("guest-set-time (explicit ns) returns", True, repr(reply))
    time.sleep(2)
    fixed = offset("after explicit set-time")
    if fixed is None:
        record("the explicit form re-anchors the guest", False, "no reading")
        return
    record("the explicit form re-anchors the guest", abs(fixed) < 2.0,
           f"offset {fixed:+.3f}s (was {after:+.3f}s)")

    # 6. THE ONE THAT CLOSES THE LOOP. Everything above measures a clock; this
    #    measures what the clock was on the critical path OF. Rung 3 T5 wired
    #    the mint-time check in, so a guest whose clock is behind is repaired
    #    ON A CACHE MISS, before the leaf it is about to be handed is signed.
    #
    #    The skew is SET rather than paused for, and it has to exceed the
    #    1-hour notBefore backdate or the assertion cannot fail for the right
    #    reason: inside the backdate a stale guest validates a fresh leaf
    #    anyway. Two hours, using the explicit-nanoseconds form measurement 5
    #    just proved works.
    #
    #    And it dials a name this guest has NEVER dialled. A cache hit does not
    #    run the clock check -- re-dialling the first name would pass while
    #    proving nothing.
    say(f"== 6. a guest {SKEW_SECONDS}s behind still gets a usable leaf ==")
    first, second = REACHABLE_HOSTS[0], REACHABLE_HOSTS[1]

    warm = guest(f"curl -sS -o /dev/null -w '%{{http_code}}' "
                 f"--max-time 40 https://{first}/", timeout=90)
    record("https works through the inspector before any skew",
           warm.returncode == 0 and warm.stdout.strip().startswith(("2", "3")),
           f"rc={warm.returncode} {warm.stdout.strip()!r} "
           f"{warm.stderr.strip()[:120]!r}")

    before_counts = mint_counts()
    reply, err = ga("guest-set-time",
                    {"time": int((time.time() - SKEW_SECONDS) * 1_000_000_000)})
    if err or "error" in reply:
        record("the guest can be pushed back past the backdate", False,
               err or str(reply.get("error")))
        return
    time.sleep(2)
    skewed = offset("after being pushed back")
    if skewed is None:
        record("the guest can be pushed back past the backdate", False,
               "no reading")
        return
    record("the guest can be pushed back past the backdate",
           skewed < -(SKEW_SECONDS / 2),
           f"offset {skewed:+.1f}s, backdate is -3600s")

    r = guest(f"curl -sS -o /dev/null -w '%{{http_code}}' "
              f"--max-time 60 https://{second}/", timeout=120)
    ok = r.returncode == 0 and r.stdout.strip().startswith(("2", "3"))
    record("a skewed guest still validates a freshly minted leaf", ok,
           f"rc={r.returncode} {r.stdout.strip()!r} "
           f"{r.stderr.strip()[:160]!r}")

    # WHY the request worked, not just that it did. Without this the same pass
    # is produced by a backdate quietly widened to cover two hours, which is
    # the change this measurement most needs to catch.
    healed = offset("after the mint-time check")
    if healed is not None:
        record("the mint path is what put the clock back",
               abs(healed) < 60.0,
               f"offset {healed:+.1f}s (was {skewed:+.1f}s)")

    # A LATER tick, not the current file -- see mint_counts_after.
    say("  waiting for a status tick ...")
    after_counts = mint_counts_after(before_counts)
    if before_counts is None or after_counts is None:
        record("the resync is counted where diagnose can see it", False,
               "no readable inspect-status.json"
               if before_counts is None else
               "no status tick arrived within 90s of the request")
    else:
        moved = (after_counts.get("clock_resyncs", 0)
                 - before_counts.get("clock_resyncs", 0))
        record("the resync is counted where diagnose can see it", moved >= 1,
               f"clock_resyncs +{moved}, "
               f"mints +{after_counts.get('mints', 0) - before_counts.get('mints', 0)}")
        # The figure that says the remedy is present at all. A guest with no
        # agent counts here instead, and every other line on this rig still
        # passes -- which is exactly the state T8 added it to make visible.
        record("this guest's clock remedy is not inert",
               after_counts.get("clock_unavailable", 0) == 0,
               f"clock_unavailable={after_counts.get('clock_unavailable')}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--keep", action="store_true",
                    help="leave the guest running for poking at")
    ap.add_argument("--no-deploy", action="store_true",
                    help="assume the guest is already up")
    args = ap.parse_args()

    preflight()
    try:
        if not args.no_deploy:
            deploy()
        measure()
    finally:
        if not args.keep:
            teardown()

    say("")
    failed = [r for r in RESULTS if not r[1]]
    say(f"== {len(RESULTS) - len(failed)}/{len(RESULTS)} assertions passed ==")
    for label, ok, detail in RESULTS:
        say(f"  {'ok  ' if ok else 'FAIL'} {label}: {detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
