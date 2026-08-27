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

TWO REMEDIES, AND THE RIG MEASURES BOTH

The guest-side one is `ptp_kvm`: the seed points chrony at a paravirtual clock
that reads the host's over a KVM hypercall, so it needs no network (which is
what makes it usable at all here) and nothing CONFIGURED on the host.
Measurement 3 proves it repairs the very pause measurement 4 shows is otherwise
permanent -- on a host that can offer it at all. It needs the host's own
clocksource to be the TSC, since that is the only case in which KVM answers the
clock-pairing hypercall; on a host running hpet or acpi_pm the module refuses to
load in every guest and measurement 3 skips, saying so.

The host-side one is the mint-path check, and it exists because the guest-side
one is not guaranteed to be there: a custom [vm.cloud_init].user_data_file
replaces the built-in seed outright, so a guest seeded from one carries no
ptp_kvm wiring unless its author copied it. Measurements 4 to 7 are about THAT
guest, which the rig becomes by stopping chronyd after measurement 3 rather
than by contriving a second workload.

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
explicit-nanoseconds form is untested. Those two are measurements 5 and 6
below, and they are the whole reason this rig is not just a re-run of the
pause.

Measurement 7 is the one that closes the loop, and it arrived after T5 wired the
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
# 7 dials. Two names, because that measurement needs a name it has NEVER minted
# for -- a cache HIT does not run the clock check, so re-dialling the first one
# would prove nothing and look like a pass.
REACHABLE_HOSTS = ["example.com", "example.org"]

# How far back measurement 7 pushes the guest's clock. Past the leaf's 1-hour
# notBefore backdate, which is the whole point: inside the backdate a stale
# clock validates anyway and the assertion cannot fail for the right reason.
# Two hours, set with the explicit-nanoseconds guest-set-time measurement 6
# proves works -- a rig that reached this by PAUSING for two hours is a rig
# nobody runs.
SKEW_SECONDS = 7200
# ptp_kvm's guest-side init issues KVM_HC_CLOCK_PAIRING, and KVM answers
# EOPNOTSUPP unless the HOST's clocksource is the TSC. So this file decides
# whether measurement 3 can run at all, on a host the rig does not control.
HOST_CLOCKSOURCE = Path(
    "/sys/devices/system/clocksource/clocksource0/current_clocksource")
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


# CHRONYC CANNOT WRITE TO AN SSH EXEC CHANNEL, AND SELINUX IS WHY. Measured
# 2026-08-27 in the guest, with the audit log naming it:
#
#   avc: denied { write } for comm="chronyc" path="pipe:[12398]" dev="pipefs"
#     scontext=unconfined_u:unconfined_r:chronyc_t:s0-s0:c0.c1023
#     tcontext=system_u:system_r:sshd_session_t:s0-s0:c0.c1023 tclass=fifo_file
#
# /usr/bin/chronyc is chronyc_exec_t, so it transitions to chronyc_t, which
# stock Fedora policy does not let read or write sshd_session_t's pipes -- the
# stdin/stdout/stderr of a non-tty `ssh <host> <command>`. `setenforce 0` makes
# the whole table appear and `setenforce 1` silences it again, which is the
# control that settles it. It is the GUEST's policy, not ours, and not the
# transport: writes of the same size from any other program cross the same
# channel intact.
#
# The workaround is one `| cat`, and the shape is the explanation: chronyc may
# write to a pipe bash created, and unconfined cat may write to sshd's. A file
# works for the same reason. Redirections do NOT -- `1>&2`, `exec 3>&1`, a
# subshell, setsid and stdbuf all still have chronyc touching sshd's pipe.
#
# WHY THIS MATTERS MORE THAN THE WORKAROUND: a rig that reads chronyc directly
# does not fail, it reads EMPTY -- which parses as "no sources", "no refclock",
# and any other absence the caller happens to be looking for. Both readings
# below were making claims about output that never arrived (2026-08-27): the
# refclock assertion failed on a guest whose refclock was live and selected,
# and the NTP-path assertion passed by counting zero of the two server sources
# the guest actually had.

def chronyc(argv):
    """Read chronyc through a pipe, because reading it directly reads nothing."""
    return guest(f"command -v chronyc >/dev/null && chronyc {argv} 2>&1 | cat; "
                 f"echo __END__")


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

    Never raises. The counters are corroboration for measurement 7, not its
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
        # mints. Without it measurement 7 has no mint path to drive and the rig
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
    # 1. The NETWORK time path is dead. It is the premise the whole question
    #    rests on, and it is invisible from the host because chronyd stays
    #    `active` while no server it is configured with is reachable.
    #
    #    This used to read `chronyc tracking` and look for an unsynchronised
    #    clock. It cannot any more, and the reason is the point of measurement
    #    3: every seed now gives the guest a PHC refclock, so a healthy filtered
    #    guest IS synchronised -- from the host, over a hypercall, with no
    #    packets. The claim being made here was always about the servers, so it
    #    is now made against the servers: every `^` line is an NTP source and
    #    every one of them must be unreachable.
    say("== 1. is the NTP *network* path actually dead in there ==")
    # ZERO SOURCES IS THE ANSWER, NOT A BROKEN READING. In a filtered guest the
    # `pool` line never resolves, so chrony ends up with no sources at all --
    # and chronyc then prints NOTHING, not even the column headers. An earlier
    # version of this measurement required at least one `^` line before it would
    # believe the reading, and failed every run for it (2026-08-26), indicting a
    # filter that was doing exactly its job. No server source at all is the
    # strongest form of the claim, so it passes.
    #
    # The sentinel is what keeps that from being a free pass: it proves chronyc
    # ran and said nothing, rather than chronyc being absent.
    r = chronyc("-n sources")
    say("    " + (r.stdout.strip().replace("\n", "\n    ") or "(no output)"))
    ran = "__END__" in r.stdout
    servers = [ln.split() for ln in r.stdout.splitlines() if ln.startswith("^")]
    reachable = [ln for ln in servers if len(ln) > 4 and ln[4] != "0"]
    record("no ntp server is reachable from a filtered guest",
           ran and not reachable,
           f"{len(servers)} server source(s), {len(reachable)} reachable"
           if ran else "chronyc did not run; the reading proves nothing")

    # 2. Baseline.
    say("== 2. baseline offset ==")
    base = offset("baseline")
    if base is None:
        record("baseline offset readable", False, "no reading")
        return
    record("baseline offset readable", True, f"{base:+.3f}s")

    # 3. THE GUEST-SIDE REMEDY, which is the half that needs no agent and no
    #    host involvement. The seed loads ptp_kvm, names the device by the
    #    driver's clock_name, points chrony at it and sets `makestep 1 -1`; the
    #    guest then reads the host's clock over a KVM hypercall. Nothing is
    #    configured on the host for this -- if it works, it works because
    #    `-machine accel=kvm -cpu host` already implies it.
    #
    #    The assertion is the whole reason it was added: the SAME pause that
    #    measurement 4 shows is permanent must, here, repair itself.
    say("== 3. the guest's own paravirtual clock ==")
    # THE HOST GATE, and it is not a formality. ptp_kvm's guest-side init issues
    # KVM_HC_CLOCK_PAIRING, and KVM answers EOPNOTSUPP unless the HOST's own
    # clocksource is the TSC -- so on a host running hpet or acpi_pm the module
    # refuses to load in every guest, with `modprobe: ERROR: could not insert
    # 'ptp_kvm': Operation not supported` and nothing else to go on. Measured
    # 2026-08-26 on a development host whose available_clocksource is
    # `hpet acpi_pm` with no tsc at all: every piece of the seed was correct and
    # the device still never appeared.
    #
    # So this is a SKIP, not a failure: the seed's chrony edit is guarded on the
    # device existing precisely so such a host keeps its stock time
    # configuration, and measurements 4 to 7 are exactly the guest this host
    # produces anyway.
    host_clocksource = HOST_CLOCKSOURCE.read_text().strip() \
        if HOST_CLOCKSOURCE.exists() else "unknown"
    ptp_possible = host_clocksource == "tsc"
    say(f"    host clocksource: {host_clocksource}")

    r = guest("test -e /dev/ptp_kvm && echo present || echo missing")
    present = r.stdout.strip() == "present"
    if ptp_possible:
        record("the guest has /dev/ptp_kvm", present, r.stdout.strip())
    else:
        say(f"  [obs] /dev/ptp_kvm is {r.stdout.strip()}, and cannot be "
            f"otherwise: this host's clocksource is {host_clocksource!r}, not "
            f"'tsc', so KVM refuses the clock-pairing hypercall")

    # Whether the guest was left ALONE is assertable on any host, and it is the
    # half that would hurt: chronyd treats a refclock it cannot open as fatal,
    # so a seed that appended unconditionally would leave this guest -- the
    # common case on such a host -- with no time service at all.
    r = guest("grep -c '^makestep 1 -1' /etc/chrony.conf 2>&1 || echo 0")
    steps = r.stdout.strip().splitlines()[0]
    if ptp_possible:
        # `makestep 1 -1` is the load-bearing line, not the refclock: Fedora
        # ships `makestep 1.0 3`, which steps three times and then slews at
        # ~83 us/s forever -- months to walk off a two-hour jump. A guest with
        # the refclock and the stock makestep looks configured and repairs
        # nothing.
        record("chrony may step at any time, not just at startup",
               steps == "1", f"makestep 1 -1 lines: {steps}")
        # Selection is not instant, and sampling it once turns a healthy guest
        # into a red run: chronyd logs `Selected source PHC0` about 12 s after
        # it starts, and until then the refclock reads `#?` -- present, polling,
        # not yet trusted. Poll for the selection rather than race it.
        deadline, refclocks, selected = time.time() + 90, [], []
        while time.time() < deadline:
            r = chronyc("-n sources")
            refclocks = [ln for ln in r.stdout.splitlines()
                         if ln.startswith("#")]
            selected = [ln for ln in refclocks if ln[:2] in ("#*", "#+")]
            if selected:
                break
            time.sleep(5)
        record("chrony is using it as a refclock", bool(selected),
               (selected or refclocks or ["no refclock line at all"])[0].strip())
    else:
        record("a host without ptp_kvm leaves the guest's chrony untouched",
               steps == "0" and not present,
               f"makestep 1 -1 lines: {steps}, device {'present' if present else 'absent'}")
        record("and its chronyd is still running",
               guest("systemctl is-active chronyd").stdout.strip() == "active",
               "chronyd active")
        say("  -- skipping 3b (self-repair): this host cannot offer the clock. "
            "Measurements 4 to 7, the host-side remedy, run as normal.")

    if ptp_possible:
        say(f"== 3b. the same pause, with the guest-side remedy ON ==")
        t_stop = time.time()
        qmp(["stop"])
        time.sleep(PAUSE_SECONDS)
        qmp(["cont"])
        paused = time.time() - t_stop
        say(f"    paused {paused:.3f}s wall")
        # chrony polls the refclock every 4 s; give it a wide margin and report the
        # time it actually took, since that number is the operator-facing one.
        deadline, healed_at, healed_off = time.time() + 180, None, None
        while time.time() < deadline:
            o = offset_once()
            if o is not None and abs(o[1]) < 5.0:
                healed_at, healed_off = time.time() - t_stop - paused, o[1]
                break
            time.sleep(4)
        record("the guest repairs the pause by itself", healed_at is not None,
               f"back to {healed_off:+.3f}s after {healed_at:.0f}s"
               if healed_at is not None else
               f"still out after 180s (last {o[1]:+.1f}s)" if o else "unreachable")

        # EVERYTHING BELOW MEASURES A GUEST WITHOUT THAT REMEDY, and that is a
        # configuration we support rather than a contrivance: a custom
        # [vm.cloud_init].user_data_file replaces the built-in seed outright, so a
        # guest seeded from one carries no ptp_kvm wiring unless its author copied
        # it. The host-side check is what covers those, and it is what measurements
        # 4 to 7 are about. Stopping chronyd is the smallest way to become one.
        say("== 3c. disabling the guest-side remedy for the rest of the rig ==")
        # sudo: `workloadctl exec` logs in as the guest user, not root. The
        # seed gives that account NOPASSWD sudo; without it this reads
        # "Access denied" and the rig proceeds against a guest it believes it
        # disabled -- measured 2026-08-26.
        r = guest("sudo systemctl stop chronyd 2>&1; "
                  "systemctl is-active chronyd 2>&1 || true")
        record("the guest-side remedy can be turned off",
               "inactive" in r.stdout or "failed" in r.stdout, r.stdout.strip())
        base = offset("baseline (guest-side remedy off)")
        if base is None:
            record("baseline offset readable (remedy off)", False, "no reading")
            return

    else:
        # Nothing to disable: this host never gave the guest a refclock, so it
        # already IS the guest measurements 4 to 7 are about. `base` from
        # measurement 2 still stands.
        say("== 3c. skipped: there was no guest-side remedy to disable ==")

    # 4. The pause. This is the operation `backup --consistency crash`
    #    performs, against the same socket, in the same order.
    say(f"== 4. stopping vCPUs for {PAUSE_SECONDS}s (this is what backup does) ==")
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

    # 5. The unknown: does the no-argument form return? Recorded either way --
    #    §16 says it was issued once and did not return, and one observation is
    #    not a result.
    say("== 5. guest-set-time, NO ARGUMENT (reads the host RTC) ==")
    ping, err = ga("guest-sync", {"id": 1})
    if err:
        record("the guest agent answers at all", False, err)
        say("    -> no agent: measurements 5 and 6 cannot run. Is "
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
    # the documented behaviour holds. What DOES get asserted is measurement 6:
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

    # 6. The untested one. This is the form a remedy would actually use, since
    #    it does not depend on the guest's RTC being right.
    say("== 6. guest-set-time, EXPLICIT nanoseconds ==")
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

    # 7. THE ONE THAT CLOSES THE LOOP. Everything above measures a clock; this
    #    measures what the clock was on the critical path OF. Rung 3 T5 wired
    #    the mint-time check in, so a guest whose clock is behind is repaired
    #    ON A CACHE MISS, before the leaf it is about to be handed is signed.
    #
    #    The skew is SET rather than paused for, and it has to exceed the
    #    1-hour notBefore backdate or the assertion cannot fail for the right
    #    reason: inside the backdate a stale guest validates a fresh leaf
    #    anyway. Two hours, using the explicit-nanoseconds form measurement 6
    #    just proved works.
    #
    #    And it dials a name this guest has NEVER dialled. A cache hit does not
    #    run the clock check -- re-dialling the first name would pass while
    #    proving nothing.
    say(f"== 7. a guest {SKEW_SECONDS}s behind still gets a usable leaf ==")
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
