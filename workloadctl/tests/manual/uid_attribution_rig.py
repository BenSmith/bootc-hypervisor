#!/usr/bin/python3
"""Which uid does a container's egress actually leave as, per network mode?

Answers P0-1 from the container egress-parity build spec, and then guards the
answer. Every egress rule in workload-filter.nft selects on ONE uid -- the
workload's -- so the whole design rests on a container's packets carrying that
uid. This measures whether they do, across the axis that turns out to decide
it: the in-container uid, set by `[container] user`.

WHAT IT FOUND (2026-09-05, on a KVM host under enforcing)

    pasta:  image default -> uid   user="0" -> uid   user="1000" -> uid
    host:   image default -> uid   user="0" -> SUB   user="1000" -> SUB

Under the default `[security] userns = "keep-id"` exactly one in-container uid
maps to the workload uid; every other one maps into the workload's 65536-wide
subuid window. Pasta hides this completely -- it re-originates the container's
traffic as a host socket it owns, so all three arms carry the workload uid. In
host mode there is no such indirection, the container's sockets ARE host
sockets, and two arms of three leave as subuids that no shipped rule matches.
Hence the refusal in validate_container_network(): host mode plus any egress
key would filter whichever containers happened to run as the keep-id uid.

The host's own traffic was never captured, on any arm -- root and an ordinary
user both matched nothing, even with the namespace shared.

WHY COUNTERS AND NOT AN END-TO-END DIAL. Nothing is armed for a host-mode
workload, so there is nothing to dial through. Three competing counters on one
packet at the output hook measure the primitive itself, and cannot be confounded
by whether an inspector is up, whether a route exists, or whether anything
listens. The destination is unroutable on purpose (TEST-NET-3): every probe is
one SYN and the only thing that varies is which rule claimed it.

FOUR WAYS THIS RIG LIED BEFORE IT TOLD THE TRUTH, all of which read as product
defects first. They are why the code below looks paranoid:

  1. `nft reset counters table` resets NAMED counters only, not the anonymous
     per-rule ones here. Every row inherited the previous row's count, and one
     probe that sent NO PACKET was dressed up as a match. Fixed by deltas.
  2. busybox `su` is not GNU `su` and silently refused to drop privileges, so
     the "non-root" probe would have measured root and read as a clean
     falsification of the hypothesis it existed to test. It now proves the uid
     changed before its verdict counts.
  3. keep-id injects the HOST username into the container's /etc/passwd, so
     `id` inside prints `uid=10002(_wl-<name>)` -- which looks exactly like an
     exec that escaped to the host. It had not; that IS the container.
  4. An unroutable destination leaves every probe retransmitting on a doubling
     backoff, and under pasta those retransmits are re-originated by a
     long-lived host process owned by the workload uid -- landing in the NEXT
     probe's window and attributing the host's own curl to the workload. A
     settle-and-hope window fits inside the backoff gap; per-probe ports do
     not. See next_port().

Needs root and the workloadctl RPM. Writes nothing outside
/etc/workloads.d/<arm>, a scratch nft table, and the throwaway workloads' own
state; purges all of it in a finally.

    sudo python3 tests/manual/uid_attribution_rig.py          # host mode
    sudo python3 tests/manual/uid_attribution_rig.py pasta    # the shipped path
"""

import subprocess
import sys
import time
from pathlib import Path
from typing import NamedTuple

# Set from argv in main(), NOT at import: tests/test_manual_rig_configs.py
# imports this module to validate what toml_for() generates, and reading
# sys.argv at module level would make it parse unittest's arguments (the same
# trap that keeps stub_upstream.py off that gate's discovery list). "host" is
# the default because that is the mode this rig exists to answer for.
NETMODE = "host"


class Arm(NamedTuple):
    """One throwaway workload. `user` is the `[container] user` it runs as --
    None means the image's default, which under keep-id is the mapped uid."""
    name: str
    user: str | None = None


# Named ARMS with a `.name`, per tests/test_manual_rig_configs.py, which calls
# toml_for(arm) once per arm. A rig whose shape does not match that gate is
# skipped by it without comment.
ARMS = [Arm("hmspk"), Arm("hmspk0", "0"), Arm("hmspk1k", "1000")]

# What each arm is expected to measure, per network mode -- established on
# hardware 2026-09-05 and asserted rather than printed. `keep-id` maps exactly
# one in-container uid to the workload uid; pasta re-originates every
# container's traffic as a host socket it owns, which erases the distinction,
# while host mode has no such indirection and exposes it.
EXPECTED = {
    "host":   {"hmspk": "exact-uid", "hmspk0": "subrange",
               "hmspk1k": "subrange"},
    "pasta":  {"hmspk": "exact-uid", "hmspk0": "exact-uid",
               "hmspk1k": "exact-uid"},
    # Bridge gives each container its own netns and re-originates the same way
    # pasta does; expected identical, never measured. Run it before believing
    # this row.
    "bridge": {"hmspk": "exact-uid", "hmspk0": "exact-uid",
               "hmspk1k": "exact-uid"},
}

IMAGE = "docker.io/library/alpine:latest"
WORKLOAD_DIR = Path("/etc/workloads.d")
SCRATCH = "hmspike"
# TEST-NET-3. Unroutable on purpose: the SYN is counted at the output hook and
# then goes nowhere, so no listener, no route and no timeout tuning matter.
PROBE_IP = "192.0.2.99"
PROBE_PORT = 8000        # bumped per probe by next_port()
ARMED = (None, None)     # (uid, subuid range) of the workload under test

SUBID_BASE = None   # read from /etc/subuid for this workload
UID_MIN = 10000

ok = True


def say(m):
    print(m, flush=True)


def run(argv, check=False, timeout=120):
    return subprocess.run(argv, capture_output=True, text=True,
                          check=check, timeout=timeout)


def inside(name, script, timeout=60):
    return run(["workloadctl", "exec", name, "--", "sh", "-c", script],
               timeout=timeout)


def uid_of(name):
    p = run(["getent", "passwd", f"_wl-{name}"])
    return int(p.stdout.split(":")[2]) if p.returncode == 0 else None


def subid_range(name, uid):
    """This workload's subuid window, as allocated in /etc/subuid."""
    for line in Path("/etc/subuid").read_text().splitlines():
        parts = line.split(":")
        if len(parts) == 3 and parts[0] in (f"_wl-{name}", str(uid)):
            start, count = int(parts[1]), int(parts[2])
            return start, start + count - 1
    return None


def ifnames(text):
    return {l.split(":")[1].strip() for l in text.splitlines() if ":" in l}


def toml_for(arm):
    """A host-mode workload, optionally pinned to an in-container uid.

    `[container] user` is how a real bundle selects the uid its process runs
    as, and it is the axis that matters here: under the default
    `userns = "keep-id"` exactly ONE in-container uid maps to the workload uid
    on the host. Every other one -- including in-container root -- maps into
    the workload's subuid window. So the interesting probes are not
    root-vs-nonroot, they are keep-id-uid vs anything else.
    """
    name, user = arm.name, arm.user
    body = f"""# {name} -- generated by uid_attribution_rig.py. Throwaway.
[workload]
name = "{name}"
enabled = false

[container]
image = "{IMAGE}"
command = ["sleep", "infinity"]
"""
    if user is not None:
        body += f'user = "{user}"\n'
    body += f"""
[network]
mode = "{NETMODE}"
"""
    return body


def scratch_up(uid, sub, port):
    """Three competing counters on the same packet, most specific first.

    `any` is the control: if it counts and neither selector does, the packet
    left this host attributed to nothing we can name, which is the failure.
    Rebuilt per probe against a fresh `port` -- see next_port().
    """
    lo, hi = sub
    rules = f"""
table inet {SCRATCH} {{
    chain out {{
        type filter hook output priority -100; policy accept;
        ip daddr {PROBE_IP} tcp dport {port} meta skuid {uid} counter comment "exact-uid"
        ip daddr {PROBE_IP} tcp dport {port} meta skuid {lo}-{hi} counter comment "subrange"
        ip daddr {PROBE_IP} tcp dport {port} counter comment "any"
    }}
}}
"""
    run(["nft", "delete", "table", "inet", SCRATCH])
    p = subprocess.run(["nft", "-f", "-"], input=rules,
                       capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"scratch table failed: {p.stderr}")


def counters():
    """(exact, subrange, any) packet counts."""
    p = run(["nft", "list", "table", "inet", SCRATCH])
    out = {}
    for line in p.stdout.splitlines():
        for label in ("exact-uid", "subrange", "any"):
            if f'comment "{label}"' in line:
                # ... counter packets N bytes M ...
                toks = line.split()
                out[label] = int(toks[toks.index("packets") + 1])
    return out.get("exact-uid", -1), out.get("subrange", -1), out.get("any", -1)


def next_port():
    """A destination port no earlier probe has used.

    WAITING FOR QUIET DOES NOT WORK HERE. An unroutable destination leaves
    every probe's socket retransmitting its SYN on a doubling backoff (1s, 2s,
    4s, 8s...), and under pasta those retransmits are re-originated by a
    long-lived host process owned by the workload uid. A settle window short
    enough to be practical fits *inside* a backoff gap, so the counters read
    still and then the next row inherits a retransmit -- which is exactly how
    the host's own curl got attributed to the workload. Giving each probe its
    own port makes the previous probe's tail unmatchable by construction
    instead of merely unlikely.
    """
    global PROBE_PORT
    PROBE_PORT += 1
    return PROBE_PORT


def probe_in(name, label):
    """Dial from inside a container. No expectation -- WHICH selector matched
    is the finding, so this reports rather than judges."""
    return _probe(label, lambda port: inside(
        name, f"wget -T 3 -q -O- http://{PROBE_IP}:{port}/ 2>/dev/null || true",
        timeout=40), expect=None)


def probe_host(label, as_uid=None):
    """Dial from the host. Here there IS a required answer: the host's own
    sockets must match neither workload selector."""
    def fire(port):
        argv = ["curl", "-s", "-m", "3", "-o", "/dev/null",
                f"http://{PROBE_IP}:{port}/"]
        if as_uid:
            argv = ["runuser", "-u", as_uid, "--", *argv]
        return subprocess.run(argv, capture_output=True, text=True, timeout=40)
    return _probe(label, fire, expect="unattributed")


def _probe(label, fire, *, expect):
    """One SYN, then read which selector claimed it.

    DELTAS, NOT RESETS. `nft reset counters table` resets NAMED counters only;
    the anonymous per-rule counters used here are untouched by it. An earlier
    run of this rig reset nothing, so every row inherited the first probe's
    `exact` count and three of four rows were misread -- including one where
    the probe had in fact sent no packet at all, which the stale count dressed
    up as a match. Take the difference around each probe and nothing is
    inherited.
    """
    # A fresh port AND a freshly built table: the counters start at zero and
    # no earlier probe's retransmits can match this port. See next_port().
    port = next_port()
    scratch_up(ARMED[0], ARMED[1], port)
    before = counters()
    p = fire(port)
    after = counters()
    exact, sub, any_ = (a - b for a, b in zip(after, before))
    got = ("exact-uid" if exact else "subrange" if sub else
           "unattributed" if any_ else "no packet")
    if got == "no packet":
        # The probe never left the box. That is a rig fault, not a finding:
        # report the command's own output so it can be fixed rather than
        # silently read as "nothing matched".
        say(f"  {label:<34} NO PACKET -- probe did not run")
        say(f"      rc={p.returncode} out={p.stdout.strip()[:200]!r} "
            f"err={p.stderr.strip()[:200]!r}")
        return False, got
    good = expect is None or got == expect
    verdict = "" if expect is None else ("OK" if good else f"!! expected {expect}")
    say(f"  {label:<34} exact={exact} subrange={sub} any={any_}"
        f"  -> {got}   {verdict}")
    return good, got


def deploy(arm):
    """Enable one throwaway workload; return (uid, subuid range)."""
    name = arm.name
    d = WORKLOAD_DIR / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "workload.toml").write_text(toml_for(arm))
    p = run(["workloadctl", "enable", name], timeout=900)
    if p.returncode != 0:
        sys.exit(f"enable {name} failed:\n{p.stdout}\n{p.stderr}")
    deadline = time.time() + 300
    while time.time() < deadline:
        q = run(["workloadctl", "exec", name, "--", "sh", "-c", "echo UP"],
                timeout=30)
        if q.returncode == 0 and "UP" in q.stdout:
            break
        time.sleep(5)
    else:
        run(["journalctl", "-u", f"workload-{name}.service", "-n", "40",
             "--no-pager"])
        sys.exit(f"{name} never answered exec")
    uid = uid_of(name)
    return uid, subid_range(name, uid)


def purge(name):
    run(["workloadctl", "disable", name, "--purge"], timeout=300)
    d = WORKLOAD_DIR / name
    if d.exists():
        for c in d.iterdir():
            c.unlink()
        d.rmdir()


def main():
    global ok
    global NETMODE
    if len(sys.argv) > 1:
        NETMODE = sys.argv[1]
    if NETMODE not in ("host", "pasta", "bridge"):
        sys.exit(f"unknown network mode {NETMODE!r}; use host|pasta|bridge")
    say(f"network mode under test: {NETMODE}\n")
    for arm in ARMS:
        purge(arm.name)

    verdicts = {}
    try:
        for arm in ARMS:
            name = arm.name
            label = (f"[container] user = {arm.user!r}" if arm.user
                     else "image default")
            say(f"\n{'=' * 66}\n== {name}: {label}\n{'=' * 66}")
            uid, sub = deploy(arm)
            say(f"  host uid={uid}  subuid={sub[0]}-{sub[1]}")

            e = run(["workloadctl", "exec", name, "--", "sh", "-c",
                     "id -u; cat /proc/self/uid_map"], timeout=60)
            say(f"  in-container id -u / uid_map:\n"
                + "\n".join("    " + l for l in e.stdout.strip().splitlines()))

            # Everything below is meaningless if podman gave it its own netns.
            host_names = ifnames(run(["ip", "-o", "link"]).stdout)
            cont_names = ifnames(run(["workloadctl", "exec", name, "--", "sh",
                                      "-c", "ip -o link 2>/dev/null || true"],
                                     timeout=60).stdout)
            # host mode MUST share the netns (otherwise the whole question is
            # moot); pasta/bridge mode must NOT (if it did, the topology under
            # test is not the one named).
            shared = bool(host_names) and host_names == cont_names
            want_shared = NETMODE == "host"
            good = shared == want_shared
            say(f"  netns shared={shared} (want {want_shared}): "
                f"{'OK' if good else '!! wrong topology -- rest is moot'}")
            ok = ok and good

            global ARMED
            ARMED = (uid, sub)

            # (a) is this container's egress selectable at all, and by WHICH
            # selector? `exact-uid` means a plain `meta skuid <uid>` rule
            # catches it; `subrange` means only the subuid window does.
            _, got = probe_in(name, "egress from this container")
            verdicts[name] = got

            # (b) the host's own traffic must match neither, on every arm --
            # in host mode the netns wall is gone, so this is the only thing
            # keeping the host's sockets out of a workload's policy.
            good, _ = probe_host("host traffic, as root")
            ok = ok and good
            good, _ = probe_host("host traffic, as uid 1000", as_uid="ben")
            ok = ok and good

            run(["nft", "delete", "table", "inet", SCRATCH])
            purge(name)

        say("\n" + "=" * 66)
        # SCORED, not merely printed. The host-traffic rows below were the only
        # scored thing for a while, so a run could report the uid finding
        # inverted and still say PASS -- which is precisely the shape of gap
        # this rig was written to expose in the product.
        for arm in ARMS:
            label = f"user={arm.user!r}" if arm.user else "image default"
            want = EXPECTED[NETMODE][arm.name]
            got = verdicts.get(arm.name, "unmeasured")
            good = got == want
            ok = ok and good
            say(f"  {arm.name:<9} {label:<20} -> {got:<13}"
                f"{'OK' if good else '!! expected ' + want}")
        say(f"""
  READ THIS AS: every rule in workload-filter.nft selects on the single
  workload uid, so an arm reporting `subrange` is egress no shipped rule
  matches. Under {NETMODE!r} the expected shape is above; a diff here is a
  real change in how podman maps container uids onto the host, and it decides
  whether validate_container_network()'s mode = "host" refusal is still the
  right call. An arm reporting `unattributed` would be new and worse: egress
  that no uid selector can name at all.""")
    finally:
        say("\npurging ...")
        run(["nft", "delete", "table", "inet", SCRATCH])
        for arm in ARMS:
            purge(arm.name)

    say("\nRESULT: " + ("PASS" if ok else "FAIL"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
