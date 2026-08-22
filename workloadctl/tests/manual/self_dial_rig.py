#!/usr/bin/python3
"""Does the wrong-port self-dial counter actually count, and does `diagnose`
say so? (design doc ss11, HLD ss12 rung 1)

The guard behind this counter drops two different things, and the counter is
the only thing that tells them apart. A packet to *another* workload's plane is
an isolation event. A packet to **this** workload's plane on a port the
inspector does not serve is an operator one `allow` line from a working config,
staring at a green `diagnose` -- because inside the guest a dropped SYN is a
hang, not an error, and every other line of `diagnose` passes.

WHAT THE UNIT TESTS CANNOT REACH, AND WHY THIS EXISTS

Three separate things have to hold and only the first has a unit test:

  1. the parser reads the element shape a counted set renders     (unit-tested)
  2. the kernel increments that element on the dropped packet     (needs a hook)
  3. `diagnose` gets from the host's nft to the printed line      (needs both)

2 is the one that made this worth writing. `meta skuid` cannot be exercised
without a process that really owns the uid, so nothing under `just test` can
send the packet -- and a counter that never increments is indistinguishable
from a guest that never self-dialled. 3 is the seam: every piece of this rung
that shipped inert shipped inert at a seam.

A note on the shape, because it is the trap here rather than a detail. A set
carrying `counter` renders its elements WRAPPED:

    {"elem": {"val": {"concat": [10000, "198.18.1.0"]},
              "counter": {"packets": 12, "bytes": 720}}}

An uncounted set renders them bare, `{"concat": [...]}`. `vm_owned_elements`
matches the bare shape, so it finds nothing at all in these sets. This rig
reads a real incremented counter through the real reader, which is the only way
to know the wrapped path was taken rather than assumed.

Run as root. Everything happens in a throwaway network namespace -- no host
interface, address, route or ruleset is touched -- but it does need a real uid
to send from, so it is a host rig and not a `just test` case.

    sudo python3 tests/manual/self_dial_rig.py
"""

import json
import os
import pwd
import socket
import subprocess
import sys

sys.dont_write_bytecode = True

LIBDIR = "/usr/libexec/workloadctl"
SKELETON = "/usr/share/workloadctl/workload-filter.nft"
NS = "wlsd"

# Spelled out rather than imported, on input_chain_rig.py's reasoning: a rig
# that computes both sides from one constant cannot notice them drifting apart.
UID = 10000
V4 = "198.18.1.0"          # vm_inspect_address(10000).v4
V6 = "2001:2::c612:100"    # ...v6
SERVED = 8080              # VM_INSPECT_PORT_CLEARTEXT -- in the accept set
UNSERVED = 2222            # the wrong-port dial: nothing serves it

results = []


def record(label, ok, detail=""):
    results.append((label, ok, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{'  -- ' + detail if detail else ''}")


def run(argv, check=True, **kw):
    return subprocess.run(argv, capture_output=True, text=True, check=check, **kw)


def ns(*argv, check=True):
    return run(["ip", "netns", "exec", NS, *argv], check=check)


def self_counter():
    """(v4, v6) packets on this uid's two self-dial elements, via the real
    reader -- not a hand-rolled parse, since the reader is half of what is
    under test."""
    out = []
    for set_name in ("wl_inspect_self", "wl_inspect_self6"):
        doc = json.loads(ns("nft", "-j", "list", "set", "inet",
                            "workload_filter", set_name).stdout)
        script = (
            "import json,sys;sys.path.insert(0,%r);"
            "from vm import nft_element_counter;"
            "c=nft_element_counter(json.load(sys.stdin),%d);"
            "print(-1 if c is None else c[0])" % (LIBDIR, UID))
        r = run(["python3", "-c", script], input=json.dumps(doc))
        out.append(int(r.stdout.strip()))
    return tuple(out)


def dial_as_root(host, port):
    """The same connect, from root. Must not be counted."""
    script = ("import socket;s=socket.socket();s.settimeout(2);"
              "s.connect_ex((%r,%d))" % (host, port))
    return ns("python3", "-c", script, check=False)


def dial(host, port, family):
    """One connect attempt as UID, from inside the namespace.

    Sent by a child that has really dropped to the uid, because `meta skuid`
    matches the socket's owner and nothing else -- a root dial is a different
    packet and lands on a different rule.
    """
    script = (
        "import os,socket,sys;os.setgid(%d);os.setuid(%d);"
        "s=socket.socket(%s,socket.SOCK_STREAM);s.settimeout(2);"
        "sys.exit(0 if s.connect_ex((%r,%d)) else 1)"
        % (UID, UID, family, host, port))
    return ns("python3", "-c", script, check=False)


def build():
    run(["ip", "netns", "add", NS])
    # A dummy link carrying both planes, so the dial has somewhere to go. The
    # names match the host's only to keep the ruleset unmodified.
    ns("ip", "link", "add", "workload-proxy", "type", "dummy")
    ns("ip", "link", "set", "workload-proxy", "up")
    ns("ip", "addr", "add", f"{V4}/32", "dev", "workload-proxy")
    ns("ip", "-6", "addr", "add", f"{V6}/128", "nodad", "dev", "workload-proxy")
    ns("nft", "-f", SKELETON)
    # Exactly what workload-vm-inspect arms: the served ports accepted, and the
    # whole listener address in the self set with NO port, which is what makes
    # the residue -- the unserved ports -- reach the drop.
    for port in (SERVED, 8443):
        ns("nft", "add", "element", "inet", "workload_filter", "wl_inspect_dst",
           "{ %d . %s . %d }" % (UID, V4, port))
        ns("nft", "add", "element", "inet", "workload_filter", "wl_inspect_dst6",
           "{ %d . %s . %d }" % (UID, V6, port))
    ns("nft", "add", "element", "inet", "workload_filter", "wl_inspect_self",
       "{ %d . %s }" % (UID, V4))
    ns("nft", "add", "element", "inet", "workload_filter", "wl_inspect_self6",
       "{ %d . %s }" % (UID, V6))


def teardown():
    run(["ip", "netns", "del", NS], check=False)


def measure():
    print("== the counter ==")
    before = self_counter()
    record("the element exists and reads through the real parser",
           before != (-1, -1), f"v4={before[0]} v6={before[1]}")
    record("a freshly armed element reads zero, not absent",
           before == (0, 0), f"{before}")

    dial(V4, UNSERVED, "socket.AF_INET")
    after_v4 = self_counter()
    record("a v4 dial to an unserved port increments the v4 element",
           after_v4[0] > before[0], f"{before[0]} -> {after_v4[0]}")
    record("...and does not touch the v6 element",
           after_v4[1] == before[1], f"v6 {before[1]} -> {after_v4[1]}")

    dial(f"{V6}", UNSERVED, "socket.AF_INET6")
    after_v6 = self_counter()
    record("a v6 dial to an unserved port increments the v6 element",
           after_v6[1] > after_v4[1], f"{after_v4[1]} -> {after_v6[1]}")

    # The qualifier is the whole design: the element is keyed on the uid, so a
    # root dial to the same address and port must land elsewhere. Without this
    # control every assertion above would still pass against a rule that had
    # lost `meta skuid` and was dropping the address for everyone -- including
    # the host tooling that has to be able to probe a listener.
    pre_root = self_counter()
    dial_as_root(V4, UNSERVED)
    post_root = self_counter()
    record("a ROOT dial to the same address and port is not counted",
           post_root == pre_root, f"{pre_root} -> {post_root}")

    # The accept set covers the served ports, so this must NOT be counted --
    # a self rule that caught them would drop every guest's own inspector
    # traffic, which is the failure the ordering exists to avoid.
    baseline = self_counter()
    dial(V4, SERVED, "socket.AF_INET")
    served = self_counter()
    record("a dial to a SERVED port is not counted as a self-dial",
           served[0] == baseline[0], f"{baseline[0]} -> {served[0]}")


def measure_diagnose():
    """The seam: from the host's nft to the line an operator reads."""
    print("== diagnose ==")
    script = r'''
import sys, json
sys.path.insert(0, "%s")
sys.dont_write_bytecode = True
from types import SimpleNamespace
import cmd_diagnose

uid = %d
cfg = SimpleNamespace(name="wlsd", uid=uid, vm_bridge=None,
                      vm_network={"egress": "filtered"},
                      config={"vm": {"network": {"egress": "filtered"}}})
elems = [{"concat": [uid, 80]}, {"concat": [uid, 443]}]
# self_dials is left to PROBE on purpose: this is the half no unit test can
# cover, the real _inspect_self_counter reading the real nft in this netns.
name, ok, detail = cmd_diagnose.vm_inspect_check(
    cfg, elements4=elems, elements6=elems, socket_active=True, v6_route=True)
print(json.dumps({"ok": ok, "detail": detail}))
''' % (LIBDIR, UID)
    r = ns("python3", "-c", script, check=False)
    line = [l for l in r.stdout.splitlines() if l.startswith("{")]
    if not line:
        record("diagnose produced a line", False,
               (r.stderr.strip().splitlines() or ["<no output>"])[-1])
        return
    out = json.loads(line[-1])
    detail = out["detail"]
    record("diagnose reports the self-dial count it read from the kernel",
           "dropped dialling this guest's own listener" in detail, detail[-140:])
    record("the count it prints is the one nft holds",
           f"{self_counter()[0] + self_counter()[1]} packet(s)" in detail,
           detail[-140:])
    record("it names the remedy rather than only the symptom",
           "allow" in detail)
    record("a self-dial does not turn the check red", out["ok"])


def main():
    if os.geteuid() != 0:
        sys.exit("run as root: this needs a netns and a real uid to send from")
    for path in (SKELETON, LIBDIR):
        if not os.path.exists(path):
            sys.exit(f"{path} is missing -- install the workloadctl RPM first")
    try:
        pwd.getpwuid(UID)
    except KeyError:
        sys.exit(f"uid {UID} does not exist on this host; enable one workload "
                 f"first, or the dial cannot be made from it")
    teardown()
    try:
        build()
        measure()
        measure_diagnose()
    finally:
        teardown()
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
