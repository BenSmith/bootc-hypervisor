#!/usr/bin/python3
"""Two rung-1 measurements the unit tests structurally cannot make.

Both concern packets that must cross a real kernel hook, so nothing in
`just test` can reach them: one asks whether a rule drops traffic that has
never been sent, and the other counts what a capture actually contains.

  1. THE INPUT CHAIN'S OFF-BOX DROP (design doc item 0a, ss7.2.6)

     `iif != lo ... daddr <listener plane> counter drop` has two halves and the
     tests pin neither. The loopback half is proven in passing by any green
     inspect_rig run -- if the exemption were wrong, no guest dial would ever
     reach the listener. The off-box half is not proven by anything: the unit
     tests assert the rules carry `counter`, which is that the keyword is
     present, not that it ever increments. Until a packet arrives from another
     interface, the drop is a rule believed correct because the traffic it
     exists to stop has never been sent.

  2. THE CAPTURE DOUBLING (design doc item 0b, ss11.2)

     `pcap_output_rule` and `pcap_input_rule` log to the SAME nflog group. A
     host-local packet crosses both hooks, so one packet is handed to nflog
     twice and `tcpdump -i nflog:N` has no way to tell the copies apart. This
     is latent today because almost nothing a VM does is host-local; under the
     inspector all of its HTTP and HTTPS is.

Run as root. Everything happens in throwaway network namespaces -- no host
interface, address, route or ruleset is touched, and there is no KVM
dependency, so this runs anywhere `unshare`/`ip netns` and `tcpdump` do.

    sudo python3 tests/manual/input_chain_rig.py

Last green 2026-08-22 on a bare-metal Fedora 44 host, against the installed
RPM's /usr/share/workloadctl/workload-filter.nft.
"""

import json
import os
import subprocess
import sys
import time

sys.dont_write_bytecode = True

SKELETON = "/usr/share/workloadctl/workload-filter.nft"

# Spelled out rather than imported, on inspect_rig.py's reasoning: a rig that
# computes both sides from one constant cannot notice them drifting apart.
UID = 10000
V4 = "198.18.1.0"          # vm_inspect_address(10000).v4
V6 = "2001:2::c612:100"    # ...v6
PORT = 8080                # VM_INSPECT_PORT_CLEARTEXT
GROUP = 1000               # vm_nflog_group(10000)
SNAPLEN = 1500

results = []


def record(label, ok, detail=""):
    results.append((label, ok, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{'  -- ' + detail if detail else ''}")


def run(argv, check=True, **kw):
    return subprocess.run(argv, capture_output=True, text=True, check=check, **kw)


def ns(name, *argv, check=True):
    return run(["ip", "netns", "exec", name, *argv], check=check)


def counters(namespace, chain):
    out = ns(namespace, "nft", "-j", "list", "chain",
             "inet", "workload_filter", chain).stdout
    total = 0
    for item in json.loads(out)["nftables"]:
        rule = item.get("rule")
        if not rule:
            continue
        for expr in rule.get("expr", []):
            if "counter" in expr:
                total += expr["counter"]["packets"]
    return total


def input_chain_counters(namespace):
    """(v4, v6) packet counts on the input chain's two drops."""
    out = ns(namespace, "nft", "-j", "list", "chain",
             "inet", "workload_filter", "input").stdout
    v4 = v6 = 0
    for item in json.loads(out)["nftables"]:
        rule = item.get("rule")
        if not rule:
            continue
        is_v6 = "ip6" in json.dumps(rule)
        for expr in rule.get("expr", []):
            if "counter" in expr:
                if is_v6:
                    v6 += expr["counter"]["packets"]
                else:
                    v4 += expr["counter"]["packets"]
    return v4, v6


def dial(namespace, addr, port, as_uid=None, timeout=3):
    """connect() from inside a namespace, optionally as an unprivileged uid."""
    script = (
        "import socket,sys\n"
        f"a={addr!r}\n"
        "af=socket.AF_INET6 if ':' in a else socket.AF_INET\n"
        "s=socket.socket(af,socket.SOCK_STREAM); s.settimeout(%r)\n" % timeout +
        f"try:\n    s.connect((a,{port})); print('OK')\n"
        "except Exception as e: print(type(e).__name__)\n")
    argv = ["ip", "netns", "exec", namespace]
    if as_uid is not None:
        argv += ["setpriv", f"--reuid={as_uid}", f"--regid={as_uid}",
                 "--clear-groups"]
    return run(argv + ["python3", "-c", script], check=False).stdout.strip()


LISTENER = """
import socket, sys, threading
port = int(sys.argv[1])
def serve(af, addr):
    s = socket.socket(af, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port)); s.listen(8)
    while True:
        try:
            c, _ = s.accept()
            c.recv(4096)
            c.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nhi')
            c.close()
        except OSError:
            return
for a in sys.argv[2:]:
    af = socket.AF_INET6 if ':' in a else socket.AF_INET
    threading.Thread(target=serve, args=(af, a), daemon=True).start()
import time; time.sleep(300)
"""


def request(namespace, addr, port, as_uid):
    """A full request/response as `as_uid`, not a bare connect().

    measure_doubling needs the whole exchange: a connect-and-close leaves the
    tail of the teardown straddling the end of the capture, so the copy count
    comes out odd and the doubling looks inexact when it is not.
    """
    script = (
        "import socket\n"
        f"s=socket.create_connection(({addr!r},{port}),timeout=5)\n"
        "s.sendall(b'GET / HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n')\n"
        "r=s.recv(200); s.close()\n"
        "print('OK' if r.startswith(b'HTTP/1.1 200') else r[:20])\n")
    return run(["ip", "netns", "exec", namespace, "setpriv",
                f"--reuid={as_uid}", f"--regid={as_uid}", "--clear-groups",
                "python3", "-c", script], check=False).stdout.strip()


def build(namespace):
    """A namespace holding the advertised link, the plane addresses, and the
    real skeleton -- built the way ensure_advertised_interface builds it."""
    run(["ip", "netns", "add", namespace])
    ns(namespace, "ip", "link", "set", "lo", "up")
    ns(namespace, "ip", "link", "add", "workload-proxy", "type", "dummy")
    ns(namespace, "ip", "link", "set", "workload-proxy", "up")
    for addr in ("192.0.2.1/32", f"{V4}/32"):
        ns(namespace, "ip", "addr", "add", addr, "dev", "workload-proxy")
    ns(namespace, "ip", "addr", "add", f"{V6}/128", "dev", "workload-proxy",
       "nodad")
    ns(namespace, "nft", "-f", SKELETON)


def teardown(*names):
    for n in names:
        run(["ip", "netns", "del", n], check=False)


def measure_off_box():
    """Item 0a: the loopback leg passes, the off-box leg is dropped and counted."""
    print("\n1. the input chain's off-box drop (item 0a, ss7.2.6)")
    NS, PEER = "wlinsp", "wlinsp-peer"
    teardown(NS, PEER)
    try:
        build(NS)
        run(["ip", "netns", "add", PEER])
        ns(PEER, "ip", "link", "set", "lo", "up")
        # A veth is the whole point: packets over it arrive with iif=veth0, so
        # `iif != lo` matches and the drop is reachable. Nothing else in the
        # tree can produce that ingress.
        ns(NS, "ip", "link", "add", "veth0", "type", "veth",
           "peer", "name", "veth1", "netns", PEER)
        ns(NS, "ip", "link", "set", "veth0", "up")
        ns(PEER, "ip", "link", "set", "veth1", "up")
        ns(NS, "ip", "addr", "add", "10.77.0.1/24", "dev", "veth0")
        ns(PEER, "ip", "addr", "add", "10.77.0.2/24", "dev", "veth1")
        ns(PEER, "ip", "route", "add", f"{V4}/32", "via", "10.77.0.1")
        ns(NS, "ip", "addr", "add", "fd77::1/64", "dev", "veth0")
        ns(PEER, "ip", "addr", "add", "fd77::2/64", "dev", "veth1")
        ns(PEER, "ip", "route", "add", f"{V6}/128", "via", "fd77::1")

        listener = subprocess.Popen(
            ["ip", "netns", "exec", NS, "python3", "-c", LISTENER,
             str(PORT), V4, V6],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        try:
            before = input_chain_counters(NS)

            # The loopback leg. A green inspect_rig implies this, but implying
            # is not measuring, and the two halves fail in opposite directions.
            for addr in (V4, V6):
                got = dial(NS, addr, PORT)
                record(f"loopback dial to {addr} reaches the listener",
                       got == "OK", got)
            mid = input_chain_counters(NS)
            record("the loopback leg is not counted by the drops",
                   mid == before, f"{before} -> {mid}")

            # The off-box leg, which is what nothing has ever exercised.
            for addr in (V4, V6):
                got = dial(PEER, addr, PORT)
                record(f"off-box dial to {addr} does not reach the listener",
                       got != "OK", got)
            after = input_chain_counters(NS)
            record("the v4 drop counted the off-box packets",
                   after[0] > mid[0], f"{mid[0]} -> {after[0]}")
            record("the v6 drop counted the off-box packets",
                   after[1] > mid[1], f"{mid[1]} -> {after[1]}")
        finally:
            listener.kill()
    finally:
        teardown(NS, PEER)


def measure_doubling():
    """Item 0b: how many copies of one host-local request land in one file."""
    print("\n2. the capture doubling (item 0b, ss11.2)")
    NS = "wlpcap"
    cap = "/tmp/workloadctl-doubling.pcap"
    teardown(NS)
    try:
        build(NS)
        # Exactly lib/pcap.py's install for direction="inout". Spelled out so a
        # change to those builders shows up here as a drift rather than being
        # silently followed.
        ns(NS, "nft", "add", "chain", "inet", "workload_filter", "pcap_output",
           "{ type filter hook output priority filter - 10; policy accept; }")
        ns(NS, "nft", "add", "rule", "inet", "workload_filter", "pcap_output",
           "meta", "skuid", str(UID), "counter", "log", "group", str(GROUP),
           "snaplen", str(SNAPLEN), "continue")
        ns(NS, "nft", "add", "chain", "inet", "workload_filter", "pcap_input",
           "{ type filter hook input priority 0; policy accept; }")
        ns(NS, "nft", "add", "rule", "inet", "workload_filter", "pcap_input",
           "ct", "mark", "and", "0xc0000000", "==", "0x40000000",
           "ct", "mark", "and", "0x3fffffff", "==", str(UID),
           "counter", "log", "group", str(GROUP),
           "snaplen", str(SNAPLEN), "continue")

        if os.path.exists(cap):
            os.unlink(cap)
        # The listener runs as the WORKLOAD uid, as the real inspector does.
        # As root it is a different measurement: its replies miss `meta skuid`
        # and only the guest's half doubles.
        listener = subprocess.Popen(
            ["ip", "netns", "exec", NS, "setpriv", f"--reuid={UID}",
             f"--regid={UID}", "--clear-groups",
             "python3", "-c", LISTENER, str(PORT), V4],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        tcpdump = subprocess.Popen(
            ["ip", "netns", "exec", NS, "tcpdump", "-i", f"nflog:{GROUP}",
             "-w", cap, "-U"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
        try:
            got = request(NS, V4, PORT, as_uid=UID)
            record("the request completed", got == "OK", got)
            # Long enough for the teardown's last copies to reach the file;
            # a short settle is what makes an exact doubling read as inexact.
            time.sleep(5)
        finally:
            tcpdump.terminate(); tcpdump.wait()
            listener.kill()

        out = run(["ip", "netns", "exec", NS, "tcpdump", "-r", cap, "-nn"],
                  check=False).stdout.strip().splitlines()
        in_file = len(out)
        # A packet's identity for this count is its flags and sequence text --
        # the copies are byte-identical, so anything else would need the
        # timestamps that distinguish them, which is the whole problem.
        distinct = len({ln.split(": ", 1)[-1] for ln in out})
        out_c = counters(NS, "pcap_output")
        in_c = counters(NS, "pcap_input")

        # Every packet a SOCKET sends is doubled. A bare ACK the kernel emits
        # on its own behalf -- a delayed ack, and the final ack after close()
        # when the socket is already gone -- has no owner for `meta skuid` to
        # match, so only the ct-mark input rule sees it and it lands once. That
        # is the same attribution asymmetry pcap_input_rule's docstring exists
        # for, showing up on the capture side.
        counted = {}
        for line in out:
            counted[line.split(": ", 1)[-1]] = counted.get(
                line.split(": ", 1)[-1], 0) + 1
        socket_sent = {k: v for k, v in counted.items()
                       if "Flags [.]" not in k}
        bare_acks = {k: v for k, v in counted.items() if "Flags [.]" in k}
        record("every packet a socket sent is captured twice",
               all(v == 2 for v in socket_sent.values()),
               f"{len(socket_sent)} distinct, counts {sorted(set(socket_sent.values()))}")
        record("bare kernel-emitted acks land once or twice, never more",
               all(v <= 2 for v in bare_acks.values()),
               f"{len(bare_acks)} distinct, counts {sorted(set(bare_acks.values()))}")
        record("the file holds what BOTH rules handed to nflog",
               in_file == out_c + in_c,
               f"output {out_c} + input {in_c} = {out_c + in_c}, file {in_file}")
        # The number ss11.2 wanted. Its "roughly four copies" counts two legs;
        # rung 1's listener only logs and closes, so there is one leg and the
        # ceiling is 2x. The 4x arrives with rung 2's re-origination.
        record("the inflation is 2x, not the 4x ss11.2 predicts",
               distinct < in_file <= distinct * 2,
               f"{in_file}/{distinct} = {in_file / distinct:.1f}x")
    finally:
        teardown(NS)
        if os.path.exists(cap):
            os.unlink(cap)


def main():
    if os.geteuid() != 0:
        sys.exit("this rig needs root: it creates network namespaces")
    if not os.path.exists(SKELETON):
        sys.exit(f"{SKELETON} is missing; install the workloadctl RPM first")
    measure_off_box()
    measure_doubling()
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} assertions passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
