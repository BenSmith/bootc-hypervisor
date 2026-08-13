"""
test_runtime_vm_hostname_policy.py — the proxy half of ADR 006 §4.4, live.

The address half of VM egress already has a runtime proof
(test_runtime_vm_egress_isolation.py). The *hostname* half had none: nothing
under cli_surface/ mentioned `hosts`, tinyproxy or `wl_proxy_*`, so every claim
about what a guest actually gets when it asks the proxy for a name rested on
unit tests of the generated config plus a manual run nobody could repeat.

tests/test_vm_proxy.py is not the gap. It is thorough about *construction* — the
FilterDefaultDeny directive, the map element's shape, the cgroup exemption's
position ahead of the drop, the unit's dependencies. What no unit test can reach
is the composition: a booted guest, a real tinyproxy, a real redirect, and the
question of whether the answer differs by name.

WHY THE UPSTREAM IS LOCAL AND THE NAMES ARE FAKE

The sibling test probes 1.1.1.1:53 and 9.9.9.9:53 — raw addresses, no DNS. A
hostname test cannot do that; names are the thing under test. Rather than take a
dependency on public DNS and a public host staying up, the harness points two
`.test` names (RFC 6761: guaranteed never to resolve publicly) at a stub on the
host through /etc/hosts. tinyproxy resolves them, because tinyproxy runs on the
host; the guest never resolves anything, since a proxied client sends the name
in the CONNECT and lets the proxy do the lookup.

The stub speaks no TLS and does not need to. CONNECT establishes an opaque
tunnel and tinyproxy answers `200 Connection established` as soon as its own
connect() to the upstream succeeds, so a plain TCP listener is a complete
upstream for the purpose of testing a *policy* decision. That also keeps the
positive and negative probes symmetrical: both are one CONNECT and one status
line, and neither interprets a protocol.

WHY THE PROBE IS RAW CONNECT AND NOT curl

curl would work, but it answers a fuzzier question. `curl: (56) CONNECT tunnel
failed, response 403` and a TLS error against a plaintext stub are different
shapes of failure, and the exit code alone does not separate "the proxy refused"
from "the tunnel opened and TLS did not". Reading the proxy's status line
directly gives exactly one bit of policy: 200 or 403.
"""

import base64

import pytest

from fixtures import (
    dump_journal, poll_vm_reachable, skip_if_no_kvm, skip_if_no_vm_toolchain,
    _enable_workload, _install_toml, _purge_workload,
)

pytestmark = [pytest.mark.runtime, pytest.mark.slow]

WORKLOAD = "rt-vm-hostname"

# The advertised endpoint. Hardcoded rather than imported: it is a constant by
# design (lib/vm.py — a per-workload key would let two workloads disagree about
# a host-global object), and a test that reads it from the source cannot catch a
# change to it that would break every deployed guest's cloud-init. The unit
# suite already asserts the constant and the nft skeleton agree.
PROXY_ADDR = "192.0.2.1"
PROXY_PORT = 3128

# Matches rt-vm-hostname.toml's `hosts`. The fixture itself is guarded in the
# normal suite by tests/test_vm_proxy.py TestRuntimeFixture — that it validates,
# that it is `filtered` with no `allow`, and that the wildcard's apex is not
# separately listed. Those checks are text and run on every PR; this module only
# runs on a host with /dev/kvm, so a drifted fixture has to be caught there.
ALLOWED = "wl-allowed.test"          # exact entry
WILD_SUB = "sub.wl-wild.test"        # matches *.wl-wild.test
WILD_APEX = "wl-wild.test"           # does NOT match *.wl-wild.test
UNLISTED = "wl-denied.test"          # in no entry at all

STUB_PORT = 443                      # the only port CONNECT may target
STUB_PID = "/run/wl-rt-hostname-stub.pid"
STUB_SCRIPT = "/run/wl-rt-hostname-stub.py"
HOSTS_MARK = "workloadctl-rt-hostname"

# A dropped SYN times out rather than refusing, so every probe pays this in the
# negative case. Long enough for a local connect and a proxy round trip.
PROBE_TIMEOUT = 10

STUB_SOURCE = f"""\
import socket, threading
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", {STUB_PORT}))
srv.listen(16)


def serve(conn):
    try:
        conn.sendall(b"WL-STUB\\n")
    finally:
        conn.close()


while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
"""


def _stub_up(target):
    """Point the fixture's names at a local listener, and start it.

    Both halves are the harness's, not the product's: /etc/hosts is what makes
    tinyproxy's lookup resolve, and the listener is what makes its connect()
    succeed. Neither is under test; they exist so that a 403 means policy and a
    200 means policy, rather than either meaning "no upstream".
    """
    target.put_content(STUB_SOURCE, STUB_SCRIPT)
    names = " ".join([ALLOWED, WILD_SUB, WILD_APEX])
    target.run(
        f"printf '127.0.0.1 {names}  # {HOSTS_MARK}\\n' >> /etc/hosts",
        sudo=True, check=True)
    # UNLISTED resolves too. If it did not, a 403 for it would be ambiguous —
    # tinyproxy refuses on the filter before it ever resolves, but a reader
    # cannot tell that from the result, and a test whose negative case would
    # also pass with the mechanism removed is not evidence.
    target.run(
        f"printf '127.0.0.1 {UNLISTED}  # {HOSTS_MARK}\\n' >> /etc/hosts",
        sudo=True, check=True)
    target.run(
        f"setsid nohup python3 {STUB_SCRIPT} >/dev/null 2>&1 & echo $! > {STUB_PID}",
        sudo=True, check=True)


def _stub_down(target):
    """Tolerant teardown: every step is legitimately a no-op after a failed setup."""
    target.run(f"test -f {STUB_PID} && kill $(cat {STUB_PID}) || true",
               sudo=True, check=False)
    target.run(f"rm -f {STUB_PID} {STUB_SCRIPT}", sudo=True, check=False)
    # A pidfile rather than `pkill -f`: the pattern would also match the shell
    # ssh spawned to run it, killing the connection instead of the stub.
    target.run(f"sed -i '/{HOSTS_MARK}/d' /etc/hosts", sudo=True, check=False)


def _stub_listening(target) -> bool:
    result = target.run(
        f"timeout 5 bash -c 'echo > /dev/tcp/127.0.0.1/{STUB_PORT}'",
        sudo=True, check=False, timeout=20)
    return result.rc == 0


def _connect_status(target, host: str) -> str:
    """Ask the guest to CONNECT to `host` through the proxy; return the status.

    Returns tinyproxy's status code as a string ("200", "403"), or a marker:
    NOPROXY (the guest could not open a socket to the advertised endpoint at
    all, which is a redirect problem, not a policy one) or NOREPLY (connected
    and got no status line before the timeout).

    bash's /dev/tcp rather than curl or nc: it needs no package in the cloud
    image and speaks exactly as much HTTP as the question requires.

    THE REQUEST IS BASE64 AND THAT IS NOT DECORATION. A CONNECT line is
    terminated by CRLF, and this command crosses four shells — pytest's
    subprocess, ssh to the harness host, `workloadctl exec`, and the guest's own
    — each of which gets an opinion about a backslash. Written as a `printf`
    format the escapes arrived at the guest as the literal characters `\\r`,
    which produced a request with no line terminator: tinyproxy waited for the
    rest of it and the probe timed out as NOREPLY, on both the permitted and the
    refused name. That failure is worse than a wrong answer, because NOREPLY
    reads as an infrastructure problem and invites debugging the harness. base64
    is transport-safe through all four and decodes to exact bytes.
    """
    request = (f"CONNECT {host}:{STUB_PORT} HTTP/1.1\r\n"
               f"Host: {host}:{STUB_PORT}\r\n\r\n")
    payload = base64.b64encode(request.encode()).decode()
    script = (
        f"exec 3<>/dev/tcp/{PROXY_ADDR}/{PROXY_PORT} || {{ echo NOPROXY; exit 0; }}; "
        f"echo {payload} | base64 -d >&3; "
        f"IFS= read -r -t {PROBE_TIMEOUT} line <&3 || {{ echo NOREPLY; exit 0; }}; "
        f"echo \"$line\""
    )
    result = target.wl_exec(
        WORKLOAD, ["bash", "-c", script],
        sudo=True, check=False, timeout=PROBE_TIMEOUT + 60)
    text = (result.stdout or "").strip().splitlines()
    line = text[-1].strip() if text else ""
    if line in ("NOPROXY", "NOREPLY"):
        return line
    # "HTTP/1.1 403 Filtered" -> "403"
    parts = line.split()
    return parts[1] if len(parts) >= 2 and parts[1].isdigit() else line or "EMPTY"


def _uid(target) -> int:
    return int(target.run(f"id -u _wl-{WORKLOAD}", sudo=True,
                          check=True).stdout.strip())


def _redirect_armed(target, uid: int) -> bool:
    """Is this uid in the proxy redirect map?"""
    result = target.run(
        "nft list map inet workload_proxy wl_proxy_dest",
        sudo=True, check=False, timeout=30)
    return result.rc == 0 and f"{uid} :" in result.stdout


def test_the_proxy_answers_by_name(target):
    """THE PROPERTY: one guest, one proxy, four names, two answers.

    Every probe is the same CONNECT through the same redirect to the same
    tinyproxy in the same second. The only variable is the name, so a difference
    in the answer has one available explanation.
    """
    skip_if_no_kvm(target)
    skip_if_no_vm_toolchain(target)

    _install_toml(target, f"{WORKLOAD}.toml")
    _stub_up(target)
    try:
        assert _stub_listening(target), (
            f"the harness stub is not listening on 127.0.0.1:{STUB_PORT}, so "
            f"an allowlisted name would fail for want of an upstream and the "
            f"positive probes below would be meaningless")

        try:
            _enable_workload(target, WORKLOAD, timeout=900,
                             expect_container=False)
        except Exception:
            dump_journal(target, WORKLOAD)
            raise

        reachable = poll_vm_reachable(target, WORKLOAD, token=f"{WORKLOAD}-up",
                                      timeout=420)
        if not (reachable and reachable.rc == 0):
            dump_journal(target, WORKLOAD)
        assert reachable is not None and reachable.rc == 0, (
            "the guest never became reachable, so nothing below would mean "
            "anything")

        # Deploy-time guards. Both failures below would otherwise present as a
        # policy result: without the redirect every probe is NOPROXY, and
        # without a running proxy every probe is NOPROXY as well — neither is
        # evidence about hostname policy.
        uid = _uid(target)
        assert _redirect_armed(target, uid), (
            f"uid {uid} has no element in wl_proxy_dest, so the guest has no "
            f"path to its proxy and every probe below would fail for that "
            f"reason rather than on policy")
        proxy_unit = target.run(
            f"systemctl is-active workload-{WORKLOAD}-proxy.service",
            sudo=True, check=False)
        assert proxy_unit.stdout.strip() == "active", (
            f"the proxy unit is {proxy_unit.stdout.strip()!r}, so there is "
            f"nothing listening where the redirect points")

        allowed = _connect_status(target, ALLOWED)
        wild_sub = _connect_status(target, WILD_SUB)
        wild_apex = _connect_status(target, WILD_APEX)
        unlisted = _connect_status(target, UNLISTED)

        assert allowed == "200", (
            f"an exact allowlist entry ({ALLOWED}) got {allowed!r}, not 200. "
            f"If NOPROXY, the redirect is the problem; if 403, the filter file "
            f"or FilterDefaultDeny is; if 500/504, the harness stub is")
        assert unlisted == "403", (
            f"a name on no entry ({UNLISTED}) got {unlisted!r}, not 403. A 200 "
            f"here means FilterDefaultDeny is not in force and the allowlist "
            f"is behaving as a denylist — the whole policy inverted")

        # The proxy's own egress reached the upstream for the 200 above, which
        # is the cgroup exemption working: the proxy runs as the workload's own
        # uid, which IS in wl_filtered, and nothing in `allow` names the stub.
        assert wild_sub == "200", (
            f"a subdomain of the wildcard entry ({WILD_SUB}) got {wild_sub!r}, "
            f"not 200 — `*.wl-wild.test` is not matching what it should")

    finally:
        _purge_workload(target, WORKLOAD)
        _stub_down(target)


def test_a_wildcard_entry_does_not_cover_its_own_apex(target):
    """The trap: `*.example.com` does not match `example.com`.

    fnmatch, not a DNS suffix match — the wildcard needs something to match
    before the dot. This is tinyproxy's behaviour rather than ours, which is
    exactly why it is pinned here: it is invisible in every unit test of our
    config generation, the refusal is a 403 identical to a genuine policy
    denial, and an operator who allowlists a vendor as `*.vendor.com` gets a
    working `www.` and a refused bare domain with nothing to distinguish that
    from a deliberate decision.

    A separate test from the one above because it is a separate claim: that one
    says the proxy answers by name, this one says how far a pattern reaches. If
    tinyproxy ever changed to suffix semantics, this test failing is the signal
    to update the docs that promise otherwise — docs/workloads.md and
    docs/vm-egress-walkthrough.md both state it.
    """
    skip_if_no_kvm(target)
    skip_if_no_vm_toolchain(target)

    _install_toml(target, f"{WORKLOAD}.toml")
    _stub_up(target)
    try:
        assert _stub_listening(target), "harness stub is not listening"
        try:
            _enable_workload(target, WORKLOAD, timeout=900,
                             expect_container=False)
        except Exception:
            dump_journal(target, WORKLOAD)
            raise
        reachable = poll_vm_reachable(target, WORKLOAD, token=f"{WORKLOAD}-apex",
                                      timeout=420)
        assert reachable is not None and reachable.rc == 0, (
            "the guest never became reachable")

        sub = _connect_status(target, WILD_SUB)
        apex = _connect_status(target, WILD_APEX)

        # Paired deliberately. The apex 403 alone is satisfied by a proxy that
        # refuses everything; it only means "the wildcard excludes the apex"
        # alongside a subdomain that is permitted through the same entry.
        assert sub == "200", (
            f"{WILD_SUB} got {sub!r}, not 200 — the wildcard entry is not "
            f"working at all, so the apex result below says nothing about how "
            f"far it reaches")
        assert apex == "403", (
            f"{WILD_APEX} got {apex!r}, not 403. If this is a 200, tinyproxy's "
            f"fnmatch now covers the apex of a `*.` pattern, and the guidance "
            f"in docs/workloads.md and docs/vm-egress-walkthrough.md telling "
            f"operators to list the apex separately is stale")

    finally:
        _purge_workload(target, WORKLOAD)
        _stub_down(target)


def test_the_guest_environment_carries_the_proxy(target):
    """The policy binds ordinary clients only if the guest is told to use it.

    Unit-tested at the cloud-init generation level; unverified in a booted
    guest until now. It matters at runtime because the write_files half can
    succeed while the guest's own shell never reads the file — which is why the
    generator writes both /etc/environment and a profile.d snippet.
    """
    skip_if_no_kvm(target)
    skip_if_no_vm_toolchain(target)

    _install_toml(target, f"{WORKLOAD}.toml")
    try:
        try:
            _enable_workload(target, WORKLOAD, timeout=900,
                             expect_container=False)
        except Exception:
            dump_journal(target, WORKLOAD)
            raise
        reachable = poll_vm_reachable(target, WORKLOAD, token=f"{WORKLOAD}-env",
                                      timeout=420)
        assert reachable is not None and reachable.rc == 0, (
            "the guest never became reachable")

        env = target.wl_exec(
            WORKLOAD, ["bash", "-lc", "env"], sudo=True, check=False,
            timeout=120).stdout

        assert f"https_proxy=http://{PROXY_ADDR}:{PROXY_PORT}" in env, (
            "the guest's login environment has no https_proxy, so every "
            "proxy-honouring client in it dials the internet directly and is "
            "dropped by the filter")
        assert f"NO_PROXY=" in env and PROXY_ADDR in env, (
            "the advertised address is not in the guest's NO_PROXY, which is "
            "the regression that made a broker request go through the proxy "
            "and come back as a 403 indistinguishable from a real refusal")

    finally:
        _purge_workload(target, WORKLOAD)
