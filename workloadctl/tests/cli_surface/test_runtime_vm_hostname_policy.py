"""
test_runtime_vm_hostname_policy.py — hostname policy under the inspector, live.

The address half of VM egress already has a runtime proof
(test_runtime_vm_egress_isolation.py). The *hostname* half needs its own,
because nothing a unit test can reach answers the question: a booted guest, a
real redirect, a real inspector, and whether the answer differs by name.

WHAT THIS SUITE USED TO BE, AND WHY EVERY PROBE CHANGED

Through rung 1 this file tested a proxy. Each probe opened a socket to an
advertised endpoint, wrote a CONNECT line, and read tinyproxy's status. Rung 2
deleted the proxy, the endpoint and the CONNECT, so none of those probes could
survive — but the CLAIMS survived unchanged, which is why this is a rewrite and
not a deletion:

    an exact `hosts` entry is reachable
    a `*.` entry covers its subdomains
    a `*.` entry does NOT cover its own apex
    a name on no entry is refused

What is different is that the guest is no longer a participant. It dials the
name on port 80 like any other host, a uid-keyed DNAT lands it on its own
inspector, and the inspector reads the Host header. There is nothing in the
guest to configure and nothing it could unset to escape.

WHY PORT 80 AND NOT 443

The TLS plane would need the guest to emit a real ClientHello with an SNI
extension, which means shipping a handshake into a cloud image through four
shells. The cleartext plane carries the same policy decision — the same
`hosts` list, the same matcher, the same allow/refuse — and the request is one
line of HTTP that bash can write. tests/manual/inspect_rig.py is where the TLS
plane is proven against a real guest; this suite proves the composition.

WHY THE REFUSED PROBES DIAL A LITERAL AND SET THEIR OWN Host HEADER

Not because DNS refuses the name — it does not, and this file used to say it
did. Synthesis is UNCONDITIONAL: the responder answers every name it is asked
about with the inspector's own address (lib/vm.py vm_resolve_policy, and the
matching comment in libexec/workload-vm-resolve). `hosts` changes no answer it
gives; the list is carried so unlisted queries can be COUNTED. The refusal is
the listener's, and only the listener's.

The probes dial a literal anyway, and it is worth being exact about what that
buys now that it is not the only way in: it takes DNS out of the probe
entirely. A probe that dialled the name would reach the same listener by the
same redirect, but its failure would have two available explanations instead of
one. Dialling an address the redirect catches and putting the name in the Host
header leaves exactly one thing that can decide the answer.

The DNS half is asserted on its own below, in the terms the design actually
holds: every name resolves, all to one address, and the unlisted ones are
counted.

WHY THE UPSTREAM IS LOCAL AND THE NAMES ARE FAKE

The sibling test probes 1.1.1.1:53 and 9.9.9.9:53 — raw addresses, no DNS. A
hostname test cannot do that; names are the thing under test. Rather than take a
dependency on public DNS and a public host staying up, the harness points two
`.test` names (RFC 6761: guaranteed never to resolve publicly) at a stub on the
host through /etc/hosts. The INSPECTOR resolves them, because the inspector runs
on the host; what the guest resolves is answered by the workload's own
synthesising responder and is always the inspector's own address.

That local stub is why the fixture carries [[vm.network.internal]] entries. The
inspector's upstream dial is subject to the internal-destination guard, and
127.0.0.1 is squarely inside it.
"""

import base64
import ipaddress
import json
import time

import pytest

from fixtures import (
    dump_journal, poll_vm_reachable, skip_if_no_kvm, skip_if_no_vm_toolchain,
    _enable_workload, _install_toml, _purge_workload,
)

pytestmark = [pytest.mark.runtime, pytest.mark.slow]

WORKLOAD = "rt-vm-hostname"

# The redirected cleartext port. Hardcoded rather than imported for the reason
# the advertised endpoint was: it is fixed by the rules in workload-proxy.nft,
# and a test that reads it from the source cannot catch a change to it. The unit
# suite already asserts the constant and the skeleton agree.
HTTP_PORT = 80

# The endpoint the retired proxy advertised. Nothing listens there any more, and
# one test below asserts exactly that.
RETIRED_PROXY_ADDR = "192.0.2.1"
RETIRED_PROXY_PORT = 3128

# Matches rt-vm-hostname.toml's `hosts`. The fixture itself is guarded in the
# normal suite by tests/test_vm_inspect.py TestRuntimeFixture — that it
# validates, that it is `filtered` with no `allow`, and that the wildcard's apex
# is not separately listed. Those checks are text and run on every PR; this
# module only runs on a host with /dev/kvm, so a drifted fixture has to be
# caught there.
ALLOWED = "wl-allowed.test"          # exact entry
WILD_SUB = "sub.wl-wild.test"        # matches *.wl-wild.test
WILD_APEX = "wl-wild.test"           # does NOT match *.wl-wild.test
UNLISTED = "wl-denied.test"          # in no entry at all

# The inspector reservation (RFC 2544 benchmarking space), spelled out for the
# reason HTTP_PORT is. Every workload's listener address is a /32 inside it.
INSPECT_NETWORK = ipaddress.ip_network("198.18.0.0/16")

STUB_PORT = 80                       # what the inspector dials upstream
STUB_PID = "/run/wl-rt-hostname-stub.pid"
STUB_SCRIPT = "/run/wl-rt-hostname-stub.py"
HOSTS_MARK = "workloadctl-rt-hostname"

# A dropped SYN times out rather than refusing, so every probe pays this in the
# negative case. Long enough for a local connect and an inspector round trip.
PROBE_TIMEOUT = 10

# The stub answers any request with a fixed 200. It is not a web server and does
# not parse what it is sent: the question under test is whether the inspector
# opened a connection to it at all, and a body it could not have invented is the
# cleanest way to see that from inside the guest.
STUB_BODY = "WL-STUB-OK"

STUB_SOURCE = f"""\
import socket, threading
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", {STUB_PORT}))
srv.listen(16)


def serve(conn):
    try:
        conn.recv(65536)
        body = b"{STUB_BODY}"
        conn.sendall(
            b"HTTP/1.1 200 OK\\r\\nContent-Length: %d\\r\\n"
            b"Connection: close\\r\\n\\r\\n%s" % (len(body), body))
    except OSError:
        pass
    finally:
        conn.close()


while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
"""


def _stub_up(target):
    """Point the fixture's names at a local listener, and start it.

    Both halves are the harness's, not the product's: /etc/hosts is what makes
    the INSPECTOR's lookup resolve, and the listener is what makes its connect()
    succeed. Neither is under test; they exist so that a 403 means policy and a
    200 means policy, rather than either meaning "no upstream".
    """
    target.put_content(STUB_SOURCE, STUB_SCRIPT)
    names = " ".join([ALLOWED, WILD_SUB, WILD_APEX])
    # Lists, and `bash -c` for anything with shell syntax in it. There is no
    # shell on the far end: Target.run shlex.splits a string command and
    # shlex.quotes it back together, so `>>`, `&` and `$!` written bare arrive
    # as literal arguments. `printf ... '>>' /etc/hosts` then exits 0 having
    # appended nothing, and the backgrounding never happens — the stub runs in
    # the foreground and holds the ssh channel until the 300s timeout.
    target.run(
        ["bash", "-c",
         f"printf '127.0.0.1 {names}  # {HOSTS_MARK}\\n' >> /etc/hosts"],
        sudo=True, check=True)
    # UNLISTED resolves too. If it did not, a 403 for it would be ambiguous —
    # the inspector refuses on the allowlist before it ever resolves, but a
    # reader cannot tell that from the result, and a test whose negative case
    # would also pass with the mechanism removed is not evidence.
    target.run(
        ["bash", "-c",
         f"printf '127.0.0.1 {UNLISTED}  # {HOSTS_MARK}\\n' >> /etc/hosts"],
        sudo=True, check=True)
    target.run(
        ["bash", "-c",
         f"setsid nohup python3 {STUB_SCRIPT} >/dev/null 2>&1 & "
         f"echo $! > {STUB_PID}"],
        sudo=True, check=True)


def _stub_down(target):
    """Tolerant teardown: every step is legitimately a no-op after a failed setup."""
    # `&&`, `$(...)` and `||` are shell syntax too — see _stub_up. Left as a
    # bare string this killed nothing, so every run leaked its stub.
    target.run(["bash", "-c",
                f"test -f {STUB_PID} && kill $(cat {STUB_PID}) || true"],
               sudo=True, check=False)
    target.run(["rm", "-f", STUB_PID, STUB_SCRIPT], sudo=True, check=False)
    # A pidfile rather than `pkill -f`: the pattern would also match the shell
    # ssh spawned to run it, killing the connection instead of the stub.
    target.run(["sed", "-i", f"/{HOSTS_MARK}/d", "/etc/hosts"],
               sudo=True, check=False)


def _stub_listening(target) -> bool:
    result = target.run(
        f"timeout 5 bash -c 'echo > /dev/tcp/127.0.0.1/{STUB_PORT}'",
        sudo=True, check=False, timeout=20)
    return result.rc == 0


def _http_status(target, dial: str, host_header: str) -> str:
    """Ask the guest to GET `/` at `dial`, with `host_header` as the Host.

    Returns the status code as a string ("200", "403"), or a marker: NOCONN
    (the guest could not open a socket at all, which is a redirect or DNS
    problem, not a policy one) or NOREPLY (connected and got no status line
    before the timeout).

    `dial` and `host_header` are separate arguments on purpose. For an
    allowlisted name they are the same string and the probe is what an ordinary
    client does. For a name the responder will not answer for, `dial` is a name
    that DOES resolve and `host_header` is the one under test — which is the
    only way to put an unresolvable name in front of the inspector.

    bash's /dev/tcp rather than curl or nc: it needs no package in the cloud
    image and speaks exactly as much HTTP as the question requires.

    THE REQUEST IS BASE64 AND THAT IS NOT DECORATION. A request line is
    terminated by CRLF, and this command crosses four shells — pytest's
    subprocess, ssh to the harness host, `workloadctl exec`, and the guest's own
    — each of which gets an opinion about a backslash. Written as a `printf`
    format the escapes arrived at the guest as the literal characters `\\r`,
    which produced a request with no line terminator: the listener waited for
    the rest of it and the probe timed out as NOREPLY, on both the permitted and
    the refused name. That failure is worse than a wrong answer, because NOREPLY
    reads as an infrastructure problem and invites debugging the harness. base64
    is transport-safe through all four and decodes to exact bytes.
    """
    request = (f"GET / HTTP/1.1\r\n"
               f"Host: {host_header}\r\n"
               f"Connection: close\r\n\r\n")
    payload = base64.b64encode(request.encode()).decode()
    script = (
        f"exec 3<>/dev/tcp/{dial}/{HTTP_PORT} || {{ echo NOCONN; exit 0; }}; "
        f"echo {payload} | base64 -d >&3; "
        f"IFS= read -r -t {PROBE_TIMEOUT} line <&3 || {{ echo NOREPLY; exit 0; }}; "
        f"echo \"$line\""
    )
    result = target.wl_exec(
        WORKLOAD, ["bash", "-c", script],
        sudo=True, check=False, timeout=PROBE_TIMEOUT + 60)
    text = (result.stdout or "").strip().splitlines()
    line = text[-1].strip() if text else ""
    if line in ("NOCONN", "NOREPLY"):
        return line
    # "HTTP/1.1 403 Forbidden" -> "403"
    parts = line.split()
    return parts[1] if len(parts) >= 2 and parts[1].isdigit() else line or "EMPTY"


def _resolved_address(target, host: str) -> str | None:
    """The v4 address the guest's own resolver returns for `host`, or None.

    getent, not dig: the cloud image has no bind-utils and getent goes through
    the same stub the guest's real clients use.

    Returns the ADDRESS rather than a bool because under this responder the
    interesting question is never whether a name resolved — every name does —
    but what it resolved TO. A bool cannot tell "answered with the inspector"
    from "answered with something the guest could reach directly", and those
    are the pass and the fail.

    `getent ahostsv4` prints one line per socket type, all with the same
    address in the first field:

        198.18.1.0      STREAM wl-allowed.test
        198.18.1.0      DGRAM
        198.18.1.0      RAW
    """
    result = target.wl_exec(
        WORKLOAD, ["getent", "ahostsv4", host],
        sudo=True, check=False, timeout=60)
    if result.rc != 0:
        return None
    first = (result.stdout or "").strip().splitlines()
    if not first:
        return None
    parts = first[0].split()
    return parts[0] if parts else None


# /run/workload-vm/<name>/resolve-status.json, spelled out for the reason
# HTTP_PORT is: a test that read the path from lib/vm.py would follow a change
# to it instead of catching one.
RESOLVE_STATUS = f"/run/workload-vm/{WORKLOAD}/resolve-status.json"

# The responder replaces its status file on a 30s tick (STATUS_INTERVAL), so a
# counter read straight after a query legitimately reports the tick before it.
# Long enough for one full tick plus the round trip, and no longer — a budget
# that hides a responder which stopped writing is not a budget.
STATUS_SETTLE = 45


def _resolve_status(target) -> dict | None:
    """The responder's own status document, or None if it has not written one."""
    result = target.run(["cat", RESOLVE_STATUS], sudo=True, check=False,
                        timeout=30)
    if result.rc != 0:
        return None
    try:
        return json.loads(result.stdout or "")
    except ValueError:
        return None


def _await_unlisted(target, names, timeout=STATUS_SETTLE) -> dict | None:
    """Poll the status file until every name in `names` is in unlisted_names.

    Returns the last document read, whether or not it satisfied the condition,
    so the caller's assertion can show what the responder actually reported
    rather than a bare None.
    """
    deadline = time.monotonic() + timeout
    doc = None
    while True:
        doc = _resolve_status(target) or doc
        if doc is not None:
            seen = doc.get("unlisted_names") or {}
            if all(n in seen for n in names):
                return doc
        if time.monotonic() >= deadline:
            return doc
        time.sleep(3)


def _uid(target) -> int:
    return int(target.run(f"id -u _wl-{WORKLOAD}", sudo=True,
                          check=True).stdout.strip())


def _redirect_armed(target, uid: int) -> bool:
    """Is this uid in the v4 redirect map, for the cleartext port?"""
    result = target.run(
        "nft list map inet workload_proxy wl_inspect4",
        sudo=True, check=False, timeout=30)
    return result.rc == 0 and f"{uid} . {HTTP_PORT}" in result.stdout.replace(
        "{ ", "").replace(",", "")


def _bring_up(target, token: str):
    """Install, enable and wait for the fixture. Shared by every test here."""
    _install_toml(target, f"{WORKLOAD}.toml")
    try:
        _enable_workload(target, WORKLOAD, timeout=900, expect_container=False)
    except Exception:
        dump_journal(target, WORKLOAD)
        raise
    reachable = poll_vm_reachable(target, WORKLOAD, token=token, timeout=420)
    if not (reachable and reachable.rc == 0):
        dump_journal(target, WORKLOAD)
    assert reachable is not None and reachable.rc == 0, (
        "the guest never became reachable, so nothing below would mean "
        "anything")


def test_the_inspector_answers_by_name(target):
    """THE PROPERTY: one guest, one inspector, four names, two answers.

    Every probe is the same GET through the same redirect to the same listener
    in the same second. The only variable is the name, so a difference in the
    answer has one available explanation.
    """
    skip_if_no_kvm(target)
    skip_if_no_vm_toolchain(target)

    try:
        # Inside the try, both of them: _stub_up appends to the target's
        # /etc/hosts before it starts the listener, so a failure part-way
        # through leaves those lines behind for every later test on the same
        # target — pointing fixture names at a 127.0.0.1 with nothing on it.
        # _stub_down and _purge_workload are both no-ops against state that was
        # never created, which is what makes covering the setup safe.
        _stub_up(target)

        assert _stub_listening(target), (
            f"the harness stub is not listening on 127.0.0.1:{STUB_PORT}, so "
            f"an allowlisted name would fail for want of an upstream and the "
            f"positive probes below would be meaningless")

        _bring_up(target, f"{WORKLOAD}-up")

        # Deploy-time guards. Both failures below would otherwise present as a
        # policy result: without the redirect every probe leaves the host
        # untranslated and is dropped, and without a bound socket every probe
        # is NOCONN — neither is evidence about hostname policy.
        uid = _uid(target)
        assert _redirect_armed(target, uid), (
            f"uid {uid} has no port-{HTTP_PORT} element in wl_inspect4, so "
            f"this guest's traffic is not redirected to its inspector and "
            f"every probe below would fail for that reason rather than on "
            f"policy")
        sock_unit = target.run(
            f"systemctl is-active workload-{WORKLOAD}-inspect.socket",
            sudo=True, check=False)
        assert sock_unit.stdout.strip() == "active", (
            f"the inspector socket is {sock_unit.stdout.strip()!r}, so there "
            f"is nothing listening where the redirect points")

        allowed = _http_status(target, ALLOWED, ALLOWED)
        wild_sub = _http_status(target, WILD_SUB, WILD_SUB)
        # The refused pair dial a name that resolves and carry the name under
        # test in the Host header — see the module docstring.
        wild_apex = _http_status(target, ALLOWED, WILD_APEX)
        unlisted = _http_status(target, ALLOWED, UNLISTED)

        assert allowed == "200", (
            f"an exact allowlist entry ({ALLOWED}) got {allowed!r}, not 200. "
            f"If NOCONN, the redirect or the responder is the problem; if 403, "
            f"the inspector's policy document is; if 502, the internal-"
            f"destination guard refused the upstream and the fixture's "
            f"[[vm.network.internal]] entries are not armed")
        assert unlisted == "403", (
            f"a name on no entry ({UNLISTED}) got {unlisted!r}, not 403. A 200 "
            f"here means the allowlist is behaving as a denylist — the whole "
            f"policy inverted")

        # The inspector's own egress reached the upstream for the 200 above,
        # which is the cgroup exemption working: the inspector runs as the
        # workload's own uid, which IS in wl_filtered, and nothing in `allow`
        # names the stub.
        assert wild_sub == "200", (
            f"a subdomain of the wildcard entry ({WILD_SUB}) got {wild_sub!r}, "
            f"not 200 — `*.wl-wild.test` is not matching what it should")
        assert wild_apex == "403", (
            f"the apex of the wildcard entry ({WILD_APEX}) got {wild_apex!r}, "
            f"not 403 — see the dedicated test below for what that means")

    finally:
        _purge_workload(target, WORKLOAD)
        _stub_down(target)


def test_a_wildcard_entry_does_not_cover_its_own_apex(target):
    """The trap: `*.example.com` does not match `example.com`.

    fnmatch, not a DNS suffix match — the wildcard needs something to match
    before the dot. This behaviour was tinyproxy's, and rung 2 PRESERVED it
    rather than fixing it: widening it would silently have granted every
    existing config a destination its operator never wrote down. That is
    exactly why it is pinned here — it is invisible in every unit test of our
    policy generation, the refusal is a 403 identical to a genuine policy
    denial, and an operator who allowlists a vendor as `*.vendor.com` gets a
    working `www.` and a refused bare domain with nothing to distinguish that
    from a deliberate decision.

    A separate test from the one above because it is a separate claim: that one
    says the inspector answers by name, this one says how far a pattern reaches.
    If the matcher ever changed to suffix semantics, this test failing is the
    signal to update the docs that promise otherwise — docs/workloads.md and
    docs/vm-egress-walkthrough.md both state it.
    """
    skip_if_no_kvm(target)
    skip_if_no_vm_toolchain(target)

    try:
        _stub_up(target)  # inside the try — see the note in the test above
        assert _stub_listening(target), "harness stub is not listening"
        _bring_up(target, f"{WORKLOAD}-apex")

        sub = _http_status(target, WILD_SUB, WILD_SUB)
        apex = _http_status(target, ALLOWED, WILD_APEX)

        # Paired deliberately. The apex 403 alone is satisfied by an inspector
        # that refuses everything; it only means "the wildcard excludes the
        # apex" alongside a subdomain that is permitted through the same entry.
        assert sub == "200", (
            f"{WILD_SUB} got {sub!r}, not 200 — the wildcard entry is not "
            f"working at all, so the apex result below says nothing about how "
            f"far it reaches")
        assert apex == "403", (
            f"{WILD_APEX} got {apex!r}, not 403. If this is a 200, the "
            f"matcher now covers the apex of a `*.` pattern, and the guidance "
            f"in docs/workloads.md and docs/vm-egress-walkthrough.md telling "
            f"operators to list the apex separately is stale")

    finally:
        _purge_workload(target, WORKLOAD)
        _stub_down(target)


def test_the_guest_is_told_nothing_and_is_filtered_anyway(target):
    """THE NEGATIVE THIS RUNG OWES: the old configuration is gone and inert.

    Three claims, and they only mean anything together.

    The guest's login environment carries no proxy variable — which under rung 1
    was the thing that made policy apply at all, and the test that used to live
    here asserted its presence. Its absence now is the property: nothing the
    guest can read tells it it is filtered.

    A guest that sets the retired variable anyway reaches nothing. An operator
    upgrading a workload whose image bakes in the old export, or whose seed was
    written against the old docs, gets a client dialling a host address where
    nothing listens — and it has to FAIL rather than quietly work, or the two
    designs would be running side by side.

    And it is filtered regardless: the same guest, told nothing and misconfigured
    both, still gets a 200 for an allowlisted name and a 403 for an unlisted one.
    That is the whole of what "transparent" has to mean.
    """
    skip_if_no_kvm(target)
    skip_if_no_vm_toolchain(target)

    try:
        _stub_up(target)
        assert _stub_listening(target), "harness stub is not listening"
        _bring_up(target, f"{WORKLOAD}-env")

        env = target.wl_exec(
            WORKLOAD, ["bash", "-lc", "env"], sudo=True, check=False,
            timeout=120).stdout

        for var in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
                    "no_proxy", "NO_PROXY"):
            assert f"{var}=" not in env, (
                f"the guest's login environment still sets {var}, which rung 2 "
                f"stopped writing. A client honouring it dials an address "
                f"where nothing listens, so the seed or the image is one "
                f"design behind")

        # The retired endpoint, dialled directly. `timeout` bounds it because a
        # dropped SYN hangs; a refusal and a timeout are both "nothing there"
        # and both acceptable, which is why the assertion is on the absence of
        # a successful connect rather than on an errno.
        dial = target.wl_exec(
            WORKLOAD,
            ["bash", "-c",
             f"timeout {PROBE_TIMEOUT} bash -c "
             f"'echo > /dev/tcp/{RETIRED_PROXY_ADDR}/{RETIRED_PROXY_PORT}' "
             f"&& echo OPEN || echo CLOSED"],
            sudo=True, check=False, timeout=PROBE_TIMEOUT + 60)
        assert "CLOSED" in (dial.stdout or ""), (
            f"something answered at {RETIRED_PROXY_ADDR}:{RETIRED_PROXY_PORT} "
            f"inside the guest. That is the retired proxy endpoint: rung 2 "
            f"removed the map element and the listener, so an open socket "
            f"means a stale nft element or an old workloadctl on this host")

        # ...and policy still applies to the guest that just failed to find it.
        assert _http_status(target, ALLOWED, ALLOWED) == "200"
        assert _http_status(target, ALLOWED, UNLISTED) == "403"

    finally:
        _purge_workload(target, WORKLOAD)
        _stub_down(target)


def test_every_name_resolves_to_the_inspector_and_unlisted_ones_are_counted(target):
    """The DNS half. NOT a second refusal — the responder refuses nothing.

    WHAT THIS TEST USED TO ASSERT, AND WHY IT WAS WRONG

    It asserted that an unlisted name does not resolve. It does resolve, and it
    is supposed to: synthesis is unconditional. Every name the guest asks about
    that is not in the `allow`-derived static map is answered with the
    inspector's own address, so `hosts` changes no answer this responder gives
    (lib/vm.py vm_resolve_policy states it; libexec/workload-vm-resolve's
    Policy.answers is where it happens). The old assertion described a design
    the project considered and rejected, and it had never run: dev mode skips
    the VM modules and the VM half had never run in gate mode, so it failed the
    first time anything executed it, on 2026-08-27.

    THE PROPERTY THAT IS ACTUALLY LOAD-BEARING

    Synthesis makes the exfiltration channel ABSENT rather than filtered. A
    guest encoding data into a1.example.com … aN.example.com is not refused —
    it is answered, identically, every time, and nothing resolves those names
    onward. So the thing worth proving is not that a name fails but that no
    name is ever answered with anywhere the guest could actually reach:

      * all four names resolve
      * all four resolve to ONE address
      * that address is in the inspector reservation, 198.18.0.0/16

    The third is what keeps the second from being vacuous. Two names agreeing
    on 127.0.0.1, or on whatever an upstream said, would satisfy "the same
    address" while meaning the opposite.

    AND THE COUNTER, WHICH IS THE PART WITH NO OTHER WITNESS

    The responder classifies each query against every list that could
    authorise the name and counts the ones no list does. That figure is the
    tunnelling signature and it is the only observable difference between an
    allowlisted lookup and an unlisted one — the wire answer is identical by
    design. A counter nothing increments reads 0 and passes any test that only
    checks it exists, so this asserts the split: UNLISTED and WILD_APEX land in
    `unlisted_names`, ALLOWED and WILD_SUB do not.

    WILD_APEX carries the apex trap here, and it is a stronger form of it than
    the old assertion managed. `*.wl-wild.test` does not cover `wl-wild.test`,
    so the apex must be counted unlisted while its subdomain is not — the same
    matcher parity the inspector's 403 proves on the request plane, proved
    independently on the DNS plane.
    """
    skip_if_no_kvm(target)
    skip_if_no_vm_toolchain(target)

    try:
        _stub_up(target)
        assert _stub_listening(target), "harness stub is not listening"
        _bring_up(target, f"{WORKLOAD}-dns")

        answers = {name: _resolved_address(target, name)
                   for name in (ALLOWED, WILD_SUB, WILD_APEX, UNLISTED)}

        unresolved = sorted(n for n, a in answers.items() if not a)
        assert not unresolved, (
            f"{unresolved} did not resolve inside the guest. Synthesis is "
            f"unconditional — every name is answered with the inspector's "
            f"address — so a name that resolves to nothing means the "
            f"responder is not the guest's resolver at all, or is not running")

        distinct = set(answers.values())
        assert len(distinct) == 1, (
            f"the guest got more than one address across four names: "
            f"{answers}. Every name is supposed to land on this workload's "
            f"own inspector; a name answered differently is a destination "
            f"reached without passing the listener that decides about it")

        synthesised = distinct.pop()
        assert ipaddress.ip_address(synthesised) in INSPECT_NETWORK, (
            f"the guest resolved every name to {synthesised}, which is outside "
            f"the inspector reservation {INSPECT_NETWORK}. One address for all "
            f"four names is only the right answer when that address is the "
            f"inspector's: agreeing on the harness stub's 127.0.0.1, or on "
            f"whatever an upstream returned, satisfies the check above while "
            f"meaning that the responder was bypassed")

        doc = _await_unlisted(target, (UNLISTED, WILD_APEX))
        assert doc is not None, (
            f"the responder never wrote {RESOLVE_STATUS}. It emits once before "
            f"its first query and on a {STATUS_SETTLE}s-covered tick after "
            f"that, so an absent file is a responder that never started")

        counted = doc.get("unlisted_names") or {}
        for name in (UNLISTED, WILD_APEX):
            assert name in counted, (
                f"{name} is on no list this workload carries, and the guest "
                f"just looked it up, but the responder did not count it as "
                f"unlisted: {doc}. The answer it gave is identical to an "
                f"allowlisted name's by design, so this counter is the only "
                f"place the difference is visible — silent here means an "
                f"operator watching for a name-encoding guest sees nothing")
        for name in (ALLOWED, WILD_SUB):
            assert name not in counted, (
                f"{name} IS authorised — {ALLOWED} by an exact `hosts` entry, "
                f"{WILD_SUB} by the `*.wl-wild.test` one — and was still "
                f"counted as unlisted: {doc}. The tunnelling signature reading "
                f"loud on a correct config is how it stops being read at all")

        assert doc.get("unlisted", 0) >= 2, (
            f"unlisted_names holds the names but the `unlisted` total is "
            f"{doc.get('unlisted')}: {doc}. The two are written from one "
            f"observation under one lock, so a disagreement is a bug in the "
            f"counting, not a race")

    finally:
        _purge_workload(target, WORKLOAD)
        _stub_down(target)
