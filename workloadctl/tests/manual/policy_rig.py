#!/usr/bin/python3
"""Does rung 4 enforce what it claims, against the INSTALLED listener?
(the inspector design ss7.7.1, rung 4 T1, T3, tiers 4-5, T6, T7 and T9)

Rung 4 added four ways for a host to be treated differently -- a per-host
splice hatch, method/path rules, an h2 bypass, and a split in two counters --
and every one of them is unit-tested against a socket pair the tests own. That
leaves the same gap rung 2 and rung 3 each found the hard way: the unit suite
proves the DECISION, and the rig proves the decision is reached by the process
systemd actually starts, from the policy document on disk, with a real TLS
stack on both sides of it.

WHAT THE UNIT TESTS CANNOT REACH, AND WHY THIS EXISTS

  1. a spliced host and a terminated host on the SAME listener, told
     apart by the certificate the guest ends up holding      (needs two stacks)
  2. `methods`/`paths` refusing a real request that a real
     client sent and a real origin never received            (needs an origin
                                                              that can report)
  3. an h2 host relaying real frames, and the SAME host
     refusing a guest that does not speak h2                 (needs ALPN on
                                                              both legs)
  4. the origin half of the h2 check: an entry written for a
     host that answers http/1.1                              (needs a server
                                                              that declines)
  5. the four split counters carrying non-zero values in a
     LIVE status file, under the keys `diagnose` reads       (needs the process
                                                              to have run)

5 is the reason to write this even though every figure below has a unit test.
`tests/test_vm_inspect_diagnose.py` pins the four key strings against the
listener's own constants, so a rename cannot rot them. What no unit test can
say is that anything ever INCREMENTS them: a counter that is declared,
exported, pinned and never written reads 0, and 0 is a legal value that every
test passes. The status assertions here are read off a file a real process
wrote after real refusals, which is the only reading that tells those two
states apart.

2 has the shape rung 3's rig found. `not permitted by policy` is a refusal that
must reach NOBODY -- a request denied after the head went upstream has already
asked the question, and from outside the listener that failure looks exactly
like a working denial. So every refusal here asserts the origin's own count as
well as the guest's answer.

THE ONE THING THIS RIG DOES NOT COVER is `workloadctl diagnose` rendering these
figures, which needs an installed workload rather than a policy document in a
namespace. What it covers instead is the half that can rot silently: that the
keys diagnose looks up are the keys a running listener writes.

Run as root. Everything happens in a throwaway network namespace -- no host
interface, address or route is touched -- but it binds 443 in it, writes this
workload's names into a namespace-private /etc/hosts, and reads the installed
listener, so it is a host rig and not a `just test` case. It needs NO KVM and
no VM.

    sudo python3 tests/manual/policy_rig.py
"""

import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True

LIBDIR = "/usr/libexec/workloadctl"
LISTENER = f"{LIBDIR}/workload-vm-inspect-listener"
NS = "wlpol"

# The throwaway workload this rig pretends to be. Nothing is enabled and no
# user is created, but the listener derives BOTH its policy path and its CA
# path from the name, so the name has to be one no real workload owns.
NAME = "wlpol"

# Spelled out rather than imported, on the other rigs' reasoning: a rig that
# computes both sides from one constant cannot notice them drifting apart.
PORT_TLS = 8443            # VM_INSPECT_PORT_TLS
PORT_CLEARTEXT = 8080      # VM_INSPECT_PORT_CLEARTEXT
ORIGIN_PORT = 443          # VM_INSPECT_ORIG_TLS
RUNDIR = f"/run/workload-vm/{NAME}"
POLICY = f"{RUNDIR}/inspect.json"
STATUS = f"{RUNDIR}/inspect-status.json"
STATE_DIR = f"/var/lib/workloads/{NAME}/state"
CA_DIR = f"{STATE_DIR}/ca"
CA_CERT = f"{CA_DIR}/egress-ca.crt"
CA_KEY = f"{CA_DIR}/egress-ca.key"

# Six names, one address. Each one exists to be treated differently by exactly
# one rung-4 key, so a difference in the answer has one available explanation.
PLAIN = "plain.wlpol.test"      # allowlisted, terminated, no rules
OTHER = "other.wlpol.test"      # allowlisted, and never dialled -- see T7
POLICED = "api.wlpol.test"      # [[vm.network.policy]], and NOT in hosts
SPLICED = "spliced.wlpol.test"  # [[vm.network.splice]]
H2 = "h2.wlpol.test"            # [[vm.network.http2]], origin selects h2
H1ONLY = "h1only.wlpol.test"    # [[vm.network.http2]], origin declines h2
UNLISTED = "nowhere.example"    # on no list of any kind

HOSTNAMES = (PLAIN, OTHER, POLICED, SPLICED, H2, H1ONLY)

# The drop-reason strings, restated for the reason lib/vm.py restates four of
# them: the listener is an extension-less entrypoint and nothing can import it.
# A rig that matched on substrings would be unable to tell either split apart,
# which is the entire property under test here.
DROP_NOT_PERMITTED = "not permitted by policy"
DROP_NOT_HTTP = "not HTTP"
DROP_NOT_HTTP_POLICY = "not HTTP (policy entry)"
DROP_NOT_H2 = "not HTTP/2"
DROP_MISDIRECTED = "host does not match the server name"
DROP_MISDIRECTED_LISTED = "host does not match the server name (allowlisted)"

# RFC 9113 §3.4. Written out rather than imported for the same reason.
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
H2_SETTINGS = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"

results = []


def record(label, ok, detail=""):
    results.append((label, ok, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{'  -- ' + detail if detail else ''}")


def run(argv, check=True, **kw):
    return subprocess.run(argv, capture_output=True, text=True, check=check, **kw)


# --- the origin: one TLS server, answering to six names ---


class Origin:
    """A real TLS server on 127.0.0.1:443, with a per-NAME ALPN answer.

    One server rather than several, because the discriminating fact is what it
    does DIFFERENTLY per SNI: `h2.wlpol.test` selects h2 and `h1only.wlpol.test`
    declines it, and running those on separate ports would let a wrong dial
    reach the wrong assertion. The sni_callback swaps the socket's context,
    which is the only way one listening socket can vary its ALPN by name.

    Everything it is sent is recorded, because half of rung 4's claims are
    about what did NOT arrive. A refusal that reached the origin first has
    already asked the question, and from the guest's side it looks identical to
    one that did not.
    """

    def __init__(self, certdir):
        self.cert = os.path.join(certdir, "origin.pem")
        key = os.path.join(certdir, "origin.key")
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", self.cert, "-days", "1",
             "-subj", "/CN=origin.wlpol.test",
             "-addext", "subjectAltName=" + ",".join(
                 f"DNS:{h}" for h in HOSTNAMES)])
        self.sni = []
        self.connections = 0
        self.heads = []          # HTTP/1.1 request heads, as bytes
        self.h2_prefaces = 0     # connections that opened with the h2 preface
        self.alpn = []           # what was selected, per connection

        def context(protocols):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.cert, key)
            ctx.set_alpn_protocols(list(protocols))
            return ctx

        # The h2 context offers BOTH, so selecting h2 is the client's doing and
        # not a server that could speak nothing else -- the listener's offer is
        # what has to be seen to work.
        self._ctx_h2 = context(["h2", "http/1.1"])
        self._ctx_h1 = context(["http/1.1"])
        self._ctx_h1.sni_callback = self._sni
        self._ctx_h2.sni_callback = self._sni
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", ORIGIN_PORT))
        self._sock.listen(16)
        threading.Thread(target=self._accept, daemon=True).start()

    def _sni(self, sock, name, _ctx):
        self.sni.append(name)
        # H1ONLY is the origin half of the http2 check: it is NAMED in
        # [[vm.network.http2]] and answers http/1.1 anyway, which is the
        # mistake the key invites and the one an ALPN offer cannot prevent.
        sock.context = self._ctx_h2 if name == H2 else self._ctx_h1

    def _accept(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._serve, args=(conn,),
                             daemon=True).start()

    def _serve(self, conn):
        try:
            with self._ctx_h1.wrap_socket(conn, server_side=True) as t:
                selected = t.selected_alpn_protocol()
                self.alpn.append(selected)
                t.settimeout(5.0)
                if selected == "h2":
                    self._serve_h2(t)
                else:
                    self._serve_http1(t)
        except OSError:
            pass

    def _serve_h2(self, t):
        """Read the preface and answer with a SETTINGS frame.

        Not a real h2 implementation and does not need to be: the claim under
        test is that the listener RELAYS frames rather than parsing them, so
        the preface arriving intact and a frame coming back the other way is
        the whole of it.
        """
        buf = b""
        while len(buf) < len(H2_PREFACE):
            chunk = t.recv(4096)
            if not chunk:
                return
            buf += chunk
        if buf.startswith(H2_PREFACE):
            self.h2_prefaces += 1
        t.sendall(H2_SETTINGS)
        try:
            t.recv(4096)
        except OSError:
            pass

    def _serve_http1(self, t):
        # Keep-alive with one response per request: several rung-4 probes send
        # two requests on one connection, and an origin that answered once and
        # closed would make the second decision untestable.
        buf = b""
        while True:
            while b"\r\n\r\n" not in buf:
                chunk = t.recv(4096)
                if not chunk:
                    return
                buf += chunk
            head, buf = buf.split(b"\r\n\r\n", 1)
            self.heads.append(head)
            t.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n"
                      b"\r\nFROM-ORIGIN")

    def der(self):
        """The origin's certificate in DER, to compare against what the client
        was actually handed."""
        return ssl.PEM_cert_to_DER_cert(open(self.cert).read())

    def targets(self):
        """The request targets the origin actually received."""
        return [h.split(b" ")[1].decode() for h in self.heads if b" " in h]


# --- the listener, started the way systemd starts it ---


def start_listener(tmp, logpath, name=NAME, cafile=None):
    """Run the INSTALLED listener on inherited fds, as the socket unit does.

    Both planes are bound because the socket unit binds both; every probe below
    is on the TLS plane, which is the only one termination happens on.

    `cafile` becomes SSL_CERT_FILE, and it is the rig's substitute for a real
    upstream. The listener verifies every upstream leg FULLY against the host's
    trust store and has no configuration key to weaken that -- deliberately,
    since such a key would turn the inspector into an attacker with a friendly
    name. So a rig whose origin is self-signed gets a 502 on every terminated
    host, with `upstream certificate unverified` in the log, and every policy
    assertion below silently measures that instead of policy. Pointing
    ssl.create_default_context() at a file naming this origin alone is the
    honest way in: the trust decision is still the listener's, made the way it
    always makes it, against anchors the RIG owns rather than the host's.
    """
    socks = []
    for port in (PORT_CLEARTEXT, PORT_TLS):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(16)
        os.set_inheritable(s.fileno(), True)
        socks.append(s)
    # The wrapper does in the CHILD what only the child can do: LISTEN_PID has
    # to be its own pid and the fds have to land on 3.. in order. Doing the dup
    # in the parent clobbers whatever the parent holds there -- the bug that
    # made splice_rig's first run report a bypass.
    wrapper = os.path.join(tmp, "activate.sh")
    with open(wrapper, "w") as f:
        f.write('#!/bin/sh\nexport LISTEN_PID=$$\n'
                'eval "exec 3<&$FD0" && eval "exec 4<&$FD1"\nexec "$@"\n')
    os.chmod(wrapper, 0o755)
    log = open(logpath, "w+")
    proc = subprocess.Popen(
        [wrapper, sys.executable, LISTENER, name],
        env=dict(os.environ, LISTEN_FDS="2",
                 FD0=str(socks[0].fileno()), FD1=str(socks[1].fileno()),
                 **({"SSL_CERT_FILE": cafile} if cafile else {})),
        stdout=log, stderr=subprocess.STDOUT,
        pass_fds=tuple(s.fileno() for s in socks))
    return proc, log, socks


def make_ca():
    """This workload's egress CA, the way `workload-vm-inspect up` makes it.

    The listener refuses to START without it under tls = "inspect", which is
    the mode every probe here needs, so this is setup and not a check.
    """
    os.makedirs(CA_DIR, exist_ok=True)
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", CA_KEY, "-out", CA_CERT, "-days", "1",
         "-subj", f"/CN=workloadctl egress CA ({NAME})",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign"])
    os.chmod(CA_KEY, 0o600)


def client_context(alpn=None):
    """A client that verifies nothing, so a WRONG certificate reaches the
    assertion rather than being refused before it can be looked at."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols(list(alpn))
    return ctx


def connect(sni, *, alpn=None, timeout=6.0):
    """One terminated TLS session through the listener, or (None, error)."""
    raw = socket.create_connection(("127.0.0.1", PORT_TLS), timeout=timeout)
    try:
        t = client_context(alpn).wrap_socket(raw, server_hostname=sni)
        t.settimeout(timeout)
        return t, None
    except (ssl.SSLError, OSError) as exc:
        raw.close()
        return None, type(exc).__name__


def wait_for_log(logtext, needle, timeout=3.0):
    """Whether `needle` reaches the listener's log within `timeout`.

    Polled rather than read once. The listener logs a refusal from the thread
    serving the connection, and the rig reads the log from the thread that just
    closed it -- so a bare `needle in logtext()` is a race that reports a
    working refusal as a missing one, intermittently. Two runs of this rig
    disagreed by one assertion before this existed, which is the worst possible
    way for a rig to be wrong: it looks like flakiness in the product.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if needle in logtext():
            return True
        time.sleep(0.1)
    return False


def read_until_quiet(sock, timeout=1.5):
    """Everything the guest is sent, up to a lull or a close.

    A lull and not a length: some probes expect two responses on one connection
    and some expect a close, so a reader that stopped at the first complete
    message would see the same thing in either case.
    """
    sock.settimeout(timeout)
    out = b""
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                return out
            out += chunk
    except (TimeoutError, OSError):
        return out


def request(sni, method, target, *, host=None, timeout=6.0):
    """One HTTP request inside one terminated session. Returns (status, body).

    `host` defaults to the server name, which is the ordinary case; passing a
    different one is what the T7 binding probes do.
    """
    t, err = connect(sni, timeout=timeout)
    if t is None:
        return None, err.encode()
    try:
        head = (f"{method} {target} HTTP/1.1\r\n"
                f"Host: {host or sni}\r\n\r\n").encode()
        t.sendall(head)
        got = read_until_quiet(t)
    except OSError as exc:
        return None, type(exc).__name__.encode()
    finally:
        t.close()
    if not got.startswith(b"HTTP/"):
        return None, got[:60]
    return got.split(b" ")[1].decode(), got


def issuer_of(der):
    """The issuer line of a DER certificate, via openssl.

    Used rather than getpeercert(): the client verifies nothing (so the parsed
    dict is empty), and the question is who SIGNED what the guest was handed.
    """
    r = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout",
                        "-issuer"], input=der, capture_output=True)
    return r.stdout.decode().strip()


# --- the probes ---


def probe_splice_hatch(origin, logtext):
    """T1: one listener, two hosts, told apart by whose key ends the session.

    This is the pair a unit test cannot make. `tls = "inspect"` and a splice
    entry produce two DIFFERENT dispositions on the same process, and the only
    honest way to tell which happened is the certificate the client is holding
    when the handshake finishes -- an inspected host gets a leaf this workload's
    CA signed, and a spliced one gets the origin's own.
    """
    t, err = connect(SPLICED)
    record("a spliced host completes a real handshake through the listener",
           t is not None, err or "")
    if t is not None:
        cert = t.getpeercert(True)
        record("and the certificate the guest holds is the ORIGIN's own",
               cert == origin.der(),
               "our CA signed it" if cert != origin.der() else "")
        t.close()

    t, err = connect(PLAIN)
    record("an inspected host on the same listener completes one too",
           t is not None, err or "")
    if t is not None:
        cert = t.getpeercert(True)
        issuer = issuer_of(cert)
        record("and ITS certificate is a leaf this workload's CA signed",
               cert != origin.der() and NAME in issuer, issuer)
        t.close()

    # The hatch is a hole and the file says so; what it must not be is a hole
    # in the ALLOWLIST too. A spliced entry names a host that is allowlisted --
    # an unlisted name is refused whether or not anything would splice it.
    t, err = connect(UNLISTED)
    refused = t is None or not t.getpeercert(True) == origin.der()
    if t is not None:
        # Read before asserting: the refusal is BUMPED, so the handshake
        # succeeding is not the answer -- the 403 delivered through it is.
        read_until_quiet(t, timeout=2.0)
        t.close()
    record("a name on no list is refused even with a splice hatch present",
           refused and wait_for_log(logtext, "not allowlisted"))


def probe_policy(origin, logtext):
    """T3: what a guest may ASK for, not just who it may reach."""
    before = origin.connections

    status, _ = request(POLICED, "GET", "/v1/messages")
    record("a method and path the rules permit is relayed",
           status == "200", f"got {status}")
    record("and the entry allowlisted its own host, with .hosts never naming it",
           origin.targets()[-1:] == ["/v1/messages"], repr(origin.targets()[-3:]))

    # The query string is not part of the path, which the schema states and
    # nothing outside a unit test has ever exercised.
    status, _ = request(POLICED, "GET", "/v1/messages?stream=true")
    record("a query string does not change which path was matched",
           status == "200", f"got {status}")

    # MEASURED IN REQUESTS, NOT CONNECTIONS, and the difference is the design
    # rather than a weaker assertion. §6: the upstream leg is established
    # BEFORE the guest's handshake completes, precisely so that nothing sniffs
    # the guest to decide what to say upstream -- so by the time a REQUEST can
    # be refused, the origin has already been dialled. What must never reach it
    # is the request, and the first version of this rig asserted the
    # connection count and reported the design as a leak.
    seen_targets = list(origin.targets())
    status, body = request(POLICED, "DELETE", "/v1/messages")
    record("a method the rules do not permit is refused", status == "403",
           f"got {status}")
    record("the refusal names policy rather than the allowlist",
           wait_for_log(logtext, DROP_NOT_PERMITTED), repr(body[-80:]))
    record("and the refused method's REQUEST reached no origin",
           origin.targets() == seen_targets,
           repr(origin.targets()[len(seen_targets):]))

    seen_targets = list(origin.targets())
    status, _ = request(POLICED, "GET", "/admin")
    record("a path the rules do not permit is refused", status == "403",
           f"got {status}")
    record("and the refused path reached no origin either",
           origin.targets() == seen_targets,
           repr(origin.targets()[len(seen_targets):]))

    # The control, and it is the composition claim: a host NO entry matches is
    # allowlisted by .hosts with no method or path constraint. Without this,
    # every refusal above is equally explained by "the listener refuses DELETE".
    status, _ = request(PLAIN, "DELETE", "/anything")
    record("a host no entry matches keeps any method and any path",
           status == "200", f"got {status}")
    _ = before


def probe_http2(origin, logtext):
    """Tiers 4-5: the h2 bypass, and both halves of what binds it."""
    before_prefaces = origin.h2_prefaces
    t, err = connect(H2, alpn=["h2"])
    if t is None:
        record("an http2 host completes a handshake offering h2", False, err)
    else:
        record("an http2 host completes a handshake offering h2",
               t.selected_alpn_protocol() == "h2",
               repr(t.selected_alpn_protocol()))
        t.sendall(H2_PREFACE + H2_SETTINGS)
        got = read_until_quiet(t, timeout=3.0)
        t.close()
        record("the guest's preface reaches the origin intact",
               origin.h2_prefaces == before_prefaces + 1,
               f"{origin.h2_prefaces - before_prefaces} preface(s)")
        record("the origin selected h2 for it", origin.alpn[-1:] == ["h2"],
               repr(origin.alpn[-1:]))
        record("and a frame comes back the other way",
               got.startswith(H2_SETTINGS[:3]) or len(got) >= 9, repr(got[:12]))

    # The guest half. Without it the key would mean "exempt from policy" rather
    # than "speaks h2", reachable by writing different first bytes.
    before_prefaces = origin.h2_prefaces
    t, err = connect(H2, alpn=["h2"])
    if t is None:
        record("an http2 host that is sent HTTP/1.1 is refused", False, err)
    else:
        t.sendall(b"GET /sneak HTTP/1.1\r\nHost: %s\r\n\r\n" % H2.encode())
        got = read_until_quiet(t, timeout=3.0)
        t.close()
        record("an http2 host that is sent HTTP/1.1 is refused",
               wait_for_log(logtext, DROP_NOT_H2), repr(got[:60]))
        record("and its HTTP/1.1 request was never relayed as one",
               "/sneak" not in origin.targets(), repr(origin.targets()[-2:]))

    # The origin half: the entry is simply wrong, and an ALPN offer binds
    # nobody -- a server speaking only http/1.1 completes the handshake and
    # selects nothing, with no alert of any kind.
    before_prefaces = origin.h2_prefaces
    t, err = connect(H1ONLY, alpn=["h2"])
    if t is not None:
        t.sendall(H2_PREFACE + H2_SETTINGS)
        read_until_quiet(t, timeout=3.0)
        t.close()
    record("an http2 entry for a host that answers http/1.1 is refused",
           logtext().count(DROP_NOT_H2) >= 2,
           f"{logtext().count(DROP_NOT_H2)} occurrence(s)")
    record("and no h2 session was relayed into it",
           origin.h2_prefaces == before_prefaces,
           f"{origin.h2_prefaces - before_prefaces} unexpected preface(s)")


def probe_not_http_split(origin, logtext):
    """T6: the same bytes, refused under two different names.

    A tunnel inside a terminated session is one operator problem when the host
    has no rules and a different one when it does -- on a policed host it means
    the rules that host was given could never have run. One bucket for both
    reports them identically, which is what the split exists to stop.
    """
    seen_heads = len(origin.heads)
    t, _ = connect(PLAIN)
    if t is not None:
        t.sendall(bytes(range(8)) * 4)
        read_until_quiet(t, timeout=2.0)
        t.close()
    record("non-HTTP bytes on a host with no rules are refused as 'not HTTP'",
           wait_for_log(logtext, DROP_NOT_HTTP))

    t, _ = connect(POLICED)
    if t is not None:
        t.sendall(bytes(range(8)) * 4)
        read_until_quiet(t, timeout=2.0)
        t.close()
    record("the SAME bytes on a policed host get their own reason",
           wait_for_log(logtext, DROP_NOT_HTTP_POLICY))
    # Requests again, for the reason probe_policy states: the upstream is
    # dialled before the guest is read, so a tunnel costs a connection and must
    # cost nothing more.
    record("and neither tunnel put a request on the origin",
           len(origin.heads) == seen_heads,
           f"{len(origin.heads) - seen_heads} unexpected request(s)")


def probe_binding_split(origin, logtext):
    """T7: a Host that is not the server name, split by whether it is listed.

    A guest reusing a session it was granted to reach a name it never was is
    the attack the binding closes. A client coalescing two allowlisted names
    onto one connection -- which no client asks permission for -- produces the
    identical mismatch with nothing adversarial happening. Merged, every
    coalescing client reports as an intrusion.
    """
    seen_heads = len(origin.heads)

    # THE COUNTER KEY IS NOT THE LOG LINE, and a rig that assumed it was got
    # this backwards twice. The log interpolates the server name INSIDE the
    # reason -- "host does not match the server name plain.wlpol.test
    # (allowlisted)" -- so the counter's key is not a substring of it. Matching
    # the log on DROP_MISDIRECTED_LISTED therefore never fires, and matching it
    # on DROP_MISDIRECTED matches BOTH halves, which made the sibling
    # assertion below pass vacuously on a listener that had merged them. The
    # log is checked on its distinguishing suffix; the split itself is checked
    # where it is authoritative, in the status document (probe_status).
    status, _ = request(PLAIN, "GET", "/coalesced", host=OTHER)
    record("a Host naming a DIFFERENT allowlisted name is refused",
           status == "421", f"got {status}")
    record("and the log says which half it was",
           wait_for_log(logtext, f"{DROP_MISDIRECTED} {PLAIN} (allowlisted)"))

    status, _ = request(PLAIN, "GET", "/stolen", host=UNLISTED)
    record("a Host naming an unlisted name is refused too",
           status == "421", f"got {status}")
    unlisted_lines = [ln for ln in logtext().splitlines()
                      if f"{DROP_MISDIRECTED} {PLAIN}'" in ln]
    record("and the OTHER half is a distinguishable line, not the same one",
           bool(unlisted_lines),
           "the two halves are indistinguishable in the log")

    record("neither binding refusal put a request on the origin",
           len(origin.heads) == seen_heads,
           f"{len(origin.heads) - seen_heads} unexpected request(s)")


def probe_status(status_doc):
    """T9: the four split figures, in a file a real process wrote.

    Every key here is pinned against the listener's own constant by
    tests/test_vm_inspect_diagnose.py, so a rename cannot rot them. What that
    pin cannot say is whether anything ever INCREMENTS them -- a counter with
    no writer reads 0, and 0 is a legal value every test passes. These are the
    same figures after the refusals above actually happened.
    """
    if not status_doc:
        record("the listener wrote a status file on the way out", False,
               "no file")
        return
    record("the listener wrote a status file on the way out", True)

    reasons = status_doc.get("drop_reasons", {})
    dropped = status_doc.get("dispositions", {}).get("dropped")
    record("sum(drop_reasons) still reconciles with dispositions.dropped",
           sum(reasons.values()) == dropped,
           f"{sum(reasons.values())} vs {dropped}")

    for key in (DROP_NOT_PERMITTED, DROP_NOT_HTTP, DROP_NOT_HTTP_POLICY,
                DROP_NOT_H2, DROP_MISDIRECTED, DROP_MISDIRECTED_LISTED):
        record(f"the {key!r} figure has a writer, not just a declaration",
               reasons.get(key, 0) > 0, f"reads {reasons.get(key, 'absent')}")

    # The asymmetry T7 chose deliberately: the allowlisted half gets a per-host
    # figure because those names come off this workload's own file and the
    # bounded key space is the whole question; the other half is guest-chosen
    # and unbounded, exactly like `not allowlisted`.
    per_host = status_doc.get("per_host", {})
    listed = per_host.get(DROP_MISDIRECTED_LISTED, {})
    record("the allowlisted half names WHICH pair a client coalesced",
           OTHER in listed, repr(listed))
    record("and the guest-chosen half has no per-host map to inflate",
           DROP_MISDIRECTED not in per_host, repr(list(per_host)))


# --- assembly ---


POLICY_DOC = {
    "tls": "inspect",
    # POLICED is deliberately ABSENT: a policy entry allowlists its own host,
    # and the 200 it gets below is the only proof of that composition rule.
    "hosts": [PLAIN, OTHER, SPLICED, H2, H1ONLY],
    # PATTERN STRINGS, not tables. `reason` is a schema key that never reaches
    # the document -- vm_inspect_policy carries `vm_splice_hosts(net)`, which is
    # the patterns alone. Writing the schema's shape here instead cost a run:
    # load_policy checks that these are LISTS but not what is in them, so a
    # table reached vm_normalise_hostname and took the connection thread down
    # with an AttributeError rather than failing the start. `policy` below is
    # the one that validates its entries, which is why it takes tables.
    "splice": [SPLICED],
    "http2": [H2, H1ONLY],
    "policy": [{"host": POLICED, "methods": ["GET", "POST"],
                "paths": ["/v1/*"]}],
}


def inner():
    tmp = tempfile.mkdtemp(prefix="policy-rig.")
    logpath = os.path.join(tmp, "listener.log")
    try:
        os.makedirs(RUNDIR, exist_ok=True)
        with open(POLICY, "w") as f:
            json.dump(POLICY_DOC, f)
        make_ca()

        origin = Origin(tmp)
        proc, log, socks = start_listener(tmp, logpath, cafile=origin.cert)
        time.sleep(1.5)

        def logtext():
            log.flush(); log.seek(0)
            return log.read()

        if proc.poll() is not None:
            record("the installed listener starts on inherited fds", False,
                   logtext().strip()[-200:])
            return
        record("the installed listener starts on inherited fds, loads the "
               "policy at the installed path, and finds this workload's CA",
               True)
        # The summary line is the cheapest possible check that all four rung-4
        # keys were READ rather than defaulted -- splice_rig's own log has read
        # `splice=0 http2=0 policy=0` for every run since rung 4 landed.
        record("and the policy it loaded carries all four rung-4 lists",
               "splice=1 http2=2 policy=1" in logtext(),
               next((ln for ln in logtext().splitlines() if "tls=" in ln), ""))
        try:
            probe_splice_hatch(origin, logtext)
            probe_policy(origin, logtext)
            probe_http2(origin, logtext)
            probe_not_http_split(origin, logtext)
            probe_binding_split(origin, logtext)
        finally:
            # SIGTERM and not a kill: the shutdown write is the moment the
            # figures are complete, and it is the path an operator's `systemctl
            # stop` takes.
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            for s in socks:
                s.close()
        try:
            with open(STATUS) as f:
                status_doc = json.load(f)
        except (OSError, ValueError):
            status_doc = None
        probe_status(status_doc)
    finally:
        print("\n--- listener log ---")
        try:
            print(open(logpath).read())
        except OSError:
            pass
        shutil.rmtree(tmp, ignore_errors=True)


def teardown():
    run(["ip", "netns", "del", NS], check=False)
    shutil.rmtree(f"/etc/netns/{NS}", ignore_errors=True)


def main(argv):
    if "--inner" in argv:
        inner()
        failed = [r for r in results if not r[1]]
        print(f"\n{len(results) - len(failed)}/{len(results)} passed")
        return 1 if failed else 0

    if os.geteuid() != 0:
        sys.exit("run as root: this needs a netns and binds 443 in it")
    if not os.path.exists(LISTENER):
        sys.exit(f"{LISTENER} is missing -- install the workloadctl RPM first")
    if not shutil.which("openssl"):
        sys.exit("openssl is missing -- it generates the CA and the origin")
    for path in (POLICY, CA_DIR):
        if os.path.exists(path):
            sys.exit(f"{path} already exists: a real workload is named "
                     f"{NAME!r} on this host, and this rig would overwrite it")
    teardown()
    run(["ip", "netns", "add", NS])
    try:
        # `ip netns exec` bind-mounts /etc/netns/<ns>/* over /etc/*, so these
        # six names resolve INSIDE the namespace and nowhere else. Editing the
        # host's own /etc/hosts would leave six entries behind on a rig that
        # was interrupted, pointing later work at a listener that is gone.
        os.makedirs(f"/etc/netns/{NS}", exist_ok=True)
        with open(f"/etc/netns/{NS}/hosts", "w") as f:
            f.write("127.0.0.1 localhost\n")
            for host in HOSTNAMES:
                f.write(f"127.0.0.1 {host}\n")
        run(["ip", "netns", "exec", NS, "ip", "link", "set", "lo", "up"])
        r = subprocess.run(["ip", "netns", "exec", NS, sys.executable,
                            os.path.abspath(__file__), "--inner"])
        return r.returncode
    finally:
        teardown()
        shutil.rmtree(RUNDIR, ignore_errors=True)
        shutil.rmtree(f"/var/lib/workloads/{NAME}", ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
