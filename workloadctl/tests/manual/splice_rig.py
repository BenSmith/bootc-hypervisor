#!/usr/bin/python3
"""Does a real TLS session survive the splice, and does a real HTTP request get
authorised by the name it carries? (the inspector design ss7.7.1, rung 2 T4a
and T4b)

`tls = "splice"` claims two things at once, and a unit test can only reach the
first. It claims the bytes replayed upstream are the bytes read -- which
`test_the_bytes_replayed_upstream_are_the_bytes_read` holds against a
hand-built ClientHello -- and it claims that what comes back is a session
between the GUEST and the origin, with this process holding no key to it. The
second is a claim about a real TLS stack completing a real handshake, and no
amount of byte comparison against a hello we wrote ourselves can make it.

WHAT THE UNIT TESTS CANNOT REACH, AND WHY THIS EXISTS

  1. the parser reads a name out of a ClientHello                 (unit-tested)
  2. the replayed buffer is byte-identical to the read one        (unit-tested)
  3. a real client and a real server complete a handshake THROUGH
     the splice, and the certificate the client ends up holding
     is the origin's                                              (needs a stack)
  4. the drop happens BEFORE the upstream is dialled              (needs a server
                                                                   that can say
                                                                   it saw nobody)
  5. the installed listener starts from an inherited fd, at the
     installed policy path, under the installed module set        (needs the RPM)
  6. two requests on ONE connection get two decisions, and the
     head the origin receives is the one we composed              (needs an
                                                                   origin that
                                                                   can report)

3 is the reason this is worth writing. A hello that is subtly re-serialised --
a reordered extension block, a dropped GREASE value, a rebuilt record header --
still compares "close enough" to a human reading a diff, and still fails a real
handshake. The client's own `getpeercert` is the honest question: if anything
between it and the origin terminated the session, the certificate is the wrong
one and every other check here still passes.

4 has a history worth carrying. The first version of this rig reported a
denied name completing a handshake -- an apparent policy bypass. It was the
rig: its own `dup2(fd, 3)` had clobbered the upstream server's listening
socket, so the parent raced the listener for the guest's connections and
answered them itself. That false pass is exactly what a real bypass looks like
from outside, which is why "the upstream saw nobody" is an assertion here and
not an aside.

T4b adds a second question the unit tests cannot ask. They drive the cleartext
plane over a socketpair they own, so they can read what was written; they
cannot have an ORIGIN report what arrived. The head that reaches the origin is
where "the framing we send upstream is the one we computed, not the guest's"
becomes an observation instead of an inspection of our own buffer -- and the
refused request reaching NOBODY is the same class of claim as 4 above.

Run as root. Everything happens in a throwaway network namespace -- no host
interface, address or route is touched -- but it binds 80 and 443 in it and
reads the installed listener, so it is a host rig and not a `just test` case.
It needs NO KVM and no VM.

    sudo python3 tests/manual/splice_rig.py
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
NS = "wlspl"

# The throwaway workload this rig pretends to be. It never becomes a real
# workload -- nothing is enabled and no user is created -- but the listener
# derives its policy path from the name, so the name has to be one no real
# workload on the host already owns.
NAME = "wlspl"

# Spelled out rather than imported, on the other rigs' reasoning: a rig that
# computes both sides from one constant cannot notice them drifting apart.
PORT_TLS = 8443            # VM_INSPECT_PORT_TLS
PORT_CLEARTEXT = 8080      # VM_INSPECT_PORT_CLEARTEXT
ORIGIN_PORT = 443          # VM_INSPECT_ORIG_TLS
ORIGIN_PLAIN_PORT = 80     # VM_INSPECT_ORIG_CLEARTEXT
POLICY = f"/run/workload-vm/{NAME}/inspect.json"

ALLOWED = "localhost"      # resolves everywhere, and to the origin below
DENIED = "denied.example"  # on no list
UNREACHABLE = "nx.invalid" # ON the list, and .invalid never resolves

results = []


def record(label, ok, detail=""):
    results.append((label, ok, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{'  -- ' + detail if detail else ''}")


def run(argv, check=True, **kw):
    return subprocess.run(argv, capture_output=True, text=True, check=check, **kw)


# --- the origin: a real TLS server, with a certificate only it holds ---


class Origin:
    """A real TLS server on 127.0.0.1:443, recording the SNI it was sent.

    The SNI is recorded from the SERVER side, through the stack's own callback,
    because that is the question: did the origin receive the guest's hello, or
    a hello something in the middle composed?
    """

    def __init__(self, certdir):
        self.cert = os.path.join(certdir, "origin.pem")
        key = os.path.join(certdir, "origin.key")
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", self.cert, "-days", "1",
             "-subj", f"/CN={ALLOWED}"])
        self.sni = []
        self.connections = 0
        self.received = []
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, key)
        ctx.sni_callback = lambda sock, name, _c: self.sni.append(name)
        self._ctx = ctx
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", ORIGIN_PORT))
        self._sock.listen(8)
        threading.Thread(target=self._accept, daemon=True).start()

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
            with self._ctx.wrap_socket(conn, server_side=True) as t:
                t.sendall(b"FROM-ORIGIN")
                t.settimeout(3.0)
                self.received.append(t.recv(64))
        except OSError:
            pass

    def der(self):
        """The origin's certificate in DER, to compare against what the client
        was actually handed."""
        return ssl.PEM_cert_to_DER_cert(open(self.cert).read())


class PlainOrigin:
    """A plain HTTP origin on 127.0.0.1:80, recording the heads it was sent.

    Separate from Origin, and not a second port on it: the cleartext plane
    dials the same NAME at a different port speaking a different protocol, and
    what has to be recorded is different too. The heads are what makes "the
    framing sent upstream is the one we computed" visible from OUTSIDE the
    listener process -- a unit test reads the bytes off a socketpair it owns,
    which is not the same as an origin reporting what arrived.
    """

    def __init__(self):
        self.connections = 0
        self.heads = []
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", ORIGIN_PLAIN_PORT))
        self._sock.listen(8)
        threading.Thread(target=self._accept, daemon=True).start()

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
        # Keep-alive, and one response per request: the per-request claim is
        # about several requests on ONE connection, so an origin that answered
        # once and closed would make the second decision untestable.
        conn.settimeout(5.0)
        buf = b""
        try:
            while True:
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                head, buf = buf.split(b"\r\n\r\n", 1)
                self.heads.append(head)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n"
                             b"\r\nFROM-ORIGIN")
        except OSError:
            pass
        finally:
            conn.close()


# --- the listener, started the way systemd starts it ---


def start_listener(tmp, logpath, name=NAME):
    """Run the INSTALLED listener on inherited fds, as the socket unit does.

    Both planes are bound, not just the TLS one: the cleartext control below
    needs a listener that could have taken port 80 over and did not.
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
    # to be its own pid, and the fds have to land on 3.. in order. Doing the
    # dup in the parent would clobber whatever the parent already holds there
    # -- which is the bug that made the first run of this rig report a bypass.
    wrapper = os.path.join(tmp, "activate.sh")
    with open(wrapper, "w") as f:
        f.write('#!/bin/sh\nexport LISTEN_PID=$$\n'
                'eval "exec 3<&$FD0" && eval "exec 4<&$FD1"\nexec "$@"\n')
    os.chmod(wrapper, 0o755)
    log = open(logpath, "w+")
    proc = subprocess.Popen(
        [wrapper, sys.executable, LISTENER, name],
        env=dict(os.environ, LISTEN_FDS="2",
                 FD0=str(socks[0].fileno()), FD1=str(socks[1].fileno())),
        stdout=log, stderr=subprocess.STDOUT,
        pass_fds=tuple(s.fileno() for s in socks))
    return proc, log, socks


def client_context():
    """A client that verifies nothing, so that a WRONG certificate reaches the
    assertion rather than being refused before it can be looked at."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def dial(sni, *, port=PORT_TLS, timeout=5.0):
    """One TLS connection through the listener. Returns (peercert_der, first
    bytes read, error-name-or-None)."""
    raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        with client_context().wrap_socket(raw, server_hostname=sni) as t:
            t.settimeout(timeout)
            return t.getpeercert(True), t.recv(64), None
    except (ssl.SSLError, OSError) as exc:
        return None, b"", type(exc).__name__
    finally:
        raw.close()


# --- the probes ---


def probe(origin, log):
    def logtext():
        log.flush(); log.seek(0)
        return log.read()

    # 1. the whole point: a real session, end to end, through the splice.
    cert, first, err = dial(ALLOWED)
    record("an allowlisted name completes a real TLS handshake through the "
           "splice", err is None, err or "")
    record("data crosses from the origin to the guest", first == b"FROM-ORIGIN",
           repr(first))

    # 2. and the session is with the ORIGIN, not with the inspector. This is
    #    the assertion the byte-comparison unit test cannot make: a subtly
    #    re-serialised hello still looks right in a diff and still fails here.
    record("the certificate the guest holds is the origin's own",
           cert is not None and cert == origin.der(),
           "no certificate" if cert is None else "mismatch"
           if cert != origin.der() else "")
    record("the origin was sent the guest's own server name",
           origin.sni[-1:] == [ALLOWED], repr(origin.sni))

    seen_before = origin.connections

    # 3. a name on no list. Both halves matter: the guest is refused, AND the
    #    origin never heard from anybody -- a drop that dialled upstream first
    #    has already told the network which host the guest wanted.
    _, _, err = dial(DENIED)
    record("a name on no list gets no session", err is not None, err or "none")
    record("and the upstream was never dialled for it",
           origin.connections == seen_before,
           f"{origin.connections - seen_before} unexpected connection(s)")
    record("the refusal is logged as a policy decision",
           f"host={DENIED} reason='not allowlisted'" in logtext())

    # 4. the three drop reasons stay distinguishable at runtime, not only in
    #    the source. An operator with one bucket for them cannot tell a policy
    #    decision from a broken resolver from a tunnel.
    _, _, err = dial(UNREACHABLE)
    record("an allowlisted name that does not resolve is its own reason",
           "upstream unreachable" in logtext(), err or "")

    raw = socket.create_connection(("127.0.0.1", PORT_TLS), timeout=5)
    raw.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    time.sleep(0.5)
    tail = logtext()
    raw.close()
    record("bytes that are not TLS are a distinct reason from a name miss",
           "no readable name" in tail)
    record("and are not reported as a policy decision",
           "no readable name: record type" in tail
           and tail.count("not allowlisted") == 1)



def read_until_quiet(conn, timeout=1.5):
    """Everything the guest is sent, up to a lull or a close.

    A lull and not a length: several of these probes expect TWO responses on
    one connection and one expects a close, so a reader that stopped at the
    first complete message would see the same thing in every case.
    """
    conn.settimeout(timeout)
    out = b""
    try:
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                return out
            out += chunk
    except (TimeoutError, OSError):
        return out


def probe_cleartext(plain, origin, log):
    """The T4b claim, through the installed listener and a real origin.

    The unit tests drive `_serve_cleartext` over a socketpair they own. What
    they cannot do is have an ORIGIN report what arrived: that the head it was
    sent is the one this process composed rather than the guest's, and that the
    refused request reached nobody at all.
    """
    def logtext():
        log.flush(); log.seek(0)
        return log.read()

    # 5. one connection, two names, two decisions. The whole of T4b's shape:
    #    a per-CONNECTION decision would send the second request to the first
    #    request's upstream, and nothing outside would look wrong.
    before_plain, before_tls = plain.connections, origin.connections
    conn = socket.create_connection(("127.0.0.1", PORT_CLEARTEXT), timeout=5)
    conn.sendall(b"GET /one HTTP/1.1\r\nHost: %s\r\n\r\n"
                 b"GET /two HTTP/1.1\r\nHost: %s\r\n\r\n"
                 % (ALLOWED.encode(), DENIED.encode()))
    got = read_until_quiet(conn)
    conn.close()
    record("an allowlisted Host is relayed to a real origin",
           b"FROM-ORIGIN" in got and plain.connections == before_plain + 1,
           f"{plain.connections - before_plain} origin connection(s)")
    # NAMES NOTHING, and the inversion is the assertion. This once required the
    # denied host to appear in the body, back when a refusal read
    # "workloadctl: GET / is not permitted on <host> by this workload's egress
    # policy". That body made one refused request a reliable oracle for "you are
    # sandboxed" and what the sandbox was called, before the guest had inspected
    # a single certificate, so it was stripped to a bare POLICY_REFUSAL_BODY.
    # The rig kept demanding the name for one commit and failed here on the next
    # hardware run -- asserting the leak the change closed. Guarding the absence
    # is what keeps a future edit from putting it back.
    record("a Host on no list gets a 403 whose body names NOTHING",
           b"403" in got and DENIED.encode() not in got, repr(got[-80:]))
    record("both decisions were taken on the one connection",
           got.count(b"HTTP/1.1 ") == 2
           and got.index(b"200") < got.index(b"403"),
           f"{got.count(b'HTTP/1.1 ')} response(s)")
    record("the refused request reached no origin at all",
           plain.connections == before_plain + 1
           and all(b"/two" not in h for h in plain.heads),
           f"heads={[h.split(b' ')[1] for h in plain.heads]}")
    record("the origin was sent OUR head, not the guest's",
           any(h.startswith(b"GET /one HTTP/1.1") and b"Connection: keep-alive"
               in h for h in plain.heads),
           repr(plain.heads[-1:]))
    record("and the cleartext plane dialled no TLS upstream",
           origin.connections == before_tls,
           f"{origin.connections - before_tls} unexpected TLS connection(s)")

    # 6. the smuggling refusal, end to end: two framings at once is declined
    #    rather than resolved, and nothing reaches the origin.
    before_plain = plain.connections
    conn = socket.create_connection(("127.0.0.1", PORT_CLEARTEXT), timeout=5)
    conn.sendall(b"POST /smuggle HTTP/1.1\r\nHost: %s\r\n"
                 b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n"
                 b"\r\nhello" % ALLOWED.encode())
    got = read_until_quiet(conn)
    conn.close()
    record("a request framed both ways at once is refused, not resolved",
           b"400" in got, repr(got[:40]))
    record("and it reached no origin", plain.connections == before_plain,
           f"{plain.connections - before_plain} unexpected connection(s)")
    record("the refusal is not reported as a policy decision",
           "unreadable request" in logtext()
           and logtext().count("not allowlisted") == 2)


def probe_lf_smuggle(plain, log):
    """The bare LF, checked where it would actually land: at the origin.

    The head is framed on CRLF, so a lone LF inside a header value survives the
    split and travels upstream inside the field it was written in. An origin
    that accepts bare-LF line endings -- many do -- reads it as the start of a
    line, and what follows is a whole second request line that never passed
    policy, arriving behind our own Host header. The unit test reads our
    buffer; this reads the ORIGIN's, which is the side the smuggle is aimed at.
    """
    before = plain.connections
    conn = socket.create_connection(("127.0.0.1", PORT_CLEARTEXT), timeout=5)
    conn.sendall(b"GET /one HTTP/1.1\r\nHost: %s\r\n"
                 b"X-T: v\nGET /smuggled HTTP/1.1\nHost: %s\r\n\r\n"
                 % (ALLOWED.encode(), ALLOWED.encode()))
    got = read_until_quiet(conn)
    conn.close()
    record("a bare LF in a header value is refused, not forwarded",
           b"400" in got, repr(got[:40]))
    record("and the origin was never sent the line hiding in it",
           plain.connections == before
           and all(b"/smuggled" not in h for h in plain.heads),
           f"{plain.connections - before} connection(s)")


def probe_no_policy(tmp):
    """The control for 5: a listener with no policy fails LOUDLY.

    Driven by starting one for a workload name nothing ever wrote a policy for,
    rather than by moving this rig's own file out from under a running process
    -- the question is what a start with no document does, and a start is what
    that asks.

    The tempting fallback is an empty allowlist, and it is the worst option --
    an empty `hosts` is a legal configuration, so the listener could not tell
    "the operator allowed nothing" from "the file was not there" and would
    enforce the strictest reading of a policy it never read while reporting
    itself healthy.
    """
    absent = f"{NAME}-nopolicy"
    proc, log, socks = start_listener(tmp, os.path.join(tmp, "nopolicy.log"),
                                      name=absent)
    try:
        rc = proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        record("a listener with no policy fails its start", False,
               "it kept running")
        return
    finally:
        for s in socks:
            s.close()
    log.seek(0)
    text = log.read()
    record("a listener with no policy fails its start", rc != 0, f"rc={rc}")
    record("and says which file it could not read",
           f"/run/workload-vm/{absent}/inspect.json" in text,
           text.strip()[-120:])


def inner():
    tmp = tempfile.mkdtemp(prefix="splice-rig.")
    logpath = os.path.join(tmp, "listener.log")
    try:
        os.makedirs(os.path.dirname(POLICY), exist_ok=True)
        with open(POLICY, "w") as f:
            json.dump({"tls": "splice", "hosts": [ALLOWED, UNREACHABLE]}, f)

        origin = Origin(tmp)
        plain = PlainOrigin()
        proc, log, socks = start_listener(tmp, logpath)
        time.sleep(1.5)
        if proc.poll() is not None:
            log.seek(0)
            record("the installed listener starts on inherited fds", False,
                   log.read().strip()[-160:])
            return
        record("the installed listener starts on inherited fds and loads the "
               "policy at the installed path", True)
        try:
            probe(origin, log)
            probe_cleartext(plain, origin, log)
            probe_lf_smuggle(plain, log)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            for s in socks:
                s.close()
        probe_no_policy(tmp)
    finally:
        print("\n--- listener log ---")
        try:
            print(open(logpath).read())
        except OSError:
            pass
        shutil.rmtree(tmp, ignore_errors=True)


def teardown():
    run(["ip", "netns", "del", NS], check=False)


def main(argv):
    if "--inner" in argv:
        inner()
        failed = [r for r in results if not r[1]]
        print(f"\n{len(results) - len(failed)}/{len(results)} passed")
        return 1 if failed else 0

    if os.geteuid() != 0:
        sys.exit("run as root: this needs a netns and binds 80 and 443 in it")
    if not os.path.exists(LISTENER):
        sys.exit(f"{LISTENER} is missing -- install the workloadctl RPM first")
    if not shutil.which("openssl"):
        sys.exit("openssl is missing -- it generates the origin's certificate")
    if os.path.exists(POLICY):
        sys.exit(f"{POLICY} already exists: a real workload is named {NAME!r} "
                 f"on this host, and this rig would overwrite its policy")
    teardown()
    run(["ip", "netns", "add", NS])
    try:
        run(["ip", "netns", "exec", NS, "ip", "link", "set", "lo", "up"])
        # The netns is entered here, and everything above runs inside it: the
        # origin binds 443 and the listener binds both planes on a loopback
        # that belongs to nobody else.
        r = subprocess.run(["ip", "netns", "exec", NS, sys.executable,
                            os.path.abspath(__file__), "--inner"])
        return r.returncode
    finally:
        teardown()
        shutil.rmtree(os.path.dirname(POLICY), ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
