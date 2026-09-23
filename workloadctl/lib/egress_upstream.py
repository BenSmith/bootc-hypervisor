"""egress_upstream: the leg from the inspector to the name the policy named.

Every upstream connection either plane opens goes through here: the plain
dial the cleartext plane makes, the verified TLS session the terminated plane
opens to an origin, and the loopback hop to this workload's own credential
broker. `Upstream` holds the two verifying contexts and the pool that reuses
a connection across the requests of one guest connection; the module
functions name a failed leg -- which drop reason it is, and the one sentence
a guest may be told.

Dialled by NAME, never by the address the guest aimed at (the inspector
design, §7.4): that address is this inspector's own listener, so resolving
the authorised name here is what makes the destination the one the policy
named rather than one the guest chose.

Installed to /usr/libexec/workloadctl/egress_upstream.py.
"""

import ipaddress
import socket
import ssl

from egress_plane import CLEARTEXT, TLS
from egress_record import (
    DROP_CLIENT_CERT, DROP_INTERNAL, DROP_UNREACHABLE, DROP_UNVERIFIED,
)
import egress_relay
from http_framing import RELAY_CHUNK, _Stream


# How many upstream connections one client connection may hold open at once.
# The map that caches them is keyed by authorised host, which makes it a
# guest-driven collection and so one that needs a ceiling: with a wildcard
# pattern (`hosts = ["*.example.com"]`) a guest can
# pipeline a1.example.com, a2.example.com, ... down a single connection and
# open a socket per name, times MAX_CONNECTIONS admitted connections, until
# the process is out of file descriptors -- and every one of those sockets is
# a host socket owned by the workload uid. Reuse is what the map is for, and
# reuse is a property of the few names a real client actually alternates
# between; past this many the least recently used is closed, which costs a
# redial rather than an error. Eight is well above any honest fan-out on one
# connection and far below anything that threatens the fd table.
UPSTREAMS_MAX = 8

# The prefix that gives a host's BROKER connection a pool slot of its own, so
# it cannot collide with the ORIGIN connection to the same host. A NUL is used
# because it cannot occur in a hostname -- validation refuses far more than
# that -- so no host, however chosen by a guest, can name the brokered slot.
# See connection_for's `key` argument for what went wrong without it.
BROKER_UPSTREAM_KEY = "broker\x00"

# What the inspector offers upstream, and what it offers the guest. One
# protocol, from configuration, on both legs -- never mirrored from what the
# guest asked for. Mirroring would make the inspector sniff the guest's ALPN and
# then have to speak whatever came back, including h2 it does not
# parse; §6 requires the upstream leg up BEFORE the guest's handshake completes
# precisely so there is nothing to mirror.
UPSTREAM_ALPN = ("http/1.1",)

# What a host named in [[vm.network.http2]] is offered instead, on BOTH legs.
#
# THIS OFFER BINDS NOBODY, and every reader of this path has to know it.
# Measured on Python 3.14 / OpenSSL 3.5.7: a server offering `http/1.1` alone
# facing a client offering `h2` alone COMPLETES the handshake, with
# selected_alpn_protocol() returning None on both sides -- no
# no_application_protocol alert, no failure of any kind. So the offer above
# selects what a COOPERATING client speaks, and the guest this design exists
# for writes its own bytes. What actually binds a terminated host to HTTP/1.1
# is the non-HTTP refusal in inspect_tls._is_http, and what binds an `http2`
# host to h2 is the preface check in inspect_tls._serve_h2 -- not either of these
# tuples. Deleting a refusal because "the ALPN already says so" reopens the whole plane.
ALPN_H2 = ("h2",)


class Upstream:
    """How this inspector reaches an authorised name, on either plane."""

    def __init__(self, broker_endpoint=None):
        # One context for every upstream leg, built once. FULL verification
        # against the host's own trust store, with no configuration key of ours
        # -- a knob that turned this off would be a knob that turns the
        # inspector into an attacker with a friendly name. A host behind a
        # private root fails here until the operator adds that root to the
        # HOST's anchors, and the 502 says so.
        self._ctx = ssl.create_default_context()
        self._ctx.set_alpn_protocols(list(UPSTREAM_ALPN))
        # A SECOND context rather than one whose ALPN is set per dial: the
        # protocol list belongs to the context and contexts are shared across
        # connections here, so mutating one before a handshake would race every
        # other connection using it -- silently, and in the direction that
        # gives a host the offer another host asked for.
        self._ctx_h2 = ssl.create_default_context()
        self._ctx_h2.set_alpn_protocols(list(ALPN_H2))
        # The (address, port) of THIS workload's credential broker instance,
        # handed in by whoever started the listener, or None for a listener
        # started without one. Handed in rather than derived: the derivation
        # is "this uid's loopback address plus the instance port", which is a
        # fact about how workloadctl lays out a host, and the inspector has no
        # business knowing it -- the generator (gen_egress) does the
        # derivation from the workload's uid and writes the pair into the
        # unit's ExecStart=. A None here makes a brokered dial a legible
        # refusal rather than a guess.
        self._broker_endpoint = (
            None if broker_endpoint is None else tuple(broker_endpoint))

    def dial_cleartext(self, host):
        """A plain connection to an authorised name, as a _Stream."""
        sock = socket.create_connection(
            (host, CLEARTEXT.guest_port),
            timeout=egress_relay.CONNECTION_TIMEOUT)
        sock.settimeout(egress_relay.RELAY_IDLE_TIMEOUT)
        return _Stream(sock)


    def dial_tls(self, host, alpn=UPSTREAM_ALPN):
        """A verified TLS session to an allowlisted name, as a _Stream.

        Dials the NAME (§7.4), like every other upstream here. Verification is
        full and against the HOST's trust store; see __init__ on why there is
        no key to turn it off.
        """
        sock = socket.create_connection(
            (host, TLS.guest_port), timeout=egress_relay.CONNECTION_TIMEOUT)
        try:
            ctx = (self._ctx_h2 if alpn == ALPN_H2
                   else self._ctx)
            ssock = ctx.wrap_socket(sock, server_hostname=host)
        except BaseException:
            sock.close()
            raise
        try:
            early = early_bytes(ssock)
        except BaseException:
            ssock.close()
            raise
        ssock.settimeout(egress_relay.RELAY_IDLE_TIMEOUT)
        return _Stream(ssock, prefill=early)


    def dial_broker(self, host):
        """A plain connection to THIS workload's credential broker instance.

        Cleartext, and on loopback, which is not a downgrade: the leg the guest
        cares about is the broker's own, which is TLS to the provider and
        verified there. This hop never leaves the host, and the endpoint it
        goes to was handed to this process on its command line, derived by
        the generator from the workload's uid -- so a second workload's
        inspector, handed its own,
        reaches its own broker and finds nothing here. That derivation is the
        whole of ADR 007 decision 6: a single broker on 127.0.0.1 would be
        reachable by every workload on the box.

        `host` is unused for ADDRESSING and is deliberately still the argument,
        because `connection_for` calls every dial the same way. It is not
        discarded either -- it rides the request head as `Host`, which is half
        the broker's dispatch key.

        A listener started with no endpoint raises OSError here, so it lands
        in the caller's broker arm as a legible refusal. That is not a
        theoretical case: it is what a listener started by hand, outside its
        unit, would hit, and a bare exception there kills the connection
        thread with a traceback instead of telling the operator what is wrong.
        """
        if self._broker_endpoint is None:
            raise OSError("this inspector was started without a broker "
                          "endpoint, and the policy names a credential for "
                          f"{host}")
        sock = socket.create_connection(
            self._broker_endpoint,
            timeout=egress_relay.CONNECTION_TIMEOUT)
        sock.settimeout(egress_relay.RELAY_IDLE_TIMEOUT)
        return _Stream(sock)


    def connection_for(self, host, upstreams, reusable=True, dial=None,
                       key=None):
        """The connection to an authorised name, opened once and reused.

        `dial` is what OPENS one, and it is the whole of the difference between
        the two planes here: cleartext dials port 80, the terminated plane dials
        443 and verifies. A redial is a real possibility on both -- an origin
        that answers `Connection: close`, an HTTP/1.0 exchange -- so the
        terminated plane passes the same verifying dial it used at the front of
        the connection rather than a socket it captured once.

        Dialled by NAME (§7.4), like the TLS plane: the address the guest aimed
        at is this inspector's own listener, so resolving the authorised name
        here is what makes the destination the one the policy named.

        Bounded at UPSTREAMS_MAX and evicted least-recently-used, because the
        set of names is the guest's to choose: a wildcard pattern makes every
        distinct subdomain a new socket, and the map outlives the request that
        opened it. Eviction is not a refusal -- the evicted name is redialled
        if it comes back -- so the bound costs a round trip in the pathological
        case and nothing at all in the honest one. `upstreams` is an ordinary
        dict, which preserves insertion order, and a hit reinserts to move the
        entry to the young end.

        `reusable=False` opts one exchange out of the map entirely -- see the
        branch below for which requests do that and why. The stream is still
        returned; it is simply the caller's to close.

        `key` SEPARATES THE POOL SLOT FROM THE NAME DIALLED, because with a
        broker leg those are not the same thing: two connections for one host
        go to two different places, and the origin one is already in this map
        before the first request is read. A
        pool keyed by the name alone hands a brokered request the origin socket
        and never calls `dial` -- silently, because everything downstream is
        identical and the record has already been told a credential is
        attached. Defaults to the host, so every other caller is unchanged.
        """
        slot = key or host
        up = upstreams.pop(slot, None)
        if up is None:
            up = (dial or self.dial_cleartext)(host)
        if not reusable:
            # Not cached at all. rebuild_request sends `Connection: close`
            # upstream for an HTTP/1.0 request, deliberately -- speaking 1.1 on
            # a 1.0 guest's behalf invites a chunked response the guest has
            # never heard of. A socket we told the origin to close is not one
            # to hand the next request: RFC 9112 §9.6 requires the origin to
            # echo `close`, and when it does _relay_response ends the whole
            # connection -- but an origin that omits it (1.0 origins do) leaves
            # this entry cached and dead, and the guest's next request for the
            # same name dies as `relay failed` rather than being redialled.
            # The caller closes it after the response.
            return up
        upstreams[slot] = up
        while len(upstreams) > UPSTREAMS_MAX:
            # The oldest entry, and never the one just returned: the dict holds
            # at least two here, and `slot` is the last key inserted.
            oldest = next(iter(upstreams))
            try:
                upstreams.pop(oldest).sock.close()
            except OSError:
                pass
        return up


def early_bytes(ssock):
    """One non-blocking read straight after the upstream handshake.

    THIS IS THE CLIENT-CERTIFICATE PROBE, and it is an optimisation rather
    than a guarantee. Under TLS 1.3 a server that REQUIRES a client
    certificate still completes the handshake and only then sends
    `certificate_required` -- so the failure arrives on the first read, and
    by taking that read here, before a single request byte has been
    forwarded, the request never reaches the origin. The alert is normally
    already buffered by the time the handshake returns; when it is not, this
    comes back empty and the first real read raises it instead, which the
    relay path handles as a failed exchange. Both are correct; only one
    keeps the request out of the origin.

    Anything that is not an alert is DATA, which an origin has no business
    sending before a request. It is kept rather than dropped -- see
    _Stream's prefill -- because the alternative is a stream read out of
    order for a case nobody has a reason to be sure about.
    """
    previous = ssock.gettimeout()
    ssock.settimeout(0)
    try:
        return ssock.recv(RELAY_CHUNK)
    except (ssl.SSLWantReadError, BlockingIOError):
        return b""
    finally:
        ssock.settimeout(previous)


def tls_failure(host, exc):
    """(drop reason, the operator's sentence) for a failed leg.

    The sentence goes to the journal, not to the guest: it names this
    host's trust anchors and the `splice` list, and a guest that could read
    those would learn from one failed request that it is sandboxed. The
    guest is given a bare 502 (http_framing.send_response).

    THREE CASES, ONE OF THEM DISTINGUISHABLE. A TLS 1.3 server that requires
    a client certificate is named exactly. A TLS 1.2 one sends
    `handshake_failure`, which it shares with "no common cipher" and half a
    dozen others -- so that arm names the possibility rather than asserting
    it. A server for which the certificate is OPTIONAL is invisible at every
    layer here; the symptom is a host that starts answering 401 or 403 only
    under termination, and `diagnose` is where that sentence belongs.
    """
    code = getattr(exc, "reason", "") or ""
    if "CERTIFICATE_REQUIRED" in code:
        return (DROP_CLIENT_CERT,
                f"{host} requires a client certificate, which this "
                f"inspector cannot present on the guest's behalf. Set "
                f"tls = \"splice\" for this workload so the guest's own "
                f"handshake reaches {host}.")
    if isinstance(exc, ssl.SSLCertVerificationError):
        detail = getattr(exc, "verify_message", None) or str(exc)
        return (DROP_UNVERIFIED,
                f"{host}'s certificate could not be verified: {detail}. If "
                f"{host} is behind a private root CA, that root must be "
                f"added to THIS HOST's trust anchors -- the guest's copy "
                f"is not consulted, because the guest is not the party "
                f"verifying {host}.")
    if code == "SSLV3_ALERT_HANDSHAKE_FAILURE":
        return (DROP_UNVERIFIED,
                f"{host} refused the handshake ({exc}). Under TLS 1.2 that "
                f"is also the alert a server sends when it requires a "
                f"client certificate, and the two are not distinguishable "
                f"here; if {host} uses client certificates it must be "
                f"spliced.")
    return (DROP_UNVERIFIED, f"the TLS session to {host} failed: {exc}")


def dial_failure_reason(host: str, internal) -> str:
    """Why an upstream dial to an ALLOWLISTED name failed, as far as this
    process can honestly tell.

    Two failures arrive as the same OSError. A name that resolves into
    private space with no [[vm.network.internal]] entry -- `internal` is the
    policy's set of the names that have one -- was refused by the
    kernel's internal drop -- the wildcard trap firing, and an operator one
    line from a working config. A name that resolves anywhere else, or that
    has an entry already, is a host that is down.

    This RE-RESOLVES the name rather than reading the address the failed
    dial used, because create_connection does not report which address it
    tried. The re-resolution can disagree with the first under a rotating
    record, and the cost of that is a misattributed counter rather than a
    wrong decision: nothing here admits or refuses anything. The decision
    was already taken, by the kernel, on the address that was actually
    dialled.

    Anything unexpected degrades to the generic reason. A counter is not
    worth failing a connection over, and this runs on a path that has
    already failed.

    THE COST, STATED

    getaddrinfo blocks and CONNECTION_TIMEOUT does not bound it -- that
    timeout is set on the socket, and this is a resolver call. So a failed
    dial to an allowlisted-but-down host costs a second synchronous
    lookup while still holding its slot against the ceiling, and a guest can
    provoke that at will by dialling such a host repeatedly. Bounded, not
    free: MAX_CONNECTIONS caps how many can be in this state at once, and
    the host-side resolver is the same one the first dial already used, so
    the answer is normally cached. Accepted because the alternative --
    attributing without resolving -- means create_connection reporting
    which address it tried, which it does not.
    """
    if host in internal:
        return DROP_UNREACHABLE
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return DROP_UNREACHABLE
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return DROP_INTERNAL
    return DROP_UNREACHABLE
