"""
inspect_http: authorise every request on a connection, and relay the ones
that pass.

Per REQUEST, not per connection. One connection carries many requests, each
free to name a different host, so a decision taken once at the front of it
would authorise everything behind the first name -- and the framing that
says where one request ends is written by the guest. Every refusal in
`lib/http_framing.py` exists because the alternative is a request the guest
smuggled past the authorisation of the one in front of it; `lib/http_target.py`
is why the target is normalised before anything here acts on it, and
`lib/http_request.py` is the head as this module sees it.

Two callers, one loop. The cleartext plane (port 80) enters at
serve_cleartext with the accepted socket; a terminated TLS connection enters
at serve_one_request with the decrypted one. The allowlist means the same
thing on both only because it is this loop that applies it on both.

Every function takes the workload's Inspection (lib/inspect_scope.py) first:
the policy the request is matched against, the counters and record it lands
in, the upstream pool it is sent down, and the log.
"""

import ssl

from egress_record import (
    DROP_BROKER_UNREACHABLE, DROP_MISDIRECTED, DROP_MISDIRECTED_LISTED,
    DROP_NOT_ALLOWLISTED, DROP_NOT_PERMITTED, DROP_RELAY_FAILED,
    DROP_TIMED_OUT, DROP_UNREADABLE_REQUEST, Record,
)
from egress_relay import relay
import egress_relay
from egress_upstream import BROKER_UPSTREAM_KEY, dial_failure_reason, tls_failure
from http_framing import (
    ReadTimedOut, RequestUnreadable, _Stream, _get_all, _is_count,
    _split_response_head, copy_body, drain, response_framing, send_response,
)
from http_request import parse_request, rebuild_request
from http_target import SCHEME_HTTP, redirect_target


# How many 1xx interim responses one request may collect before the exchange is
# abandoned. One is the real number -- a 100 for an Expect, or a 103 carrying
# early hints -- and the rest of the allowance is there so the bound is never
# what breaks an honest origin. It exists because the loop that reads them is
# driven by the far end: without it an allowlisted host can hold a guest's
# connection, and one of MAX_CONNECTIONS slots, with interim heads alone.
INTERIM_MAX = 32


# The body every POLICY denial shows the guest: generic, and identical for the
# not-allowlisted and the not-permitted case alike. The split between those two
# is real and it is the OPERATOR'S -- it lives in the journal line and in the
# per-request record's `reason` -- but a guest has no business learning it, or
# even that there is a policy to be on the wrong side of. A body that named the
# allowlist, the egress policy, or the tool would turn a single refused request
# into a reliable "you are sandboxed" oracle, answerable before the guest looked
# at one certificate; a bare status does not. See http_framing.send_response for the same reasoning
# applied to a tool-name prefix.
POLICY_REFUSAL_BODY = "Forbidden"


def serve_cleartext(insp, conn, where):
    """Authorise every request on this connection, and relay the ones that
    pass.

    Port 80. Two properties hold: a name that is on no list gets a real
    403 naming it, and nothing reaches an upstream the policy did not
    authorise. A guest is not configured to send its requests here; it is
    redirected.

    Per REQUEST, not per connection. One connection carries many requests,
    each free to name a different host, so a decision taken once at the
    front of it would authorise everything behind the first name -- and
    the framing that says where one request ends is written by the guest.
    Every refusal in `lib/http_framing.py` exists because the alternative
    is a request the guest smuggled past the authorisation of the one in
    front of it; `lib/http_target.py` is why the target is normalised
    before anything here acts on it, and `lib/http_request.py` is the head
    as this method sees it.

    The upstreams are keyed by the AUTHORISED NAME and outlive the request
    that opened them, so a second request for the same name reuses one and
    a second request for a different name gets its own. No request is ever
    sent down an upstream an earlier one chose.
    """
    client = _Stream(conn)
    upstreams = {}
    try:
        first = True
        seq = 1
        while serve_one_request(insp, client, conn,
                                      where.request(seq),
                                      upstreams, first):
            first = False
            seq += 1
    finally:
        for up in upstreams.values():
            up.sock.close()


def serve_one_request(insp, client, conn, where, upstreams, first, *,
                       scheme=SCHEME_HTTP, pinned_host=None):
    """One request, and the record it leaves. True to stay on the connection.

    A WRAPPER, so that the record is written on every way out of the pass
    below without wrapping two hundred argued lines in another try. Every
    path through serve_request either sets a decision on `rec` or is one
    of the two that are not requests at all -- an idle kept-alive
    connection reaching its bound, and a guest that closed between
    requests -- and Record.emit writes nothing for those.
    """
    rec = Record(insp.record, where,
                  "terminate" if pinned_host is not None else "forward")
    try:
        return serve_request(insp, client, conn, where, upstreams, first,
                                   rec, scheme=scheme,
                                   pinned_host=pinned_host)
    finally:
        rec.emit()


def serve_request(insp, client, conn, where, upstreams, first, rec, *,
                   scheme=SCHEME_HTTP, pinned_host=None):
    """One request, start to finish. True to stay on the connection.

    `scheme` says which plane this is, for the two parser refusals that
    differ by it. `pinned_host`, on the terminated plane, is the server name
    the session's certificate was minted for: a request naming any other
    host is answered 421 rather than relayed, because the connection it
    would be relayed down is not the one its Host header authorises.

    `where` arrives with the connection id AND this request's ordinal
    already in it -- composed by the caller, because the ordinal is the
    loop's to count and this function serves exactly one request. Nothing
    here rebuilds it, so `_refuse`, `_relay_response` and the redirect
    notes all carry the same key without knowing it exists.

    `first` says which of the two timeouts bounds the wait for this
    request's first byte. On the first request it is the decision timeout:
    a connection that has been accepted and says nothing is holding one of
    MAX_CONNECTIONS slots for nothing. On every request after it, it is the
    idle timeout: the guest is entitled to keep the connection and use it
    again, and cutting that at five seconds both breaks keep-alive and
    counts the break as a request we could not read.
    """
    # Back to the decision timeout at the top of every request, whatever
    # the previous one left on the socket. What follows is a head to read
    # and a policy to apply against it; the relay's idle bound is not the
    # bound for that, and the idle_timeout below overrides this one for the
    # only wait it should apply to.
    conn.settimeout(egress_relay.CONNECTION_TIMEOUT)
    try:
        head = client.read_head(
            idle_timeout=None if first else egress_relay.RELAY_IDLE_TIMEOUT)
    except ReadTimedOut as exc:
        if exc.idle:
            # Not a drop and not counted as one: an idle kept-alive
            # connection reaching its bound is this end closing a
            # connection nobody was using. Logged all the same -- the guest
            # sees a closed connection either way, and an operator staring
            # at one wants to know which end let go and why.
            insp.log(f"close {where} reason='{exc}'")
            return False
        insp.counters.record_drop(DROP_TIMED_OUT)
        rec.set(decision="drop", reason=DROP_TIMED_OUT)
        insp.log(f"drop {where} reason='timed out: {exc}'")
        return False
    except RequestUnreadable as exc:
        insp.counters.record_drop(DROP_UNREADABLE_REQUEST)
        rec.set(decision="drop", reason=DROP_UNREADABLE_REQUEST)
        insp.log(f"drop {where} reason='unreadable request: {exc}'")
        return False
    if not head:
        return False                # the guest closed between requests
    # A head exists, so the record's clock restarts here: on a kept-alive
    # connection the pass began when the previous response finished.
    rec.started()
    try:
        req = parse_request(head, scheme)
    except RequestUnreadable as exc:
        # No 403 here and no host in the line: this is not a policy
        # decision, and reporting it as one would put a name we could not
        # read into the same bucket as a name we refused.
        insp.counters.record_drop(DROP_UNREADABLE_REQUEST)
        # No host, no method and no path: the head is exactly what could
        # not be read, so the record says so by carrying none of them
        # rather than by guessing at a name out of bytes we refused.
        rec.set(decision="drop", reason=DROP_UNREADABLE_REQUEST, status=400)
        insp.log(f"drop {where} reason='unreadable request: {exc}'")
        send_response(conn, 400, "Bad Request", str(exc), close=True)
        return False
    if pinned_host is not None and req.host != pinned_host:
        # Not a policy refusal and deliberately not counted as one: the name
        # may well be allowlisted. What it is not is the name THIS session
        # was established for, and 421 is the answer HTTP already has for
        # that -- the client reopens to the right origin and is checked
        # there on its own merits.
        #
        reason = _binding_reason(insp, req.host)
        insp.counters.record_drop(reason, req.host)
        rec.request(req)
        rec.set(decision="drop", reason=reason, status=421)
        listed = " (allowlisted)" if (
            reason is DROP_MISDIRECTED_LISTED) else ""
        insp.log(f"drop {where} host={req.host} reason='host does not "
                            f"match the server name {pinned_host}{listed}'")
        return _refuse(
            client, conn, req, 421, "Misdirected Request",
            f"this session was established for {pinned_host}, not "
            f"{req.host}")
    if not insp.policy.admits(req.host):
        # A STATUS is speakable on 80, unlike 443 -- there is no session to
        # be inside, so the guest gets a real 403 rather than a connection
        # that closed for reasons it cannot see. What it does NOT get is a
        # body naming the host or the allowlist: that reason is recorded for
        # the operator (the journal line and the record below), never handed
        # to the guest, whose only use for it is to learn it is filtered.
        insp.counters.record_drop(DROP_NOT_ALLOWLISTED, req.host)
        rec.request(req)
        rec.set(decision="drop", reason=DROP_NOT_ALLOWLISTED, status=403)
        insp.log(f"drop {where} host={req.host} reason='not allowlisted'")
        return _refuse(
            client, conn, req, 403, "Forbidden", POLICY_REFUSAL_BODY)
    if not insp.policy.permits(req.host, req.method, req.path):
        # A SECOND refusal and a second reason, never merged into the one
        # above -- FOR THE OPERATOR. The host IS allowlisted (written down on
        # purpose) and what was refused is the method or the path; an
        # operator with one bucket for the two reads a working allowlist as a
        # broken one, so the journal and the record keep them apart. The
        # guest is told neither: it gets the same generic 403 as an unlisted
        # host, because the one thing it could do with the distinction is
        # learn it is behind a policy and start mapping the shape of it.
        insp.counters.record_drop(DROP_NOT_PERMITTED, req.host)
        rec.request(req)
        rec.set(decision="drop", reason=DROP_NOT_PERMITTED, status=403)
        insp.log(f"drop {where} host={req.host} method={req.method} "
                            f"reason='not permitted by policy'")
        return _refuse(
            client, conn, req, 403, "Forbidden", POLICY_REFUSAL_BODY)
    # An HTTP/1.0 request is the one we tell the origin to close (see
    # rebuild_request), so its upstream is opened for this request alone
    # and is not put in the map for the next one to find.
    transient = req.version == "HTTP/1.0"
    rec.request(req)
    # THE BROKER BRANCH (ADR 007). An authorised request to a host whose
    # policy entry names a credential goes to this workload's own broker
    # instance instead of to the origin -- and that is the whole of the
    # difference, because `Upstream.connection_for` takes the dial as an argument.
    # Everything downstream is the same: the head that goes up is
    # the same `rebuild_request(req)`, carrying the same `Host`, which is
    # half of the broker's `(uid, Host)` key. The other half is the uid on
    # the far end of the socket, which is this process's own and is not
    # ours to send.
    #
    # The credential NAME is recorded and the material is not seen. It also
    # decides nothing about the request: policy was applied above, on the
    # same terms as an unbrokered host, so a credential cannot widen what a
    # guest may ask for -- it only changes who attaches the authorisation.
    credential = insp.policy.credential_for(req.host)
    if credential:
        rec.set(credential=credential)
    try:
        up = insp.upstream.connection_for(
            req.host, upstreams, reusable=not transient,
            # A KEY OF ITS OWN FOR THE BROKER LEG, and this is not tidiness.
            # `_serve_terminated` seeds the pool with the ORIGIN connection
            # it opened before the request was read -- keyed by the host --
            # so a brokered request found that entry, was handed the origin,
            # and `dial` was never called. The credential was recorded as
            # attached and was not: the request reached the provider
            # carrying whatever the guest held, which for a real client is
            # the placeholder. No unit test sees it, because none seeds
            # the pool the way a terminated session does.
            key=BROKER_UPSTREAM_KEY + req.host if credential else req.host,
            dial=insp.upstream.dial_broker if credential
            else (insp.upstream.dial_tls if pinned_host is not None
                  else insp.upstream.dial_cleartext))
    except ssl.SSLError as exc:
        # BEFORE the OSError arm: ssl.SSLError IS an OSError, so a single
        # generic arm reported a certificate that would not verify as a
        # host that could not be reached -- and then paid for a second
        # getaddrinfo to decide which flavour of unreachable to call it.
        # The front of a terminated connection has always split these two
        # (see _serve_tls_inspect); this is the REDIAL, which reaches the
        # same verifying dial by way of an origin that answered
        # `Connection: close` or an HTTP/1.0 exchange, and it deserves the
        # same sentence -- the one naming the host's own trust anchor,
        # which is the only thing an operator can act on.
        reason, text = tls_failure(req.host, exc)
        insp.counters.record_drop(reason, req.host)
        rec.set(decision="drop", reason=reason, status=502)
        insp.log(f"drop {where} host={req.host} "
                            f"reason='{reason}: {exc}'")
        return _refuse(client, conn, req, 502, "Bad Gateway", text)
    except OSError as exc:
        # THE BROKER LEG GETS ITS OWN REASON AND ITS OWN SENTENCE, and does
        # NOT go through dial_failure_reason: that helper re-resolves the
        # HOST to decide whether the wildcard trap fired, and the name that
        # failed here was never dialled -- a loopback address on this box
        # was. Running it would attribute a dead broker to whatever
        # `req.host` happens to resolve to, which is the most confusing
        # possible answer, and would pay a synchronous getaddrinfo for it.
        if credential:
            reason = DROP_BROKER_UNREACHABLE
            text = (f"{req.host} is brokered and this workload's "
                    f"credential broker did not answer ({exc}). The "
                    f"request was NOT sent to {req.host}: check "
                    f"workload-<name>-broker.service on the host, and "
                    f"check audit.log -- a missing SELinux rule on this "
                    f"dial presents exactly like a broker that is down.")
        else:
            reason = dial_failure_reason(
                req.host, insp.policy.internal)
            text = f"{req.host} could not be reached: {exc}"
        insp.counters.record_drop(reason, req.host)
        rec.set(decision="drop", reason=reason, status=502)
        insp.log(f"drop {where} host={req.host} "
                            f"reason='{reason}: {exc}'")
        return _refuse(client, conn, req, 502, "Bad Gateway", text)
    if credential:
        # After the dial and not before it: a request whose broker never
        # answered carried no credential, and counting it above would
        # report a key as used on a request that reached nobody.
        insp.counters.record_credentialed(req.host, credential)
    # Authorised: the socket leaves the decision timeout and joins the
    # relay's. Everything from here is transfer -- a body up, a body back
    # -- and transfer is bounded by idleness, not by a five-second clock
    # that would cut a large download at the first pause on either end and
    # count it as `relay failed`. The upstream socket is set to the same
    # number where it is opened, and the TLS plane's splice sets both.
    conn.settimeout(egress_relay.RELAY_IDLE_TIMEOUT)
    # The address a policy NAME became, resolved by this process and known
    # to nobody else -- §11's other half of the join.
    rec.dialled(up.sock)
    try:
        try:
            up.sock.sendall(rebuild_request(req))
        except OSError as exc:
            # THE HEAD NEVER LEFT, which makes this a refusal like the dial
            # failures above rather than a relay that broke in the middle:
            # the guest's body is still unread and no byte of a response has
            # been written, so `_refuse` can drain and answer exactly as it
            # does there. Falling through to the relay's handler instead --
            # which is what this did -- ends the connection with `return
            # False` and gives the guest a SILENT CLOSE, the one outcome
            # _serve_tls_inspect argues against at length: a guest told "no"
            # by a dead socket cannot tell a refusal from the host being
            # down, and the CA is held precisely so it can be told.
            #
            # IT IS ALSO WHERE A CLIENT-CERTIFICATE ORIGIN LANDS, SOMETIMES,
            # and that is why the body names the possibility. Under TLS 1.3
            # a CertificateRequest is answered after the handshake
            # completes, so the same origin either fails at the dial with
            # `CERTIFICATE_REQUIRED` -- named exactly, by
            # egress_upstream.tls_failure -- or resets the connection here, with
            # nothing left to read the reason from. Which one happens is
            # decided inside the peer's stack and is not ours to make
            # deterministic. It presents as a flaky test rather than as a
            # guest being told nothing.
            #
            # The COUNTER stays `relay failed`. A bare reset is genuinely
            # ambiguous -- an origin that crashed or closed an idle socket
            # produces the same errno -- and minting a client-certificate
            # figure out of it would misfile those. The sentence names the
            # possibility without asserting it, which is the same choice the
            # TLS 1.2 arm of tls_failure makes for the same
            # reason.
            insp.counters.record_drop(DROP_RELAY_FAILED, req.host)
            rec.set(decision="drop", reason=DROP_RELAY_FAILED, status=502)
            insp.log(f"drop {where} host={req.host} "
                                f"reason='relay failed before the head was sent: "
                                f"{exc}'")
            return _refuse(
                client, conn, req, 502, "Bad Gateway",
                f"the request to {req.host} was not delivered: the "
                f"upstream connection failed before its head could be "
                f"sent ({exc}). If {req.host} requires a client "
                f"certificate, this is one of the two ways that arrives -- "
                f"under TLS 1.3 the demand can land after the handshake "
                f"succeeded, leaving a reset rather than a named alert -- "
                f"and it must then be spliced: set tls = \"splice\" for "
                f"this workload so the guest's own handshake reaches "
                f"{req.host}.")
        if req.expects_continue:
            # AFTER policy, and by us. The natural implementation answers a
            # continue while reading the head, which grants it on a request
            # about to be refused. Expect is not forwarded upstream either:
            # waiting for the origin's own interim answer means reading the
            # response before the body has been sent, and the two waits
            # deadlock.
            conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
        # The body goes up before the response comes back, in that order
        # and not multiplexed. An origin that answers WITHOUT reading the
        # body it was sent -- an early 413, a redirect -- stops draining,
        # this send blocks, and the connection dies on RELAY_IDLE_TIMEOUT
        # rather than on the answer that was already waiting. Named rather
        # than fixed: full duplex here means a second thread or a state
        # machine per connection, and the failure is bounded, loud and rare
        # where a half-built pump would be none of the three.
        copy_body(client, up.sock, req.framing)
        insp.counters.record_forward()
        rec.set(decision="forward")
        insp.log(f"forward {where} host={req.host} method={req.method}")
        keep = _relay_response(insp, up, client, conn, req, where, rec)
        if credential and rec.fields.get("status") in (401, 403):
            # §11's second named failure, and the reason it is counted
            # rather than merely documented: every layer of ours succeeded.
            # The policy admitted the host, the broker attached material,
            # the origin answered -- and it answered "no". Read from the
            # record, not from a second parse: `_relay_response` has
            # already put the FINAL status there, past any interim head,
            # so there is one definition of what the origin said.
            insp.counters.record_credential_unauthorized()
        return keep
    except (RequestUnreadable, OSError) as exc:
        insp.counters.record_drop(DROP_RELAY_FAILED, req.host)
        # OVERWRITES the `forward` set above, and follows the counter,
        # which does the same. A relay that broke mid-exchange is counted
        # as a drop, so recording it as a forward would put the record and
        # every figure derived from it into disagreement. `status` survives
        # if a head had already come back, which is how a reader tells a
        # relay that failed before the answer from one that failed after.
        rec.set(decision="drop", reason=DROP_RELAY_FAILED)
        insp.log(f"drop {where} host={req.host} "
                            f"reason='relay failed: {exc}'")
        return False
    finally:
        # A transient upstream is in no map, so serve_cleartext's own
        # close over `upstreams` will never reach it. Closed here, on every
        # path out of the exchange, or it leaks a host socket owned by the
        # workload uid for as long as the client connection lives.
        if transient:
            try:
                up.sock.close()
            except OSError:
                pass


def _relay_response(insp, up, client, conn, req, where="", rec=None):
    """Relay one response. True if the connection may carry another.

    `rec` is the caller's record, given the status as soon as one is
    parsed. Set here rather than returned, because the interesting statuses
    are the ones on paths that do not return normally: a 101 leaves through
    the upgrade relay, and an interim head is replaced by the final one.

    The head goes across verbatim, which is not the rule the REQUEST
    direction follows -- there the framing we emit is the framing we
    computed. The asymmetry is the point: the framing being defended
    against is the GUEST's, and this head was written by the host its
    policy authorised. It is parsed all the same, because where the body
    ends is what says whether the next request can be read from here --
    but by _split_response_head, which is lenient where the request parser
    refuses, so that being stricter than the web cannot turn an authorised
    request into a dead connection.
    """
    interim = 0
    while True:
        head = up.read_head()
        if not head:
            raise RequestUnreadable("the upstream closed before answering")
        start, headers = _split_response_head(head)
        fields = start.split(" ")
        if len(fields) < 2 or not _is_count(fields[1]):
            raise RequestUnreadable(
                f"status line {start!r} is not one we read")
        status = int(fields[1])
        if rec is not None:
            # Every head, so an interim is overwritten by the final one and
            # a 101 is recorded as itself.
            rec.set(status=status)
        framing = response_framing(status, req.method, headers)
        conn.sendall(head)
        if status == 101:
            # THE REQUEST WAS POLICED; THE STREAM IS NOT. An `Upgrade:` is
            # an ordinary HTTP request and was authorised as one -- and
            # after the origin accepts it, what flows is whatever protocol
            # the two of them agreed on, which this does not parse and does
            # not pretend to. Narrower than it sounds: an upgraded
            # connection cannot carry further HTTP requests, so unlike the
            # keep-alive case there is no per-request re-authorisation being
            # lost. Logged all the same, because "policy stopped applying
            # here" is not something an operator should have to infer from
            # a byte count.
            insp.log(f"upgrade {where} host={req.host} "
                                f"reason='switched protocols; per-request policy no "
                                f"longer applies to this connection'")
            # Anything EITHER side read past the message boundary belongs
            # to the tunnel and goes across before the relay starts, or the
            # stream is delivered out of order. Both directions, which for
            # one rung this did not do: the guest's own surplus stayed in
            # its _Stream buffer and was never sent, so a client that
            # pipelined its first frame behind the upgrade request -- which
            # is legal, and which some clients do -- lost exactly those
            # bytes into a tunnel that then looked merely stalled.
            pending_up = up.take_buffered()
            if pending_up:
                conn.sendall(pending_up)
            pending_client = client.take_buffered()
            if pending_client:
                up.sock.sendall(pending_client)
            return _relay_upgraded(conn, up.sock)
        _note_redirect(insp, status, headers, req, where)
        if 100 <= status < 200:
            # Interim; the real response follows -- but not indefinitely.
            # Every other guest- or peer-driven loop in this file carries a
            # ceiling, and this one is driven by an authorised origin that
            # can hold a guest's connection, and one of MAX_CONNECTIONS
            # slots, by sending interim heads forever. A real exchange
            # sends one (a 100, or a 103 with early hints); the bound is
            # generous enough that no honest origin meets it.
            interim += 1
            if interim > INTERIM_MAX:
                raise RequestUnreadable(
                    f"the upstream sent more than {INTERIM_MAX} interim "
                    f"responses without a final one")
            continue
        break
    copy_body(up, conn, framing)
    # An origin that ends its connection ends the guest's too, rather than
    # this quietly opening a replacement: the guest asked one question and
    # got one answer, and a reopen would hide a flapping upstream behind a
    # connection that looks healthy.
    closing = framing.kind == "close" or "close" in {
        t.strip() for v in _get_all(headers, "connection")
        for t in v.lower().split(",")}
    return not closing and not req.wants_close


def _relay_upgraded(conn, up_sock):
    """Move an upgraded connection's bytes both ways, then end it."""
    relay(conn, up_sock)
    return False


def _note_redirect(insp, status, headers, req, where):
    """Log a redirect that leaves the allowlist. Decides nothing.

    THIS IS THE ONLY POINT IN THE SYSTEM WHERE BOTH NAMES ARE KNOWN
    TOGETHER. The guest follows a redirect by opening a NEW connection,
    which is redirected, resolved by our responder and checked on its own
    merits -- so the refusal, when it comes, names the target and has no way
    to say what sent the guest there. Without this line a 403 for a CDN host
    is unattributable to the site the operator actually configured.
    """
    if not 300 <= status < 400:
        return
    for value in _get_all(headers, "location"):
        target, path = redirect_target(value)
        if not target:
            continue
        # `admits`, not a `hosts` match: a redirect to a host named only
        # by a `policy` entry is allowlisted, and a note saying otherwise
        # would send the operator to add a name that is already there.
        if not insp.policy.admits(target):
            insp.log(f"note {where} host={req.host} reason='redirected to "
                                f"{target}, which is not allowlisted'")
        elif path is not None and insp.policy.governs(target):
            _note_policy_redirect(insp, status, target, path, req, where)


def _note_policy_redirect(insp, status, target, path, req, where):
    """Log a redirect an allowlisted target's own policy will refuse.

    The second half of the same diagnosability problem: the operator
    allowlisted the target, so the note above stays silent, and the guest's next connection ends in
    `not permitted by policy` naming a host and a path with nothing
    connecting either to the site that sent it there. This is still the
    only point where both names are known together.

    WHICH METHOD THE GUEST WILL USE IS NOT OURS TO DECIDE, so where the
    readings differ this says nothing rather than guessing. 307 and 308
    preserve the method (RFC 9110 §15.4.8-9). 303 mandates GET. 301 and 302
    are the awkward pair: the RFC preserves the method and essentially every
    real client rewrites a non-GET to GET, so both are live readings and the
    note is emitted only if the entry refuses BOTH. Over-accepting in the
    silent direction on purpose -- a missing note costs an operator the
    search they would have done anyway, and a wrong one sends them to edit
    a rule that was never going to fire.

    A SAME-HOST redirect gets nothing from here, and that is not an
    oversight: a relative Location names no host, and a 403 for a path on
    the host the operator configured already names the host they configured.
    Nothing is unattributable, so there is nothing to attribute.
    """
    if status in (307, 308):
        methods = (req.method,)
    elif status == 303:
        methods = ("GET",)
    elif status in (301, 302):
        methods = (req.method, "GET")
    else:
        # 300, 304, 305: a Location here does not describe a request the
        # guest is about to repeat, so there is no verdict to predict.
        return
    if any(insp.policy.permits(target, method, path)
           for method in set(methods)):
        return
    insp.log(f"note {where} host={req.host} reason='redirected to "
                        f"{target}{path}, which its [[vm.network.policy]] entry does "
                        f"not permit'")


def _binding_reason(insp, host):
    """Which of the two §4 binding figures a mismatched name lands in.

    `admits` decides only WHICH FIGURE; it does not admit the request,
    which is refused either way and refused BEFORE the allowlist is
    consulted. The two answers are the attack and the ordinary client --
    a guest reusing a session it was granted to reach a name it never was,
    against a client coalescing two names it was given -- and §4 asks for a
    count an operator can read at a glance, which one bucket for both is
    not.

    Asked here rather than left to whoever reads the figure: by then the
    connection is gone and the name with it. The log line carries the name
    either way; the figure is what has to arrive already split.
    """
    if insp.policy.admits(host):
        return DROP_MISDIRECTED_LISTED
    return DROP_MISDIRECTED


def _refuse(client, conn, req, status, reason, text):
    """Answer a request we will not relay. True if the connection lives.

    The body is drained BEFORE the answer, or the connection is closed.
    Answering without draining leaves the next request read out of the
    middle of this one's body -- the same smuggle, arriving through the
    error path, which is the path every test exercises least.

    `Expect: 100-continue` is the case that cannot be drained: the guest is
    waiting for a continue that policy has just decided not to give, so
    there is no body to read to the end of. That connection is closed.
    """
    keep = not req.wants_close and not req.expects_continue
    if keep:
        keep = drain(client, req.framing)
    send_response(conn, status, reason, text, close=not keep)
    return keep
