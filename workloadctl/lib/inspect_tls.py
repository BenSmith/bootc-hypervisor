"""
inspect_tls: the TLS plane -- peek, match, then splice or terminate.

A connection on 443 has its ClientHello read and its server name matched
against this workload's `hosts`. What happens next is the mode the policy
names, and every decision is made against the workload's Inspection
(lib/inspect_scope.py), which every function here takes first.

TWO TLS MODES, AND THE PEEK IS THE SAME PEEK

`tls = "splice"` decrypts nothing: the bytes read to find the name are the bytes
replayed upstream, verbatim, headers included. A ClientHello reconstructed from
a parse is a different ClientHello — different extension order, different
GREASE, a different JA3 — so the raw buffer is what travels and the parse is
only ever consulted for a decision.

`tls = "inspect"` (the default) TERMINATES. The same peek takes the
same decision, and then this process completes the guest's handshake itself with
a leaf minted by the workload's own CA, opens a separately verified session to
the origin, and authorises every REQUEST inside on the same matcher the
cleartext plane uses. The allowlist means the same thing on both planes only
under termination: spliced, a name is checked once at the front of a connection
whose contents nothing can see.

The reader itself is `lib/tls_hello.py`, and so is why the inspect path
peeks with MSG_PEEK where the splice path consumes.

BUMP-THEN-ANSWER

Every refusal a terminated connection carries is delivered THROUGH a completed
handshake, denials included: mint, complete the guest's handshake, then answer
403 or 502 in plain HTTP. Failing the handshake instead gives the guest an
opaque certificate error indistinguishable from the host being down. The
answer is a status and a generic body; the reason is the operator's, and goes
to the journal.
"""

import socket
import ssl

from inspect_document import normalise_hostname
from egress_ca import LeafRefused
from egress_mint import MintFailed, MintThrottled
from egress_plane import TLS
from egress_record import (
    DROP_MINT_FAILED, DROP_NOT_ALLOWLISTED, DROP_NOT_H2, DROP_NOT_HTTP,
    DROP_NOT_HTTP_POLICY, DROP_NO_NAME, DROP_RELAY_FAILED, DROP_THROTTLED,
    Record,
)
from egress_relay import relay
import egress_relay
from egress_upstream import (
    ALPN_H2, UPSTREAM_ALPN, dial_failure_reason, tls_failure,
)
from h2_framing import H2_PREFACE, H2Framing, NotH2
from http_framing import (
    RequestUnreadable, _Stream, is_http_request_start, send_response,
)
from http_target import SCHEME_HTTPS
from inspect_http import POLICY_REFUSAL_BODY, UPSTREAM_FAILURE_BODY
import inspect_http
from tls_hello import HelloUnreadable, read_client_hello


def serve_tls(insp, conn, where):
    """Peek, match, and then act by mode.

    The peek and the decision are the same on both modes and are taken here,
    once. What differs is everything after: `splice` replays the guest's own
    bytes at the origin and never sees inside; `inspect` completes the
    guest's handshake itself and authorises each request in it.

    The outcomes are logged with DISTINCT reasons, never merged: a hello
    that could not be read, a name that is on no list, and an upstream that
    could not be reached fail the guest's connection identically, and an
    operator who cannot tell them apart cannot tell a policy decision from a
    broken resolver from something speaking a non-TLS protocol at the TLS
    port.
    """
    # Whether this LISTENER can terminate at all, which is the mode. Which
    # of its connections it actually terminates is a per-host question
    # taken below, once there is a name -- so the hello is PEEKED whenever
    # the mode allows termination, not only when this connection will get
    # it. A consuming read here would leave a spliced host's own hello
    # already off the socket, and the splice property is that the origin
    # completes its handshake with the guest's bytes.
    inspect = insp.policy.tls == "inspect"
    if inspect and insp.minter is None:
        # Unreachable through the entrypoint, which refuses to start in
        # this state.
        # Kept anyway and LOUD: a Listener that terminated without a minter
        # would fail every guest handshake with an opaque certificate error,
        # which is the one failure this whole path exists to avoid, and a
        # test that constructed one would otherwise get it silently.
        insp.counters.record_drop(DROP_MINT_FAILED)
        insp.connection_record(where, "terminate", decision="drop",
                                          reason=DROP_MINT_FAILED)
        insp.log(f"drop {where} reason='could not mint a leaf: this "
                            f"listener has no minter'")
        return
    try:
        raw, hello = read_client_hello(conn, peek=inspect)
    except HelloUnreadable as exc:
        insp.counters.record_unreadable_hello()
        insp.counters.record_drop(DROP_NO_NAME)
        insp.connection_record(where, "terminate", decision="drop",
                                          reason=DROP_NO_NAME)
        insp.log(f"drop {where} reason='no readable name: {exc}'")
        return
    if not hello.server_name:
        # The tripwire runs BEFORE the drop and with on_a_list False: a
        # hello that withholds SNI matched nothing, and if it also carried
        # ECH that is the strongest form of the signal, not an absent one.
        insp.counters.record_hello(hello, False)
        insp.counters.record_drop(DROP_NO_NAME)
        insp.connection_record(where, "terminate", decision="drop",
                                          reason=DROP_NO_NAME)
        insp.log(f"drop {where} reason='no readable name: the "
                            f"ClientHello carries no server_name extension'")
        return
    host = normalise_hostname(hello.server_name)
    # `admits`, not a bare `hosts` match: a [[vm.network.policy]] entry
    # allowlists its own host, so a workload whose entire allowlist is
    # written as policy entries would otherwise lose every connection at
    # the front, before the request its rules were written about exists.
    allowed = insp.policy.admits(host)
    insp.counters.record_hello(hello, allowed)
    # THE ALLOWLIST DECISION COMES FIRST, and the parenthesisation is what
    # says so. A name on the splice list and on no allowlist is refused,
    # not spliced -- and on a terminating listener it is refused the way
    # every other denial is, bump-then-403, rather than by a close the
    # guest cannot read. The reverse order looks equivalent and is not: a
    # `splice` PATTERN can cover names `hosts` does not (`*.example.com`
    # spliced, one name of it allowlisted), and validation cannot catch
    # that because the pattern does match allowlisted names.
    if inspect and not (allowed and insp.policy.splices(host)):
        _serve_tls_inspect(insp, conn, where, host, allowed)
        return
    if not allowed:
        insp.counters.record_drop(DROP_NOT_ALLOWLISTED, host)
        insp.connection_record(where, "splice", host=host,
                                          decision="drop",
                                          reason=DROP_NOT_ALLOWLISTED)
        insp.log(f"drop {where} host={host} reason='not allowlisted'")
        return
    # Dial the NAME, never an address (§7.4). The address the guest aimed
    # at is this inspector's own listener anyway -- the redirect already
    # rewrote it -- so there is nothing to forward even if forwarding one
    # were wanted, and resolving here is what makes the destination the one
    # the policy authorised rather than one the guest chose.
    try:
        upstream = socket.create_connection(
            (host, TLS.guest_port), timeout=egress_relay.CONNECTION_TIMEOUT)
    except OSError as exc:
        reason = dial_failure_reason(host, insp.policy.internal)
        insp.counters.record_drop(reason, host)
        insp.connection_record(where, "splice", host=host,
                                          decision="drop", reason=reason)
        insp.log(f"drop {where} host={host} reason='{reason}: {exc}'")
        return
    try:
        # The buffered hello, unmodified and before anything else. This is
        # the splice property: the server sees the guest's own ClientHello,
        # so the handshake it completes is with the guest, and this process
        # never holds a key to it.
        #
        # Nothing to replay when the hello was PEEKED -- a per-host splice
        # on a terminating listener -- because the bytes are still on the
        # socket and the relay below reads them first. Sending `raw` there
        # too would deliver the hello TWICE and the origin would fail the
        # handshake on the duplicate, which presents as the spliced host
        # being broken by the exemption that was supposed to fix it.
        if not inspect:
            upstream.sendall(raw)
        insp.counters.record_splice()
        insp.log(f"splice {where} host={host}"
                            f"{' per-host' if inspect else ''}")
        rec = Record(insp.record, where, "splice", host=host)
        rec.dialled(upstream)
        rec.set(decision="forward")
        try:
            relay(conn, upstream)
        finally:
            # A NAMED EXEMPTION SHOULD BE VISIBLE IN THE RECORD AS ONE.
            # There is no path, no method and no status here and there
            # never will be -- that is what splicing means -- so the line
            # says which host was exempted and for how long, and a reader
            # who finds no requests for that host has this to find instead.
            rec.emit()
    finally:
        upstream.close()


def _serve_tls_inspect(insp, conn, where, host, allowed):
    """Terminate one connection: decide, dial, mint, handshake, serve.

    THE ORDER IS THE DESIGN. The upstream leg is established BEFORE the
    guest's handshake completes, so nothing here ever sniffs the guest to
    learn what to say upstream -- the protocol offered on both legs comes
    from UPSTREAM_ALPN, which is configuration. And the mint comes after the
    dial, so a host that cannot be reached or cannot be verified costs a
    leaf only because the REFUSAL is delivered through one.

    A BROKERED HOST HAS NO LEG TO ESTABLISH, and that does not weaken the
    invariant: the offer is still configuration, it is just always
    `http/1.1`. The request goes to this workload's broker, which is dialled
    per request, so an origin connection opened here would be verified and
    never written to -- and would make the ORIGIN's reachability and
    certificate a prerequisite for a request that never reaches it. See the
    branch below.

    EVERY OUTCOME IS BUMPED, denials included. A guest told "no" by a failed
    handshake is told nothing it can distinguish from the host being down;
    told "no" by a 403 or 502 through a chain it trusts, it knows it was
    answered rather than cut off, and has something to put in a log. That is
    the whole argument for holding a CA at all, and it applies with more
    force to the refusals than to the successes.
    """
    upstream = None
    refusal = None            # (drop reason, status, phrase, body text)
    # THE OFFER IS CHOSEN FROM CONFIGURATION, BEFORE EITHER HANDSHAKE, and
    # §6 is why there is no alternative: the upstream leg must be up before
    # a leaf is minted, so nothing here can sniff the guest and then speak
    # whatever came back. With the non-HTTP fallback gone there is also
    # nothing to sniff -- the only thing that ever needed a protocol
    # discovered after the fact was the relay path §8 deleted.
    h2 = insp.policy.speaks_h2(host)
    # A BROKERED HOST IS NOT DIALLED HERE AT ALL, and the §6 invariant above
    # survives that: the offer is still chosen from configuration, it is
    # simply always `http/1.1` -- the broker leg is cleartext HTTP/1.1, and
    # `credential` with `http2` on one host is a validation error, so there
    # is no h2 session to relay and never was.
    #
    # WHAT THE DIAL WAS DOING FOR A BROKERED HOST WAS NOTHING GOOD. The
    # request goes to the broker, so the origin connection was opened,
    # verified, put in the pool and never written to. Its three purposes all
    # belong to the origin: hold the upstream leg open before the mint (the
    # broker leg is opened per request and has its own reason), check that
    # the origin took an h2 offer (there is no h2 here), and fail early if
    # the origin is unreachable. That last one is the harm: it made the
    # ORIGIN's reachability and certificate a prerequisite for a request
    # that never goes there, and reported the failure against the origin's
    # name. A provider having an outage failed brokered requests that would
    # have reached the broker fine, and a private origin behind a CA this
    # host does not hold failed them permanently.
    #
    # The mint does not need it either: `insp.minter.leaf(host, ...)` takes
    # the name and nothing else.
    brokered = allowed and insp.policy.credential_for(host) is not None
    if brokered:
        h2 = False
    if not allowed:
        # Generic body, like every policy denial (POLICY_REFUSAL_BODY): the
        # reason is the operator's, carried by the record_drop this refusal
        # triggers, and is not handed to the guest.
        refusal = (DROP_NOT_ALLOWLISTED, 403, "Forbidden",
                   POLICY_REFUSAL_BODY)
    elif brokered:
        pass  # no upstream leg at connection time; see above
    else:
        try:
            upstream = insp.upstream.dial_tls(
                host, ALPN_H2 if h2 else UPSTREAM_ALPN)
        except ssl.SSLError as exc:
            reason, text = tls_failure(host, exc)
            refusal = (reason, 502, "Bad Gateway", text)
        except OSError as exc:
            reason = dial_failure_reason(host, insp.policy.internal)
            refusal = (reason, 502, "Bad Gateway",
                       f"{host} could not be reached: {exc}")
        else:
            # AND THE ORIGIN HAS TO HAVE TAKEN THE OFFER. ALPN_H2 says at
            # length that an offer binds nobody: a server speaking only
            # HTTP/1.1 completes this handshake and selects NOTHING, with
            # no alert of any kind. Unchecked, the guest's connection
            # preface is relayed into an HTTP/1.1 server and the session
            # fails as unattributable garbage -- while DROP_NOT_H2 cannot
            # fire from the other side, because the guest is speaking h2
            # perfectly and it is the ENTRY that is wrong.
            #
            # The guest half of this key is checked exhaustively -- preface,
            # first frame, framing, alignment -- precisely so that
            # [[vm.network.http2]] means SPEAKS H2 rather than EXEMPT.
            # Leaving the origin half unchecked settles that question on one
            # side of a relay whose entire content is the other side's
            # protocol, and hands the operator a broken host with no figure
            # naming it. One call, and it is the same reason and the same
            # remedy as every other way this key can be wrong.
            if h2 and upstream.sock.selected_alpn_protocol() != "h2":
                # Closed HERE rather than left to the refusal branch, which
                # has never had an upstream to close: every other refusal
                # above is taken before the dial or by its failure. Keeping
                # that invariant true is cheaper than a second close on a
                # path where a leak is one verified socket per connection,
                # owned by the workload uid, in a process the guest dials
                # at will.
                upstream.sock.close()
                upstream = None
                refusal = (
                    DROP_NOT_H2, 502, "Bad Gateway",
                    f"{host} is in [[vm.network.http2]] but did not select "
                    f"h2 for this connection, so there is no HTTP/2 session "
                    f"to relay. Either it does not speak h2 -- drop the "
                    f"entry and let it be inspected as HTTP/1.1 -- or it "
                    f"cannot take this workload's CA, and belongs in "
                    f"[[vm.network.splice]]")
    leaf = None
    try:
        # `denied` picks the CACHE, not the disposition: an allowlisted host
        # that was merely unreachable keeps its leaf in the working set,
        # because the next connection to it is expected to succeed and
        # should not pay for a mint. Only a name policy refused goes in the
        # denial set, which is the set a flood can fill.
        leaf = insp.minter.leaf(host, denied=not allowed)
    except MintThrottled:
        # Nothing legible can be delivered without a leaf, so this is the
        # one outcome that closes on the guest. It is reachable only after
        # the bucket has been emptied, which honest traffic does not do.
        insp.counters.record_drop(DROP_THROTTLED, host)
        insp.connection_record(where, "terminate", host=host,
                                          decision="drop", reason=DROP_THROTTLED)
        insp.log(f"drop {where} host={host} reason='mint rationed: the "
                            f"leaf bucket is empty'")
        return
    except (LeafRefused, MintFailed) as exc:
        insp.counters.record_drop(DROP_MINT_FAILED, host)
        insp.connection_record(where, "terminate", host=host,
                                          decision="drop", reason=DROP_MINT_FAILED)
        insp.log(f"drop {where} host={host} "
                            f"reason='could not mint a leaf: {exc}'")
        return
    finally:
        # The upstream leg is open by now on the allowed path -- except a
        # brokered one, which never opens it -- and every arm above
        # returns. Closed here rather than in each of them, or a mint
        # failure leaks a host socket owned by the workload uid.
        if leaf is None and upstream is not None:
            upstream.sock.close()
    if leaf is None:
        return
    try:
        # `http/1.1` WHENEVER THERE IS A REFUSAL TO DELIVER, even on an
        # http2 host. Every refusal below is an HTTP/1.1 response written
        # into this session, so offering h2 for it would advertise a
        # protocol the next thing we send is not -- and buy nothing, since
        # the connection ends with that answer. The offer costs a
        # cooperating h2 client one fallback and gets it a readable 502
        # instead of a protocol error.
        tls_conn = wrap_guest(
            conn, leaf,
            ALPN_H2 if (h2 and refusal is None) else UPSTREAM_ALPN)
    except (ssl.SSLError, OSError) as exc:
        # The guest rejected the leaf, or went away mid-handshake. The most
        # common real cause is a guest that never got the CA -- an existing
        # instance whose seed predates it, which cloud-init will not revisit.
        #
        # BUT NOT IF THE LEAF IS GONE, and that is worth a branch of its
        # own. A cache eviction unlinks the PEM, so a leaf handed over and
        # then evicted before load_cert_chain opens it fails right here --
        # with an OSError about a path, and the sentence below would send
        # an operator to re-provision a guest whose trust is perfectly
        # fine. The caches are sized so this cannot happen (see
        # DENIAL_CACHE_MAX on the invariant), which is exactly why it must
        # say so if it ever does: it means that sizing is wrong, and no
        # other line would ever tell anyone.
        if not leaf.path.exists():
            insp.counters.record_drop(DROP_MINT_FAILED, host)
            insp.connection_record(where, "terminate", host=host,
                                              decision="drop",
                                              reason=DROP_MINT_FAILED)
            insp.log(f"drop {where} host={host} reason='the leaf minted "
                                f"for this connection was evicted before it could be "
                                f"presented: {exc}. This is a cache-sizing fault, "
                                f"not a trust one -- the leaf cache must hold more "
                                f"entries than there are connection slots'")
            if upstream is not None:
                upstream.sock.close()
            return
        insp.counters.record_drop(DROP_RELAY_FAILED, host)
        insp.connection_record(where, "terminate", host=host,
                                          decision="drop", reason=DROP_RELAY_FAILED)
        # NAMES BOTH SHAPES. "A guest provisioned before this workload had
        # a CA does not trust it and must be re-seeded" is true for a VM
        # instance whose seed predates the CA, and actively misleading for
        # the other case, which has no seed to revisit and no CA route to
        # repair; a sentence naming only the first is wrong half the time.
        # A JVM image is the standing example: `ca_delivery = "env"` delivers all five variables, every
        # one readable inside the container, and the JVM still refuses the
        # leaf -- because its anchors are
        # `cacerts` INSIDE THE IMAGE and no environment variable adds to
        # them, so telling that operator to re-seed names a guest that does
        # not exist. Anything with an embedded store is in this class: a JVM,
        # anything built on rustls with webpki-roots, a statically linked
        # client that never consults the system store.
        #
        # The listener cannot tell the two apart -- it sees a handshake
        # that did not complete and nothing about how the client was built
        # -- so it names both and the remedy each one needs, rather than
        # guessing and being confidently wrong for one substrate.
        insp.log(f"drop {where} host={host} reason='the client did not "
                            f"complete the handshake: {exc}. It did not trust the "
                            f"leaf this workload minted, which has two shapes and "
                            f"they need different remedies. (1) A client that COULD "
                            f"be given the CA and was not: a VM instance seeded "
                            f"before this workload had one, which cloud-init will "
                            f"not revisit and which must be re-seeded; or a "
                            f"container whose ca_delivery route is absent or wrong. "
                            f"(2) A client that CANNOT be given it at all because "
                            f"its trust store is embedded in the image and it reads "
                            f"none of the CA environment variables -- a JVM, or "
                            f"anything on rustls. For (2) there is no CA route to "
                            f"fix: add {host} to [[network.splice]] "
                            f"([[vm.network.splice]] for a VM) so the connection is "
                            f"spliced rather than terminated, or change the image'")
        if upstream is not None:
            upstream.sock.close()
        return
    # wrap_socket DETACHES the socket it was given: `conn` has no fd from
    # here, so _serve's own close is a no-op and this is the only thing that
    # closes the guest's connection. Missing it leaks one fd per terminated
    # connection in a process the guest can open connections to at will.
    try:
        if refusal is not None:
            reason, status, phrase, text = refusal
            insp.counters.record_drop(reason, host)
            insp.counters.record_bump()
            # THE MOST COMMON DENIAL ON THIS PLANE, and it never reaches
            # inspect_http.serve_request: the decision was taken from the server name
            # before the guest's handshake completed, so there is no
            # request to hang it on. Without this the record's terminated
            # plane holds every allowed request and no refused one.
            insp.connection_record(where, "terminate", host=host,
                                              decision="drop", reason=reason,
                                              status=status)
            insp.log(f"bump {where} host={host} status={status} "
                                f"reason='{reason}: {text}'")
            # The text is the operator's; the guest gets a generic body.
            _bump_answer(tls_conn, status, phrase,
                         POLICY_REFUSAL_BODY if status == 403
                         else UPSTREAM_FAILURE_BODY)
            return
        insp.counters.record_termination()
        insp.log(f"terminate {where} host={host}"
                            f"{' h2' if h2 else ''}")
        if h2:
            _serve_h2(insp, tls_conn, where, host, upstream)
        else:
            serve_terminated(insp, tls_conn, where, host, upstream)
    finally:
        try:
            tls_conn.close()
        except OSError:
            pass


def _bump_answer(tls_conn, status, phrase, text):
    """Deliver a refusal inside a handshake we just completed.

    The guest's request is read first and thrown away. Not for anything in
    it -- the decision was taken from the server name before this socket was
    ever wrapped -- but because a client that is mid-send when the answer
    arrives and the connection closes reports a broken pipe instead of
    showing the status, and the whole point of bumping was to be legible.
    Bounded by the socket's own timeout, and failure to read one changes
    nothing: the answer goes out either way.
    """
    try:
        _Stream(tls_conn).read_head()
    except (RequestUnreadable, OSError):
        pass
    send_response(tls_conn, status, phrase, text, close=True)


def wrap_guest(conn, leaf, alpn=UPSTREAM_ALPN):
    """Complete the guest's handshake as the origin it dialled.

    A context per connection rather than one cached per name: the expensive
    half of this is the mint, which the working set already avoids, and a
    cache of live SSLContexts keyed by name would have to be invalidated by
    the same renewal the leaf cache handles -- two evictions that must agree
    about one certificate.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(leaf.path))
    ctx.set_alpn_protocols(list(alpn))
    return ctx.wrap_socket(conn, server_side=True)


def _serve_h2(insp, tls_conn, where, host, upstream):
    """Relay one h2 session at the frame level, refusing what is not h2.

    THE POINT OF THE CHECK IS WHAT THE KEY MEANS. Without it
    [[vm.network.http2]] names a byte relay -- no Host binding, no `paths`,
    no `methods`, and nothing establishing that the bytes are h2 at all --
    so a guest reaches a full policy opt-out on any host somebody listed
    for performance. With it the key means what it says: this host speaks
    h2, and the cost is that `:authority` goes unread. That is still a
    bypass (true fronting stays open here), which is why validation makes
    it carry a written `reason` and refuses it beside a `policy` entry.

    NOTHING IS DECODED. The preface is checked, frame headers are counted,
    and every byte is passed through unaltered -- stream ids untouched, the
    HPACK dynamic table end to end. §16's decoder is an increment on this,
    not a rewrite of it, because frame-header parsing is the half of that
    decoder which lands here.

    THE REMEDY IS THE ONE THE NON-HTTP REFUSAL NAMES, deliberately, because
    it is the same situation one key along: a session this design cannot
    police. `splice` gives the host back its end-to-end TLS and needs no CA
    in the guest.
    """
    # The upstream leg is THIS function's to close from here, exactly as
    # it is serve_terminated's on the other branch. Missing it leaks one
    # verified TLS socket owned by the workload uid per h2 connection, in a
    # process a guest can open connections to at will -- and every
    # assertion about frames and counters passes while it does, because
    # nothing in the exchange is wrong.
    # ONE RECORD FOR THE WHOLE SESSION, because nothing inside it is
    # decoded -- that is what [[vm.network.http2]] means, and §11 names it
    # rather than letting the file be silent about a connection that
    # carried requests. `h2_unrecorded` beside it is the count a reader
    # needs before concluding a guest made no requests.
    rec = Record(insp.record, where, "h2", host=host)
    rec.dialled(upstream.sock)
    try:
        client = _Stream(tls_conn)
        tls_conn.settimeout(egress_relay.CONNECTION_TIMEOUT)
        try:
            preface = client.read_exactly(len(H2_PREFACE))
        except (RequestUnreadable, OSError) as exc:
            insp.counters.record_drop(DROP_NOT_H2, host)
            rec.set(decision="drop", reason=DROP_NOT_H2)
            insp.log(f"drop {where} host={host} reason='not HTTP/2: the "
                                f"connection preface never arrived ({exc}); drop the "
                                f"[[vm.network.http2]] entry for {host}, or move it "
                                f"to [[vm.network.splice]]'")
            return
        if preface != H2_PREFACE:
            insp.counters.record_drop(DROP_NOT_H2, host)
            rec.set(decision="drop", reason=DROP_NOT_H2)
            insp.log(f"drop {where} host={host} reason='not HTTP/2: "
                                f"{preface[:8]!r} is not the connection preface, and "
                                f"{host} is in [[vm.network.http2]]. Either it does not "
                                f"speak h2 -- drop the entry -- or it speaks something "
                                f"this cannot police, and belongs in "
                                f"[[vm.network.splice]] instead'")
            return
        framing = H2Framing()
        # Everything the preface read pulled in past its own 24 bytes. It is
        # already frames, so it is fed to the scanner and forwarded with the
        # preface -- dropping it would lose the guest's opening SETTINGS, which
        # is the frame the scanner exists to check.
        surplus = client.take_buffered()
        try:
            framing.feed(surplus)
        except NotH2 as exc:
            _drop_not_h2(insp, where, host, exc)
            rec.set(decision="drop", reason=DROP_NOT_H2)
            return
        try:
            upstream.sock.sendall(preface + surplus)
            # And anything the ORIGIN sent before we asked. On h2 a server
            # opens with its own SETTINGS immediately, so the client-certificate
            # probe in egress_upstream.early_bytes routinely catches it; stranded in
            # that buffer it would stall the session rather than break it,
            # which is the harder failure to read.
            early = upstream.take_buffered()
            if early:
                tls_conn.sendall(early)
        except OSError as exc:
            insp.counters.record_drop(DROP_RELAY_FAILED, host)
            rec.set(decision="drop", reason=DROP_RELAY_FAILED)
            insp.log(f"drop {where} host={host} "
                                f"reason='relay failed: {exc}'")
            return
        try:
            relay(tls_conn, upstream.sock,
                        on_client_bytes=framing.feed)
        except NotH2 as exc:
            _drop_not_h2(insp, where, host, exc)
            rec.set(decision="drop", reason=DROP_NOT_H2)
            return
        except OSError as exc:
            insp.counters.record_drop(DROP_RELAY_FAILED, host)
            rec.set(decision="drop", reason=DROP_RELAY_FAILED)
            insp.log(f"drop {where} host={host} "
                                f"reason='relay failed: {exc}'")
            return
        # The session ran. Recorded as a forward and counted as a blind
        # spot in the same breath, because both are true of it.
        rec.set(decision="forward")
        insp.counters.record_h2_unrecorded()
        if not framing.aligned:
            # Counted, and the session is over either way -- but silence
            # here would make a stream that stopped framing halfway
            # indistinguishable from one that ended, which is the case
            # worth seeing.
            _drop_not_h2(
                insp, where, host,
                NotH2("the connection ended part-way through a frame"))
            rec.set(decision="drop", reason=DROP_NOT_H2)
    finally:
        rec.emit()
        upstream.sock.close()


def _drop_not_h2(insp, where, host, exc):
    insp.counters.record_drop(DROP_NOT_H2, host)
    insp.log(f"drop {where} host={host} reason='not HTTP/2: {exc}. "
                        f"{host} is in [[vm.network.http2]] and this session did not "
                        f"speak h2; drop the entry, or move the host to "
                        f"[[vm.network.splice]]'")


def serve_terminated(insp, tls_conn, where, host, upstream):
    """Authorise every request inside one terminated session.

    The same loop the cleartext plane runs, with the upstream already open
    -- except on a brokered host, where there is deliberately none and every
    request opens the broker leg itself -- and the name PINNED to the server
    name the handshake was completed for.
    Pinning is not belt-and-braces: this session's certificate was minted
    for one name, and a request inside it naming another is asking to be
    relayed down a connection its Host header did not authorise. It gets a
    421, which is the answer HTTP already has for exactly this and which
    every client knows to retry elsewhere.
    """
    client = _Stream(tls_conn)
    # `upstream` is None for a brokered host: nothing was dialled at
    # connection time, because the request goes to this workload's broker
    # and not to the origin (see _serve_tls_inspect). Seeding the pool with
    # None would hand the first request a non-socket; seeding it with the
    # origin is what made the broker unreachable in the first place.
    upstreams = {host: upstream} if upstream is not None else {}
    try:
        if not _is_http(insp, client, tls_conn, where, host):
            return
        first = True
        seq = 1
        while inspect_http.serve_one_request(
                insp, client, tls_conn, where.request(seq),
                upstreams, first, scheme=SCHEME_HTTPS, pinned_host=host):
            first = False
            seq += 1
    finally:
        for up in upstreams.values():
            up.sock.close()


def _is_http(insp, client, conn, where, host):
    """Whether this terminated connection is speaking HTTP. Closed if not.

    Closed, and not answered. See is_http_request_start for why an HTTP
    response is the wrong thing to write into a protocol that is not HTTP,
    and note that the guest gets no reason either way -- it is inside a
    session we completed, so a close here is a close it can see and cannot
    interpret.

    THE COST IS REAL AND THIS LINE IS THE ONLY EVIDENCE. A host that
    speaks something other than HTTP over 443 stops working the moment a
    workload terminates, and nothing before the connection could have
    predicted it -- which is why the remedy is written into the line rather
    than left for a doc. The remedy is a per-host [[vm.network.splice]]
    entry (HLD §11 hatch 2): the host keeps end-to-end TLS while every
    other name on the workload stays inspected. Whole-workload
    `tls = "splice"` is hatch 3 and gives up far more than the one host
    asked for.

    AND THE TWO REFUSALS ARE COUNTED APART. A host a [[vm.network.policy]]
    entry names is the same wire failure with a different remedy: the
    entry's `methods` and `paths` never ran and never can, so splicing the
    host is only half of it -- the entry has to go too, because `validate`
    refuses a host that is in `splice` and `policy` both. Reporting one
    merged figure would leave that operator with a number they cannot act
    on, and the split is the entire reason §11 asked for this counter.
    """
    conn.settimeout(egress_relay.CONNECTION_TIMEOUT)
    start = client.peek_start(
        until=lambda buf: is_http_request_start(buf) is not None)
    if is_http_request_start(start) is not False:
        # True is HTTP and None is undecided, which includes the b"" of a
        # peer that said nothing at all. Both go on to the loop below,
        # which owns the ways they end -- a 400, a clean close, a timeout
        # -- with the dispositions they already have.
        return True
    # Asked of the policy, not of the request: there is no request. See
    # Policy.governs.
    if insp.policy.governs(host):
        insp.counters.record_drop(DROP_NOT_HTTP_POLICY, host)
        insp.connection_record(where, "terminate", host=host,
                                          decision="drop",
                                          reason=DROP_NOT_HTTP_POLICY)
        insp.log(
            f"drop {where} host={host} reason='not HTTP (policy entry): "
            f"this session was terminated and {start[:8]!r} does not begin "
            f"a request line, so the [[vm.network.policy]] entry for "
            f"{host} never ran and never will. Either the host does not "
            f"belong in policy at all, or it needs a [[vm.network.splice]] "
            f"entry AND that policy entry deleted -- validate refuses both "
            f"on one host'")
        return False
    insp.counters.record_drop(DROP_NOT_HTTP, host)
    insp.connection_record(where, "terminate", host=host,
                                      decision="drop", reason=DROP_NOT_HTTP)
    insp.log(f"drop {where} host={host} reason='not HTTP: this session "
                        f"was terminated and {start[:8]!r} does not begin a request "
                        f"line. Add {host} to [[vm.network.splice]] if it needs to "
                        f"keep end-to-end TLS'")
    return False
