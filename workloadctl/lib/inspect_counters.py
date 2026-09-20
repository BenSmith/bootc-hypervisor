"""inspect_counters: what the egress inspector reports about itself.

The writer of `/run/workload-vm/<name>/inspect-status.json`; `inspect_figures`
is its reader, and the two agree on the document's shape only because the
listener writes exactly `Counters.snapshot()` and nothing composes a second
one. `egress_status` is the substrate under both this and the resolver's own
figures -- the bounded per-host map and the atomic replace -- and holds no
figure of its own.

Installed to /usr/libexec/workloadctl/inspect_counters.py.
"""

import threading

from inspect_document import TLS_DEFAULT
from egress_record import (
    DROP_INTERNAL, DROP_REASONS, DROP_UNCLASSIFIED, PER_HOST_REASONS,
)
from egress_status import STATUS_TOP_N, BoundedCounts
from tls_hello import TLS_EXT_ECH

class Counters:
    """What the listener reports, and the only place any of it is defined.

    Emitted, not rendered: `doctor` and the exporter read these through
    `inspect_figures` and add no figure of their own. The counter lives beside
    the code that creates the failure it counts, not beside the code that
    displays it, so a path can be debugged from its own figures.

    THE TWO ECH NUMBERS, AND WHY THEY ARE TWO

    `ech_seen` counts the encrypted_client_hello extension wherever it appears.
    That is a CAPABILITY metric and is dominated by GREASE: a modern client
    sends the real 0xfe0d codepoint with deliberately fake contents on ordinary
    connections, so this number moves as soon as such a client is installed in
    the guest and says nothing about intent.

    `ech_alarm` counts the PAIR -- extension present and the name landed on no
    list -- which is the signature of real ECH being used to reach somewhere
    policy would refuse. Counting only the first is how a tripwire ends up
    permanently lit and therefore ignored; counting only the second loses the
    "when did this guest become ECH-capable" question entirely.

    A hello with no readable name counts toward the alarm on the same footing
    as one whose name was refused. Both are "the extension was there and the
    name matched nothing", and an ECH hello that also withholds SNI is the
    stronger version of the signal, not a weaker one.

    WHAT `dispositions` COUNTS, AND WHY IT IS NOT ONE UNIT

    A TLS decision is taken once per CONNECTION -- one hello, one name, one
    splice or one close. A cleartext decision is taken once per REQUEST, because
    a kept-alive connection carries several and each is authorised separately.
    So `spliced` counts connections, `forwarded` counts requests, and `dropped`
    counts whichever the refusal was.

    That is not reconcilable into a single unit and is deliberately not
    disguised as one: a listener that reported only connections would hide every
    request after the first on a keep-alive, which is the majority of them, and
    one that reported only requests would have nothing to say about a spliced
    tunnel that carries no requests this process can see. Each figure is exact
    for its own plane. Summing across the three is the operation that means
    nothing.

    `drop_reasons` reconciles with `dropped` exactly -- every drop lands in one
    reason, DROP_UNCLASSIFIED included.

    `terminated` is the third connection figure and joins `spliced` on its own
    footing: one hello, one name, one completed handshake, after which the
    REQUESTS inside it are counted by `forwarded` exactly as the cleartext
    plane's are. A workload reading terminated=1 forwarded=40 had one HTTPS
    connection carrying forty authorised requests, which is the reading `spliced`
    can never produce.

    THE PER-HOST MAPS ARE A DIFFERENT KIND OF FIGURE

    `dispositions` and `drop_reasons` answer "what happened, how often".
    `per_host` answers "to which host", and only for the reasons whose remedy
    is written against a name -- an internal destination missing an entry, an
    upstream this host cannot verify, a host wanting a client certificate, a
    host not speaking HTTP, and a host that did not speak h2 after being told
    it would. All but the first are the operator's list of `splice`
    candidates, which is the whole reason they are per host.

    `not HTTP` is TWO of those figures rather than one, split by whether a
    [[vm.network.policy]] entry named the host. Merged, an operator reading a
    single total can see that some host needs splicing but not that some OTHER
    host has method and path rules that never ran; and those two facts have
    different remedies, the second of which includes deleting the policy entry
    (`validate` refuses `splice` and `policy` on one host). See
    PER_HOST_REASONS.

    They are bounded top-N with a counted overflow because the keys come from
    the guest. `per_host_totals` is exact regardless: the top-N can lose which
    names, never how many.

    `bumped` IS NOT A DISPOSITION and is reported outside that map on purpose.
    A bump is a refusal DELIVERED THROUGH a completed handshake, so it is
    already counted in `dropped` under its own reason; the figure says how the
    guest was told, not what was decided. Putting it in `dispositions` would
    break the one property that map has -- every connection or request in
    exactly one bucket -- to record something that is not a decision.
    """

    def __init__(self, policy=None, top_n=STATUS_TOP_N):
        self._lock = threading.Lock()
        self.dispositions = {"spliced": 0, "terminated": 0, "forwarded": 0,
                             "dropped": 0}
        self.bumped = 0
        # Records the per-request sink could not take. HAS A WRITER, which is
        # the whole point of it being here rather than a journal line: the
        # WARNING is emitted once per process, so a sink that has been broken
        # since boot is invisible to anyone who was not tailing at the moment
        # it failed. This is the reading that survives, and a non-zero here
        # means the record is incomplete -- which a reader must know before
        # concluding a guest made no requests.
        self.record_failures = 0
        # Connections whose requests are NOT in the record, because nothing in
        # them was decoded: an h2 session is relayed at frame level by design.
        # Named rather than left to look like silence -- without it a reader
        # counting requests in the file concludes the guest made none, when
        # what happened is that this listener cannot see them. The connection
        # itself IS recorded (mode "h2"); this is the count of how many such
        # blind spots there are.
        self.h2_unrecorded = 0
        # Connections whose caller the peer-identity lookup could not name.
        # Not a drop: they are admitted (see _handle). Counted because the
        # alternative is a hardening layer that degrades to inert with nothing
        # anywhere saying so -- a counter with no writer reads 0, and so does
        # a check that never resolves.
        self.caller_unresolved = 0
        # Pre-seeded from DROP_REASONS rather than grown on first use. A reason
        # absent from the file and a reason reading zero are the same fact and
        # must look the same, or an operator reads "no key" as "not measured".
        self.drop_reasons = {reason: 0 for reason in DROP_REASONS}
        self._unclassified = 0
        self.ech_seen = 0
        self.ech_alarm = 0
        self.per_host = {reason: BoundedCounts(top_n)
                         for reason in PER_HOST_REASONS}
        # THE CREDENTIAL FIGURES. Two breakdowns of one total,
        # because the two questions an operator has are different: `per_host`
        # answers "which of my brokered hosts is the guest actually using", and
        # `per_credential` answers "is this key being used at all" -- which is
        # the one that catches a policy entry pointing at a credential the guest
        # never triggers, and the one worth reading before rotating a key.
        #
        # BoundedCounts on both, like every other per-name figure here, and the
        # bound is free rather than defensive: unlike the guest-chosen names in
        # `per_host`, both key spaces come off this workload's own file and are
        # already bounded by it.
        #
        # NEVER THE CREDENTIAL ITSELF, only its credstore name. The material is
        # in the broker's process and this one has never seen it, which is the
        # whole of ADR 007 -- a figure carrying it would put it in a file the
        # exporter publishes.
        self.credentialed = 0
        self.credentialed_hosts = BoundedCounts(top_n)
        self.per_credential = BoundedCounts(top_n)
        # A brokered request the ORIGIN refused for want of authorisation, on a
        # request this inspector considers fully authorised. The failure worth
        # counting rather than merely naming: the guest sent
        # a placeholder whose shape the provider does not accept, or the broker
        # attached material the provider has retired, and every layer of ours
        # reports success. Without this figure that is an hour of reading a
        # record whose every line says `decision=forward`.
        #
        # 401 AND 403 BOTH, and no other status. 401 is the shape a provider
        # that wants a credential returns; 403 is the shape one that got a
        # credential without the right scope returns, which is the same
        # operator question with a different remedy. A 5xx is the provider
        # failing and is not this.
        self.credential_unauthorized = 0
        # `internal_refusals` is the per-host figure for DROP_INTERNAL under
        # the key the status document and the exporter name it by.
        self.internal_refusals = self.per_host[DROP_INTERNAL]
        # The lists as LOADED, not as written in the file: `drift` cannot see
        # them, and the question an operator has is what this process is
        # actually enforcing.
        #
        # EVERY list this process enforces, and a key added here whenever one
        # is added there. Three of these decide something on their own --
        # `splice` exempts a host from termination, `http2` changes what is
        # offered on both legs, `policy` decides individual requests -- so a
        # status file naming only `hosts` and `internal` answers "what is this
        # process enforcing" with a subset, in a file whose whole purpose is
        # that the answer is not a guess. `policy` carries the rules and not
        # just the names: which hosts are governed is half the question, and
        # what they are governed BY is the half an operator is reading this
        # for.
        self.lists = {
            "tls": policy.tls if policy else TLS_DEFAULT,
            "hosts": list(policy.hosts) if policy else [],
            "internal": list(policy.internal) if policy else [],
            "splice": list(policy.splice) if policy else [],
            "http2": list(policy.http2) if policy else [],
            "policy": [
                {"host": e.host,
                 "methods": None if e.methods is None else list(e.methods),
                 "paths": None if e.paths is None else list(e.paths),
                 # Unconditional here, unlike the policy DOCUMENT, which emits
                 # the key only where it is set. The sparseness there buys a
                 # stable digest across a fleet; this file is digested by
                 # nobody, and an operator asking "which hosts are brokered"
                 # should not have to tell a missing key from a null one.
                 "credential": e.credential}
                for e in policy.policy
            ] if policy else [],
        }

    def record_hello(self, hello, on_a_list: bool) -> None:
        """The ECH tripwire. Called once per readable ClientHello.

        `on_a_list` is the decision already taken, passed in rather than
        recomputed: a tripwire that matched the lists a second time could
        disagree with the decision it is describing.
        """
        if TLS_EXT_ECH not in hello.extensions:
            return
        with self._lock:
            self.ech_seen += 1
            if not on_a_list:
                self.ech_alarm += 1

    def record_unreadable_hello(self) -> None:
        """A hello that could not be parsed at all.

        No ECH figure moves here, and that is not an oversight: the extension
        list comes FROM the parse, so a hello that did not parse has no
        extensions to have seen. Guessing would put unparseable bytes in the
        capability count and make the alarm's denominator a fiction.
        """

    def record_splice(self) -> None:
        with self._lock:
            self.dispositions["spliced"] += 1

    def record_termination(self) -> None:
        """One connection whose guest handshake we completed and then served."""
        with self._lock:
            self.dispositions["terminated"] += 1

    def record_write_failure(self) -> None:
        """One record the sink refused. Passed to RequestLog as its callback
        rather than called from the write path, so the counter cannot drift
        from the failures it counts."""
        with self._lock:
            self.record_failures += 1

    def record_caller_unresolved(self) -> None:
        """One connection admitted without naming its caller."""
        with self._lock:
            self.caller_unresolved += 1

    def record_h2_unrecorded(self) -> None:
        """One h2 session whose requests this process never decoded."""
        with self._lock:
            self.h2_unrecorded += 1

    def record_bump(self) -> None:
        """One handshake completed solely to deliver a refusal legibly.

        Always paired with a `record_drop` naming the reason; see the class
        docstring for why the two are not one call.
        """
        with self._lock:
            self.bumped += 1

    def record_forward(self) -> None:
        with self._lock:
            self.dispositions["forwarded"] += 1

    def record_drop(self, reason: str, host: str = None) -> None:
        """One refused connection or request, by reason.

        The reason strings are the log's, deliberately the same ones: an
        operator who greps a reason out of `workloadctl logs` and then looks
        for it in the status file must find the same word.
        """
        with self._lock:
            self.dispositions["dropped"] += 1
            if reason in self.drop_reasons:
                self.drop_reasons[reason] += 1
            else:
                # Counted, not discarded: sum(drop_reasons) == dropped has to
                # hold unconditionally or an operator reconciling the two maps
                # is reconciling against a number that quietly lost rows.
                self._unclassified += 1
            if host and reason in self.per_host:
                self.per_host[reason].add(host)

    def record_credentialed(self, host: str, credential: str) -> None:
        """One request sent to the broker instead of to the origin.

        Counted where the dial SUCCEEDS, not where the policy says a credential
        applies: a broker that is down raises DROP_BROKER_UNREACHABLE and the
        request reached no provider, so counting it here would report a
        credential as used on a request that never carried one.
        """
        with self._lock:
            self.credentialed += 1
            self.credentialed_hosts.add(host)
            self.per_credential.add(credential)

    def record_credential_unauthorized(self) -> None:
        """One brokered request the origin answered 401 or 403."""
        with self._lock:
            self.credential_unauthorized += 1

    def snapshot(self, *, open_now: int, refused: int) -> dict:
        with self._lock:
            reasons = dict(self.drop_reasons)
            if self._unclassified:
                reasons[DROP_UNCLASSIFIED] = self._unclassified
            return {
                "dispositions": dict(self.dispositions),
                "drop_reasons": reasons,
                "ech": {"seen": self.ech_seen, "alarm": self.ech_alarm},
                "bumped": self.bumped,
                "record_failures": self.record_failures,
                "h2_unrecorded": self.h2_unrecorded,
                "caller_unresolved": self.caller_unresolved,
                "internal_refusals": self.internal_refusals.snapshot(),
                "internal_refusals_total": self.internal_refusals.total,
                "per_host": {reason: counts.snapshot()
                             for reason, counts in self.per_host.items()},
                "per_host_totals": {reason: counts.total
                                    for reason, counts in
                                    self.per_host.items()},
                "credentialed": self.credentialed,
                "credentialed_hosts": self.credentialed_hosts.snapshot(),
                "per_credential": self.per_credential.snapshot(),
                "credential_unauthorized": self.credential_unauthorized,
                "concurrency": {"open": open_now, "refused": refused},
                "lists": dict(self.lists),
            }
