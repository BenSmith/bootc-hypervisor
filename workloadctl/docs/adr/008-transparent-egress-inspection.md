# ADR 008: VM egress is inspected transparently, and terminated by default

**Status:** Implemented. Supersedes the per-workload proxy that
[ADR 006](006-vm-networking-passt-not-managed-bridge.md) added for hostname
policy; [ADR 007](007-per-workload-credential-broker.md) chains the credential
broker behind the inspector this record decides.

## Context

A VM workload with `[vm.network].egress = "filtered"` reached the network through
a per-workload tinyproxy enforcing an fnmatch hostname allowlist. Two properties
bounded what that could be:

- **The guest must cooperate.** It was handed `HTTPS_PROXY` pointing at an
  advertised literal, and the nftables redirect rewrote exactly that one
  destination. A process that ignores its proxy environment is not filtered by
  name at all — it hits the default drop and reaches nothing. Fail-closed, but the
  strong default applies only to the well-behaved half of the guest, and the
  adversary this exists for — a prompt-injected coding agent, or software it
  installed — is precisely the party that would unset the variable.
- **A hostname is the only unit of policy.** `github.com` cannot be narrowed to
  two repositories, a POST body carrying a secret is invisible, and an allowlisted
  name served by a CDN can reach any other tenant of that CDN by putting the real
  target in the `Host` header — which is inside TLS, so a proxy that does not
  decrypt cannot see it.

The workload uid is what makes any of this enforceable: under passt, guest traffic
is re-originated as host sockets owned by `_wl-<name>`, so `meta skuid` is a
per-workload selector the guest cannot forge (ADR 006).

## Decision

1. **Reachability is a transparent, uid-keyed redirect, and the guest is told
   nothing.** Ports 80 and 443 are DNATed to a per-workload inspector before any
   name is read. `vm_proxy_env()` and the `https_proxy`/`no_proxy` variables in the
   seed are deleted, not deprecated alongside the redirect: a retained
   guest-configured path is a bypass that only requires the guest to cooperate with
   itself. A terminated connection whose first bytes do not begin a request line is
   closed rather than answered — an HTTP response written into a protocol that is
   not HTTP is worse than silence.

2. **The default disposition is TLS termination.** Decrypt, apply policy,
   re-originate. Splicing — forwarding bytes untouched — becomes a named exemption
   carrying a written `reason`, never a default and never implicit. The mechanism
   is not novel; the *default* is the decision. Under splice-by-default nothing in
   config review distinguishes "spliced because it must be" from "spliced because
   nobody tried".

3. **One inspector per workload, running as that workload's own uid, with its own
   CA.** A host-wide inspector would hold every workload's CA — a genuine crown
   jewel. Scoped per workload the key is nearly worthless: the only party trusting
   it is the guest whose uid already owns it, so stealing it buys the ability to
   impersonate sites *to itself*.

4. **The CA is generated once and never rotated.** cloud-init runs once per
   instance-id, so a rotated CA never reaches a provisioned guest; treating it as
   instance-lifetime, with re-provision as the escape hatch, is honest about that.
   Defensible precisely because the key is low-value.

5. **Policy gains method and URL path, per host**, and the `Host` header inside a
   terminated session must match the name that authorised the connection, compared
   after normalisation; a request naming any other host is answered `421`. Three
   schema keys carry it:

   - **`[[vm.network.policy]]`** — `methods` and `paths` per host, a cross product
     inside one entry, entries unioning so file order cannot change what is
     allowed. A host any entry matches is governed by those entries ALONE;
     `hosts` contributes no rules to it. A policy entry allowlists its own host, so
     a workload's whole allowlist may be written as policy entries.
   - **`[[vm.network.splice]]`** — the per-host form of `tls = "splice"`, carrying
     a required `reason`. This is the hatch an operator should reach for first, and
     it cannot be opened without saying why. `tls = "splice"` remains the
     whole-workload hatch of last resort and requires `tls_reason` beside it, since
     the asymmetry was the wrong way round: every narrow bypass had to justify
     itself while the widest one — every host the workload reaches — was the only
     one openable in silence. The refusal names `[[vm.network.splice]]` before it
     names the reason, because an operator reaching for the mode is usually fixing
     one host. Nothing reads `tls_reason` at runtime, and that is the point: the
     audience is the person deciding months later whether a bypass is still needed,
     who is not the person who opened it.
   - **`[[vm.network.http2]]`** — every terminated host is offered `http/1.1`
     alone, which is what lets `methods`, `paths` and the `Host` binding work on
     plain text with no HPACK decoder anywhere. This key is the opt-out, and it is
     a HOLE rather than a protocol setting: a host listed here is relayed at the
     frame level and enforced by its name alone. It carries a `reason` for that
     reason, and `validate` refuses it beside a `policy` or a `splice` entry.
     Where `splice` works it is the better choice — both leave enforcement at the
     server name, and `splice` additionally returns the host its end-to-end TLS and
     needs no CA in the guest.

6. **Both address families, from the first rung.** Clients try IPv6 first, so a
   v4-only redirect sends dual-stack traffic out unredirected into the default
   drop — a timeout rather than a policy decision. Every element has a twin:
   redirect map, accept set and guard rule.

7. **tinyproxy is removed and the inspector owns the allowlist.** A terminated
   connection produces no `CONNECT` line to filter. Keeping tinyproxy as well would
   put one allowlist in two matchers that diverge only on the splice path, which is
   a security bug visible nowhere else.

8. **The inspector's listener range needs an explicit nftables guard.** See
   *Rationale* — the one conclusion here overturned by measurement rather than
   reached by argument.

9. **The guest's resolver is ours, and it synthesises rather than forwards.**
   passt already directs the guest's queries wherever `--dns-host` names, so a
   per-workload responder answers every `A`/`AAAA` — for any name, on a list or not
   — with that workload's own inspector address, and answers every other type,
   `HTTPS`/`SVCB` included, with `NODATA` rather than `REFUSED`: the guest's
   resolver list has one entry, so `REFUSED` costs a timeout per lookup where
   `NODATA` fails fast. **No query the guest emits leaves the host.** From inside
   the guest DNS works normally, which is what distinguishes this from
   `resolver = "none"`; what changes is that the real lookup is the inspector's,
   performed host-side for a name already checked against the allowlist.

10. **An allowlisted name that resolves into private address space is refused,
    with one narrow declared exemption.** The inspector dials whatever an
    allowlisted name resolves to, so a wildcard or a compromised zone would reach
    RFC 1918, loopback or link-local space from a VM that reports itself confined.
    The exemption names a host and carries a written `reason`, and exempts the
    *destination* check alone: the host stays inspected and its method and path
    policy still apply.

## Rationale

**Transparency is the whole point, and it costs the ECH-immune posture.**
`resolver = "none"` is immune to Encrypted ClientHello — ECH needs an ECHConfig
from DNS, and a guest that cannot resolve must state names to a proxy in
plaintext. That escape exists *because* the guest is proxy-aware, so it cannot
survive decision 1: a guest that does not know a proxy exists and cannot resolve
reaches nothing. The trade is deliberate. A guest that declines its proxy
configuration is a certainty; ECH is one `dnf install` away but not present in the
base image's toolchain.

What replaces that immunity needs no guest cooperation, and it is decision 9.
ECH's prerequisite is an ECHConfig carried in an HTTPS/SVCB record, and the
guest's DNS already runs through the host. An earlier draft had the responder
*forward* the query and delete the `ech=` parameter from the answer. Synthesising
instead is strictly stronger and smaller: it removes ECH at its source rather than
editing it out of a reply, so there is no hostile wire format to parse and no
obligation to preserve every other parameter byte-for-byte; it removes DNS as an
exfiltration channel, since a compromised agent encoding data in query names has
no upstream query to ride on; and the responder needs no egress of its own, so the
host's own `/etc/resolv.conf` stops mattering to a filtered guest. It is available
only because the redirect already made the guest's answer irrelevant — the
inspector connects to the name it authorised, never to the address the guest was
given, so that address never had to be true.

Both address families must be answered, though not for the obvious reason:
leaving IPv6 unsaid lets passt advertise the host's own v6 nameserver from its
`resolv.conf` scan. That is **not** an open resolver — with no v6 `--dns-forward`
nothing is intercepted and the guest's query is ordinary egress meeting the
default deny — but it costs a full retry schedule per lookup on the family clients
try first, presenting as broken DNS. Pointing IPv6 at the guest's own loopback
makes it an immediate local refusal instead.

**Synthesis costs services reached by name on other ports** — an SSH forge, an
internal registry, a Kubernetes API. Nothing in the rules blocks these; the
synthesised answer simply sends them to a port the inspector does not serve, and
an operator cannot route around it by writing the address, because such a
service's certificate is issued for its name. So an `allow` entry may be written
by name, resolved host-side once at start and answered from a static map rather
than synthesised. That widens nothing — the name comes from a list the operator
wrote — and it leaves the connection uninspected and end to end, which is what
`allow` has always meant.

**Two residues, and they are the same residue.** A guest that *hardcodes* an
ECHConfig — they are public data — skips DNS entirely, but fails closed: the cover
name is on no list, so the connection is denied, and the
`encrypted_client_hello` tripwire covers it as an alarm rather than
instrumentation. And a wildcard over a domain in which anyone can create records
hands the exfiltration channel back, since the guest picks the label, the
allowlist authorises it, and the inspector's own lookup carries it to a nameserver
the attacker controls. Neither is closed here. Nor is the larger channel beside
them: an allowlisted host permitting `POST` with no path restriction carries
unlimited data in a body, where a query name carries tens of bytes. Method and
path policy is where exfiltration is managed; decision 9 is the cheap structural
win next to it.

**Inverting the default converts a partial failure into a total one, so the
exemption path has to be good.** Under splice-by-default a client that cannot
trust the CA still reaches every spliced host; inverted, it reaches nothing until
its host is exempted. Measured on Fedora 44 with the CA installed only in the
system trust store, curl, stdlib Python, Node 22, Go, `git`, Java and `pip` all
work; only `requests` against a pip-installed `certifi` fails. But those successes
are distro packaging, not client generosity — an upstream Node from nvm or a
hand-installed JDK ships its own root list. The risk concentrates in runtimes
installed outside the package manager, and it degrades one client at a time. Hence
a per-host exemption, a per-workload exemption, and CA environment variables
written into the seed, all reversible with a restart.

**The 127/8 property does not transfer, and measurement caught it.** Every
host-local address a filtered uid can otherwise reach is inside `127.0.0.0/8`,
which is the *guest's own* loopback — a guest packet aimed at another workload's
`127.128.x.y` never leaves its stack, so cross-workload reach is closed by the
address family rather than by any rule, which is what makes the shipped
`meta skuid @wl_filtered oif lo accept` safe. An inspector on a routable host-local
range has no such property: one workload reached another's listener on the first
try, admitted by that same rule. The design therefore carries an explicit guard on
the listener range, ordered between the per-workload accept and the shipped
`oif lo` rule, with **two** qualifiers doing different jobs:

- `meta skuid @wl_filtered` keeps host tooling out of the rule, so `diagnose` can
  still probe a listener.
- `ct direction original` keeps the *inspector's own replies* out of it — and that
  one is the difference between this design working and not working at all. The
  inspector runs as the workload uid, so its replies are output traffic from a
  filtered uid addressed to the peer; whenever that address is inside the listener
  range the reply is dropped and the connection hangs with its SYN already
  accepted. Under decision 9 that is not an edge case but the normal path, since a
  synthesised answer means every connection is addressed to the inspector's own
  address from that same address.

The reply itself is accepted by a rule of its own —
`meta skuid @wl_filtered ct direction reply accept`, placed first among the chain's
*terminating* rules. Not first outright: the chain's first rule is a
**non-terminating** `ct mark set`, and that mark is the whole of inbound capture
attribution, since nftables has no input-side uid match. An accept ahead of it
would terminate the chain for every reply-direction packet a filtered workload
emits — which is the first output packet of every connection opened *toward* the
guest, so management SSH and every published port would go unmarked and
`workloadctl pcap -Q in` would return nothing for filtered VMs, with no error
anywhere. `ct direction reply` rather than `ct state established`, because the
guest's outbound data is already accepted on its own tuple and the broader form
silently converts the per-workload accept's counter from packets to connections.

An earlier revision credited the uid qualifier alone, because the rig it was
measured on ran the listener as root and never exercised a filtered uid's reply
path. Both errors are invisible to every functional test — one silently opens
cross-workload reach, the other silently takes the workload down — which is why
they are asserted by rendering tests rather than trusted.

**Termination makes refusals expensive, and the guest picks the hostnames.** Under
`CONNECT` a denial cost a plaintext 403 and no crypto. Transparently there is no
plaintext moment, so saying anything requires completing a handshake — which means
minting a certificate for a name that was just refused. Still worth doing: an
agent VM's failure mode is a silent retry loop, and a printed 403 is the difference
between reading a message and running `pcap`. It is bounded by minting only after
the upstream leg is established, a separate cache for denial-only leaves, and a
per-workload token bucket whose overflow turns a denial back into a closed
connection.

**Why not merge this with the credential broker.** Both terminate TLS from the
guest, identify a caller, apply policy and re-originate upstream with full
verification. It fails on one point: the inspector runs as `_wl-<name>`, the uid
QEMU runs as, so a guest escape would obtain the provider credential that the
broker's disjoint `DynamicUser` identity prevents. ADR 007 records the chaining
decision that follows.

## Consequences

**Gained.**

- Policy binds a guest that actively tries to avoid it, which is the guest this
  exists for.
- Method and URL path become expressible, and `Host`-binding closes true CDN
  fronting — unclosable while spliced, because the header is inside the TLS a
  spliced connection deliberately does not open. It closes it on every terminated
  host: `http/1.1` is the ALPN default, and a host offered h2 is one named in
  `[[vm.network.http2]]`, where `:authority` is HPACK-encoded and goes unread.
  Those hosts and spliced hosts are the only exceptions, and both are a line of
  TOML carrying a reason. That the exceptions are only those two rests on refusing
  what does not speak HTTP/1.1 rather than on the ALPN offer: an ALPN mismatch does
  not fail a TLS handshake, so the offer binds cooperating clients and nothing else.
- A denied host becomes a message the client prints rather than a hang
  indistinguishable from a network fault.
- Every weakening is a line of TOML carrying a reason somebody had to type.
- DNS stops being an open channel out of a confined guest: no name the guest
  composes leaves the host. Narrowed, not closed — see the two residues above.
- An allowlisted name can no longer reach inside the host's own network by
  accident or by a compromised zone, and permitting one that is *meant* to resolve
  inside is a declared line rather than a blanket bypass.

**Given up.**

- *End-to-end TLS.* Not the guest's ability to notice *us* — interception is the
  point, and a guest that notices can do nothing about it. What is given up is the
  guest's ability to validate the **origin**: it now checks a chain we minted, so a
  third party between the inspector and the origin is something the guest cannot
  see. That validation does not disappear, it moves — the inspector's upstream leg
  must verify fully and fail distinguishably. Getting this wrong converts a policy
  engine into a way to strip TLS validation from the whole guest.
- *ECH immunity.* No posture immune by construction remains.
- *Transparent support for anything on 443 that is not HTTP.* Relaying such a
  session opaquely — the compatible answer — is a policy opt-out the guest selects
  by sending different first bytes. So it is closed, with a log line naming the
  host and `[[vm.network.splice]]`, which gives the host back end-to-end TLS for
  one line and a written reason. The cost is that websockets over a tunnel, gRPC
  and plain TLS services break until somebody writes that line.
- *A TLS service reachable only by address.* With no name there is no SNI, so the
  inspector cannot authorise it, and an `allow` element on 443 is a validation
  error. Named services on other ports are covered by writing the `allow` entry by
  name; a nameless one is not, and `egress = "open"` is the answer for a workload
  that needs one. Mutual TLS runs on 443, so its path is `splice` rather than
  `allow`.
- *A small attack surface.* A process parsing hostile guest input while holding
  plaintext and a CA key is new, and it sits on the path for all HTTP and HTTPS
  rather than a named few. This cost is paid in full as soon as any host is
  inspected, which is why it is not an argument against inverting the default.
- *Cheap refusals*, as above.

**Costs that are not security properties.** Every byte is decrypted and
re-encrypted in userspace: measured over loopback, 512 MB, best of three — direct
1876 MB/s, spliced 1681 MB/s, terminated 729 MB/s. Roughly 2.3× the cost of a
splice and still an order of magnitude above any link this reaches, but measured
idle; contention with guests on a loaded host is unmeasured.

**Not decided here.** Whether `Host`-binding must cover HTTP/2 relayed hosts —
closing it needs an HPACK decoder, and inverting the ALPN default turned this from
a hole to close into a capability worth buying, since an h2 host is now one an
operator named with a reason.

**Decided after this record was first written, noted so their absence is not read
as an open question.** Behaviour on redirects (pass through, log both host names —
the guest opens a new connection that is checked on its own merits) and on
protocol upgrades (police the request as ordinary HTTP, relay opaquely after the
`101`); what the inspector may log (redaction by default, applied at the point of
capture rather than of formatting, bodies never logged); TLS on non-standard
ports, deferred with a stated condition, since a *named* service on another port is
reached through an `allow` entry written by name and nobody has yet needed method
or path policy on one; and the SELinux domain, which turned out to be a harvest
rather than a decision — shipped Fedora policy already entrypoints a `#!` script
into a private domain on the script's own label, which is the mechanism a Python
entrypoint needs.
