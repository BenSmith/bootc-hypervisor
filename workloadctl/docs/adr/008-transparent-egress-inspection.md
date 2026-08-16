# ADR 008: VM egress is inspected transparently, and terminated by default

**Status:** **Proposed, not implemented.** Recorded ahead of the work because
`007-per-workload-credential-broker.md` is an accepted decision that assumes
this one, and an accepted record resting on an undecided premise is the wrong
order. Nothing here has shipped.

**Date:** 2026-08-16.

## Context

A VM workload with `[vm.network].egress = "filtered"` reaches the network today
through a per-workload tinyproxy enforcing an fnmatch hostname allowlist. Two
properties bound what that can be:

- **The guest must cooperate.** It is handed `HTTPS_PROXY` pointing at an
  advertised literal, and the nftables redirect rewrites exactly that one
  destination. A process that ignores its proxy environment is not filtered by
  name at all — it hits the default drop and reaches nothing. Fail-closed, but
  the strong default applies only to the well-behaved half of the guest, and the
  adversary this exists for — a prompt-injected coding agent, or software it
  installed — is precisely the party that would unset the variable.
- **A hostname is the only unit of policy.** `github.com` cannot be narrowed to
  two repositories, a POST body carrying a secret is invisible, and an
  allowlisted name served by a CDN can be used to reach any other tenant of that
  CDN by putting the real target in the `Host` header — which is inside TLS, so
  a proxy that does not decrypt cannot see it.

The workload uid is what makes any of this enforceable: under passt, guest
traffic is re-originated as host sockets owned by `_wl-<name>`, so `meta skuid`
is a per-workload selector the guest cannot forge (ADR 006).

## Decision

1. **Reachability is a transparent, uid-keyed redirect, and the guest is told
   nothing.** Ports 80 and 443 are DNATed to a per-workload inspector before any
   name is read. `vm_proxy_env()` and the `https_proxy`/`no_proxy` variables in
   the seed are deleted, not deprecated alongside the redirect: a retained
   guest-configured path is a bypass that only requires the guest to cooperate
   with itself.

2. **The default disposition is TLS termination.** Decrypt, apply policy,
   re-originate. Splicing — forwarding bytes untouched, as today — becomes a
   named exemption carrying a written `reason`, never a default and never
   implicit. The mechanism is not novel; the *default* is the decision. Under
   splice-by-default nothing in config review distinguishes "spliced because it
   must be" from "spliced because nobody tried".

3. **One inspector per workload, running as that workload's own uid, with its
   own CA.** A host-wide inspector would hold every workload's CA — a genuine
   crown jewel. Scoped per workload, the key is nearly worthless: the only party
   trusting it is the guest whose uid already owns it, so stealing it buys the
   ability to impersonate sites *to itself*.

4. **The CA is generated once and never rotated.** cloud-init runs once per
   instance-id, so a rotated CA never reaches a provisioned guest; treating it
   as instance-lifetime, with re-provision as the escape hatch, is honest about
   that. Defensible precisely because the key is low-value.

5. **Policy gains method and URL path, per host**, and the `Host` header inside
   a terminated session must match the name that authorised the connection,
   compared after normalisation.

6. **Both address families, from the first rung.** Clients try IPv6 first, so a
   v4-only redirect sends dual-stack traffic out unredirected into the default
   drop — a timeout rather than a policy decision. Every element has a twin:
   redirect map, accept set, and guard rule.

7. **tinyproxy is removed and the inspector owns the allowlist.** A terminated
   connection produces no `CONNECT` line to filter. Keeping tinyproxy as well
   would put one allowlist in two matchers that diverge only on the splice path,
   which is a security bug visible nowhere else.

8. **The inspector's listener range needs an explicit nftables guard.** See
   *Rationale* — this is the one conclusion here that was overturned by
   measurement rather than reached by argument.

## Rationale

**Transparency is the whole point, and it costs the ECH-immune posture.**
`resolver = "none"` is immune to Encrypted ClientHello — ECH needs an ECHConfig
from DNS, and a guest that cannot resolve must state names to a proxy in
plaintext. That escape exists *because* the guest is proxy-aware, so it cannot
survive decision 1: a guest that does not know a proxy exists and cannot resolve
reaches nothing. The trade is deliberate. A guest that declines its proxy
configuration is a certainty; ECH is one `dnf install` away but not present in
the base image's toolchain.

What replaces that immunity is narrower and needs no guest cooperation. ECH's
prerequisite is an ECHConfig carried in an HTTPS/SVCB record, and the guest's
DNS already runs through the host — passt forwards its queries to the host
resolver as the workload uid, which is one of the two reasons
`nftables/workload-filter.nft` accepts that uid's loopback traffic. Stripping
`ech=` from those answers leaves a client with nothing to encrypt to, so it
sends a plaintext SNI. The plumbing for that already exists: passt takes
`--dns-host`, and `libexec/workload-vm-netdev` already derives and sets it per
workload, so what is missing is the filter at the far end and not a way to reach
it. It has to cover both address families for the same reason decision 6 does —
a workload whose v4 DNS is filtered and whose v6 DNS is not can fetch its
ECHConfig over v6. A guest that *hardcodes* a config — they are public data
— defeats the stripping and is not defeated by anything else, but it fails
closed: the cover name is on no list, so the connection is denied. The
`encrypted_client_hello` tripwire covers that residue and is an alarm rather
than instrumentation.

**Inverting the default converts a partial failure into a total one, so the
exemption path has to be good.** Under splice-by-default a client that cannot
trust the CA still reaches every spliced host; inverted, it reaches nothing
until its host is exempted. Measured on Fedora 44 with the CA installed only in
the system trust store, curl, stdlib Python, Node 22, Go, `git`, Java and `pip`
all work; only `requests` against a pip-installed `certifi` fails. But those
successes are distro packaging, not client generosity — an upstream Node from
nvm or a hand-installed JDK ships its own root list. The risk is concentrated in
runtimes installed outside the package manager, and it degrades one client at a
time. Hence a per-host exemption, a per-workload exemption, and CA environment
variables written into the seed, all reversible with a restart.

**The 127/8 property does not transfer, and measurement caught it.** Today every
host-local address a filtered uid can reach is inside `127.0.0.0/8`, which is
the *guest's own* loopback — a guest packet aimed at another workload's
`127.128.x.y` never leaves its stack, so cross-workload reach is closed by the
address family rather than by any rule. That is what makes the shipped
`meta skuid @wl_filtered oif lo accept` in `nftables/workload-filter.nft` safe.
An inspector on a routable host-local range has no such property: measured
2026-08-16, one workload reached another's listener on the first try, admitted
by that same rule. The design therefore carries an explicit guard on the
listener range, ordered between the per-workload accept and the shipped `oif lo`
rule, and qualified on the workload uid — unqualified, it also drops the
inspector's own reply traffic on a self-dial and stops host tooling probing a
listener at all. Both errors are invisible to every functional test, which is
why they are asserted by rendering tests rather than trusted.

**Termination makes refusals expensive, and the guest picks the hostnames.**
Under `CONNECT` a denial cost a plaintext 403 and no crypto. Transparently there
is no plaintext moment, so saying anything requires completing a handshake —
which means minting a certificate for a name that was just refused. That is
still worth doing, because an agent VM's failure mode is a silent retry loop and
a printed 403 is the difference between reading a message and running `pcap`.
It is bounded by minting only after the upstream leg is established, a separate
cache for denial-only leaves, and a per-workload token bucket whose overflow
turns a denial back into a closed connection.

**Why not merge this with the credential broker.** Both terminate TLS from the
guest, identify a caller, apply policy and re-originate upstream with full
verification, and merging would collect real wins. It fails on one point: the
inspector runs as `_wl-<name>`, the uid QEMU runs as, so a guest escape would
obtain the provider credential that the broker's disjoint `DynamicUser` identity
prevents today. ADR 007 records the chaining decision that follows.

## Consequences

**Gained.**

- Policy binds a guest that actively tries to avoid it, which is the guest this
  exists for.
- Method and URL path become expressible, and `Host`-binding closes true CDN
  fronting — unclosable while spliced, because the header is inside the TLS a
  spliced connection deliberately does not open.
- A denied host becomes a message the client prints rather than a hang
  indistinguishable from a network fault.
- Every weakening is a line of TOML carrying a reason somebody had to type.

**Given up.**

- *End-to-end TLS.* The guest can no longer detect a MITM by inspecting the real
  chain; that responsibility moves entirely to the inspector's upstream leg,
  which must verify fully and fail distinguishably. Getting this wrong converts
  a policy engine into a way to strip TLS validation from the whole guest.
- *ECH immunity.* No immune posture remains, only the tripwire.
- *A small attack surface.* A process parsing hostile guest input while holding
  plaintext and a CA key is new, and it sits on the path for all HTTP and HTTPS
  rather than a named few. This cost is paid in full as soon as any host is
  inspected, which is why it is not an argument against inverting the default.
- *Cheap refusals*, as above.

**Costs that are not security properties.** Every byte is decrypted and
re-encrypted in userspace: measured over loopback, 512 MB, best of three —
direct 1876 MB/s, spliced 1681 MB/s, terminated 729 MB/s. Roughly 2.3× the cost
of a splice and still an order of magnitude above any link this reaches, but
measured idle; contention with guests on a loaded host is unmeasured.

**Tracked claims this falsifies.** The instruction to export
`http_proxy`/`https_proxy` in `workloads/vm-base/workload.toml`,
`docs/schema-reference.toml` and `docs/workloads.md`; the statement in
`lib/vm.py` and those same files that the allowlist works *with no interception
and no CA*; `docs/vm-egress-walkthrough.md`, whose spine is the advertised
literal and which needs rewriting rather than editing; and ADR 006's
*Consequences*, which takes an amendment naming this record. They do not all
become false at the same moment, so they are corrected with the change that
breaks each rather than in one sweep.

**Not decided here.** Whether `Host`-binding must cover HTTP/2 relayed hosts
(closing it needs an HPACK decoder); behaviour on redirects and protocol
upgrades; what the inspector may log, given `Authorization` headers are visible
on every host; TLS on non-standard ports; and the SELinux domain for a
network-facing process holding a private key.
