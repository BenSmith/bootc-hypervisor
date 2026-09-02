# ADR 007: Credentials live in a per-workload broker, substituted per host

**Status:** Implemented. Depends on the transparent egress inspector
([ADR 008](008-transparent-egress-inspection.md)), which is what dials the broker.

## Context

`libexec/agent-broker` holds a provider API key that a sandboxed VM never
receives, and attaches it to outbound requests the guest makes through it.
Callers are identified by the uid owning the far end of the connection, recovered
from `/proc/net/tcp` — under passt that uid is the workload's own and is
unforgeable by the guest ([ADR 006](006-vm-networking-passt-not-managed-bridge.md)).

It began as one host-wide service reached at an advertised endpoint the guest was
handed as `WORKLOAD_BROKER_URL`. Three properties of that shape bounded what it
could express:

- **One profile per sandbox.** Each sandbox resolved to a single
  `(upstream, credential, auth_header, auth_format)`. A workload needing two
  providers could not have them.
- **Dispatch by uid alone.** There was no per-host dimension anywhere in the
  broker; the upstream was fixed by config, deliberately, so it is not a general
  proxy.
- **No path or method policy.** The caller controlled the path suffix entirely,
  and the only method restriction was which handlers existed.

Meanwhile the egress inspector terminates TLS for a VM workload's traffic on
ports 80 and 443, reached by a uid-keyed transparent redirect rather than by guest
configuration. It matches the destination hostname against a per-workload
allowlist, constrains method and URL path per host, binds the `Host` header to the
name that authorised the connection, and re-originates upstream with full
certificate verification. It runs as the workload's own user and holds a
per-workload CA whose only relying party is that workload's guest.

**The two did not compose.** Every channel a guest had was subject to hostname,
method and path policy *except* the one carrying a real credential, which was
constrained only by its upstream host. An agent reaching the broker could issue
any path on that provider with the real key attached. That is backwards: the
credential-bearing channel should be the most constrained, not the least.

Folding the broker into the inspector is the obvious repair and is rejected. The
inspector runs as `_wl-<name>` — the uid QEMU runs as — so a guest escape would
obtain any credential it held. The broker's `DynamicUser` identity (systemd
allocates from 61184–65519, disjoint from the workload range 10000–52948) is
precisely what prevents that. Merging would also put a provider key behind a
parser handling every ClientHello and every HTTP request the guest emits, rather
than only requests to one endpoint.

## Decision

1. **The broker runs per workload, not host-wide.** One instance per workload
   that declares credentials, each with its own `DynamicUser` identity and its own
   `LoadCredentialEncrypted=` lines naming only that workload's material.

2. **The broker is chained behind the inspector, not merged with it.** The
   inspector owns hostname, method and path policy and the guest-facing TLS
   termination. The broker owns credentials and nothing else. For a host declared
   credential-backed, the inspector re-originates to that workload's broker
   instead of to the origin; the broker substitutes the credential and forwards.

3. **Credentials are selected per host.** A credential is named on the policy
   entry for the host it belongs to, so one workload may hold several. The
   broker's profile table is keyed by `(workload, Host)` rather than by workload
   alone. A `Host` with no entry is **refused** — there is no default profile and
   no per-host analogue of `allow_unknown_callers` — and the broker resolves the
   profile from its *own* table rather than trusting the inspector to have bound
   the header correctly.

   The material itself is declared once in a `[[vm.network.credential]]` block and
   the policy entry carries only the selector:

   ```toml
   [[vm.network.credential]]
   name        = "github-token"
   placeholder = "ghp_000000000000PLACEHOLDER000000000000"
   env         = "GITHUB_TOKEN"

   [[vm.network.policy]]
   host       = "api.github.com"
   methods    = ["GET", "POST"]
   paths      = ["/repos/myorg/*"]
   credential = "github-token"          # the selector, which IS per entry
   ```

   Putting `placeholder` on the policy entry was tried first and needs a rule
   forcing entries that name one credential to agree about it, since it is a
   property of the credential rather than of the entry — and every further
   credential-scoped fact doubles that rule. With one declaration there is nothing
   to disagree. Two errors replace the agreement rule, in opposite directions: a
   `credential` naming no block, and a block no entry selects.

   The block also carries the provider's auth convention. `auth_header` and
   `auth_format` are optional, defaulting in the broker alone to `x-api-key` and
   `{secret}`. Without them a generated config could express *less* than the
   hand-written file it replaced, and every provider wanting
   `Authorization: Bearer` answered 401 to a request every layer here had
   authorised. `validate` refuses a header name that is not an RFC 9110 field
   name, one that frames the message or is hop-by-hop, and a format string the
   broker would fail to render — which it does at startup, so the alternative to
   refusing here is a unit that will not start.

4. **The guest is told nothing.** `WORKLOAD_BROKER_URL` and `vm_broker_env()` are
   removed. The guest is configured with each provider's ordinary URL and a
   placeholder credential of plausible shape; the broker discards the placeholder
   and substitutes the real value, as it already does for a forged one.

5. **Substitution is limited to credentials carried in a request header.**
   Signature schemes, mutual TLS and OAuth token exchange are out of scope — see
   *Consequences*.

6. **The guest's route to the broker is deleted, not policed.** Each instance
   listens on a uid-derived loopback address — the same offset arithmetic
   `vm_management_address()` uses, in a disjoint range — and the inspector dials it
   directly. The advertised endpoint, the `wl_broker_dest` map and the
   `inet workload_broker` table go with it. A guest cannot reach a `127.x` address
   at all: that range is its *own* loopback, so the packet never leaves its stack.
   Reachability becomes structural rather than rule-enforced, the same property
   ADR 006 relies on for the management address.

7. **The inspector→broker leg is plaintext, and the broker verifies the origin.**
   Both ends are host-local on an address no guest can address, and the caller is
   identified by uid rather than by anything it presents — TLS there buys nothing
   and hands the inspector a second trust anchor to hold and rotate. The
   consequence that must be stated rather than discovered: on a credential-backed
   host the inspector never dials the origin, so the *broker's* configuration
   decides how that origin's certificate is verified, `relax_x509_strict`
   included. Two hosts in one workload's allowlist can be verified to different
   standards, decided in different files.

8. **Per-workload instances are generated units, and workloadctl owns their
   lifecycle.** A template unit cannot carry a variable number of
   `LoadCredentialEncrypted=` lines, so the generator writes a full
   `workload-<name>-broker.service` per workload, exactly as it writes the rest of
   a workload's units, started and stopped with the workload rather than enabled by
   hand. (Drop-ins over a shipped unit cannot express this either: a drop-in
   attaches to a unit, and a single non-templated `agent-broker.service` has one of
   those.) Two things follow for free — the instance lands in
   `workload_run_files()`, so `PartOf=` and ordering work as every other workload
   unit's does, and `drift` covers it as an ordinary run-file.

9. **The `credential` name in `workload.toml` is the authority, and nothing
   travels on the wire.** The broker's `(workload, Host)` table must contain a
   matching entry; a `credential` naming material the instance does not load is a
   startup error, and so is a table entry resolving one host to different material.
   The inspector sends no credential name and no selector — it dials the broker,
   and identity plus `Host` are everything the broker needs.

10. **`profile.prefix` is dead under chaining.** Prepending an upstream base path
    composes only while the guest sends a bare endpoint suffix to a broker URL.
    Once the guest sends the provider's ordinary full path (decision 4), a prefixed
    upstream produces `/v1/v1/messages` — and, worse, the path the inspector
    *authorised* stops being the path the provider receives. An `upstream` carrying
    a base path is a configuration error rather than a silently doubling one.

11. **Credentials require inspection, and `[vm.network].broker` goes away.**
    `credential` requires `tls = "inspect"`, which requires `egress = "filtered"`,
    so "give this VM a credential without also building it a hostname allowlist"
    ceases to exist. `broker` becomes a validation error naming `credential` as the
    replacement.

## Rationale

**Per-workload instances follow from credentials becoming plural.** The original
nftables map for reaching the broker chose a map over a set for this reason: one
shared process holding every workload's credentials means a single bug leaks the
set rather than one member. One credential per sandbox made that theoretical;
several makes it the expected state. That argument is about where credentials
live — the map was only how a guest reached them, and under decision 6 the guest
reaches them nowhere, so per-workload instances need a listener address each and
no nftables at all. One fewer mechanism than the shape this ADR started from.

**Chaining rather than merging keeps the uid separation that does the work.** A
QEMU breakout yields `_wl-<name>`. The broker is a different uid in a disjoint
range, so the escape cannot `ptrace` it or read the tmpfs its credential was
decrypted into. The duplication chaining leaves behind is small — two TLS
terminators and two processes, both of which already exist.

**Per-host selection belongs to the inspector because per-host is what it already
is.** Giving the broker its own hostname matcher means a second fnmatch
implementation, a second apex-trap rule, and two allowlists that can disagree.

**Keying on `Host` is a threat-model change, and decision 3 takes the conservative
answer twice.** `docs/agent-broker.md` states the property being qualified —
"`upstream` is fixed and never taken from a request" — and the important half
survives: the upstream is still a lookup into a closed set an operator wrote, so
this is not a general proxy and the guest cannot name a destination. What changes
is that a header now selects *which* member, and therefore which credential is
attached to whom. So an unknown `Host` is refused rather than falling through to a
default, because a second `allow_unknown_callers`-style knob on the host dimension
would let a typo'd hostname collect a real credential. And the broker re-validates
the `Host` against its own table rather than trusting the inspector's binding,
because without that a bug in that binding becomes credential *misdirection* — the
wrong key sent to a host the operator did allow — rather than a policy bypass
caught by the next layer. The binding is documented as unenforced on the h2 path,
so the inspector's guarantee is known to have a hole; re-validation is a dict
lookup on a path already doing one, and it converts that hole into a 4xx.

**Reversing the boundary is the price of policing the credential channel at all.**
Previously workloadctl provided reachability and knew nothing about credentials.
Under chaining, `credential = "github-token"` sits in `workload.toml`, so
workloadctl knows a credential's *name*, and it runs the broker. Both clauses of
the old boundary fall, deliberately: keeping it and letting an operator wire
instances by hand means the cross-check that catches a `credential` naming
material the instance does not load cannot exist, and the guest's route can be
left open by omission. A separation that can be silently misconfigured into the
hole this ADR closes is not worth keeping.

**Coupling credentials to inspection reverses an argument that was right about the
wrong question.** `broker` deliberately did not require `egress = "filtered"`,
because the broker holds the credential either way, so an unfiltered guest still
cannot obtain one. That holds exactly as long as the broker is reached at an
advertised endpoint. It stops holding under decision 6: the route to the broker
*is* the inspector, so an uninspected workload has no route at all. The capability
removed is real ("a credential without an allowlist") and nothing shipped uses it;
the narrowest way to keep it — let `egress = "open"` retain the advertised
endpoint — reintroduces precisely the unpoliced channel decision 6 deletes.

**The advertised endpoint had to be deleted, not reused.** The tempting shape is
to let the inspector dial it "exactly as a guest does". That is the one shape
leaving this ADR's central hole open: the redirect translated on `meta skuid`
alone, and under passt a guest's traffic wears the same uid the inspector runs as,
so the map could not distinguish them. The advertised port was neither 80 nor 443,
so no inspector redirect intercepted it, and the translated destination was
host-local, which `oif lo` admits. A guest hardcoding the literal would keep
exactly the unpoliced access this ADR exists to end. Removing
`WORKLOAD_BROKER_URL` stops *telling* the guest an address that was a documented
constant, not a secret — and a guest that knows no endpoints at all is a simpler
thing to reason about than one with a documented exception.

## Consequences

**Gained.**

- A workload may use several credentialed services while holding none of them.
  What is not in the guest cannot be exfiltrated from it.
- Method and path policy reaches the credential channel: "may POST `/v1/messages`
  and nothing else" becomes expressible, enforced by the component that already
  matches paths.
- A credential leak is bounded by one workload rather than by the host.
- The guest needs exactly one trust anchor — the inspector's per-workload CA — and
  cannot come to need a second, because the broker stops facing it at all.
- The credential channel's reachability stops being enforced by a rule and becomes
  a property of the address family: no rule to misorder, no map to leave stale,
  nothing to get wrong on a restart. `nftables/workload-broker.nft`,
  `vm_broker_element()`, `vm_broker_map_command()`, `vm_broker_env()` and
  `VM_BROKER_ENV_VAR` are deleted with it.

**Costs.**

- N broker processes instead of one, each with a unit, an identity and a
  credential set.
- Two TLS *sessions* across three legs: the inspector terminates the guest's, the
  broker originates its own to the provider, and the leg between them is plaintext
  by decision 7.
- The configuration "a credential without a hostname allowlist" is removed.
- A workload using credentials cannot take the whole-workload `tls = "splice"`
  escape hatch, since `credential` requires `tls = "inspect"` and a credential host
  may not appear in `splice` either. Both rules are right — under splice nobody
  opens the request, so a credential would be silently inert — but together they
  mean a credential-backed host has no exemption path, which is the one thing the
  inspector's design argues hardest against. It is therefore a **startup refusal
  naming the remedy** rather than a rule citation: remove the `credential` lines,
  or splice the other hosts individually and leave the credential hosts inspected.
  The failure guarded against is an operator reaching for the escape hatch at 2am.
- An upstream with a base path is a configuration error where it used to be a
  working feature.

**Not covered, deliberately.** Substitution rewrites a request header. It cannot
rewrite:

| scheme | why not |
|---|---|
| request signing (AWS SigV4 and kin) | the signature covers method, path, headers, body hash and timestamp; the request must be re-signed, which is per-provider canonicalisation |
| mutual TLS | a client certificate cannot be supplied from the middle of a split session |
| OAuth token exchange | needs the broker to mint and exchange, not substitute — tractable per provider, but a different mechanism |
| key in a query parameter or body field | mechanically possible; the broker forwards bodies verbatim and would have to parse and re-serialise |

Header-carried credentials cover the common case; the rest is declared
unsupported rather than discovered when a tool fails.

**Three details that bite.**

- An instance must bind the address derived for *its* workload. `listen_address`
  defaults to `127.0.0.1`, and an instance left on the default sits where every
  other workload's inspector also dials — which grows the hole decision 6 closes.
  The per-instance value is generated, never defaulted, and `0.0.0.0` is worse
  than either.
- Many SDKs validate the *shape* of a credential before making any request
  (`ghp_`, `sk-ant-`, `sk_live_`). The placeholder the seed writes has to be
  plausible per provider, or the client fails before the broker sees a packet.
- Two policy entries for one host — the documented way to vary `methods` by path —
  render that host's broker table twice, which TOML refuses. The render collapses
  on the host. `validate` had called such a config clean and the broker then exited
  at start, so every brokered request answered 502.
