# ADR 007: Credentials live in a per-workload broker, substituted per host

**Status:** **Accepted, not implemented.** Depends on the transparent egress
inspector, which is designed but unbuilt; this ADR records the credential
architecture that design assumes, and the decision not to fold the two together.

**Date:** 2026-08-16.

## Context

`libexec/agent-broker` holds a provider API key that a sandboxed VM never
receives, and attaches it to outbound requests the guest makes through it. It is
one host-wide service (`agent-broker.service`, `DynamicUser=yes`), reached at an
advertised endpoint the guest is handed as `WORKLOAD_BROKER_URL`. Callers are
identified by the uid owning the far end of the connection, recovered from
`/proc/net/tcp` — under passt that uid is the workload's own and is unforgeable
by the guest (ADR 006). See `docs/agent-broker.md`.

Three properties of the current shape bound what it can express:

- **One profile per sandbox.** `build_profiles()` resolves each sandbox to a
  single `(upstream, credential, auth_header, auth_format)`. A workload that
  needs two providers cannot have them.
- **Dispatch is by uid alone.** There is no per-host dimension anywhere in the
  broker; the upstream is fixed by config, deliberately, so it is not a general
  proxy.
- **No path or method policy.** `path = profile.prefix + self.path`, with the
  caller controlling the suffix entirely, and the only method restriction is
  which `do_*` handlers exist.

Meanwhile the planned egress inspector terminates TLS for a VM workload's
traffic on ports 80 and 443, reached by a uid-keyed transparent redirect rather
than by guest configuration. It matches the destination hostname against a
per-workload allowlist, may constrain method and URL path per host, binds the
`Host` header to the name that authorised the connection, and re-originates
upstream by name with full certificate verification. It runs as the workload's
own user, `_wl-<name>`, and holds a per-workload CA whose only relying party is
that same workload's guest.

**The two do not compose.** Every channel a guest has is subject to hostname,
method and path policy *except* the one carrying a real credential, which is
constrained only by its upstream host. An agent reaching the broker may issue
any path on that provider with the real key attached. That is backwards: the
credential-bearing channel should be the most constrained, not the least.

Folding the broker into the inspector is the obvious repair and is rejected
here. The inspector runs as `_wl-<name>` — the uid QEMU runs as — so a guest
escape would obtain any credential the inspector held. The broker's `DynamicUser`
identity (systemd allocates from 61184–65519, disjoint from the workload range
10000–52948) is precisely what prevents that today. Merging would also put a
provider key behind a parser handling every ClientHello and every HTTP request
the guest emits, rather than only requests to one endpoint.

## Decision

1. **The broker runs per workload, not host-wide.** One instance per workload
   that declares credentials, each with its own `DynamicUser` identity and its
   own `LoadCredentialEncrypted=` lines naming only that workload's material.

2. **The broker is chained behind the inspector, not merged with it.** The
   inspector owns hostname, method and path policy and the guest-facing TLS
   termination. The broker owns credentials and nothing else. For a host
   declared credential-backed, the inspector re-originates to that workload's
   broker instead of to the origin; the broker substitutes the credential and
   forwards.

3. **Credentials are selected per host.** A credential is named on the policy
   entry for the host it belongs to, so one workload may hold several. The
   broker's profile table is keyed by `(workload, Host)` rather than by
   workload alone. A `Host` with no entry in that table is **refused** — there
   is no default profile and no per-host analogue of `allow_unknown_callers` —
   and the broker resolves the profile from its *own* table rather than trusting
   the inspector to have bound the header correctly. See *Rationale*: this is a
   change to the threat model of the component holding the keys, not a schema
   detail.

4. **The guest is told nothing.** `WORKLOAD_BROKER_URL` and `vm_broker_env()`
   are removed. The guest is configured with each provider's ordinary URL and a
   placeholder credential of plausible shape; the broker discards the
   placeholder and substitutes the real value, as it already does for a forged
   one.

5. **Substitution is limited to credentials carried in a request header.**
   Signature-based schemes (AWS SigV4 and kin), mutual TLS, and OAuth token
   exchange are out of scope. See *Consequences*.

6. **The guest's route to the broker is deleted, not policed.** Each instance
   listens on a uid-derived loopback address — the same offset arithmetic
   `vm_management_address()` uses, in a disjoint range — and the inspector dials
   it directly. The advertised `192.0.2.1:8081` endpoint, the `wl_broker_dest`
   map and the `inet workload_broker` table go with it. A guest cannot reach a
   `127.x` address at all: that range is its *own* loopback, so the packet never
   leaves its stack. Reachability becomes structural rather than rule-enforced,
   which is the same property ADR 006 relies on for the management address.

7. **The inspector→broker leg is plaintext, and the broker verifies the
   origin.** Both ends are host-local, on a loopback address no guest can
   address, and the caller is identified by uid rather than by anything it
   presents — TLS there would buy nothing and would hand the inspector a second
   trust anchor to hold and rotate. The consequence that must be stated rather
   than discovered: on a credential-backed host the inspector never dials the
   origin, so the *broker's* configuration decides how that origin's certificate
   is verified, `relax_x509_strict` included. Two hosts in one workload's
   allowlist can therefore be verified to different standards, decided in
   different files.

8. **Per-workload instances are generated units, and workloadctl owns their
   lifecycle.** A template unit cannot carry a variable number of
   `LoadCredentialEncrypted=` lines — one workload with three providers needs
   three, the next needs one — so the generator writes a full unit per workload,
   `workload-<name>-broker.service`, exactly as it already writes
   `workload-<name>-setup.service` and the rest. The instance is started and
   stopped with the workload rather than enabled by hand.

   *Corrected 2026-08-20.* This decision previously said "generated drop-ins
   over the shipped unit", which is not realisable: a drop-in attaches to a
   unit, and `agent-broker.service` is a single non-templated unit, so
   `agent-broker.service.d/` overrides that one service rather than producing
   one instance per workload. The variable-directive argument is sound and
   rules out a template; what it leaves is the mechanism this project already
   uses everywhere else. Two things follow for free — the instance lands in
   `workload_run_files()`, so `PartOf=` and ordering work the way every other
   workload unit's does instead of being special-cased, and `drift` covers it
   as an ordinary run-file with no extra machinery.

   This reverses the boundary `docs/schema-reference.toml` states today —
   "workloadctl provides reachability only. It does not run the broker or know
   what a credential is" — in both halves, deliberately. See *Rationale*.

9. **The `credential` name in `workload.toml` is the authority, and nothing
   travels on the wire.** The broker's `(workload, Host)` table must contain a
   matching entry; a `credential` naming material that workload's instance does
   not load is a startup error, and so is a table entry that resolves the same
   host to different material. The inspector sends no credential name and no
   selector of any kind — it dials the broker, and identity plus `Host` are
   everything the broker needs.

10. **`profile.prefix` is dead under chaining.** The broker prepends its
    upstream's base path to every forwarded request, which composes only while
    the guest is sending a bare endpoint suffix to a broker URL. Once the guest
    sends the provider's ordinary full path (decision 4), a prefixed upstream
    produces `/v1/v1/messages` — and, worse, the path the inspector *authorised*
    stops being the path the provider receives. An `upstream` carrying a base
    path becomes a configuration error rather than a silently doubling one.

11. **Credentials require inspection, and `[vm.network].broker` goes away.**
    `credential` requires `tls = "inspect"`, which requires
    `egress = "filtered"`, so the configuration "give this VM a credential
    without also building it a hostname allowlist" ceases to exist. That
    reverses an argued position in `docs/workloads.md` and is not a side effect;
    see *Rationale*. `broker` becomes a validation error under
    `tls = "inspect"` that names `credential` as the replacement, is retained
    only for the pre-inspection posture, and is deleted with `vm_broker_env()`
    and `vm_uses_broker()` when that posture does.

## Rationale

**Per-workload instances follow from credentials becoming plural.**
`nftables/workload-broker.nft` already chose a map over a set for this case, and
says why: one shared process holding every workload's credentials means "a single
bug leaks the set rather than one member of it". One credential per sandbox made
that theoretical. Several credentials per sandbox makes it the expected state.
That argument is about where credentials live; the map was only ever how a guest
reached them. Under decision 6 the guest reaches them nowhere, so per-workload
instances need a listener address each and no nftables at all — one fewer
mechanism than the shape this ADR started from.

**Chaining rather than merging keeps the uid separation that does the work.** A
QEMU breakout yields `_wl-<name>`. The broker is a different uid in a disjoint
range, so the escape cannot `ptrace` it or read the tmpfs its credential was
decrypted into. That property is worth more than the duplication chaining
leaves behind, and the duplication is small: two TLS terminators and two
processes, both of which already exist.

**Per-host selection belongs to the inspector because per-host is what it
already is.** Giving the broker its own hostname matcher would mean a second
fnmatch implementation, a second apex-trap rule, and two allowlists that can
disagree — the same argument that keeps hostname policy in one place. (Written
when that place was the shipped tinyproxy configuration; it is now the egress
inspector, ADR 008, and the argument is unchanged by the move.)

**Keying on `Host` moves credential selection from configuration alone to
configuration plus a request header, and that is a threat-model change.**
`docs/agent-broker.md` states the property being qualified in those words —
"**`upstream` is fixed and never taken from a request.** That is the security
property" — and `libexec/agent-broker` repeats it at the top of the file. What
survives is the important half: the upstream is still a lookup into a closed set
written by an operator, never a value taken from the request, so this is not a
general proxy and the guest still cannot name a destination. What changes is that
a header now selects *which* member of that set, and therefore which credential
is attached and to whom. Two consequences follow, and decision 3 takes the
conservative answer to both.

An unknown `Host` is refused rather than falling through to a default. The uid
dimension has `allow_unknown_callers`, which the broker warns about at startup
precisely because it is dangerous; a second such knob on the host dimension
would let a typo'd hostname collect a real credential, which is the failure this
component exists to make impossible. And the broker re-validates the `Host`
against its own table rather than trusting the inspector's binding, because
without that a bug in the inspector's `Host`-binding becomes credential
*misdirection* — the wrong key sent to a host the operator did allow — rather
than a policy bypass caught by the next layer. That matters concretely: the
binding is documented as unenforced on the h2 path, so the inspector's guarantee
is known to have a hole in it today. Re-validation is a dict lookup on the path
that was already doing a dict lookup, and it converts that hole into a 4xx.

**Reversing the boundary is the price of policing the credential channel at
all.** Today workloadctl provides reachability and knows nothing about
credentials, and that separation is clean: an operator writes `broker.toml`, and
`[vm.network].broker` says only "this workload may reach the thing". Under
chaining, `credential = "github-token"` sits in `workload.toml`, so workloadctl
knows a credential's *name*, and per-workload instances are started as part of a
workload's unit set, so workloadctl runs the broker. Both clauses of the stated
boundary fall. The alternative — keep the boundary and let the operator wire
instances by hand — means the cross-check that catches a `credential` naming
material the instance does not load cannot exist, and the guest's route can be
left open by omission. A separation that can be silently misconfigured into the
hole this ADR closes is not worth keeping.

**Coupling credentials to inspection reverses an argued decision, and the
argument it reverses was right about the wrong question.** `docs/workloads.md`
records that `broker` deliberately does not require `egress = "filtered"`,
because "the broker holds the credential either way, so an unfiltered guest
still cannot obtain one. Filtering is what stops the guest reaching *other*
destinations, which is a separate question with a separate answer." That holds
exactly as long as the broker is reached at an advertised endpoint — the
credential stays out of the guest whether or not anything else is filtered. It
stops holding under decision 6: the route to the broker *is* the inspector now,
so an uninspected workload has no route at all. The capability being removed is
real ("a credential without an allowlist") and no shipped bundle uses it. The
narrowest way to keep it would be to let `egress = "open"` retain the advertised
endpoint, which reintroduces for that workload precisely the unpoliced channel
decision 6 deletes — so the honest answer is that credentials now require
inspection, written where the opposite is argued today.

**Removing `WORKLOAD_BROKER_URL` removes the last endpoint the guest knows.**
The inspector's whole premise is that reachability is not guest-configurable,
because the adversary — a prompt-injected agent, or software it installed — is
exactly the party that would unset a variable to escape policy. The broker's
variable is not that hazard (unsetting it loses the guest its credential, which
is self-harm rather than evasion), but a guest that knows no endpoints at all is
a simpler thing to reason about than one with a documented exception.

**The peer-uid mechanism survives unchanged; the guest's route to the broker
does not.** The inspector runs as `_wl-<name>`, so a connection it opens to the
broker still carries the workload uid and the `/proc/net/tcp` identification is
untouched. But it must dial the broker's listener **directly**, and the
advertised endpoint must be deleted rather than reused, which decision 6 states.

The tempting shape — let the inspector dial the advertised endpoint "exactly as
a guest does" — is the one shape that leaves this ADR's central hole open.
`nftables/workload-broker.nft` translates on `meta skuid` alone, and under passt
a guest's traffic wears the same `_wl-<name>` uid the inspector runs as, so the
map cannot distinguish them. The advertised port is neither 80 nor 443, so no
inspector redirect intercepts it, and the translated destination is host-local,
which the shipped `oif lo` accept admits. A guest that hardcodes the literal
would keep exactly today's access to the real credential — unpoliced, which is
what this ADR exists to end. Removing `WORKLOAD_BROKER_URL` stops *telling* the
guest an address that is a documented constant, not a secret.

## Consequences

**Gained.**

- A workload may use several credentialed services while holding none of them.
  What is not in the guest cannot be exfiltrated from it.
- Method and path policy reaches the credential channel: "may POST
  `/v1/messages` and nothing else" becomes expressible, enforced by the
  component that already matches paths.
- A credential leak is bounded by one workload rather than by the host.
- The guest needs exactly one trust anchor — the inspector's per-workload CA —
  and cannot come to need a second. The broker's guest-facing TLS is optional
  and unset in the default deployment (the advertised URL is `http://`), so in
  most deployments there is no second anchor to remove today; what changes is
  that a deployment enabling `tls_cert`/`tls_key` no longer puts a private CA in
  front of the guest at all, because the broker stops facing it.
- `vm_broker_env()`, `VM_BROKER_ENV_VAR` and the `WORKLOAD_BROKER_URL` contract
  become deletable, and so do `nftables/workload-broker.nft`,
  `vm_broker_element()` and `vm_broker_map_command()`: with the guest's route
  gone, nothing adds an element and an empty map is a mechanism pretending to be
  a control.
- The credential channel's reachability stops being enforced by a rule and
  becomes a property of the address family, which is the strongest form this
  repo has — no rule to misorder, no map to leave stale, nothing to get wrong on
  a restart.

**Costs.**

- N broker processes instead of one, each with a unit, an identity and a
  credential set. Idle cost is small; operational surface is not zero.
- Two TLS *sessions* across three legs. The inspector terminates the guest's;
  the broker originates its own to the provider; the leg between them is
  plaintext by decision 7, so it is two terminators and not three.
- `broker.toml`'s per-sandbox model has to grow a per-host dimension, and the
  entitlement moves next to the workload it belongs to.
- The configuration "a credential without a hostname allowlist" is removed
  (decision 11). Nothing shipped uses it.
- A workload using credentials cannot take the whole-workload `tls = "splice"`
  escape hatch, because `credential` requires `tls = "inspect"` and a
  credential host may not appear in `splice` either. Both rules are right —
  under splice nobody opens the request, so a credential would be silently inert
  — but together they mean a credential-backed host has no exemption path, which
  is the one thing the inspector's design argues hardest against. It is
  therefore a **startup refusal that names the remedy** rather than a validation
  error to be decoded: this workload's credentials cannot be attached under
  splice; remove the `credential` lines, or splice the other hosts individually
  and leave the credential hosts inspected. The failure this guards against is
  an operator reaching for the escape hatch at 2am and getting a rule citation;
  that is survivable when the error says what to type.
- An upstream with a base path is a configuration error (decision 10) where it
  used to be a working feature. The shipped example
  (`docs/agent-broker.toml.example`) has no path, so nothing breaks today —
  which is exactly why this would otherwise be found by whoever first sets one.

**Not covered, and deliberately so.** Substitution rewrites a request header.
It cannot rewrite:

| scheme | why not |
|---|---|
| request signing (AWS SigV4 and kin) | the signature covers method, path, headers, body hash and timestamp; the request must be re-signed, which is per-provider canonicalisation |
| mutual TLS | a client certificate cannot be supplied from the middle of a split session |
| OAuth token exchange | needs the broker to mint and exchange, not substitute — tractable per provider, but a different mechanism |
| key in a query parameter or body field | mechanically possible; the broker forwards bodies verbatim today and would have to parse and re-serialise |

Header-carried credentials cover the common case. The rest should be declared
unsupported rather than discovered by an operator when a tool fails.

**A second detail that will bite.** An instance must bind the address derived
for *its* workload. The broker's `listen_address` defaults to `127.0.0.1`, and
an instance left on the default sits at an address every other workload's
inspector also dials — which grows the hole decision 6 closes. The per-instance
value is generated, never defaulted, and `0.0.0.0` is worse than either.

**A detail that will bite.** Many SDKs validate the *shape* of a credential
before making any request (`ghp_`, `sk-ant-`, `sk_live_`). The placeholder the
seed writes has to be plausible per provider, or the client fails before the
broker sees a packet.

**Sequencing.** The broker works today and is proven end to end against a real
authenticated upstream; the inspector does not exist. Nothing here is built
until the inspector is, and the broker keeps its current host-wide shape in the
meantime. This ADR is a decision about direction, not a change already made.
