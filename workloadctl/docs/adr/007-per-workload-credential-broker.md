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
   workload alone.

4. **The guest is told nothing.** `WORKLOAD_BROKER_URL` and `vm_broker_env()`
   are removed. The guest is configured with each provider's ordinary URL and a
   placeholder credential of plausible shape; the broker discards the
   placeholder and substitutes the real value, as it already does for a forged
   one.

5. **Substitution is limited to credentials carried in a request header.**
   Signature-based schemes (AWS SigV4 and kin), mutual TLS, and OAuth token
   exchange are out of scope. See *Consequences*.

## Rationale

**Per-workload instances follow from credentials becoming plural.**
`nftables/workload-broker.nft` already chose a map over a set for this case, and
says why: one shared process holding every workload's credentials means "a single
bug leaks the set rather than one member of it". One credential per sandbox made
that theoretical. Several credentials per sandbox makes it the expected state.
The map keys on uid and carries the listener address as its value, so
per-workload instances need no nftables change — only an element per workload,
which is already how every other per-workload rule works.

**Chaining rather than merging keeps the uid separation that does the work.** A
QEMU breakout yields `_wl-<name>`. The broker is a different uid in a disjoint
range, so the escape cannot `ptrace` it or read the tmpfs its credential was
decrypted into. That property is worth more than the duplication chaining
leaves behind, and the duplication is small: two TLS terminators and two
processes, both of which already exist.

**Per-host selection belongs to the inspector because per-host is what it
already is.** Giving the broker its own hostname matcher would mean a second
fnmatch implementation, a second apex-trap rule, and two allowlists that can
disagree — the same argument that keeps hostname policy out of the shipped
tinyproxy configuration once inspection exists.

**Removing `WORKLOAD_BROKER_URL` removes the last endpoint the guest knows.**
The inspector's whole premise is that reachability is not guest-configurable,
because the adversary — a prompt-injected agent, or software it installed — is
exactly the party that would unset a variable to escape policy. The broker's
variable is not that hazard (unsetting it loses the guest its credential, which
is self-harm rather than evasion), but a guest that knows no endpoints at all is
a simpler thing to reason about than one with a documented exception.

**The peer-uid mechanism survives unchanged.** The inspector runs as
`_wl-<name>`, so a connection it opens to the broker still carries the workload
uid, and if it dials the advertised endpoint rather than the listener directly,
the existing uid-keyed redirect and `SO_ORIGINAL_DST` recovery work exactly as
they do for a guest. No change to how the broker identifies callers.

## Consequences

**Gained.**

- A workload may use several credentialed services while holding none of them.
  What is not in the guest cannot be exfiltrated from it.
- Method and path policy reaches the credential channel: "may POST
  `/v1/messages` and nothing else" becomes expressible, enforced by the
  component that already matches paths.
- A credential leak is bounded by one workload rather than by the host.
- The guest needs exactly one trust anchor — the inspector's per-workload CA.
  The broker stops facing the guest, so its `tls_cert`/`tls_key` and any private
  CA behind them leave the guest's trust store.
- `vm_broker_env()`, `VM_BROKER_ENV_VAR` and the `WORKLOAD_BROKER_URL` contract
  become deletable.

**Costs.**

- N broker processes instead of one, each with a unit, an identity and a
  credential set. Idle cost is small; operational surface is not zero.
- Two TLS terminators on the credentialed path. The inspector terminates the
  guest's session; the broker terminates its own to the provider.
- `broker.toml`'s per-sandbox model has to grow a per-host dimension, and the
  entitlement moves next to the workload it belongs to.

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

**A detail that will bite.** Many SDKs validate the *shape* of a credential
before making any request (`ghp_`, `sk-ant-`, `sk_live_`). The placeholder the
seed writes has to be plausible per provider, or the client fails before the
broker sees a packet.

**Sequencing.** The broker works today and is proven end to end against a real
authenticated upstream; the inspector does not exist. Nothing here is built
until the inspector is, and the broker keeps its current host-wide shape in the
meantime. This ADR is a decision about direction, not a change already made.
