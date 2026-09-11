# ADR 009: Containers get the VM egress mechanism by presence of a trigger, and the inspector keeps the workload's uid

**Status:** Implemented. Extends [ADR 008](008-transparent-egress-inspection.md)
and [ADR 007](007-per-workload-credential-broker.md) to container workloads;
decides nothing new about the mechanism itself. Most of this record is the
alternatives that lost, kept because each is the obvious idea and will be
proposed again.

## Context

ADR 006–008 gave VM workloads egress filtering, transparent TLS inspection and a
per-workload credential broker. Container workloads — the older substrate — had
none of it. Two questions followed: whether containers need the same treatment
at all, and if so what the container-side shape should be, given that the two
substrates differ in exactly the places the VM design leaned on:

- A VM had no deployed instances when its egress work started, so it could
  default to `egress = "filtered"` with nothing to break. Containers have live
  deployed workloads on every host.
- A VM is one guest, so "the workload made this request" and "the guest made
  this request" are the same sentence. A `pod`- or `bridge`-mode workload is N
  containers under one `_wl-<name>` uid.
- A VM resolves names through a per-workload synthesising responder. A
  container resolves through the host's resolver.

Separately, the inspector runs as the workload's own uid, and the `output` chain
of `workload-filter.nft` consequently carries two notions of "this workload"
that every rule has to pick between. That has already produced one real hole
(below), and giving the inspector its own uid is the obvious repair.

## Decision

1. **Containers get parity with where the VM side stands, not a lesser
   version.** Not every container here is operator-authored: some run images
   this project did not build and binaries it did not compile. That is close
   enough to the hostile-or-curious-guest threat model ADR 008 was built for to
   warrant the same treatment. Scope is egress policy, the credential broker
   and the request log. Sandbox concealment is explicitly *not* included — it
   is unfinished for VMs, and pulling containers into an unsettled design would
   mean building against a moving target twice. Revisit for containers only
   after it ships for VMs, if ever.

2. **The mechanism is shared byte-for-byte; only the arming differs.** The
   listener, both nft table skeletons, the broker binary, the policy document
   shape and `lib/peer_identity.py` are the VM ones unchanged. The container
   contributes `workload-container-inspect`/`-filter` as arming helpers and a
   `[network]` schema mirroring `[vm.network]`. `docs/egress-and-broker-architecture.md`
   §5 tabulates the genuine differences.

3. **A container is inspected by presence of a trigger, and only by that.**
   `container_uses_inspect()` (`lib/config_parser.py`) is true when any one of
   `[network].hosts`, `[[network.allow]]` or `[[network.policy]]` is present.
   There is no `egress` key on the container side and no default-deny for a
   container that has not opted in. Host-network mode is never inspected.

4. **The egress inspector runs as the workload's uid, and will keep doing so.**
   The rules that need to distinguish inspector traffic from guest traffic use
   `socket cgroupv2 level 2` selectors; `tests/test_nft_selector_intent.py`
   pins every rule in the chain to the selector its purpose requires.

## Rationale

### Why the trigger is the whole statement

The presence of `hosts`, `allow` or `policy` already *is* the statement that
this workload's egress is governed. A second way to say it — an `egress`
scalar in `[network]` — is a knob that has to agree with itself; the VM side
ended up validating that agreement in three places, and containers were an
opportunity not to repeat it.

`[[network.policy]]` cannot be the *sole* trigger: that leaves
`hosts = ["*.pypi.org"]` on its own doing nothing, an allowlist that reads as
enforcement and is not. `hosts` is already a trigger on the VM side, so three
triggers is parity, not a container invention. Erroring on hosts-without-policy
instead is the same amount of code, spent forbidding a key rather than making
it work.

### Why no default-deny for containers

The VM could default that way because none were deployed when the work
started. Containers have live deployed workloads, and opt-in-by-presence is
what makes an existing workload unaffected regardless of how much of the chain
is built. Read that exactly: it rules out a key that could default-deny a
workload *without* giving it an inspector. A *triggered* container is in
`wl_filtered` and meets the drop like any VM.

### Why `tls = "inspect"` is defaulted the same way, not demanded on every rung

Requiring it everywhere makes the minimum filtered workload two keys, one of
which needs knowledge of the image's trust store, and it terminates TLS in
order to apply zero rules — with no policy entries there is nothing to inspect
*for*. Making `tls` always explicit is zero magic but is again two keys, a
divergence from the VM which does default, and forces the choice at the moment
the operator knows least about it.

### Why the inspector does not get its own uid

The observation behind the proposal is real. The `output` chain carries two
notions of "this workload":

- `meta skuid @wl_filtered` — the guest **and** the inspector, which share a uid;
- `socket cgroupv2 level 2 @wl_egress_cg` — the inspector only.

Six rules use the cgroup form, and picking the wrong one is a silent hole or a
silent outage, never an error. The cross-workload live guard was first written
`meta skuid @wl_filtered` where the intent was "exempt the host's own tooling";
`@wl_filtered` is the strictly narrower set, so every unfiltered workload and
every ordinary shell on the host walked through it, reached a filtered
workload's listener, and had its dials written into that workload's egress
records. The repair was `meta skuid != 0`. Two overlapping notions of "which
workload" are what made that mistake available, and the root cause is that the
inspector's traffic and the guest's carry the same uid.

A second uid does not fix it, because `uid → workload` is a **bijection** and
that bijection is what keeps the design registry-free. Breaking it is not a
local change to six rules; it turns arithmetic into a lookup at every one of:

- `workload_name(uid)` in `lib/peer_identity.py` — how the broker answers
  "which workload is calling me" and how the listener attributes a caller.
  This is the load-bearing case: with two uids per workload the map is no
  longer injective, so every consumer must first ask which *kind* of uid it
  holds.
- `derived_subid_range()` in `lib/workload_lib.py` — a 64K subid block per
  uid. A second uid per workload either halves the workload ceiling or needs a
  second, non-subid uid range to live in.
- every uid-derived address in `lib/workload_addr.py` (`management_address`,
  `inspect_address`, `broker_listen_address`, `resolve_address`,
  `nflog_group`) — all `base + (uid − UID_MIN)`.
- the `meta skuid 10000-52948` ct-mark rule and every `typeof meta skuid` set
  key in both tables.

Plus group or ACL access to the CA key and policy under `/run`, and a rewrite
of six security-critical rules in the path that took six rungs to get right.
The two-selector split is the price of "the uid *is* the workload", and that
property buys far more elsewhere than the split costs in one chain. Do not
re-propose this without first showing what replaces `workload_name()`.

### Why the ingress/egress asymmetry is correct

Ingress is two rules; egress is nineteen. That is not an imbalance to correct:
**ingress is a bind, egress is an interception.** A workload can only receive
on what it declared, and the enforcement is the *absence* of a socket — there
is nothing to filter. Egress needs the machinery because the guest dials
arbitrary destinations and is never asked to cooperate.

## Rejected alternatives

| Rejected | Why it lost |
|---|---|
| Widen `vm_uses_inspect()` to understand `[network]` | Its body is legitimately VM-shaped (`"vm" in config`, the bridge exclusion, `egress` read off `[vm.network]`). Teaching it `[network]` makes one predicate branch on substrate internally. Each substrate's gate stays honest about what it checks; the *command output* is what gets unified |
| Hand-written `is_vm` branches per command | `get_substrate()` **is** that branch, written once. More hand-rolled routers entrench the split |
| `uses_inspect()` defaulting to `False` on the `Substrate` ABC | A default lets a third substrate silently inherit "never inspected". Abstract converts "did we update every call site?" from a grep into a class-instantiation error |
| Per-workload nft tables | Buy no safety — uid recycling is already closed by `purge_uid_elements()` in `lib/nft.py` — and cost N base chains at one hook instead of one shared chain's O(1) set lookup |
| systemd `NFTSet=` | Auto-inserts a unit's *own* cgroup/uid/gid into one set and cannot populate the **destination** allowlists (`wl_allow4/6`, `wl_inspect_dst`) the TOML requires. Adopting it means running it alongside the hand-rolled wrapper: two mechanisms, no capability gained |
| Warn-and-arm-what-resolved for an unresolvable `[[network.internal]]` name | Precisely the silent degrade the VM rule was written against: the workload runs and one LAN host is mysteriously refused, reading as a broken service rather than a policy decision |
| A per-workload DNS responder for containers | A container resolves through the host/podman resolver, not a per-workload nameserver. Not free: a `[network]` trigger drops port 53 unless that resolver is on loopback, and no name the guest composes is rewritten to the inspector — the container's DNS is the host's |
| Image trust-store probing as a gate | A probe reports on the image, not on the binary that will make the request, so it can be confidently wrong. At most a `doctor` hint, never a gate |
| Re-resolution on a timer | A second resolution with a second answer, which the filter-element builder already documents as its own problem |
| Consolidating `workload-container-inspect` into `workload-vm-inspect` | Looks like duplication, isn't: the container helper is already the smaller one *because* it reuses the listener, `peer_identity` and every uid-keyed element builder. What remains in each is per-substrate by construction — the two halves state different rules, not the same rule twice |
| Splitting the inspect listener into `lib/` modules | Pure logic inside it (policy matching, SNI/Host parsing, upstream pool) could move, but this is the file rungs 1–6 were fought in and it is covered by six hardware rigs. Last, if ever |
| A per-mode strategy record for the `single`/`pod`/`bridge` axis | Would consolidate ~22 `mode ==` branch sites — and "single-container TOMLs produce byte-identical units" is a deliberate constraint, and this is exactly the code that would break it quietly |

## Consequences

**Gained.**

- A container image this project did not build is bound by the same policy a
  hostile VM guest is, through one implementation and two arming scripts.
- Enabling it costs one line of TOML, and an unmodified workload is untouched.

**Given up.**

- *Per-container attribution.* The record names the workload, because the
  uid is the workload and every container in a pod or bridge workload
  re-originates through it. An operator reading a pod workload's record gets a
  true statement they will read as a narrower one; `docs/cli.md` discloses it,
  and it is a gap by design, not a bug to fix.
- *A default-deny posture for containers.* Ruled out permanently as far as
  this work goes, for the deployed-workload reason above.
- *`[[network.http2]]`.* Deferred, not rejected; `[[vm.network.http2]]` shows
  the shape.
- *Homelab-root trust in containers and provisioning markers* are independent
  of this chain in both directions and were not folded in. The *inspector* CA
  is in scope and shipped.

## What running it corrected

Every unit was green, and the container broker was inert on hardware: the
instance unit was generated, ordered ahead of the right unit, given its
`IPAddressAllow=` and its internal-set exemption, and pulled in by nothing.
`Before=` orders a unit; it does not start one. Forty-five unit rows passed
with it in place because each of them reads the broker unit's own text and the
missing half lived in a different unit. The rig row that found it is the kind
`tests/manual/README.md` describes: it makes a real request and asserts on the
provider's side, not on the unit's.
