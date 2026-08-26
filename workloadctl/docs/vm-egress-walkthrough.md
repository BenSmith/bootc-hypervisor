# Walkthrough: the life of a filtered VM

The reference material for VM egress is spread across three places by topic —
[Egress filtering](workloads.md#egress-filtering) and [Hostname Egress
Policy](workloads.md#hostname-egress-policy) for the schema, and [ADR
006](adr/006-vm-networking-passt-not-managed-bridge.md) for why the design is
shaped this way. This document is the other cut through the same material: one
VM, followed end to end, from the TOML through unit start to a packet leaving
the host.

Neither shipped VM bundle is filtered — `vm-base` and `virtual-forgejo` are both
`egress = "open"`, with their reasons stated inline — so the config below is one
an operator writes. Call the workload `web`, with uid 10004:

```toml
[vm.network]
egress = "filtered"                                    # the default; stated for clarity
hosts  = ["*.fedoraproject.org", "api.example.com"]    # HTTP/HTTPS, by name;
                                                       # the wildcard excludes
                                                       # the bare apex — see below

[[vm.network.allow]]                                   # everything else, by
address = "192.168.0.10:22"                            # address or by name,
reason  = "backup target; SSH, not HTTP"               # on a port that is
                                                       # not 80 or 443
```

## The fact everything rests on

passt terminates the guest's network stack and re-originates every flow as a
host socket owned by `_wl-web`. So `meta skuid` is a complete and unforgeable
per-VM selector: the guest cannot produce a packet that leaves the host without
wearing uid 10004. Every mechanism below is a consequence of that one property.

It is also what a `bridge` VM gives up. Such a guest sends from its own LAN
address, nothing of ours is in its data path, and there is no uid to match on —
which is why the validator rejects `egress`, `allow` and `hosts` alongside
`bridge` rather than accepting them and quietly doing nothing.

## Enable time: what the validator refuses

`_validate_egress` (`lib/vm.py`) rejects the configurations that would
misreport confinement:

| config | why it is refused |
|---|---|
| `filtered`, both lists empty | a VM that can reach nothing at all, which boots and then hangs |
| `hosts` with `egress = "open"` | nothing is redirected under `open`, so the list would be read by a process no connection ever reaches |
| any of these with `bridge` | no host socket in the path, so no uid, so no policy |

All three fail the enable rather than degrading silently. The whole layer exists
to prevent a VM that claims confinement and does not have it.

## Boot: what gets armed, and by whom

Because `hosts` is non-empty, the generator emits two extra socket units,
`workload-web-inspect.socket` and `workload-web-resolve.socket`, and makes them
prerequisites of `workload-web.service`. **Both listeners are socket-activated**:
the sockets bind before the VM, the services start when the guest first dials,
and both stop with the VM.

**`workload-vm-inspect up web`** — the inspect socket's `ExecStartPre`, run as
root:

1. Writes this workload's policy to `/run/workload-vm/web/inspect.json`, and
   clears the previous instance's counters. Policy is written *before* anything
   is armed, because the redirect existing is enough for the guest's first dial
   to start the listener.
2. Creates the `workload-proxy` dummy link and puts `192.0.2.1/32` on it.
   Shared and host-global, created on demand, never torn down by a workload
   stop — it holds no per-workload state and an orphan is inert. (The name is
   the retired proxy's; it is a kernel object on running hosts, and renaming it
   would strand addresses on two links for no gain.)
3. Applies both nft skeletons — the nat table *and* the filter table. The second
   is not redundant: the guard sets live in the filter table, and this unit
   starts before the VM whose prestart would otherwise be first to create it.
4. Adds this workload's listener addresses to the link: `198.18.1.4` and
   `2001:2::c612:104`, derived from uid 10004, so uniqueness is inherited from
   the uid allocator — no registry, no allocation step, no collision.
5. Arms **six elements across two tables**: the DNAT maps `wl_inspect4` /
   `wl_inspect6` (uid . port → listener), and the guard sets `wl_inspect_dst`,
   `wl_inspect_dst6`, `wl_inspect_self`, `wl_inspect_self6`. Purge-then-add, so
   the armed state is a function of the current config alone. Arming one table
   and not the other leaves a workload that looks configured and reaches nothing.
6. Resolves each `[[vm.network.internal]]` host and arms `wl_internal_ok4/6`.

**The two cgroup exemptions are not armed here.** They are armed by each
listener *service*'s own `ExecStartPre` and withdrawn by its `ExecStopPost`,
because an element resolves to a cgroup id at add time and systemd makes a fresh
cgroup on every start — at the moment the socket's prestart runs, the service has
no cgroup for one to resolve to. Each service arms both: `wl_egress_cg` in the
filter table (exempt from the default deny) and `wl_inspect_cg` in the nat table
(exempt from the redirect). One without the other is a listener that reaches
nothing, or one that dials into itself.

**`workload-vm-filter up web`** — the VM unit's `ExecStartPre`:

7. Purges every element owned by uid 10004 from the filter sets, *then* adds the
   configured ones: `10004` to `wl_filtered` and `10004 . 192.168.0.10 . 22` to
   `wl_allow4`.

That purge is the entire reason this is a script rather than three
`ExecStartPre=` lines. `ExecStopPost` deletes the entries the unit file names at
stop time, so removing an entry from `allow` and re-enabling would delete only
what is still configured and leave the dropped entry armed — permitting traffic
the config no longer permits, silently, until the host reboots. Verified on
nftables 1.1.6. The purge makes the armed state a function of the current config
alone, rather than of the config plus every config it ever had
(`libexec/workload-vm-filter:11-28`).

**The VM then boots knowing none of this.** Its cloud-config carries no proxy
variables, no resolver address and nothing else about egress. Through rung 1 it
was handed `https_proxy=http://192.0.2.1:3128` and a matching `no_proxy`, and
that was the weakness: a process free to ignore the variables did, and the
default-deny chain could only turn that into a failure rather than into a
filtered request. There is now nothing in the guest to ignore.

## The output chain

In `inet workload_filter`, at filter hook priority 0 — ahead of firewalld's
`filter_OUTPUT` at filter+10, in headroom firewalld leaves deliberately.
firewalld cannot express this policy itself: its rich language has no uid
predicate, so it can reach the traffic class but cannot tell one VM from another.

```
 1  meta skuid 10000-52948 ct mark set meta skuid or 0x40000000  (non-terminating)
 2  meta skuid @wl_filtered ct direction reply                    accept
 3  meta skuid . ip  daddr . th dport @wl_allow4                  accept
 4  meta skuid . ip6 daddr . th dport @wl_allow6                  accept
 5  meta skuid . ip  daddr . th dport @wl_inspect_dst             accept
 6  meta skuid . ip6 daddr . th dport @wl_inspect_dst6            accept
 7  meta skuid . ip  daddr @wl_inspect_self  ct dir original      drop
 8  meta skuid . ip6 daddr @wl_inspect_self6 ct dir original      drop
 9  meta skuid @wl_filtered ct dir original ip  daddr 198.18.0.0/16  drop
10  meta skuid @wl_filtered ct dir original ip6 daddr 2001:2::/48    drop
11  @wl_egress_cg th dport 53                                     accept
12  @wl_egress_cg meta skuid . ip  daddr @wl_internal_ok4 ct dir original  accept
13  @wl_egress_cg meta skuid . ip6 daddr @wl_internal_ok6 ct dir original  accept
14  @wl_egress_cg ct dir original ip  daddr @wl_internal4         drop
15  @wl_egress_cg ct dir original ip6 daddr @wl_internal6         drop
16  meta skuid @wl_filtered oif lo                                accept
17  @wl_egress_cg                                                 accept
18  meta skuid @wl_filtered udp dport 443                         drop
19  meta skuid @wl_filtered                                       drop
```

(`@wl_egress_cg` is shorthand for `socket cgroupv2 level 2 @wl_egress_cg`. There
is also a two-rule `input` chain, covered under rule 16.)

Four groups, and the order among them is the whole design:

- **2** is the reply direction, ahead of every terminating rule so no
  destination-keyed drop below ever sees a reply. It is `ct direction reply`
  rather than `ct state established` deliberately: the guest's own outbound data
  is already accepted by the tuple sets, so only the reply direction needs a rule
  — and `established` would turn the accept sets' counters from counting traffic
  into counting connections. It widens more than inspected replies, which is
  named here rather than absorbed into a rule justified by something else.
- **3–6** are the accepts: the operator's explicit `allow` grants, then the
  *redirected* connection. The filter chain runs after nat `dstnat`, so it sees
  the rewritten destination — which is why 5 and 6 match the translated tuple
  (uid . listener address . listener port), armed by the same script that armed
  the DNAT maps.
- **7–10** are the listener-plane guards, and they come *after* the served ports
  are admitted. 7 and 8 are per workload and carry per-element counters, so
  `diagnose` can say "this guest dialled its own listener on a port nothing
  serves" — the case that actually happens. 9 and 10 catch what is left, which is
  a cross-workload attempt, on a shared counter where attribution is not needed.
- **11–15** are the destination check on rule 17, and **17** is the
  re-originators' exemption. See "What rule 17 does not say".

## A packet's life

The guest runs `curl https://api.example.com`. It has not been told anything, so
this is an ordinary dial on an ordinary network:

1. It asks its resolver for `api.example.com`. Its resolver is passt's
   interception, which reaches **this workload's synthesising responder** on
   `127.130.0.4`. The responder answers with this workload's inspector address,
   `198.18.1.4` — it answers every A/AAAA that way, and it has no upstream socket
   at all, so the query never leaves the host.
2. curl opens TCP to `198.18.1.4:443`. passt re-originates it as a host socket
   owned by uid 10004.
3. `inet workload_proxy` at nat hook output (priority `dstnat`, −100, so it runs
   before the filter chain) matches `tcp dport 443`, looks uid 10004 up in
   `wl_inspect4`, and DNATs to `198.18.1.4:8443`.
4. The filter chain sees the translated tuple and rule 5 accepts it.
5. The inspector reads the ClientHello **without answering it**, takes
   `api.example.com` out of the SNI, and fnmatches it against `hosts`. It
   matches.
6. The inspector opens its own socket to `api.example.com:443` — same uid 10004,
   and that destination is in no allow set. What saves it is rule 17: the
   inspector runs as its workload's own user *on purpose*, so `meta skuid` cannot
   separate its traffic from the guest's, and the control group is the
   discriminator that survives the shared uid. systemd assigns it, a guest can
   neither enter nor forge it, and it widens no destination or port.
7. Under the default `tls = "inspect"` the connection is **terminated**. The
   inspector completes the guest's handshake with a leaf minted by *this
   workload's* own CA, verifies the origin's certificate against **the host's**
   trust anchors on its own session, and authorises every request inside by its
   `Host` header. So the guest's trust store IS touched — it has to hold this
   workload's CA, which the seed installs — and this host holds the plaintext
   for the length of the connection. That is the trade the default takes: the
   allowlist's claim, that the guest reaches these hosts and no others, is only
   true per request once something is reading the requests.

   Under `tls = "splice"` step 7 is instead a byte-for-byte replay: nothing is
   decrypted, no CA is involved, and the guest's trust store is untouched. The
   name is then checked **once**, at the front of a connection whose contents
   nothing can see. Weaker, fully supported, and the answer for a guest that
   cannot be re-seeded or a host that does not speak HTTP over 443.

Cleartext is the same path one plane over: DNAT to `:8080`, the `Host` header
read in place of the SNI, and a match **forwarded**. Under termination the two
planes converge — the same per-request authorisation runs on both.

Then the paths that don't work, which are the point:

- **The guest dials `1.2.3.4:443` directly, by literal.** The redirect keys on
  the port, not the destination, so it is DNATed into the inspector anyway —
  where a TLS record with no SNI, or a byte stream that is not a handshake at
  all, has no name to match. Dropped, and counted under *no readable name*.
  There is nothing to opt out of: this is the difference from the retired proxy,
  where the same guest simply did not use it and had to be caught by the default
  deny instead.
- **The guest asks for a host not on the list.** For HTTP, a `403` before
  anything is forwarded. For HTTPS under `inspect`, the same `403` — delivered
  *through* a completed handshake, using a leaf minted for the refused name, so
  the guest reads a sentence instead of guessing at a closed socket. Under
  `splice` there is no session to say it in, so the connection is dropped after
  the ClientHello is read and the guest cannot tell that from the host being
  down.
- **The guest speaks something other than HTTP over 443.** A database wire
  protocol, a tunnel, HTTP/2 — under `inspect` the inspector is the one reading,
  and bytes that do not begin a request line get the connection **closed**,
  counted per host under *not HTTP*. Under `splice` those bytes went through
  untouched. That per-host figure is the list of workloads to move to `splice`.
- **The guest asks for a host not on the list, by name.** It does not get that
  far: the responder answers only for names policy knows about, so the lookup
  fails first. That is a second, earlier refusal than the inspector's.

That second refusal has a trap in it. The patterns are fnmatch, not a DNS suffix
match, so `*.fedoraproject.org` requires something before the dot and does **not**
cover the bare `fedoraproject.org`. On the VM above, `download.fedoraproject.org`
is reached and `fedoraproject.org` is refused — with a 403 identical to the one
an entirely unlisted host gets. Nothing distinguishes "you did not allowlist this"
from "your pattern did not reach as far as you thought". List the apex separately
when you want both.

Widening by port instead — "let this uid reach 443 anywhere" — was the obvious
alternative to rule 17 and is fatal: it is precisely the bypass rule 19 exists to
close.

Meanwhile `ssh 192.168.0.10` matches rule 3 directly and never involves the
inspector at all. That is what `allow` is for: the exceptions on ports no
redirect touches.

**HTTP/3 is dropped, and rule 18 is why that is visible.** The redirect keys on
`tcp dport`, so QUIC on UDP 443 is never redirected and falls to the default
deny. Rule 18 sits immediately ahead of it and counts the same packets it would
have dropped — a pure attribution split, not a policy change. A non-zero count is
normal: a client that tries h3 and falls back presents as "some sites are slow
for no reason anyone can find", and this counter is the difference between
finding that in a minute and never finding it.

## What an inspected request looks like when it arrives

Under `tls = "inspect"` the request the origin receives is not the guest's bytes
forwarded. The inspector parses the head, decides on it, and then **re-emits**
one it composed itself, so nothing on the path can read the framing two ways.
Three consequences are visible from the origin's side and worth knowing before
you debug one:

- **Header names arrive lowercased.** They are folded to lowercase when the head
  is parsed and re-emitted in that form. HTTP field names are case-insensitive,
  so this is legal and nothing in the wild should care — but an origin with a
  hand-rolled parser that string-matches `Content-Type` might, and the symptom
  is a request that works direct and fails inspected.
- **`Content-Length` and `Transfer-Encoding` are the inspector's**, recomputed
  from what it read rather than copied. A request framed both ways at once is
  refused outright rather than resolved in favour of either.
- **`Host` is the name that was authorised**, which for an absolute-form request
  target is not what the guest's own `Host` header said.

Hop-by-hop headers are dropped. The one exception is a protocol upgrade: an
`Upgrade:` offer the inspector recognises is re-emitted, so the origin can
answer `101` and the connection becomes an opaque tunnel from there — the
request was policed as ordinary HTTP, and what flows afterwards is not, which
the journal says in as many words. An `h2c` offer is the one that is *not*
carried: HTTP/2 requests are HPACK frames this relay cannot read, so forwarding
one would let a guest leave per-request authorisation behind. Such a request
completes as the ordinary HTTP/1.1 exchange it also is.

The response head, by contrast, is relayed **verbatim**. It was written by a
host the policy authorised, and it is parsed only far enough to learn where the
body ends.

## What rule 17 does not say

Rule 17 exempts the re-originators by control group and says nothing about where
they are going. For a while that was the whole of it, and it left a gap: a
policy point matches the *name*, resolves it with the host resolver, and connects
to whatever comes back. It has no notion of destination ranges. So an allowlisted
name pointing into RFC 1918, loopback or link-local space was reachable from a VM
whose `diagnose` output said it was confined.

The guest never controls that resolution, so this is not DNS rebinding — the
gap was that nothing looked at the answer. The ways in are ordinary: a wildcard
over a domain where someone else can create records, an allowlisted third party
whose DNS is compromised, an internal name allowlisted without thinking about
where it points. On a cloud instance, `169.254.169.254`.

Rules 14 and 15 are the check. Four things about them are load-bearing:

- **`ct direction original`.** The drop must cover connections the inspector
  *opens*, never the reply direction of connections made *to* it. Once the
  responder synthesises, every inspected connection's reply is addressed back
  into a host-local range; without the qualifier every one of them hangs with the
  SYN already accepted. Measured: the qualified form works, the unqualified one
  does not. `192.0.2.0/24` is likewise absent from `wl_internal4` — that is the
  advertised address, which still carries the credential broker, and listing it
  would drop the broker's replies to its own client.
- **Rule 11, the DNS carve-out, comes first.** The inspector resolves through the
  host's configured resolver, and that address is inside these ranges whichever
  form it takes — `127.0.0.53` under a stub resolver, or a box on the LAN.
  Without the carve-out every lookup fails and the listener answers 502 while
  every other signal looks correct. It is scoped to destination port 53, so the
  residual is an internal service answering HTTP on port 53.

  **This carve-out was written for the retired proxy and had to survive it.**
  Deleting it alongside the proxy is the obvious mistake: the inspector resolves
  host-side on every connection it authorises, permanently, and the responder
  resolves the names it synthesises answers for. Both are in `wl_egress_cg`.
- **Rules 12 and 13 are `[[vm.network.internal]]`** — the per-workload
  exceptions, for an allowlisted name that is *supposed* to resolve into private
  space. Without them a homelab forge on the LAN fails as
  `403 <host> resolves to an internal address` on the one host the operator meant
  to reach: a confinement working exactly as designed against the stated intent.
- **Rules 3 and 4 come before all of it.** `allow` is the escape hatch on every
  other port, and the grant is evaluated ahead of the drop. This is deliberately
  not an inspector-specific key — the same entry opens the guest's own direct
  path, which is the honest description of what it grants.

The interval sets' contents are constant and host-global, so the skeleton
`flush set`s them before loading, the way it flushes the chain. `wl_filtered`,
the allow sets, the inspect sets and `wl_internal_ok4/6` all carry per-workload
state and are never flushed here.

## Rules 1 and 16 exist because it broke without them

Both were added after watching a live VM fail.

**Rule 16 (`oif lo`).** Without it a filtered VM is cut off from the host in two
ways that both look like bugs elsewhere. `workloadctl exec` and `shell` hang:
passt binds the management address `127.128.0.4:2222` as the workload user, so
replies on that socket are output traffic owned by uid 10004 and hit this chain
— the connection is accepted and then silently dies. And DNS stops resolving
whenever the host runs a stub resolver, because passt sends the forwarded query
to `127.0.0.53` as the same uid.

Accepting it widened nothing *when it was written*, and the reasoning still
holds for the case it was written about: passt runs with
`--map-host-loopback none`, so no guest-chosen destination translates to host
loopback; the only loopback traffic passt originates is replies on sockets it
already bound, and the DNS forward. A guest packet aimed at `127.0.0.1` never
leaves the guest's own stack.

**That argument rests on every host-local address a filtered uid can reach
being inside `127/8`, and it stopped being true when the transparent inspector
landed.** The inspector listens on a routable-looking address per workload in
`198.18.0.0/16` (and its IPv6 twin in `2001:2::/48`), on the shared
`workload-proxy` dummy link — deliberately not loopback, because guest traffic
re-originated toward a remote address cannot be DNATed into `127/8` without a
host-wide sysctl. Those addresses are host-local, so a filtered uid's packet to
one of them leaves on `lo` and rule 16 accepts it, exactly as it accepts the
management address.

The rule stays as it is; the guards go **in front of it** — rules 7 to 10.
Two things bound what rule 16 now admits, and neither is rule 16:

- an `input` chain drops anything addressed to a listener plane that arrives on
  any interface other than `lo`, so the planes are reachable only from this
  host. Measured, both families, in `tests/manual/input_chain_rig.py`;
- the output chain carries per-uid guards ahead of rule 16 so that one
  workload's uid cannot reach *another* workload's plane — the addresses are
  derived from the uid, so they are guessable by construction. This was
  measured, not assumed: workload B reached A's listener on the first try
  before the guard existed. A blanket range guard catches whatever the
  per-workload rules do not.

The invariant behind that ordering is enforced rather than assumed: an `allow`
entry naming an address inside a listener range is refused, in both families,
by `validate` and again by the helper that arms the element. It has to be, and
not merely be documented as a bad idea — `allow` is matched *ahead of* the
guard rule, so such an entry would not bypass that guard so much as replace it,
landing the connection on a policy point that enforces a different workload's
allowlist and re-originates as a different workload's uid.

Read rule 16 as "the host's own loopback path is not the place policy is
enforced", not as "nothing routable is reachable here".

**Rule 1 (`ct mark`)** is not policy at all — it is what lets a capture
attribute *inbound* packets to a workload, since nftables has no input-side uid
match. It is guarded on the workload uid *range* rather than on `@wl_filtered`,
because attribution is not policy: an `egress = "open"` VM is exactly as
interesting to capture as a filtered one. Keying it on set membership made
`pcap -Q in` silently empty for every unfiltered workload while `-Q out` kept
working — one broken direction per workload class, and no error. It also claims
the whole mark: the `0x40000000` tag plus a uid of up to 52948 spend all 32
bits, so on a host that marks connections for its own policy routing, any mark
set on a workload's connections is replaced here.

## Reading the state

`workloadctl diagnose web` reports whether the policy is actually in force and
whether the redirect is armed. Both matter for the same reason: a config that
says `filtered` while the uid is absent from the set describes a VM that is wide
open, and every other signal — unit active, guest online, `status` green — looks
correct. Likewise the socket can be bound while the guest has no path to it.

One caveat before you read a counter: the drop counter on rule 19 is **host-wide**,
shared by every filtered VM. There is one drop rule, guarded on set membership,
so they all accumulate on the same number. Per-workload counts would take a rule
or a named counter per uid — exactly the machinery a single set-guarded rule was
chosen to avoid — so `diagnose` prints the figure and says it is shared, rather
than attributing a sibling's dropped traffic to the VM being diagnosed.

## Teardown and break-glass

`ExecStopPost` runs `workload-vm-filter down` and `workload-vm-inspect down`,
and each listener service withdraws its own two cgroup elements. All of them
are tolerant, unlike the `up` halves: an element is legitimately absent
whenever a start failed before arming, or an operator used the break-glass. The
`up` halves fail loudly on the reasoning above — a VM that claims confinement
and did not arm is the failure mode this layer exists to prevent.

`nft delete table inet workload_filter` removes the policy wholesale; the next
VM start rebuilds it from the skeleton. An abandoned table is inert: chain policy
is `accept`, the drop is set-guarded, and an empty `wl_filtered` matches nothing.
Orphaned elements self-heal on reboot, since nft state does not survive one.
