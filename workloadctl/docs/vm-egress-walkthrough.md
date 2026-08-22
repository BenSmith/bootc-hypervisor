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
allow  = ["192.168.0.10:22"]                           # everything else, by address
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

`_validate_egress` (`lib/vm.py:825`) rejects the configurations that would
misreport confinement:

| config | why it is refused |
|---|---|
| `filtered`, both lists empty | a VM that can reach nothing at all, which boots and then hangs |
| `hosts` with `egress = "open"` | no drop, so the allowlist binds only guests that choose to be bound — while still standing up a daemon parsing guest-controlled HTTP |
| any of these with `bridge` | no host socket in the path, so no uid, so no policy |

All three fail the enable rather than degrading silently. The whole layer exists
to prevent a VM that claims confinement and does not have it.

## Boot: two units, six prestart actions

Because `hosts` is non-empty, the generator emits `workload-web-proxy.service`
in addition to `workload-web.service` and makes it a prerequisite
(`generators/workload-generate:1838`).

**`workload-vm-proxy up web`** — the proxy unit's `ExecStartPre`:

1. Creates the `workload-proxy` dummy link and puts `192.0.2.1/32` on it. Shared
   and host-global, created on demand, never torn down by a workload stop —
   it holds no per-workload state and an orphan is inert.
2. Applies both nft skeletons: the proxy table *and* the filter table. The
   second is not redundant — the exemption element at step 5 lives in the filter
   table, and this unit starts before the VM whose prestart would otherwise be
   first to create it (`libexec/workload-vm-proxy:119`).
3. Writes `/run/workload-vm/web/tinyproxy.conf` and `hosts.allow`. The listen
   address is `127.128.0.4`, derived from the uid, so uniqueness is inherited
   from the uid allocator: no registry, no allocation step, no collision. The
   config carries `FilterDefaultDeny Yes` (without it the filter file is a
   *deny*list and an unlisted host is permitted), `ConnectPort 443` (without it
   the proxy is a general TCP tunnel out of the guest), and `Allow 192.0.2.1`
   as well as loopback.
4. Adds `10004 : 127.128.0.4 . 3128` to `wl_proxy_dest`.
5. Adds `workloads.slice/workload-web-proxy.service` to `wl_proxy_cg`.

**`workload-vm-filter up web`** — the VM unit's `ExecStartPre`:

6. Purges every element owned by uid 10004 from all three filter sets, *then*
   adds the configured ones: `10004` to `wl_filtered` and
   `10004 . 192.168.0.10 . 22` to `wl_allow4`.

That purge is the entire reason this is a script rather than three
`ExecStartPre=` lines. `ExecStopPost` deletes the entries the unit file names at
stop time, so removing an entry from `allow` and re-enabling would delete only
what is still configured and leave the dropped entry armed — permitting traffic
the config no longer permits, silently, until the host reboots. Verified on
nftables 1.1.6. The purge makes the armed state a function of the current config
alone, rather than of the config plus every config it ever had
(`libexec/workload-vm-filter:11-28`).

The VM then boots with `https_proxy=http://192.0.2.1:3128` and
`no_proxy=localhost,127.0.0.1,::1,192.0.2.1` in its cloud-config.

## The output chain

Five rules and a drop, in `inet workload_filter`, at filter hook priority 0 —
ahead of firewalld's `filter_OUTPUT` at filter+10, in headroom firewalld leaves
deliberately. firewalld cannot express this policy itself: its rich language has
no uid predicate, so it can reach the traffic class but cannot tell one VM from
another.

```
1  meta skuid 10000-52948 ct mark set meta skuid or 0x40000000   (non-terminating)
2  meta skuid . ip daddr  . th dport @wl_allow4              accept
3  meta skuid . ip6 daddr . th dport @wl_allow6              accept
4  @wl_proxy_cg th dport 53                                  accept
5  @wl_proxy_cg ct direction original ip  daddr @wl_internal4 drop
6  @wl_proxy_cg ct direction original ip6 daddr @wl_internal6 drop
7  meta skuid @wl_filtered oif lo                            accept
8  socket cgroupv2 level 2 @wl_proxy_cg                      accept
9  meta skuid @wl_filtered                                   drop
```

(`@wl_proxy_cg` is shorthand for `socket cgroupv2 level 2 @wl_proxy_cg`.)

Rules 4–6 are the destination check on rule 8, and the order among them is the
whole design — see "What rule 8 does not say" below. Rules 2 and 3 moved above
the loopback accept when they were added, which changes nothing for any existing
config: every rule they used to sit behind is also an accept.

## A packet's life

The guest runs `curl https://api.example.com`:

1. It sends `CONNECT api.example.com:443` to `192.0.2.1:3128`.
2. passt re-originates it as a host socket owned by uid 10004.
3. `inet workload_proxy` at nat hook output (priority `dstnat`, −100, so it runs
   before the filter chain) matches daddr `192.0.2.1` dport 3128, looks the
   skuid up in `wl_proxy_dest`, and DNATs to `127.128.0.4:3128`.
4. The filter chain now sees a translated packet on `oif lo` — rule 7 accepts.
5. tinyproxy sees a client connecting *from* `192.0.2.1`. The guest's packet was
   routed to that address before it was translated, so the host picked it as the
   source; omit it from the ACL and every request answers 403 while the
   listener, the redirect and the guest all look healthy. The hostname is
   fnmatched against `hosts.allow` and permitted.
6. tinyproxy opens its own socket to `api.example.com:443` — same uid 10004, and
   that destination is not in `wl_allow4`. What saves it is rule 8: the proxy
   runs as its workload's own user *on purpose*, so `meta skuid` cannot separate
   its traffic from the guest's, and the control group is the discriminator that
   survives the shared uid. systemd assigns it, a guest can neither enter nor
   forge it, and it widens no destination or port.

Then the two paths that don't work, which are the point:

- **The guest ignores `HTTPS_PROXY` and dials `1.2.3.4:443` directly.** uid
  10004, the VM's cgroup rather than the proxy's, destination absent from
  `wl_allow4` → rule 9. This is what makes the proxy mandatory rather than
  advisory, and it is why `hosts` requires `egress = "filtered"`.
- **The guest asks the proxy for a host not on the list.** 403, before any TLS
  handshake — the name comes out of the plaintext CONNECT, so there is no
  interception and no CA.

That second refusal has a trap in it. The patterns are fnmatch, not a DNS suffix
match, so `*.fedoraproject.org` requires something before the dot and does **not**
cover the bare `fedoraproject.org`. On the VM above, `download.fedoraproject.org`
is proxied and `fedoraproject.org` is refused — with a 403 identical to the one
an entirely unlisted host gets. Nothing distinguishes "you did not allowlist this"
from "your pattern did not reach as far as you thought". List the apex separately
when you want both.

Widening by port instead — "let this uid reach 443 anywhere" — was the obvious
alternative to rule 8 and is fatal: it is precisely the bypass rule 9 exists to
close.

Meanwhile `ssh 192.168.0.10` matches rule 2 directly and never involves the
proxy at all. That is what `allow` is for: the non-HTTP exceptions a hostname
proxy cannot carry.

## What rule 8 does not say

Rule 8 exempts the proxy by control group and says nothing about where it is
going. For a while that was the whole of it, and it left a gap: tinyproxy
matches the CONNECT hostname against `hosts.allow`, resolves it with the host
resolver, and connects to whatever comes back. It has no notion of destination
ranges and no directive that could express one. So an allowlisted name pointing
into RFC 1918, loopback or link-local space was reachable from a VM whose
`diagnose` output said it was confined.

The guest never controls that resolution, so this is not DNS rebinding — the
gap was that nothing looked at the answer. The ways in are ordinary: a wildcard
over a domain where someone else can create records, an allowlisted third party
whose DNS is compromised, an internal name allowlisted without thinking about
where it points. On a cloud instance, `169.254.169.254`.

Rules 5 and 6 are the check. Three things about them are load-bearing:

- **`ct direction original`.** The drop must cover connections the proxy
  *opens*, never the reply direction of connections made *to* it. tinyproxy's
  client ACL admits `127.0.0.0/8` as well as the advertised address, so without
  this a client that reached the proxy from loopback would have every reply
  dropped, and hostname policy would fail with the proxy looking healthy.
  `192.0.2.0/24` is likewise absent from `wl_internal4`, for the same reason on
  the normal path: the guest's flow reaches tinyproxy *from* `192.0.2.1`.
- **Rule 4, the DNS carve-out, comes first.** tinyproxy resolves through the
  host's configured resolver, and that address is inside these ranges whichever
  form it takes — `127.0.0.53` under a stub resolver, or a box on the LAN.
  Without the carve-out every lookup fails and the proxy answers 502 while every
  other signal looks correct. It is scoped to destination port 53, so the
  residual is an internal service answering HTTP on port 53.
- **Rules 2 and 3 come before both.** `allow` is the escape hatch: a site that
  needs its proxy to reach an internal service names the address and port there,
  and the grant is evaluated ahead of the drop. This is deliberately not a
  proxy-specific key — the same entry opens the guest's own direct path, which
  is the honest description of what it grants.

The set contents are constant and host-global, so the skeleton `flush set`s them
before loading, the way it flushes the chain. `wl_filtered` and the allow sets
carry per-workload state and are never flushed here.

## Rules 1 and 7 exist because it broke without them

Both were added after watching a live VM fail.

**Rule 7 (`oif lo`).** Without it a filtered VM is cut off from the host in two
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
one of them leaves on `lo` and rule 7 accepts it, exactly as it accepts the
management address.

The rule stays as it is; the guard goes **in front of it**. Two things bound
what rule 7 now admits, and neither is rule 7:

- an `input` chain drops anything addressed to a listener plane that arrives on
  any interface other than `lo`, so the planes are reachable only from this
  host. Measured, both families, in `tests/manual/input_chain_rig.py`;
- the output chain carries per-uid guards ahead of rule 7 so that one
  workload's uid cannot reach *another* workload's plane — the addresses are
  derived from the uid, so they are guessable by construction. This was
  measured, not assumed: workload B reached A's listener on the first try
  before the guard existed. A blanket range guard catches whatever the
  per-workload rules do not.

One promise behind that ordering is still owed and is worth knowing about:
validation does not yet refuse an `allow` entry *inside* the listener ranges,
and such an entry would be accepted ahead of the guard that exists to refuse
exactly it. The ordering is correct; the invariant it assumes is not yet
enforced in the tree.

Read rule 7 as "the host's own loopback path is not the place policy is
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
correct. Likewise the proxy can be listening while the guest has no path to it.

One caveat before you read a counter: the drop counter on rule 9 is **host-wide**,
shared by every filtered VM. There is one drop rule, guarded on set membership,
so they all accumulate on the same number. Per-workload counts would take a rule
or a named counter per uid — exactly the machinery a single set-guarded rule was
chosen to avoid — so `diagnose` prints the figure and says it is shared, rather
than attributing a sibling's dropped traffic to the VM being diagnosed.

## Teardown and break-glass

`ExecStopPost` runs `workload-vm-filter down` and `workload-vm-proxy down`. Both
are tolerant, unlike their `up` halves: an element is legitimately absent
whenever a start failed before arming, or an operator used the break-glass. The
`up` halves fail loudly on the reasoning above — a VM that claims confinement
and did not arm is the failure mode this layer exists to prevent.

`nft delete table inet workload_filter` removes the policy wholesale; the next
VM start rebuilds it from the skeleton. An abandoned table is inert: chain policy
is `accept`, the drop is set-guarded, and an empty `wl_filtered` matches nothing.
Orphaned elements self-heal on reboot, since nft state does not survive one.
