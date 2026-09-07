# How inspection and brokering fit together

Two host-side programs sit between a workload and the network: the **egress
inspector**, which decides whether a request may go out, and the **credential
broker**, which attaches a secret the workload was never given. This document
is the picture of how they attach to the two substrates — a VM behind passt and
a rootless container behind pasta — and why the same code serves both.

The reference material it condenses: [ADR 006](adr/006-vm-networking-passt-not-managed-bridge.md)
(why passt, not a bridge), [ADR 008](adr/008-transparent-egress-inspection.md)
(why a transparent inspector, terminating by default),
[ADR 007](adr/007-per-workload-credential-broker.md) and
[the broker's own doc](agent-broker.md) (what the broker refuses to do),
[the VM walkthrough](vm-egress-walkthrough.md) (one filtered VM, end to end,
including the full nftables chain), and [workloads.md](workloads.md) for the
schema.

---

## 1. The one property everything rests on

**Every packet a workload emits leaves the host from a socket owned by that
workload's uid.** Nothing below works without it, and each substrate earns it a
different way.

```mermaid
flowchart LR
  subgraph guest["VM guest — its own kernel, own netns"]
    G["curl https://api.example.com"]
  end
  subgraph ctr["Container — rootless, keep-id userns"]
    C["curl https://api.example.com"]
  end

  G -- "virtio-net frames" --> P["passt<br/>(user process, uid 10004)"]
  C -- "tap/socket" --> PA["pasta<br/>(user process, uid 10004)"]

  P --> S1["host socket<br/>skuid = 10004"]
  PA --> S2["host socket<br/>skuid = 10004"]

  S1 --> NFT["nftables: meta skuid<br/>selects the workload"]
  S2 --> NFT
```

The guest's own kernel stack terminates *inside* passt; passt re-originates each
flow as an ordinary host socket it owns. pasta is the same program in its
container-side mode. So `meta skuid 10004` is a complete and unforgeable
per-workload selector — the guest cannot produce a packet that leaves the host
without wearing the workload uid.

**Where it does not hold**, and why those shapes are refused rather than quietly
half-filtered:

| shape | uid attribution | outcome |
|---|---|---|
| VM with `[vm.network].bridge` | none — the guest sends from its own LAN address, nothing of ours in the path | `egress`/`allow`/`hosts` are a validation error |
| container with `[network] mode = "host"` | partial and image-dependent — see below | never inspected; `container_uses_inspect()` returns false |
| VM `passt` (default) | exact | inspected |
| container `pasta` / `bridge` mode | exact | inspected |

### The user-namespace detail that excludes host mode

Under the default `userns = "keep-id"`, **exactly one in-container uid maps to
the workload uid**. In-container root and every other user map into the
workload's 65536-wide *subuid* window instead.

```mermaid
flowchart LR
  subgraph inner["in-container uids"]
    R["0 (root)"]
    U["1000 (app user)"]
    K["the keep-id uid"]
  end
  subgraph host["host uids"]
    SUB["subuid window<br/>e.g. 524288 … 589823"]
    WL["_wl-web = 10004"]
  end
  R --> SUB
  U --> SUB
  K --> WL
```

With pasta or bridge mode this does not matter: whatever the in-container uid,
the traffic is re-originated by a **host** process owned by `_wl-web`, so every
flow presents uid 10004. On the host network there is no re-originator — the
container's own sockets are the host's sockets — so a container running as image
root would emit from a subuid and match no selector. Filtering there would cover
only bundles that happen to run as the keep-id uid, which is an image detail
rather than a policy decision, so host mode is excluded outright. (Measured on
hardware: the host's own root and uid-1000 traffic is *not* dragged into a
workload's policy even with the netns shared — the failure is under-coverage,
not over-coverage.)

---

## 2. Units: what exists, and what starts what

For a workload named `web` at uid 10004 with an inspection trigger and a
credential:

```mermaid
flowchart TD
  IS["workload-web-inspect.socket<br/>binds 198.18.1.4:8080 / :8443"]
  RS["workload-web-resolve.socket<br/>binds 127.130.0.4:53 — VM only"]
  ISVC["workload-web-inspect.service<br/>workload-vm-inspect-listener"]
  RSVC["workload-web-resolve.service"]
  BR["workload-web-broker.service<br/>DynamicUser, 127.129.0.4:8081"]
  HEAD["head unit<br/>VM: workload-web.service<br/>container single: the container unit<br/>pod/bridge: -pod / -net unit"]

  IS -- "ExecStartPre: workload-vm-inspect up / workload-container-inspect up<br/>(policy doc, listener address, DNAT map, guard sets)" --> IS
  HEAD -- "ExecStartPre: workload-vm-filter up / workload-container-filter up<br/>(uid → wl_filtered, allow tuples)" --> HEAD

  IS -.->|Requires + Before| HEAD
  RS -.->|Requires + Before| HEAD
  BR -.->|Requires + Before| HEAD
  IS -->|socket activation| ISVC
  RS -->|socket activation| RSVC
  ISVC -- "ExecStartPre arms wl_egress_cg + wl_inspect_cg<br/>ExecStopPost withdraws them" --> ISVC
  ISVC -->|dials for a brokered host| BR
```

Three ordering facts that have each cost a real defect:

- **`Before=` orders a unit; it does not start one.** The broker unit was once
  generated, correctly ordered, given its exemptions — and pulled in by nothing.
  Forty-five unit tests passed while the feature did nothing. It needs a
  `Requires=`-shaped pull from the head unit.
- **The head unit is not the umbrella in pod/bridge mode.** The umbrella is
  `After=` its members, so arming there would run only once every container was
  already up, leaving the whole of member startup unfiltered. Arming (and the
  broker's ordering) attaches to the pod-create / network-create head unit.
- **The two cgroup exemptions belong to the listener *service*, not the
  socket.** An nft element resolves a cgroup path to an id at add time, and
  systemd makes a fresh cgroup on every start — at socket-prestart time the
  service has no cgroup to resolve.

---

## 3. A request, end to end

```mermaid
sequenceDiagram
    autonumber
    participant W as Workload
    participant N as Re-originator
    participant NAT as nft nat
    participant F as nft filter
    participant I as Inspector
    participant B as Broker
    participant O as Origin

    Note over W: guest or container
    Note over N: passt or pasta, uid 10004
    Note over I: uid 10004, own cgroup, port 8443
    Note over B: 127.129.0.4 port 8081, DynamicUser

    W->>N: DNS A query for api.example.com
    N->>W: answer 198.18.1.4
    Note over W,N: VM uses this workload's synthesising responder
    W->>N: TCP to 198.18.1.4 port 443
    Note over W,N: any address works, the redirect keys on the port
    N->>NAT: host socket with skuid 10004
    NAT->>F: DNAT via wl_inspect4 to port 8443
    F->>I: rule 5 accepts the translated tuple
    I->>I: read SNI or Host and match policy
    alt policy entry names a credential
        I->>B: plain HTTP over loopback
        Note over I,B: needs wl_egress_cg and wl_internal_ok4
        B->>O: TLS from the host with the real key
        O-->>B: 200
        B-->>I: 200
    else ordinary allowed host
        I->>O: own TLS session against the host trust store
        O-->>I: 200
    end
    I-->>W: response over the terminated session
```

Reading the diagram against the mechanisms:

- **The workload is never told anything.** No proxy variable, no broker address,
  no resolver of its own choosing. The redirect does not ask, so an agent that
  ignores its whole environment is inspected anyway. This is the difference
  between an inspector and a CONNECT proxy.
- **The inspector runs as the workload's own uid on purpose**, so `meta skuid`
  cannot separate its re-originated traffic from the guest's. The **control
  group** is the discriminator that survives the shared uid: systemd assigns it,
  a guest can neither enter nor forge it, and the exemption widens no
  destination and no port.
- **A brokered host is never dialled at the origin.** The inspector's dial goes
  to loopback only — so origin reachability is not a prerequisite for a brokered
  request, and no `allow` entry is owed for the provider.
- **The broker's own address needs an explicit exemption.** `127.129.x.y` is
  inside 127/8, hence inside `wl_internal4`, and the cgroup-keyed drop that stops
  a workload reaching host-internal ranges sits above the rule accepting the
  inspector's loopback traffic. Without `wl_internal_ok4` the dial is dropped in
  silence and presents as a dead broker.

For the full 19-rule output chain and the refusal paths (dial by literal,
unlisted host, non-HTTP on 443), see [the VM walkthrough](vm-egress-walkthrough.md).

---

## 4. Addressing: everything is derived from the uid

No registry, no allocator, no collision handling — uniqueness is inherited from
the uid allocator that already exists.

```mermaid
flowchart LR
  UID["workload uid<br/>10004 (offset 4 from UID_MIN)"]
  UID --> L4["inspector 198.18.1.4:8080 / :8443<br/>on the shared workload-proxy dummy link"]
  UID --> L6["inspector 2001:2::c612:104"]
  UID --> R["resolver 127.130.0.4:53<br/>(VM only)"]
  UID --> BK["broker 127.129.0.4:8081"]
  UID --> SETS["nft elements:<br/>wl_filtered, wl_allow4/6,<br/>wl_inspect4/6, wl_inspect_dst/self/live"]
```

Two consequences worth holding onto:

- **The listener ranges are loopback and non-routable on purpose.** Isolation
  between workloads is the address family itself, not a rule — a routable
  listener range would silently reopen cross-workload reach. The guard sets
  `wl_inspect_live`/`wl_inspect_live6` exist because any local uid could
  otherwise dial another workload's inspector and pollute its records.
- **Two constants must agree** across three files: the broker's
  `listen_address`/`listen_port`, what the generator renders into `broker.toml`,
  and what the inspector dials (`vm_broker_listen_address` /
  `VM_BROKER_INSTANCE_PORT` in `lib/vm.py`). A mismatch presents exactly as the
  broker being down — connection refused, no log line anywhere.

---

## 5. One mechanism, two substrates

The container path is the VM path with substitutions, not a parallel
implementation. The listener binary and both nft tables are shared verbatim; the
uid-keyed element builders take nothing but a uid.

```mermaid
flowchart TB
  subgraph shared["Shared, byte-for-byte"]
    LST["workload-vm-inspect-listener<br/>TLS termination, SNI/Host policy, broker dial"]
    NFT2["inet workload_filter + inet workload_proxy skeletons"]
    BRK["libexec/agent-broker + workload-vm-broker config"]
    PI["lib/peer_identity.py — caller identified by the uid owning the far end"]
  end

  subgraph vm["VM"]
    VT["[vm.network] hosts / allow / policy / credential"]
    VA["workload-vm-inspect + workload-vm-filter"]
    VR["workload-vm-resolve — synthesising DNS responder"]
    VE["egress = filtered/open, default-deny for the uid"]
  end

  subgraph ct["Container"]
    CT["[network] hosts / allow / policy / credential"]
    CA["workload-container-inspect + workload-container-filter"]
    CN["no responder — resolves through the host's resolver"]
    CE["no egress key: presence of a trigger IS the statement"]
  end

  vm --> shared
  ct --> shared
```

The genuine differences:

| | VM | Container |
|---|---|---|
| re-originator | passt | pasta (or the bridge-mode equivalent) |
| arming helper | `workload-vm-inspect` / `-filter` | `workload-container-inspect` / `-filter` |
| DNS | per-workload synthesising responder on `127.130.x.y`; answers every A/AAAA with the inspector address and has no upstream socket at all | none; the host's resolver answers, and a `[network]` trigger drops port 53 unless that resolver is on loopback |
| turning it on | `egress = "filtered"` (stated explicitly; there is no safe default) plus a trigger | any one of `hosts`, `[[allow]]`, `[[policy]]` |
| default deny | yes, keyed on the uid | no — the triggers are the whole statement |
| schema | `[vm.network].*` | `[network].*` |
| broker ordering | before `workload-<name>.service` | before the pod/net head unit in pod and bridge mode |

Both substrates read the *same* policy document shape and run the same listener,
which is why the brokered path needed one implementation and two arming scripts.

---

## 6. Why the credential never enters the workload

```mermaid
flowchart LR
  subgraph inside["Inside the sandbox — uid 10004"]
    A["agent<br/>holds a placeholder, or nothing"]
  end
  subgraph host["Host side"]
    I2["inspector<br/>reads the request, holds no credential"]
    B2["broker<br/>holds the credential, parses nothing beyond the request line + headers"]
    CS["systemd credential store<br/>tmpfs, 0400, DynamicUser-owned, gone at stop"]
  end
  P2["provider"]

  A -->|"https://api.anthropic.com — the real name"| I2
  I2 -->|"policy entry names credential 'anthropic'"| B2
  CS --> B2
  B2 -->|"ordinary verified TLS, real key"| P2
  A -.->|"cannot name, cannot reach, cannot read broker.toml"| B2
```

The split of labour is the reason this is ~600 lines and not a TLS-rewriting
middlebox: **authorising a request** (a host, a method, a path) and **rewriting
it to carry a credential** (per-provider auth schemes, key in hand, parsing
guest-controlled bytes) are different jobs, and they live in different programs.

Properties that follow from the picture, each of which is load-bearing:

- The workload has **no endpoint, no variable and no name** for the broker, so
  it cannot decline to use one or be pointed at another workload's. A base-URL
  environment variable would be exactly the step an attacker-influenced agent
  can undo.
- Callers are identified by **the uid owning the far end of the connection**
  (`lib/peer_identity.py`, shared with the inspector's listener). One instance
  per workload, so the uid is an assertion rather than a route: a resolved
  caller that is not the configured one is a 403 on a connection that should
  have been impossible to open.
- **One instance per workload.** N sandboxes sharing one broker with N different
  keys means one bug leaks all N.
- The broker is **not a general proxy**: upstreams come from config and never
  from the request; absolute-form request targets are a 400; a `Host` naming no
  row is a 403. The guest picks among rows the host wrote.
- **The workload uid cannot read its own `broker.toml`.** The instance runs as a
  dynamic user disjoint from `_wl-<name>`, and the file names the seal — which is
  the one thing between a workload and asking systemd for the material.
- The upstream leg **is not attributable to the sandbox**: the broker egresses as
  its own dynamic user outside the workload uid range, so the connection-marking
  rule does not tag it and per-workload packet capture will not show that half.

What none of this closes: the agent talks to a model provider by design, and can
write anything it can read into a prompt. After a network boundary exists, **the
mount set is the real secret boundary** — egress is mediated and scoped, a
filesystem passthrough is not.

---

## 7. Failure shapes to recognise

Each of these was found on hardware after a fully green unit suite; they share a
shape, which is that the wiring between two correct halves belongs to neither.

| symptom | cause |
|---|---|
| brokered request never reaches the broker; the origin is dialled instead | a terminated session seeded the upstream pool with the *origin* connection |
| broker dial refused, no log line on either side | the broker's `127.129.x.y` is inside `wl_internal4` and needs the `wl_internal_ok4` exemption |
| every unit active, feature inert | a generated unit that nothing `Requires=` — `Before=` orders, it does not start |
| 401 on a fully authorised request | the rendered config could not name the provider's `auth_header`/`auth_format` |
| workload unfiltered for the whole of member startup | arming attached to the umbrella, which is `After=` its members |
| container resolves nothing once a `[network]` trigger is added | port 53 is dropped unless the host's resolver is on loopback |
| `403` that names the host, on a host you did list | `hosts` patterns are fnmatch, not DNS suffix — `*.example.com` does not cover the apex |

Diagnostics: `workloadctl egress <name>` for the per-request record,
`workloadctl rules <name>` for what the workload is allowed to do, and
`workloadctl diagnose <name>` for the runtime setup.
