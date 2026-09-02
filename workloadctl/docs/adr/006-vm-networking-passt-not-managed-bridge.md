# ADR 006: VM networking uses passt, not a shared managed bridge

**Status:** Implemented. Supersedes
[ADR 002](002-vm-bridge-host-level-network-config.md).

The per-workload tinyproxy this decision originally added for hostname policy has
since been replaced by a transparent, uid-keyed egress inspector — see
[ADR 008](008-transparent-egress-inspection.md). The network model below is
unchanged by that: the inspector rests on exactly the property this ADR chose,
that the workload uid is an unforgeable selector.

## Context

VM workloads attached to `_workload-br`, a single host-global NAT bridge shared by
every VM that did not name its own. ADR 002 resolved a last-write-wins hazard in
that unit, but the topology itself was the problem:

- **Every VM shares one L2 segment.** VM-to-VM isolation depends on rules rather
  than structure — there is a segment to spoof onto and an ARP cache to poison.
- **There is no per-VM network identity to key policy on.** Guest-chosen
  addresses are forgeable by definition, so egress policy would need L2
  anti-spoofing to mean anything, and address allocation to have something to
  write rules about.
- **The data path needs host privilege:** a host-global
  `sysctl net.ipv4.ip_forward=1`, a setuid-root `qemu-bridge-helper` reached
  through `/etc/qemu/bridge.conf`, an `ip workload_nat` table and a firewalld
  zone — all of which sit oddly against the rootless posture the rest of the
  project holds to.
- **A shared, refcount-persistent resource resists per-VM configuration**, which
  is ADR 002's finding.

Container workloads have none of these problems, because pasta gives each one its
own re-originated network identity. The same backend is available to VMs.

## Decision

**VM workloads use passt as their network backend. The managed bridge is
removed.**

passt terminates the guest's network stack in userspace and re-originates its
traffic as ordinary host sockets. Those sockets are owned by the workload's
existing dedicated system user, so **the workload uid becomes the network
identity** — unforgeable by the guest, unique per workload with no allocation
step, and directly matchable by nftables. Per-VM egress policy is therefore a
host output chain matching `meta skuid`.

Three values derive from the uid with no registry:

| Derived value | Formula | Used for |
|---|---|---|
| Management address | `127.128.0.0 + (uid - UID_MIN)` | inbound SSH |
| nflog group | `1000 + (uid - UID_MIN)` | per-workload packet capture |
| Policy key | the uid itself | `meta skuid` in nftables |

`UID_MIN..UID_MAX` is 10000–52948 — 42,949 values, inside both `127.128.0.0/9`
and the 16-bit nflog group space.

**Both bases exist to miss a convention.** `127.128.0.0` clears `127.0.1.1`,
which Debian conventionally places in `/etc/hosts`, and everything else customary
in `127.0.0.0/8` — systemd-resolved's `.53`/`.54`, Istio's `.6`, the DNSBL
`.2`/`.3` — which clusters at the bottom of the /8 because RFC 6890 registers it
as one undivided block with nothing reserved inside it. The range spans addresses
that *look* like network and broadcast addresses (`127.128.0.0`,
`127.128.0.255`); `lo` carries `127.0.0.1/8`, so they are ordinary hosts, and
this is asserted by binding and completing a round trip rather than by string
comparison. The nflog group base was added later and matters as much: with no
base, the first workload on a host lands on group 0, the netfilter default that
stock ulogd configurations bind — not a crash but a silent two-way merge, putting
a site's logged packets into that workload's capture and vice versa.

The per-VM schema gains `[vm.network]` with `ports`, `egress` (`"filtered"`
default / `"open"`), `allow`, `hosts`, `outbound_if` and `resolver`. `allow` is
address policy; `hosts` is hostname policy, owned by the egress inspector.
`[vm.network].bridge` is retained as the unfiltered escape hatch: a VM naming an
operator-provided bridge attaches directly, takes a real LAN identity, and is not
filtered — by design.

## Rationale

**The uid is the whole argument.** Everything else follows from a network
identity the guest cannot influence. Verified rather than assumed: with two
concurrent VMs, one `meta skuid` rule blocked one and left the other untouched.

**Load-bearing precondition, from passt's source:** passt keeps its inherited uid
*only because it is not started as root*. Started as root it drops to `nobody`,
collapsing every workload into one uid and silently defeating the scheme — the
failure is invisible, since traffic still flows. The generated unit's `User=`
prevents this, and a test asserts it rather than assuming it.

**Throughput is not a constraint.** Measured guest→host: 11.3 Gbit/s TX,
4.9 Gbit/s RX in stream mode — bridge-class. `vhost-user=on` measures faster and
is deliberately not adopted, because it reintroduces a shared memory path for a
gain nothing here needs.

**No new packaging risk.** QEMU 10.2 exposes a native `passt` netdev, so there is
no separate process to launch or socket to wire. `passt` is an explicit
dependency in `hypervisor.Containerfile` rather than arriving transitively via
podman, since it moves from an incidental container detail to the VM data path.

**The default posture is stricter than the zone it replaces.** With
`--map-host-loopback none`, host loopback is unreachable from the guest, and the
host's default-route address is unreachable *structurally* — the guest is
assigned that same address, so traffic to it never leaves the guest's own stack.
Other host addresses remain ordinary routable destinations, which is precisely
the residue egress policy exists to handle.

**passt is self-confining.** Before serving traffic it drops all but a few
capabilities, `pivot_root`s into an empty filesystem, applies a seccomp filter and
enters a user namespace — independently of SELinux.

**Alternative rejected — keep the bridge and add anti-spoofing.** This buys back a
forgeable identity at the cost of address allocation, per-VM L2 rules, and every
privileged component above. Strictly more machinery for a strictly weaker
property.

## Decisions the design above does not settle

**`allow` carries addresses and ports; hostname *policy* lives elsewhere.** The
entries become elements of an nftables set keyed on `ip daddr`/`ip6 daddr`, where
a hostname has no representation — accepting one means resolving once at start
and pinning the result, which is wrong from the moment the record moves and wrong
permissively if the address is reassigned. That cost is now paid on purpose in
one narrow case: ADR 008 makes the guest's resolver a host-side synthesising
responder, so an `allow` destination named only by address had no way to be
reached by name at all. An `allow` entry may therefore name a host with a port,
resolved host-side once at start. The half that stands unchanged is the second:
hostname policy is `hosts`, because that is the path where the name is re-read on
every connection instead of pinned once.

**`egress = "filtered"` with nothing reachable is a validation error.** The
alternatives were to default to `"open"` and tighten later, or to let such a VM
boot unreachable. Refusing the combination puts the secure default in now, and
means nothing can boot claiming a confinement it does not have. The cost is that
every VM config states a posture explicitly. Twice a mechanism change was expected
to retire this refusal and did not — a workload gets a proxy, and later an
inspector, only when `hosts` is non-empty, since an instance permitting nothing is
indistinguishable from a broken one. So the refusal is permanent, with its trigger
widened rather than removed: `"filtered"` is an error when `allow` and `hosts` are
*both* empty. That it survived two mechanisms is the sign it belongs to the schema.

**Loopback is exempt from the filter, and has to be.** Management inbound and
egress policy are not independent. passt binds the management address
`127.128.x.y:2222` *as the workload user*, so replies carrying an `exec`/`shell`
session are output traffic owned by the workload uid and land in the same chain as
the guest's own traffic; it forwards DNS the same way. A filtered VM without a
loopback exemption is therefore unreachable *and* unable to resolve — observed as
a TCP connection accepted and then silently dying while the drop counter climbed.
The skeleton accepts `oif lo` for filtered uids before the drop. This widens
nothing a guest can reach: with `--map-host-loopback none` no guest-chosen
destination translates to host loopback, and a guest packet aimed at `127.0.0.1`
never leaves its own stack.

**The drop counter is host-wide, not per-workload.** There is one drop rule,
guarded on set membership, so every filtered workload's dropped packets accumulate
on it. Per-workload counts would need a rule or named counter per uid — the
machinery the shared rule avoids. `diagnose` reports the number and says it is
shared, because silently attributing a sibling VM's drops to the one being
diagnosed sends an operator after the wrong workload.

**Confinement ships in the RPM, not the image.** workloadctl is a standalone
package that does not depend on this image, so a policy module delivered by the
image would leave VM confinement broken on any other host and would version-skew
against the code that needs it. `security/workload-vm.cil` is installed by `%post`
instead. Neither vehicle closes the bootc gap the image's Containerfile already
records — the policy store lives in `/etc`, which ostree 3-way-merges, so an
upgrade does not deliver a changed module to a host that has ever loaded a local
one. `diagnose` reports whether it is loaded.

**One module, two rules that look unrelated.** `workload-vm.cil` was named for
virtiofsd and also grants `svirt_t` what QEMU's native passt netdev needs. Both
exist for one reason — workloadctl runs QEMU as `svirt_t` *outside libvirt*, and
the shipped policy is written around libvirt's arrangement — so they are one
module rather than two that would always be installed together.

**`runcon`, not a `setexeccon()` call.** `lib/` has no third-party dependencies
and the stdlib has no SELinux binding, so the alternative is a
`python3-libselinux` requirement for one call. `runcon` also execs the target in
its own process, scoping the pending exec context to the child by construction,
where `setexeccon()` in `workload-vm-notify` would leave it armed for whatever
that process execs next.

**Confinement is unconditional for VM workloads, and degrades rather than fails.**
It is not gated on `[security].selinux_policy`, for the same reason disk labelling
is not: a VM omitting the flag would be silently unconfined. On a host with
SELinux disabled the `runcon` prefix is dropped and the VM runs as it did before,
because failing the start would turn "this host has no SELinux" into "VMs do not
run". `diagnose` reports which of the two happened.

## What running it corrected

None of these would have failed a unit test or a review.

**Registering an fcontext rule does not label a directory.** The kernel labels a
new file from its *parent*, and `file_contexts` is consulted only by userspace
tools. A directory mkdir'd under `/run` inherits `var_run_t` however many rules
name it, so a confined QEMU could not create its QMP socket or read the cloud-init
ISO — and `/run` is a tmpfs, so it recurs every boot. `setup_vm_socket_dir` runs
`restorecon` on the directory *before* anything is written into it.

**passt needs a grant no audit harvest will show you.** QEMU's native netdev forks
passt with one end of a socketpair already open, where libvirt starts it
separately and connects by path — so `passt_t` must read and write a
`unix_stream_socket` labelled `svirt_t`, which the shipped policy does not grant
and *dontaudits*. What is observed is passt failing with `Failed to add fd to
epoll: Operation not permitted`, QEMU respawning it in a tight loop, an
unreachable guest, and an empty audit log; the denials appear only under
`semodule -DB`. QEMU also needs `signal` on `passt_t`, or every stop leaks a passt
process.

**A permissive harvest is not the whole module.** The FUSE-serving permissions did
close for free, but they are the entire write surface on `svirt_image_t`, a
mapping of QEMU's memfd, a `search` on the `container_file_t` parent, and socket
cleanup on exit — and one permission was denied under enforcing after a permissive
run that never reached it. For a fail-fast daemon the inversion is stronger still:
a process that exits on its first unreadable file records the first gate and
nothing behind it, so enforcing iteration *is* the harvest.

**The virtiofsd sidecar is unprivileged, and must not be hardened further.** An
earlier design ran it as root, because an unprivileged virtiofsd squashes every
guest-created file to its own uid. The id map made that premise false: every guest
id now translates to the one host uid, so the credential switch is never
attempted, and the sidecar runs as `_wl-<name>` with an empty
`CapabilityBoundingSet=`, `--sandbox=none` (chroot mode is root-only) and the
unit's own mount namespace. `wlvfsd_t` grants no capability at all. The trap: the
unit must **not** set `NoNewPrivileges=`, which makes the kernel refuse the
`init_t` → `wlvfsd_t` transition and fails the exec with a bare 203/EXEC. See the
comment in `generate_virtiofs_service`.

**A volume outside the workload tree is not covered.** `wlvfsd_t` is granted the
types workloadctl itself labels. A volume pointing at an operator path carries
whatever label that path has (`/srv` is `var_t`) and the sidecar is denied it. The
module cannot pre-empt this without granting the union of every type on the host,
so the fix is an fcontext rule on the operator's path.

**`nft -j list map` renders elements as `[key, value]`, not `{"elem": {…}}`,** and
the document is keyed `"map"` rather than `"set"`. Reading a map with set-shaped
code returns no elements, which reads as "not armed" — so `diagnose` reported a
demonstrably working redirect as broken.

**Two nft/iproute2 surprises.** `redirect` is a reserved word, so a nat chain
cannot be called that, and the parse error points at the chain name without saying
why. iproute2 answers a duplicate *address* with "Address already assigned", not
the "File exists" a duplicate *link* produces, so an idempotency check keyed on
the wrong string fails only on a workload's second start.

**Two things the design worried about are free.** `route_localnet` is not
required — DNAT from the output hook to a 127/8 destination works at its default
0. And a redirected host-local endpoint needs no entry in `wl_allow4`: the nat
hook (dstnat, −100) runs before the filter chain (0), so the filter sees the
translated destination and the skeleton's `oif lo` rule already accepts it.

### Capture, which writes into a table it does not own

`workloadctl pcap` produced more corrections than anything else here, and all of
them reduce to one lesson: **a feature that writes into another component's table
has to write into its own chain**, or it inherits that component's ordering and
its flushes.

- **An appended rule is not a reachable rule.** `nft add rule` appends, and the
  skeleton's output chain ends with a terminating accept or drop per filtered uid,
  so the outbound `log` rule landed below the drop and could never match — `pcap
  -Q out` captured nothing for exactly the workloads egress filtering exists to
  observe, while reporting a healthy capture.
- **The skeleton flushes what it owns.** `flush chain … output` is what makes it
  re-appliable, and it deleted any in-flight capture's rule on every VM start. Set
  elements survive a flush; appended rules do not.
- **`nft delete chain` does not refuse a non-empty base chain.** It succeeds and
  takes the rules with it, so a tolerant teardown silently ended every concurrent
  capture.

Capture now lives in `pcap_output`/`pcap_input`, created on demand, which the
skeleton neither declares nor flushes; `pcap_output` sits at `filter - 10` so a
packet is captured before the drop decides its fate. Relatedly, the skeleton's
`ct mark set` rule is guarded on the workload uid *range* rather than on
`@wl_filtered`: the mark is attribution, not policy — inbound capture selects on
it — so guarding it on the policy set made `-Q in` silently empty for every
container and every `egress = "open"` VM.

Five more, mostly teardown and ownership:

- **nft cannot delete a rule by its text.** Deletion is by handle, and a
  text-shaped delete fails *silently* under a tolerant runner, leaving a `log`
  rule in a security-critical table with nothing owning it. Removal reads live
  handles and narrows them to this workload's nflog group, so a concurrent capture
  keeps its rule.
- **SIGTERM does not run `finally`.** Python's default disposition terminates
  without unwinding, so the ordinary `systemctl stop` path was the one path where a
  guest-side capture was never finalized. The helper turns SIGTERM into
  `SystemExit`.
- **A confined QEMU cannot write the operator's `-w` path**, and it fails on plain
  DAC before SELinux has an opinion, *silently*: `object-add` is accepted, the
  object exists, and no file appears. Captures are staged in the workload's own
  runtime directory and moved on finalize, and the file's existence is checked
  rather than trusted.
- **`Type=exec` marks a unit active before it can fail**, so `--detach` reported
  "Capturing in the background" for a unit that was already dead. The settle check
  is a dwell rather than a poll-until-active: the interesting states arrive
  quickly, and the wrong answer is the early one.
- **wireshark-cli is not installed on a default host.** Packet counts, first-packet
  times and the guest-side timestamp shift went through `capinfos`/`editcap`, which
  the spec listed as `Suggests:` — and they were called from a teardown block, so
  the `FileNotFoundError` aborted the rest of it and the guest-side file was never
  moved. All three are read out of the file in `lib/pcap.py` now; classic pcap is a
  24-byte header and 16 bytes per record and both writers emit it. That also
  retires a silent failure of its own: capinfos renamed its first-packet label
  between releases, and matching one spelling skipped the timestamp correction
  without saying so.

**Both files are classic pcap, not pcapng.** The design wanted pcapng to keep
per-container annotation possible; tcpdump cannot write it (`--pcap-ng` belongs to
dumpcap/tshark). QEMU's `filter-dump` writes classic pcap too, so both vantages
agree on the format, which is what matters for comparing two files. The guest-side
timestamp needs correcting by two independent terms — the timezone offset plus VM
uptime — and the timezone term is the *standard*-time offset even on a host
running DST, because `gmtime_r` leaves `tm_isdst` at 0 and `mktime` then applies
none.

**`[vm.network].ports` may not bind the management range.** Any valid address was
accepted, including the `127.128.0.0/9` carrying management addresses, so one
workload could publish a guest port where another's SSH listener belongs, with
start order deciding the winner. The host-key pin stops that short of a session in
the wrong guest, but a plane documented as never routable and never configurable
should not be reachable from a config key. Now rejected; the rest of 127/8 remains
a normal bind address.

**`hosts` with `egress = "open"` is refused.** Not because it misreports —
`open` means unfiltered and `diagnose` says so — but because hostname policy
stands up a daemon parsing guest-controlled input, with its own SELinux domain and
an egress exemption the guest's uid does not get. That is the wrong thing to build
for a control that binds only cooperative guests. Refused rather than silently
skipped, because a `hosts` list accepted and then ignored *would* be a misreport.

## Consequences

**Removed:**

| Removed | Why it can go |
|---|---|
| `generate_vm_bridge_service()`, the bridge lifecycle | no bridge |
| dnsmasq, its lease file, lease parsing | passt serves DHCP/DNS to the guest |
| `ip workload_nat` table | passt does not forward; it re-originates |
| host-global `sysctl net.ipv4.ip_forward=1` | same |
| setuid-root `qemu-bridge-helper`, `/etc/qemu/bridge.conf` | passt needs no privilege |
| `firewalld/workloadctl.xml` and its test | managed-bridge only |
| `VM_BRIDGE_NAME`, `managed_bridge_params()`, `VM_DHCP_LEASE_FILE` | dead with the bridge |
| the bridge refcount in VM teardown | nothing shared to refcount |

`managed_bridge_params()` is the mechanism ADR 002 introduced; removing it is what
makes this a supersession rather than an amendment.

**Added:** passt netdev construction in the generator; the nftables filter
skeleton, its element management and the `[vm.network]` schema keys; the `runcon`
prefix in `workload-vm-notify` and the `workload-vm` policy module; hostname
policy, since rebuilt as the transparent inspector of ADR 008; and
`workloadctl pcap` with its two vantages.

**New capability, not a migration.** Managed-bridge VMs had no port publishing, so
`[vm.network].ports` adds a facility rather than replacing one.

**Not addressed:**

- **Exfiltration through an allowed destination.** Permitting a host means
  anything the guest can read can leave through it. Structural.
- **DNS tunnelling** where the guest is given a forwarding resolver. Narrowed
  since by ADR 008's synthesising responder, not closed.
- **VMs on an operator-provided bridge**, which are unfiltered by design.
- **Capture of a workload that is not running** — both vantages need a live
  process, a socket to attribute or a netdev to tap.
- **Confinement of the guest's own workloads.** `svirt_t` bounds what the
  hypervisor process may touch on the host and says nothing about what runs inside
  the guest.
- **A host-side reader of guest TLS.** This design put nothing on the host that
  could read a guest's plaintext. ADR 008's `tls = "inspect"` default changed that
  deliberately: a filtered VM's HTTPS is terminated on the host, with a leaf from
  that workload's own CA. It is the price of the allowlist meaning per request what
  it previously meant only per connection, and `tls = "splice"` keeps the original
  property for a workload that needs it. Unchanged by all of it: the guest still
  has no LAN identity of its own, the management address is still uid-derived and
  unroutable, and `[vm.network].ports` is still the only inbound path.

**Testing.** `tests/cli_surface/test_runtime_vm_egress_isolation.py` runs a
filtered workload and an open one concurrently, from TOMLs differing in two lines,
and asserts the *difference*: the open VM reaches a destination the filtered one
cannot, and the filtered one still reaches the single entry in its own `allow`
list. A second test purges the open VM and shows the survivor stays armed — the
disarming direction being the silent one, since a VM that quietly stops being
filtered keeps passing every other check. A single filtered VM failing to reach a
host proves only that something is broken; the property lives in the difference
between two guests identical apart from a posture. Both tests read the postures
back out of `wl_filtered` before probing and skip rather than pass if the harness
host cannot reach the destination itself.
