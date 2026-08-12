# ADR 006: VM networking uses passt, not a shared managed bridge

**Status:** **Implemented.** All five steps of the implementation sequence. Supersedes ADR 002.

- Step 1 (2026-08-09): the passt netdev, the schema, and the SELinux label work.
- Step 2 (2026-08-10): the nftables skeleton and the `egress`/`allow` schema.
- Step 3 (2026-08-10): QEMU confined as `svirt_t`, and the virtiofsd domain.
- Step 4 (2026-08-10): the per-workload proxy, the `hosts` schema key, and its domain.
- Step 5 (2026-08-11): `workloadctl pcap`, both vantages, and the timestamp correction.

**Date:** 2026-08-09.

## Context

VM workloads attach to `_workload-br`, a single host-global NAT bridge
provisioned by `workload-bridge.service` and shared by every VM that does not
name its own. ADR 002 resolved a last-write-wins hazard in that unit by lifting
subnet and DNS to host-level configuration. That fix was correct for the
topology it was given, but the topology itself is the problem:

- **Every VM shares one L2 segment.** VM-to-VM isolation depends on rules, not
  structure — there is a segment to spoof onto and an ARP cache to poison.
- **There is no per-VM network identity to key policy on.** Guest-chosen
  addresses are forgeable by definition, so any egress policy would need L2
  anti-spoofing to mean anything, and would need address allocation to have
  something to write rules about.
- **The data path needs host privilege:** a host-global
  `sysctl net.ipv4.ip_forward=1`, a setuid-root `qemu-bridge-helper` reached
  through `/etc/qemu/bridge.conf`, an `ip workload_nat` table, and a firewalld
  zone — all of which sit oddly against the rootless-podman posture the rest of
  the project holds to.
- **A shared, refcount-persistent resource resists per-VM configuration**, the
  finding ADR 002 already recorded.

Container workloads have none of these problems, because pasta gives each one
its own re-originated network identity. The same backend is available to VMs.

## Decision

**VM workloads use passt as their network backend. The managed bridge is
removed.**

passt terminates the guest's network stack in userspace and re-originates its
traffic as ordinary host sockets. Those sockets are owned by the workload's
existing dedicated system user (`_wl-<name>`, UID 10000+), so **the workload
uid becomes the network identity** — unforgeable by the guest, unique per
workload without any allocation step, and directly matchable by nftables.

Per-VM egress policy is therefore a host output chain matching `meta skuid`.
No address allocation, no L2 anti-spoofing, no shared bridge to secure.

Three values derive from the uid with no registry:

| Derived value | Formula | Used for |
|---|---|---|
| Management address | `127.128.0.0 + (uid - UID_MIN)` | inbound SSH, proxy listener |
| nflog group | `1000 + (uid - UID_MIN)` | per-workload packet capture |
| Policy key | the uid itself | `meta skuid` in nftables |

`UID_MIN..UID_MAX` is 10000–52948 — 42,949 values, inside both `127.128.0.0/9`
and the 16-bit nflog group space.

**Both bases exist to miss a convention, and the second was added late.** The
`127.128.0.0` base avoids `127.0.1.1`, which Debian conventionally places in
`/etc/hosts`. The nflog group originally had no base, which put the *first*
workload allocated on any host on group 0 — iptables' `--nflog-group` default
and what stock ulogd configurations bind. That is not a crash: it silently
merges two streams in both directions, putting a site's logged packets into
that workload's capture and the workload's packets into the site's log. Base
1000 clears the small numbers convention uses and leaves 21,587 groups spare.

Everything customary in `127.0.0.0/8` sits below the range — `127.0.0.1`,
Debian's `127.0.1.1`, systemd-resolved's `127.0.0.53`/`.54`, Istio's
`127.0.0.6`, the DNSBL `127.0.0.2`/`.3` — because RFC 6890 registers the /8 as
one undivided Loopback block, so there is nothing *reserved* to hit and the
conventions cluster at the bottom where the addresses are memorable. The range
also spans addresses that look like network and broadcast addresses
(`127.128.0.0` for the first workload, `127.128.0.255` for the 256th), and they
are ordinary hosts: `lo` carries `127.0.0.1/8`, so the only special addresses of
that prefix are `127.0.0.0` and `127.255.255.255`, neither of which is in range.
Verified by binding and completing a TCP round trip on both, since every unit
test until now asserted only the string.

The per-VM schema gains `[vm.network]` with `ports`, `egress`
(`"filtered"` default / `"open"`), `allow`, `hosts`, `outbound_if`, and
`resolver` (`"host"` default / `"none"`). `allow` is address policy; `hosts`
is hostname policy, served by the per-workload proxy step 4 added.
`[vm.network].bridge` is retained as the unfiltered escape hatch: a VM that
names an operator-provided bridge attaches directly, takes a real LAN
identity, and is not filtered — by design.

## Rationale

**The uid is the whole argument.** Everything else follows from having a
network identity the guest cannot influence. This was verified rather than
assumed: with two concurrent VMs, one `meta skuid` rule blocked one and left
the other untouched.

**Load-bearing precondition, from passt's source:** passt keeps its inherited
uid *only because it is not started as root*. Started as root it drops to
`nobody`, collapsing every workload into a single uid and silently defeating
the scheme — the failure is invisible, since traffic still flows. The generated
unit's `User=` prevents this, and a test must assert it rather than assume it.

**Throughput is not a constraint.** Measured guest→host with iperf3 on a
Fedora 44 host: 11.3 Gbit/s TX, 4.9 Gbit/s RX in stream mode — bridge-class.
`vhost-user=on` measures faster still and is deliberately not adopted, because
it would reintroduce a shared memory path for a throughput gain nothing here
needs.

**No new packaging risk.** QEMU 10.2 exposes a native `passt` netdev, so there
is no separate process to launch or socket to wire; the image already ships
`qemu-kvm` 10.2.x. `passt` is now an explicit dependency in
`hypervisor.Containerfile` rather than arriving transitively via podman, since
it moves from an incidental container detail to the VM data path.

**The default posture is stricter than the zone it replaces.** With
`--map-host-loopback none`, host loopback is unreachable from the guest, and
the host's default-route address is unreachable *structurally* — the guest is
assigned that same address, so traffic to it never leaves the guest's own
stack. Other host addresses (a secondary IP, a second interface) remain
ordinary routable destinations, which is precisely the residue the egress
policy exists to handle. Deleting the firewalld zone is therefore not a
regression.

**passt is self-confining.** Before serving traffic it drops all but a few
capabilities, `pivot_root`s into an empty filesystem, applies a seccomp filter,
and enters a user namespace. This holds independently of SELinux.

**Alternative rejected — keep the bridge and add anti-spoofing.** This buys
back a forgeable identity at the cost of address allocation, per-VM L2 rules,
and retaining every privileged component above. It is strictly more machinery
for a strictly weaker property.

## Decisions taken during implementation

Four things the design above does not settle. All were decided or found while
building step 2, and are recorded here because a later reader would otherwise
be entitled to "fix" them.

**`allow` takes addresses and ports only, never hostnames.** The entries
become elements of an nftables set keyed on `ip daddr` / `ip6 daddr`. A
hostname has no representation there, so accepting one would mean resolving it
once at unit start and pinning the result for the life of the VM — silently
wrong from the moment the record moves, and wrong in the permissive direction
if the address is later reassigned. Hostname policy is `hosts`, carried by the
per-workload proxy step 4 added; `allow` is for the non-HTTP exceptions a
proxy cannot carry, and those are overwhelmingly single hosts (ssh, a
database, an NTP peer) where an address is the honest way to say it.

**`egress = "filtered"` with nothing reachable is a validation error.** The
choices were to default to `"open"` and tighten later, to accept `"filtered"`
and let the VM boot unreachable, or to refuse the combination. Refusing it was
chosen: the secure default lands now rather than being retrofitted, and nothing
can boot in a state where the config claims a confinement the VM does not have
— the failure mode this whole layer exists to prevent. The cost is that every
VM config must state a posture explicitly, including ones that only ever wanted
defaults; `egress = "open"` is what the shipped bundles and examples say, with
the reason given inline.

Step 4 was expected to retire this. The design pairs the `"filtered"` default
with an implicit allow to the workload's own proxy, which would have made a
bare `[vm.network]` valid again and meaning `"filtered"`. It did not, because a
workload gets a proxy instance only when `hosts` is non-empty — the schema
deliberately cannot express "proxy on, allowlist empty", an instance permitting
nothing being indistinguishable from a broken one. A bare `[vm.network]`
therefore still describes a VM that can reach nothing. The refusal is permanent,
with its trigger widened rather than removed: `"filtered"` is an error when
`allow` and `hosts` are *both* empty.

**Loopback is exempt from the filter, and has to be.** The design treats
management inbound (§3.3) and egress policy (§4) as independent, and they are
not. passt binds the management address `127.128.x.y:2222` *as the workload
user*, so the replies carrying an `exec`/`shell` session are output traffic
owned by the workload uid and land in the same chain as the guest's own
traffic. It forwards DNS to `dns-host` the same way, which on a
systemd-resolved host is `127.0.0.53`. A filtered VM without a loopback
exemption is therefore unreachable *and* unable to resolve — observed on a
live VM, where the TCP connection to the management port was accepted and then
silently died while the drop counter climbed.

This also corrects §5.2 of the design, which states that under a stub resolver
guest DNS is "invisible to `meta skuid`". It is not: passt makes that query, so
it carries the workload uid and is filtered like anything else.

The skeleton therefore accepts `oif lo` for filtered uids, before the drop.
This does not widen what a guest can reach. `--map-host-loopback none` means no
guest-chosen destination translates to host loopback, so the only loopback
traffic passt originates is replies on sockets it already bound and the DNS
forward; a guest packet aimed at `127.0.0.1` never leaves the guest's own
stack.

**The drop counter is host-wide, not per-workload.** The design says the
`counter` on the drop rule "gives `diagnose` per-workload drop counts with no
extra machinery". It does not: there is one drop rule, guarded on set
membership, so every filtered workload's dropped packets accumulate on the same
counter. Per-workload counts would need a rule or a named counter per uid,
which is the machinery the shared rule was chosen to avoid. `diagnose` reports
the number and says explicitly that it is shared, because silently attributing
a sibling VM's dropped traffic to the one being diagnosed would send an
operator after the wrong workload.

### Step 3: confinement

**The host-global policy ships in the RPM, not in the image.** The design says
the virtiofsd domain "ships with the image beside `security/pasta_sandbox.cil`
and is installed by the RPM", which are two different vehicles. It went in the
RPM (`workloadctl/security/workload-vm.cil` →
`/usr/share/workloadctl/workload-vm.cil`, loaded by `%post`) because workloadctl
is a standalone package that does not depend on this image: a module delivered
by the image would leave VM confinement broken on any other host, and the code
that needs the module and the module itself would version-skew. Neither vehicle
closes the bootc gap the image's own Containerfile already records — the policy
store lives in `/etc`, which ostree 3-way-merges, so an upgrade does not deliver
a changed module to a host that has ever loaded a local one. `diagnose` reports
whether it is loaded, which is the same answer the image gives for its booleans.

**The module carries a second, unrelated-looking rule, and should.** It was
named for virtiofsd and now also grants `svirt_t` what QEMU's native passt
netdev needs. Both exist for one reason — workloadctl runs QEMU as `svirt_t`
*outside libvirt*, and the shipped policy is written around libvirt's
arrangement — so they are one module, `workload-vm`, rather than a virtiofsd
module plus a passt module that would always be installed together.

**`runcon`, not a `setexeccon()` call.** `lib/` has no third-party dependencies
and the stdlib has no SELinux binding, so the alternative is a
`python3-libselinux` requirement for one call. `runcon` also execs the target in
its own process, which scopes the pending exec context to the child by
construction; `setexeccon()` in `workload-vm-notify` would leave it armed for
whatever that process execs next.

**Confinement is unconditional for VM workloads, and degrades rather than
fails.** It is not gated on `[security].selinux_policy`, for the same reason
disk labelling is not: a VM that omitted the flag would be silently unconfined.
On a host with SELinux disabled the runcon prefix is dropped and the VM runs as
it did before this step, because failing the start would turn "this host has no
SELinux" into "VMs do not run". `diagnose` reports which of the two happened.

### Corrections from the enforcing run (step 3)

Five things the design did not have right. Every one of them was found by
running it, and none would have failed a unit test or a review.

**Registering the fcontext rule does not label the directory.** §9.4 says
relabel `/run/workload-vm` to `svirt_var_run_t` and "the same command runs",
which reads as though the `semanage` rule is the work. It is not: the kernel
labels a newly created file from its *parent directory*, and `file_contexts` is
consulted only by userspace tools like `restorecon`. A directory mkdir'd under
`/run` inherits `var_run_t` however many rules name it, so a confined QEMU could
not create its QMP socket or read the cloud-init ISO — and `/run` is a tmpfs, so
it recurs every boot. `setup_vm_socket_dir` now runs `restorecon` before
anything is written into the directory, since everything created inside
inherits from it.

**passt needs a rule that no audit harvest will show you.** QEMU's native netdev
forks passt with one end of a socketpair already open; libvirt starts passt
separately and connects by path. So under our topology `passt_t` must read and
write a `unix_stream_socket` labelled `svirt_t`, which the shipped policy does
not grant — and *dontaudits*, so the denial produces no AVC at all. What is
observed is passt failing with `Failed to add fd to epoll: Operation not
permitted`, QEMU respawning it in a tight loop, an unreachable guest, and an
empty audit log. 1563 suppressed denials in 30 seconds, visible only under
`semodule -DB`. Anyone re-deriving this module from a fresh harvest will miss it
the same way. QEMU also needs `signal` on `passt_t`, or every stop leaks a passt
process.

**`dac_override` is genuine for virtiofsd.** §9.7 discounts it as a bench
artifact of running QEMU as root. That is right about QEMU, which production
runs as `_wl-<name>`, and wrong about the sidecar, which runs as root
deliberately (an unprivileged virtiofsd squashes every guest-created file to its
own uid). Without it virtiofsd exits 1 with nothing in the journal and the VM
fails on the dependency.

**The permissive harvest under load was larger than "a few more lines".** §9.7
predicted the FUSE-serving permissions would "close for free" — they did close,
but they are the whole write surface on `svirt_image_t` (file
create/read/write/unlink, dir add_name/remove_name/rmdir/write), a mapping of
QEMU's memfd (`svirt_tmpfs_t`), a `search` on the `container_file_t` parent the
share is reached through, and the socket cleanup on exit. The prediction that
one enforcing pass would still be required was correct and load-bearing:
`dac_override` was denied enforcing after a permissive run that never reached
it.

**A volume outside the workload tree is not covered.** `wlvfsd_t` is granted the
types workloadctl itself labels. A volume pointing at an operator path carries
whatever label that path already has (`/srv` is `var_t`) and the sidecar is
denied it. The module cannot pre-empt this without granting the union of every
type on the host, so the fix is an fcontext rule on the operator's path.

**Verified enforcing on Fedora 44 (selinux-policy 44.5):** boot, virtiofs mount,
32 MiB write/read/delete at 154 MB/s, mkdir/rmdir, DNS, `workloadctl exec`, and
a clean stop — zero denials, no leaked passt. `diagnose` reports 12/12, and
fails as intended when the module is removed.

### Step 4: the proxy

**The open question is closed, and the answer keeps tinyproxy.** The design
tracked "how large is the SELinux delta for a confined tinyproxy?" as its last
open question, because the answer could reopen the choice — squid's one
advantage is that `squid_t` and `squid_exec_t` already exist. Measured: **14
allow rules, no capabilities at all**, smaller than the virtiofsd domain next
door. The choice stands, and now on a measurement rather than an estimate.

**Harvesting that module is not like harvesting `wlvfsd_t`.** A permissive run
is close to useless for tinyproxy: it exits 70 the moment it cannot read its own
config, so the harvest records the first gate and nothing behind it. The
permissive pass produced 10 rules, of which the module needed 14 — and the
missing 4 were each revealed by a separate *enforcing* iteration, one gate at a
time. Step 3's guidance (harvest permissive, confirm enforcing) inverts here:
for a fail-fast daemon, enforcing iteration *is* the harvest.

**The advertised address is a constant, not a schema key** — a deliberate
deviation from §4.4, which says "settable in the schema". The address belongs to
a host-global dummy interface, so a per-workload key would let two workloads
disagree about a shared object: the last-write-wins hazard ADR 002 exists to
describe and this design deleted along with the bridge. A site that genuinely
uses TEST-NET-1 internally uses `allow` and skips hostname policy.

**The proxy's slice is pinned, not inherited from `[resources]`.** The egress
exemption below is an nftables `socket cgroupv2 level 2` match, so the cgroup
path must be exactly two components; a nested custom slice would deepen it and
the match would silently stop firing. The proxy is not the payload — resource
control belongs on the VM.

**One module per component, both host-global.** `workload-proxy.cil` is separate
from `workload-vm.cil` rather than merged: they exist for unrelated reasons (one
because we run QEMU outside libvirt, one because Fedora has no tinyproxy policy
at all) and they are removable independently.

### Corrections from the live run (step 4)

Four more the design did not have right, all found by running it.

**The proxy shares the guest's uid, so default-deny drops the proxy too.** This
is the largest of them, and it follows directly from a property §4.4 presents as
a *feature*: "each instance runs as `_wl-<name>` … so one `meta skuid` rule
governs both the direct and the via-proxy path". It does — including the drop.
On a live VM the guest's CONNECT reached the proxy, the proxy resolved the host,
and its outbound SYN was dropped by the workload's own filter. Hostname policy
permitted nothing at all while every component looked healthy.

The fix has to separate proxy from guest *within one uid*, and the control group
is the only discriminator that does: systemd assigns it, a guest can neither
enter nor forge it, and it widens no destination or port. The obvious
alternative — "let this uid reach 443 anywhere" — is fatal, because it is
exactly the bypass the default-deny chain exists to close. `wl_proxy_cg` is a
set of cgroup paths in the filter skeleton, managed as elements like everything
else, and re-added on every proxy start because an element resolves to a cgroup
id and systemd makes a fresh cgroup each time.

**tinyproxy's client ACL must name the advertised address.** The guest's packet
is routed to `192.0.2.1` *before* it is translated, so the host picks that same
address as the source and the proxy sees a client connecting from it. Without
`Allow 192.0.2.1` every request answers 403 while the listener, the redirect,
the interface and the guest all look correct; the only trace is tinyproxy's
"Unauthorized connection from" at INFO level.

**`nft -j list map` renders elements as `[key, value]`, not `{"elem": {...}}`.**
The set shape and the map shape differ, and the map document is keyed `"map"`
rather than `"set"`. Reading a map with set-shaped code returns no elements at
all, which reads as "not armed" — so `diagnose` reported a demonstrably working
redirect as broken, on the same host, in the same minute.

**Two smaller ones.** iproute2 answers a duplicate address with "Address already
assigned", not the "File exists" a duplicate *link* produces, so the idempotency
check failed only on the second start of a workload. And `redirect` is a
reserved word in nft, so a nat chain cannot be called that — the parse error
points at the chain name without saying why.

Two things the design worried about turned out to be free. `route_localnet` is
**not** required: DNAT from the output hook to a 127/8 destination works with it
at its default 0, verified on a live host and not only in a namespace. And the
proxy endpoint needs **no** entry in `wl_allow4`: the nat hook (dstnat, -100)
runs before the filter chain (0), so the filter sees the translated destination
— the workload's own loopback address — which the skeleton's `oif lo` rule
already accepts.

**Verified enforcing on Fedora 44:** with `egress = "filtered"` and an empty
`allow`, a guest reached an allowlisted host over HTTPS (200) and over plain
HTTP (200), reached a wildcard-matched host (200), was refused a non-allowlisted
host by the proxy, and was **dropped by the kernel when it bypassed the proxy
entirely** — which is the property that makes hostname policy binding rather
than advisory. Clean across a full restart cycle, with zero SELinux denials and
`diagnose` at 13/13.

### Step 5: capture

**Host-side first, as the sequence directs** — it is the default, works on
every substrate, and needs no QMP. The guest side followed, and the ordering
paid: every teardown and ownership defect below was found with the simpler
vantage, before a QMP object was in the picture.

**The plan is one object, not two renderings.** `--dry-run` prints it and the
helper executes it, and it travels to the helper as JSON rather than being
re-derived — because a helper that recomputed the plan from the config could
disagree with what was printed, and the whole contract of §6.6 is that they
cannot.

**Both files are classic pcap, not pcapng.** The design wanted pcapng so
per-container annotation stayed possible later. tcpdump cannot write it —
`--pcap-ng` is not a tcpdump option at all (4.99.6; it belongs to
dumpcap/tshark). QEMU's `filter-dump` writes classic pcap too, so both vantages
agree on the format, which is what actually matters for comparing two files.

### Corrections from review (step 5)

Three, all one mistake: **capture wrote into chains the policy skeleton owns.**
Each half of it was silent, and the live run missed all three because it
exercised one workload at a time, and an unfiltered one.

**An appended rule is not a reachable rule.** `nft add rule` appends, and the
skeleton's `output` chain ends with a terminating `accept`/`drop` for every
filtered uid — so the outbound `log` rule landed below the drop and could never
match. `pcap -Q out` captured nothing at all for exactly the workloads egress
filtering exists to observe, while reporting a healthy capture.

**The skeleton flushes what it owns.** `flush chain ... output` is what makes
the skeleton re-appliable, and it deleted any in-flight capture's rule — on
every VM start, and on any other workload starting a capture. Set elements
survive a flush; appended rules do not.

Both are fixed by the same move: capture now lives in `pcap_output` and
`pcap_input`, created on demand, which the skeleton neither declares nor
flushes. `pcap_output` sits at `filter - 10`, ahead of policy, so a packet is
captured *before* the drop decides its fate — which is the more useful vantage
anyway.

**`nft delete chain` does not refuse a non-empty base chain.** It succeeds and
takes the rules with it, so teardown's "delete it and let it fail harmlessly"
silently ended every concurrent capture. A chain is now deleted only after a
re-list shows no `log` rule left in it.

A fourth, related: the skeleton's `ct mark set` rule was guarded on
`@wl_filtered`. The mark is *attribution*, not policy — inbound capture selects
on it — so guarding it on the policy set made `-Q in` silently empty for every
container and every `egress = "open"` VM. It is now guarded on the workload uid
range, which is what the mark always meant.

The common lesson is narrower than "test concurrency": **a feature that writes
into a table another component owns has to write into its own chain**, or it
inherits that component's ordering and its flushes.

### Corrections from the live run (step 5)

Six, and five of them were teardown or ownership rather than capture.

**nft cannot delete a rule by its text.** Deletion is by handle. A text-shaped
delete fails, and fails *silently* under a tolerant runner — so the first
implementation's teardown removed nothing at all, and left a `log` rule in the
security-critical table with nothing owning it. Removal now reads the live
handles and narrows them to this workload's nflog group, so a concurrent
capture on another workload keeps its rule.

**SIGTERM does not run `finally`.** Python's default disposition terminates the
process outright without unwinding, so the ordinary `systemctl stop` path — the
one an operator uses every time — was the single path where a guest-side
capture never got finalized: the process died, and `ExecStopPost` then found a
staged file with nobody left to move it. The helper now turns SIGTERM into
`SystemExit`.

**A confined QEMU cannot write the operator's `-w` path**, which §13 predicted
and which is worse than predicted: it fails on plain **DAC** before SELinux has
an opinion (QEMU runs as `_wl-<name>`, the path is root-owned), and it fails
*silently* — `object-add` is accepted, the object exists, and no file ever
appears. The capture is staged in the workload's own runtime directory, which
step 3 already labelled `qemu_var_run_t` so a confined QEMU could create
sockets there, and moved on finalize. The move rides along free because the
timestamp correction already required a finalize step. The file's existence is
now checked rather than trusted.

**`Type=exec` marks a unit active before it can fail.** A capture whose
`object-add` QEMU refuses, or whose tcpdump exits on a bad option, is
observably "active" first — so `--detach` reported "Capturing in the
background" for a unit that was already dead. The settle check is now a dwell
rather than a poll-until-active: the interesting states arrive quickly, and the
wrong answer is the early one.

**capinfos says "Earliest packet time", not "First packet time."** Matching one
label is a silent no-op — the correction is skipped, the file keeps a timestamp
hours in the future, and nothing says so. Both labels are accepted and a failed
correction now warns.

**A second capture was refused only after the plan had been narrated**, which
described something that was not going to happen.

**§6.9 confirmed on hardware, both terms.** The measured offset was
**−29,407.4 s**: 28,800 s of timezone offset plus ~607 s of VM uptime, exactly
the two independent errors the design separated. 28,800 s is the *standard*-time
offset (PST) on a host that was on PDT at the time, because `gmtime_r` leaves
`tm_isdst` at 0 and `mktime` then applies no DST — so the term is not even the
offset in force when the capture ran. After correction the file's first
packet landed on wall clock. The probe is a TCP connect to the workload's own
management address — passt hands the guest a SYN, which the tap sees, and the
guest is not asked for anything.

**Verified on Fedora 44:** host vantage alone (rule installed, traffic
attributed, rule removed, file readable); guest vantage alone (object added,
staged, corrected, moved); both together, producing files whose first packets
are 1.0 s apart on the same wall clock — the alignment that is the entire point
of two vantages, and which does not exist without the correction. The guest
file held 77 packets to the host file's 18, which is §6.2's claim about what
never becomes a host socket, measured. A `kill -9` of the capture process left
**zero** rules, no chain, and no QEMU object — teardown by `ExecStopPost`, not
by a `finally`. A second concurrent capture was refused by name. Zero SELinux
denials throughout.

### Corrections from the pre-merge review

Three, found by reading rather than running, and the first would have hit every
default install.

**capinfos and editcap are not installed, and were called from a `finally`.**
Packet counts, first-packet times and the guest-side shift went through
wireshark-cli, which the spec listed as `Suggests:` — and dnf installs
`Recommends:` but not `Suggests:`, so the default host had tcpdump and neither
finisher. Every one of those calls sits in the helper's teardown block, so the
`FileNotFoundError` aborted the rest of it: the guest-side file was never moved
to the operator's `-w` path, and only the unit's `ExecStopPost` kept a `log`
rule from being left behind. The tell that it was an oversight rather than a
choice is that `editcap` *was* guarded and capinfos was not, from the same
package.

All three are now read out of the file in `lib/pcap.py` — classic pcap is a
24-byte header and 16 bytes per record, and both our writers emit it — so the
dependency is gone rather than guarded. That also retires a silent failure of
its own: capinfos renamed the first-packet label between releases, and matching
one spelling skipped the correction without saying so.

**`[vm.network].ports` could bind the management range.** Any valid address was
accepted, including the `127.128.0.0/9` that carries the per-workload
management addresses, so one workload could publish a guest port where
another's SSH listener belongs — with start order deciding the winner. The
host-key pin stops that short of a session in the wrong guest, since `exec`
fails verification rather than connecting, but a plane the design calls "never
routable and never configurable" should not be reachable from a config key.
Now rejected; the rest of 127/8 is still a normal bind address.

**The nflog group had no base, so the first workload took group 0.** The
address derivation got a base specifically to dodge `127.0.1.1`; the group
derivation got none, and landed on the netfilter default — see the Decision
above for what that merges. Fixed by the same move the addresses already used.
The addresses themselves check out, including the `.0` and `.255` ones, which
is now asserted by binding rather than by spelling.

**`hosts` with `egress = "open"` is refused.** It was accepted, and it built a
proxy that bound only the guests choosing to be bound — the drop is what makes
the allowlist mandatory. The first review draft called this a misreport and it
is not: `open` means unfiltered, `diagnose` says so plainly, and the
no-silent-default rule means nobody reaches `open` without typing it. The
reason to refuse it is narrower and better: a proxy is a daemon parsing
guest-controlled input, with its own SELinux domain and an egress exemption the
guest's uid does not get, and that is the wrong thing to stand up for a control
that stops only cooperative guests. Refused rather than silently skipped,
because a `hosts` list accepted and then ignored *would* be the misreport. It
joins the two refusals already there — `hosts` with `bridge`, and
`hosts = ["*"]`.

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

`managed_bridge_params()` is the mechanism ADR 002 introduced; removing it is
what makes this a supersession rather than an amendment.

**Added:** netdev construction in the generator (step 1); the nftables
skeleton, its element management, and the schema keys above (step 2); the
`runcon` prefix in `workload-vm-notify` and the `workload-vm` policy module
(step 3); the per-workload tinyproxy, its uid-keyed redirect, and the
`workload-proxy` policy module (step 4); `workloadctl pcap` and its two
vantages (step 5).

**New capability, not a migration.** Managed-bridge VMs have no port publishing
today, so `[vm.network].ports` adds a facility rather than replacing one.

**Not addressed by this ADR:**

- **Exfiltration through an allowed destination.** Permitting a host means
  anything the guest can read can leave through it. Structural.
- **DNS tunnelling** when the guest is given a forwarding resolver.
- **VMs on an operator-provided bridge**, which are unfiltered by design.
- **Capture of a workload that is not running.** Both vantages need a live
  process — a socket to attribute or a netdev to tap.
- ~~**SELinux confinement of VM workloads.**~~ **Closed by step 3**, which the
  original text listed here as a separate decision with unresolved cost. QEMU
  now enters `svirt_t` via a `runcon` prefix in `workload-vm-notify`, and passt
  and swtpm transition for free on the shipped policy's own rules. What was not
  anticipated is that the QEMU-native passt netdev needs two grants libvirt's
  arrangement never does — see the corrections above.

- **Confinement of the guest's own workloads.** `svirt_t` bounds what the
  hypervisor process may touch on the host. It says nothing about what runs
  inside the guest, which is the guest's own problem.

**Testing debt: closed.** The runtime harness now boots two VMs.
`tests/cli_surface/test_runtime_vm_egress_isolation.py` runs a filtered
workload and an open one concurrently, from TOMLs that differ in exactly two
lines, and asserts the difference: the open VM reaches a destination the
filtered one cannot, and the filtered one still reaches the single entry in its
own `allow` list. A second test purges the open VM and shows the survivor stays
armed — the disarming direction being the silent one, since a VM that quietly
stops being filtered keeps passing every other check.

The shape of that test is the point. A single filtered VM failing to reach a
host proves only that something is broken; the property lives in the
*difference* between two guests that are identical apart from a posture. Both
tests guard their own preconditions first — the postures are read back out of
`wl_filtered` before any probe, and the run skips rather than passes if the
harness host cannot reach the destination itself — because every one of those
would otherwise turn into a green that means nothing.
