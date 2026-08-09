# ADR 006: VM networking uses passt, not a shared managed bridge

**Status:** **Implemented** 2026-08-09 (step 1 of the implementation sequence: the netdev, the schema, and the SELinux label work). Supersedes ADR 002.

The uid-keyed nftables egress policy this decision exists to enable is **not** in that step — VM workloads run unfiltered today, the same posture as under the bridge. `[vm.network].egress` and `.allow` are rejected by `validate` rather than accepted-and-ignored, so no config can claim a confinement that is not in force.

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
| nflog group | `uid - UID_MIN` | per-workload packet capture |
| Policy key | the uid itself | `meta skuid` in nftables |

`UID_MIN..UID_MAX` is 10000–52948 — 42,949 values, inside both `127.128.0.0/9`
and the 16-bit nflog group space. The `127.128.0.0` base avoids `127.0.1.1`,
which Debian conventionally places in `/etc/hosts`.

The per-VM schema gains `[vm.network]` with `ports`, `egress`
(`"filtered"` default / `"open"`), `allow`, `outbound_if`, and `resolver`
(`"host"` default / `"none"`). `[vm.network].bridge` is retained as the
unfiltered escape hatch: a VM that names an operator-provided bridge attaches
directly, takes a real LAN identity, and is not filtered — by design.

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

**Added:** netdev construction in the generator, the nftables skeleton and its
element management, and the schema keys above.

**New capability, not a migration.** Managed-bridge VMs have no port publishing
today, so `[vm.network].ports` adds a facility rather than replacing one.

**Not addressed by this ADR:**

- **Exfiltration through an allowed destination.** Permitting a host means
  anything the guest can read can leave through it. Structural.
- **DNS tunnelling** when the guest is given a forwarding resolver.
- **VMs on an operator-provided bridge**, which are unfiltered by design.
- **SELinux confinement of VM workloads.** Today the unit sets no
  `SELinuxContext=`, so QEMU runs `unconfined_service_t` while container
  workloads get per-workload types. That asymmetry predates this decision and
  is not closed by it. passt makes closing it cheaper — the shipped policy
  already carries a `svirt_t` → `passt_t` transition, and `passt-selinux` is
  pulled in by a rich dependency on `selinux-policy-targeted` rather than as a
  weak dep, so it survives `install_weak_deps=False` — but confining QEMU
  itself remains a separate decision with unresolved cost.

**Testing debt.** The runtime harness boots a single VM. The central property
above — one rule blocking one workload and not its sibling — cannot be tested
with one VM. A multi-VM harness is required to cover it, and is tracked
separately as lower priority than the implementation itself.
