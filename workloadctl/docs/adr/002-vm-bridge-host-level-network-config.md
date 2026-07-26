# ADR 002: VM managed-bridge network config is host-level, not per-VM

**Status:** **Implemented** 2026-07-03 (code review 2026-07 follow-up, item D1;
carded as B16). `managed_bridge_params` in `workload_lib.py` derives the gateway,
CIDR, and DHCP range from `WORKLOADCTL_VM_BRIDGE_SUBNET`; per-VM subnet/dns are
rejected.

**Date:** 2026-07-03.

## Context

The shared managed VM bridge (`_workload-br`, `VM_BRIDGE_NAME`) is provisioned by a
single host-global unit, `workload-bridge.service`, emitted by the generator only
when at least one VM uses the default bridge. Its lifecycle:

- `Type=oneshot, RemainAfterExit=yes`; held up by each VM's
  `Requires=`/`After=workload-bridge.service` plus a `multi-user.target.wants`
  symlink. Because it is `Requires`-held (not `BindsTo`/`PartOf`), **once started it
  stays up until an explicit stop or reboot** — a dependent VM stopping does not tear
  it down.
- Ownership marker `/run/workload-vm/bridge-managed` gates every NAT / dnsmasq /
  teardown step, so it only touches a bridge it created (create-or-adopt is
  idempotent).

The subnet and DNS servers, however, were read **per-VM** from `[vm.network].subnet`
/ `[vm.network].dns` and interpolated into this single shared unit. Two consequences:

1. **Last-write-wins across VMs.** The last VM the generator processes defines the
   bridge for *all* VMs. Worse, given the `RemainAfterExit` lifecycle above, the
   running bridge reflects whoever *started* first while the on-disk unit reflects
   whoever *generated* last — the two can silently disagree until a restart.
2. **The per-VM override never fully worked, even for one VM.** The bridge IP/CIDR
   and the NAT masquerade rule were derived from the override, but dnsmasq's
   `--dhcp-range` used the hardcoded `VM_DHCP_RANGE` constant
   (`192.168.200.100,199`). Overriding `subnet` to e.g. `10.100.0.0/24` put the
   bridge on `10.100.0.1` and masqueraded `10.100.0.0/24`, but guests were handed
   `192.168.200.x` addresses off the wrong subnet → no connectivity.

No shipped workload, example, or the live `git` VM sets `subnet`/`dns`; all use the
defaults. So the feature is both unused and broken.

## Decision

**Subnet and DNS for the managed bridge are host-level configuration, not per-VM.**

- Remove `[vm.network].subnet` and `[vm.network].dns` from the per-VM schema (and the
  per-VM validation added in `d08a2fb`, which validated fields that no longer exist).
- Introduce a single host-level source of truth for the managed-bridge subnet and DNS
  (a host config value / constant override), consumed once by
  `generate_vm_bridge_service`.
- **Derive `--dhcp-range` from the configured subnet** so a non-default subnet
  actually works end-to-end (fixes the latent DHCP bug above).
- `[vm.network].bridge` stays per-VM — pinning a VM to a *user-provided* bridge
  (e.g. `br0`) is a legitimate per-VM choice and already skips
  `workload-bridge.service` entirely; only the *managed*-bridge subnet/DNS is
  host-scoped.

## Rationale

A shared, host-global, refcount-persistent resource cannot coherently take per-VM
overrides — the config granularity must match the resource granularity. The
"validate consistency across VMs" alternative was rejected: it preserves a per-VM
field that is both unused and non-functional, adds generate-time cross-VM validation
complexity, and still can't reconcile the disk-vs-runtime disagreement the
`RemainAfterExit` lifecycle creates. Lifting to host-level is near-zero migration
cost (nothing sets these today) and lets the DHCP-range fix fall out naturally.

## Consequences

- Breaking schema change, but with no real-world impact (no config sets these fields).
- `docs/schema-reference.toml`, `docs/workloads.md`, and `validate_vm_config` update
  to drop the per-VM fields and document the host-level knob.
- The dhcp-range-from-subnet fix means the managed bridge is relocatable for the first
  time (e.g. to avoid a `192.168.200.0/24` clash on the host LAN).
- Implemented: `managed_bridge_params()` in `lib/vm.py` derives
  `VM_BRIDGE_IP`/`VM_BRIDGE_CIDR`/`VM_BRIDGE_SUBNET`/`VM_DHCP_RANGE` from the
  host-level subnet; `validate_vm_config` rejects the per-VM fields.
