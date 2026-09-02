# ADR 002: VM managed-bridge network config is host-level, not per-VM

**Status:** Superseded by [ADR 006](006-vm-networking-passt-not-managed-bridge.md),
which removed the managed bridge entirely. `managed_bridge_params()`,
`WORKLOADCTL_VM_BRIDGE_SUBNET` and `WORKLOADCTL_VM_BRIDGE_DNS` no longer exist,
and `[vm.network].subnet` / `.dns` are rejected with a pointer to ADR 006.

Kept because the finding is what motivated the supersession: a shared,
refcount-persistent host resource cannot coherently take per-VM configuration.

## Context

The shared managed VM bridge (`_workload-br`) was provisioned by a single
host-global unit, `workload-bridge.service`, emitted by the generator whenever at
least one VM used the default bridge:

- `Type=oneshot, RemainAfterExit=yes`, held up by each VM's `Requires=`/`After=`
  plus a `multi-user.target.wants` symlink. Being `Requires`-held rather than
  `BindsTo`/`PartOf`, **once started it stayed up until an explicit stop or
  reboot** — a dependent VM stopping did not tear it down.
- An ownership marker `/run/workload-vm/bridge-managed` gated every NAT, dnsmasq
  and teardown step, so it only touched a bridge it created.

Subnet and DNS, however, were read **per-VM** from `[vm.network].subnet` /
`[vm.network].dns` and interpolated into that single shared unit. Two
consequences:

1. **Last-write-wins across VMs.** The last VM the generator processed defined
   the bridge for all of them — and given the `RemainAfterExit` lifecycle, the
   running bridge reflected whoever *started* first while the on-disk unit
   reflected whoever *generated* last. The two could silently disagree until a
   restart.
2. **The override never fully worked, even for one VM.** The bridge IP/CIDR and
   the NAT masquerade rule came from the override, but dnsmasq's `--dhcp-range`
   used the hardcoded `VM_DHCP_RANGE` (`192.168.200.100,199`). Overriding
   `subnet` to `10.100.0.0/24` put the bridge on `10.100.0.1` and masqueraded
   `10.100.0.0/24` while guests were handed `192.168.200.x` off the wrong subnet
   — no connectivity.

No shipped workload or example set either field. The feature was both unused and
broken.

## Decision

**Subnet and DNS for the managed bridge are host-level configuration, not
per-VM.**

- Remove `[vm.network].subnet` and `[vm.network].dns` from the per-VM schema.
- Introduce a single host-level source of truth consumed once by
  `generate_vm_bridge_service()`.
- Derive `--dhcp-range` from the configured subnet, so a non-default subnet works
  end to end.
- `[vm.network].bridge` stays per-VM: pinning a VM to an *operator-provided*
  bridge is a legitimate per-VM choice and already skipped
  `workload-bridge.service` entirely. Only the *managed* bridge's subnet and DNS
  are host-scoped.

## Rationale

The config granularity must match the resource granularity. The alternative —
validate consistency across VMs — was rejected: it preserves a per-VM field that
is unused and non-functional, adds cross-VM validation at generate time, and
still cannot reconcile the disk-vs-runtime disagreement the `RemainAfterExit`
lifecycle creates. Lifting to host level cost nothing to migrate and let the
DHCP-range fix fall out.

## Consequences

- Breaking schema change with no real-world impact.
- The dhcp-range-from-subnet fix made the managed bridge relocatable for the
  first time (e.g. off a `192.168.200.0/24` that clashes with the host LAN).
- Superseded in full by ADR 006: passt gives each VM its own re-originated
  identity, so there is no shared resource left to configure at either scope.
