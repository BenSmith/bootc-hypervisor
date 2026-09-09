#!/usr/bin/env python3
"""How QEMU enters a confined SELinux domain, and which policy modules ship.

Split out of vm.py, where this sat under a `# --- SELinux confinement ---`
header that had accumulated three other topics beneath it -- nft JSON payload
parsing, conntrack pressure, and the filter's element commands -- none of which
has anything to do with SELinux. A section header that names one of the four
things below it is worse than none: it tells a reader the block is about a
subject it has largely stopped being about.

Nothing here imports vm; vm imports this and re-exports every public name, so
no caller changed.

Installed to /usr/libexec/workloadctl/egress_selinux.py.
"""

import os

from vm_defs import VM_SOCKET_DIR


# QEMU runs as svirt_t (alias qemu_t), the domain the shipped policy already
# maintains for a hypervisor process hosting an untrusted guest. We deliberately
# do NOT author a wl_vm_t: svirt_t is a virt_domain and an mcs_constrained_type
# that already declares the entrypoints this needs, including
#   allow svirt_t qemu_exec_t:file entrypoint;
#   allow svirt_t passt_exec_t:file { entrypoint execute ... };
#   allow svirt_t swtpm_exec_t:file { entrypoint execute ... };
# so passt and swtpm transition to passt_t/swtpm_t automatically the moment QEMU
# is svirt_t, with no rules of ours.
#
# s0 with no categories: svirt_t is mcs_constrained and libvirt allocates a
# category pair per VM because all of its VMs share one uid. Ours each run as
# their own _wl-<name>, so DAC already provides the inter-VM separation MCS
# would buy — and categories on files are invisible to `ls -l` and produce EPERM
# that looks like nothing is wrong, a failure mode this project has been bitten
# by before. Categories stay available if uid separation ever stops sufficing.
VM_QEMU_TYPE = "svirt_t"
VM_QEMU_CONTEXT = f"system_u:system_r:{VM_QEMU_TYPE}:s0"

# The host-global policy delta VM confinement needs: a domain for the virtiofsd
# sidecar, and one grant to svirt_t that only a QEMU-native passt netdev needs.
# Installed by the RPM rather than shipped through the per-workload
# [security].selinux_policy bundle: nothing in it is per-workload, and N
# identical copies would race semodule while gated on a flag that has nothing to
# do with whether virtiofs works. See security/workload-vm.cil.
VM_SELINUX_MODULE = "workload-vm"
VM_SELINUX_CIL = "/usr/share/workloadctl/workload-vm.cil"

# The inspector's and the responder's domains, installed the same way and for
# the same reason. Named here rather than only in the spec because `diagnose`
# compares each loaded module against the source the RPM shipped: a module
# missing from that list is a domain whose policy can drift out from under a
# running host with nothing saying so, which is the failure the check exists
# for. They replaced workload-proxy, which the RPM's %post now removes.
VM_INSPECT_SELINUX_MODULE = "workload-inspect"
VM_INSPECT_SELINUX_CIL = "/usr/share/workloadctl/workload-inspect.cil"
VM_RESOLVE_SELINUX_MODULE = "workload-resolve"
VM_RESOLVE_SELINUX_CIL = "/usr/share/workloadctl/workload-resolve.cil"

# --- The label the QMP socket directory has to carry ---
#
# The type VM_SOCKET_DIR must carry, and the fcontext pattern the RPM's %post
# registers to give it that type. A confined QEMU cannot create a socket under
# /run's default var_run_t, so without this the guest dies before it binds QMP
# and the only symptom is a timeout that names nothing SELinux.
#
# Two spellings, both needed. svirt_var_run_t is an ALIAS: it is what the rule
# is written with (and what the policy and every doc call it), but the kernel
# stores the real name, so getfattr, `ls -Z` and matchpathcon all report
# qemu_var_run_t. A label comparison that knows only one of them is wrong half
# the time, which is why `diagnose`'s socket-label check accepts either.
VM_SOCKET_SELINUX_TYPE = "svirt_var_run_t"
VM_SOCKET_SELINUX_TYPE_REAL = "qemu_var_run_t"
VM_SOCKET_FCONTEXT_PATTERN = f"{VM_SOCKET_DIR}(/.*)?"


# The transition needs a wrapper, and only a wrapper. `SELinuxContext=` in the
# unit does NOT work: systemd execs from init_t and the policy has no
# init_t -> svirt_t transition, deliberately — libvirt reaches svirt_t through
# its own virtqemud_t. But the domain VM units run in today may do it:
#   allow unconfined_service_t virt_domain:process transition;
# so `runcon <context> qemu-system-x86_64` from workload-vm-notify succeeds with
# no local policy at all.
#
# runcon rather than a setexeccon() call in Python, for two reasons. lib/ has no
# third-party dependencies and the stdlib has no SELinux binding, so the
# alternative is a new python3-libselinux Requires for one call. And runcon
# execs the target in its own process, which scopes the pending exec context to
# the child by construction — setexeccon() in the parent would leave it armed
# for whatever that process execs next.
#
# runcon must exec QEMU DIRECTLY. The entrypoint above is on qemu_exec_t; a
# shell in between is bin_t and the transition is refused.
VM_RUNCON_BIN = "/usr/bin/runcon"

# Presence means selinuxfs is mounted, i.e. SELinux is enabled. Enforcing vs
# permissive is not consulted: permissive is exactly the mode an AVC harvest
# runs in, so the transition has to happen there too or the harvest measures the
# wrong domain. Only a *disabled* host skips it, where setexeccon() would fail
# and take QEMU down with it.
SELINUX_ENFORCE_PATH = "/sys/fs/selinux/enforce"


def selinux_enabled(root: str = "") -> bool:
    """Whether SELinux is enabled on this host (selinuxfs mounted)."""
    return os.path.exists(root + SELINUX_ENFORCE_PATH)


def qemu_launch_argv(qemu_cmd: list[str], *, enabled: bool | None = None,
                     runcon: str = VM_RUNCON_BIN) -> list[str]:
    """`qemu_cmd`, prefixed with runcon so QEMU enters svirt_t.

    Returns `qemu_cmd` unchanged when SELinux is disabled or runcon is missing,
    so a non-SELinux host still boots VMs — unconfined, as it was before ADR 006
    step 3. It is `workloadctl diagnose` that reports the difference; failing
    the start here would turn "this host has no SELinux" into "VMs do not run".
    """
    if enabled is None:
        enabled = selinux_enabled()
    if not enabled or not os.path.exists(runcon):
        return list(qemu_cmd)
    return [runcon, VM_QEMU_CONTEXT, *qemu_cmd]
