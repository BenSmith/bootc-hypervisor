#!/usr/bin/env python3
"""Generating the units for a VM workload.

Split out of generators/workload-generate, which generated both substrates
from one file and was therefore the file every change to either one touched.
The two halves share nothing: measured by AST across the whole entrypoint,
there is not one call from a VM function into a container function or back.
What they did share is in gen_common, and what is left in the entrypoint is
argv, main(), and the dispatch between the two.

`main` is the only caller here; the entrypoint imports the four entry points
it dispatches to and nothing else. Tests import THIS module rather than
reaching the same functions through the entrypoint, because a name reached
through a re-export cannot be patched at its source.

Installed to /usr/libexec/workloadctl/gen_vm.py.
"""


from config_parser import parse_volume_spec
from workload_lib import (
    GENERATED_BY, workload_state_dir, workload_data_dir, expand_volume_path,
    dq, uq, virtiofs_tags, systemd_escape_path,
)
from egress_policy import (
    VM_INSPECT_PORT_CLEARTEXT, VM_INSPECT_PORT_TLS, vm_uses_inspect,
    vm_uses_resolve, vm_inspect_logs_directory,
)
from egress_ca import vm_denial_dir, vm_leaf_dir
from vm import vm_inspect_cgroup_command, vm_inspect_cgroup_filter_command
from broker_config import (
    VM_BROKER_BIN, vm_uses_credentials, vm_broker_config_path,
    vm_broker_credential, vm_broker_hosts, vm_broker_runtime_directory,
    vm_broker_upstream_addresses, vm_host_resolver_addresses,
)
from vm_defs import (
    VM_REBOOT_EXIT_CODE, VM_GUEST_UID, VM_GUEST_AGENT_PORT, VM_SIDECAR_SLICE,
    vm_mac_address, parse_vm_port, find_ovmf_code, parse_memory_mib,
    VM_SOCKET_DIR,
)
from workload_addr import (
    VM_MGMT_SSH_PORT, VM_INSPECT_LISTENER_BIN, vm_management_address,
    vm_inspect_address, VM_RESOLVE_LISTENER_BIN, VM_RESOLVE_PORT,
    vm_resolve_address,
)
from unit_file import Unit
from gen_common import (
    services_dir, log_msg, _RunFileConfig, emitted_run_paths,
    generate_sysuser_config_vm, cgroup_directives, generate_setup_service,
    _external_host_path, _resource_overrides,
)


def generate_virtiofs_service(name: str, tag: str, host_path: str, user_name: str, uid: int,
                              after_mounts=(), announce_submounts: bool = True) -> str:
    """Generate a virtiofsd sidecar service for one virtiofs volume.

    The design this unit implements — the share's ownership model, why the
    daemon holds no capabilities, and what confines it instead — is
    docs/vm-virtiofs.md. The comments below carry the per-directive why.

    Note: the runtime socket directory (/run/workload-vm/{name}/) is owned by
    the main VM service (RuntimeDirectory + RuntimeDirectoryPreserve). Sidecars
    must not declare RuntimeDirectory or they would refcount-cleanup the dir
    on sidecar stop and yank the VM's qmp/console sockets out from under it.
    """
    runtime_dir = f"/run/workload-vm/{name}"
    socket_path = f"{runtime_dir}/virtiofs-{tag}.sock"
    home_dir = str(workload_state_dir(name))

    # ProtectHome= masks /home, /root and /run/user. [vm].volumes takes an
    # arbitrary host path, and one pointing into any of those cannot be both
    # masked and served — so take the hardening only where it costs nothing.
    protect_home = not any(
        host_path == p or host_path.startswith(p + "/")
        for p in ("/home", "/root", "/run/user"))

    # Every guest id lands on the host as the workload user. The `map` entry is
    # bidirectional, so the guest's own user reads its files back as itself; the
    # two squashes cover everything on either side of it, one-way.
    #
    # WHY NOT LET OTHER GUEST IDS THROUGH. Passthrough is the obvious reading of
    # "share a directory faithfully" — but the guest chooses those
    # ids, so passthrough means a guest can create host files owned by any uid
    # it names, root included, with any mode it likes. Verified on a live VM: a
    # guest planting a setuid-root binary in its share produced
    # `-rwsr-xr-x root root` on the host filesystem. The share sits in a 0700
    # workload-owned directory and nothing on the host execs from it, so it is
    # not directly exploitable — but `backup` captures data/, so the bit travels
    # in the archive to wherever it is restored, and anything that ever runs as
    # _wl-<name> and execs from the tree gets root. Squashing removes the
    # primitive rather than relying on those two facts staying true.
    #
    # What it costs: a multi-user guest no longer sees per-user ownership inside
    # the share, on the host OR in the guest — squash is one-way, so the reverse
    # lookup finds only the `map` entry and every squashed file reads back as
    # the guest's default user. That is the deliberate trade. These are
    # single-user appliance VMs; a workload that genuinely needs multi-user
    # sharing wants a data disk, which is a block device the guest formats and
    # owns outright.
    #
    # The ranges must PARTITION: virtiofsd rejects any entry whose source range
    # intersects one already added (soft_idmap::IdMap::do_push), so an overlap
    # is a start failure, not a precedence question. And the tail cannot reach
    # the top of the range — ranges are half-open and built with checked_add, so
    # ending at 2^32 overflows.
    #
    # ONE ID ESCAPES THE MAP, AND ONLY AN UNPRIVILEGED DAEMON MAKES THAT SAFE.
    # 4294967295 cannot be covered by any --translate-* entry (the overflow
    # above), and virtiofsd identity-maps anything unmapped rather than refusing
    # it (soft_idmap: "unmapped ranges default to identity mapping"). Its
    # credential switch skips only id 0 (`is_root()` is `== 0`), so for this id
    # it calls setresuid(-1, 4294967295, -1) — which the kernel reads as -1,
    # "leave it alone", and returns success. Whatever the euid already was is
    # what the file gets. Unprivileged that is the workload user, so the id
    # lands where every squashed id lands; at euid 0 a guest asking for that id
    # would plant a root-owned file. This is the sharpest reason the unit below
    # must stay unprivileged.
    squash_tail = (1 << 32) - 1 - (VM_GUEST_UID + 1)
    idmap = " ".join(
        f"--translate-{kind}=map:{VM_GUEST_UID}:{uid}:1 "
        f"--translate-{kind}=squash-guest:0:{uid}:{VM_GUEST_UID} "
        f"--translate-{kind}=squash-guest:{VM_GUEST_UID + 1}:{uid}:{squash_tail}"
        for kind in ("uid", "gid")
    )
    # --inode-file-handles=never overrides virtiofsd's default of `prefer`.
    # File handles (name_to_handle_at/open_by_handle_at) need CAP_DAC_READ_SEARCH
    # in the initial user namespace, which this daemon does not hold and cannot
    # acquire — so `prefer` can only fail and fall back. Measured: it fails
    # once at startup and virtiofsd disables handles for the rest of the run
    # ("File handles do not appear safe to use"), leaving a WARN in the journal
    # and one dac_read_search AVC per start that look like a policy bug and are
    # not. Asking for the fallback directly costs nothing and says nothing false.
    #
    # The trade the flag documents — handles keep fewer fds open — is why
    # LimitNOFILE= below is set rather than left at the default.
    # Submount announcement: virtiofsd flags each directory that is a mount
    # point on the host (ATTR_SUBMOUNT), and a guest kernel with virtio-fs
    # submount support answers by automounting it -- a second virtiofs mount,
    # its own superblock, its own st_dev, inheriting this mount's options.
    #
    # Without it a nested mount shares st_dev with the share around it, and two
    # files on opposite sides of the boundary can collide on (st_dev, st_ino) --
    # a real risk when the nested filesystem is CIFS with `serverino`, where the
    # inode numbers come from Samba and have never been coordinated with the
    # local ones underneath. Anything that uses that pair for identity mis-pairs
    # them: `rsync -a` and `tar` hardlink detection, `cp -a`, `find` loop
    # detection.
    #
    # BOTH FORMS ARE PASSED EXPLICITLY, and that is the point of this block.
    # virtiofsd's own default has moved: the C implementation shipped with qemu
    # announced nothing unless asked, while the Rust one (1.x, --help: "Tell the
    # guest which directories are mount points [default]") announces unless told
    # --no-announce-submounts. Emitting a flag only for the true case therefore
    # made announce_submounts=false unachievable -- it silently got the announced
    # behaviour anyway -- and would flip meaning again under a future default.
    # Naming the state we want in every unit costs one argument and pins it.
    #
    # Default true, matching current virtiofsd and every already-deployed
    # sidecar. The opt-out is for a guest whose kernel lacks submount support,
    # or one that cannot tolerate mounts it did not create appearing in
    # /proc/mounts; the collision above is the price it pays for that.
    submounts = (" --announce-submounts" if announce_submounts
                 else " --no-announce-submounts")
    virtiofsd_cmd = (
        f"/usr/libexec/virtiofsd "
        f"--socket-path={socket_path} "
        f"--shared-dir={dq(host_path)} "
        f"{idmap} "
        f"--cache=auto --sandbox=none --inode-file-handles=never{submounts}"
    )

    unit = Unit()
    unit.comment(f"virtiofsd sidecar for {name}/{tag}")
    unit.comment(GENERATED_BY)

    u = unit.section("Unit")
    u.set("Description", f"virtiofsd for {name}/{tag}")
    u.set("Requires", f"workload-{name}-setup.service workload-{name}.service")
    u.set("After", f"workload-{name}-setup.service")
    u.set("Before", f"workload-{name}.service")
    u.set("PartOf", f"workload-{name}.service")
    # The sidecar is what opens the host path, so the mount guard belongs here
    # rather than on the VM service. Same reasoning as the container units: an
    # unmounted filesystem would otherwise be shared into the guest as an empty
    # directory. PartOf= propagates the resulting failure to the VM.
    external = _external_host_path(host_path, name)
    if external is not None:
        u.add("RequiresMountsFor", uq(external))
    # ...but that guards the SHARE ROOT ONLY, and only when the root is out of
    # tree. A mount nested *below* an in-tree share -- `./home` with a CIFS
    # share at `./home/netmnt` -- is invisible to it: RequiresMountsFor= pulls
    # in the mounts along a path's prefix, never the ones underneath it, and
    # _external_host_path returns None for the in-tree root anyway. That share
    # is then handed to the guest with an empty directory where the nested
    # content should be.
    #
    # [vm].after_mounts is how the operator names those. It is DECLARATIVE
    # rather than discovered on purpose: this generator runs during early boot,
    # before a _netdev mount has had any chance to come up, so a walk of the
    # share for nested mountpoints would find nothing in exactly the boot where
    # the guard was needed, and would look correct every time it was tested by
    # hand afterwards.
    #
    # ORDERING ONLY -- After=, not RequiresMountsFor=. The stronger form implies
    # Requires=, and PartOf=workload-<name>.service propagates a sidecar failure
    # to the VM, so a hard edge here means the VM will not boot at all while the
    # remote filesystem is unreachable. What it would buy is closing a
    # sub-second window: a host mount made after the guest is up becomes visible
    # to the guest within about a second anyway (measured; it is the --cache=auto
    # entry timeout, and nothing latches the empty view). Trading VM
    # availability against that transient is a bad deal, so the edge stays weak.
    for mount_path in after_mounts:
        u.add("After", f"{systemd_escape_path(mount_path)}.mount")

    svc = unit.section("Service")
    # Type=exec: systemd marks the service active once virtiofsd exec()s,
    # without waiting for sd_notify. virtiofsd 1.x only sends READY after
    # QEMU connects, which deadlocks with Type=notify + Before=VM.service.
    svc.set("Type", "exec")

    # WHY THIS RUNS AS THE WORKLOAD USER, WITH NO CAPABILITIES AT ALL.
    #
    # virtiofsd serves each request under the requesting guest's uid/gid —
    # setresuid/setresgid per request — and that is what would demand
    # CAP_SETUID/CAP_SETGID, plus fowner/fsetid to carry a file's mode across the
    # switch. The id map above means it never happens: every guest id translates
    # to this one host uid, so `self.uid == current_uid` and the switch is not
    # attempted (passthrough/credentials.rs: `change_uid = !self.uid.is_root()
    # && self.uid != current_uid`). There is no caller to impersonate, so there
    # is nothing to be privileged for.
    #
    # The id map is therefore load-bearing for FUNCTION as much as for security:
    # if a change lets other guest ids through, this unit fails with EPERM on the
    # switch rather than quietly needing privilege back. That is the failure
    # direction to keep.
    #
    # Measured on a live VM under SELinux enforcing: CapPrm/CapEff/CapBnd all 0,
    # euid/egid the workload user, and a first-boot cloud-init completes with
    # /home/<user>/.ssh 0700 and authorized_keys 0600.
    svc.set("User", user_name)
    svc.set("Group", user_name)
    # Empty, not merely reduced: with no credential switch, nothing here wants a
    # capability. This is also why security/workload-vm.cil carries no capability
    # rule — SELinux cannot grant a capability the process does not hold.
    svc.set("CapabilityBoundingSet", "")
    svc.set("AmbientCapabilities", "")

    # DO NOT ADD NoNewPrivileges=yes (nor DynamicUser=yes, which implies it).
    #
    # It looks like the obvious next tightening and it breaks the unit outright,
    # with an error that points nowhere near the cause: exec fails 203/EXEC,
    # "Permission denied", on a 0755 binary. Under NNP the kernel refuses any
    # SELinux domain transition that is not *bounded* by the calling domain, and
    # wlvfsd_t is not bounded by init_t:
    #
    #   type=SELINUX_ERR op=security_bounded_transition seresult=denied
    #     oldcontext=system_u:system_r:init_t:s0
    #     newcontext=system_u:system_r:wlvfsd_t:s0
    #
    # systemd then retries as execute_no_trans, which is also denied. Setting
    # SELinuxContext= explicitly does not help — the bounded check is on the
    # transition, however it is requested. Making it work would mean a typebounds
    # declaration in security/workload-vm.cil, i.e. constraining wlvfsd_t to a
    # subset of init_t forever, to buy a no-op: the bounding set is already
    # empty, so there are no privileges left to gain.
    #
    # The seccomp-based options (PrivateDevices=, ProtectKernel*=,
    # RestrictSUIDSGID=, SystemCallFilter=, ...) are NOT affected, despite the
    # documentation's "requires NNP" phrasing: systemd only forces NNP for them
    # when the *manager* lacks CAP_SYS_ADMIN (exec-invoke.c
    # context_has_no_new_privileges), which is never true for a system service.
    # They are omitted here because they are untested against virtiofsd, not
    # because they cannot be used.
    svc.set("ProtectSystem", "strict")
    if protect_home:
        svc.set("ProtectHome", "yes")
    svc.set("ProtectProc", "invisible")
    svc.set("PrivateTmp", "yes")
    # ProtectSystem=strict makes the whole hierarchy read-only, /run included, so
    # both the share and the socket directory have to be named back.
    svc.set("ReadWritePaths", f"{uq(host_path)} {uq(runtime_dir)}")
    # virtiofsd asks for RLIMIT_NOFILE=1_000_000 (limits.rs DEFAULT_NOFILE) and
    # holds an fd per open guest file. Unprivileged it cannot raise its own hard
    # limit, so systemd — which still has the privilege at this point — raises it
    # before dropping. Without this the daemon logs a warning and quietly runs at
    # the login hard limit instead.
    svc.set("LimitNOFILE", "1000000")

    svc.set("Environment", f'"HOME={home_dir}"')
    # The socket and its lock file are recreated on every start, and a leftover
    # of either stops this unit dead. The pid file is the one that bites on
    # upgrade: virtiofsd opens it O_CREAT|O_WRONLY mode 0600 (util.rs
    # write_pid_file), so a root-owned one — which is what any host upgraded from
    # a workloadctl that ran this sidecar as root still has in /run — is
    # unopenable by the workload user. The daemon then exits with "Error creating
    # pid file ... Permission denied", which reads as a policy or SELinux fault rather
    # than a stale file. Removing it here is safe against a live peer: virtiofsd
    # takes an flock and re-checks the inode precisely so a racing unlink is
    # handled. Not prefixed with `-`: if the removal genuinely fails, rm's error
    # is the diagnostic we want in the journal.
    svc.add("ExecStartPre",
            f"/bin/rm -f {dq(socket_path)} {dq(socket_path + '.pid')}")
    svc.set("ExecStart", virtiofsd_cmd)
    # Wait for virtiofsd to create the socket before QEMU starts.
    # virtiofsd creates the socket before blocking on accept(), so this
    # resolves the ordering dependency without the sd_notify deadlock.
    svc.set("ExecStartPost",
            f"/bin/sh -c 'until test -S {socket_path}; do sleep 0.1; done'")
    svc.set("StandardOutput", "journal")
    svc.set("StandardError", "journal")

    return unit.render()


def build_passt_netdev(name: str, uid: int, net_cfg: dict, mac: str) -> str:
    """Build the `-netdev passt,...` argument for a VM workload (ADR 006).

    passt terminates the guest's stack in userspace and re-originates its
    traffic as ordinary host sockets owned by this workload's own uid, which is
    what makes `meta skuid` per-VM egress policy possible. QEMU 10.2 has a
    native passt netdev, so there is no separate process to launch and no
    socket to wire.

    The host-derived half — the per-family DNS options — is NOT here. It is
    `${WL_PASST_DNS}`, written at unit start by libexec/workload-vm-netdev,
    because this generator runs Before=basic.target where there is no default
    route to derive an address from. See that script's module docstring.
    """
    props = [f"passt,id=net0,mac={mac}"]

    # Two classes of inbound, and they are genuinely different.
    #
    # 1. MANAGEMENT — `workloadctl exec` / `shell`. Bound to this workload's own
    #    127.128.x.y address at a fixed port, so it is never routable and never
    #    configurable. Derived from the uid, so there is no registry and no
    #    collision.
    # 2. PUBLISHED — declared by the operator, bound where they say, following
    #    the container convention ports = ["8080:80"]. Managed-bridge VMs had no
    #    port publishing at all, so this is new capability, not a migration.
    mgmt_addr = vm_management_address(uid)
    tcp_ports = [f"{mgmt_addr}/{VM_MGMT_SSH_PORT}:22"]
    udp_ports = []
    for spec in net_cfg.get("ports", []):
        bind_addr, host_port, guest_port, proto = parse_vm_port(spec)
        # passt's spelling is [addr/]host:guest; ours is [addr:]host:guest.
        forward = f"{bind_addr}/" if bind_addr else ""
        forward += f"{host_port}:{guest_port}"
        (udp_ports if proto == "udp" else tcp_ports).append(forward)
    # One key per entry, NOT a comma-joined value. tcp-ports/udp-ports are
    # list-typed netdev properties (qapi/net.json:224-225), and -netdev passt
    # goes through the traditional QemuOpts path — netdev_is_modern() returns
    # true only for stream/dgram — where the opts visitor builds a list from
    # *repeated occurrences of the same key* (qapi/opts-visitor.c:74-77). A
    # comma-joined value would make QEMU read the second entry as a bare
    # unknown option and refuse to start.
    props += [f"tcp-ports={spec}" for spec in tcp_ports]
    props += [f"udp-ports={spec}" for spec in udp_ports]

    # What the guest can reach on the host. `--map-host-loopback none` closes
    # the one that bites: passt's default maps the host's loopback onto the
    # gateway address, and loopback-bound services are exactly the ones that
    # skip authentication *because* they are not reachable off-box. The host's
    # default-route address is unreachable structurally — the guest is assigned
    # that same address, so traffic to it never leaves the guest's own stack —
    # and --map-guest-addr, which would undo that shadowing, has no default.
    props.append("map-host-loopback=none")

    # Suppress the resolv.conf search list, which is otherwise advertised over
    # both DHCP and NDP and leaks internal domain names. Host-independent, so
    # unlike the DNS options it belongs here rather than in the prestart. This
    # is passt-mode-specific: pasta forces no_dhcp_dns_search on, passt does
    # not, so the container side of this project has never been exposed to it.
    props.append("search=none")

    # Pin egress to one host interface, if asked. Per-VM egress scoping with no
    # nftables at all: a VM can be made structurally unable to originate on a
    # management VLAN. Composes with the uid-keyed policy rather than replacing
    # it. Both families, since the key names an interface, not an address.
    outbound_if = net_cfg.get("outbound_if")
    if outbound_if:
        props.append(f"outbound-if4={outbound_if}")
        props.append(f"outbound-if6={outbound_if}")

    # Host-derived DNS, spliced in at start time. ${VAR} interpolates without
    # word-splitting, which is what this needs — the whole netdev is one argv
    # element. The helper always writes a non-empty value, so this never
    # expands to a dangling comma.
    props.append("${WL_PASST_DNS}")

    return "-netdev " + ",".join(props)


def generate_vm_inspect_socket(config, user_name: str, uid: int,
                               arming_helper: str = "workload-vm-inspect") -> str:
    """Generate the socket unit for one workload's transparent egress
    inspector -- VM or container (P1-9): the unit shape is substrate-generic
    (uid-derived addressing, name-keyed ordering), so this function is reused
    verbatim for both. `arming_helper` is the one substrate-specific fact --
    which script's `up`/`down` the ExecStartPre/ExecStopPost invoke, since the
    VM and container arming scripts read the config's [vm.network] vs
    [network] table respectively (workload-vm-inspect vs
    workload-container-inspect). D6's "the binary does not change" is about
    the LISTENER (workload-vm-inspect-listener, ExecStart below in
    generate_vm_inspect_service) -- the arming helper is not that binary.

    The listener is a systemd socket unit, not a process that opens its own
    socket: the workload must not be able to start before the listener
    exists, and a `.socket` ordered `Before=` it makes early connections
    queue in the kernel rather than be refused. The four ListenStream= lines
    are the whole of what the socket binds — both families, both the
    cleartext and the TLS listener port — so a dial to 80 or one to 443 is
    translated onto a port that is already bound before the workload's
    first packet can arrive.
    """
    name = config["workload"]["name"]
    # The uid is passed in, never looked up. On a first enable this runs
    # BEFORE systemd-sysusers has created _wl-<name> -- the generator has only
    # just written the sysusers config -- so a getpwnam here raises KeyError
    # and takes the whole VM workload down with it. The caller already holds
    # the allocated uid; that is the only value that exists this early.
    addr = vm_inspect_address(uid)

    unit = Unit()
    unit.comment(f"egress inspector socket for {name}")
    unit.comment(GENERATED_BY)

    u = unit.section("Unit")
    u.set("Description", f"Transparent egress inspection socket for {name}")
    # Ordered after the setup service, exactly as the virtiofsd sidecars are,
    # for the reason generate_setup_service's docstring gives: the user must be
    # resolvable before any ExecStartPre runs. This socket's ExecStartPre calls
    # workload-vm-inspect up, whose second statement is a getpwnam of
    # _wl-<name>, and the user does not exist until setup.service has run --
    # creation is deferred to it and /run is tmpfs, so nothing survives a boot
    # to pre-create it. The VM unit's After= orders the VM behind all of its
    # prerequisites but does NOT order them against each other, so without this
    # the socket and setup.service start concurrently and the socket usually
    # wins: getpwnam raises, ExecStartPre fails, the socket fails, and the VM's
    # Requires= on the socket means the VM does not boot at all.
    u.set("Requires", f"workload-{name}-setup.service")
    u.set("After", f"workload-{name}-setup.service")
    # The VM is the hard prerequisite, not the other way round: an inspector
    # with no guest behind it is a listener that logs nothing. PartOf= so the
    # socket stops with the VM (its ExecStopPost is what removes the armed
    # addresses and elements — a socket that outlived the VM would leave a
    # redirect pointing at a listener with nothing behind it).
    u.set("Before", f"workload-{name}.service")
    u.set("PartOf", f"workload-{name}.service")

    sock = unit.section("Socket")
    # The address-add lives on the SOCKET unit, not the service, because the
    # socket binds its ListenStream= when the socket unit starts — which is
    # before the service ever runs. An ExecStartPre on the service is too late
    # by one unit: the DNAT target address would not exist when the bind is
    # attempted. `+` runs it as root; not `-` — an address that failed to add
    # leaves a socket bound to nothing that no guest can reach.
    sock.add("ExecStartPre",
             f"+/usr/libexec/workloadctl/{arming_helper} up {dq(name)}")
    # Tolerant, unlike the prestart: the elements and addresses are
    # legitimately absent whenever the start failed before arming them, so the
    # stop must not block. The shared dummy link and the advertised address are
    # never torn down — the helper does not touch them, for the reason its
    # own docstring gives.
    sock.add("ExecStopPost",
             f"-+/usr/libexec/workloadctl/{arming_helper} down {dq(name)}")
    # Four listener ports, both families, cleartext and TLS. The values come
    # from the T4 derivation (vm_inspect_address) and the port constants —
    # never a literal. The v6 form brackets the address so it is not parsed as
    # the scope-id separator.
    sock.add("ListenStream", f"{addr.v4}:{VM_INSPECT_PORT_CLEARTEXT}")
    sock.add("ListenStream", f"{addr.v4}:{VM_INSPECT_PORT_TLS}")
    sock.add("ListenStream", f"[{addr.v6}]:{VM_INSPECT_PORT_CLEARTEXT}")
    sock.add("ListenStream", f"[{addr.v6}]:{VM_INSPECT_PORT_TLS}")
    # One service instance, not one per connection: the listener is a single
    # long-lived process, and Accept=no is what makes the trigger limit below
    # the meaningful knob. Set explicitly rather than inherited.
    sock.set("Accept", "no")
    # Accept=no silently lowers systemd's trigger-limit default to 20 per 2s
    # (not 200), and hitting it fails the socket unit PERMANENTLY until it is
    # restarted — reachable by exactly the inspector-fails-to-start case this
    # unit of work deliberately creates. Set both explicitly, so a failed
    # start is a transient slowdown the service's own Restart= recovers from,
    # not an outage that needs an operator.
    sock.set("TriggerLimitIntervalSec", "2s")
    sock.set("TriggerLimitBurst", "200")
    # Deliberately NOT FreeBind=yes. FreeBind would bind an address that does
    # not exist, which converts a loud failure (the socket unit fails, the VM's
    # hard prerequisite fails, the operator gets a message naming the unit)
    # into a silent blackhole (everything starts, the guest reaches nothing,
    # diagnose says healthy): a DNAT whose target is on no interface is dropped
    # by the kernel regardless of whether anything bound it. Fail at bind.
    # The address-add above is the mechanism; there is no belt worth adding
    # behind it.

    return unit.render()


def _harden_vm_sidecar(svc, name: str, *, families: str, tasks_max: int,
                       memory_max: str, extra_rw: tuple = ()) -> None:
    """The sandbox both egress sidecars run in.

    These two processes are the ones ADR 008 names as the cost of the design:
    code parsing hostile guest input, on the path for all HTTP and HTTPS, and
    from a later rung holding a CA key. They were shipped confined by SELinux
    alone, which is one mechanism where the virtiofsd sidecar three functions
    up carries two -- and the sidecar's confinement was argued, while the
    absence here was not argued anywhere.

    DO NOT ADD NoNewPrivileges=yes (nor DynamicUser=yes, which implies it).
    Both units reach their domain through a `#!` entrypoint transition from
    init_t, and under NNP the kernel refuses a transition that is not bounded
    by the calling domain -- which fails the exec with a bare 203/EXEC that
    points nowhere near the cause. The generate_vm_virtiofs_service comment
    carries the measurement and the audit record; it applies here unchanged.

    ProtectSystem=strict makes the whole hierarchy read-only, /run included, so
    the workload's socket directory is named back: it holds the policy document
    these read at start and the status document they replace every 30 seconds.
    The directory is created by workload-<name>-setup.service, which both units
    Requires= and are ordered After=, so it exists by the time this applies.

    `extra_rw` is how the inspector names its leaf caches, and /var being
    inside "the whole hierarchy" is the only reason it exists. Without it every
    mint fails with EROFS on the cache directory, the guest's connection is
    reset, and the journal says NOTHING -- the mint
    raised an OSError from outside the minter's own try block and the
    per-connection handler swallows OSError by design. A warm cache hid it
    completely, so the failure was "the first request to any host fails and the
    second succeeds", which reads as a network fault rather than a sandbox one.
    The CA directory is deliberately NOT here: the inspector reads it and must
    never rewrite it, which is the same split its two SELinux types make.

    The ExecStartPre/ExecStopPost lines that arm the cgroup exemptions are
    prefixed `+`, and systemd exempts those from the sandboxing options here --
    which is what lets nft keep working while the listener itself runs inside
    all of this.
    """
    # Empty, not merely reduced. Neither process binds a privileged port: both
    # take their listeners from their socket unit, which is the whole reason
    # the socket units exist. Nothing else here wants a capability.
    svc.set("CapabilityBoundingSet", "")
    svc.set("AmbientCapabilities", "")

    svc.set("ProtectSystem", "strict")
    svc.set("ProtectHome", "yes")
    svc.set("ProtectProc", "invisible")
    svc.set("PrivateTmp", "yes")
    svc.set("ReadWritePaths",
            " ".join([uq(f"{VM_SOCKET_DIR}/{name}")]
                     + [uq(str(path)) for path in extra_rw]))

    # The families each one actually opens, so a code path that grew a socket
    # nobody expected fails loudly instead of reaching the network. AF_UNIX and
    # AF_NETLINK are not decoration on the inspector: glibc's getaddrinfo
    # enumerates interfaces over netlink and talks to nscd or resolved over a
    # unix socket, and losing either turns every upstream dial into `upstream
    # unreachable` -- a policy gap wearing a network error's clothes.
    svc.set("RestrictAddressFamilies", families)

    # A ceiling on threads and memory, because the connection ceiling inside
    # the listener is a number this process chooses and these are numbers it
    # cannot. A process that has lost track of either takes the host down with
    # it otherwise; here it is restarted by its own Restart=on-failure and
    # re-triggered by its socket.
    svc.set("TasksMax", str(tasks_max))
    svc.set("MemoryMax", memory_max)


def generate_vm_inspect_service(config, user_name: str) -> str:
    """Generate the service unit for one VM's transparent egress inspector.

    Socket-activated by the matching .socket: the kernel hands the listener its
    accepted connection when the guest first dials. It runs as _wl-<name> so
    the inspector's own traffic carries the workload's uid, which is what the
    two cgroup exemptions below key on.

    The two cgroup elements are armed and removed HERE, not by the socket's
    helper: an element resolves to a cgroup id at add time and systemd makes a
    fresh cgroup on every start, so the add belongs to the unit that owns the
    cgroup (its ExecStartPre) and the remove to the point at which the path
    still resolves to the id being retired (its ExecStopPost). At the moment the
    socket's ExecStartPre runs, the service has not started and its cgroup does
    not exist, so the socket cannot arm these. Both or neither: the redirect
    exemption (wl_inspect_cg, proxy table) without the egress exemption
    (wl_egress_cg, filter table) is an inspector that redirects its own dials
    into itself; the egress exemption without the redirect exemption is one
    whose upstream traffic is caught by the default-deny drop. Both missing is
    both failures at once.
    """
    name = config["workload"]["name"]

    unit = Unit()
    unit.comment(f"egress inspector service for {name}")
    unit.comment(GENERATED_BY)

    u = unit.section("Unit")
    u.set("Description", f"Transparent egress inspector for {name}")
    # The same ordering as the socket, for the same reason one step later: this
    # unit carries User=_wl-<name>, which systemd must resolve before it can
    # execute anything. Socket activation means it starts long after boot in
    # practice, so this is the lower-risk half of the pair -- but leaving the
    # two asymmetric would invite a reader to conclude the socket's ordering
    # was the accident.
    u.set("Requires", f"workload-{name}-setup.service")
    u.set("After", f"workload-{name}-setup.service")
    # Before= the VM is the socket's job, not this service's: the service is
    # pulled in by the socket (which the ladder orders Before= the VM), so a
    # Before= here would be redundant and would misstate who owns the
    # ordering. What this unit owns is that it STOPS with the VM.
    # PartOf=, not Requires= in the other direction: a socket-activated process
    # that survived a VM restart would hold the previous inspect.json in memory
    # and keep enforcing it while the VM runs the new one. PartOf= is what
    # makes the service actually stop with the VM, which is what makes the
    # recovery path (an edited list applies on a plain restart) work.
    u.set("PartOf", f"workload-{name}.service")

    svc = unit.section("Service")
    # Socket activation: no Type= is needed; systemd considers the unit active
    # the instant the process it execs is running, and the listener has no
    # readiness protocol the generator would otherwise have to wait on.
    svc.set("User", user_name)
    svc.set("Group", user_name)
    # Pinned, NOT taken from [resources].slice: the two cgroup exemptions
    # this unit arms are `socket cgroupv2 level 2`
    # matches, so the cgroup path has to be exactly two components — a nested
    # custom slice would deepen it and both matches would silently stop firing,
    # dropping the inspector's own traffic (the redirect side into itself, the
    # egress side into the default-deny drop). The inspector is not the
    # payload; resource control belongs on the VM.
    svc.set("Slice", VM_SIDECAR_SLICE)
    # Arm BOTH cgroup exemptions before the listener starts. `+` runs them as
    # root (nft needs the capability); not `-` — an exemption that failed to
    # install leaves a healthy-looking inspector that reaches nothing or dials
    # into itself. Both lines, always: one missing is one of the two failures
    # the docstring names. Each argv token is quoted with dq (the systemd-Exec
    # literal-token helper), not a bare join: the `inet workload_proxy` table
    # and the cgroup path each carry a space that a bare join would split, and
    # dq is the repo's own quoting for Exec lines, not shell quoting.
    for cmd in (
        vm_inspect_cgroup_command(name, "add"),
        vm_inspect_cgroup_filter_command(name, "add"),
    ):
        svc.add("ExecStartPre",
                "+" + " ".join(dq(a) for a in cmd))
    # The workload name is an argument, not something the listener derives.
    # It is socket-activated with four identically-named fds, so there is
    # nothing on the socket to recover it from, and the alternative -- reading
    # it back out of getpwuid(geteuid()) -- would make the listener's identity
    # depend on the _wl- naming convention instead of on the unit it was
    # generated for. It is what the listener resolves its policy path from.
    svc.add("ExecStart", f"{VM_INSPECT_LISTENER_BIN} {dq(name)}")
    # Remove both exemptions on stop, kill and failure. ExecStopPost so a
    # killed or failed inspector still withdraws them; `-+` tolerant because
    # the elements are legitimately absent when the start failed before
    # arming them. Both lines, always -- but NOT because a leftover would
    # exempt the wrong process. It would not: the docstring above is the
    # governing fact, and it cuts both ways. An element resolves to a cgroup
    # ID at add time, kernfs IDs are not reused, and systemd makes a fresh
    # cgroup on every start -- so an element left behind names an ID nothing
    # will ever hold again and matches no packet. It is inert, unlike every
    # uid-keyed element this design has, where the uid IS reissued and a
    # leftover is armed for whoever gets it next.
    #
    # What a leftover costs is the set growing by two per unclean stop for the
    # life of the boot, and an operator reading `nft list set` being unable to
    # tell a live exemption from a dead one. Stated as hygiene rather than as
    # a security property, because the removal is not always POSSIBLE -- the
    # delete names the cgroup path, and once the service is gone the path does
    # not resolve. This is the only moment it does, which is the whole reason
    # the remove lives here and not on the socket's helper. See
    # workload-vm-inspect's `down`, which cannot do it and says so.
    for cmd in (
        vm_inspect_cgroup_command(name, "delete"),
        vm_inspect_cgroup_filter_command(name, "delete"),
    ):
        svc.add("ExecStopPost",
                "-+" + " ".join(dq(a) for a in cmd))
    svc.blank()
    # 128 connections is MAX_CONNECTIONS in the listener, one thread each, plus
    # the accept loop and a little room; a listener that has lost track of its
    # own ceiling stops here instead of at the host's. The memory number is
    # generous against the work: 128 relays at a 64 KiB buffer each direction
    # is single-digit megabytes on top of the interpreter.
    _harden_vm_sidecar(svc, name,
                       families="AF_INET AF_INET6 AF_UNIX AF_NETLINK",
                       tasks_max=192, memory_max="512M",
                       extra_rw=(vm_leaf_dir(workload_state_dir(name)),
                                 vm_denial_dir(workload_state_dir(name))))
    svc.blank()
    svc.add("StandardOutput", "journal")
    svc.add("StandardError", "journal")
    svc.blank()
    # Where the PER-REQUEST RECORD goes, which is NOT the journal above. The
    # two lines are different documents with different readers: the journal
    # carries the decision and the remedy, and the record carries what the
    # guest actually asked for -- paths, and query strings that can carry a
    # credential outright. vm.py's VM_INSPECT_RECORD_ROOT comment has the
    # argument; the modes are the access decision.
    #
    # LogsDirectory= rather than a mkdir of ours, for three things at once:
    # systemd creates it as User= (so the listener can recreate the file after
    # a rotation, which the logrotate snippet's `nocreate` requires), recreates
    # it if an operator deletes it, and -- the part that is easy to miss --
    # adds it to the unit's writable set under ProtectSystem=strict with no
    # ReadWritePaths= entry of ours. See _harden_vm_sidecar's `extra_rw`
    # comment for what the absence of that costs: EROFS, swallowed by the
    # per-connection OSError handler, presenting as a network fault.
    svc.add("LogsDirectory", vm_inspect_logs_directory(name))
    # 0700, not the 0755 systemd would default to. Root and the workload uid,
    # nobody else -- the whole reason the record is not in a journal.
    svc.add("LogsDirectoryMode", "0700")
    svc.blank()
    # The socket's trigger limit is a transient slowdown by design; the service
    # still needs its own restart policy so a failed listener that the socket
    # re-triggers actually comes back rather than the socket giving up.
    svc.add("Restart", "on-failure")
    svc.add("RestartSec", "5s")

    return unit.render()


def generate_vm_resolve_socket(config, user_name: str, uid: int) -> str:
    """Generate the socket unit for one VM's synthesising DNS responder.

    A socket unit for ONE reason: port 53 is privileged and the responder runs
    as _wl-<name>, so the bind has to happen in PID 1 and be handed over. It
    borrows nothing else from the inspector's socket unit -- and specifically
    there is NO ExecStartPre address-add here, which is the difference a reader
    coming from generate_vm_inspect_socket will look for.

    The kernel treats all of 127/8 as local on `lo`, so the responder's address
    needs no assignment: binding 127.130.1.4 succeeds with nothing
    configured. A `workload-vm-resolve up` twin adding a /32 would be a no-op, and worse, it would invent an address whose absence the inspector's
    fail-at-bind argument would then appear to depend on. There is likewise no
    FreeBind= question to answer, and no teardown that would make the presence
    of an address mean a running process.

    Both transports. Answers do not normally set the truncate bit -- a
    synthesised answer is one record -- but clients open TCP connections for
    their own reasons, and a UDP-only responder leaves those hanging with
    nothing to diagnose from.
    """
    name = config["workload"]["name"]
    # The uid is passed in, never looked up, for the reason
    # generate_vm_inspect_socket gives: on a first enable this runs before
    # systemd-sysusers has created _wl-<name>.
    address = vm_resolve_address(uid)

    unit = Unit()
    unit.comment(f"synthesising DNS responder socket for {name}")
    unit.comment(GENERATED_BY)

    u = unit.section("Unit")
    u.set("Description", f"Synthesising DNS responder socket for {name}")
    # Ordered after setup.service like the inspector's pair, one step weaker in
    # what it needs: this socket has no ExecStartPre and so no getpwnam of its
    # own, but the service it triggers carries User=_wl-<name>, and leaving the
    # socket unordered would invite a reader to conclude the inspector's
    # ordering was the accident rather than the rule.
    u.set("Requires", f"workload-{name}-setup.service")
    u.set("After", f"workload-{name}-setup.service")
    # The guest's first query can arrive as soon as the VM runs, so the socket
    # is bound before it; PartOf= so it stops with the VM rather than lingering
    # as a nameserver for a guest that is gone.
    u.set("Before", f"workload-{name}.service")
    u.set("PartOf", f"workload-{name}.service")

    sock = unit.section("Socket")
    # Both transports on the workload's own loopback address. IPv4 only: there
    # is deliberately no v6 responder plane (§9 rejects one on cost), and a v6
    # plane on `lo` would not be a substitute anyway -- the shipped `oif lo
    # accept` would make it reachable from every workload on the host, which is
    # the one property 127/8's unreachability from the guest is providing.
    sock.add("ListenDatagram", f"{address}:{VM_RESOLVE_PORT}")
    sock.add("ListenStream", f"{address}:{VM_RESOLVE_PORT}")
    # One long-lived process, not one per connection -- and with Accept=no the
    # trigger limit below is the meaningful knob. Set explicitly.
    sock.set("Accept", "no")
    # Accept=no silently lowers systemd's trigger-limit default to 20 per 2s,
    # and hitting it fails the socket unit PERMANENTLY until something restarts
    # it. A guest boot is a burst of lookups; 20 is inside what one `dnf
    # makecache` costs. Both values explicit, for the reason the inspector's
    # socket sets them.
    sock.set("TriggerLimitIntervalSec", "2s")
    sock.set("TriggerLimitBurst", "200")

    return unit.render()


def generate_vm_resolve_service(config, user_name: str) -> str:
    """Generate the service unit for one VM's synthesising DNS responder.

    Socket-activated, and it never binds: the program refuses to open a socket
    of its own, because port 53 is privileged and this process is not -- a
    fallback bind would be a listener on some other port that nothing forwards
    to, which is a working responder no guest can reach.

    No cgroup exemptions here, unlike the inspector's service. Those exist
    because the inspector ORIGINATES traffic that would otherwise be redirected
    into itself or caught by the default-deny drop; the responder originates
    none at all -- it has no upstream socket, which is the property that makes
    DNS exfiltration absent rather than filtered. There is nothing to exempt.
    """
    name = config["workload"]["name"]

    unit = Unit()
    unit.comment(f"synthesising DNS responder service for {name}")
    unit.comment(GENERATED_BY)

    u = unit.section("Unit")
    u.set("Description", f"Synthesising DNS responder for {name}")
    u.set("Requires", f"workload-{name}-setup.service")
    u.set("After", f"workload-{name}-setup.service")
    # PartOf=, not Requires= in the other direction, for the reason the
    # inspector's service gives: a socket-activated process that survived a VM
    # restart would keep answering from the previous run's document while the
    # VM runs the new one. The recovery contract is that an edited config
    # applies on a restart, and this is what makes that true.
    u.set("PartOf", f"workload-{name}.service")

    svc = unit.section("Service")
    svc.set("User", user_name)
    svc.set("Group", user_name)
    # Placement, not policy. The inspector pins this slice because two
    # `socket cgroupv2 level 2` matches depend on the path being exactly two
    # components; nothing keys on this unit's cgroup, so the pin here only
    # keeps the responder out of the VM's own resource accounting. Stated so a
    # later reader does not conclude the inspector's pin is decorative.
    svc.set("Slice", VM_SIDECAR_SLICE)
    # The workload name is an argument, not something the responder derives:
    # it is socket-activated with two identically-named fds, so there is
    # nothing on the socket to recover it from. It is what the responder
    # resolves its answer document's path from.
    svc.add("ExecStart", f"{VM_RESOLVE_LISTENER_BIN} {dq(name)}")
    svc.blank()
    # Narrower than the inspector on both axes, and the address families are
    # the load-bearing half: this program must contain no call that could
    # consult a resolver, and it opens no socket of its own at all -- its two
    # listeners are handed to it. AF_NETLINK is absent for that reason, so a
    # getaddrinfo that appeared here would fail at the socket rather than
    # quietly reaching a nameserver. One process, one loop: 16 tasks is slack.
    _harden_vm_sidecar(svc, name, families="AF_INET AF_UNIX",
                       tasks_max=16, memory_max="128M")
    svc.blank()
    svc.add("StandardOutput", "journal")
    svc.add("StandardError", "journal")
    svc.blank()
    svc.add("Restart", "on-failure")
    svc.add("RestartSec", "5s")

    return unit.render()


def generate_vm_broker_service(config, uid: int, *, before: str = None,
                               hosts=None, upstream=None) -> str:
    """Generate the credential broker instance for one workload.

    Substrate-neutral through three keyword parameters, on the same terms as
    generate_vm_inspect_socket/_service (D6): nothing in the unit below is
    VM-specific, so the container branch is a call site rather than a second
    generator. `before` is the unit this one must be ordered ahead of,
    `hosts` the (host, credential) pairs, `upstream` the addresses those
    hosts resolve to. Omitted, all three take their VM values.

    P2-3: `before` exists because the VM default is WRONG for a container in
    pod/bridge mode. There the umbrella carries `After=` its member services,
    so `Before=workload-<name>.service` orders the broker after every
    container has already started -- the same hole the inspector arming was
    moved off the umbrella for (see _head_unit). The container branch passes
    the pod/net head unit, which is the one workload-level unit ordered ahead
    of the members.

    Modelled on the host-wide agent-broker.service this replaces -- deleted in
    the same rung, so read it from git history if the derivation matters -- and
    NOT on _harden_vm_sidecar. The two sandboxes differ in the one directive
    that matters most here: this unit is DynamicUser=yes, and that is the whole
    of ADR 007's protection. The inspector runs as _wl-<name>, the uid QEMU runs
    as, so a guest escape obtains everything that uid can read; the broker's
    dynamic uid sits at 61184-65519, disjoint from the workload range, and the
    credential is only ever decrypted into ITS tmpfs. Give this unit
    User=_wl-<name> "for consistency" and the design's central claim is gone.

    That disjointness is also why NoNewPrivileges=yes is safe here and is
    refused three functions up: the sidecars reach an SELinux domain through an
    entrypoint transition that NNP forbids, and this program has no domain of
    its own to transition into.

    A full unit per workload rather than a template or a drop-in, for a reason
    that is structural: the number of LoadCredentialEncrypted= lines varies with
    the workload (one per declared credential), a @.service cannot carry a
    variable number of directives, and a drop-in has no per-instance base to
    attach to. Being an ordinary generated unit also buys PartOf=, ordering,
    teardown and `drift` coverage with no special-casing -- and drift coverage
    is not decoration on a unit whose content decides which credential goes to
    which host.
    """
    name = config["workload"]["name"]
    if before is None:
        before = f"workload-{name}.service"
    if hosts is None:
        hosts = vm_broker_hosts(config)
    if upstream is None:
        upstream = vm_broker_upstream_addresses(config)

    unit = Unit()
    unit.comment(f"credential broker instance for {name}")
    unit.comment(GENERATED_BY)

    u = unit.section("Unit")
    u.set("Description", f"Credential broker for {name}")
    # The RPM's copy, not a checkout: a unit on a host cannot usefully cite a
    # path that exists only on the machine it was written on.
    u.set("Documentation", "file:/usr/share/doc/workloadctl/agent-broker.md")
    u.set("Requires", f"workload-{name}-setup.service")
    u.set("After", f"workload-{name}-setup.service")
    # Stated from both ends, like the inspector socket and for the same reason:
    # Before= orders the broker ahead of the VM, and the VM's own Requires=/
    # After= is what makes its start wait. A later reader who deletes one side
    # leaves the other direction's ordering rather than nothing.
    u.set("Before", before)
    # PartOf=, so the instance stops with the workload that owns it. Lifecycle
    # tied to the VM and not to `systemctl enable`: the shipped host-wide unit
    # was deliberately not enabled because a broker with no config is a restart
    # loop, and an instance generated FROM a config that exists cannot fail that
    # way.
    u.set("PartOf", f"workload-{name}.service")

    svc = unit.section("Service")
    svc.set("Type", "exec")
    # The config is written into the unit's own runtime directory, by the unit,
    # at every start (D2). systemd creates the leaf as the DynamicUser at 0700
    # and removes it on stop, so the file is readable by the broker, unreadable
    # by the workload uid, and gone when the broker is -- no chown of ours, and
    # no way to serve the previous boot's credential set.
    svc.set("RuntimeDirectory", vm_broker_runtime_directory(name))
    svc.set("RuntimeDirectoryMode", "0700")
    # NOT `+` prefixed. This runs unprivileged, as the instance's own dynamic
    # user, which is what makes the file it writes owned by that user; it needs
    # no privilege, because everything it reads (the workload TOML, the passwd
    # db) is world-readable and the only thing it writes is $RUNTIME_DIRECTORY.
    # And not `-` either: a broker started against a stale or missing config is
    # a broker serving the wrong credentials or none.
    svc.add("ExecStartPre",
            f"/usr/libexec/workloadctl/workload-vm-broker config {dq(name)}")
    svc.add("ExecStart", f"{VM_BROKER_BIN} {dq(str(vm_broker_config_path(name)))}")
    svc.blank()
    # One line per DECLARED credential, not per credential-backed host: two
    # hosts may share one, and loading it twice under one id is an error.
    # `<seal name>:<path>` -- the id is the name the blob was sealed under, so a
    # unit pointing at another workload's file gets a decrypt failure at start
    # rather than that workload's key, and it is also the filename the broker
    # finds under $CREDENTIALS_DIRECTORY.
    seen_credentials = []
    for _host, credential in hosts:
        if credential in seen_credentials:
            continue
        seen_credentials.append(credential)
        path, cred_id = vm_broker_credential(name, credential)
        svc.add("LoadCredentialEncrypted", f"{cred_id}:{path}")
    svc.blank()
    # No persistent identity: the broker owns no files and needs no home. This
    # is the protection, not a tidiness measure -- see the docstring.
    svc.set("DynamicUser", "yes")
    svc.blank()
    # This process holds a live provider key in memory and parses input that
    # arrives, ultimately, from a guest assumed to be hostile.
    svc.set("NoNewPrivileges", "yes")
    svc.set("CapabilityBoundingSet", "")
    svc.set("AmbientCapabilities", "")
    svc.set("PrivateTmp", "yes")
    svc.set("PrivateDevices", "yes")
    # PrivateUsers= is deliberately NOT set. The broker identifies each caller
    # by the uid owning the far end of the connection, and /proc/net translates
    # that column through the reader's user namespace -- from a restricted one
    # every caller reads as the overflow uid and they all collapse into one
    # identity, with no error. The broker refuses to start if it detects this.
    svc.set("ProtectSystem", "strict")
    svc.set("ProtectHome", "yes")
    svc.set("ProtectProc", "invisible")
    svc.set("ProtectClock", "yes")
    svc.set("ProtectHostname", "yes")
    svc.set("ProtectKernelTunables", "yes")
    svc.set("ProtectKernelModules", "yes")
    svc.set("ProtectKernelLogs", "yes")
    svc.set("ProtectControlGroups", "yes")
    # AF_UNIX and AF_NETLINK beyond the two the shipped unit named, and the
    # difference is deliberate: that unit has never run anywhere (it ships
    # disabled and has no users), while the inspector's identical pair was
    # MEASURED -- glibc's getaddrinfo opens a netlink socket for source-address
    # selection and nss-resolve talks varlink over AF_UNIX. Without them the
    # broker's own lookups fail, which presents as the provider being
    # unreachable.
    svc.set("RestrictAddressFamilies", "AF_INET AF_INET6 AF_UNIX AF_NETLINK")
    svc.set("RestrictNamespaces", "yes")
    svc.set("RestrictRealtime", "yes")
    svc.set("RestrictSUIDSGID", "yes")
    svc.set("LockPersonality", "yes")
    svc.set("MemoryDenyWriteExecute", "yes")
    svc.set("SystemCallArchitectures", "native")
    svc.set("SystemCallFilter", "@system-service")
    svc.set("SystemCallErrorNumber", "EPERM")
    svc.set("UMask", "0077")
    # Coredumps would contain the credential.
    svc.set("LimitCORE", "0")
    svc.blank()
    # THE ONLY EGRESS BOUND ON THIS PROCESS. The instance's uid is not in
    # wl_filtered -- that is the same disjointness the protection rests on --
    # so workload-filter.nft's default-deny does not apply to it and its
    # output chain matches nothing it sends. A missing IPAddressAllow= line is
    # therefore not a degraded bound but no bound at all, which is why the
    # render gate asserts the deny and the shape of the list rather than
    # trusting them.
    #
    # `localhost` covers two things at once: the 127.129.x.y address this
    # instance binds, and the stub resolver a systemd-resolved host puts at
    # 127.0.0.53.
    svc.add("IPAddressAllow", "localhost")
    for addr in vm_host_resolver_addresses():
        svc.add("IPAddressAllow", addr)
    # Resolved at generation time, because systemd will not resolve a name in
    # this directive. Stale on a moved record like every other resolve-at-start
    # element in this design, and fixed by the same restart.
    for addr in upstream:
        svc.add("IPAddressAllow", addr)
    svc.add("IPAddressDeny", "any")
    svc.blank()
    svc.add("StandardOutput", "journal")
    svc.add("StandardError", "journal")
    svc.blank()
    # An instance whose config exists cannot fail for the reason the host-wide
    # unit could, so restarting it is worth doing rather than a loop waiting to
    # happen; the guest gets a refused connection from the inspector in the
    # meantime, which is D5's named drop reason and not a silence.
    svc.add("Restart", "on-failure")
    svc.add("RestartSec", "2")

    return unit.render()


def generate_vm_build_service(config, user_name) -> str:
    """Generate the oneshot build service that creates system.qcow2."""
    name = config["workload"]["name"]
    home_dir = str(workload_state_dir(name))
    system_disk = f"{home_dir}/system.qcow2"
    setup_service = f"workload-{name}-setup.service"

    unit = Unit()
    unit.comment(f"Build service for {name} VM workload")
    unit.comment(GENERATED_BY)

    u = unit.section("Unit")
    u.set("Description", f"Build system disk for {name} VM")
    u.set("Requires", setup_service)
    u.set("After", setup_service)
    # Skip rebuild if system disk already exists — update explicitly removes it
    u.set("ConditionPathExists", f"!{system_disk}")

    svc = unit.section("Service")
    svc.set("Type", "oneshot")
    svc.set("RemainAfterExit", "yes")
    svc.set("TimeoutStartSec", "3600")
    svc.set("ExecStart", f"/usr/libexec/workloadctl/workload-vm-build-disk {name}")
    svc.set("StandardOutput", "journal")
    svc.set("StandardError", "journal")

    return unit.render()


def generate_vm_service(config, user_name: str, uid: int, vfs_tags=None) -> str:
    """Generate the main VM service (QEMU, Type=notify via workload-vm-notify).

    `vfs_tags` (the collision-safe virtiofs tags) is passed in by the caller so
    the boot generator computes it once per VM; falls back to deriving it here so
    the function stays callable standalone (tests)."""
    name = config["workload"]["name"]
    vm_cfg = config.get("vm", {})
    home_dir = str(workload_state_dir(name))
    # data.qcow2 is the precious disk → lives in the backup-captured data/ subtree,
    # apart from the reconstructible system.qcow2 (state/).
    data_dir = str(workload_data_dir(name))
    socket_dir = f"/run/workload-vm/{name}"

    # Always pass QEMU an integer number of MiB so memfd's "size=NM" stays valid.
    memory_mib = parse_memory_mib(vm_cfg.get("memory", 2048))
    vcpus = vm_cfg.get("vcpus", 2)
    slice_name = config.get("resources", {}).get("slice", "workloads.slice")

    ovmf_code = find_ovmf_code() or "/usr/share/edk2/ovmf/OVMF_CODE.fd"
    mac = vm_mac_address(name)

    # Parse virtiofs volumes — collision-safe tags shared with the sidecar loop,
    # ensure-user, and purge (B3). Computed once by the caller and threaded in.
    volumes = vm_cfg.get("volumes", [])
    if vfs_tags is None:
        vfs_tags = virtiofs_tags(volumes)

    # Network: passt unless the operator named a host bridge (ADR 006). The
    # presence of `bridge` IS the topology selector — there is no mode key — so
    # the contradictory combination is unrepresentable rather than rejected.
    net_cfg = vm_cfg.get("network", {})
    bridge_name = net_cfg.get("bridge")

    # Service dependencies
    prereqs = [
        f"workload-{name}-setup.service",
        f"workload-{name}-build.service",
    ]
    for tag in vfs_tags:
        prereqs.append(f"workload-{name}-virtiofs-{tag}.service")
    # The inspector socket is a hard prerequisite, not a Wants=. A filtered VM
    # whose inspector socket is not bound reaches nothing on 80 or 443 while the
    # VM itself looks healthy — the misreported-confinement failure. Requires=,
    # not
    # Wants=, so a failed ExecStartPre — the nft arming — stops the VM from
    # booting rather than booting it unprotected. And the ordering is now
    # stated twice, from both ends: the socket's
    # Before=workload-<name>.service AND this After=. That is deliberate, not
    # redundant: Before= orders the socket ahead of the VM, and this After=
    # is what makes the VM's own start wait for it — a later reader who
    # deletes either side leaves only the other direction's ordering.
    # G1 in the container egress-parity build spec: VM-only by construction,
    # not by this predicate -- this whole function (generate_vm_workload)
    # only runs for kind == "vm". The container path's own inspect-socket
    # prerequisite wiring is P1-7/P1-9, in the container branch below the
    # `kind == "vm"` dispatch.
    if vm_uses_inspect(config):
        prereqs.append(f"workload-{name}-inspect.socket")
    # And the responder, on the same terms for the same reason: the guest has
    # exactly one nameserver, so a VM booted with its responder socket unbound
    # resolves nothing at all while looking healthy. Requires=, not Wants=.
    if vm_uses_resolve(config):
        prereqs.append(f"workload-{name}-resolve.socket")
    # And the broker instance, Requires= on the same terms once more: a
    # credential-backed host reached while the broker is down produces a
    # refusal on the one channel the guest cannot work around, and the guest
    # holds a placeholder, so failing over to the provider directly is a 401
    # rather than a degradation. The instance is ordered Before= the VM from
    # its own side too.
    if vm_uses_credentials(config):
        prereqs.append(f"workload-{name}-broker.service")
    prereqs_str = " ".join(prereqs)

    has_data_disk = bool(vm_cfg.get("data_disk_size"))

    # QEMU arguments — built here so the unit file is self-documenting
    qemu_args = [
        "/usr/bin/qemu-system-x86_64",
        "-machine q35,accel=kvm",
        "-cpu host",
    ]

    # Memory: use shared memfd backend when virtiofs is in use
    if vfs_tags:
        qemu_args += [
            f"-object memory-backend-memfd,id=mem,size={memory_mib}M,share=on",
            f"-m {memory_mib}",
            "-numa node,memdev=mem",
        ]
    else:
        qemu_args.append(f"-m {memory_mib}")

    qemu_args.append(f"-smp {vcpus}")

    # UEFI
    qemu_args += [
        f"-drive if=pflash,format=raw,readonly=on,file={ovmf_code}",
        f"-drive if=pflash,format=raw,file={home_dir}/nvram.fd",
    ]

    # Disks
    qemu_args.append(
        f"-drive file={home_dir}/system.qcow2,if=virtio,format=qcow2,id=system"
    )
    if has_data_disk:
        qemu_args.append(
            f"-drive file={data_dir}/data.qcow2,if=virtio,format=qcow2,id=data"
        )

    # Cloud-init seed (always present; removed from command after first boot
    # would require rebuild — keep it; cloud-init runs once per instance-id).
    # Lives on tmpfs (the runtime dir) not the persistent home: in template
    # mode the ISO embeds decrypted secrets, so it must not survive a reboot at
    # rest. The setup service rebuilds it into this dir every boot.
    qemu_args.append(
        f"-drive file={socket_dir}/cloud-init.iso,if=virtio,format=raw,readonly=on,media=cdrom,id=cloudinit"
    )

    # Network. Two shapes, selected by whether [vm.network].bridge is set.
    if bridge_name:
        # The unfiltered escape hatch: a real LAN identity, which passt cannot
        # provide because the guest takes the *host's* address. Supported and
        # deliberate, not a lapse — but nothing in the egress design reaches a
        # VM here, and `diagnose` says so plainly.
        qemu_args.append(f"-netdev bridge,id=net0,br={bridge_name}")
    else:
        qemu_args.append(build_passt_netdev(name, uid, net_cfg, mac))
    qemu_args.append(f"-device virtio-net-pci,netdev=net0,mac={mac}")

    # virtiofs chardev + device per volume
    for tag in vfs_tags:
        sock = f"{socket_dir}/virtiofs-{tag}.sock"
        qemu_args += [
            f"-chardev socket,id=chr-vfs-{tag},path={sock}",
            f"-device vhost-user-fs-pci,chardev=chr-vfs-{tag},tag={tag}",
        ]

    # Memory balloon — allows host to reclaim idle guest memory
    if vm_cfg.get("balloon", True):
        qemu_args.append("-device virtio-balloon-pci")

    # qemu-guest-agent channel. The guest agent is the only *authoritative*
    # source for a guest's addresses: it asks the guest's own kernel, so it works
    # on a managed bridge and on a pre-existing LAN bridge alike, and needs
    # neither a dnsmasq lease nor a populated host ARP table nor working mDNS.
    # Every other source is an inference the host makes from outside — see the
    # fallback chain in substrate_vm._vm_guest_addresses, which this fronts.
    #
    # Always wired, with no [vm] toggle: a guest without qemu-ga installed simply
    # never opens its end of the port, which costs one idle virtio-serial device
    # and changes nothing else. Making it conditional would only create a second
    # way for address lookup to silently lose its best source.
    qemu_args += [
        "-device virtio-serial-pci",
        f"-chardev socket,id=chr-qga,path={socket_dir}/ga.sock,server=on,wait=off",
        f"-device virtserialport,chardev=chr-qga,name={VM_GUEST_AGENT_PORT}",
    ]

    # Console + QMP + display.
    # Two QMP monitors: qmp.sock is the control channel (notify/info/ExecStop
    # system_powerdown); qmp-metrics.sock is a dedicated read-only channel for
    # the always-on Prometheus exporter. A single QMP monitor serves one client
    # at a time, so giving the exporter its own monitor keeps a 15s scrape from
    # ever blocking the shutdown powerdown command (which would otherwise time
    # out into a SIGKILL / unclean shutdown).
    qemu_args += [
        f"-serial unix:{socket_dir}/console.sock,server=on,wait=off",
        f"-qmp unix:{socket_dir}/qmp.sock,server=on,wait=off",
        f"-qmp unix:{socket_dir}/qmp-metrics.sock,server=on,wait=off",
    ]
    # on-reboot mode needs the notify wrapper to watch for the guest SHUTDOWN
    # event to tell a reboot from a poweroff (see the restart-policy block
    # below). A QMP monitor serves one client at a time, so it gets its OWN
    # dedicated socket rather than contending with qmp.sock (control/ExecStop)
    # or qmp-metrics.sock (exporter). Only added in on-reboot mode so the
    # default/on-failure unit shape is unchanged.
    if vm_cfg.get("restart") == "on-reboot":
        qemu_args.append(
            f"-qmp unix:{socket_dir}/qmp-notify.sock,server=on,wait=off")
    qemu_args += [
        "-nographic",
        "-no-reboot",
        f"-name {name}",
    ]

    resources = config.get("resources", {})

    # Build ExecStart: workload-vm-notify wraps QEMU
    qemu_cmd = " \\\n        ".join(qemu_args)

    unit = Unit()
    unit.comment(f"VM workload service for {name}")
    unit.comment(GENERATED_BY)

    u = unit.section("Unit")
    u.set("Description", f"{name} VM workload")
    u.set("Requires", prereqs_str)
    if bridge_name:
        u.set("After", prereqs_str)
    else:
        # passt needs a configured host interface, not merely a network stack:
        # it takes the guest's address and gateway from the host's, and the
        # netdev prestart reads the default route to derive the DNS options.
        # network.target is not enough — it only means "network management has
        # started". This ordering used to arrive transitively, via
        # workload-bridge.service's After=network.target; that unit is gone.
        u.set("Wants", "network-online.target")
        u.set("After", f"{prereqs_str} network-online.target")
    u.set("StartLimitIntervalSec", "300")
    u.set("StartLimitBurst", "3")

    svc = unit.section("Service")
    svc.set("Type", "notify")
    svc.set("NotifyAccess", "all")
    svc.set("Slice", slice_name)
    svc.set("User", user_name)
    svc.set("Group", user_name)
    # Environment= is repeatable/cumulative; HOME here and the optional
    # WORKLOADCTL_VM_REBOOT_EXIT below must both survive, so use add() not set().
    svc.add("Environment", f'"HOME={home_dir}"')
    svc.add("EnvironmentFile", f"-/run/workload-env/workload-{name}.env")
    if not bridge_name:
        # Written by the ExecStartPre below, and read back for ExecStart:
        # systemd re-reads every EnvironmentFile= once per Exec* command
        # (exec_spawn() calls exec_context_load_environment() per invocation),
        # so a file written by a prestart is visible to the start that follows.
        svc.add("EnvironmentFile", f"-/run/workload-env/workload-{name}.passt")
    # Own the per-VM socket dir; preserve across restarts so virtiofsd
    # sidecars (PartOf=) and QEMU's qmp/console sockets aren't yanked.
    svc.set("RuntimeDirectory", f"workload-vm/{name}")
    svc.set("RuntimeDirectoryMode", "0750")
    svc.set("RuntimeDirectoryPreserve", "yes")

    # The VM service unit IS the payload's cgroup (QEMU runs directly under it,
    # with no user manager in between), so [resources] binds here rather than in
    # a user@{uid} drop-in — same keys, same meaning as a container workload.
    directives = cgroup_directives(resources)
    if directives:
        svc.blank()
        for key, value in directives:
            svc.add(key, value)

    svc.blank()
    # custom_directives splice point: every directive from here down uses .add(),
    # never .set(), so the generator cannot overwrite a user's line in place
    # (see _resource_overrides, and lib/unit_file.py for the full invariant).
    _resource_overrides(svc, resources, name)

    # Restart policy. QEMU runs with -no-reboot, so a guest reboot AND a guest
    # poweroff both make QEMU exit 0 — indistinguishable by exit code alone.
    #   "always"     (default) — any exit relaunches QEMU, so a guest reboot
    #                comes back (e.g. the first-boot kernel-upgrade reboot) and a
    #                guest poweroff also comes back. StartLimitBurst bounds a
    #                boot-loop; an explicit stop/disable goes through ExecStop and
    #                is never auto-restarted.
    #   "on-failure" — only a genuine crash (nonzero exit) restarts; a guest
    #                reboot or poweroff (exit 0) stays down.
    #   "on-reboot"  — a guest reboot cycles the VM but a guest poweroff stays
    #                down. QEMU can't express that via exit code, so the notify
    #                wrapper watches the QMP SHUTDOWN event and exits
    #                VM_REBOOT_EXIT_CODE on a reboot vs 0 on a poweroff; the env
    #                var below arms that path (and gates the qmp-notify.sock
    #                added above). Restart=on-failure then relaunches the reboot
    #                (and any real crash) while leaving a poweroff down.
    restart_mode = vm_cfg.get("restart", "always")
    if restart_mode in ("on-failure", "on-reboot"):
        restart_directive = "on-failure"
    else:
        restart_directive = "always"

    if restart_mode == "on-reboot":
        svc.add("Environment",
                f"WORKLOADCTL_VM_REBOOT_EXIT={VM_REBOOT_EXIT_CODE}")

    if not bridge_name:
        # Derive the host-dependent passt DNS options. The `+` prefix runs it as
        # root under User=_wl-<name> — it writes into /run/workload-env, which
        # the workload user may read but not write. Always exits 0: a VM that
        # cannot resolve is bad, a VM that will not boot is worse.
        svc.add("ExecStartPre",
                f"+/usr/libexec/workloadctl/workload-vm-netdev {dq(name)}")

        # Egress policy (ADR 006 §4). The skeleton is applied on every VM start
        # rather than by a shared unit: retiring the bridge removed the only
        # unit that owned a shared table, and nothing replaces it. The file is
        # idempotent by construction, and each `nft -f` is one transaction, so
        # concurrent VM starts cannot interleave.
        #
        # NOT `-` prefixed. If the table cannot be built, a VM configured as
        # filtered would otherwise run wide open while its config claims
        # confinement — the failure this layer exists to prevent. Fail the
        # start instead.
        # The helper applies the skeleton, clears any elements left over from a
        # previous config, and installs the current ones. It is a script rather
        # than a few Exec lines because an edited allowlist cannot be reconciled
        # without enumerating the sets — see its module docstring.
        svc.add("ExecStartPre",
                f"+/usr/libexec/workloadctl/workload-vm-filter up {dq(name)}")
        # ExecStopPost, not ExecStop: systemd runs it on kill and on failure
        # too, so a crashed VM does not leave its uid armed. Tolerant (`-`)
        # because the elements are legitimately absent when the start failed
        # before arming, or after the break-glass `nft delete table`.
        svc.add("ExecStopPost",
                f"-+/usr/libexec/workloadctl/workload-vm-filter down {dq(name)}")

    svc.add("ExecStart",
            f"/usr/libexec/workloadctl/workload-vm-notify {dq(name)} \\\n"
            f"    {qemu_cmd}")
    svc.blank()
    # Graceful shutdown: ACPI power-off, then *block* until the guest is
    # gone (workload-vm-shutdown waits up to 80s). ExecStop must block —
    # systemd only enters its kill phase after it returns, so a
    # fire-and-forget powerdown would let SIGTERM hard-kill QEMU within
    # milliseconds (unclean power-off / data corruption). TimeoutStopSec
    # below (90s) is the backstop if the guest ignores ACPI.
    svc.add("ExecStop", f"/usr/libexec/workloadctl/workload-vm-shutdown {dq(name)}")
    svc.blank()
    svc.add("StandardOutput", "journal")
    svc.add("StandardError", "journal")
    svc.blank()
    svc.add("Restart", restart_directive)
    svc.add("RestartSec", "10s")
    # Generous start timeout: guest may be slow on first boot. Both defaults
    # yield to an explicit [resources] value, which _resource_overrides already
    # emitted above.
    if "timeout_start_sec" not in resources:
        svc.add("TimeoutStartSec", "300")
    if "timeout_stop_sec" not in resources:
        svc.add("TimeoutStopSec", "90")

    install = unit.section("Install")
    install.set("WantedBy", "multi-user.target")

    return unit.render()


def generate_vm_workload(config, user_name: str, uid: int):
    """Emit all unit files for a VM workload. Returns the workload name."""
    name = config["workload"]["name"]
    home_dir = str(workload_state_dir(name))
    vm_cfg = config.get("vm", {})
    volumes = vm_cfg.get("volumes", [])
    view = _RunFileConfig(config=config, name=name, uid=uid, is_vm=True)
    paths = emitted_run_paths(view)

    # Sysusers (with implicit kvm)
    sysuser_content = generate_sysuser_config_vm(config, user_name, uid)
    paths[("sysusers", "sysusers")][0].write_text(sysuser_content)
    log_msg("  Created VM sysusers config (implicit kvm group)")

    # Setup service (same as container)
    setup_content = generate_setup_service(config, user_name)
    paths[("unit", "setup")][0].write_text(setup_content)
    log_msg("  Created setup service")

    # No shared network unit any more (ADR 006). passt runs inside the VM's own
    # unit, as the workload user, so there is nothing host-global to provision,
    # refcount or tear down — which is also why the nftables egress table has to
    # find a new home: workload-bridge.service was the only place a shared table
    # was created and destroyed.
    wants_dir = services_dir() / "multi-user.target.wants"
    wants_dir.mkdir(parents=True, exist_ok=True)

    # Transparent egress inspection socket + service, when egress is filtered
    # (not bridged). The socket binds and arms the redirect before the VM can
    # start; the service is socket-activated and owns the inspector process and
    # its cgroup exemptions.
    # G2 in the container egress-parity build spec: VM-only by construction
    # (generate_vm_workload only runs for kind == "vm"), same as G1 above.
    # Container inspect-unit emission is P1-7/P1-9.
    uses_inspect = vm_uses_inspect(config)
    if uses_inspect:
        socket_dests = paths.get(("unit", "inspect-socket"), [])
        if socket_dests:
            socket_dests[0].write_text(
                generate_vm_inspect_socket(config, user_name, uid))
            log_msg("  Created egress inspector socket")
        inspect_dests = paths.get(("unit", "inspect"), [])
        if inspect_dests:
            inspect_dests[0].write_text(generate_vm_inspect_service(config, user_name))
            log_msg("  Created egress inspector service")

    # The credential broker instance, on the inspector's terms plus at least one
    # declared credential. It is not socket-activated (nothing dials it until
    # the inspector does, and the inspector is not a socket that could pass it
    # a connection), so it is an ordinary unit ordered before the VM.
    if vm_uses_credentials(config):
        broker_dests = paths.get(("unit", "broker"), [])
        if broker_dests:
            broker_dests[0].write_text(generate_vm_broker_service(config, uid))
            log_msg("  Created credential broker service")

    # The synthesising responder, on the inspector's terms plus `resolver` not
    # being "none" -- a separate predicate, not a second reading of this one,
    # so the knob has one meaning here and in the passt fragment.
    if vm_uses_resolve(config):
        resolve_socket_dests = paths.get(("unit", "resolve-socket"), [])
        if resolve_socket_dests:
            resolve_socket_dests[0].write_text(
                generate_vm_resolve_socket(config, user_name, uid))
            log_msg("  Created DNS responder socket")
        resolve_dests = paths.get(("unit", "resolve"), [])
        if resolve_dests:
            resolve_dests[0].write_text(
                generate_vm_resolve_service(config, user_name))
            log_msg("  Created DNS responder service")

    # virtiofsd sidecar services — collision-safe tags, same order/set as the
    # VM service's chardevs and the purge/cloud-init sites (B3).
    vfs_tags = virtiofs_tags(volumes)
    vfs_dests = paths.get(("unit", "virtiofs"), [])
    # Both apply to every sidecar of the workload rather than being matched to
    # the share they sit under: an After= on an unrelated mount costs an
    # ordering edge and nothing else, and pairing them by path would need the
    # nested mount declared twice.
    after_mounts = [expand_volume_path(p, home_dir).split(":", 2)[0]
                    for p in vm_cfg.get("after_mounts", [])]
    announce_submounts = bool(vm_cfg.get("announce_submounts", True))
    for (tag, vol_spec), vfs_dest in zip(zip(vfs_tags, volumes), vfs_dests):
        host_raw, _guest_path, _opts = parse_volume_spec(vol_spec)
        # Expand ./ @/ data/ state/ anchors relative to the workload dirs.
        host_path = expand_volume_path(host_raw, home_dir).split(":", 2)[0]
        vfs_content = generate_virtiofs_service(
            name, tag, host_path, user_name, uid,
            after_mounts=after_mounts,
            announce_submounts=announce_submounts)
        vfs_dest.write_text(vfs_content)
        log_msg(f"  Created virtiofsd service for tag '{tag}'")

    # Build service
    build_content = generate_vm_build_service(config, user_name)
    paths[("unit", "build")][0].write_text(build_content)
    log_msg("  Created build service")

    # Main VM service
    vm_service_content = generate_vm_service(config, user_name, uid, vfs_tags)
    paths[("unit", "main")][0].write_text(vm_service_content)
    log_msg("  Created VM service")

    # Wants symlink for main service
    symlink_path = paths[("wants-symlink", "main")][0]
    if symlink_path.exists() or symlink_path.is_symlink():
        symlink_path.unlink()
    symlink_path.symlink_to(f"../workload-{name}.service")

    return name
