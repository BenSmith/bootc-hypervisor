#!/usr/bin/env python3
"""Generating the egress units both substrates share.

The transparent egress inspector's socket and service, the credential broker
instance, the synthesising DNS responder's socket and service, and the sandbox
all three run in. ADR 009's second decision is that the mechanism is shared byte for byte
and only the arming differs, and these are the units that decision is about:
generators/workload-generate emits them for a container with a `[network]`
trigger and gen_vm emits them for a VM with `egress = "filtered"`, and the
rendered text differs in nothing but the workload's name, uid and arming
helper.

They lived in gen_vm, where the container branch of the entrypoint reached
in for them -- the one call across the VM/container split that gen_vm's own
docstring says does not exist. Nothing here names a substrate: every
substrate-specific value (which arming script, which unit the broker is
ordered before, which hosts it serves) is a required argument, so the module
cannot quietly default to one side.

Installed to /usr/libexec/workloadctl/gen_egress.py.
"""


from workload_lib import workload_state_dir, dq, uq
from run_files import GENERATED_BY
from customs.egress_plane import PLANES
from egress_policy import (
    inspect_logs_directory, inspect_policy_path, inspect_record_path,
    inspect_status_path, resolve_static_path,
)
from customs.egress_ca import denial_dir, leaf_dir
from nft_elements import (
    inspect_cgroup_command, inspect_cgroup_filter_command, resolve_status_path,
)
from broker_config import broker_credential, host_resolver_addresses
from config_parser import SOCKET_DIR
from nft_constants import SIDECAR_SLICE
from workload_addr import (
    BROKER_INSTANCE_PORT, INSPECT_LISTENER_BIN, RESOLVE_LISTENER_BIN,
    RESOLVE_PORT, broker_listen_address, inspect_address, resolve_address,
)
from unit_file import Unit


def generate_inspect_socket(config, user_name: str, uid: int, *,
                            arming_helper: str) -> str:
    """Generate the socket unit for one workload's transparent egress
    inspector -- VM or container (P1-9): the unit shape is substrate-generic
    (uid-derived addressing, name-keyed ordering), so this function is reused
    verbatim for both. `arming_helper` is the one substrate-specific fact --
    which script's `up`/`down` the ExecStartPre/ExecStopPost invoke, since the
    VM and container arming scripts read the config's [vm.network] vs
    [network] table respectively (workload-vm-inspect vs
    workload-container-inspect). It has no default: the caller is the
    substrate, and a default would make this module name one of them. D6's
    "the binary does not change" is about the LISTENER
    (customs-inspect, ExecStart below in
    generate_inspect_service) -- the arming helper is not that binary.

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
    addr = inspect_address(uid)

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
    # A socket's default dependencies order it Before=sockets.target, which is
    # ordered before basic.target, which every service with default
    # dependencies -- setup.service included -- is After=. With the After= on
    # setup above that is a cycle: socket > setup > basic > sockets > socket.
    # Starting never trips it (sockets.target is already reached by the time
    # anything pulls this socket in), but a shutdown puts all four in one
    # transaction and systemd deletes a job of its choosing to break it. The
    # sockets.target edge is false anyway: this socket is pulled in by the
    # workload's own unit, never by sockets.target. Dropped, and the defaults
    # that matter re-stated -- stop at shutdown; sysinit.target comes through
    # setup.service.
    u.set("DefaultDependencies", "no")
    u.set("Conflicts", "shutdown.target")
    u.add("Before", "shutdown.target")

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
    # Four listener ports, both families, one per plane. The values come
    # from the T4 derivation (inspect_address) and the plane's inspect port —
    # never a literal. The v6 form brackets the address so it is not parsed as
    # the scope-id separator.
    for family_addr in (addr.v4, f"[{addr.v6}]"):
        for plane in PLANES:
            sock.add("ListenStream", f"{family_addr}:{plane.inspect_port}")
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


def harden_sidecar(svc, name: str, *, families: str, tasks_max: int,
                   memory_max: str, extra_rw: tuple = ()) -> None:
    """The sandbox both egress sidecars run in.

    Public rather than underscored because its other caller is in another
    module: gen_vm's virtiofsd sidecar runs in this same sandbox.

    These two processes are the ones ADR 008 names as the cost of the design:
    code parsing hostile guest input, on the path for all HTTP and HTTPS, and
    from a later rung holding a CA key. They were shipped confined by SELinux
    alone, which is one mechanism where gen_vm's virtiofsd sidecar carries
    two -- and the sidecar's confinement was argued, while the absence here
    was not argued anywhere.

    DO NOT ADD NoNewPrivileges=yes (nor DynamicUser=yes, which implies it).
    Both units reach their domain through a `#!` entrypoint transition from
    init_t, and under NNP the kernel refuses a transition that is not bounded
    by the calling domain -- which fails the exec with a bare 203/EXEC that
    points nowhere near the cause. The generate_virtiofs_service comment in
    gen_vm carries the measurement and the audit record; it applies here
    unchanged.

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
            " ".join([uq(f"{SOCKET_DIR}/{name}")]
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


def inspect_listener_command(name: str, uid: int) -> list:
    """The listener's argv: the binary and the five values it is handed.

    THIS IS WHERE THE INSPECTOR AND WORKLOADCTL MEET, and it is the only
    place. The inspector (customs-inspect, from the customs package) knows
    nothing about workloads -- not where one keeps its policy, its state, its
    counters or its record, and not what a uid becomes. Each of those is a
    fact about how workloadctl lays out a host, computed HERE from the name
    and uid the generator already holds, and written into ExecStart= as a
    flag. The entrypoint parses; it derives nothing, so a third substrate
    writes a unit, not a program. tests/test_customs_seam.py asserts that
    this command names every one of the five and that customs-inspect takes
    each.

    The broker pair is computed from the uid with the same function the
    broker's own `--listen` flag is (broker_config.broker_command, when its
    unit is written), so the address in this unit and the address the broker
    binds cannot drift: no registry, no allocation step. Always
    emitted, even for a policy with no brokered host, because the policy is
    read at the listener's start and this unit is written before it exists;
    a pair that goes unused costs nothing, and a pair that is missing when a
    policy edit adds a `credential` costs a regenerate the operator was not
    told about.

    The name rides along as a LABEL, not a lookup key: the CA subject and
    the log lines carry it. Every VALUE goes through dq (the systemd-Exec
    literal-token helper) on the ExecStart= line, so a name or path carrying
    a space stays one token; the binary and the flags are written bare, as
    every other Exec= line in these units writes its binary and verbs.
    """
    return [
        INSPECT_LISTENER_BIN,
        "--name", name,
        "--policy", inspect_policy_path(name),
        "--state-dir", str(workload_state_dir(name)),
        "--status", inspect_status_path(name),
        "--record", str(inspect_record_path(name)),
        "--broker", f"{broker_listen_address(uid)}:{BROKER_INSTANCE_PORT}",
    ]


def generate_inspect_service(config, user_name: str, uid: int) -> str:
    """Generate the service unit for one workload's transparent egress
    inspector.

    Socket-activated by the matching .socket: the kernel hands the listener its
    accepted connection when the guest first dials. It runs as _wl-<name> so
    the inspector's own traffic carries the workload's uid, which is what the
    two cgroup exemptions below key on. The uid is passed in and never looked
    up, for the reason generate_inspect_socket gives: on a first enable the
    user does not exist yet. Here it is what the broker endpoint on the
    ExecStart= line is derived from.

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
    svc.set("Slice", SIDECAR_SLICE)
    # Arm BOTH cgroup exemptions before the listener starts. `+` runs them as
    # root (nft needs the capability); not `-` — an exemption that failed to
    # install leaves a healthy-looking inspector that reaches nothing or dials
    # into itself. Both lines, always: one missing is one of the two failures
    # the docstring names. Each argv token is quoted with dq (the systemd-Exec
    # literal-token helper), not a bare join: the `inet workload_proxy` table
    # and the cgroup path each carry a space that a bare join would split, and
    # dq is the repo's own quoting for Exec lines, not shell quoting.
    for cmd in (
        inspect_cgroup_command(name, "add"),
        inspect_cgroup_filter_command(name, "add"),
    ):
        svc.add("ExecStartPre",
                "+" + " ".join(dq(a) for a in cmd))
    # Everything the listener needs to know about this workload, as flags:
    # inspect_listener_command says why the derivation lives here and not in
    # the listener. The name among them because the listener cannot recover
    # it: it is socket-activated with four identically-named fds, and reading
    # it back out of getpwuid(geteuid()) would make its identity depend on
    # the _wl- naming convention instead of on the unit it was generated for.
    binary, *args = inspect_listener_command(name, uid)
    svc.add("ExecStart", " ".join(
        [binary] + [a if a.startswith("--") else dq(a) for a in args]))
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
        inspect_cgroup_command(name, "delete"),
        inspect_cgroup_filter_command(name, "delete"),
    ):
        svc.add("ExecStopPost",
                "-+" + " ".join(dq(a) for a in cmd))
    svc.blank()
    # 128 connections is MAX_CONNECTIONS in the listener, one thread each, plus
    # the accept loop and a little room; a listener that has lost track of its
    # own ceiling stops here instead of at the host's. The memory number is
    # generous against the work: 128 relays at a 64 KiB buffer each direction
    # is single-digit megabytes on top of the interpreter.
    harden_sidecar(svc, name,
                   families="AF_INET AF_INET6 AF_UNIX AF_NETLINK",
                   tasks_max=192, memory_max="512M",
                   extra_rw=(leaf_dir(workload_state_dir(name)),
                             denial_dir(workload_state_dir(name))))
    svc.blank()
    svc.add("StandardOutput", "journal")
    svc.add("StandardError", "journal")
    svc.blank()
    # Where the PER-REQUEST RECORD goes, which is NOT the journal above. The
    # two lines are different documents with different readers: the journal
    # carries the decision and the remedy, and the record carries what the
    # guest actually asked for -- paths, and query strings that can carry a
    # credential outright. egress_policy's INSPECT_RECORD_ROOT comment has the
    # argument; the modes are the access decision.
    #
    # LogsDirectory= rather than a mkdir of ours, for three things at once:
    # systemd creates it as User= (so the listener can recreate the file after
    # a rotation, which the logrotate snippet's `nocreate` requires), recreates
    # it if an operator deletes it, and -- the part that is easy to miss --
    # adds it to the unit's writable set under ProtectSystem=strict with no
    # ReadWritePaths= entry of ours. See harden_sidecar's `extra_rw`
    # comment for what the absence of that costs: EROFS, swallowed by the
    # per-connection OSError handler, presenting as a network fault.
    svc.add("LogsDirectory", inspect_logs_directory(name))
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


def generate_broker_service(config, uid: int, *, before: str,
                            hosts, upstream, command) -> str:
    """Generate the credential broker instance for one workload.

    Substrate-neutral through four keyword parameters, on the same terms as
    generate_inspect_socket/_service (D6): nothing in the unit below is
    VM-specific, so each substrate is a call site rather than a generator of
    its own. `before` is the unit this one must be ordered ahead of, `hosts`
    the (host, credential) pairs, `upstream` the addresses those hosts
    resolve to, `command` the broker's argv (broker_config.vm_broker_command
    or container_broker_command). None has a default, for the reason
    generate_inspect_socket's `arming_helper` has none.

    P2-3: `before` exists because the VM default is WRONG for a container in
    pod/bridge mode. There the umbrella carries `After=` its member services,
    so `Before=workload-<name>.service` orders the broker after every
    container has already started -- the same hole the inspector arming was
    moved off the umbrella for (see gen_container_heads._head_unit). The container branch passes
    the pod/net head unit, which is the one workload-level unit ordered ahead
    of the members.

    Modelled on the host-wide agent-broker.service this replaces -- deleted in
    the same rung, so read it from git history if the derivation matters -- and
    NOT on harden_sidecar. The two sandboxes differ in the one directive
    that matters most here: this unit is DynamicUser=yes, and that is the whole
    of ADR 007's protection. The inspector runs as _wl-<name>, the uid QEMU runs
    as, so a guest escape obtains everything that uid can read; the broker's
    dynamic uid sits at 61184-65519, disjoint from the workload range, and the
    credential is only ever decrypted into ITS tmpfs. Give this unit
    User=_wl-<name> "for consistency" and the design's central claim is gone.

    That disjointness is also why NoNewPrivileges=yes is safe here and is
    refused by harden_sidecar: the sidecars reach an SELinux domain through an
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
    # The broker sends READY=1 once its socket is listening. Type=exec would
    # call it started at the exec, while the interpreter is still loading and
    # the credential is still being read, and what is ordered after it would
    # then find nothing listening. The default NotifyAccess=main suffices:
    # the notification comes from the process systemd started.
    svc.set("Type", "notify")
    # Everything the broker needs to know about this workload, as flags, the
    # way the inspector's ExecStart= carries the inspector's: the address it
    # binds and the uid it serves (both from the uid, computed here and not
    # by the broker), one --host per credentialed host naming the credential
    # id the LoadCredentialEncrypted= line below loads it under, and the
    # per-credential placeholder and auth convention. No ExecStartPre and no
    # RuntimeDirectory=: there was a broker.toml here, rendered at every
    # start from the same TOML this unit was rendered from, and a document
    # that is a pure function of the unit's inputs is the unit's to carry.
    # No material is on the line -- a credential id names a file under
    # $CREDENTIALS_DIRECTORY, and the line holds nothing the workload does
    # not already hold (its hosts, its placeholders, its own uid) or that
    # this world-readable unit does not already name (the credential ids).
    #
    # Each value is quoted with dq (the systemd-Exec literal-token helper):
    # a placeholder is operator prose and may carry a quote, a `$` or a `%`,
    # and this is the second unit to put one on an Exec line (the container
    # `--env` was first). The binary and the flags are written bare, as
    # every other Exec= line in these units writes its binary and verbs.
    binary, *args = command
    svc.add("ExecStart", " ".join(
        [binary] + [a if a.startswith("--") else dq(a) for a in args]))
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
        path, cred_id = broker_credential(name, credential)
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
    for addr in host_resolver_addresses():
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


def generate_resolve_socket(config, user_name: str, uid: int) -> str:
    """Generate the socket unit for one workload's synthesising DNS responder.

    A socket unit for ONE reason: port 53 is privileged and the responder runs
    as _wl-<name>, so the bind has to happen in PID 1 and be handed over. It
    borrows nothing else from the inspector's socket unit -- and specifically
    there is NO ExecStartPre address-add here, which is the difference a reader
    coming from generate_inspect_socket will look for.

    The kernel treats all of 127/8 as local on `lo`, so the responder's address
    needs no assignment: binding 127.130.1.4 succeeds with nothing
    configured. A step adding a /32 would be a no-op, and worse, it would invent
    an address whose absence the inspector's fail-at-bind argument would then
    appear to depend on. There is likewise no
    FreeBind= question to answer, and no teardown that would make the presence
    of an address mean a running process.

    Both transports. A static name with more addresses than fit in a datagram
    is answered with the truncate bit set, and the client asks again over TCP;
    clients also open TCP connections for their own reasons, and a UDP-only
    responder leaves those hanging with nothing to diagnose from.
    """
    name = config["workload"]["name"]
    # The uid is passed in, never looked up, for the reason
    # generate_inspect_socket gives: on a first enable this runs before
    # systemd-sysusers has created _wl-<name>.
    address = resolve_address(uid)

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
    # The workload's first query can arrive as soon as it runs, so the socket
    # is bound before it; PartOf= so it stops with the workload rather than
    # lingering as a nameserver for one that is gone. The workload's own unit
    # (or a container pod's head unit) also Requires= and orders After= this
    # socket, since Before= alone starts nothing.
    u.set("Before", f"workload-{name}.service")
    u.set("PartOf", f"workload-{name}.service")
    # No default dependencies, for the ordering cycle generate_inspect_socket
    # describes: the After= on setup.service above and a socket's implicit
    # Before=sockets.target close a loop through basic.target.
    u.set("DefaultDependencies", "no")
    u.set("Conflicts", "shutdown.target")
    u.add("Before", "shutdown.target")

    sock = unit.section("Socket")
    # Both transports on the workload's own loopback address. IPv4 only: there
    # is deliberately no v6 responder plane (§9 rejects one on cost), and a v6
    # plane on `lo` would not be a substitute anyway -- the shipped `oif lo
    # accept` would make it reachable from every workload on the host, which is
    # the one property 127/8's unreachability from the workload is providing:
    # a guest's 127/8 and a container's are their own, and passt or pasta's
    # DNS forwarding is the only way here.
    sock.add("ListenDatagram", f"{address}:{RESOLVE_PORT}")
    sock.add("ListenStream", f"{address}:{RESOLVE_PORT}")
    # One long-lived process, not one per connection -- and with Accept=no the
    # trigger limit below is the meaningful knob. Set explicitly.
    sock.set("Accept", "no")
    # Accept=no silently lowers systemd's trigger-limit default to 20 per 2s,
    # and hitting it fails the socket unit PERMANENTLY until something restarts
    # it. A workload starting is a burst of lookups; 20 is inside what one
    # `dnf makecache` costs. Both values explicit, for the reason the inspector's
    # socket sets them.
    sock.set("TriggerLimitIntervalSec", "2s")
    sock.set("TriggerLimitBurst", "200")

    return unit.render()


def resolve_command(name: str, uid: int) -> list:
    """The responder's argv: customs-resolve and the values it is handed.

    The same seam as gen_egress.inspect_listener_command: customs-resolve
    knows nothing about workloads, so where this one's lists, static map and
    counters live, and what its uid makes the inspector's address, are
    computed here and written into ExecStart= as flags.
    tests/test_customs_seam.py holds this command to the program's flags.

    `--address` is the inspector's, not the responder's: every
    synthesised A points the workload at the listener its 80 and 443 are
    redirected to anyway, so a workload that ignores the redirect and one that
    does not both arrive at the same place. That address is on the
    workload-proxy link, not loopback, so a container's dial to it leaves
    through pasta like any other. `--policy` is the inspector's own
    document, read to COUNT queries for names on no list, never to answer.

    No `--address6`, so AAAA queries get no records. pasta and passt both
    copy a host IPv6 address onto the workload's interface -- pasta onto a
    container's, passt's DHCPv6 onto a guest's -- and on a host with no IPv6
    default route the one they copy can be an inspector's own address from
    the workload-proxy link, this workload's included. An AAAA answer naming
    it is a dial to the workload's own interface, refused before it leaves,
    and clients try IPv6 first. A dial to an IPv6 literal on 80 or 443 is
    still redirected by port.
    """
    return [
        RESOLVE_LISTENER_BIN,
        "--name", name,
        "--address", inspect_address(uid).v4,
        "--policy", inspect_policy_path(name),
        "--static", resolve_static_path(name),
        "--status", resolve_status_path(name),
    ]


def generate_resolve_service(config, user_name: str, uid: int) -> str:
    """Generate the service unit for one workload's synthesising DNS responder.

    Socket-activated, and it never binds: the program refuses to open a socket
    of its own, because port 53 is privileged and this process is not -- a
    fallback bind would be a listener on some other port that nothing forwards
    to, which is a working responder no workload can reach.

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
    # Stopped with the workload, for the reason the inspector's service
    # gives: a process that survived a workload restart would keep answering
    # from the previous run's static map while the workload runs the new one.
    # StopPropagatedFrom= and not PartOf=, because PartOf= propagates a
    # restart as a restart, which starts the responder at once -- before the
    # workload's own prestart (workload-*-filter up) rewrites the static map,
    # so it would load the previous start's. A propagated stop leaves it down
    # until the workload's first query, which cannot come before that
    # prestart.
    u.set("StopPropagatedFrom", f"workload-{name}.service")

    svc = unit.section("Service")
    svc.set("User", user_name)
    svc.set("Group", user_name)
    # Placement, not policy. The inspector pins this slice because two
    # `socket cgroupv2 level 2` matches depend on the path being exactly two
    # components; nothing keys on this unit's cgroup, so the pin here only
    # keeps the responder out of the workload's own resource accounting. Stated so a
    # later reader does not conclude the inspector's pin is decorative.
    svc.set("Slice", SIDECAR_SLICE)
    # Everything the responder needs to know about this workload, as flags;
    # resolve_command says why. The name among them because it is
    # socket-activated with two identically-named fds, so there is nothing on
    # the socket to recover it from.
    binary, *args = resolve_command(name, uid)
    svc.add("ExecStart", " ".join(
        [binary] + [a if a.startswith("--") else dq(a) for a in args]))
    # No user site: as the workload user, site.py would stat a
    # site-packages dir under the workload's home, which wlresolve_t may not
    # traverse (security/workload-resolve.cil), and nothing there belongs on
    # this program's path anyway.
    svc.add("Environment", "PYTHONNOUSERSITE=1")
    svc.blank()
    # Narrower than the inspector on both axes, and the address families are
    # the load-bearing half: this program must contain no call that could
    # consult a resolver, and it opens no socket of its own at all -- its two
    # listeners are handed to it. AF_NETLINK is absent for that reason, so a
    # getaddrinfo that appeared here would fail at the socket rather than
    # quietly reaching a nameserver. One process, one loop: 16 tasks is slack.
    harden_sidecar(svc, name, families="AF_INET AF_UNIX",
                       tasks_max=16, memory_max="128M")
    svc.blank()
    svc.add("StandardOutput", "journal")
    svc.add("StandardError", "journal")
    svc.blank()
    svc.add("Restart", "on-failure")
    svc.add("RestartSec", "5s")

    return unit.render()
