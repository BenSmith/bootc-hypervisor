#!/usr/bin/env python3
"""Generating the egress units both substrates share.

The transparent egress inspector's socket and service, the credential broker
instance, and the sandbox the inspector and the synthesising responder run
in. ADR 009's second decision is that the mechanism is shared byte for byte
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
from egress_plane import PLANES
from egress_policy import (
    inspect_logs_directory, inspect_policy_path, inspect_record_path,
    inspect_status_path,
)
from egress_ca import denial_dir, leaf_dir
from nft_elements import inspect_cgroup_command, inspect_cgroup_filter_command
from broker_config import (
    BROKER_BIN, broker_config_path, broker_credential,
    broker_runtime_directory, host_resolver_addresses,
)
from config_parser import SOCKET_DIR
from nft_constants import SIDECAR_SLICE
from workload_addr import (
    BROKER_INSTANCE_PORT, INSPECT_LISTENER_BIN, broker_listen_address,
    inspect_address,
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
    (workload-inspect-listener, ExecStart below in
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

    Public rather than underscored because its second caller is in another
    module: gen_vm's synthesising responder is the VM-only sidecar, and it
    runs in this same sandbox.

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
    place. The inspector (lib/inspect_listener.py and its closure, the
    entrypoint included) knows nothing about workloads -- not where one
    keeps its policy, its state, its counters or its record, and not what a
    uid becomes. Each of those is a fact about how workloadctl lays out a
    host, computed HERE from the name and uid the generator already holds,
    and written into ExecStart= as a flag. The entrypoint parses; it derives
    nothing. tests/test_inspector_closure.py asserts both halves: that the
    entrypoint's closure reaches no workload-side module, and that this
    command names every one of the five.

    It used to be `workload-inspect-listener <name>`, with the entrypoint
    importing egress_policy, workload_lib and workload_addr to compute the
    rest for itself -- a launcher. The generator already imported all three
    for other lines of this unit, so moving the derivation cost nothing
    here and removed the last workload-side import from the inspector's
    side of the line. A third launcher on a third substrate now writes a
    unit, not a program.

    The broker pair is computed from the uid with the same function the
    broker's own config is rendered from (broker_config, at every start of
    the broker unit), so the address in this unit and the address in
    broker.toml cannot drift: no registry, no allocation step. Always
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
                            hosts, upstream) -> str:
    """Generate the credential broker instance for one workload.

    Substrate-neutral through three keyword parameters, on the same terms as
    generate_inspect_socket/_service (D6): nothing in the unit below is
    VM-specific, so each substrate is a call site rather than a generator of
    its own. `before` is the unit this one must be ordered ahead of, `hosts`
    the (host, credential) pairs, `upstream` the addresses those hosts
    resolve to. None has a default, for the reason generate_inspect_socket's
    `arming_helper` has none.

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
    svc.set("Type", "exec")
    # The config is written into the unit's own runtime directory, by the unit,
    # at every start (D2). systemd creates the leaf as the DynamicUser at 0700
    # and removes it on stop, so the file is readable by the broker, unreadable
    # by the workload uid, and gone when the broker is -- no chown of ours, and
    # no way to serve the previous boot's credential set.
    svc.set("RuntimeDirectory", broker_runtime_directory(name))
    svc.set("RuntimeDirectoryMode", "0700")
    # NOT `+` prefixed. This runs unprivileged, as the instance's own dynamic
    # user, which is what makes the file it writes owned by that user; it needs
    # no privilege, because everything it reads (the workload TOML, the passwd
    # db) is world-readable and the only thing it writes is $RUNTIME_DIRECTORY.
    # And not `-` either: a broker started against a stale or missing config is
    # a broker serving the wrong credentials or none.
    svc.add("ExecStartPre",
            f"/usr/libexec/workloadctl/workload-broker-config config {dq(name)}")
    svc.add("ExecStart", f"{BROKER_BIN} {dq(str(broker_config_path(name)))}")
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
