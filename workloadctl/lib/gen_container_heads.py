"""The units of a multi-container workload that are not a container.

The pod-create and bridge-network-create head unit -- the one oneshot
ordered before every member, which is why it carries the egress arming and
the broker dependency -- and the umbrella whose active state reflects the
members'. Rendered text only; the per-container service is gen_container's.

Installed to /usr/libexec/workloadctl/gen_container_heads.py.
"""
from container_network_config import container_uses_inspect
from workload_lib import workload_state_dir, dq
from run_files import GENERATED_BY
from broker_config import container_uses_credentials
from container_run_args import build_userns_args
from unit_file import Unit


def container_egress_exec(svc, name: str) -> None:
    """Element-lifecycle ExecStartPre/ExecStopPost for one container
    workload's egress policy (P1-7 in the container egress-parity build
    spec). Mirrors the VM hook shape at generate_vm_workload's
    `workload-vm-filter up/down` pair -- same `+`/`-+` prefixes, same
    tolerant-on-teardown reasoning (see lib/filter_arm.py's module
    docstring).

    NOT gated here on the config: the caller only calls this when
    container_uses_inspect() is true (R10 -- a workload with no [network]
    trigger must produce byte-identical units to before this work, and
    conditioning inside this function rather than at the call site would
    still add these two lines to every unit).

    No restart-policy addition: _hardening() already sets
    Restart=on-failure/RestartSec=5s for every container workload
    (workload-generate:~1136,~1356), and StartLimitIntervalSec/Burst apply
    host-wide to the unit regardless. Adding a second Restart= here would
    change the units of workloads with no triggers and would double up
    where they do (R10's neighbour in P1-7).
    """
    svc.add("ExecStartPre",
            f"+/usr/libexec/workloadctl/workload-container-filter up {dq(name)}")
    svc.add("ExecStopPost",
            f"-+/usr/libexec/workloadctl/workload-container-filter down {dq(name)}")


def _head_unit(name, user_name, uid, slice_name, header_comment, description,
                create_cmd, rm_cmd, uses_inspect=False, uses_credentials=False):
    """Shared skeleton for the pod-create and bridge-network-create head units.

    Both are single-command oneshot services that run before any member
    container: create the shared pod/network on start, tear it down on
    stop, and re-arm podman's pause namespace first (this is each
    workload's first podman touch, so the recreated pause namespace stays
    consistent for every member container -- see the fresh-pause comment
    in generate_system_service). They differ only in the file header, the
    [Unit] Description=, and the podman create/rm commands.

    'uses_inspect' arms the egress element-lifecycle helper (P1-7) HERE, on
    the one unit that pod/bridge mode orders *before* every member container.

    IT USED TO LIVE ON THE UMBRELLA AND THAT WAS A HOLE. `[network]` is
    workload-level (one uid, D1) and the umbrella is the unit that represents
    "this uid's workload is up", so it looked like the right owner -- but the
    umbrella carries `After=` the member services, so systemd starts every
    container FIRST and only then runs the arming. For the whole of member
    startup the workload had no element in `wl_filtered`, no DNAT, and no
    listener: it ran completely unfiltered, image pull included, and then
    became filtered mid-flight. Single mode was never affected (the arming is
    an ExecStartPre on the container's own unit, ahead of `podman run`). What
    hides it is a test that probes steady state -- enable, recreate, sleep,
    probe -- because by then a late arming and a correct one look identical.
    Assert the ordering itself.

    The head unit is the right owner because the ordering it needs already
    exists in both directions: members are `Requires=`/`After=`/`BindsTo=`
    this unit, so arming precedes the first container and the teardown in
    ExecStopPost runs only after the last one has stopped.
    """
    home_dir = str(workload_state_dir(name))

    unit = Unit()
    unit.comment(header_comment)
    unit.comment(GENERATED_BY)

    u = unit.section("Unit")
    u.set("Description", description)
    u.set("Requires", f"workload-{name}-setup.service")
    u.set("After", f"network.target workload-{name}-setup.service")
    # PartOf the umbrella so `systemctl stop` (and workloadctl disable)
    # tears this down too -- otherwise this oneshot lingers active(exited)
    # and a later re-enable never re-runs the create command.
    u.set("PartOf", f"workload-{name}.service")
    if uses_inspect:
        # Requires=, not Wants=: without the socket started there is nothing
        # listening on the addresses the DNAT sends 80/443 to, and every
        # redirected connection hangs. After=, so it is up before the first
        # member container exists.
        u.add("Requires", f"workload-{name}-inspect.socket")
        u.add("After", f"workload-{name}-inspect.socket")
    if uses_credentials:
        # THE BROKER'S OWN `Before=` DOES NOT START IT. Ordering is not a
        # dependency: the instance was generated, ordered ahead of this unit,
        # given its egress bound and its internal-set exemption, and then never
        # pulled in by anything -- so it sat inactive and every brokered
        # request 502'd while `systemctl status` on the workload was clean.
        # This is the container twin of generate_vm_workload's
        # prereqs.append, and it is Requires= for the same reason: a workload
        # holding a placeholder cannot fail over to the provider directly --
        # that is a 401, not a degradation.
        u.add("Requires", f"workload-{name}-broker.service")
        u.add("After", f"workload-{name}-broker.service")

    svc = unit.section("Service")
    svc.set("Type", "oneshot")
    svc.set("RemainAfterExit", "yes")
    svc.set("Slice", slice_name)
    svc.set("User", user_name)
    svc.set("Group", user_name)
    svc.set("Environment", f'"HOME={home_dir}"')
    svc.set("EnvironmentFile", f"-/run/workload-env/workload-{name}.env")
    svc.add("ExecStartPre", "-/usr/bin/podman system migrate")
    svc.add("ExecStartPre",
             f"-/usr/bin/rm -f /run/user/{uid}/libpod/tmp/pause.pid"
             f" /run/user/{uid}/libpod/tmp/ns_handles")
    svc.add("ExecStartPre", f"-{rm_cmd}")
    if uses_inspect:
        # After the podman ExecStartPre lines above and before ExecStart, so
        # the elements are armed before the pod/network the members join even
        # exists. The `+` prefix runs it as root regardless of User= above.
        container_egress_exec(svc, name)
    svc.set("ExecStart", create_cmd)
    svc.set("ExecStop", rm_cmd)
    svc.set("StandardOutput", "journal")
    svc.set("StandardError", "journal")
    # No [Install]: this helper is pulled in by the umbrella's Requires=
    # and never gets its own multi-user.target.wants symlink.

    return unit.render()


def generate_pod_service(workload, user_name, uid):
    """Generate the workload-{name}-pod.service unit (pod mode only)."""
    name = workload["workload"]["name"]
    slice_name = workload.get("resources", {}).get("slice", "workloads.slice")

    network_config = workload.get("network", {})
    network_mode = network_config.get("mode", "pasta")
    # --share-parent=false: do NOT give the pod its own libpod_pod_<id>.slice.
    # Rootless + systemd cgroup manager, every container start (infra included)
    # unconditionally StartTransientUnit's that shared slice (podman
    # container_internal.go -> platformMakePod -> util_linux.go, guarded only by a
    # cgroupfs-dir check that an empty-but-loaded slice defeats); crun then sends
    # it in "fail" mode with only a scope-scoped one-shot retry
    # (cgroup-systemd.c enter_scope), so there is no recovery path. systemd lets
    # the first caller win; every later member dies with exit 126 ("slice already
    # loaded or has a fragment file"). Giving each container its own cgroup under
    # the user manager removes the contended slice entirely, and it costs nothing:
    # workload resource limits live on the user@<uid>.service subtree
    # (generate_user_dropin), not the pod cgroup, and namespaces (net/ipc/uts/pid)
    # are still shared -- --share-parent is cgroup-layout only, orthogonal to
    # --share (the namespace knob).
    #
    # This is a workaround at our layer for an upstream podman+crun race we can't
    # patch in the image; we arrange never to trigger it rather than fixing it.
    # Revisit only if a workload ever needs genuine pod-level cgroup accounting or
    # a pod-scoped limit -- that real fix belongs upstream.
    pod_args = [f"--name=workload-{name}", f"--network={network_mode}",
                "--share-parent=false"]
    if network_mode not in ("host", "none"):
        for port in network_config.get("ports", []):
            pod_args.append(f"--publish {port}")
    # The pod's infra container owns the user namespace shared by every member
    # container, so userns is workload-level in pod mode: read from the
    # top-level [security] block, not per-container [containers.*.security].
    extra_groups = workload.get("security", {}).get("extra_groups", [])
    pod_args.extend(
        build_userns_args(workload.get("security", {}), uid, extra_groups, name)
    )
    pod_args_str = " ".join(pod_args)

    return _head_unit(
        name, user_name, uid, slice_name,
        header_comment=f"Pod-create service for {name}",
        description=f"{name} pod",
        create_cmd=f"/usr/bin/podman pod create {pod_args_str}",
        rm_cmd=f"/usr/bin/podman pod rm -f --ignore workload-{name}",
        uses_inspect=container_uses_inspect(workload),
        uses_credentials=container_uses_credentials(workload),
    )


def generate_net_service(workload, user_name, uid):
    """Generate the workload-{name}-net.service unit (bridge mode only).

    Creates a per-workload podman bridge network. Member containers join it
    via --network, which gives them DNS resolution of each other by name.
    """
    name = workload["workload"]["name"]
    slice_name = workload.get("resources", {}).get("slice", "workloads.slice")
    net_name = f"workload-{name}-net"

    return _head_unit(
        name, user_name, uid, slice_name,
        header_comment=f"Bridge-network service for {name}",
        description=f"{name} bridge network",
        create_cmd=f"/usr/bin/podman network create {net_name}",
        rm_cmd=f"/usr/bin/podman network rm -f {net_name}",
        uses_inspect=container_uses_inspect(workload),
        uses_credentials=container_uses_credentials(workload),
    )


def generate_umbrella_service(workload_name, container_names, slice_name, mode):
    """Generate the workload-{name}.service umbrella oneshot.

    'mode' is "pod" or "bridge". Determines whether the umbrella requires
    the pod or the net service.

    Requires= (not Wants=) is used for the per-container sub-services so that
    `systemctl is-active workload-<name>.service` reflects sub-service failure:
    if any container fails to start, the umbrella is failed too, which is what
    external monitoring expects to alert on. The trade-off is that a single
    bad container takes the whole workload down — a deliberate choice; users
    who want one-container-failure-tolerance can split into separate workloads.

    THE EGRESS ARMING IS NOT HERE, and the reason is this unit's own After=.
    It carries `After=` the member services so its active state reflects
    theirs, which means anything it runs at start runs AFTER every container
    is already up. P1-7 originally put the arming here and that left a
    pod/bridge workload unfiltered for the whole of member startup. It lives
    on the pod/net head unit instead -- see _head_unit's docstring.
    """
    helper = "pod" if mode == "pod" else "net"
    sub_services = " ".join(
        f"workload-{workload_name}-{c}.service" for c in container_names
    )

    unit = Unit()
    unit.comment(f"Umbrella service for {workload_name}")
    unit.comment(GENERATED_BY)

    u = unit.section("Unit")
    u.set("Description", f"{workload_name} multi-container workload")
    u.add("Requires",
          f"workload-{workload_name}-setup.service workload-{workload_name}-{helper}.service")
    u.add("After",
          f"workload-{workload_name}-setup.service workload-{workload_name}-{helper}.service")
    u.add("Requires", sub_services)
    u.add("After", sub_services)

    svc = unit.section("Service")
    svc.set("Type", "oneshot")
    svc.set("RemainAfterExit", "yes")
    svc.set("Slice", slice_name)
    svc.set("ExecStart", "/bin/true")

    inst = unit.section("Install")
    inst.set("WantedBy", "multi-user.target")

    return unit.render()
