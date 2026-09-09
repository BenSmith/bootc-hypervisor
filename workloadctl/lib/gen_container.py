#!/usr/bin/env python3
"""Generating the units for a container workload.

The other half of the split gen_vm.py describes: single, pod and bridge
topologies, the podman run argv assembled from a dozen `_*_args` builders, the
umbrella unit, and the container-side egress and credential wiring. Nothing
here calls into gen_vm and nothing there calls in here -- that is measured, not
intended, and it is what made the entrypoint's 3,665 lines two files rather
than one file with a comment in the middle.

SECCOMP_BASELINE lives here rather than in gen_common because it is a podman
argument; a VM never applies one.

Installed to /usr/libexec/workloadctl/gen_container.py.
"""

import os
import grp
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

from config_parser import (
    workload_root_dir, container_credential_entries, container_uses_inspect,
)
from workload_lib import (
    GENERATED_BY, workload_state_dir, expand_volume_path,
    expand_workload_tokens, dq, uq, selinux_type_name,
    container_ca_delivery, container_ca_mount_path,
)
from vm import (
    container_uses_credentials, VM_CA_ENV_VARS, VM_CA_BUNDLE_PATH,
    vm_ca_cert_path,
)
from secrets_template import (
    SECRET_PATTERN, auto_detect_credentials, validate_env_key,
)
from gen_common import (
    log_msg, _external_host_path, _resource_overrides,
)
from validation import valid_userns_mode
from unit_file import Unit



# Baseline seccomp profile applied to all workloads unless overridden via security_opt
SECCOMP_BASELINE = "/usr/share/containers/seccomp-workload-baseline.json"


def get_group_gid(group_name):
    """Get GID for a group name."""
    try:
        return grp.getgrnam(group_name).gr_gid
    except KeyError:
        return None


def build_userns_args(security, uid, extra_groups, name):
    """Return podman --userns / --uidmap / --gidmap args for a security dict.

    Used for single- and bridge-mode container services (per-container
    [security]) and for the `podman pod create` command in pod mode, where
    the user namespace is owned by the pod's infra container and is therefore
    workload-level (read from the top-level [security] block).
    """
    args = []
    userns_mode = security.get("userns", "keep-id")
    if not valid_userns_mode(userns_mode):
        log_msg(f"WARNING: Invalid userns mode '{userns_mode}' for {name}. "
                f"Defaulting to 'keep-id'.",
                level="warning")
        userns_mode = "keep-id"

    if userns_mode == "host":
        log_msg(f"WARNING: {name} uses userns=host. Container root maps to workload user. "
                f"Container escape grants workload user privileges.", level="warning")

    # Extra UID/GID maps for keep-id userns.
    # When extra_groups or explicit maps are present, we emit +N:@N:1 flags
    # which imply keep-id behavior.
    # Podman 5.x treats --userns and --uidmap/--gidmap as mutually exclusive,
    # so we must omit --userns when + prefixed maps are used.
    extra_uidmaps = security.get("extra_uidmaps", [])
    extra_gidmaps = security.get("extra_gidmaps", [])
    needs_auto_maps = (
        userns_mode.startswith("keep-id")
        and (extra_groups or extra_uidmaps or extra_gidmaps)
    )
    if needs_auto_maps:
        # GID == UID for workload users (sysusers convention)
        gid = uid
        # Honor the optional :uid=N,gid=N suffix on keep-id, which remaps the
        # workload user to a different in-container uid/gid (e.g. for images
        # that ship a fixed non-root user). Without this, +N:@N:1 hardcodes the
        # in-container uid to the host workload uid, silently ignoring the
        # suffix that the non-needs_auto_maps branch would have honored.
        target_uid = uid
        target_gid = gid
        if userns_mode.startswith("keep-id:"):
            for param in userns_mode[len("keep-id:"):].split(","):
                key, _, value = param.partition("=")
                if key == "uid":
                    target_uid = int(value)
                elif key == "gid":
                    target_gid = int(value)
        # Auto-map the workload user's own UID and GID (+ prefix implies keep-id)
        args.append(f"--uidmap +{target_uid}:@{uid}:1")
        args.append(f"--gidmap +{target_gid}:@{gid}:1")
        # Auto-map GIDs from extra_groups
        mapped_gids = {gid}
        for group in extra_groups:
            group_gid = get_group_gid(group)
            if group_gid is not None and group_gid not in mapped_gids:
                args.append(f"--gidmap +{group_gid}:@{group_gid}:1")
                mapped_gids.add(group_gid)
        # Explicit maps from TOML (with {UID}/{GID} placeholder substitution)
        for m in extra_uidmaps:
            m = m.replace("{UID}", str(uid)).replace("{GID}", str(gid))
            args.append(f"--uidmap {m}")
        for m in extra_gidmaps:
            m = m.replace("{UID}", str(uid)).replace("{GID}", str(gid))
            args.append(f"--gidmap {m}")
    else:
        args.append(f"--userns={userns_mode}")
    return args


def build_plain_env_args(container):
    """Build --env arguments for non-secret environment variables.

    Env vars containing ${SECRET:name} references are omitted — those are
    resolved at runtime by workload-write-env and passed via --env-file.
    """
    env_vars = container.get("container", {}).get("environment", {})
    env_args = []

    for key, value in env_vars.items():
        if not validate_env_key(key):
            log_msg(f"  WARNING: skipping env var with invalid key: {key!r}", level="warning")
            continue
        if SECRET_PATTERN.search(str(value)):
            continue  # Handled by workload-write-env via --env-file
        # dq() gives systemd-correct literal quoting: double-quote + escape
        # \ " and DOUBLE $ / % so systemd doesn't expand a literal $VAR or %
        # specifier in the value (single-quoting via shlex did NOT stop that —
        # systemd expands after quote removal). See dq()'s docstring.
        env_args.append(f'--env {key}={dq(str(value))}')

    return env_args


def resolve_auto_gpu(name=None):
    """Detect the primary GPU from sysfs.

    Returns 'nvidia', 'nouveau', 'amd', 'intel', or 'none'. For NVIDIA cards
    the bound driver is checked: the proprietary driver uses the CDI path,
    but nouveau has no NVIDIA Container Toolkit support and must use the plain
    DRM render node instead — so it is reported separately.

    On a multi-GPU host the pick (first card in sysfs sort order) is
    arbitrary; if `name` is given, a warning is logged when more than one
    candidate GPU is present so the operator knows "auto" isn't deterministic
    across GPUs and can pin one via `devices.gpu = "nvidia:<uuid-or-index>"`.

    WORKLOAD_GPU_OVERRIDE pins the result regardless of host hardware. This
    makes the generated units deterministic for the snapshot tests (which must
    pass on any runner, GPU or not) and lets an operator force a result.
    """
    override = os.environ.get("WORKLOAD_GPU_OVERRIDE")
    if override:
        return override

    vendor_map = {"0x10de": "nvidia", "0x1002": "amd", "0x8086": "intel"}
    candidates = []
    try:
        for vendor_path in sorted(Path("/sys/class/drm").glob("card*/device/vendor")):
            vendor = vendor_path.read_text().strip().lower()
            if vendor in vendor_map:
                candidates.append((vendor_path, vendor_map[vendor]))
    except OSError:
        pass

    if not candidates:
        return "none"

    if len(candidates) > 1 and name is not None:
        cards = ", ".join(p.parent.parent.name for p, _ in candidates)
        log_msg(
            f"WARNING: {name} uses devices.gpu=\"auto\" with {len(candidates)} "
            f"GPUs present ({cards}); picking {candidates[0][0].parent.parent.name} "
            f"(sysfs sort order, arbitrary). Pin a specific GPU via "
            f"devices.gpu=\"nvidia:<uuid-or-index>\" to avoid ambiguity.",
            level="warning",
        )

    vendor_path, result = candidates[0]
    if result == "nvidia":
        try:
            if (vendor_path.parent / "driver").resolve().name == "nouveau":
                return "nouveau"
        except OSError:
            pass
    return result


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
        _container_egress_exec(svc, name)
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


@dataclass(frozen=True)
class RunSpec:
    """The four things every podman-argv builder below needs, in one object.

    WHY THIS EXISTS. Ten builders assemble the `podman run` argv, and each used
    to take its own subset of the same handful of values: `container` appeared
    in eight signatures, `name` in seven, `mode` in four -- and in three
    different positions, so `_cgroup_args(container, name, mode)` sat beside
    `_network_args(mode, workload, name, container)`. Nothing was wrong with
    any one of them; the cost was that adding a value to a builder meant
    editing a signature, its call, and every test that had pinned the old
    arity, which is friction with no reader benefit.

    WHAT IT DELIBERATELY DOES NOT HOLD. Only values that are a PURE FUNCTION of
    these four fields. Anything the caller had to *decide* -- with a validity
    check, a fallback, or a warning -- stays an explicit argument, because a
    resolved decision passed in a bundle reads exactly like a raw config read
    and it is not one. That is why `_base_run_args` still takes `service_type`
    and `lifecycle` by hand: each is a value the caller validated and logged
    about, and burying that in a constructor would both hide it and reorder the
    generator's warning output.

    The two narrow builders keep their own signatures for the same reason in
    reverse: `_health_check_args(container)` and `_gpu_device_args(gpu_vendor,
    gpu_spec)` each state exactly what they read, and a spec would only make
    that less true. `gpu_vendor` is not derivable here anyway -- resolving
    `gpu = "auto"` does I/O, and this object is constructed on the boot path.
    """

    workload: dict
    """The full parsed TOML. Workload-level tables ([network], [security],
    [setup]) are read from here, never from `container`."""

    container: dict
    """One element of normalize_containers(workload) -- in single mode a
    synthesised one-element shape, which is what makes single-container TOMLs
    render byte-identical units."""

    uid: int
    name: str
    container_name: str
    mode: str

    @property
    def home_dir(self) -> str:
        return str(workload_state_dir(self.name))

    @property
    def container_name_quoted(self) -> str:
        return dq(self.container_name)

    @property
    def pull_policy(self) -> str:
        """[container].pull -- missing (default), always, newer, never.

        A property and not an argument because nothing resolves it: podman
        owns the value's validity, so there is no check here to hide.
        """
        return self.container["container"].get("pull", "missing")

    @property
    def privileged(self) -> bool:
        """Workload-level, not per-container: one uid per workload, so a
        per-container answer here would be a lie (see D1)."""
        return self.workload.get("security", {}).get("privileged", False)

    @property
    def extra_groups(self) -> list:
        return self.workload.get("security", {}).get("extra_groups", [])

    @cached_property
    def has_secret_env_vars(self) -> bool:
        """Does any [container.environment] value reference ${SECRET:...}?

        Decides whether the unit gets the per-container --env-file that
        workload-write-env produces. Cached because the scan is the only
        non-trivial derivation on this object and `frozen=True` makes it safe.
        """
        return any(
            SECRET_PATTERN.search(str(v))
            for v in self.container.get("container", {}).get("environment", {}).values()
        )


def _gpu_device_args(gpu_vendor, gpu_spec):
    """--device flags for the [devices].gpu convenience flag.

    gpu = "nvidia"           → all GPUs, all DRM nodes
    gpu = "nvidia:<spec>"    → one GPU; CDI injects only that card's DRM
                                nodes, so the umbrella /dev/dri is omitted.
    <spec> is any CDI device name from `nvidia-ctk cdi list`: an index
    ("1") or a stable GPU UUID ("GPU-...").

    The umbrella /dev/dri is a directory, so it is bind-mounted (live view)
    rather than passed as --device: --device freezes the enumerated node list
    at container-create time, which breaks a reused ("pet") container when the
    DRM nodes renumber (GPU add/remove/reseat). /dev/kfd is a single node.
    """
    if gpu_vendor == "amd":
        return ["--device /dev/kfd", "--volume /dev/dri:/dev/dri"]
    elif gpu_vendor == "nvidia":
        if gpu_spec:
            return [f"--device=nvidia.com/gpu={gpu_spec}"]
        return ["--device=nvidia.com/gpu=all", "--volume /dev/dri:/dev/dri"]
    elif gpu_vendor in ("intel", "nouveau"):
        # nouveau (and Intel) expose the GPU through the standard DRM render
        # node — no CDI / Container Toolkit involved.
        return ["--volume /dev/dri:/dev/dri"]
    return []


def _health_check_args(container):
    """--health-* flags from [container.health]."""
    health = container.get("container", {}).get("health", {})
    health_cmd = health.get("cmd", "")
    if not health_cmd:
        return []
    args = [f"--health-cmd {dq(health_cmd)}"]
    if "interval" in health:
        args.append(f"--health-interval={health['interval']}")
    if "timeout" in health:
        args.append(f"--health-timeout={health['timeout']}")
    if "retries" in health:
        args.append(f"--health-retries={health['retries']}")
    if "start_period" in health:
        args.append(f"--health-start-period={health['start_period']}")
    on_failure = health.get("on_failure", "none")
    args.append(f"--health-on-failure={on_failure}")
    return args


def _secret_mount_args(spec):
    """--volume flags bind-mounting [[secrets.files]] credentials.

    Credentials are decrypted by systemd to
    /run/credentials/{container_name}.service/{credential_name}; in
    multi-container modes that's the per-container service unit, not the
    umbrella, so the bind-mount source must use container_name, not the
    workload name.
    """
    container, container_name = spec.container, spec.container_name
    service_name = f"{container_name}.service"
    secrets_config = container.get("secrets", {})
    secrets_files = secrets_config.get("files", [])

    args = []
    for file_spec in secrets_files:
        credential_name = file_spec.get("credential")
        container_path = file_spec.get("path")

        if not credential_name or not container_path:
            log_msg("WARNING: secrets.files entry missing 'credential' or 'path', skipping", level="warning")
            continue

        # Credential will be decrypted to /run/credentials/{service}/
        source_path = f"/run/credentials/{service_name}/{credential_name}"

        # Validate and default to read-only for security.
        file_mode = file_spec.get("mode", "ro")
        valid_modes = ["ro", "rw"]
        if file_mode not in valid_modes:
            log_msg(
                f"WARNING: Invalid mode '{file_mode}' for credential '{credential_name}', "
                f"must be 'ro' or 'rw'. Defaulting to 'ro'.",
                level="warning"
            )
            file_mode = "ro"

        args.append(f"--volume {dq(source_path)}:{dq(container_path)}:{file_mode}")
        log_msg(f"  Mounting credential '{credential_name}' to {container_path} (mode: {file_mode})")
    return args


def _base_run_args(spec, service_type, wl_lifecycle, systemd_mode):
    """Base podman run/create invocation: name/hostname/rm/replace/init/
    systemd/sdnotify/pull/log-driver.

    The last three are passed rather than read off `spec` because the caller
    did not read them, it DECIDED them: `service_type` and `wl_lifecycle` each
    have a validity check and a warn-and-fall-back path, and `systemd_mode` is
    lowercased and whitelisted with an invalid value ABORTING unit generation
    outright. A resolved decision that arrives looking like a config read is
    how a fallback stops being visible at the point it matters -- and reading
    `container["container"]["systemd"]` off the spec here would silently
    restore the raw, unchecked value on the one path that must not have it.
    """
    container_name_quoted = spec.container_name_quoted
    mode, name = spec.mode, spec.name
    pull_policy = spec.pull_policy
    args = [
        "/usr/bin/podman run" if wl_lifecycle == "cattle" else "/usr/bin/podman create",
        f"--name {container_name_quoted}",
    ]
    # In pod mode the container joins the pod's UTS namespace, so it cannot
    # set its own hostname (podman rejects it). Single and bridge mode each
    # own their UTS namespace and take a hostname normally.
    if mode != "pod":
        args.append(f"--hostname {dq(name)}")
    if wl_lifecycle == "cattle":
        args.append("--rm")
        # --replace removes a same-named container leftover from an unclean shutdown
        # (OOM kill, SIGKILL) before starting, breaking the "name already in use" loop.
        args.append("--replace")

    # --init provides a minimal init process (tini) for signal handling.
    # Skip when container.systemd is set — the container either runs systemd
    # as PID 1 or has its own init/entrypoint.
    if systemd_mode is None:
        args.append("--init")
    else:
        args.append(f"--systemd={systemd_mode}")

    # Use sdnotify=conmon only when the unit type is notify; otherwise ignore.
    sdnotify = "conmon" if service_type == "notify" else "ignore"
    args.extend([
        f"--sdnotify={sdnotify}",
        f"--pull={pull_policy}",
        # passthrough: conmon hands the container's stdout/stderr fds straight
        # to the unit's journal stream (single copy, named via the unit's
        # SyslogIdentifier=). The journald driver would double-log every line:
        # once tagged by conmon, once as untagged podman[pid] via the attached
        # foreground `podman run` relaying container output to unit stdout.
        # NOTE: journald attributes these passthrough lines to the rootless user
        # manager's cgroup (user@<uid>.service), not this .service unit, so
        # `journalctl -u` misses them — `workloadctl logs` ORs the container's
        # SyslogIdentifier in to catch them (see cmd_interact._journal_selection).
        "--log-driver=passthrough",
    ])
    return args


def _security_args(spec):
    """--user/--cap-add/--security-opt (selinux label, seccomp baseline,
    privileged)/--group-add=keep-groups flags from [security].

    Reads BOTH levels on purpose: capabilities and security_opt are
    per-container, while selinux_policy, privileged and extra_groups are
    workload-level (one uid, one policy module per workload) and a
    per-container spelling of them is warned about and ignored below.
    """
    container, config = spec.container, spec.workload
    mode, name = spec.mode, spec.name
    privileged, extra_groups = spec.privileged, spec.extra_groups
    args = []

    # Override the container image's USER directive if specified
    container_user = container.get("container", {}).get("user", "")
    if container_user:
        args.append(f"--user={container_user}")

    capabilities = container.get("security", {}).get("capabilities", [])
    for cap in capabilities:
        args.append(f"--cap-add={cap}")

    # ${WORKLOAD_*} expands against the *instance* name, not the bundle's: a
    # seccomp= profile written by a [host] setup script lives beside the
    # instance's own workload.toml, and `init --as` makes those two names
    # differ. Pure string substitution — no I/O, boot-path safe.
    security_opts = container.get("security", {}).get("security_opt", [])
    expanded_opts = []
    for opt in security_opts:
        try:
            expanded_opts.append(expand_workload_tokens(opt, name))
        except ValueError as e:
            # Never block boot on a bad token. Dropping the opt is the
            # conservative direction — a dropped seccomp= falls back to the
            # baseline below rather than running unfiltered.
            log_msg(f"WARNING: {name}: ignoring security_opt {opt!r}: {e}",
                    level="warning")
    security_opts = expanded_opts
    for opt in security_opts:
        args.append(f"--security-opt={opt}")

    # Per-workload SELinux type: launch the container under wl_<name>.process
    # instead of widening the shared container_t/container_init_t domains (a
    # global semodule load). The matching CIL policy module is loaded by the CLI
    # on enable; here we only apply the label, which is a pure string function of
    # the workload name — no I/O, boot-path safe.
    # selinux_policy is a workload-level decision (one module per workload, keyed
    # on the workload name). Read it from the top-level [security] block so the
    # label matches what cmd_enable loads in all modes including multi-container.
    workload_selinux = config.get("security", {}).get("selinux_policy")
    if mode != "single" and container.get("security", {}).get("selinux_policy"):
        log_msg(f"WARNING: {name}/{container.get('name', '?')} sets selinux_policy "
                f"under [containers.security]; this is ignored. Set selinux_policy "
                f"in the top-level [security] block to apply it to all containers "
                f"in this workload.", level="warning")
    if workload_selinux:
        args.append(f"--security-opt=label=type:{selinux_type_name(name)}")

    # Apply baseline seccomp profile unless the workload overrides it or uses --privileged
    # (--privileged disables seccomp anyway; adding it would just be noise)
    if not privileged and not any(opt.startswith("seccomp=") for opt in security_opts):
        args.append(f"--security-opt=seccomp={SECCOMP_BASELINE}")

    if privileged:
        log_msg(f"WARNING: {name} uses privileged=true. "
                f"Consider using specific capabilities for better security.", level="warning")
        args.append("--privileged")

    # Pass host supplementary groups into the container.
    # keep-groups preserves all supplementary groups from the host process and
    # is required for @GID userns delegation in --gidmap +GID:@GID:1.
    # The workload user is added to extra_groups via sysusers 'm' directive.
    if extra_groups:
        args.append("--group-add=keep-groups")

    return args


def _device_args(spec):
    """--device flags: generic passthrough + input/audio/virtualization
    convenience flags from [devices].

    --device is for single device NODES (and CDI names). A device DIRECTORY
    passed as --device has its child nodes enumerated and frozen into the OCI
    spec at container-create time, so a reused ("pet") container breaks when
    device numbering renumbers across a reboot. Device directories must be
    bind-mounted via [storage] volumes instead (resolved live at start) -- the
    generic `devices` list stays literal --device, and the convenience flags
    below emit volumes for their directory parts (/dev/input, /dev/snd)."""
    container, uid = spec.container, spec.uid
    args = []
    devices_config = container.get("devices", {})
    generic_devices = devices_config.get("devices", [])
    for device in generic_devices:
        args.append(f"--device {device}")

    # CONVENIENCE FLAGS (multi-device shortcuts)

    # Input devices: /dev/input is a directory (volume, tracks renumbering),
    # /dev/uinput is a single node.
    if devices_config.get("input", False):
        args.extend([
            "--volume /dev/input:/dev/input",
            "--device /dev/uinput",
        ])

    # Audio devices (directory + socket auto-detection)
    if devices_config.get("audio", False):
        args.append("--volume /dev/snd:/dev/snd")
        # Mount PulseAudio/PipeWire sockets. XDG_RUNTIME_DIR is deterministically
        # /run/user/<uid> (set by workload-ensure-user's EnvironmentFile), and uid
        # is already known at generation time -- embed it directly rather than
        # relying on ${XDG_RUNTIME_DIR} runtime expansion, which resolves to an
        # empty string (mounting host "/pulse") if the EnvironmentFile is missing.
        for suffix in ["pulse", "pipewire-0"]:
            args.append(f"--volume /run/user/{uid}/{suffix}:/run/user/{uid}/{suffix}:ro")

    # Virtualization devices (3 devices)
    if devices_config.get("virtualization", False):
        args.extend([
            "--device /dev/kvm",
            "--device /dev/vhost-net",
            "--device /dev/vhost-vsock",
        ])

    return args


def _cgroup_args(spec):
    """--shm-size/--pids-limit/--memory/--cpus/--cpu-shares/--device-read-bps/
    --device-write-bps flags from [resources], plus their warnings."""
    container, name, mode = spec.container, spec.name, spec.mode
    args = []

    # Shared memory size
    shm_size = container.get("resources", {}).get("shm_size", "")
    if shm_size:
        args.append(f"--shm-size={shm_size}")

    # Container PID limit (podman default is 2048, independent of systemd TasksMax)
    tasks_max = container.get("resources", {}).get("tasks_max", 0)
    if tasks_max:
        args.append(f"--pids-limit={tasks_max}")

    # Per-container cgroup limits via podman flags. Under option 1b (non-split
    # topology) payloads live in a transient libpod scope under the user manager;
    # podman flags write directly to the scope's cgroup files via OCI/crun, so they
    # bind in all modes (single/bridge/pod).
    # Workload-level limits (aggregate cap for the whole user manager) are in the
    # user@<uid>.service.d drop-in; these per-container flags add finer-grained OOM
    # scoping on top.
    c_res = container.get("resources", {})
    if "memory_max" in c_res:
        args.append(f"--memory={c_res['memory_max']}")
    if "cpu_quota" in c_res:
        # CPUQuota is a percentage string ("50%"); --cpus takes a float (0.5 = ½ core)
        try:
            cpus_val = str(float(c_res["cpu_quota"].rstrip("%")) / 100)
            args.append(f"--cpus={cpus_val}")
        except (ValueError, AttributeError):
            log_msg(f"WARNING: {name}: cannot convert cpu_quota "
                    f"'{c_res['cpu_quota']}' to --cpus; skipping", level="warning")
    if "cpu_weight" in c_res:
        args.append(f"--cpu-shares={c_res['cpu_weight']}")
    if "memory_high" in c_res and mode != "single":
        # ADR 001 source-verified: no podman flag writes memory.high.
        # --memory-reservation maps to memory.low, not memory.high.
        # Use workload-level memory_high (in the drop-in) for soft limits.
        #
        # Only reachable from a per-container [[containers]].resources block. In
        # single mode normalize_containers() copies the *workload-level*
        # [resources] table in here, and that one is already honoured verbatim as
        # MemoryHigh= in the user@<uid> drop-in — warning about it would tell the
        # author to do the thing they just did.
        log_msg(f"WARNING: {name}/{container['name']}: per-container memory_high is "
                f"not settable via podman flags (ADR 001); use workload-level "
                f"memory_high instead", level="warning")
    for spec in c_res.get("io_read_bandwidth_max", []):
        parts = spec.split(None, 1)
        if len(parts) == 2:
            args.append(f"--device-read-bps={parts[0]}:{parts[1]}")
    for spec in c_res.get("io_write_bandwidth_max", []):
        parts = spec.split(None, 1)
        if len(parts) == 2:
            args.append(f"--device-write-bps={parts[0]}:{parts[1]}")

    return args


def _network_args(spec):
    """--network/--publish/--network-alias flags: single/pod/bridge mode."""
    mode, workload = spec.mode, spec.workload
    name, container = spec.name, spec.container
    args = []
    if mode == "single":
        network_config = workload.get("network", {})
        network_mode = network_config.get("mode", "pasta")  # Default to pasta (works in Podman 5.3+)

        args.append(f"--network={dq(network_mode)}")
        if network_mode not in ("host", "none"):
            for port in network_config.get("ports", []):
                args.append(f"--publish {port}")
    elif mode == "pod":
        args.append(f"--pod={dq(f'workload-{name}')}")
    else:  # bridge
        args.append(f"--network={dq(f'workload-{name}-net')}")
        # Publish the short container name as a DNS alias so siblings resolve
        # each other by name (e.g. "db"); the --name is workload-{name}-{ctr}.
        args.append(f"--network-alias={dq(container['name'])}")
        for port in container.get("network", {}).get("ports", []):
            args.append(f"--publish {port}")
    return args


def _rw_path_is_bindable(resolved):
    """Can `resolved` be named in ReadWritePaths= -- and does it need to be?

    Both answers are no for a socket, fifo or device node, and getting this
    wrong is fatal rather than merely wide: systemd bind-mounts every
    ReadWritePaths= entry inside the unit's namespace, and the targeted policy
    does not let init_t `mounton` a sock_file, so the unit dies at namespace
    setup with a bare 226/NAMESPACE (`avc: denied { mounton } ...
    tcontext=...:syslogd_var_run_t tclass=sock_file`). Four shipped bundles
    mount /run/systemd/journal/socket that way.

    Nor is the entry needed: the kernel's read-only-filesystem check
    (sb_permission) returns EROFS only for S_ISREG/S_ISDIR/S_ISLNK, so
    connecting to a unix socket or writing a fifo/device works fine under
    ProtectSystem=strict.

    An unstattable path is treated as bindable -- an out-of-tree volume on a
    filesystem that is not mounted yet is the common case here (that is what
    RequiresMountsFor= is for) and it is virtually always a directory.
    """
    if not os.path.exists(resolved):
        return True
    return os.path.isdir(resolved) or os.path.isfile(resolved)


def _volume_args(spec):
    """--volume flags: [storage].volumes expansion, escape-warn, quoting.

    Returns (args, external_paths, external_rw_paths). `external_paths` are the
    host paths that resolve outside the workload tree, deduplicated in
    declaration order, for the caller to turn into RequiresMountsFor= -- see
    _unit_deps. `external_rw_paths` is the subset of those the container may
    write, for ReadWritePaths= -- see _hardening.

    WHY THE SECOND LIST. `_hardening` sets ProtectSystem=strict, which mounts
    the whole hierarchy read-only inside the unit's namespace, and a
    ReadWritePaths= naming only the workload tree. podman bind-mounts the host
    path *out of that namespace*, so an out-of-tree volume reaches the container
    read-only however it is declared: the guest gets EROFS on a directory it
    owns, on a filesystem that is mounted rw, with no denial logged anywhere.
    Measured on a plain container_file_t directory owned by the workload user,
    so it is not about labels or ownership. The virtiofs sidecar never had this
    bug because generate_virtiofs_service names its share explicitly.

    A volume the operator declared `:ro` is deliberately left out: podman would
    enforce read-only in the container anyway, so adding it would widen what the
    unit may write to buy nothing. So is anything that is not a directory or a
    regular file -- see _rw_path_is_bindable, where naming it is both
    unnecessary and fatal.
    """
    container, home_dir, name = spec.container, spec.home_dir, spec.name
    args = []
    external = []
    external_rw = []
    for volume in container.get("storage", {}).get("volumes", []):
        expanded = expand_volume_path(volume, home_dir)
        if ':' in expanded:
            parts = expanded.split(':', 2)
            # Warn if host path escapes the workload home directory
            resolved = _external_host_path(parts[0], name)
            if resolved is not None:
                log_msg(f"  WARNING: volume host path '{parts[0]}' resolves to "
                        f"'{resolved}' outside workload dir "
                        f"'{workload_root_dir(name)}'", level="warning")
                if resolved not in external:
                    external.append(resolved)
                opts = parts[2].split(',') if len(parts) > 2 else []
                if ('ro' not in opts and resolved not in external_rw
                        and _rw_path_is_bindable(resolved)):
                    external_rw.append(resolved)
            expanded = ':'.join(dq(p) for p in parts)
        else:
            expanded = dq(expanded)
        args.append(f"--volume {expanded}")
    return args, external, external_rw


def _env_args(spec):
    """--env flags: HOST_IP, plain container env vars, and (if any env var
    references a secret) the per-container --env-file written by
    workload-write-env."""
    container, container_name = spec.container, spec.container_name
    has_secret_env_vars = spec.has_secret_env_vars
    args = ["--env HOST_IP=${HOST_IP}"]
    # Plain env vars go as --env args; secret env vars go via --env-file
    args.extend(build_plain_env_args(container))
    if has_secret_env_vars:
        # Per-container secrets file: each container has its own
        # LoadCredentialEncrypted/CREDENTIALS_DIRECTORY, so a shared file
        # would race when multiple containers in the same workload start.
        secrets_env_file = f"/run/workload-env/{container_name}.secrets"
        args.append(f"--env-file {dq(secrets_env_file)}")
    return args


def _unit_deps(u, workload, mode, unit_description, setup_service, pod_service,
                net_service, umbrella_service, gpu_vendor,
                external_volume_paths=()):
    """[Unit] Description/Requires/After/Wants/BindsTo/PartOf + nvidia deps
    + RequiresMountsFor= for volume host paths outside the workload tree."""
    u.set("Description", unit_description)
    if mode == "single":
        u.add("Requires", setup_service)
        u.add("After", f"network.target {setup_service}")
    else:
        # pod mode binds to the pod-create service; bridge mode to the
        # network-create service.
        dep_service = pod_service if mode == "pod" else net_service
        u.add("Requires", dep_service)
        u.add("After", dep_service)
        u.add("BindsTo", dep_service)
        u.add("PartOf", umbrella_service)
    u.set("StartLimitIntervalSec", 300)
    u.set("StartLimitBurst", 5)

    # [workload].requires → Wants= (start them if possible, but don't fail us)
    # [workload].after    → After= (ordering only, no dependency)
    wl_requires = workload.get("workload", {}).get("requires", [])
    wl_after = workload.get("workload", {}).get("after", [])
    if wl_requires:
        wants = " ".join(f"workload-{n}.service" for n in wl_requires)
        u.add("Wants", wants)
    if wl_after:
        after_deps = " ".join(f"workload-{n}.service" for n in wl_after)
        u.add("After", after_deps)

    if gpu_vendor == "nvidia":
        u.add("Requires", "nvidia-cdi-generator.service")
        u.add("After", "nvidia-cdi-generator.service")

    # A volume host path outside the workload tree can be its own filesystem.
    # RequiresMountsFor= pulls in and orders after the mount unit backing each
    # one, so a filesystem that is absent or fails to mount stops the workload.
    # Without it the failure is silent and looks healthy: podman creates the
    # missing bind source, and the container comes up over an empty directory.
    if external_volume_paths:
        u.add("RequiresMountsFor",
              " ".join(uq(p) for p in external_volume_paths))


def _service_identity(svc, service_type, slice_name, systemd_mode, user_name, home_dir, name):
    """[Service] Type/Slice/NotifyAccess/KillSignal/User/Group/Environment/
    EnvironmentFile. No possible earlier same-key line for any of these
    (they run before the custom_directives splice) -- .set() is safe here."""
    svc.set("Type", service_type)
    svc.set("Slice", slice_name)

    # NotifyAccess only needed for Type=notify
    if service_type == "notify":
        svc.set("NotifyAccess", "all")

    # systemd containers need SIGRTMIN+3 for clean shutdown
    if systemd_mode in ("always", "true"):
        svc.set("KillSignal", "SIGRTMIN+3")

    svc.set("User", user_name)
    svc.set("Group", user_name)
    svc.set("Environment", f'"HOME={home_dir}"')
    svc.set("EnvironmentFile", f"-/run/workload-env/workload-{name}.env")
    svc.blank()


def _credential_loads(svc, credentials):
    """LoadCredentialEncrypted= for each auto-detected credential."""
    if credentials:
        svc.comment("Load encrypted credentials (auto-decrypted to /run/credentials/{service}/)")
        # sorted() so unit output is reproducible: auto_detect_credentials
        # returns a set, whose iteration order otherwise varies per process.
        for cred_name in sorted(credentials):
            cred_file = f"/etc/credstore.encrypted/{cred_name}"
            svc.add("LoadCredentialEncrypted", f"{cred_name}:{cred_file}")
        svc.blank()


def _exec_start_pre(svc, mode, name, container, has_secret_env_vars, gpu_vendor, uid):
    """ExecStartPre chain: write-env, nvidia CDI-spec check, and (single mode
    only) the fresh-pause cleanup that works around the pasta stale-pause bug."""
    if has_secret_env_vars:
        # Multi-container: pass the local container name so workload-write-env
        # resolves *that* container's env vars only and writes the matching
        # per-container secrets file. Single-mode keeps the legacy one-arg form.
        if mode == "single":
            svc.add("ExecStartPre", f"+/usr/libexec/workloadctl/workload-write-env {name}")
        else:
            svc.add(
                "ExecStartPre",
                f"+/usr/libexec/workloadctl/workload-write-env "
                f"{name} {container['name']}",
            )

    if gpu_vendor == "nvidia":
        svc.add(
            "ExecStartPre",
            "/bin/bash -c "
            "'test -s /run/cdi/nvidia.yaml"
            " || { echo \"NVIDIA CDI spec missing: check nvidia-cdi-generator.service\" >&2; exit 1; }'",
        )

    if mode == "single":
        # Force a *fresh* libpod pause process before the first podman touch of
        # this invocation. Trigger: any pasta-networked workload. pasta's
        # prefork isolation does mount("","/tmp","tmpfs")+pivot_root (passt
        # isolation.c, TMPDIR==/tmp, compile-time) — if /tmp doesn't resolve in
        # pasta's mount ns it dies with "Failed to mount empty tmpfs for
        # pivot_root(): ENOENT" and the unit restart-loops to StartLimitBurst.
        # How /tmp goes missing: a pause that outlives the previous activation
        # (podman moves it into podman-pause-*.scope under user@<uid>, where it
        # survives the unit stop) still pins that activation's PrivateTmp /tmp,
        # which systemd already deleted. The next `podman run` takes the rootless
        # join shortcut (rootless_linux.c can_use_shortcut → join_namespace_or_die
        # "mnt") and *inherits that dead mount ns*. NB the join is userns-agnostic
        # — keep-id vs userns=host is irrelevant; only pasta (vs --network=host,
        # which spawns no pasta) is the trigger.
        #   `podman system migrate` is necessary but not sufficient: it stops all
        # running containers first and returns *before* killing the pause if any
        # stop errors (runtime_migrate.go), and it's tolerant ("-"). So we also
        # rm pause.pid + ns_handles unconditionally — that makes the shortcut
        # fall through so `podman run` builds a fresh pause in the live (valid)
        # mount ns. migrate runs first so it can still SIGKILL the tracked pause;
        # the rm cleans up when migrate couldn't. Both tolerant so first boot
        # (no rundir/handles yet) never blocks startup. Pod/bridge members must
        # NOT do this (it would kill the pause out from under the live pod infra
        # / sibling containers) — their head units handle it.
        svc.add("ExecStartPre", "-/usr/bin/podman system migrate")
        svc.add(
            "ExecStartPre",
            f"-/usr/bin/rm -f /run/user/{uid}/libpod/tmp/pause.pid"
            f" /run/user/{uid}/libpod/tmp/ns_handles",
        )

    svc.blank()


def _lifecycle_exec(svc, wl_lifecycle, podman_cmd, container_name_quoted, pull_policy,
                     mode, uid, resources):
    """run-vs-pet ExecStart + ExecStop/ExecStopPost."""
    if wl_lifecycle == "pet":
        # Pet lifecycle: create the container once; subsequent starts reuse the
        # writable overlay.  The "-" prefix on create ignores "name already in
        # use" so the unit starts cleanly after a plain reboot.
        # --pull is honoured on the initial create; later starts use whatever
        # image the overlay was originally built from.
        svc.comment("Pet lifecycle: create-once + start (overlay survives stop/reboot)")
        svc.add("ExecStartPre", f"-{podman_cmd}")
        svc.blank()
        svc.add("ExecStart", f"/usr/bin/podman start -a {container_name_quoted}")
    else:
        svc.comment(f"Image pulling handled by podman run --pull={pull_policy}")
        svc.blank()
        svc.add("ExecStart", podman_cmd)

    svc.blank()

    # podman's own container-stop grace (-t): how long the container gets to
    # exit on the stop signal before podman SIGKILLs it. Keep it a few seconds
    # under the unit's TimeoutStopSec so systemd doesn't kill `podman stop`
    # before podman can do its own SIGKILL + reap. Tracks timeout_stop_sec when
    # set (so a write-heavy workload's longer drain actually reaches podman);
    # otherwise stays the historical 10s (systemd default TimeoutStopSec=30).
    # (resources dict is already set above from container.get("resources", {}))
    stop_grace = resources.get("timeout_stop_sec")
    try:
        podman_stop_timeout = (
            max(1, int(stop_grace) - 5) if stop_grace is not None else 10
        )
    except (TypeError, ValueError):
        # timeout_stop_sec given as a systemd timespan (e.g. "2min"); fall back
        # to the safe default rather than guessing a seconds value.
        podman_stop_timeout = 10

    svc.add("ExecStop", f"/usr/bin/podman stop -t {podman_stop_timeout} {container_name_quoted}")
    # Under option 1b payloads live in the user manager's cgroup, not the unit's
    # cgroup, so KillMode=control-group can't reach them. ExecStopPost force-removes
    # any container that survived ExecStop (e.g. a SIGKILLed podman client).
    # Pod mode is excluded: the pod-create service already has ExecStop=podman pod rm
    # which tears down all member containers; per-container services don't need it.
    # Pet mode is excluded: the overlay must survive stop — never rm a pet container.
    if mode != "pod" and wl_lifecycle != "pet":
        svc.add("ExecStopPost", f"-/usr/bin/podman rm -f -t0 {container_name_quoted}")
    svc.blank()


def _logging(svc, container_name, resources):
    """StandardOutput/Error/SyslogIdentifier + LogRateLimit* defaults."""
    custom_d = resources.get("custom_directives", {})
    svc.add("StandardOutput", "journal")
    svc.add("StandardError", "journal")
    # Name the journal stream after the container so passthrough log lines
    # read `workload-<name>[pid]: ...` (members: workload-<wl>-<ctr>).
    # Podman's own messages (pull errors etc.) share the identifier.
    svc.add("SyslogIdentifier", container_name)
    if "LogRateLimitIntervalSec" not in custom_d:
        svc.add("LogRateLimitIntervalSec", 30)
    if "LogRateLimitBurst" not in custom_d:
        svc.add("LogRateLimitBurst", 250)
    svc.blank()


def _hardening(svc, name, uid, resources, external_rw_paths=()):
    """Restart/RestartSec + filesystem/socket-family hardening + default timeouts.

    `external_rw_paths` are writable volume host paths outside the workload tree
    (see _volume_args). Without them ProtectSystem=strict hands podman a
    read-only source and the container gets EROFS with nothing logged.
    """
    svc.add("Restart", "on-failure")
    svc.add("RestartSec", "5s")
    svc.blank()
    svc.comment("Filesystem hardening: restrict writes to workload home + podman runtime")
    svc.add("ProtectSystem", "strict")
    rw = f'"{str(workload_root_dir(name))}" /run/user/{uid}'
    if external_rw_paths:
        svc.comment("Writable out-of-tree volumes: ProtectSystem=strict would")
        svc.comment("otherwise make podman's bind source read-only (EROFS in the")
        svc.comment("container, no denial logged).")
        rw += " " + " ".join(uq(p) for p in external_rw_paths)
    svc.add("ReadWritePaths", rw)
    svc.add("PrivateTmp", "yes")
    svc.comment("Socket-family hardening: deny AF_ALG (CVE-2026-31431 LPE vector) and")
    svc.comment("AF_PACKET tree-wide, covering the host _wl- podman process too. Deny-list")
    svc.comment("(~) keeps AF_INET/AF_UNIX/AF_NETLINK for pasta networking + getaddrinfo.")
    svc.add("RestrictAddressFamilies", "~AF_ALG AF_PACKET")

    if "timeout_start_sec" not in resources:
        svc.add("TimeoutStartSec", 300)
    if "timeout_stop_sec" not in resources:
        svc.add("TimeoutStopSec", 30)


def _container_egress_exec(svc, name: str) -> None:
    """Element-lifecycle ExecStartPre/ExecStopPost for one container
    workload's egress policy (P1-7 in the container egress-parity build
    spec). Mirrors the VM hook shape at generate_vm_workload's
    `workload-vm-filter up/down` pair -- same `+`/`-+` prefixes, same
    tolerant-on-teardown reasoning (see workload-vm-filter's module
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


def _container_credential_env_args(spec) -> list:
    """`--env <ENV>=<placeholder>` for each declared credential.

    The container half of the fiction, and without it the brokered path does
    not work at all: the container holds nothing in the variable its client
    reads, so either the client refuses to send a request (failing INSIDE the
    container, before a packet, which looks nothing like a policy failure) or
    it sends one with no authorisation header for the broker's substitution to
    replace -- and the provider answers 401 on a request every layer here
    authorised. Same job as vm_credential_env() in the VM's cloud-init seed.

    The placeholder is not a secret and is refused if it equals the real
    material, so it is safe on a podman command line in a generated unit --
    which is where the CA variables one function down already are.
    """
    workload = spec.workload
    net = workload.get("network", {}) or {}
    if not container_uses_credentials(workload):
        return []
    return [f"--env {cred.env}={dq(cred.placeholder)}"
            for cred in container_credential_entries(net)]


def _container_ca_delivery_args(spec) -> list:
    """--volume / --env podman flags delivering this workload's egress CA
    into one container, per [network].ca_delivery (P1-10, G12-G15's
    container counterpart).

    "image" needs no action here -- the claim is that the image already
    trusts this workload's CA (validate_container_network refuses the value
    on a bundle with no Containerfile, so the claim was at least plausible
    at validate time; R9 -- this cannot VERIFY it, only the operator's
    assertion is on record).

    "mount" and "env" both bind the CA certificate generated by
    generate_egress_ca/provision_egress_pki_dirs (libexec/workload-ensure-user
    -- fully name-keyed already, reused verbatim for containers, see that
    file's G12 comment) into the container read-only. "env" additionally
    points the same five variables the VM guest gets (VM_CA_ENV_VARS) at a
    FIXED in-container path -- VM_CA_BUNDLE_PATH, reused rather than
    inventing a container-only constant, since it names nothing VM-specific
    (just a conventional certificate path) and keeping one constant is what
    lets a future reader search for the one path both substrates present a
    CA at. "mount" instead uses the operator's own ca_mount_path -- their
    entrypoint installs it into the image's trust store, so workloadctl's
    job is only to land the bytes there, never to also set the five vars
    (that would tell the client to distrust the very install the operator
    asked for).

    This needs a policy grant. The source
    path is labelled by provision_egress_pki_dirs for the host-side inspector's own
    read access (comment there: "a directory the inspector creates for itself
    inherits svirt_image_t"), and a plain bind-mount with no `:Z`/`:z` was
    EACCES from inside the container: `avc: denied { read } ...
    tcontext=...wlinspect_ca_t`. Relabelling the source is the wrong fix -- it
    would break the inspector's own access to the same path -- so the grant
    went the other way, in security/workload-inspect.cil, to the
    container_domain attribute rather than to container_t (a workload with
    [security] selinux_policy runs as its own udica-derived type and is not
    container_t; see that file for the whole argument). No `:Z` here on
    purpose: the label is deliberate and shared.
    """
    workload, name = spec.workload, spec.name
    net = workload.get("network", {}) or {}
    if not container_uses_inspect(workload):
        return []
    delivery = container_ca_delivery(net)
    if delivery in (None, "image"):
        return []
    cert_path = str(vm_ca_cert_path(workload_state_dir(name)))
    if delivery == "mount":
        dest = container_ca_mount_path(net)
        if not dest:
            return []
        return [f"--volume {dq(cert_path)}:{dq(dest)}:ro"]
    # "env"
    args = [f"--volume {dq(cert_path)}:{dq(VM_CA_BUNDLE_PATH)}:ro"]
    for var in VM_CA_ENV_VARS:
        args.append(f"--env {var}={dq(VM_CA_BUNDLE_PATH)}")
    return args


def generate_system_service(workload, container, user_name, uid, mode="single"):
    """Generate systemd system service for rootless podman execution.

    Requires the setup service to have created the user first.

    'workload' is the full parsed TOML (used for workload-level fields like
    [network] and [setup]); 'container' is one element of
    normalize_containers(workload). 'mode' is "single", "pod", or "bridge".
    """
    name = workload["workload"]["name"]
    if mode == "single":
        container_name = f"workload-{name}"
    else:
        container_name = f"workload-{name}-{container['name']}"
    home_dir = str(workload_state_dir(name))

    image = container["container"]["image"]
    command = container["container"].get("command", None)
    gpu_type = container.get("devices", {}).get("gpu", "none")
    if gpu_type == "auto":
        gpu_type = resolve_auto_gpu(name)
    # "nvidia:<spec>" pins a specific GPU via the CDI device name (UUID or index).
    # When a spec is set, only that GPU's DRM nodes are mounted — the umbrella
    # /dev/dri is dropped so the other GPUs are invisible inside the container.
    gpu_vendor, _, gpu_spec = gpu_type.partition(":")
    setup_service = f"workload-{name}-setup.service"
    pod_service = f"workload-{name}-pod.service"
    net_service = f"workload-{name}-net.service"
    umbrella_service = f"workload-{name}.service"
    # Slice assignment (default: workloads.slice). In pod mode, slice is
    # workload-level; in single mode it lives on the (only) container.
    if mode == "single":
        slice_name = container.get("resources", {}).get("slice", "workloads.slice")
    else:
        slice_name = workload.get("resources", {}).get("slice", "workloads.slice")

    if mode == "single":
        unit_description = f"{name} rootless workload"
    else:
        unit_description = f"{name}/{container['name']} container"

    # Expanded ahead of the [Unit] section: the host paths that land outside the
    # workload tree become RequiresMountsFor= there, and the flags themselves go
    # into podman_args further down.
    spec = RunSpec(workload=workload, container=container, uid=uid,
                   name=name, container_name=container_name, mode=mode)
    volume_args, external_volume_paths, external_rw_paths = _volume_args(spec)

    unit = Unit()
    if mode == "single":
        unit.comment(f"Rootless workload service for {name}")
    else:
        unit.comment(f"Container service for {name}/{container['name']}")
    unit.comment(GENERATED_BY)

    u = unit.section("Unit")
    _unit_deps(u, workload, mode, unit_description, setup_service, pod_service,
               net_service, umbrella_service, gpu_vendor, external_volume_paths)
    # Requires=, not Wants=: mirrors generate_vm_workload's prereqs.append for
    # the VM's inspect socket. Without this the socket is generated but never
    # started, so port-80/443 traffic that should be redirected into the
    # inspector just hangs -- the workload looks healthy while nothing on
    # those ports is reachable. Single mode only: this unit IS the
    # workload-level service here (see the P1-7 gate below); pod/bridge mode
    # gets the same wiring on the pod/net head unit instead, which is the one
    # unit ordered ahead of every member container (see _head_unit).
    if mode == "single" and container_uses_inspect(workload):
        u.add("Requires", f"workload-{name}-inspect.socket")
        u.add("After", f"workload-{name}-inspect.socket")
    # And the broker instance, on the same terms and for the same reason its
    # twin is on the head unit in pod/bridge mode: the `Before=` the generator
    # gives the instance ORDERS it, and nothing else pulls it in. See
    # _head_unit.
    if mode == "single" and container_uses_credentials(workload):
        u.add("Requires", f"workload-{name}-broker.service")
        u.add("After", f"workload-{name}-broker.service")

    # container.systemd: "always", "true", "false", or unset
    systemd_mode = container.get("container", {}).get("systemd", None)
    if systemd_mode is not None:
        systemd_mode = str(systemd_mode).lower()
        valid_systemd = ("always", "true", "false")
        if systemd_mode not in valid_systemd:
            log_msg(f"ERROR: Invalid container.systemd='{systemd_mode}' for {name}. "
                    f"Valid values: {', '.join(valid_systemd)}.", level="err")
            return None

    # service_type is read here (before podman_args) so --sdnotify can match.
    # Default is "exec": activates once podman starts, no READY handshake needed.
    # "notify" does not work under the SHIPPED cgroup topology (ADR 001 option 1b:
    # no --cgroups=split, so conmon+payload migrate into user@<uid>.service).
    # systemd attributes an sd_notify datagram to the unit owning the *sender's*
    # cgroup, and under 1b the READY=1 emitter always lives in user@<uid>.service's
    # cgroup, never workload-<name>.service's: with --sdnotify=conmon the sender is
    # conmon; with --sdnotify=healthy it is the re-exec'd libpod podman migrated
    # into the same user-manager scope. Either way systemd credits the wrong unit
    # and the workload never goes active; no NotifyAccess tweak helps (the sender
    # is not in the unit's cgroup at all). This is a property of the non-split
    # topology, NOT a fundamental rootless+linger limit: under --cgroups=split +
    # Delegate=yes (ADR 001 option 1) conmon lands in workload-<name>.service's own
    # cgroup and Type=notify reaches active in 0s. Adopting it would revert the
    # split tax 1b was chosen to shed, so exec stays the default. Readiness
    # gating uses --health-cmd + the CLI's health-verified flow. See ADR 001
    # (item 8 and its addendum) and llms.txt.
    service_type = container.get("resources", {}).get("service_type", "exec")
    valid_types = ["simple", "exec", "forking", "oneshot", "dbus", "notify", "idle"]
    if service_type not in valid_types:
        log_msg(f"WARNING: Invalid service_type '{service_type}' for {name}. "
                f"Valid types: {', '.join(valid_types)}. Defaulting to 'exec'.",
                level="warning")
        service_type = "exec"

    container_name_quoted = dq(container_name)

    # Lifecycle: "cattle" (default, byte-identical to the historic unit shape) or
    # "pet" (durable overlay — create-once + start/stop, no --rm).
    # pet is only supported for single mode today; pod/bridge fall back to cattle
    # with a warning so a misconfigured TOML never blocks boot.
    wl_lifecycle = workload["workload"].get("lifecycle", "cattle")
    if wl_lifecycle == "pet" and mode != "single":
        log_msg(
            f"WARNING: {name}: lifecycle=pet is only supported in single mode "
            f"(mode={mode!r}); falling back to cattle for this workload.",
            level="warning",
        )
        wl_lifecycle = "cattle"

    podman_args = _base_run_args(spec, service_type, wl_lifecycle, systemd_mode)

    # User namespace / UID-GID maps.
    # In pod mode the user namespace is owned by the pod's infra container and
    # is set on `podman pod create` (see generate_pod_service); member
    # containers cannot set their own and podman rejects the attempt. Single
    # and bridge mode each own their userns and set it on the container.
    if mode == "pod":
        if container.get("security", {}).get("userns") is not None:
            log_msg(f"WARNING: {name}/{container['name']} sets [security].userns; "
                    f"ignored in pod mode (userns is workload-level — set it in "
                    f"the top-level [security] block)", level="warning")
    else:
        podman_args.extend(
            build_userns_args(container.get("security", {}), uid,
                              spec.extra_groups, name)
        )

    podman_args.extend(_security_args(spec))

    # GPU devices (convenience flag)
    podman_args.extend(_gpu_device_args(gpu_vendor, gpu_spec))

    podman_args.extend(_device_args(spec))

    podman_args.extend(_cgroup_args(spec))

    # Network configuration.
    #  - single: workload-level [network] mode + ports.
    #  - pod: the pod owns the netns; the container just joins it (no
    #    --network/--publish — podman rejects them on a pod member).
    #  - bridge: the container joins the per-workload bridge network and
    #    publishes its own [containers.network].ports.
    podman_args.extend(_network_args(spec))

    podman_args.extend(volume_args)

    # The egress CA (P1-10), delivered into every container of the workload
    # regardless of topology -- [network] is workload-level (D1: one uid, so
    # per-container granularity would be a lie), and each container process
    # makes its own outbound requests with its own trust path.
    podman_args.extend(_container_ca_delivery_args(spec))
    podman_args.extend(_container_credential_env_args(spec))

    credentials = auto_detect_credentials({
        "container": container.get("container", {}),
        "secrets":   container.get("secrets", {}),
    })
    # In multi-container modes the credential is loaded onto the per-container
    # service unit, so systemd decrypts it to /run/credentials/<container-unit>/.
    # Using the umbrella name here would point the bind-mount at the wrong dir.
    podman_args.extend(_secret_mount_args(spec))

    # HOST_IP is auto-detected by workload-ensure-user and written to the
    # EnvironmentFile; pass it into the container so configs can use it.
    podman_args.extend(_env_args(spec))

    # Health checks — podman's native user-manager timer works under 1b (non-split)
    podman_args.extend(_health_check_args(container))

    podman_args.append(dq(image))

    if command:
        if isinstance(command, list):
            podman_args.extend([dq(arg) for arg in command])
        else:
            podman_args.append(dq(command))

    podman_cmd = " ".join(podman_args)

    svc = unit.section("Service")
    _service_identity(svc, service_type, slice_name, systemd_mode, user_name, home_dir, name)

    # Service-level resource overrides only (cgroup limits live in the user@<uid> drop-in).
    resources = container.get("resources", {})
    _resource_overrides(svc, resources, name)

    _credential_loads(svc, credentials)

    _exec_start_pre(svc, mode, name, container, spec.has_secret_env_vars, gpu_vendor,
                    uid)

    _lifecycle_exec(svc, wl_lifecycle, podman_cmd, container_name_quoted, spec.pull_policy,
                     mode, uid, resources)

    _logging(svc, container_name, resources)

    _hardening(svc, name, uid, resources, external_rw_paths)

    # Egress element-lifecycle arming (P1-7): single mode only -- this unit
    # IS the workload-level service here (it gets the wants symlink below),
    # and its ExecStartPre runs ahead of the `podman run` in ExecStart. In
    # pod/bridge mode the pod/net head unit owns it, for the same "before the
    # first container" reason.
    # Gated on the config, not inside _container_egress_exec, for R10 (see
    # that function's docstring).
    if mode == "single" and container_uses_inspect(workload):
        _container_egress_exec(svc, name)

    # [Install] only on the workload-level service: in single mode that's
    # *this* unit (it gets the multi-user.target.wants symlink); in
    # multi-container mode the per-container services are pulled in by the
    # umbrella's Requires= and never get their own wants symlink, so an
    # [Install] block here is dead text.
    if mode == "single":
        inst = unit.section("Install")
        inst.set("WantedBy", "multi-user.target")

    return unit.render()


def container_broker_before(config, mode: str) -> str:
    """The unit a container workload's broker must be ordered ahead of (P2-3).

    NOT the umbrella. In pod/bridge mode `workload-<name>.service` carries
    `After=` its member services, so ordering the broker before it puts the
    broker after every container has started: the first brokered request in
    that window is refused with `credential broker unreachable` while every
    unit reads healthy. The pod/net head unit is the one workload-level unit
    ordered ahead of the members -- the same reasoning that moved the
    inspector arming there (see _head_unit).

    Single mode has no head unit, and needs none: `workload-<name>.service`
    IS the container's own unit there, so Before= it is already ahead of
    `podman run`. That asymmetry is exactly why the VM default reaches a host
    unnoticed -- single mode, the shape most bundles use, is unaffected.
    """
    name = config["workload"]["name"]
    if mode == "pod":
        return f"workload-{name}-pod.service"
    if mode == "bridge":
        return f"workload-{name}-net.service"
    return f"workload-{name}.service"
