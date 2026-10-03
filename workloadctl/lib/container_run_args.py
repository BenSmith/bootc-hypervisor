"""The `podman run` argv of a container workload.

RunSpec and the `_*_args` builders that turn one normalized container into
the flags gen_container writes into ExecStart, plus the userns mapping
`podman pod create` shares. Pure string work from the parsed TOML: nothing
here does I/O, because it all runs on the boot path.

SECCOMP_BASELINE lives here rather than in gen_common because it is a podman
argument; a VM never applies one.

Installed to /usr/libexec/workloadctl/container_run_args.py.
"""
import os
import grp
from dataclasses import dataclass
from functools import cached_property

from config_parser import workload_root_dir
from container_network_config import (
    container_ca_delivery,
    container_ca_mount_path,
    container_credential_entries,
    container_uses_inspect,
)
from workload_lib import (
    workload_state_dir, expand_volume_path, expand_workload_tokens, dq,
    selinux_type_name,
)
from moatery.egress_ca import ca_cert_path
from guest_ca import CA_ENV_VARS, CA_BUNDLE_PATH
from broker_config import container_uses_credentials
from egress_policy import container_uses_resolve
from workload_addr import resolve_address
from secrets_template import SECRET_PATTERN, validate_env_key
from gen_common import log_msg, _external_host_path
from validation import valid_userns_mode

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

    extra_uidmaps = security.get("extra_uidmaps", [])
    extra_gidmaps = security.get("extra_gidmaps", [])
    if _needs_auto_maps(security, userns_mode, extra_groups):
        # GID == UID for workload users (sysusers convention)
        gid = uid
        # Honor the optional :uid=N,gid=N suffix on keep-id, which remaps the
        # workload user to a different in-container uid/gid (e.g. for images
        # that ship a fixed non-root user). Without this, +N:@N:1 hardcodes the
        # in-container uid to the host workload uid, silently ignoring the
        # suffix that the non-needs_auto_maps branch would have honored.
        target_uid, target_gid = _keep_id_ids(userns_mode, uid)
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


def _needs_auto_maps(security, userns_mode, extra_groups):
    """True when keep-id is written as +N:@N:1 maps instead of --userns.

    When extra_groups or explicit maps are present, we emit +N:@N:1 flags
    which imply keep-id behavior.
    Podman 5.x treats --userns and --uidmap/--gidmap as mutually exclusive,
    so we must omit --userns when + prefixed maps are used.
    """
    return userns_mode.startswith("keep-id") and bool(
        extra_groups
        or security.get("extra_uidmaps")
        or security.get("extra_gidmaps")
    )


def _keep_id_ids(userns_mode, uid):
    """The in-container uid and gid a keep-id mode gives the workload user:
    its own (GID == UID), or those the :uid=N,gid=N suffix names."""
    ids = {"uid": uid, "gid": uid}
    if userns_mode.startswith("keep-id:"):
        for param in userns_mode[len("keep-id:"):].split(","):
            key, _, value = param.partition("=")
            if key in ids:
                ids[key] = int(value)
    return ids["uid"], ids["gid"]


def pod_member_user(security, uid, extra_groups):
    """The --user= a pod member that names no user is given, or None.

    `security` is the top-level block, which the pod create reads. Under
    --userns=keep-id the pod hands its keep-id user to a member that names
    none, but podman builds that member's capabilities as root's, and a
    `podman exec` or health check as that user holds all of them, ambient.
    Naming the same user puts the member on podman's non-root path: the
    user holds what [security].capabilities adds, as in single mode, where
    keep-id names the user itself. The image's USER is not used; the
    member's own user sets another. The +N:@N:1 maps and userns=host give
    the pod no user, and a member that names none runs as root.
    """
    userns_mode = security.get("userns", "keep-id")
    if not valid_userns_mode(userns_mode):
        userns_mode = "keep-id"
    if (not userns_mode.startswith("keep-id")
            or _needs_auto_maps(security, userns_mode, extra_groups)):
        return None
    return "%d:%d" % _keep_id_ids(userns_mode, uid)


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
    elif mode == "pod":
        member_user = pod_member_user(config.get("security", {}), spec.uid,
                                      extra_groups)
        if member_user:
            args.append(f"--user={member_user}")

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


def container_network_mode_arg(workload, uid) -> str:
    """The `--network=` value for a single-mode run or a pod create.

    `[network].mode` as written, except that a workload with a synthesising
    responder has pasta's `--dns-host` added. podman starts pasta with
    `--dns-forward` and names that address first in the container's
    resolv.conf; `--dns-host` sends what pasta catches there to the
    responder on the workload's own 127.130.x.y instead of to the host's
    nameservers. The other nameservers podman lists are dialled by the
    workload's uid and meet the filter's drop, so the responder is the only
    one that answers.
    """
    mode = workload.get("network", {}).get("mode", "pasta")
    if not container_uses_resolve(workload):
        return mode
    dns_host = f"--dns-host,{resolve_address(uid)}"
    return f"{mode},{dns_host}" if ":" in mode else f"{mode}:{dns_host}"


def _network_args(spec):
    """--network/--publish/--network-alias flags: single/pod/bridge mode."""
    mode, workload = spec.mode, spec.workload
    name, container = spec.name, spec.container
    args = []
    if mode == "single":
        network_config = workload.get("network", {})
        network_mode = network_config.get("mode", "pasta")  # Default to pasta (works in Podman 5.3+)

        args.append(
            f"--network={dq(container_network_mode_arg(workload, spec.uid))}")
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


def volume_args(spec):
    """--volume flags: [storage].volumes expansion, escape-warn, quoting.

    Returns (args, external_paths, external_rw_paths). `external_paths` are the
    host paths that resolve outside the workload tree, deduplicated in
    declaration order, for the caller to turn into RequiresMountsFor= -- see
    gen_container._unit_deps. `external_rw_paths` is the subset of those the container may
    write, for ReadWritePaths= -- see gen_container._hardening.

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
    trusts this workload's CA (container_validate.validate_container_network refuses the value
    on a bundle with no Containerfile, so the claim was at least plausible
    at validate time; R9 -- this cannot VERIFY it, only the operator's
    assertion is on record).

    "mount" and "env" both bind the CA certificate generated by
    generate_egress_ca/provision_egress_pki_dirs (libexec/workload-ensure-user
    -- fully name-keyed already, reused verbatim for containers, see that
    file's G12 comment) into the container read-only. "env" additionally
    points the same five variables the VM guest gets (CA_ENV_VARS) at a
    FIXED in-container path -- CA_BUNDLE_PATH, reused rather than
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
    cert_path = str(ca_cert_path(workload_state_dir(name)))
    if delivery == "mount":
        dest = container_ca_mount_path(net)
        if not dest:
            return []
        return [f"--volume {dq(cert_path)}:{dq(dest)}:ro"]
    # "env"
    args = [f"--volume {dq(cert_path)}:{dq(CA_BUNDLE_PATH)}:ro"]
    for var in CA_ENV_VARS:
        args.append(f"--env {var}={dq(CA_BUNDLE_PATH)}")
    return args


def podman_run_args(spec, service_type, wl_lifecycle, systemd_mode,
                    gpu_vendor, gpu_spec, volume_flags, image, command):
    """The whole `podman run`/`podman create` argv, builder by builder.

    The three decided values go to _base_run_args (see its docstring);
    `volume_flags` is passed in because the caller expands the volumes ahead
    of the [Unit] section, where their out-of-tree host paths become
    RequiresMountsFor= -- see volume_args.

    Quoting boundary: free-form values (image, command, env values, volume
    specs, the container name) go through dq(), because systemd would
    otherwise expand or re-split them. Ports, capabilities, devices and
    resource limits are spliced raw on purpose -- they are format-constrained
    (podman's own grammars) and configs are trusted. The raw ones are still
    guarded: the control-char walker blocks newlines (the only systemd
    injection vector), and validate_publish_ports holds a publish spec to
    podman's alphabet. If you add a free-form field, put it on the dq() side.
    """
    container, uid, name, mode = spec.container, spec.uid, spec.name, spec.mode

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

    podman_args.extend(volume_flags)

    # The egress CA (P1-10), delivered into every container of the workload
    # regardless of topology -- [network] is workload-level (D1: one uid, so
    # per-container granularity would be a lie), and each container process
    # makes its own outbound requests with its own trust path.
    podman_args.extend(_container_ca_delivery_args(spec))
    podman_args.extend(_container_credential_env_args(spec))

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
    return podman_args
