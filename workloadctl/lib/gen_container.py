#!/usr/bin/env python3
"""Generating the units for a container workload.

The other half of the split gen_vm.py describes: single, pod and bridge
topologies and the per-container service, with its egress and credential
wiring. The `podman run` argv is assembled in container_run_args and the
pod/net head unit and umbrella in gen_container_heads. Nothing here calls into
gen_vm and nothing there calls in here -- that is measured, not intended, and
it is what made the entrypoint's 3,665 lines two files rather than one file
with a comment in the middle.

Installed to /usr/libexec/workloadctl/gen_container.py.
"""

import os
from pathlib import Path

from config_parser import infer_workload_mode, workload_root_dir
from container_network_config import container_uses_inspect
from egress_policy import container_uses_resolve
from workload_lib import workload_state_dir, dq, uq, normalize_containers
from run_files import GENERATED_BY
from broker_config import (
    container_broker_hosts, container_broker_upstream_addresses,
    container_broker_command,
    container_uses_credentials,
)
from secrets_template import auto_detect_credentials
from gen_common import (
    log_msg, _resource_overrides, _RunFileConfig,
    emitted_run_paths, generate_sysuser_config, generate_user_dropin,
    generate_setup_service,
)
from gen_egress import (
    generate_inspect_socket, generate_inspect_service,
    generate_broker_service, generate_resolve_socket,
    generate_resolve_service,
)
from container_run_args import RunSpec, volume_args, podman_run_args
from gen_container_heads import (
    container_egress_exec, generate_pod_service, generate_net_service,
    generate_umbrella_service,
)
from unit_file import Unit


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
    # `podman stop` sends SIGTERM, and a container that dies of it hands the
    # main process 128+15 as an exit CODE. systemd only counts SIGTERM as clean
    # when it arrives as a signal, so without this every stop reads `failed`.
    # 137 stays a failure: it means the grace ran out and podman had to KILL.
    svc.add("SuccessExitStatus", "143")
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
    (see volume_args). Without them ProtectSystem=strict hands podman a
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
    volume_flags, external_volume_paths, external_rw_paths = volume_args(spec)

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
    # unit ordered ahead of every member container (see gen_container_heads._head_unit).
    if mode == "single" and container_uses_inspect(workload):
        u.add("Requires", f"workload-{name}-inspect.socket")
        u.add("After", f"workload-{name}-inspect.socket")
    # And the responder's socket, on the same terms: it is the container's
    # only nameserver that answers, so a container started with it unbound
    # resolves nothing at all while looking healthy.
    if mode == "single" and container_uses_resolve(workload):
        u.add("Requires", f"workload-{name}-resolve.socket")
        u.add("After", f"workload-{name}-resolve.socket")
    # And the broker instance, on the same terms and for the same reason its
    # twin is on the head unit in pod/bridge mode: the `Before=` the generator
    # gives the instance ORDERS it, and nothing else pulls it in. See
    # gen_container_heads._head_unit.
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
    podman_args = podman_run_args(spec, service_type, wl_lifecycle, systemd_mode,
                                  gpu_vendor, gpu_spec, volume_flags, image, command)
    credentials = auto_detect_credentials({
        "container": container.get("container", {}),
        "secrets":   container.get("secrets", {}),
    })

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
    # Gated on the config, not inside container_egress_exec, for R10 (see
    # that function's docstring).
    if mode == "single" and container_uses_inspect(workload):
        container_egress_exec(svc, name)

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
    inspector arming there (see gen_container_heads._head_unit).

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


def generate_container_workload(config, user_name: str, uid: int) -> bool:
    """Emit all unit files for a container workload; False if it was skipped.

    The container counterpart of gen_vm.generate_vm_workload: sysusers and
    the user-manager drop-in, the setup service, the egress inspector and
    credential broker where the config selects them, then the main unit --
    one service in single mode, a helper plus per-container services under an
    umbrella in pod and bridge mode -- and the wants symlink. A single-mode
    service the config cannot produce leaves the earlier files in place and
    returns False; the caller then neither starts nor counts the workload.
    """
    name = config["workload"]["name"]
    mode = infer_workload_mode(config)
    view = _RunFileConfig(config=config, name=name, uid=uid, is_vm=False, mode=mode)
    paths = emitted_run_paths(view)

    sysuser_content = generate_sysuser_config(config, user_name, uid)
    sysuser_file = paths[("sysusers", "sysusers")][0]
    sysuser_file.write_text(sysuser_content)
    log_msg(f"  Created sysusers config with UID {uid}")

    # user@<uid>.service.d drop-in: redirect the user manager into
    # workloads.slice and apply workload-level cgroup limits (ADR 001 option 1b).
    dropin_file = paths[("dropin", "dropin")][0]
    dropin_file.parent.mkdir(parents=True, exist_ok=True)
    dropin_file.write_text(generate_user_dropin(config, uid))
    log_msg(f"  Created user@{uid} drop-in (workloads.slice placement)")

    # Setup service: creates user (runs as root, no User= directive)
    setup_content = generate_setup_service(config, user_name)
    setup_file = paths[("unit", "setup")][0]
    setup_file.write_text(setup_content)
    log_msg(f"  Created setup service at {setup_file}")

    # Transparent egress inspection socket + service (P1-9), on the
    # same terms as the VM path (generate_vm_workload) -- D6: the
    # binary and unit shape do not change between substrates.
    # generate_inspect_socket/service take nothing substrate-specific
    # but the arming helper (config["workload"]["name"], uid, and
    # uid-derived addressing otherwise), so they are shared rather
    # than duplicated.
    if container_uses_inspect(config):
        socket_dests = paths.get(("unit", "inspect-socket"), [])
        if socket_dests:
            socket_dests[0].write_text(
                generate_inspect_socket(
                    config, user_name, uid,
                    arming_helper="workload-container-inspect"))
            log_msg("  Created egress inspector socket")
        inspect_dests = paths.get(("unit", "inspect"), [])
        if inspect_dests:
            inspect_dests[0].write_text(
                generate_inspect_service(config, user_name, uid))
            log_msg("  Created egress inspector service")

    # The synthesising responder, on the inspector's terms plus a network
    # pasta carries (container_uses_resolve says why), from the same two
    # generators the VM path calls.
    if container_uses_resolve(config):
        resolve_socket_dests = paths.get(("unit", "resolve-socket"), [])
        if resolve_socket_dests:
            resolve_socket_dests[0].write_text(
                generate_resolve_socket(config, user_name, uid))
            log_msg("  Created DNS responder socket")
        resolve_dests = paths.get(("unit", "resolve"), [])
        if resolve_dests:
            resolve_dests[0].write_text(
                generate_resolve_service(config, user_name, uid))
            log_msg("  Created DNS responder service")

    # The credential broker instance (P2-2), on the same reuse terms:
    # generate_broker_service takes its substrate-specific values
    # as parameters, so this is a call site and not a second
    # generator. Gated on container_uses_credentials, which is also
    # the run-file `present=` -- one predicate, so a workload that
    # drops its last credential has the unit unlinked rather than
    # left behind holding material nothing selects.
    if container_uses_credentials(config):
        broker_dests = paths.get(("unit", "broker"), [])
        if broker_dests:
            broker_dests[0].write_text(
                generate_broker_service(
                    config, uid,
                    before=container_broker_before(config, mode),
                    hosts=container_broker_hosts(config),
                    upstream=container_broker_upstream_addresses(
                        config),
                    command=container_broker_command(config, uid)))
            log_msg("  Created credential broker instance")

    # Main service: Requires+After setup service so User= is resolvable
    containers = normalize_containers(config)

    if mode == "single":
        service_content = generate_system_service(config, containers[0], user_name, uid)
        if service_content is None:
            log_msg(f"  Skipping {name} due to config errors", level="err")
            return False
        service_file = paths[("unit", "main")][0]
        service_file.write_text(service_content)
        log_msg(f"  Created system service at {service_file}")
    else:
        # Network helper service: pod-create (pod mode) or
        # network-create (bridge mode).
        if mode == "pod":
            helper = generate_pod_service(config, user_name, uid)
            paths[("unit", "pod")][0].write_text(helper)
        else:  # bridge
            if config.get("network", {}).get("ports"):
                log_msg(f"  WARNING: {name}: workload-level [network].ports "
                        f"is ignored in bridge mode; publish ports per "
                        f"container under [containers.network]",
                        level="warning")
            helper = generate_net_service(config, user_name, uid)
            paths[("unit", "net")][0].write_text(helper)
        # Per-container services (podman's native user-manager healthcheck
        # timer works under option 1b — no system-manager timer needed)
        container_dest = dict(zip(view.container_names(), paths[("unit", "container")]))
        for c in containers:
            sc = generate_system_service(config, c, user_name, uid, mode=mode)
            if sc is None:
                log_msg(f"  Skipping container {c.get('name')} due to config errors", level="err")
                continue
            container_dest[c['name']].write_text(sc)
        # Umbrella
        slice_name = config.get("resources", {}).get("slice", "workloads.slice")
        umbrella = generate_umbrella_service(
            name, [c["name"] for c in containers], slice_name, mode=mode
        )
        paths[("unit", "main")][0].write_text(umbrella)
        log_msg(f"  Created {mode}-mode units for {name} ({len(containers)} containers)")

    # Create symlink for auto-start (equivalent to systemctl enable)
    symlink_path = paths[("wants-symlink", "main")][0]
    symlink_path.parent.mkdir(parents=True, exist_ok=True)

    if symlink_path.exists() or symlink_path.is_symlink():
        symlink_path.unlink()
    symlink_path.symlink_to(f"../workload-{name}.service")
    log_msg("  Enabled service for auto-start")

    return True
