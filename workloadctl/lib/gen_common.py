#!/usr/bin/env python3
"""The generator's substrate-neutral half: logging, uids, output paths.

Split out of generators/workload-generate, which held both generators and was
the highest-traffic file in the repo for work on either substrate. The
container path's biggest file was not named for containers at all.

WHAT BELONGS HERE is not "used by both" -- that is a symptom. It is code that
does not know which substrate it is serving: kmsg logging, the uid claim and
its sysusers config, where the output goes, the setup unit and the user@
drop-in (identical for a container and a VM), and the [resources] -> cgroup
directive translation, which is a systemd question rather than a podman one.
Anything that would have to ask "container or VM?" belongs in one of the two
halves instead.

THE OUTPUT DIRECTORIES ARE FUNCTIONS, NOT NAMES. They are derived from argv
and the environment by the entrypoint, after this module is imported, so a
`from gen_common import SERVICES_DIR` in either half would copy the
pre-argv default and write units to /run/systemd/system during a test. Reading
them through services_dir()/sysusers_dir() makes that unspellable rather than
a rule someone has to remember.

Installed to /usr/libexec/workloadctl/gen_common.py.
"""

import os
import sys
from pathlib import Path

from workload_lib import (GENERATED_BY, GENERATOR_OWNED_DIRECTIVES,
                          RUN_SYSTEMD_SYSTEM, render_sysusers_config,
                          workload_root_dir, workload_run_files,
                          workload_state_dir)
from unit_file import Unit

# Set by the entrypoint once argv is parsed; see the module docstring.
_SERVICES_DIR = Path("/run/systemd/system")
_SYSUSERS_DIR = _SERVICES_DIR


def set_output_dirs(services, sysusers=None) -> None:
    """Point every writer in the generator at `services` (and `sysusers`)."""
    global _SERVICES_DIR, _SYSUSERS_DIR
    _SERVICES_DIR = Path(services)
    _SYSUSERS_DIR = Path(sysusers) if sysusers else _SERVICES_DIR


def services_dir() -> Path:
    """Where generated unit files go."""
    return _SERVICES_DIR


def sysusers_dir() -> Path:
    """Where generated sysusers .conf files go; tests point this elsewhere."""
    return _SYSUSERS_DIR



# Early logging before any imports
def _write_kmsg(priority, msg):
    """Write one line to /dev/kmsg. No fallback -- callers handle failure."""
    with open("/dev/kmsg", "w") as kmsg:
        kmsg.write(f"<{priority}>{msg}\n")


class _RunFileConfig:
    """Minimal WorkloadConfig stand-in so the generator can drive the single
    canonical run-file enumeration (workload_lib.workload_run_files) from its
    raw-dict context. Carries exactly the attributes that helper reads; uid is
    the value the generator already allocated, not a passwd lookup (WorkloadConfig
    would drag workloadctl_core onto the generate step and raise before the user
    exists)."""

    def __init__(self, *, config, name, uid, is_vm, mode=None):
        self.config = config
        self.name = name
        self.uid = uid
        self.is_vm = is_vm
        self.mode = mode  # container mode; unread (and None) for VMs

    @property
    def is_multi(self):
        return "containers" in self.config

    def container_names(self):
        if self.is_multi:
            return [c["name"] for c in self.config["containers"]]
        return [self.name]


def emitted_run_paths(view):
    """(kind, role) -> [dest Path, ...] for the files the generator writes,
    sourced from workload_run_files() so the generator no longer hand-spells any
    run-file path. The helper's paths are rooted at RUN_SYSTEMD_SYSTEM; remap that
    root onto the generator's output dirs — sysusers_dir() for the sysusers .conf
    (tests may point it elsewhere), services_dir() for everything else. Per-container
    and per-virtiofs entries preserve the helper's order (== the generator's), so
    callers zip them against their content sources."""
    out = {}
    for rf in workload_run_files(view):
        if not rf.emitted or rf.kind == "env-file":
            continue
        base = sysusers_dir() if rf.kind == "sysusers" else services_dir()
        dest = base / rf.path.relative_to(RUN_SYSTEMD_SYSTEM)
        out.setdefault((rf.kind, rf.role), []).append(dest)
    return out


def log_msg(msg, level="info"):
    """Log to kernel message buffer (available during generator execution).

    Systemd generators run very early and cannot rely on journald.
    Use /dev/kmsg which is always available.

    Messages will appear in dmesg and eventually in the journal.
    """
    # kmsg priority levels (same as syslog)
    # 3=err, 4=warning, 5=notice, 6=info, 7=debug
    priority_map = {
        "err": 3,
        "warning": 4,
        "notice": 5,
        "info": 6,
        "debug": 7
    }
    priority = priority_map.get(level, 6)

    if os.environ.get("WORKLOAD_GENERATE_LOG_STDERR"):
        print(f"workload-generate: {msg}", file=sys.stderr, flush=True)
        return
    try:
        _write_kmsg(priority, f"workload-generate: {msg}")
    except Exception:
        # /dev/kmsg isn't writable (not running as a boot-time generator, or
        # in a test); fall back to stderr so the message isn't lost.
        print(f"workload-generate: {msg}", file=sys.stderr, flush=True)


def generate_sysuser_config(config, user_name, uid):
    """Generate systemd-sysusers config content for a workload user.

    Args:
        config: Parsed TOML workload config.
        user_name: System username (e.g. _wl-foo).
        uid: Numeric UID (int). Must be pre-allocated — sysusers does not
             support range syntax.
    """
    name = config["workload"]["name"]
    return render_sysusers_config(
        name=name,
        user_name=user_name,
        uid=uid,
        home_dir=str(workload_state_dir(name)),
        extra_groups=config.get("security", {}).get("extra_groups", []),
    )


def pin_allocated_uid(config, user_name, uid, *, is_vm):
    """Durably record a freshly-allocated UID by writing its sysusers .conf.

    Called under subid_lock() the instant a UID is allocated, before the lock is
    released, so a concurrent allocator's get_next_uid() (which scans pending
    sysusers configs) sees the slot as taken — this is what closes the
    allocate-then-create window (the user isn't in /etc/passwd until the
    workload's setup service runs systemd-sysusers, potentially much later). The
    per-kind emit later in the loop rewrites this file with identical content."""
    name = config["workload"]["name"]
    view = _RunFileConfig(config=config, name=name, uid=uid, is_vm=is_vm)
    dest = emitted_run_paths(view)[("sysusers", "sysusers")][0]
    content = (
        generate_sysuser_config_vm(config, user_name, uid)
        if is_vm
        else generate_sysuser_config(config, user_name, uid)
    )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content)



# [resources] key -> cgroup directive. The [resources] block is substrate-neutral
# (one schema, documented once), so both substrates read it from here: containers
# apply it to the user manager's subtree via the user@{uid} drop-in, VMs to the
# QEMU service unit itself. Anything added here reaches both.
#
# CPUWeight/IOWeight have no default: workloads.slice already carries
# CPUWeight=80 / IOWeight=80 for host-vs-workload contention, and an
# unconditional default here would add intra-workload weight noise.
CGROUP_SCALAR_KEYS = (
    ("cpu_quota",       "CPUQuota"),
    ("cpu_weight",      "CPUWeight"),
    ("memory_max",      "MemoryMax"),
    ("memory_high",     "MemoryHigh"),
    ("memory_swap_max", "MemorySwapMax"),
    ("io_weight",       "IOWeight"),
    ("tasks_max",       "TasksMax"),
)
# Repeatable directives: one line per entry, so these take a list.
CGROUP_LIST_KEYS = (
    ("io_read_bandwidth_max",  "IOReadBandwidthMax"),
    ("io_write_bandwidth_max", "IOWriteBandwidthMax"),
)


def cgroup_directives(resources) -> list[tuple[str, str]]:
    """[resources] -> ordered (directive, value) pairs for a [Service] section."""
    out = [(directive, resources[key])
           for key, directive in CGROUP_SCALAR_KEYS if key in resources]
    for key, directive in CGROUP_LIST_KEYS:
        out += [(directive, limit) for limit in resources.get(key, [])]
    return out


def generate_user_dropin(config, uid):
    """Emit user@{uid}.service.d/50-workload.conf for 1b cgroup placement.

    Redirects the workload's user manager into workloads.slice and applies
    workload-level cgroup resource limits to the whole user manager subtree
    (which is the payload's cgroup scope under the non-split topology).
    Per-container limits bind via podman flags on each container run command.
    """
    resources = config.get("resources", {})
    slice_name = resources.get("slice", "workloads.slice")

    name = config["workload"]["name"]
    lines = [
        f"# Workload {name}: redirect user@{uid} into {slice_name} (ADR 001 option 1b)",
        f"# {GENERATED_BY}",
        "",
        "[Service]",
        f"Slice={slice_name}",
    ]
    lines += [f"{directive}={value}"
              for directive, value in cgroup_directives(resources)]

    lines.append("")
    return "\n".join(lines)


def generate_setup_service(config, user_name):
    """Generate a oneshot service that creates the workload user.

    Runs as root (no User= directive) before the main workload service.
    This avoids the chicken-and-egg problem where User= must be resolvable
    before any ExecStartPre runs — including the ones that create the user.
    """
    name = config["workload"]["name"]
    sysusers_conf = f"{services_dir()}/workload-{name}.conf"

    unit = Unit()
    unit.comment(f"Setup service for {name} workload")
    unit.comment(GENERATED_BY)

    u = unit.section("Unit")
    u.set("Description", f"Setup {name} workload user")

    svc = unit.section("Service")
    svc.set("Type", "oneshot")
    svc.set("RemainAfterExit", "yes")
    svc.add("ExecStart", f"/usr/bin/systemd-sysusers {sysusers_conf}")
    svc.add("ExecStart", f"/usr/libexec/workloadctl/workload-ensure-user {name}")

    return unit.render()


def _external_host_path(host_path, name):
    """The resolved form of `host_path` if it falls outside the workload's own
    tree, else None.

    Such a path is admin-supplied: workload-ensure-user deliberately does not
    create it (setup_volume_directories skips anything out of tree), so it may
    live on a filesystem of its own that is not mounted -- or not mounted yet.
    Callers guard it with RequiresMountsFor=. Symlinks are resolved because
    systemd matches RequiresMountsFor= paths against real mount points.
    """
    try:
        resolved = str(Path(host_path).resolve())
    except Exception:
        return None
    root = str(workload_root_dir(name))
    if resolved == root or resolved.startswith(root + '/'):
        return None
    return resolved


def _resource_overrides(svc, resources, name):
    """Service-level resource overrides (TimeoutStart/StopSec + custom_directives).
    This is the custom_directives splice point: every directive emitted from here
    on down must use .add(), never .set(), or it will overwrite a user's line in
    place and destroy it. See "The set()/add() splice-point invariant" in
    lib/unit_file.py for what add() does and does not guarantee, and for why a
    default that must yield to the user has to skip emitting itself."""
    service_directives = []
    if "timeout_start_sec" in resources:
        service_directives.append(("TimeoutStartSec", resources['timeout_start_sec']))
    if "timeout_stop_sec" in resources:
        service_directives.append(("TimeoutStopSec", resources['timeout_stop_sec']))
    for directive, value in resources.get("custom_directives", {}).items():
        if directive in GENERATOR_OWNED_DIRECTIVES:
            log_msg(
                f"WARNING: custom_directives contains '{directive}' which is managed "
                f"by the generator — this may have no effect or cause unexpected behaviour",
                level="warning"
            )
        service_directives.append((directive, value))
    if service_directives:
        svc.comment("Service-level overrides")
        for directive, value in service_directives:
            svc.add(directive, value)
        svc.blank()


def generate_sysuser_config_vm(config, user_name, uid):
    """Like generate_sysuser_config but adds implicit kvm group membership."""
    name = config["workload"]["name"]
    return render_sysusers_config(
        name=name,
        user_name=user_name,
        uid=uid,
        home_dir=str(workload_state_dir(name)),
        extra_groups=config.get("security", {}).get("extra_groups", []),
        is_vm=True,
    )


def enqueue_starts(names, run=None):
    """Enqueue a start job for each named workload, in ONE systemctl call.

    Batched on purpose. This is the only part of the generator whose cost
    scales with the workload count, and it dominated everything else: on a slow
    host each `systemctl start` costs ~27ms in fork/exec plus a D-Bus round
    trip, so 40 workloads spent 1.09s here against 77ms for all the actual
    generation work (TOML parse, validation, unit emission, UID allocation
    combined). Since this runs Before=basic.target, that was 1.09s of pure boot
    delay. One batched call costs about what a single one did.

    Falls back to one call per unit if the batch is rejected. A batched start
    is a single request: if any one unit fails to load — a malformed unit file,
    a name systemd refuses — systemctl can reject the whole set, and every
    healthy workload would silently stay down. The retry pays the per-call
    overhead again, but only on a boot that is already degraded, and it
    confines the damage to the unit that actually caused it.
    """
    import subprocess
    run = run or subprocess.run
    units = [f"workload-{name}.service" for name in names]
    if not units:
        return
    try:
        rc = run(["systemctl", "start", "--no-block", *units],
                 check=False, timeout=30).returncode
    except Exception as e:
        log_msg(f"Batch enqueue failed: {e}", level="warning")
        rc = 1

    if rc == 0:
        log_msg(f"  Enqueued start for {len(units)} workload service(s)")
        return

    log_msg(f"Batch enqueue returned {rc}; retrying individually",
            level="warning")
    for unit in units:
        try:
            run(["systemctl", "start", "--no-block", unit],
                check=False, timeout=30)
            log_msg(f"  Enqueued start for {unit}")
        except Exception as e:
            log_msg(f"  Failed to enqueue start for {unit}: {e}",
                    level="warning")
