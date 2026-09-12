"""One run of the workload generator: discover, validate, emit, enqueue.

Reads every bundle under WORKLOAD_CONFIG_DIR and, for each enabled one that
validates, writes its sysusers config and unit files into the output
directories gen_common holds. The substrate's own files come from
gen_vm.generate_vm_workload and gen_container.generate_container_workload;
this module is the loop around them -- the pre-scan that lets requires/after
be checked against the whole enabled set, the UID that pins each user, the
`--workload` narrowing, and the boot-only start enqueue at the end.

Read-only with respect to /var: user creation is systemd-sysusers' job and
everything UID-dependent is deferred to workload-ensure-user. A failure in one
workload is logged and the next is processed; a failure anywhere else is
logged and the run still reports success, because nothing here may block
boot.
"""
import os
import pwd
import subprocess
import tomllib
import traceback
from pathlib import Path

from workload_lib import (
    WORKLOAD_CONFIG_DIR, ENABLED_MARKER_NAME, iter_workloads,
    workload_username, infer_workload_kind, claim_uid, subid_lock,
)
from validation import validate_workload_config
from gen_container import generate_container_workload
from gen_vm import generate_vm_workload
from gen_common import (
    set_output_dirs, services_dir, log_msg, pin_allocated_uid, enqueue_starts,
)

LIVE_SERVICES_DIR = Path("/run/systemd/system")


def parse_args(args):
    """(output_dir, only_workload, no_start) from the command line.

    The output directory is /run/systemd/system when workload-generate.service
    runs this, or a temp directory from a test.

    `--workload NAME` narrows the run to one workload: only its files are
    written, and only it gets a start job. The CLI passes it whenever it acts
    on a single workload (enable / edit / recreate), because an unfiltered run
    writes units for the *whole* enabled set -- which would silently update a
    bystander's unit file (hiding its drift, since `drift` compares against
    the files in /run) and enqueue a start for a workload the operator had
    deliberately stopped. Boot passes no filter and emits everything.

    `--no-start` skips the daemon-reload + start-enqueue block at the end of
    generate_all(): the caller owns both. Every CLI call site passes it,
    because each already starts/restarts the workload itself AFTER its
    remaining provisioning steps -- most critically enable's image transfer
    to the user store. A generator-enqueued start races ahead of that
    transfer and pins a fresh cattle container to the *stale* user-store
    image (the transfer then retags :latest seconds too late). Boot passes no
    flag: there the enqueue is load-bearing (see generate_all).
    """
    only_workload = None
    no_start = False
    positional = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--workload" and i + 1 < len(args):
            only_workload = args[i + 1]
            i += 2
        elif a.startswith("--workload="):
            only_workload = a.split("=", 1)[1]
            i += 1
        elif a == "--no-start":
            no_start = True
            i += 1
        else:
            positional.append(a)
            i += 1
    output_dir = Path(positional[0]) if positional else None
    return output_dir, only_workload, no_start


def enabled_workload_names(config_files):
    """The [workload].name of every enabled bundle; requires/after are
    validated against this set, so it is built over every bundle even when
    the emit is narrowed to one."""
    names: set[str] = set()
    for _cf in config_files:
        try:
            if not (_cf.parent / ENABLED_MARKER_NAME).exists():
                continue
            with open(_cf, "rb") as _f:
                _c = tomllib.load(_f)
            _n = _c.get("workload", {}).get("name", "")
            if _n:
                names.add(_n)
        except Exception:
            pass
    return names


def resolve_uid(config, name, user_name, kind):
    """The UID the workload's user has, or the one it is allocated and pinned."""
    # Look up existing user to pin UID; if user doesn't exist yet,
    # allocate — adopting the owner of any state left behind by an
    # earlier deployment (claim_uid explains why).
    try:
        uid = pwd.getpwnam(user_name).pw_uid
        log_msg(f"  User {user_name} exists with UID {uid}")
    except KeyError:
        # Allocate and durably pin the UID under a single lock hold:
        # allocation scans pending sysusers configs, so writing this
        # workload's .conf before releasing the lock stops a concurrent
        # enable from handing out the same slot in the window before
        # systemd-sysusers creates the user.
        with subid_lock():
            uid, why = claim_uid(name)
            pin_allocated_uid(
                config, user_name, uid, is_vm=(kind == "vm")
            )
        if why == "adopted":
            log_msg(
                f"  User {user_name} not found but its state dir exists; "
                f"adopted owning UID {uid}"
            )
        elif why == "collision":
            # The old UID now belongs to something else, so the derived
            # subid range cannot be recovered. Fail loud rather than
            # start a workload that silently cannot read its own data.
            log_msg(
                f"  WARNING: {name}: existing state dir is owned by a UID "
                f"that is already in use; allocated {uid} instead. The "
                f"workload may be unable to read /var/lib/workloads/{name}",
                level="warning",
            )
        else:
            log_msg(f"  User {user_name} not found; allocated UID {uid}")
    return uid


def generate_workload(config_file, all_workload_names):
    """Emit one bundle's files; its name if they were written, else None."""
    log_msg(f"Processing {config_file}")
    with open(config_file, "rb") as f:
        config = tomllib.load(f)

    enabled = (config_file.parent / ENABLED_MARKER_NAME).exists()
    if not enabled:
        log_msg(f"  Skipping {config_file} (disabled)")
        return None

    if "workload" not in config or "name" not in config.get("workload", {}):
        log_msg(f"ERROR: {config_file} missing required workload.name field", level="err")
        return None

    name = config["workload"]["name"]

    # Identity is directory-based everywhere else (iter_workloads, the
    # .enabled marker, WorkloadConfig which enforces name==dir), but the
    # generator keys unit filenames off [workload].name. If the two
    # disagree we'd emit workload-<tomlname>.service while the CLI and
    # marker operate on the dir name — a split identity. Refuse it.
    if config_file.parent.name != name:
        log_msg(
            f"ERROR: {config_file}: [workload].name {name!r} does not "
            f"match bundle directory {config_file.parent.name!r}, skipping",
            level="err",
        )
        return None

    errors = validate_workload_config(config)
    if errors:
        for e in errors:
            log_msg(f"  ERROR: {name}: {e}", level="err")
        return None

    # Cross-reference: requires/after must name existing workloads.
    wl_meta = config.get("workload", {})
    for dep_key in ("requires", "after"):
        for dep_name in wl_meta.get(dep_key, []):
            if dep_name not in all_workload_names:
                log_msg(
                    f"  WARNING: {name}: [workload].{dep_key} references "
                    f"unknown workload {dep_name!r}",
                    level="warning",
                )

    kind = infer_workload_kind(config)
    user_name = workload_username(name)
    log_msg(f"  Processing {kind} workload {name}")

    uid = resolve_uid(config, name, user_name, kind)

    if kind == "vm":
        generate_vm_workload(config, user_name, uid)
        return name
    if not generate_container_workload(config, user_name, uid):
        return None
    return name


def generate_all(only_workload=None, no_start=False):
    """Every enabled bundle through generate_workload, then the start enqueue."""
    log_msg(f"Checking {WORKLOAD_CONFIG_DIR}")
    if not WORKLOAD_CONFIG_DIR.exists():
        log_msg("Workload config dir does not exist, exiting")
        return

    # Ensure output directory exists
    services_dir().mkdir(parents=True, exist_ok=True)

    # Names of workloads whose unit files were successfully written this run.
    # Used below to explicitly enqueue a start job for each -- see the block
    # at the end for why the wants symlinks alone don't suffice.
    written_workloads = []

    # Process each workload config. Discovery goes through iter_workloads so the
    # <name>/workload.toml layout lives in exactly one place (workload_lib); we
    # keep just the paths since generate_workload re-derives name from the parent.
    config_files = [path for _name, path in iter_workloads(WORKLOAD_CONFIG_DIR)]
    log_msg(f"Found {len(config_files)} config files")

    # NOTE: the generator only ever *writes* -- it emits units for enabled
    # workloads and never deletes anything. Removing a disabled workload's unit
    # files from /run is `workloadctl disable`'s job (see cmd_disable /
    # _workload_run_files); at boot /run is a fresh tmpfs so there is nothing to
    # clean up here.
    all_workload_names = enabled_workload_names(config_files)

    # The cross-reference scan above deliberately runs over every workload even
    # when the emit is filtered: a narrowed run still has to know the full name
    # set to validate this workload's requires/after against it.
    if only_workload:
        config_files = [cf for cf in config_files if cf.parent.name == only_workload]
        log_msg(f"Filtered to workload {only_workload!r}: {len(config_files)} config file(s)")

    for config_file in config_files:
        try:
            written = generate_workload(config_file, all_workload_names)
            if written:
                written_workloads.append(written)
        except Exception as e:
            # Log errors but don't fail the boot
            log_msg(f"ERROR processing {config_file}: {e}", level="err")
            log_msg(traceback.format_exc(), level="err")
            continue

    # Explicitly enqueue a start job for each workload whose unit file we
    # just wrote.
    #
    # Why this is necessary: the wants symlinks created above look like they
    # should be enough, but they aren't. systemd builds the boot transaction
    # for default.target (= multi-user.target) once at startup, resolving
    # dependencies from the unit files it knows about AT THAT MOMENT. When
    # this script runs (from workload-generate.service, After=sysinit.target
    # Before=basic.target), multi-user.target's transaction has already been
    # built — and it didn't include any workload services, because those
    # unit files didn't exist yet. daemon-reload updates systemd's in-memory
    # view of unit files, but target .wants/ directories are NOT re-scanned
    # for already-enqueued targets. The symlinks are load-bearing for a
    # subsequent boot cycle (cosmetic "enabled-runtime" in `systemctl is-
    # enabled`, and semantically meaningful if the architecture ever changes)
    # but do nothing for this boot. An explicit `systemctl start` creates
    # a new job and merges it into systemd's running job queue regardless
    # of target transaction state, which is exactly what we need.
    #
    # --no-block: enqueue the job and return immediately. We must not wait
    # for container startup from inside an early-boot oneshot service —
    # that would delay basic.target until every container is up, and would
    # risk deadlock if any workload transitively depends on something
    # downstream of basic.target.
    #
    # This block is BOOT-path only in practice: every CLI call site passes
    # --no-start and does its own daemon-reload + start, because starting
    # here would run ahead of the caller's later provisioning steps —
    # enable's user-store image transfer in particular, where a premature
    # cold start pins the container to the stale image.
    #
    # Gated on services_dir() being the live systemd directory so test runs
    # (which pass a tmp dir as argv[1]) never touch the host's systemd.
    is_live = services_dir() == LIVE_SERVICES_DIR
    if is_live and written_workloads and not no_start:
        try:
            subprocess.run(
                ["systemctl", "daemon-reload"],
                check=False,
                timeout=30,
            )
        except Exception as e:
            log_msg(f"daemon-reload failed: {e}", level="warning")

        enqueue_starts(written_workloads)



def run(argv) -> int:
    """The whole generator, from argv; always 0, since nothing may block boot."""
    output_dir, only_workload, no_start = parse_args(argv[1:])
    # Derived once, here, and pushed into gen_common, which every writer reads
    # back through services_dir()/sysusers_dir(). Not a module global: `from
    # gen_common import SERVICES_DIR` anywhere would copy the pre-argv default
    # and write units into the live /run/systemd/system during a test run.
    # SYSUSERS_DIR is the test override.
    set_output_dirs(output_dir or LIVE_SERVICES_DIR, os.environ.get("SYSUSERS_DIR"))
    try:
        log_msg("Starting rootless workload generator", level="notice")
        generate_all(only_workload, no_start)
        log_msg("Generator completed successfully", level="notice")
    except Exception as e:
        # CRITICAL: Always exit 0, even on catastrophic failure
        # Generators must never block boot - log the error and let the system come up
        log_msg(f"FATAL ERROR: {e}", level="err")
        log_msg(traceback.format_exc(), level="err")
        log_msg("Generator failed but exiting 0 to allow boot to continue", level="err")
    return 0
