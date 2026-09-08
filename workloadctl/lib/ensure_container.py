"""The provisioning a container workload needs and a VM workload never does.

Subordinate uid/gid ranges, the volume directories podman bind-mounts, the
ownership of operator-supplied required files, and linger plus the manager
slice for the rootless user manager. A VM reaches none of it: QEMU uses no
user namespace, so there is nothing to map, and it runs as a system service,
so there is no user session to keep alive.

What both substrates need lives in ensure_common -- including three functions
whose names still say `vm`. Nothing here calls anything in ensure_vm and
nothing there calls anything here; that was measured, not assumed.

`log` is reached as `ensure_common.log(...)`, never imported by name; see that
module's docstring for why the copy matters.
"""

import grp
import os
import stat
import subprocess
from pathlib import Path

import service_runtime
from workload_lib import (
    derived_subid_range, expand_volume_path, normalize_containers,
    workload_state_dir, workload_root_dir, subid_lock, append_subid_entries,
    subgid_file, subuid_file,
)
import ensure_common
from ensure_common import (
    _provision_dir_secure, _descend_nofollow,
)


def configure_subuid_subgid(pw, config):
    """Configure subordinate UID/GID ranges for rootless containers.

    Sets up the main subuid/subgid range for the user namespace.  For
    non-host-userns workloads also adds per-GID subgid entries for
    extra_groups so podman can map them via --gidmap +GID:@GID:1.

    For userns=host the workload user IS the host user, so all host GIDs are
    natively available — adding a non-contiguous subgid entry for an
    extra_groups GID creates a spurious mapping that breaks rootless pasta on
    newer podman/kernel versions.

    Uses flock for parallel safety — multiple workload services may
    start concurrently, each running this script via ExecStartPre.
    """
    uid = pw.pw_uid
    username = pw.pw_name

    # Derivation (and its UID-range / uint32 guards) lives in workload_lib so
    # this writer and diagnose's subid checks assert against one formula — a
    # range that drifts off it is invisible otherwise, since the grandfather
    # below deliberately never corrects an existing entry.
    subid_start, count = derived_subid_range(uid)

    main_entry = f"{username}:{subid_start}:{count}"
    # Ordered, main range first — these were sets, and iterating one to build the
    # append list put the main range after the supplementary `user:GID:1` entries
    # about half the time (string hashing is randomized per process, so it varied
    # per provisioning run, per host). read_subid_entry no longer cares about
    # position, but a file whose first line for a user is a single-GID mapping is
    # a trap for anything that reads these by eye or by `head -1`, so write them
    # in the order they mean. Lists, not sets: the dedup below preserves order.
    # subuid only needs the main range; group GIDs belong in subgid, not subuid
    required_uid_entries = [main_entry]
    required_gid_entries = [main_entry]

    # Extra-group subgid entries are only needed when the container runs in its
    # own user namespace.  For userns=host the GIDs are natively available.
    userns = config.get("security", {}).get("userns", "")
    if userns != "host":
        for group_name in config.get("security", {}).get("extra_groups", []):
            try:
                gid = grp.getgrnam(group_name).gr_gid
            except KeyError:
                ensure_common.log(f"  WARNING: Group '{group_name}' not found, skipping subgid entry")
                continue
            gid_entry = f"{username}:{gid}:1"
            if gid_entry not in required_gid_entries:
                required_gid_entries.append(gid_entry)

    # Lock around check-then-write to handle parallel ExecStartPre. The shared
    # subid_lock() is the same SUBID_LOCK flock the allocators hold; this script
    # only reconciles subid ranges from an already-assigned pw.pw_uid (it never
    # calls get_next_uid), so there's no nested re-acquire.
    with subid_lock():
        changed = False
        for path, required_entries in [(subuid_file(), required_uid_entries),
                                       (subgid_file(), required_gid_entries)]:
            try:
                with open(path, "r") as f:
                    existing = f.read()
            except FileNotFoundError:
                existing = ""

            # Grandfather the main range: if the user already has any entry,
            # keep it unchanged — shifting a UID mapping under a running
            # container corrupts its namespace.
            main_already_allocated = any(
                line.startswith(f"{username}:") for line in existing.splitlines()
            )
            existing_lines = set(existing.splitlines())
            missing = []
            for entry in required_entries:
                if entry == main_entry and main_already_allocated:
                    continue
                if entry not in existing_lines:
                    missing.append(entry)

            if missing:
                # Already inside subid_lock(); the re-acquire is a reentrant
                # no-op (see workload_lib._subid_lock_depth).
                append_subid_entries(path, missing)
                for entry in missing:
                    ensure_common.log(f"  Configured {path.name} entry: {entry}")
                changed = True

    # Migrate podman storage to use new subuid/subgid mappings
    if changed:
        try:
            result = subprocess.run(
                ["runuser", "-u", username, "--",
                 "env", f"XDG_RUNTIME_DIR=/run/user/{uid}",
                 "podman", "system", "migrate"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                ensure_common.log(f"  Migrated podman storage for {username}")
            else:
                ensure_common.log(f"  Note: podman system migrate returned {result.returncode} for {username}")
        except subprocess.TimeoutExpired:
            ensure_common.log(f"  WARNING: podman system migrate timed out for {username}")
        except Exception as e:
            ensure_common.log(f"  WARNING: Failed to migrate podman storage for {username}: {e}")


def _chown_file_secure(root_dir, host_path, uid, gid):
    """Chown an existing regular file under `root_dir` to the workload user
    without ever following a symlink — the file counterpart of
    `_provision_dir_secure`, and racy in exactly the same way if done naively.

    Never creates anything: a required file is the operator's to supply, and a
    missing one is preflight's error to report. Never chmods either — the
    operator's mode is deliberate (0600 is correct for a file holding a private
    key), and only the owner is wrong.

    Returns True if the file is now workload-owned, False if it was absent or a
    component was unsafe.
    """
    try:
        parts = host_path.relative_to(root_dir).parts
    except ValueError:
        return False
    if not parts or ".." in parts:
        return False
    dir_fd = _descend_nofollow(root_dir, parts[:-1], f"chown {host_path}")
    if dir_fd is None:
        return False
    try:
        try:
            file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW,
                              dir_fd=dir_fd)
        except FileNotFoundError:
            return False
        except OSError as exc:
            ensure_common.log(f"  WARNING: refusing to chown {host_path}: unsafe final "
                f"component ({exc.strerror})")
            return False
        try:
            st = os.fstat(file_fd)
            if not stat.S_ISREG(st.st_mode):
                return False
            # A hardlink to a file elsewhere on the same filesystem would make
            # this chown reach outside the tree. fs.protected_hardlinks (on by
            # default) already stops the workload user creating one to a file
            # it does not own, but the fd is in hand, so check rather than
            # lean on a tunable.
            if st.st_nlink != 1:
                ensure_common.log(f"  WARNING: refusing to chown {host_path}: "
                    f"{st.st_nlink} hardlinks")
                return False
            if st.st_uid == uid and st.st_gid == gid:
                return True
            os.fchown(file_fd, uid, gid)
            return True
        finally:
            os.close(file_fd)
    finally:
        os.close(dir_fd)


def setup_required_file_ownership(pw, config):
    """Give the workload user ownership of the required files it must read.

    `setup_volume_directories` chowns the volume *dirs*, but a required file is
    placed by the operator afterward -- the documented step is a plain
    `sudo cp` -- which leaves it root-owned. The container runs as the workload
    user, so at mode 0600 (right for a WireGuard key) it cannot read its own
    config, and the failure surfaces inside the container as whatever that
    config's parser says about an empty read, not as a permission error. This
    closes the gap between "the file exists", which preflight checks, and "the
    workload can read it", which is what actually matters.
    """
    name = config["workload"]["name"]
    state_dir = workload_state_dir(name)
    root_dir = workload_root_dir(name)

    for entry in config.get("setup", {}).get("required_files", []):
        raw = entry.get("path", "")
        if not raw:
            continue
        host_path_str = expand_volume_path(raw, str(state_dir)).split(":", 2)[0]
        if not host_path_str:
            continue
        host_path = Path(host_path_str)
        try:
            host_path.relative_to(root_dir)
        except ValueError:
            continue  # Outside the workload tree — not ours to chown.
        if _chown_file_secure(root_dir, host_path, pw.pw_uid, pw.pw_gid):
            ensure_common.log(f"  Required file {host_path} owned by {pw.pw_name}")


def setup_volume_directories(pw, config):
    """Ensure volume mount directories under the workload home exist
    and are owned by the workload user.

    Always chowns matching dirs (even pre-existing ones) so that dirs
    created by root during preflight get fixed up.
    Paths outside the home directory are skipped (admin must create them).
    Required-files paths are skipped — those must be supplied by the user
    as files; auto-creating them as directories would break the bind mount.

    Directory creation + chown goes through _provision_dir_secure so a symlink
    swap by the (untrusted) workload user can never redirect root's chown outside
    the tree (B1).
    """
    name = config["workload"]["name"]
    state_dir = workload_state_dir(name)
    root_dir = workload_root_dir(name)

    required_file_paths = set()
    for entry in config.get("setup", {}).get("required_files", []):
        path = entry.get("path", "")
        if path:
            path = expand_volume_path(path, str(state_dir)).split(":", 2)[0]
        required_file_paths.add(path)

    # Gather volumes from all containers (single and multi-container shapes).
    # Top-level storage.volumes only exists for single-container TOMLs;
    # [[containers]] entries each carry their own storage.volumes.
    all_volume_specs = []
    for ctr in normalize_containers(config):
        all_volume_specs.extend(ctr.get("storage", {}).get("volumes", []))

    for volume_spec in all_volume_specs:
        expanded = expand_volume_path(volume_spec, str(state_dir))
        host_path_str = expanded.split(":", 2)[0]
        if not host_path_str:
            continue

        host_path = Path(host_path_str)

        # Skip required_files — these are user-supplied files, not directories.
        # Attempting mkdir here would break the bind mount when the file is placed.
        if str(host_path) in required_file_paths:
            continue

        # Resolve symlinks before checking containment to prevent symlink traversal.
        # Anchor on the workload ROOT so both state/ and data/ destinations pass.
        try:
            host_path.resolve().relative_to(root_dir.resolve())
        except ValueError:
            continue  # Outside the workload dir — admin must create

        if not host_path.exists():
            ensure_common.log(f"  Creating volume directory {host_path}")
        _provision_dir_secure(root_dir, host_path, pw.pw_uid, pw.pw_gid, 0o755)


def enable_linger(pw):
    """Enable lingering for the workload user — effectively and synchronously.

    Creates a persistent systemd user manager (user@UID.service) that maintains
    /run/user/<uid> and the D-Bus session rootless podman needs.

    The heavy lifting — enable-linger, explicitly *starting* user@<uid>.service
    (serialized after any in-flight stop of a recycled UID's prior occupant, so
    we never latch onto a dying session's runtime dir), and gating on the
    manager being *active* rather than on /run/user/<uid> merely existing — lives
    in service_runtime.ensure_runtime_dir (the same primitive the CLI restart
    paths and podman.py retry use; see its docstring for the flapping-session /
    UID-recycle rationale). This provisioning path differs in two ways: it must
    fail *loudly* (linger not coming up here means the workload can't run, so we
    raise rather than best-effort return), and it must *guarantee* the persistent
    marker (/var/lib/systemd/linger/<name>) is set. ensure_runtime_dir
    short-circuits — skipping `loginctl enable-linger` — when user@<uid>.service
    is already active, which at provisioning time can be a transient login
    session (e.g. from the preceding `podman system migrate`). Without the marker
    the manager dies with that session and the workload loses /run/user/<uid>, so
    we set the marker unconditionally here first.
    """
    result = subprocess.run(
        ["loginctl", "enable-linger", str(pw.pw_uid)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"loginctl enable-linger failed: {result.stderr}")
    if service_runtime.ensure_runtime_dir(pw.pw_uid, timeout=15):
        ensure_common.log(f"  Enabled linger for {pw.pw_name} (UID {pw.pw_uid})")
        return
    raise RuntimeError(
        f"linger enabled but user@{pw.pw_uid}.service did not become active "
        f"for {pw.pw_name}"
    )


def ensure_manager_slice(pw, config):
    """Migrate the workload's user manager into its target slice (ADR 001 1b).

    The `Slice=<target>` drop-in on `user@<uid>.service` only takes effect when
    PID1 (re)starts the unit: logind's own start path — which `enable_linger`
    goes through — parks a lingered manager under `user-<uid>.slice` and ignores
    the drop-in, so `user@<uid>.service` (and the migrated container payload it
    hosts) never reaches `workloads.slice`. logind re-starts the lingered manager
    into `user-<uid>.slice` on every boot, so this check runs each start.

    Runs at ExecStartPre, before the payload starts, so the mandatory manager
    restart costs nothing (no containers under the manager yet to kill). It is
    idempotent: once the manager is in the right slice this boot, later starts
    are a no-op. Non-fatal — a mis-placed manager still runs the workload; only
    the aggregate-slice grouping is lost, so we warn rather than block start.
    """
    uid = pw.pw_uid
    slice_name = config.get("resources", {}).get("slice", "workloads.slice")
    target = f"/{slice_name}/user@{uid}.service"

    def manager_cgroup():
        r = subprocess.run(
            ["systemctl", "show", f"user@{uid}.service", "-p", "ControlGroup", "--value"],
            capture_output=True, text=True,
        )
        return r.stdout.strip() if r.returncode == 0 else ""

    cgroup = manager_cgroup()
    if not cgroup or target in cgroup:
        return  # unknown state, or already correctly placed — nothing to do

    ensure_common.log(f"  Migrating user@{uid}.service into {slice_name} "
        f"(logind started it at {cgroup!r})")
    subprocess.run(
        ["systemctl", "restart", f"user@{uid}.service"],
        capture_output=True, text=True, timeout=30,
    )
    # Re-pin linger / wait for the manager (and /run/user/<uid>) to come back.
    service_runtime.ensure_runtime_dir(uid, timeout=15)

    cgroup = manager_cgroup()
    if target in cgroup:
        ensure_common.log(f"  user@{uid}.service now in {slice_name}")
    else:
        ensure_common.log(f"  WARNING: user@{uid}.service still not in {slice_name} after restart "
            f"(cgroup={cgroup!r}); workload runs but aggregate-slice grouping is lost")
