"""
provisioning — the provisioning steps enable, disable and recreate share.

Everything here acts on the host on a workload's behalf: pre-flight checks, the
user/UID provisioning that consumes the generator's output, image transfer into
the workload's rootless store, unit generation and service start. The two
steps that run in both directions and take an `action` -- a teardown is the
same step with the sign flipped -- have their own modules: the [host] setup
hook is host_setup, the per-workload SELinux type and module workload_selinux.
"""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from cli_log import error, info
from config_parser import workload_root_dir
from workload_lib import (
    RUN_SYSTEMD_SYSTEM,
)
from podman import Podman
from workloadctl_core import (
    UsageError, WorkloadConfig, WorkloadManager, WorkloadUserNotFound,
)
from substrate import LifecycleError
from vm_defs import SEED_CONTRACT_EXIT


REQUIRED_EXECUTABLES = ["podman", "systemctl", "loginctl", "systemd-sysusers", "restorecon", "semodule"]
RECOMMENDED_EXECUTABLES = ["semanage", "udica"]




def _image_available(config: WorkloadConfig, image: str) -> bool:
    """True if a pull=never image is reachable by the workload's containers.

    Asks the same question the runtime path answers: root's store (the
    transfer_image() source) first, then the workload user's own store —
    an image staged directly into the user store satisfies the gate too.
    (The user store is a legitimate source in its own right: the override
    channel transfers there, and `containers-storage` is policy-exempt, so
    an operator can also stage an image with `sudo -u _wl-<name> podman
    load`.) Root first because on a first enable the workload user doesn't
    exist yet; in that case only root's store can hold the image.
    """
    if Podman.for_root().image_id(image):
        return True
    try:
        uid = config.uid
    except WorkloadUserNotFound:
        return False
    return bool(
        Podman.for_user(config.username, uid, config.home_dir).image_id(image)
    )


def preflight_checks(config: WorkloadConfig) -> bool:
    """Run pre-flight checks for a workload. Returns True if all checks pass."""
    info()
    info("Running pre-flight checks...")
    failed = False

    # Check required executables are available
    missing_required = [exe for exe in REQUIRED_EXECUTABLES if not shutil.which(exe)]
    if missing_required:
        info("  ✗ Missing required executables:")
        for exe in missing_required:
            info(f"    - {exe}")
        failed = True

    missing_recommended = [exe for exe in RECOMMENDED_EXECUTABLES if not shutil.which(exe)]
    if missing_recommended:
        info("  ! Missing recommended executables (SELinux policy management):")
        for exe in missing_recommended:
            info(f"    - {exe}")
        info("    Install: dnf install policycoreutils-python-utils checkpolicy")

    if config.is_vm:
        # VM-specific preflight: qemu, OVMF firmware, /dev/kvm, socat (for
        # `workloadctl shell` which execs into socat to reach the serial
        # console). Surface socat here so the first console attempt doesn't
        # exec-fail with a generic ENOENT.
        vm_required = ["qemu-system-x86_64", "qemu-img", "socat"]
        missing_vm = [exe for exe in vm_required if not shutil.which(exe)]
        if missing_vm:
            info("  ✗ Missing required VM executables:")
            for exe in missing_vm:
                info(f"    - {exe}")
            info("    Install: dnf install qemu-kvm socat")
            failed = True

        if not Path("/dev/kvm").exists():
            info("  ✗ /dev/kvm not found — KVM acceleration unavailable")
            info("    Enable nested KVM or run on bare metal")
            failed = True

        # From vm_defs, the module that DEFINES it, not from vm, which only
        # re-exports it: a name reached through a re-export cannot be patched
        # at its source, and this check is exercised entirely by patching.
        from vm_defs import find_ovmf_code
        if not find_ovmf_code():
            info("  ✗ OVMF firmware (edk2-ovmf) not found")
            info("    Install: dnf install edk2-ovmf")
            failed = True

        # Only a VM pinned to an operator-provided bridge goes through
        # qemu-bridge-helper and so needs an entry in its allow-list. Under
        # passt (the default) there is no bridge and no setuid-root helper in
        # the data path at all, so there is nothing to check.
        bridge = config.vm_bridge
        if bridge is not None:
            bridge_conf = Path("/etc/qemu/bridge.conf")
            if (not bridge_conf.exists()
                    or f"allow {bridge}" not in bridge_conf.read_text(errors="replace")):
                info(f"  ! /etc/qemu/bridge.conf missing 'allow {bridge}'")
                info(f"    Add it: echo 'allow {bridge}' | sudo tee -a {bridge_conf}")
                info("    (workloadctl provisions the bridge you named no more than "
                     "it provisions the bridge itself)")

        return not failed

    from workload_lib import expand_volume_path
    # Check pull=never images exist locally (once per container)
    for _cname, image, pull in config.container_specs():
        if pull == "never" and not _image_available(config, image):
            info(f"  ✗ Image '{image}' not found locally and pull=never")
            build_script = config.resolve_control_file("build.sh")
            if build_script.exists():
                info("    Build the image first:")
                info(f"      sudo {build_script}")
            else:
                info("    Build or pull the image first, or change pull policy")
            failed = True

    # Check required files exist (declared in [setup].required_files)
    required_files = config.get_required_files()
    required_file_paths = {entry["path"] for entry in required_files}
    missing_required_files = [e for e in required_files if not Path(e["path"]).exists()]

    if missing_required_files:
        # Auto-copy is gated on the destination being inside the workload's own
        # tree. Anchor on the workload ROOT, not home_dir: home_dir is the
        # state/ subdir, but `./`-anchored required_files resolve to the data/
        # sibling — checking against home_dir (state/) would reject every
        # data/ destination and silently skip the copy.
        # A hint is only a source path when it is absolute; bundles also use the
        # field for prose ("WireGuard client config from your VPN provider"). A
        # bare `Path(hint).exists()` would resolve a non-absolute hint against
        # the operator's cwd, so running enable from the wrong directory could
        # copy an unrelated same-named file into the workload's data dir. Same
        # test the instruction printer below uses, so the two branches agree on
        # what a hint is.
        root_resolved = workload_root_dir(config.name).resolve()
        still_missing = []
        for entry in missing_required_files:
            dest = Path(entry["path"])
            hint = entry.get("hint")
            if (hint and Path(hint).is_absolute() and Path(hint).exists()
                    and dest.resolve().is_relative_to(root_resolved)):
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(hint, dest)
                info(f"  ✓ Copied config template: {dest}")
            else:
                still_missing.append(entry)

        if still_missing:
            info("  ✗ Missing required files:")
            for entry in still_missing:
                info(f"    - {entry['path']}")
            info()
            info("  Create these files before enabling:")
            for entry in still_missing:
                hint = entry["hint"]
                if hint and Path(hint).is_absolute():
                    info(f"    sudo cp {hint} \\")
                    info(f"             {entry['path']}")
                elif hint:
                    info(f"    # {entry['path']}")
                    info(f"    #   needs: {hint}")
                else:
                    info(f"    # Create {entry['path']}")
            failed = True

    # Check volume paths exist
    # Paths in required_files are files the user must provide
    # All other volume paths are directories to auto-create
    volumes = config.all_volumes()
    missing_dirs = []
    missing_files = []

    for vol_spec in volumes:
        expanded_spec = expand_volume_path(vol_spec, str(config.home_dir))
        host_path = expanded_spec.split(':')[0]

        if Path(host_path).exists():
            continue

        if host_path in required_file_paths:
            missing_files.append(host_path)
        else:
            missing_dirs.append(host_path)

    if missing_dirs:
        # Same root-vs-home distinction as the required_files copy above: a `./`
        # volume dir resolves under data/ (sibling of state/), so anchor the
        # "auto-create vs operator-must-provision" split on the workload ROOT.
        # Genuinely external bind sources (absolute host paths) stay must-create.
        root_resolved = workload_root_dir(config.name).resolve()
        auto_create = [p for p in missing_dirs
                       if Path(p).resolve().is_relative_to(root_resolved)]
        must_create = [p for p in missing_dirs
                       if not Path(p).resolve().is_relative_to(root_resolved)]

        for path in auto_create:
            Path(path).mkdir(parents=True, exist_ok=True)
            info(f"  ✓ Created volume directory: {path}")

        if must_create:
            info("  ✗ Missing volume directories (outside workload home):")
            for path in must_create:
                info(f"    - {path}")
            info()
            info("  Create these directories before enabling:")
            for path in must_create:
                info(f"    sudo mkdir -p {path}")
            failed = True

    if missing_files:
        info("  ✗ Missing volume files:")
        for path in missing_files:
            info(f"    - {path}")
        info()
        info("  Create these files before enabling (see workload documentation).")
        failed = True

    # Check extra groups exist
    import grp as _grp
    missing_groups = []
    for group in config.get_extra_groups():
        try:
            _grp.getgrnam(group)
        except KeyError:
            missing_groups.append(group)

    if missing_groups:
        info("  ✗ Missing groups:")
        for group in missing_groups:
            info(f"    - {group}")
        info()
        info("  These groups must exist on the system.")
        failed = True

    # Check ip_unprivileged_port_start for host-mode workloads
    if config.get_network_mode() == "host":
        try:
            sysctl_path = Path("/proc/sys/net/ipv4/ip_unprivileged_port_start")
            unpriv_start = int(sysctl_path.read_text().strip())
            if unpriv_start > 0:
                info(f"  ! host-mode workload: ip_unprivileged_port_start={unpriv_start}")
                info(f"    Binding ports below {unpriv_start} will fail with 'permission denied'.")
                info("    Fix: echo 'net.ipv4.ip_unprivileged_port_start = 0' | "
                      "sudo tee /etc/sysctl.d/50-privileged-ports.conf && sudo sysctl --system")
        except Exception:
            pass

    if not failed:
        info("  ✓ Pre-flight checks passed")

    return not failed


def provision_user(config: WorkloadConfig):
    """Create the workload user and configure subuid/subgid, home dir, linger.

    Applies the sysusers config the generator already wrote (single producer —
    see generate_units): enable no longer allocates the UID or renders the
    .conf, it just runs the same two steps the boot path defers to the setup
    service's ExecStartPre. The generator ran under subid_lock() and is the sole
    UID allocator; systemd-sysusers here creates the user from its output.
    """
    sysusers_file = RUN_SYSTEMD_SYSTEM / f"workload-{config.name}.conf"

    info("  Running systemd-sysusers...")
    subprocess.run(["systemd-sysusers", str(sysusers_file)], check=True)

    info("  Configuring workload user...")
    # Not check=True: a seed-contract rejection is an operator error the helper
    # has already reported in full, so surfacing it as CalledProcessError would
    # bury that message under a traceback and the "this looks like a workloadctl
    # bug" banner — telling the operator to file a report for something they are
    # expected to hit and can fix themselves. Every other non-zero still raises.
    result = subprocess.run(
        ["/usr/libexec/workloadctl/workload-ensure-user", config.name],
        check=False,
    )
    if result.returncode == SEED_CONTRACT_EXIT:
        raise UsageError("")  # message already printed by the helper
    if result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, result.args)


class ImageTransferError(Exception):
    """A root→user image transfer failed (or a pull=never image is absent
    everywhere). The message is fully formatted for the operator."""


def transfer_image(config: WorkloadConfig, manager: WorkloadManager):
    """Push locally-held images from root's store into the workload user store.

    Root's store is the *local override channel* for images the workload
    builds itself (`is_buildable`): when it holds the exact ref such a
    container runs (a `workloadctl build`, or a hand-loaded image), that copy
    is transferred and shadows whatever the registry would serve. Third-party
    images are never overridden — their pull policy (`always`/`newer`
    especially) keeps its full meaning and root's store isn't even probed. An
    absent buildable image is an error only for `pull = "never"` (root's store
    is then the sole source); otherwise podman pulls it per policy.
    Raises ImageTransferError; the caller decides what that costs.
    """
    for cname, image, pull in config.container_specs():
        transfer_one_image(config, manager, cname, image, pull)


def transfer_one_image(config: WorkloadConfig, manager: WorkloadManager,
                       cname: str, image: str, pull: str) -> bool:
    """Apply the local override channel (see `transfer_image`) to one
    container's image. Owns the whole gate, so callers loop over
    `container_specs()` unconditionally: a non-buildable container returns
    False with neither store probed, and a buildable ref absent from root's
    store returns False so the caller falls back to its pull policy. Returns
    True when root's store holds the ref — transferred into the user store,
    or already current there — meaning the override supplied the image and
    no pull should happen.

    Compares image IDs between root and user stores; transfers if the user
    store is missing the image or has a stale copy after a rebuild.
    Raises ImageTransferError on a failed transfer, and for a pull=never
    image absent from every store (nothing can supply it).

    Boundary note (B13): the `podman load` step below hand-builds its own
    sudo invocation instead of going through `Podman.run()`. It needs a
    `TMPDIR=config.home_dir` override the wrapper's `_build_cmd()` doesn't
    expose (podman load's staging files must land somewhere the target user
    can write — the wrapper only carries XDG_RUNTIME_DIR/HOME) and a `cwd`
    set to the same dir for consistency. Documented here rather than growing
    the wrapper's env handling for this one call site (see `Podman.run()`).
    """
    if not config.is_buildable(cname, pull):
        return False
    user_image_id = manager.podman(config).image_id(image)
    root_image_id = Podman.for_root().image_id(image)

    if not root_image_id:
        if not user_image_id and pull == "never":
            info()
            build_script = config.resolve_control_file("build.sh")
            if build_script.exists():
                hint = f"Build the image first:\n  sudo {build_script}"
            else:
                hint = f"Build or pull the image '{image}' first."
            raise ImageTransferError(
                f"Error: Image '{image}' not found locally and pull=never\n{hint}"
            )
        return False

    if root_image_id != user_image_id:
        if user_image_id:
            info(f"  Root store has an updated '{image}' (rebuild detected), re-transferring...")
        else:
            info(f"  Transferring '{image}' from root store to workload user store...")

        # Use a temp file rather than a pipe.  podman save via pipe creates a
        # pipeDir in /var/tmp as root (mode 700); the target user can't access
        # it, causing the load to fail with ENOENT on large images.  Writing to
        # a file owned by the target user in their home dir sidesteps this.
        fd, tmp_path = tempfile.mkstemp(suffix=".tar", dir=config.home_dir)
        os.close(fd)
        try:
            os.chown(tmp_path, config.uid, config.gid)

            save_result = subprocess.run(
                ["podman", "save", "--format", "docker-archive", "-o", tmp_path, image],
                capture_output=True,
            )
            if save_result.returncode != 0:
                raise ImageTransferError(
                    f"Error: Failed to save image '{image}': "
                    f"{save_result.stderr.decode(errors='replace')}",
                )

            # TMPDIR=config.home_dir: Podman.run()/_build_cmd() has no env
            # override hook, so this bypasses the wrapper (see the class
            # docstring note on Podman.run()).
            load_result = subprocess.run(
                ["sudo", "-n", "-u", config.username,
                 "-E", f"XDG_RUNTIME_DIR=/run/user/{config.uid}",
                 "-E", f"HOME={config.home_dir}",
                 "-E", f"TMPDIR={config.home_dir}",
                 "podman", "load", "-i", tmp_path],
                capture_output=True,
                cwd=config.home_dir,
            )
            if load_result.returncode != 0:
                raise ImageTransferError(
                    f"Error: Failed to transfer image '{image}': "
                    f"{load_result.stderr.decode(errors='replace')}",
                )
        finally:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
        info(f"  Image '{image}' transferred successfully")
        if user_image_id:
            active = subprocess.run(
                ["systemctl", "is-active", "--quiet", config.service_name],
                check=False
            )
            if active.returncode == 0:
                info("  Note: container is still running the old image.")
                info(f"  Run 'sudo workloadctl recreate {config.name}' to restart with the new image.")
    return True


WORKLOAD_GENERATE_BIN = "/usr/libexec/workloadctl/workload-generate"


def regenerate_units(name: str, *, log_stderr: bool = False) -> None:
    """Re-run the generator for one workload into /run, then daemon-reload.

    `--workload` keeps the run to the one being changed: an unfiltered run
    rewrites every enabled workload's units. `--no-start` keeps the generator
    from enqueuing its own start job -- every caller owns its own apply step,
    and a generator-enqueued start would race ahead of it.

    `log_stderr` routes the generator's own skip/failure lines to stderr. Only
    enable's path asks for it, because there the generator's silence is the
    difference between "nothing to do" and "skipped your workload and exited 0"
    -- and enable checks for produced artifacts immediately after. Edit and
    recreate act on a workload that already generated once, and leave it off
    rather than adding generator chatter to an interactive command.
    """
    subprocess.run(
        [WORKLOAD_GENERATE_BIN, "/run/systemd/system",
         "--workload", name, "--no-start"],
        check=True,
        **({"env": {**os.environ, "WORKLOAD_GENERATE_LOG_STDERR": "1"}}
           if log_stderr else {}),
    )
    subprocess.run(["systemctl", "daemon-reload"], check=True)


def generate_units(config: WorkloadConfig):
    """Run the boot generator against the live /run dir — the single producer.

    The generator emits every per-workload artifact: the sysusers .conf + UID
    allocation, the unit files, the user@<uid> drop-in, and the wants symlink.
    enable runs the same script the boot path runs (rather than re-deriving any
    of it) and then applies the result, so there is exactly one producer.

    Architecture: the real systemd generator (`workload-generator`, shell) only
    emits a single oneshot service (`workload-generate.service`) that runs the
    Python `workload-generate` script at early boot. daemon-reload re-runs
    generators, so it re-emits workload-generate.service — but it does not
    re-run that service, so the per-workload unit files aren't regenerated. For
    post-boot config changes we invoke the Python script directly here, then
    daemon-reload so systemd picks up the new units.

    WORKLOAD_GENERATE_LOG_STDERR routes the generator's per-workload diagnostics
    (which normally go to /dev/kmsg) to this command's stderr, so an operator
    sees the reason inline when a workload can't be generated.

    `--workload` scopes the run to this workload alone. Without it the generator
    emits the whole enabled set, so acting on one workload would rewrite every
    other workload's units and enqueue a start job for each — disturbing
    bystanders and hiding their drift.

    `--no-start` keeps the generator from enqueuing its own start job: enable's
    order (generate → provision user → transfer image → start) is load-bearing,
    and a generator-enqueued start would cold-start the containers before the
    image transfer, pinning them to the stale user-store image.
    """
    info("  Generating service files...")
    regenerate_units(config.name, log_stderr=True)

    # The generator always exits 0 and *skips* any workload it can't process
    # (logging the reason above), so a produced-artifact check is how enable
    # learns whether provisioning can proceed. The sysusers .conf is the first
    # thing the generator writes per workload and the artifact provision_user
    # consumes next; its absence means UID allocation failed — almost always
    # UID-range exhaustion (the one per-workload failure preflight can't catch).
    sysusers_file = RUN_SYSTEMD_SYSTEM / f"workload-{config.name}.conf"
    if not sysusers_file.exists():
        error(
            f"Error: workload-generate produced no units for '{config.name}' "
            f"(see the messages above; the usual cause is UID-range "
            f"exhaustion). Workload left disabled.",
        )
        raise LifecycleError(1)


def start_service(config: WorkloadConfig):
    """Start the workload's umbrella service (units already generated)."""
    info(f"  Starting {config.service_name}...")
    info("  (Image pull may take a few minutes on first start)")
    # A re-enabled unit name can still carry a `start-limit-hit` lockout from a
    # prior incarnation (StartLimitBurst survives userdel/purge), which would
    # refuse this fresh start. Clear it first; idempotent on a clean unit. The
    # start stays `--no-block` so enable returns before a slow first image pull.
    subprocess.run(["systemctl", "reset-failed", config.service_name],
                   check=False, capture_output=True)
    subprocess.run(["systemctl", "start", "--no-block", config.service_name], check=True)
