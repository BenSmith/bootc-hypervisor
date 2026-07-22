"""
cmd_provision — the provisioning steps enable, disable and recreate share.

Everything here acts on the host on a workload's behalf: pre-flight checks, the
user/UID provisioning that consumes the generator's output, image transfer into
the workload's rootless store, unit generation, service start, the [host] setup
hook and the per-workload SELinux type. The hook and the SELinux module take an
`action` because they run in both directions — a teardown is the same step with
the sign flipped, and keeping the pair in one place is what stops enable and
disable from drifting apart.
"""

import difflib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from cli_log import error, info, warn
from workload_lib import (
    selinux_module_name,
    selinux_type_name,
    workload_config_dir,
    workload_data_dir,
    workload_state_dir,
    workload_username,
    WORKLOAD_BUNDLES_DIR,
    NAME_PATTERN,
    RUN_SYSTEMD_SYSTEM,
    workload_root_dir,
)
from podman import Podman
from workloadctl_core import WorkloadConfig, WorkloadManager, WorkloadUserNotFound
from substrate import LifecycleError


REQUIRED_EXECUTABLES = ["podman", "systemctl", "loginctl", "systemd-sysusers", "restorecon", "semodule"]
RECOMMENDED_EXECUTABLES = ["semanage", "udica"]


class SelinuxPolicyError(Exception):
    """Raised by apply_selinux_policy() when loading/removing a workload's
    SELinux type fails.

    Same contract as substrate.ProvisionFailed: the diagnostic has already
    been printed, so the caller exits 1 without printing again (the enable
    path) or lets it fold into the disable path's best-effort failure list.
    """

UDICA_TEMPLATE_DIR = Path("/usr/share/udica/templates")
_BUNDLES_DIR = WORKLOAD_BUNDLES_DIR


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

        from vm import find_ovmf_code
        if not find_ovmf_code():
            info("  ✗ OVMF firmware (edk2-ovmf) not found")
            info("    Install: dnf install edk2-ovmf")
            failed = True

        bridge_conf = Path("/etc/qemu/bridge.conf")
        bridge = config.vm_bridge
        if not bridge_conf.exists() or f"allow {bridge}" not in bridge_conf.read_text(errors="replace"):
            info(f"  ! /etc/qemu/bridge.conf missing 'allow {bridge}'")
            info("    Will be configured automatically on first enable via workload-ensure-user")

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
        root_resolved = workload_root_dir(config.name).resolve()
        still_missing = []
        for entry in missing_required_files:
            dest = Path(entry["path"])
            hint = entry.get("hint")
            if hint and Path(hint).exists() and dest.resolve().is_relative_to(root_resolved):
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
                if entry["hint"]:
                    info(f"    sudo cp {entry['hint']} \\")
                    info(f"             {entry['path']}")
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
    subprocess.run(["/usr/libexec/workloadctl/workload-ensure-user", config.name], check=True)


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
    Exits the process on failure (enable-path semantics).
    """
    try:
        for cname, image, pull in config.container_specs():
            transfer_one_image(config, manager, cname, image, pull)
    except ImageTransferError as e:
        error(str(e))
        sys.exit(1)


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
    subprocess.run(
        ["/usr/libexec/workloadctl/workload-generate", "/run/systemd/system",
         "--workload", config.name, "--no-start"],
        check=True,
        env={**os.environ, "WORKLOAD_GENERATE_LOG_STDERR": "1"},
    )
    subprocess.run(["systemctl", "daemon-reload"], check=True)

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


def host_setup_env(config: WorkloadConfig) -> dict:
    """The instance context a [host] setup script runs against.

    A setup script lives in the *bundle* but acts on an *instance*, and those
    are different names the moment someone runs `init --as` / `duplicate`: the
    bundle stays `gamedev-sway` while the instance is `games`. A script that
    hardcodes its own bundle name therefore touches paths belonging to a
    workload that doesn't exist — and because enable's earlier steps (users,
    units, unit symlinks) already used the *instance* name, the two halves
    disagree and the host is left half-provisioned.

    So the resolved names are passed in rather than left to the script to
    guess. Scripts should treat these as required (`${WORKLOAD_NAME:?}`) —
    defaulting to a baked-in literal reintroduces exactly the bug.
    """
    name = config.name
    return {
        "WORKLOAD_NAME": name,
        "WORKLOAD_BUNDLE": config.bundle,
        "WORKLOAD_USER": workload_username(name),
        "WORKLOAD_INSTANCE_DIR": str(workload_config_dir() / name),
        "WORKLOAD_ROOT_DIR": str(workload_root_dir(name)),
        "WORKLOAD_STATE_DIR": str(workload_state_dir(name)),
        "WORKLOAD_DATA_DIR": str(workload_data_dir(name)),
    }


def run_host_setup(config: WorkloadConfig, action: str):
    """Run host setup script if configured in [host] section.

    The setup script receives 'enable' or 'disable' as its first argument, and
    the instance context of host_setup_env() in its environment.
    It is expected to be idempotent in both directions.
    """
    setup_script = config.config.get("host", {}).get("setup", "")
    if not setup_script:
        return

    # Relative names resolve through the override chain (/etc override wins over
    # the shipped bundle); an absolute path is taken verbatim.
    script_path = config.resolve_control_file(setup_script)

    if not script_path.exists():
        warn(f"  WARNING: Host setup script not found: {script_path}")
        return

    info(f"  Running host setup script ({action})...")
    result = subprocess.run(
        [str(script_path), action],
        capture_output=False,
        env={**os.environ, **host_setup_env(config)},
    )
    if result.returncode != 0:
        error(f"  Error: Host setup script exited with code {result.returncode}")
        if action == "enable":
            sys.exit(1)


def _selinux_available() -> bool:
    """True if the host can load CIL policy modules (semodule + udica bases)."""
    return bool(shutil.which("semodule")) and UDICA_TEMPLATE_DIR.is_dir()


def _selinux_enforcing() -> bool:
    """True if SELinux is currently in enforcing mode."""
    try:
        result = subprocess.run(["getenforce"], capture_output=True, text=True)
        return result.returncode == 0 and result.stdout.strip() == "Enforcing"
    except FileNotFoundError:
        return False


def _available_bundles() -> list[str]:
    """Bundle names shipping a CIL policy under the workloads share dir.

    A bundle is a subdir <name>/ that contains policy.cil (the template
    apply_selinux_policy loads). Returned sorted for stable output.
    """
    if not _BUNDLES_DIR.is_dir():
        return []
    return sorted(
        d.name for d in _BUNDLES_DIR.iterdir()
        if d.is_dir() and (d / "policy.cil").exists()
    )


def _print_available_bundles(bundle: str):
    """Hint at valid selinux_policy bundles after a missing-template error."""
    available = _available_bundles()
    if not available:
        return
    match = difflib.get_close_matches(bundle, available, n=1)
    if match:
        error(f"         did you mean {match[0]!r}?")
    error("         available bundles: " + ", ".join(available))


def apply_selinux_policy(config: WorkloadConfig, action: str):
    """Load (enable) or remove (disable) a workload's per-workload SELinux type.

    The bundle ships its policy as a CIL template (`policy.cil`) using the
    __WL_MODULE__ placeholder. On enable we substitute the name-keyed block name
    (wl_<name>) and load it alongside udica's base templates (which the
    workload's `(blockinherit ...)` resolves against); on disable we remove the
    wl_<name> module, leaving the shared base templates loaded.

    No-op for workloads without `[security].selinux_policy = true`.
    """
    if not config.selinux_policy:
        return

    module = selinux_module_name(config.name)

    if not _selinux_available():
        # Hard-fail only on enable: the container would fail to start under
        # enforcing mode without its type loaded. disable is best-effort
        # teardown — without tooling there's nothing we could remove anyway, so
        # never block it.
        if action != "disable" and _selinux_enforcing():
            error(f"  ERROR: selinux_policy is set for '{config.name}' but SELinux tooling "
                  f"(semodule + container-selinux templates) is missing. The container "
                  f"would fail to start under enforcing mode. Install container-selinux "
                  f"and policycoreutils, then re-run enable.")
            raise SelinuxPolicyError(f"selinux tooling missing for '{config.name}'")
        warn(f"  WARNING: SELinux tooling (semodule + udica templates) not "
             f"found; skipping policy {action} for '{config.name}'")
        return

    if action == "disable":
        loaded = subprocess.run(["semodule", "-l"], capture_output=True, text=True)
        if module in loaded.stdout.split():
            info(f"  Removing SELinux module {module}...")
            subprocess.run(["semodule", "-r", module], check=False)
        return

    # enable: substitute the block name and load the workload CIL alongside the
    # udica base templates (so any `(blockinherit ...)` resolves). semodule -i
    # upgrades in place, so re-enabling is idempotent. The CIL is sourced from
    # the bundle dir (defaults to the workload name; a `selinux_policy` string
    # names it explicitly so a renamed workload keeps its original policy).
    bundle = config.selinux_bundle
    if bundle is None:
        # Reached only if a workload without selinux_policy is routed here.
        error(f"  ERROR: no SELinux bundle resolved for '{config.name}' "
              f"(selinux_policy not set)")
        raise SelinuxPolicyError(f"no SELinux bundle resolved for '{config.name}'")
    if not NAME_PATTERN.match(bundle):
        # bundle goes straight into a filesystem path; reject anything that
        # isn't a plain workload-style name (blocks traversal / odd values).
        error(f"  ERROR: invalid [workload] bundle {bundle!r} "
              f"(must match {NAME_PATTERN.pattern})")
        # Common footgun: users copy the SELinux *type* name (wl_foo_bar,
        # underscores) into `bundle`, but the bundle is a directory name
        # and dirs are hyphenated. Suggest the hyphenated form.
        if "_" in bundle:
            error(f"         did you mean {bundle.replace('_', '-')!r}? "
                  f"(the bundle is a directory name and uses hyphens, not the "
                  f"underscores of the SELinux type name)")
        raise SelinuxPolicyError(f"invalid bundle {bundle!r} for '{config.name}'")
    template = config.resolve_control_file("policy.cil")
    if not template.exists():
        error(f"  ERROR: SELinux policy template not found: {template}")
        _print_available_bundles(bundle)
        raise SelinuxPolicyError(f"policy template not found for '{config.name}'")

    bases = sorted(str(p) for p in UDICA_TEMPLATE_DIR.glob("*.cil"))
    src = template.read_text().replace("__WL_MODULE__", module)

    info(f"  Installing SELinux module {module} (type {selinux_type_name(config.name)})...")
    with tempfile.TemporaryDirectory() as work:
        cil = Path(work) / f"{module}.cil"
        cil.write_text(src)
        try:
            subprocess.run(["semodule", "-i", str(cil), *bases], check=True)
        except subprocess.CalledProcessError as e:
            error(f"  Error: SELinux policy install failed (exit {e.returncode})")
            raise SelinuxPolicyError(f"semodule -i failed for '{config.name}'")
