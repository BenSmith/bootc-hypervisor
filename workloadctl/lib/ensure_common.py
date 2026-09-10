"""Per-workload user provisioning that does not know which substrate it serves.

The half of `libexec/workload-ensure-user` that runs for every workload: the
home directory, the environment file, the SELinux relabel, the provenance
record. A function belongs here when it cannot tell a VM from a container --
not when it merely happens to be called from both branches today.

`setup_workload_runtime_dir`, `generate_egress_ca` and
`provision_egress_pki_dirs` are keyed on the workload NAME and read nothing
under `[vm]`, which is what lets the container egress path call them verbatim
rather than grow a second copy. Their names must stay substrate-neutral for
the same reason. The PATH the first one operates on is still
`/run/workload-vm/<name>`, and that is not an oversight: the string is an
SELinux fcontext rule the RPM registers, so it is an interface rather than a
name we are free to correct.

`log` is reached as `ensure_common.log(...)` from every other module, never
imported by name. `from ensure_common import log` would COPY the binding, and
a test that then patched the copy would silence nothing while the real writer
ran. That failure is not symmetric: a patch an assertion reads back fails
loudly, but a patch installed only to quiet the journal goes inert and the
test still passes. Fifteen sites patch this function; routing it through the
module leaves exactly one binding to patch, and it is the one every caller
resolves at call time. (The generator's `log_msg` is imported by name because
nothing patches it -- the difference is the traffic, not the taste.)
"""

import os
import shutil
import subprocess
import time

import deployment
from config_parser import workload_root_dir
from workload_lib import (
    workload_state_dir, workload_data_dir, workload_env_dir,
)
from egress_ca import (
    ca_cert_path, ca_dir, denial_dir, leaf_dir, ca_key_path,
    ca_openssl_argv,
)
from vm_defs import VM_SOCKET_DIR

def log(msg):
    """Print to stdout (captured by systemd journal)."""
    print(msg, flush=True)


def warn_if_stale_home(pw, name):
    """Warn (don't fix) when a workload user's passwd home doesn't match the expected state/ dir.

    The workload service is unaffected — the generator forces Environment=HOME=<state>
    in the unit — but podman's auto-generated healthcheck timer runs a bare
    `podman healthcheck run` that inherits the user manager's HOME (= the mismatched
    passwd home), resolves an empty graphroot, can't find the container, and leaves
    health frozen at 'starting' forever.

    We only warn: rewriting an in-use user's home (usermod -d) requires stopping
    the workload and bouncing user@<uid>.service to take effect, which is an
    operator decision, not something to do under an ExecStartPre on every boot.
    """
    expected = str(workload_state_dir(name))
    actual = pw.pw_dir
    if actual == expected:
        return
    uid = pw.pw_uid
    log(f"  WARNING: mismatched home for {pw.pw_name}: {actual!r} (expected {expected!r}).")
    log( "           The service runs correctly, but podman's healthcheck timer "
         "inherits this home and reads an empty graphroot, so health is frozen at 'starting'.")
    log(f"           Fix: systemctl stop workload-{name}; usermod -d {expected} "
        f"{pw.pw_name}; systemctl restart workload-{name}  "
        f"(restarting bounces user@{uid}.service so the new HOME takes effect).")


def setup_home_directory(pw, name):
    """Create and configure the workload's state/ ($HOME) and data/ subdirs.

    Anchored on workload_state_dir/workload_data_dir, not pw.pw_dir: the generator
    forces HOME=<state> independently, so these must land where the service actually
    reads/writes regardless of what passwd records. See warn_if_stale_home.
    """
    state_path = workload_state_dir(name)
    if not state_path.exists():
        log(f"  Creating home (state) directory {state_path}")
        state_path.mkdir(parents=True, exist_ok=True)
    os.chown(state_path, pw.pw_uid, pw.pw_gid)
    os.chmod(state_path, 0o700)

    data_path = workload_data_dir(name)
    if not data_path.exists():
        log(f"  Creating data directory {data_path}")
        data_path.mkdir(parents=True, exist_ok=True)
    os.chown(data_path, pw.pw_uid, pw.pw_gid)
    os.chmod(data_path, 0o700)


def record_deployment_provenance(name):
    """Stamp the workload's /var root with the deployment provisioning it now.

    /etc is per-deployment on ostree and /var is shared, so `bootc rollback`
    takes a workload's config and passwd line away while its state stays behind
    — and `cleanup`'s definition of an orphan ("state with no config") is then
    satisfied by state another deployment still owns. The stamp is how cleanup
    tells the two apart; see lib/deployment.py for the rule it feeds.

    Runs after setup_home_directory, which creates the root. Best-effort by
    design: a missing stamp costs exactly the pre-marker behavior, so warning
    and continuing is strictly better than failing a service start over it.
    """
    root = workload_root_dir(name)
    try:
        if deployment.write_marker(root, name):
            log(f"  Recorded deployment provenance in {deployment.marker_path(root)}")
    except Exception as e:
        log(f"  WARNING: Failed to record deployment provenance for {name}: {e}")


def _provision_dir_secure(root_dir, host_path, uid, gid, mode):
    """Create `host_path` (a descendant of `root_dir`) and chown/chmod it to the
    workload user WITHOUT ever following a symlink (B1 — root-TOCTOU hardening).

    This runs as **root** on every service start inside a tree the *workload
    user* owns, so a `resolve()`-then-`os.chown()` sequence is racy: the workload
    user can swap a path component to a symlink between the containment check and
    the chown, tricking root into chowning an arbitrary host file. We instead
    descend from `root_dir` one literal component at a time with
    `O_NOFOLLOW|O_DIRECTORY` (openat) and `fchown`/`fchmod` the final fd. A
    symlink anywhere on the path makes the openat fail (ELOOP) and we refuse —
    the walk itself enforces containment, so a swapped component can only abort
    provisioning, never escape the tree. `root_dir` is root-created and trusted
    as the anchor.

    Returns True on success, False if a component was unsafe (symlink/non-dir).
    """
    # Walk the LITERAL path components (not host_path.resolve(), which would
    # collapse away the very symlink we must refuse). `root_dir` is the trusted,
    # root-created anchor; every component below it is opened O_NOFOLLOW.
    try:
        parts = host_path.relative_to(root_dir).parts
    except ValueError:
        return False  # not lexically under the root — caller also gates this
    if not parts:
        # host_path == root_dir: chowning the anchor would hand the workload
        # user ownership of the root-owned trust boundary this walk relies on.
        log(f"  WARNING: refusing to provision {host_path}: it is the "
            f"workload root itself")
        return False
    if ".." in parts:
        log(f"  WARNING: refusing to provision {host_path}: '..' in path")
        return False
    dir_fd = os.open(str(root_dir), os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts:
            child_fd = None
            for _ in range(2):
                try:
                    child_fd = os.open(
                        part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=dir_fd)
                    break
                except FileNotFoundError:
                    try:
                        os.mkdir(part, mode, dir_fd=dir_fd)
                    except FileExistsError:
                        pass  # created concurrently — retry the O_NOFOLLOW open
                except OSError as exc:
                    # ELOOP (symlink) or ENOTDIR — refuse to traverse.
                    log(f"  WARNING: refusing to provision {host_path}: unsafe "
                        f"path component {part!r} ({exc.strerror})")
                    return False
            if child_fd is None:
                log(f"  WARNING: refusing to provision {host_path}: unsafe "
                    f"path component {part!r}")
                return False
            os.close(dir_fd)
            dir_fd = child_fd
        os.fchown(dir_fd, uid, gid)
        os.fchmod(dir_fd, mode)
        return True
    finally:
        os.close(dir_fd)


def _descend_nofollow(root_dir, parts, what: str):
    """Open the directory at `parts` below `root_dir`, one literal component at a
    time, never following a symlink — the non-creating half of the walk
    `_provision_dir_secure` documents at length, factored out because more than
    one caller needs root to reach a path inside a tree the workload user owns.

    Returns the final directory fd (the CALLER closes it), or None if a
    component was missing, not a directory, or a symlink.
    """
    dir_fd = os.open(str(root_dir), os.O_RDONLY | os.O_DIRECTORY)
    for part in parts:
        try:
            child_fd = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=dir_fd)
        except FileNotFoundError:
            os.close(dir_fd)
            return None
        except OSError as exc:
            log(f"  WARNING: refusing to {what}: unsafe path "
                f"component {part!r} ({exc.strerror})")
            os.close(dir_fd)
            return None
        os.close(dir_fd)
        dir_fd = child_fd
    return dir_fd


def restore_selinux_labels(name):
    """Restore SELinux labels on the workload's whole tree (state/ + data/).

    Relabels the canonical workload root, not the passwd home: for a correct
    user the passwd home is state/ (which would miss data/), and for a stale
    user it's the root — anchoring on workload_root_dir covers both subtrees.
    """
    target = str(workload_root_dir(name))
    # -F is REQUIRED, not belt-and-braces. Both container_file_t and
    # svirt_image_t are listed in contexts/customizable_types, and plain
    # restorecon SKIPS any file whose *current* type is customizable — it
    # prints "not reset as customized by admin", visible only under -v, and
    # exits 0. Without -F a VM workload's tree would silently never migrate
    # from the blanket container_file_t to svirt_image_t, and the failure would
    # surface much later as a confined QEMU unable to read its own disk.
    result = subprocess.run(
        ["restorecon", "-RF", target],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        log(f"  WARNING: restorecon failed for {target}: {result.stderr}")


def _detect_host_ip():
    """Return the host's primary LAN IP via the default route, or empty string.

    Uses the source address that would be chosen to reach 1.1.1.1, which
    selects the default-route interface and ignores secondary addresses (e.g.
    libvirt bridges, VPN tuns). Override by setting HOST_IP in the workload's
    [container.environment] in its TOML — an explicit value there takes
    precedence over the EnvironmentFile.
    """
    try:
        out = subprocess.check_output(
            ["ip", "-4", "route", "get", "1.1.1.1"],
            stderr=subprocess.DEVNULL, text=True
        )
        for token, nxt in zip(out.split(), out.split()[1:]):
            if token == "src":
                return nxt
    except Exception:
        pass
    return ""


def write_environment_file(name, pw, config):
    """Write UID-dependent environment variables for the systemd service.

    The generated service uses EnvironmentFile= to pick up XDG_RUNTIME_DIR
    (which depends on the UID). This allows the generator to create service
    files before the user exists.
    """
    # No mode= here: systemd/workloads-dirs.conf owns this directory's mode and
    # tmpfiles runs under sysinit.target, long before any workload's
    # ExecStartPre — so exist_ok=True makes a mode= argument dead, and 0700
    # would be wrong anyway (see that file: the workload user must traverse
    # this dir to read its own --env-file). Bare mkdir is the boot-order
    # fallback only.
    env_dir = workload_env_dir()
    env_dir.mkdir(parents=True, exist_ok=True)

    lines = [
        f"XDG_RUNTIME_DIR=/run/user/{pw.pw_uid}",
        f"HOST_IP={_detect_host_ip()}",
    ]

    env_file = env_dir / f"workload-{name}.env"
    env_file.write_text("\n".join(lines) + "\n")
    log(f"  Wrote environment file {env_file}")


def setup_workload_runtime_dir(pw, name: str):
    """Create the runtime directory /run/workload-vm/{name}/, labelled.

    Both substrates: a VM's QMP and console sockets, and a filtered
    container's inspect.json. The path keeps `workload-vm` in it because the
    RPM registers an fcontext rule on that exact string.

    The relabel is REQUIRED, and registering the fcontext rule is not enough on
    its own. The kernel labels a newly created file from its parent directory,
    not from `file_contexts` — that file is consulted only by userspace tools
    like restorecon. So the rule the RPM's %post registers
    (`/run/workload-vm(/.*)? -> svirt_var_run_t`) does nothing for a directory
    mkdir'd here: it inherits `var_run_t` from /run, and a confined QEMU then
    cannot create its QMP socket, cannot read the cloud-init ISO, and fails to
    start rather than degrading. /run is a tmpfs, so this recurs every boot.

    It happens HERE, before anything is written into the directory, because
    everything created inside afterwards (the sockets, cloud-init.iso) inherits
    from the directory — relabelling later would leave those behind.

    Plain restorecon, no -F: var_run_t is not a customizable type, unlike the
    container_file_t/svirt_image_t pair under /var/lib/workloads.
    """
    sock_dir = VM_SOCKET_DIR / name
    sock_dir.mkdir(parents=True, exist_ok=True)
    if shutil.which("restorecon"):
        # Recursive and rooted at the parent: the parent is what the rule names,
        # and a wrong label there is inherited by every workload's subdirectory.
        subprocess.run(["restorecon", "-R", str(VM_SOCKET_DIR)],
                       check=False, capture_output=True)
    os.chown(sock_dir, pw.pw_uid, pw.pw_gid)
    os.chmod(sock_dir, 0o750)
    log(f"  Socket directory: {sock_dir}")


def generate_egress_ca(pw, name: str):
    """Generate this workload's egress CA if absent, or raise with openssl's words.

    Symmetric to generate_vm_host_keypair, and here for the same reason it is:
    the seed ISO carries this certificate, so "before the seed" has to be a fact
    about one function rather than an ordering between units. Both are called a
    few lines above build_cloud_init_iso in the same process.

    Idempotent, and the guard is what keeps it so. Re-minting would invalidate
    the anchor already installed in a provisioned guest exactly as churning the
    host key would invalidate the SSH pin -- and worse, because cloud-init runs
    once per instance-id, so the replacement never arrives and every HTTPS
    request fails validation on a VM `diagnose` calls healthy.

    Generated for every filtered VM whatever `tls` says. Gating it on
    tls = "inspect" would turn the emergency splice into a one-way door: the
    seed is fingerprinted over its rendered text, so dropping the CA out of it
    rotates the instance-id and re-provisions the guest in the middle of the
    incident the hatch exists for.

    When it DOES mint, it clears the leaf caches -- see the comment at the end.
    provision_egress_pki_dirs recreates and relabels them a moment later, which is
    why removing them here is safe.
    """
    dir_path = ca_dir(workload_state_dir(name))
    key_path = ca_key_path(workload_state_dir(name))
    cert_path = ca_cert_path(workload_state_dir(name))

    if key_path.exists() and cert_path.exists():
        return  # already minted -- keep the guest's anchor valid

    dir_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(dir_path, pw.pw_uid, pw.pw_gid)

    result = subprocess.run(
        ca_openssl_argv(name, key_path, cert_path, now=time.time()),
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        # Same both-streams reasoning as _ssh_keygen: openssl splits its
        # diagnostics across stdout and stderr depending on the failure, so
        # reporting one of them yields an empty message on some runs.
        said = " / ".join(s.strip() for s in (result.stdout, result.stderr)
                          if s.strip())
        raise RuntimeError(
            f"openssl (egress CA) failed: "
            f"{said or f'no output, exit {result.returncode}'}")

    os.chown(key_path, pw.pw_uid, pw.pw_gid)
    os.chmod(key_path, 0o600)
    os.chown(cert_path, pw.pw_uid, pw.pw_gid)
    # The certificate is 0644 and the key is 0600: the certificate is a public
    # anchor that the seed builder and `diagnose` both read, and the private
    # half is the only part worth protecting.
    os.chmod(cert_path, 0o644)

    # A NEW CA MAKES EVERY CACHED LEAF A FORGERY, so the caches go with it.
    # This runs only on the branch that actually minted -- the guard above
    # returns before it for the ordinary case -- and the case it exists for is
    # an operator recovering a lost or damaged CA by deleting state/ca. The
    # leaves are files with a 30-day life, LeafCache adopts any PEM it finds at
    # the hashed path without asking who signed it, and the guest by then
    # trusts only the replacement. The result is a guest that fails handshakes
    # on exactly its established hosts, told by the listener's own log line to
    # re-seed -- which is both the wrong remedy and already done.
    for cache_dir in (leaf_dir(workload_state_dir(name)),
                      denial_dir(workload_state_dir(name))):
        shutil.rmtree(cache_dir, ignore_errors=True)

    log(f"  Generated egress CA: {cert_path}")


def provision_egress_pki_dirs(pw, name: str):
    """Create the leaf caches beside the CA, then label the whole PKI subtree.

    Two jobs that have to happen in this order and in this process.

    The directories exist here rather than being left to the minter's own
    mkdir because of the labelling below: a directory the inspector creates
    for itself inherits its parent's type (svirt_image_t, the workload tree
    rule), and the inspector has no `relabelto` on anything, so it would
    create a directory it then cannot use. Creating them as root and relabelling
    once is the only ordering where the inspector never has to.

    And the relabel is needed at all because `restorecon` is userspace:
    file_contexts.local decides what a path SHOULD be labelled, while the
    kernel labels a newly created directory from its parent. The fcontext rules
    are registered at enable, before this runs, so nothing has applied them to
    a subtree that did not exist yet.

    Best-effort: a host without restorecon, or with SELinux disabled, gets an
    unlabelled subtree and an inspector that fails loudly at startup, which is
    a better failure than refusing to provision the VM at all.
    """
    state_dir = workload_state_dir(name)
    for directory in (ca_dir(state_dir), leaf_dir(state_dir),
                      denial_dir(state_dir)):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chown(directory, pw.pw_uid, pw.pw_gid)
        if shutil.which("restorecon"):
            # -F for the same reason apply_vm_fcontext needs it: svirt_image_t
            # is in contexts/customizable_types, so a plain restorecon skips
            # every directory currently carrying it and exits 0.
            subprocess.run(["restorecon", "-RF", str(directory)],
                           check=False, capture_output=True)
