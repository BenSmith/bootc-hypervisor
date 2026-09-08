"""The provisioning a VM workload needs and a container workload never does.

NVRAM, virtiofs host directories, the per-workload SSH keypair, the SSH host
key, and the cloud-init seed ISO. The cut is by substrate and it is exact:
nothing here calls anything in the container half and nothing there calls
anything here -- the two sets were measured to have zero edges between them
before a line moved. What both need lives in ensure_common, which is also
where three `..._vm_...`-named functions live, because their names describe
where they were written rather than what they read.

`log` is reached as `ensure_common.log(...)`, never imported by name; see that
module's docstring for why the copy matters here specifically.

Tests import THIS module rather than reaching these functions through the
entrypoint that imports them. The entrypoint's copies are bindings, and a
patch installed on a binding is not seen by the function that resolves the
original.
"""
import base64
import hashlib
import os
import re
import shutil
import stat
import subprocess
import uuid
from pathlib import Path, PurePosixPath

from workload_lib import (
    WORKLOAD_CONFIG_DIR, expand_volume_path, virtiofs_tags,
    parse_volume_spec, workload_state_dir, workload_root_dir,
    replace_file_atomically,
)
from vm import (
    VM_SOCKET_DIR, VM_DEFAULT_GUEST_USER, VM_GUEST_HOME_BASE, VM_GUEST_UID,
    VM_CA_BUNDLE_AVAILABLE, VM_CA_BUNDLE_PATH, VM_CA_ENV_VARS,
    VM_HOME_SELINUX_CONTEXT, VM_HOME_SELINUX_TYPES, SeedContractError,
    find_ovmf_vars, vm_ca_env, vm_ca_cert_path, vm_credential_env,
    vm_ptp_kvm_runcmd_lines, vm_ptp_kvm_seed_files, vm_uses_inspect,
)
from vm_provision import (
    MAX_HEAL_ATTEMPTS, PROVISION_UNVERIFIED, heal_attempts,
    read_provision_marker, should_heal, write_provision_marker,
)
from secrets_template import substitute_template
import ensure_common
from ensure_common import (
    _provision_dir_secure, _descend_nofollow,
)

def setup_vm_volume_directories(pw, config):
    """Create host-side directories for virtiofs volumes declared in [vm].volumes.

    Resolves anchors via expand_volume_path (so `./` → data/, `@/` →
    state/volumes/, exactly like containers and the virtiofsd sidecars the
    generator emits) and anchors on the canonical Step-2 dirs. Paths outside the
    workload dir are skipped — the admin must create those by hand.
    """
    name = config["workload"]["name"]
    state_dir = workload_state_dir(name)
    root_dir = workload_root_dir(name)
    for vol_spec in config.get("vm", {}).get("volumes", []):
        host_path_str = expand_volume_path(vol_spec, str(state_dir)).split(":", 2)[0]
        if not host_path_str:
            continue
        host_path = Path(host_path_str)
        try:
            host_path.resolve().relative_to(root_dir.resolve())
        except ValueError:
            continue  # Outside the workload dir — admin's responsibility
        if not host_path.exists():
            ensure_common.log(f"  Creating virtiofs host directory {host_path}")
        _provision_dir_secure(root_dir, host_path, pw.pw_uid, pw.pw_gid, 0o755)


def setup_nvram(pw, config: dict):
    """Copy OVMF_VARS.fd to workload home as nvram.fd (per-VM writable NVRAM)."""
    home_path = Path(pw.pw_dir)
    nvram_dst = home_path / "nvram.fd"
    if nvram_dst.exists():
        return  # already present — do not overwrite (would reset EFI vars)

    ovmf_vars = find_ovmf_vars()
    if ovmf_vars is None:
        raise RuntimeError(
            "OVMF_VARS.fd not found; the VM references nvram.fd unconditionally "
            "and would fail to boot. Install edk2-ovmf (Fedora) or ovmf (Debian)."
        )

    shutil.copy2(ovmf_vars, nvram_dst)
    os.chown(nvram_dst, pw.pw_uid, pw.pw_gid)
    os.chmod(nvram_dst, 0o600)
    ensure_common.log(f"  Copied NVRAM: {ovmf_vars} → {nvram_dst}")


def _ssh_keygen(key_path: Path, comment: str, what: str):
    """Write an Ed25519 keypair to key_path, or raise with what ssh-keygen said.

    ssh-keygen talks on **stdout**, not stderr — the key paths, the fingerprint
    and the randomart all go there on success, and a failure like
    `Saving key "/x" failed: Permission denied` goes there too. Reporting
    `result.stderr` alone therefore yields an empty diagnostic on precisely the
    runs where one is needed, so take both streams and say so if there were
    neither.
    """
    result = subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", comment,
         "-f", str(key_path)],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        return
    if key_path.exists():
        # The key appeared after the caller's exists() guard, so ssh-keygen
        # refused to overwrite it (it wants an interactive "Overwrite?"). Only a
        # concurrent provisioning run can have put it there, and it is as good a
        # key as the one we were about to write — take it. ensure_user_lock()
        # should make this unreachable; it stays because the alternative to
        # losing this race gracefully is failing an `enable` for no reason.
        return
    said = " / ".join(s.strip() for s in (result.stdout, result.stderr) if s.strip())
    raise RuntimeError(
        f"ssh-keygen ({what}) failed: {said or f'no output, exit {result.returncode}'}")


def generate_ssh_keypair(pw, name: str):
    """Generate a per-workload Ed25519 SSH keypair if it doesn't exist.

    Raises RuntimeError on failure: the cloud-init ISO depends on the pubkey
    to inject an authorized_keys entry; a missing key would silently produce
    a VM with a passwordless sudoer and no way for `workloadctl exec` to SSH
    in. Better to fail provisioning loudly.
    """
    home_path = Path(pw.pw_dir)
    ssh_dir = home_path / ".ssh"
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    os.chown(ssh_dir, pw.pw_uid, pw.pw_gid)

    key_path = ssh_dir / "id_ed25519"
    if key_path.exists():
        return  # already generated

    _ssh_keygen(key_path, f"workload-{name}@hypervisor", "client key")

    os.chown(key_path, pw.pw_uid, pw.pw_gid)
    os.chmod(key_path, 0o600)
    pub_path = key_path.with_suffix(".pub")
    if pub_path.exists():
        os.chown(pub_path, pw.pw_uid, pw.pw_gid)
        os.chmod(pub_path, 0o644)
    ensure_common.log(f"  Generated SSH keypair: {key_path}")


def _read_ssh_pubkey(pw) -> str:
    """Return the workload's public SSH key, or '' if not generated yet."""
    pub_path = Path(pw.pw_dir) / ".ssh" / "id_ed25519.pub"
    try:
        return pub_path.read_text().strip()
    except OSError:
        return ""


def _validated_guest_user(vm_cfg) -> str:
    """Return [vm].user, refusing anything that is not a POSIX username.

    The value is interpolated unquoted into the built-in #cloud-config
    (`- name: {guest_user}`, just above a NOPASSWD sudo grant) and is joined into
    a host path by seed_vm_home_share_ssh_key, so both callers need the same
    guarantee: a value carrying a newline could inject arbitrary cloud-config,
    and one carrying a slash or '..' could aim the seed at another directory.
    Fail closed — a bad name aborts VM provisioning.
    """
    guest_user = vm_cfg.get("user", VM_DEFAULT_GUEST_USER)
    if not re.match(r'^[a-z_][a-z0-9_-]*$', guest_user) or len(guest_user) > 32:
        raise RuntimeError(
            f"[vm].user {guest_user!r} is not a valid POSIX username "
            f"(^[a-z_][a-z0-9_-]*$, max 32 chars)"
        )
    return guest_user



# An authorized_keys larger than this is not a real one — refuse to read it into
# memory rather than let a workload-owned file dictate root's allocation.
_AUTHORIZED_KEYS_MAX = 1 << 20

def _seed_authorized_keys(root_dir, ssh_dir: Path, pubkey: str, uid, gid) -> bool:
    """Ensure `pubkey` is present in <ssh_dir>/authorized_keys, as the workload user.

    Runs as root inside a tree the workload user owns, so it reaches the file
    through _descend_nofollow and opens it O_NOFOLLOW: a symlink swapped in for
    authorized_keys must fail the open, never redirect root's write. Additive by
    design — an operator's own keys in the file are kept, and a file that already
    carries ours is left byte-identical.

    Returns True if the key was written, False if it was already there.
    Raises RuntimeError if the file cannot be reached or is not a plain file:
    the caller has already decided the guest depends on it.
    """
    parts = (ssh_dir / "authorized_keys").relative_to(root_dir).parts
    dir_fd = _descend_nofollow(root_dir, parts[:-1], f"seed {ssh_dir}")
    if dir_fd is None:
        raise RuntimeError(f"cannot reach {ssh_dir} safely")
    try:
        created = True
        try:
            fd = os.open("authorized_keys",
                         os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=dir_fd)
        except FileExistsError:
            created = False
            try:
                fd = os.open("authorized_keys", os.O_RDWR | os.O_NOFOLLOW,
                             dir_fd=dir_fd)
            except OSError as exc:
                # ELOOP: authorized_keys is a symlink. O_NOFOLLOW turned an
                # arbitrary-file write by the workload user into this error.
                raise RuntimeError(
                    f"{ssh_dir}/authorized_keys is not a plain file "
                    f"({exc.strerror})") from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise RuntimeError(
                    f"{ssh_dir}/authorized_keys is not a regular file")
            # A hardlink to a file elsewhere would make this write — and the
            # chown below — reach outside the tree.
            if st.st_nlink != 1:
                raise RuntimeError(
                    f"{ssh_dir}/authorized_keys has {st.st_nlink} hardlinks")
            if st.st_size > _AUTHORIZED_KEYS_MAX:
                raise RuntimeError(
                    f"{ssh_dir}/authorized_keys is {st.st_size} bytes — refusing to read")
            existing = os.read(fd, st.st_size).decode("utf-8", "replace")
            present = pubkey.strip() in (l.strip() for l in existing.splitlines())
            if not present:
                os.lseek(fd, 0, os.SEEK_END)
                if existing and not existing.endswith("\n"):
                    os.write(fd, b"\n")
                os.write(fd, pubkey.strip().encode() + b"\n")
            os.fchown(fd, uid, gid)
            # Only force the mode when we made the file or when sshd's
            # StrictModes would reject what is there (group/other bits): an
            # operator's deliberate 0640 is none of our business.
            if created or st.st_mode & 0o077:
                os.fchmod(fd, 0o600)
            return not present
        finally:
            os.close(fd)
    finally:
        os.close(dir_fd)


def seed_vm_home_share_ssh_key(pw, config):
    """Put the workload's pubkey in a [vm].volumes share mounted at the guest home.

    cloud-init writes ~/.ssh/authorized_keys in its *init* stage and mounts
    [vm].volumes in the *config* stage that follows, so a share whose guest path
    is the login user's home covers the only key the CLI has. The guest boots
    perfectly healthy and `workloadctl exec`/`shell` fail authentication — on
    every boot, not just the first, since the fstab entry mounts before sshd.

    Seeding the share host-side is what makes such a TOML self-sufficient:
    without it the working configuration lives in an operator's shell history,
    and a purge, a restore onto an empty share, or the same bundle stamped on
    another host all produce a VM nobody can log into.

    Skips (with a warning) a share outside the workload tree: the no-follow walk
    needs a root-owned anchor to be safe, and an operator who mounts a directory
    of their own at the guest home owns what is in it.
    """
    vm_cfg = config.get("vm", {})
    volumes = vm_cfg.get("volumes", [])
    if not volumes:
        return
    name = config["workload"]["name"]
    guest_home = PurePosixPath(VM_GUEST_HOME_BASE) / _validated_guest_user(vm_cfg)
    pubkey = _read_ssh_pubkey(pw)
    if not pubkey:
        return  # build_cloud_init_iso raises on this; nothing to add here.

    state_dir = workload_state_dir(name)
    root_dir = workload_root_dir(name)
    for vol_spec in volumes:
        expanded = expand_volume_path(vol_spec, str(state_dir))
        host_str, guest_str, _opts = parse_volume_spec(expanded)
        if not host_str or not guest_str:
            continue
        guest_path = PurePosixPath(guest_str)
        # The share covers the home when it IS the home, or contains it (a share
        # mounted at /home). A share *below* the home hides nothing.
        try:
            sub = guest_home.relative_to(guest_path)
        except ValueError:
            continue

        home_host = Path(host_str) / sub if str(sub) != "." else Path(host_str)
        try:
            home_host.resolve().relative_to(root_dir.resolve())
        except ValueError:
            ensure_common.log(f"  WARNING: {guest_str} shares {host_str}, which is outside "
                f"{root_dir} — it hides the guest's authorized_keys and only you "
                f"can seed it. Copy {Path(pw.pw_dir) / '.ssh/id_ed25519.pub'} to "
                f"{home_host}/.ssh/authorized_keys (0600) or `workloadctl exec` "
                f"will not be able to log in.")
            continue

        if not _provision_dir_secure(root_dir, home_host, pw.pw_uid, pw.pw_gid,
                                     0o755):
            raise RuntimeError(f"could not provision guest home share {home_host}")
        ssh_dir = home_host / ".ssh"
        if not _provision_dir_secure(root_dir, ssh_dir, pw.pw_uid, pw.pw_gid,
                                     0o700):
            raise RuntimeError(f"could not provision {ssh_dir}")
        if _seed_authorized_keys(root_dir, ssh_dir, pubkey, pw.pw_uid, pw.pw_gid):
            ensure_common.log(f"  Seeded SSH key into {guest_str} share: "
                f"{ssh_dir}/authorized_keys")


def generate_vm_host_keypair(pw, name: str):
    """Generate the VM's SSH *host* keypair if absent (S1 host-key pinning).

    Symmetric to generate_ssh_keypair (the client key): the private half is
    injected into the guest as /etc/ssh/ssh_host_ed25519_key via cloud-init, and
    the public half is pinned into vm_known_hosts on the host, so the CLI can
    verify the guest with StrictHostKeyChecking=yes and no trust-on-first-use.
    Idempotent: generated once and reused across reseeds so the pin stays stable
    — do NOT churn it, that would invalidate the pin.
    """
    ssh_dir = Path(pw.pw_dir) / ".ssh"
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    os.chown(ssh_dir, pw.pw_uid, pw.pw_gid)

    key_path = ssh_dir / "vm_host_ed25519_key"
    if key_path.exists():
        return  # already generated — keep the pin stable

    _ssh_keygen(key_path, f"workload-{name}-host@hypervisor", "VM host key")

    os.chown(key_path, pw.pw_uid, pw.pw_gid)
    os.chmod(key_path, 0o600)
    pub_path = key_path.with_suffix(".pub")
    if pub_path.exists():
        os.chown(pub_path, pw.pw_uid, pw.pw_gid)
        os.chmod(pub_path, 0o644)
    ensure_common.log(f"  Generated VM host keypair: {key_path}")


def _read_vm_egress_ca(name: str) -> str:
    """The egress CA certificate in PEM, or '' if this workload has none.

    '' is an ordinary answer, not an error: an egress = "open" workload never
    gets a CA, and generate_egress_ca only runs for filtered ones.
    """
    try:
        return vm_ca_cert_path(workload_state_dir(name)).read_text()
    except OSError:
        return ""


def _read_vm_host_private_key(pw) -> str:
    """Return the PEM of the VM host private key, or '' if not generated yet."""
    priv = Path(pw.pw_dir) / ".ssh" / "vm_host_ed25519_key"
    try:
        return priv.read_text()
    except OSError:
        return ""


def _read_vm_host_pubkey(pw) -> str:
    """Return the VM host public key line, or '' if not generated yet."""
    pub = Path(pw.pw_dir) / ".ssh" / "vm_host_ed25519_key.pub"
    try:
        return pub.read_text().strip()
    except OSError:
        return ""


def write_vm_known_hosts(pw, name: str, host_pubkey: str):
    """Pin the guest host key into ~/.ssh/vm_known_hosts, keyed by workload name.

    The CLI connects with HostKeyAlias=<name>, so a single line keyed by the
    bare name (not the churning DHCP address) is the pin the CLI verifies
    against. Rewritten idempotently whenever the host pubkey changes.
    """
    known_hosts = Path(pw.pw_dir) / ".ssh" / "vm_known_hosts"
    line = f"{name} {host_pubkey}\n"
    try:
        if known_hosts.exists() and known_hosts.read_text() == line:
            return
    except OSError:
        pass
    # Atomic: the CLI reads this file with StrictHostKeyChecking=yes and takes no
    # lock, so a `vm ssh` running concurrently with a restart could otherwise
    # read the pin mid-rewrite and fail against a truncated line.
    replace_file_atomically(known_hosts, line, default_mode=0o644,
                            owner=(pw.pw_uid, pw.pw_gid))
    ensure_common.log(f"  Pinned VM host key in {known_hosts}")


def _decrypt_systemd_credential(name: str) -> str:
    """Decrypt a systemd-creds-encrypted credential at /etc/credstore.encrypted/<name>.

    Falls back to reading /etc/credstore/<name> (plain) if the encrypted form
    doesn't exist. Raises FileNotFoundError if neither exists.
    """
    encrypted = Path(f"/etc/credstore.encrypted/{name}")
    plain = Path(f"/etc/credstore/{name}")
    if encrypted.exists():
        result = subprocess.run(
            ["systemd-creds", "decrypt", f"--name={name}", str(encrypted), "-"],
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"systemd-creds decrypt failed for {name}: "
                f"{result.stderr.decode(errors='replace').strip()}"
            )
        return result.stdout.decode().rstrip("\n")
    if plain.exists():
        return plain.read_text().rstrip("\n")
    raise FileNotFoundError(
        f"credential {name!r} not found at {encrypted} or {plain}; "
        f"create it with `systemd-creds encrypt --name={name} <(echo SECRET) {encrypted}`"
    )


def _uncommented(text: str) -> str:
    """The seed with its comment lines removed, for the substring contracts.

    THE CONTRACTS BELOW ARE SUBSTRING PINS, which is a deliberate choice -- they
    establish that a seed refers to a thing at all, not that it wires it up
    correctly -- and a commented-out recipe satisfies one without doing
    anything. That is not hypothetical: the reference seed at
    workloads/vm-base/cloud-init/user-data carries both recipes commented out,
    because it is `egress = "open"` and must not install an empty anchor, and
    copying it forward is the intended way to start a filtered workload. A pin
    that counted the copy would pass every seed that was started and never
    finished, which is the false green this style has to be watched for.

    Only a line whose FIRST non-space character is `#` is dropped. A `#` part
    way through a line is content in YAML as often as it is a comment, and
    guessing which would make the contract's answer depend on a reading of the
    seed that cloud-init does not share.
    """
    return "\n".join(line for line in text.splitlines()
                      if not line.lstrip().startswith("#"))


def _covers_guest_home(guest_path: str, guest_home: PurePosixPath) -> bool:
    """Whether a volume mounted at `guest_path` contains the guest's home.

    The shared predicate behind both halves of the home-context rule: the
    built-in cloud-config adds `context=` to exactly these mounts
    (_virtiofs_mount_opts), and the seed contract in build_cloud_init_iso
    refuses a custom seed that mounts one of them without it. Split out so the
    two halves cannot disagree about which volume is the home share.
    """
    try:
        guest_home.relative_to(PurePosixPath(guest_path))
    except ValueError:
            return False
    return True


def _virtiofs_mount_opts(guest_path: str, opts_str: str,
                          guest_home: PurePosixPath) -> str:
    """Add an SELinux `context=` option when `guest_path` covers guest_home.

    A share covering the guest's home directory carries ~/.ssh, and virtiofs
    has no xattr passthrough here (no `--xattr` flag on the virtiofsd sidecar,
    see generate_virtiofs_service), so every file under it lands in the guest
    labelled bare `virtiofs_t` — a type sshd has no policy access to. That is
    silent and late: the denial is logged but not enforced for however long
    the guest happens to keep running its *current* loaded policy, then bites
    on the next boot that actually reloads one — a `dnf upgrade` touching
    selinux-policy is exactly such a boot, and the guest may run for hours on
    the old policy first. `context=` pins every file under the mount to a type
    sshd already has broad, correct access to, so login stops depending on a
    hand-run `semanage permissive` surviving the guest's own next upgrade.

    Only applied when `opts_str` is still the "rw" parse_volume_spec default —
    a spec that already sets its own mount options made this call once and
    should not be overridden.
    """
    if not _covers_guest_home(guest_path, guest_home):
        return opts_str
    if opts_str != "rw":
        return opts_str
    return opts_str + f',context="{VM_HOME_SELINUX_CONTEXT}"'


def _render_default_user_data(name: str, guest_user: str, pubkey: str,
                              mounts: list, has_data_disk: bool,
                              host_private_key: str = "",
                              host_public_key: str = "",
                              guest_env: dict | None = None,
                              ca_cert: str = "") -> str:
    """Render the built-in #cloud-config when no user_data_file is set.

    Stays in a simple, controlled subset of YAML so we never need a YAML
    library — the structure here is small and fully owned by us.
    """
    lines = [
        "#cloud-config",
        f"hostname: {name}",
        f"fqdn: {name}.local",
        "users:",
        f"  - name: {guest_user}",
        # Pin the primary user to VM_GUEST_UID so virtiofsd's uid/gid
        # translation (guest 1000 <-> host workload uid) is deterministic and
        # the guest user can write virtiofs shares. Cloud images already assign
        # the default user 1000, so this only makes the convention explicit.
        f"    uid: {VM_GUEST_UID}",
        "    sudo: ALL=(ALL) NOPASSWD:ALL",
        "    ssh_authorized_keys:",
        f"      - {pubkey}",
    ]
    # Host-key pinning (S1): install the host-generated SSH host key into the
    # guest via cloud-init's ssh_keys module, so sshd presents a key the host
    # already pinned in vm_known_hosts on first boot — no trust-on-first-use.
    # The block scalar content is indented 4 spaces under `ed25519_private: |`.
    if host_private_key and host_public_key:
        lines.append("ssh_keys:")
        lines.append("  ed25519_private: |")
        for keyline in host_private_key.splitlines():
            lines.append(f"    {keyline}")
        lines.append(f"  ed25519_public: {host_public_key}")
    # The guest environment block. Two files rather than one because they cover
    # different consumers — /etc/environment is read by PAM so login sessions and
    # systemd services inherit it, and profile.d covers interactive shells that
    # never go through PAM. dnf, curl and git all read these names from the
    # environment.
    #
    # WHAT IS AND IS NOT IN IT, AFTER RUNG 2. Through rung 1 this block carried
    # http_proxy/https_proxy/no_proxy and the enforcement was advisory by
    # construction: a guest process free to ignore the variables simply did, and
    # only the default-deny chain turned that into a failure rather than a
    # bypass. Those variables are gone. Egress filtering is now transparent — a
    # uid-keyed redirect the guest is not told about and cannot opt out of — so
    # NOTHING written here affects whether the guest is filtered. What remains
    # is the CA bundle the inspector's spliced connections are presented under
    # and the credential PLACEHOLDERS a guest's client library needs in order to
    # send a request at all: conveniences, not controls. The broker endpoint used
    # to be here too and is not, because rung 6 stopped telling the guest where
    # the broker is -- a guest that cannot name it cannot choose to use it.
    #
    # That is worth stating because the block LOOKS the same and its failure
    # mode inverted. A guest missing this block used to be a guest reaching
    # nothing; now it is a guest that reaches everything it is allowed to and
    # cannot verify a certificate.
    #
    # Only the built-in cloud-config gets this. A workload supplying its own
    # user_data_file owns its guest configuration entirely, and this is
    # documented there rather than merged into a file we do not parse.
    #
    # THE CA IS SEEDED FOR EVERY FILTERED VM, WHATEVER `tls` SAYS, and it goes
    # in by TWO routes because they reach different clients. `ca_certs.trusted`
    # below installs it into the guest's system trust store, which §5 measured
    # as covering almost everything; the write_files entry puts the same PEM at
    # a fixed path, which is what the five environment variables above name for
    # the runtimes that carry their own root list and never consult the system
    # store. Either alone leaves a measured population of clients failing.
    # write_files is unconditional now: every built-in seed carries the two
    # files that give the guest a paravirtual clock (see vm.py's ptp_kvm block).
    lines.append("write_files:")
    for path, permissions, content in vm_ptp_kvm_seed_files():
        lines.append(f"  - path: {path}")
        lines.append(f"    permissions: '{permissions}'")
        lines.append("    content: |")
        for contentline in content.splitlines():
            lines.append(f"      {contentline}")
    if ca_cert:
        lines.append(f"  - path: {VM_CA_BUNDLE_PATH}")
        lines.append("    permissions: '0644'")
        lines.append("    content: |")
        for certline in ca_cert.splitlines():
            lines.append(f"      {certline}")
    if guest_env:
        lines.append("  - path: /etc/environment")
        lines.append("    append: true")
        lines.append("    content: |")
        for key, value in guest_env.items():
            lines.append(f"      {key}={value}")
        # Filename kept as -proxy though it now carries the CA bundle and the
        # credential placeholders and no proxy variable at all: renaming it
        # would leave the
        # old file behind on every existing guest, still exporting the retired
        # https_proxy, since cloud-config runs once at first boot. A guest that
        # keeps that stale export dials an address where nothing listens.
        lines.append("  - path: /etc/profile.d/99-workload-proxy.sh")
        lines.append("    permissions: '0644'")
        lines.append("    content: |")
        for key, value in guest_env.items():
            lines.append(f"      export {key}={value}")
    # cc_ca_certs, present in Fedora 44 Cloud-Base. This is the half that
    # reaches clients using the system store, and it is why a guest usually
    # works without any of the environment variables at all.
    if ca_cert:
        lines.append("ca_certs:")
        lines.append("  trusted:")
        lines.append("    - |")
        for certline in ca_cert.splitlines():
            lines.append(f"      {certline}")
    if mounts:
        lines.append("mounts:")
        for tag, mp, fstype, opts in mounts:
            lines.append(
                f"  - [{tag!r}, {mp!r}, {fstype!r}, {opts!r}, '0', '0']"
            )
    # runcmd is assembled from independent blocks and emitted once, below.
    # Each block is a single `- |` shell fragment, so a failure in one does not
    # decide whether the next one runs.
    runcmd_blocks = [vm_ptp_kvm_runcmd_lines()]
    if has_data_disk:
        # Mount /dev/vdb at /data on first boot, formatting it only if it has no
        # filesystem yet. Formatting and mounting are separate steps on purpose:
        # /etc/fstab lives on the *system* disk, which is reconstructible and is
        # rebuilt by a restore or a re-provision, while data.qcow2 comes back
        # from the archive already formatted. Gating the fstab line on the mkfs
        # (as this once did) meant a restored data disk was attached and never
        # mounted — the disk was there, /data was empty, and nothing said why.
        # Each step is guarded independently so the whole block is idempotent.
        runcmd_blocks.append([
            "if [ -b /dev/vdb ]; then",
            "  blkid /dev/vdb | grep -q TYPE || mkfs.ext4 -L workload-data /dev/vdb",
            "  mkdir -p /data",
            "  grep -q '^LABEL=workload-data ' /etc/fstab ||"
            " echo 'LABEL=workload-data /data ext4 defaults 0 2' >> /etc/fstab",
            "  mountpoint -q /data || mount /data",
            "fi",
        ])
    lines.append("runcmd:")
    for block in runcmd_blocks:
        lines.append("  - |")
        lines += [f"    {shline}" for shline in block]
    lines += [
        "package_update: false",
        "package_upgrade: false",
        f'final_message: "workload {name} cloud-init complete after $UPTIME seconds"',
        "",
    ]
    return "\n".join(lines)


def _bundle_workloadctl_rpm(seed_dir: Path) -> bool:
    """Copy the workloadctl RPM into seed_dir for in-VM installation.

    Uses the copy pre-cached by the hypervisor image build at
    /usr/share/workloadctl/workloadctl.rpm (placed there by `dnf download`
    during the image build so the ISO is self-contained).
    """
    dest = seed_dir / "workloadctl.rpm"

    cached = Path("/usr/share/workloadctl/workloadctl.rpm")
    if cached.exists():
        shutil.copy2(cached, dest)
        ensure_common.log("  Bundled workloadctl RPM (cached copy)")
        return True

    ensure_common.log("  WARNING: no cached workloadctl RPM at /usr/share/workloadctl/workloadctl.rpm; "
        "bootstrap will not be able to install workloadctl from the ISO.")
    return False


def _resolve_cloud_init_instance_id(name: str, instance_id_file: Path,
                                    fp_unchanged: bool,
                                    marker: dict | None = None
                                    ) -> tuple[str, bool, int]:
    """Decide the cloud-init instance-id for a (re)built seed ISO.

    Reuse the persisted id when the user-data fingerprint is unchanged — that
    means we are rebuilding only because the tmpfs ISO was wiped (a host
    reboot clearing /run), so the guest should see the SAME instance and skip
    re-running its per-instance modules. Mint a fresh id when the content
    actually changed (a real edit that warrants re-provisioning) or when no id
    has been persisted yet (first provision).

    The one exception to reuse is the heal: `marker` is the recorded outcome of
    the guest's own cloud-init run (see vm_provision), and when it says that
    run *failed* for the very id we are about to reuse, reusing it would pin
    the half-provisioned guest forever — its per-instance semaphores are
    already written, so the modules that didn't finish are never retried. A
    fresh id is what makes cloud-init treat the existing disk as a new instance
    and run them again. Capped at MAX_HEAL_ATTEMPTS per lineage so a guest that
    fails deterministically re-provisions once and then stays put rather than
    churning a new instance on every start.

    Returns ``(instance_id, minted, heal_attempts)`` — ``minted`` is True when a
    new id was generated and the caller must persist it, and ``heal_attempts``
    is the lineage's attempt count to persist alongside it (nonzero only for a
    heal).
    """
    existing = (instance_id_file.read_text().strip()
                if instance_id_file.exists() else "")
    if fp_unchanged and existing:
        if not should_heal(marker, existing):
            return existing, False, 0
        attempts = heal_attempts(marker, existing) + 1
        return f"{name}-{uuid.uuid4().hex[:8]}", True, attempts
    return f"{name}-{uuid.uuid4().hex[:8]}", True, 0


def build_cloud_init_iso(pw, config: dict, name: str, config_path: Path | None = None):
    """Build cloud-init seed ISO (meta-data + user-data) into the runtime dir.

    The ISO is written to the tmpfs runtime dir /run/workload-vm/{name}/ rather
    than the persistent workload home: in template mode it embeds decrypted
    secrets in plaintext, so keeping it on tmpfs means it never survives a
    reboot at rest (the threat being an offline disk read without the TPM).
    The setup service (setup_workload_runtime_dir, run earlier in this same invocation)
    has already created the dir; the main VM service later adopts it via
    RuntimeDirectory + RuntimeDirectoryPreserve=yes, which preserves this file.

    The fingerprint stays in the persistent home, so after a reboot it still
    matches but the tmpfs ISO is gone — iso_path.exists() is False, the skip is
    bypassed, and we rebuild (re-decrypting secrets fresh). Within a single boot
    the ISO is preserved, the fingerprint matches, and we skip the rebuild.

    Refuses to build if the SSH pubkey is missing: an authorized_keys-less
    ISO would produce a VM that `workloadctl exec` cannot reach.

    The instance-id is rotated whenever the ISO content changes (pubkey or
    config), so cloud-init re-runs the modules on next boot and picks up the
    new config — keeping a stable id would lock in the first boot's settings.

    Two modes:

    * **Default mode** (no [vm.cloud_init].user_data_file): we emit a small
      built-in #cloud-config with the SSH key, optional virtiofs mounts, and
      optional data-disk init.
    * **Template mode** ([vm.cloud_init].user_data_file set): the user's
      file IS the entire #cloud-config. We do *text substitution only* —
      ${VAR} from [vm.cloud_init].template_vars or environment, ${SECRET:name}
      from /etc/credstore.encrypted (decrypted via systemd-creds), and the
      magic ${WORKLOADCTL_SSH_KEY} / ${WORKLOADCTL_WORKLOAD_NAME} that we
      inject. No YAML parsing — the user owns the file's structure.
    """
    # Anchor the persistent fingerprint/instance-id files on the canonical
    # state/ dir, not pw.pw_dir: the generator forces HOME=<state> and
    # setup_home_directory creates state/ there regardless of what passwd
    # records, so a stale passwd home would otherwise strand these files in the
    # wrong tree (see warn_if_stale_home).
    home_path = workload_state_dir(name)
    # The ISO lives on tmpfs (the VM runtime dir), never the persistent home —
    # it can embed decrypted secrets. setup_workload_runtime_dir() created this dir
    # earlier in the same invocation; recreate it defensively in case this is
    # called out of order (e.g. tests).
    runtime_dir = VM_SOCKET_DIR / name
    runtime_dir.mkdir(parents=True, exist_ok=True)
    os.chown(runtime_dir, pw.pw_uid, pw.pw_gid)
    os.chmod(runtime_dir, 0o750)
    iso_path = runtime_dir / "cloud-init.iso"
    # The seed staging dir holds the rendered user-data, which in template mode
    # is plaintext secrets (0600). It lives on the tmpfs runtime dir alongside
    # the ISO, never the persistent home: it's rmtree'd once the ISO is built,
    # but if that step is cut short by a crash the leftover must not survive a
    # reboot at rest (the offline-disk-read threat the ISO placement guards).
    seed_dir = runtime_dir / ".cloud-init-seed"

    # Migration: older builds wrote the ISO — and staged the seed dir — in the
    # persistent home. Both can embed plaintext secrets, so remove any stale
    # copies left there; the live ISO and seed dir are now the tmpfs ones above.
    legacy_iso = home_path / "cloud-init.iso"
    try:
        legacy_iso.unlink()
        ensure_common.log(f"  Removed legacy on-disk cloud-init ISO: {legacy_iso}")
    except FileNotFoundError:
        pass
    except OSError as e:
        ensure_common.log(f"  WARNING: could not remove legacy ISO {legacy_iso}: {e}")
    legacy_seed_dir = home_path / ".cloud-init-seed"
    if legacy_seed_dir.exists():
        shutil.rmtree(legacy_seed_dir, ignore_errors=True)
        ensure_common.log(f"  Removed legacy on-disk cloud-init seed dir: {legacy_seed_dir}")

    vm_cfg = config.get("vm", {})
    guest_user = _validated_guest_user(vm_cfg)
    ci_cfg = vm_cfg.get("cloud_init", {})

    pubkey = _read_ssh_pubkey(pw)
    if not pubkey:
        raise RuntimeError(
            "SSH pubkey missing — cannot build cloud-init ISO. "
            "Check the ssh-keygen step above."
        )

    # Host-key pinning (S1): the host keypair generated by
    # generate_vm_host_keypair (run earlier in this setup invocation) is
    # injected into the guest and pinned on the host. Both halves must exist.
    host_private_key = _read_vm_host_private_key(pw)
    host_public_key = _read_vm_host_pubkey(pw)
    if not host_private_key or not host_public_key:
        raise RuntimeError(
            "VM host keypair missing — cannot build cloud-init ISO. "
            "Check the generate_vm_host_keypair step above."
        )

    # Resolve user_data_file path (relative paths are anchored to the TOML's dir).
    user_data_override_path = None
    if ci_cfg.get("user_data_file"):
        raw_path = ci_cfg["user_data_file"]
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            base_dir = config_path.parent if config_path is not None else WORKLOAD_CONFIG_DIR
            candidate = base_dir / raw_path
        if not candidate.exists():
            raise FileNotFoundError(
                f"[vm.cloud_init].user_data_file {candidate} does not exist"
            )
        user_data_override_path = candidate

    # Render the user-data up front so the rebuild fingerprint can be the hash
    # of the actual bytes we'd write — substitution is side-effect-free.
    if user_data_override_path is not None:
        # Template mode: the user owns the file structure; we just substitute.
        raw = user_data_override_path.read_text()
        template_vars = dict(ci_cfg.get("template_vars", {}))
        # Magic vars we inject so user templates can reference our state
        # without having to read it from somewhere else.
        template_vars.setdefault("WORKLOADCTL_SSH_KEY", pubkey)
        template_vars.setdefault("WORKLOADCTL_WORKLOAD_NAME", name)
        # [vm].user is what the CLI SSHes in as, so a custom seed has to create
        # exactly that account. Inject it rather than making the seed repeat the
        # literal: a drifted pair is an unreachable VM, and the TOML is the half
        # the operator edits. Safe to splice unquoted — guest_user was validated
        # as a POSIX username above.
        template_vars.setdefault("WORKLOADCTL_VM_USER", guest_user)
        # Host-key pinning magic vars (S1). A custom seed bypasses the built-in
        # ssh_keys: block, so the operator must install our host key themselves
        # to keep the pin valid — these expose the material to do it. The _B64
        # form is a single line (the raw PEM is multi-line and doesn't survive
        # naive ${VAR} splicing into a YAML block scalar), meant for a
        # write_files entry with `encoding: b64`.
        host_key_b64 = base64.b64encode(host_private_key.encode()).decode()
        template_vars.setdefault("WORKLOADCTL_VM_HOST_KEY", host_private_key)
        template_vars.setdefault("WORKLOADCTL_VM_HOST_KEY_B64", host_key_b64)
        template_vars.setdefault("WORKLOADCTL_VM_HOST_PUBKEY", host_public_key)
        # The egress CA, on exactly the same terms as the host key above and
        # for the same reason: a custom seed replaces the built-in cloud-config,
        # so the operator has to install the anchor themselves -- and the
        # contract below REFUSES to build a seed that does not. Without these
        # two variables that contract is unsatisfiable, because the certificate
        # lives in the workload's state directory and a seed is rendered before
        # anything in the guest can read it. The only remaining escape would be
        # seed_provides = ["ca"], which turns the check off without the guest
        # trusting anything -- the exact outcome the check exists to prevent.
        #
        # `` for a workload with no CA (egress = "open", or a filtered one whose
        # CA has not been minted yet), which substitutes to an empty string
        # rather than raising: a seed that references the variable it does not
        # need is a mistake worth surviving, and the contract below is what
        # actually decides whether the anchor was required.
        egress_ca = _read_vm_egress_ca(name)
        template_vars.setdefault("WORKLOADCTL_VM_EGRESS_CA", egress_ca)
        template_vars.setdefault(
            "WORKLOADCTL_VM_EGRESS_CA_B64",
            base64.b64encode(egress_ca.encode()).decode() if egress_ca else "")
        try:
            user_data_text = substitute_template(
                raw,
                template_vars=template_vars,
                env=dict(os.environ),
                secret_resolver=_decrypt_systemd_credential,
            )
        except (KeyError, FileNotFoundError, RuntimeError) as e:
            raise RuntimeError(
                f"cloud-init template substitution failed for {user_data_override_path}: {e}"
            ) from e
        if not user_data_text.startswith("#cloud-config"):
            user_data_text = "#cloud-config\n" + user_data_text

        # S1 contract for custom seeds (design option (c)): a custom user-data
        # must install our host key so the pin holds. If the operator wired in
        # neither the raw private key nor its base64 form, the guest would
        # present a self-generated key that fails verification — fail
        # provisioning now rather than ship an unreachable VM (no TOFU fallback).
        via_ssh_keys = "ed25519_private" in user_data_text
        via_write_files = (host_private_key.strip() in user_data_text
                           or host_key_b64 in user_data_text)
        if not via_ssh_keys and not via_write_files:
            raise SeedContractError(
                f"[vm.cloud_init].user_data_file for {name} does not install the "
                f"workload's SSH host key: the CLI pins the host key "
                f"(StrictHostKeyChecking=yes), so a custom seed must inject it. "
                f"Add a write_files entry writing /etc/ssh/ssh_host_ed25519_key "
                f"from ${{WORKLOADCTL_VM_HOST_KEY_B64}} (encoding: b64), or an "
                f"ssh_keys: block carrying ${{WORKLOADCTL_VM_HOST_KEY}}."
            )
        # write_files alone is not enough: cc_ssh runs after cc_write_files and
        # ssh_deletekeys defaults to true, so it deletes /etc/ssh/ssh_host_* and
        # regenerates — silently discarding the key just written and leaving a
        # guest that fails the pin. cc_ssh consumes an ssh_keys: block itself, so
        # that form needs no opt-out; write_files must disable the delete.
        if via_write_files and not via_ssh_keys and not re.search(
                r"^\s*ssh_deletekeys\s*:\s*(false|no|off|0)\s*$",
                user_data_text, re.M | re.I):
            raise SeedContractError(
                f"[vm.cloud_init].user_data_file for {name} installs the SSH host "
                f"key with write_files but does not set `ssh_deletekeys: false`. "
                f"cloud-init's ssh module runs after write_files and defaults to "
                f"deleting and regenerating /etc/ssh/ssh_host_*, so the pinned key "
                f"would be discarded and the guest would fail host-key "
                f"verification. Add `ssh_deletekeys: false` to the seed."
            )

        # Seed-completeness contract. Default mode derives the guest
        # environment and the virtiofs mounts from the TOML and emits them;
        # template mode emits nothing but what the operator wrote, so a seed
        # that omits them yields a VM that boots, passes every check, and is
        # quietly wrong:
        #
        #   - no CA bundle under egress = "filtered" means every guest tool
        #     that verifies certificates rejects the leaf the inspector
        #     presents -- which under the default tls = "inspect" is every
        #     HTTPS request the guest makes -- and reads as a broken upstream
        #     rather than as a missing anchor;
        #   - an unmounted volume leaves the guest writing to the system disk
        #     at the path the operator believes is persistent, and a
        #     generational rollback then discards it.
        #
        # Both are silent, so they are checked here for the same reason the
        # host-key contract above is: provisioning is the last moment the
        # mistake is cheap. Substring pins, matching the style of that check —
        # they establish the seed refers to the thing at all, not that it wires
        # it up correctly. [vm.cloud_init].seed_provides opts out per concern,
        # for a seed that handles one of them by means we cannot see (an image
        # with the mount already in /etc/fstab, a guest-side CA store the image
        # builder populated).
        seed_provides = ci_cfg.get("seed_provides", []) or []
        live = _uncommented(user_data_text)

        # The CA contract, which replaced the proxy contract this check used to
        # be. It is pinned on the BUNDLE PATH rather than on an address: when
        # this was written the advertised broker address was in the seed of any
        # workload using the broker, so pinning on it would have passed a seed
        # that mentioned the broker and configured no anchor at all -- the exact
        # false green the substring style has to be watched for. That address is
        # gone, and the rule it taught is why this still pins the path.
        # Gated on VM_CA_BUNDLE_AVAILABLE for the reason that flag exists: until
        # rung 3 mints the CA, default mode writes no bundle either, and a
        # contract that refused custom seeds for omitting a file the built-in
        # seed also omits would be enforcing a rule against one path only.
        # G14 in the container egress-parity build spec: VM-only by
        # construction -- this whole function (build_cloud_init_iso) only
        # runs for a VM. The container analogue is `ca_delivery`, and it
        # ASSERTS rather than verifies (R9); do not overclaim its
        # replacement by trying to fold it into this contract.
        if (VM_CA_BUNDLE_AVAILABLE and vm_uses_inspect(config)
                and "ca" not in seed_provides
                and VM_CA_BUNDLE_PATH not in live):
            raise SeedContractError(
                f"[vm.cloud_init].user_data_file for {name} never installs the "
                f"egress CA bundle at {VM_CA_BUNDLE_PATH}, but this workload's "
                f"egress is filtered and inspected. A custom seed replaces the "
                f"built-in cloud-config, which is what would normally write it "
                f"and point the guest's HTTP clients at it -- without it the "
                f"guest cannot verify the certificates its own inspector "
                f"presents, and every HTTPS fetch fails as a bad certificate "
                f"rather than as a policy decision. Write the bundle from "
                f"${{WORKLOADCTL_VM_EGRESS_CA_B64}} (encoding: b64), add it to "
                f"the guest's system store with a ca_certs: block, and export "
                f"{', '.join(VM_CA_ENV_VARS)} -- "
                f"workloads/vm-base/cloud-init/user-data carries the whole "
                f"block to copy. Or set "
                f"[vm.cloud_init].seed_provides = [\"ca\"] if the guest image "
                f"already carries that configuration."
            )

        if "mounts" not in seed_provides:
            vm_volumes = vm_cfg.get("volumes", []) or []
            guest_home = PurePosixPath(VM_GUEST_HOME_BASE) / guest_user
            for tag, vol_spec in zip(virtiofs_tags(vm_volumes), vm_volumes):
                _host, guest_path, _opts = parse_volume_spec(vol_spec)
                if tag not in live:
                    raise SeedContractError(
                        f"[vm.cloud_init].user_data_file for {name} never mounts "
                        f"the volume {vol_spec!r} (virtiofs tag {tag!r}). A custom "
                        f"seed replaces the built-in cloud-config, which is what "
                        f"would normally mount it, so {guest_path} would be an "
                        f"ordinary directory on the system disk: writes there look "
                        f"fine, never reach the host, and are discarded by a disk "
                        f"rebuild. Mount tag {tag!r} at {guest_path} in the seed, "
                        f"or set [vm.cloud_init].seed_provides = [\"mounts\"] if "
                        f"the guest image mounts it already."
                    )
                # The home share's SELinux context. Default mode adds this to
                # the mount options itself (_virtiofs_mount_opts); template
                # mode emits only what the operator wrote, so a seed that
                # mounts the home share with plain `defaults` produces a guest
                # whose every home file is `virtiofs_t` and whose sshd cannot
                # read authorized_keys.
                #
                # This is the worst of the three seed-completeness failures and
                # the reason it is checked at all: it is not visible at boot.
                # The guest keeps serving logins on whatever policy is already
                # LOADED, so the seed looks correct for as long as the guest
                # stays up — then the first reboot after a `dnf upgrade` that
                # touches selinux-policy loads the new one and locks the
                # operator out of a cloud image whose only account has no
                # password. There is no console recovery from that.
                #
                # A substring pin over the rendered text, in the style of the
                # tag check above and the ssh_deletekeys check: it establishes
                # the seed names a usable type at all, not that it attached it
                # to the right mount. Checking the type rather than the bare
                # presence of `context=` is deliberate — copying the HOST-side
                # value (svirt_image_t, which is what a cifs volume under the
                # share is mounted with) is a realistic mistake that leaves
                # sshd exactly as broken as omitting the option.
                #
                # Against `live`, not the raw text, for the reason _uncommented
                # exists: workloads/vm-base/cloud-init/user-data carries this
                # very mount as a COMMENTED example, so a pin over the raw seed
                # would be satisfied by a copy of the reference that was
                # started and never uncommented — the false green this style
                # has to be watched for.
                if ("home_context" not in seed_provides
                        and _covers_guest_home(guest_path, guest_home)
                        and not re.search(
                            r"context=[\"']?[\w.-]*:[\w.-]*:(?:"
                            + "|".join(VM_HOME_SELINUX_TYPES) + r"):",
                            live)):
                    raise SeedContractError(
                        f"[vm.cloud_init].user_data_file for {name} mounts the "
                        f"volume {vol_spec!r} over the guest home {guest_home} "
                        f"without an SELinux `context=` option naming one of "
                        f"{', '.join(VM_HOME_SELINUX_TYPES)}. virtiofs carries "
                        f"no xattrs, so every file under that share would be "
                        f"labelled `virtiofs_t` in the guest — a type sshd has "
                        f"no access to — and key auth would fail. This does NOT "
                        f"fail at boot: the guest keeps running its already-"
                        f"loaded policy, so it bites on the first reboot after "
                        f"an in-guest update touches selinux-policy, locking "
                        f"you out of an account that has no password. Mount tag "
                        f"{tag!r} with "
                        f"`context=\"{VM_HOME_SELINUX_CONTEXT}\"`, or set "
                        f"[vm.cloud_init].seed_provides = [\"home_context\"] if "
                        f"the guest labels that mount by other means."
                    )
    else:
        # Default mode: built-in cloud-config with SSH key + optional disks.
        # Collision-safe tags, same set the generator emits sidecar units for (B3).
        vm_volumes = vm_cfg.get("volumes", [])
        guest_home = PurePosixPath(VM_GUEST_HOME_BASE) / guest_user
        mounts = []
        for tag, vol_spec in zip(virtiofs_tags(vm_volumes), vm_volumes):
            _host, guest_path, opts_str = parse_volume_spec(vol_spec)
            opts_str = _virtiofs_mount_opts(guest_path, opts_str, guest_home)
            mounts.append((tag, guest_path, "virtiofs", opts_str))
        user_data_text = _render_default_user_data(
            name=name,
            guest_user=guest_user,
            pubkey=pubkey,
            mounts=mounts,
            has_data_disk=bool(vm_cfg.get("data_disk_size")),
            host_private_key=host_private_key,
            host_public_key=host_public_key,
            # The placeholders last, and they cannot overwrite anything: a
            # credential whose `env` names one of workloadctl's own guest
            # variables is refused in validation, where the collision is still
            # visible. Seeded once per instance-id like every other variable in
            # this block -- so a CHANGED placeholder does not reach a running
            # guest, which is what `diagnose` says out loud.
            guest_env={**vm_ca_env(config), **vm_credential_env(config)},
            # Unconditional for a filtered VM, NOT gated on tls = "inspect".
            # The seed is fingerprinted over its rendered text and the
            # cloud-init instance-id rotates with it, so gating would make an
            # emergency switch to tls = "splice" drop the CA, rotate the id,
            # and re-run every per-instance module -- users, runcmd, bootstrap
            # -- on the next boot, in the middle of the incident the switch
            # exists for. Switching back would do it a second time. The cost of
            # not gating is a PEM in the seed of a workload not currently
            # presenting anything under it, and that key is per-workload and
            # trusted by exactly one guest.
            # G13 in the container egress-parity build spec: VM-only by
            # construction, same as G14 above -- build_cloud_init_iso only
            # runs for a VM. The container equivalent is env injection into
            # the unit at ExecStartPre/generator time (G15), not a
            # cloud-init argument.
            ca_cert=_read_vm_egress_ca(name) if vm_uses_inspect(config) else "",
        )

    # Pin the guest host key on the host (S1). Both provisioning paths have now
    # guaranteed the guest will present this key: default mode injects it, and
    # custom mode passed the (c) contract check above. Written before the
    # fingerprint early-return so the pin survives an ISO-rebuild skip (e.g. the
    # tmpfs ISO was cleared by a reboot but user-data is unchanged).
    write_vm_known_hosts(pw, name, host_public_key)

    # Fingerprint guards against unnecessary ISO rebuilds: the SHA-256 of the
    # fully-rendered user-data. This captures everything that changes the guest
    # — the user_data_file content, [vm.cloud_init].template_vars, resolved
    # secrets/env, the injected SSH key, and volume-derived mounts — so editing
    # any of them reliably triggers a rebuild (and instance-id rotation).
    current_fp = hashlib.sha256(user_data_text.encode()).hexdigest()
    fingerprint_file = home_path / ".cloud-init-fingerprint"
    fp_unchanged = (fingerprint_file.exists()
                    and fingerprint_file.read_text().strip() == current_fp)

    # The recorded outcome of the guest's own cloud-init run, if we ever
    # observed one. Read before the early return because a recorded *failure*
    # is the one thing that must defeat it: the ISO on tmpfs is fine and the
    # content is unchanged, but reusing that instance-id is precisely what
    # keeps the guest broken, so a heal has to be able to rebuild within a
    # single boot (i.e. `workloadctl restart` heals; it need not wait for the
    # next host reboot to wipe /run).
    instance_id_file = home_path / ".cloud-init-instance-id"
    existing_id = (instance_id_file.read_text().strip()
                   if instance_id_file.exists() else "")
    marker = read_provision_marker(home_path)
    healing = fp_unchanged and bool(existing_id) and should_heal(marker, existing_id)

    if iso_path.exists() and fp_unchanged and not healing:
        return

    # Rotate the cloud-init instance-id ONLY when the guest-affecting content
    # actually changed (a real config/secret/key edit that legitimately
    # warrants re-provisioning). When the content is unchanged and we're here
    # only because the tmpfs ISO was wiped — i.e. the host rebooted, clearing
    # /run — reuse the persisted instance-id so the guest sees the SAME instance
    # and does NOT re-run its per-instance modules (users, runcmd, bootstrap).
    # Without this, every host reboot churns the id and forces a full guest
    # re-provision. An absent/empty id file falls back to a fresh mint (first
    # provision).
    instance_id, minted, attempts = _resolve_cloud_init_instance_id(
        name, instance_id_file, fp_unchanged, marker)
    if minted:
        if attempts:
            errors = (marker or {}).get("errors") or []
            ensure_common.log(f"  cloud-init reported failure for instance {existing_id}"
                + (f": {errors[0]}" if errors else "")
                + f" — re-provisioning with a fresh instance-id (heal {attempts}"
                  f"/{MAX_HEAL_ATTEMPTS})")
        instance_id_file.write_text(instance_id)
        os.chown(instance_id_file, pw.pw_uid, pw.pw_gid)
        # Record the new id as unverified straight away, so the marker always
        # names the instance currently in play. Without this a heal would leave
        # the *old* failure record in place, and the next start would read it
        # as a failure of the new id and heal again.
        write_provision_marker(home_path, instance_id, PROVISION_UNVERIFIED,
                               heal_attempts=attempts,
                               uid=pw.pw_uid, gid=pw.pw_gid)

    seed_dir.mkdir(exist_ok=True)
    os.chown(seed_dir, pw.pw_uid, pw.pw_gid)

    meta_data = f"instance-id: {instance_id}\nlocal-hostname: {name}\n"
    (seed_dir / "meta-data").write_text(meta_data)

    ud = seed_dir / "user-data"
    fd = os.open(ud, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, user_data_text.encode())
    finally:
        os.close(fd)

    # For VM workloads: bundle the workloadctl RPM so the bootstrap can install
    # it directly from the cdrom instead of fetching it from a git repo.
    if vm_cfg:
        _bundle_workloadctl_rpm(seed_dir)

    # Build ISO using genisoimage or mkisofs
    iso_tool = None
    for tool in ("genisoimage", "mkisofs", "xorriso"):
        if shutil.which(tool):
            iso_tool = tool
            break

    if iso_tool is None:
        ensure_common.log("  WARNING: No ISO tool found (genisoimage/mkisofs/xorriso). "
            "cloud-init will not work.")
        return

    if iso_tool == "xorriso":
        cmd = [
            "xorriso", "-as", "mkisofs",
            "-o", str(iso_path),
            "-V", "CIDATA",
            "-joliet", "-rock",
            str(seed_dir),
        ]
    else:
        cmd = [
            iso_tool,
            "-output", str(iso_path),
            "-volid", "CIDATA",
            "-joliet", "-rock",
            str(seed_dir),
        ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        ensure_common.log(f"  WARNING: ISO build failed: {result.stderr.strip()}")
        return

    os.chown(iso_path, pw.pw_uid, pw.pw_gid)
    os.chmod(iso_path, 0o640)

    fingerprint_file.write_text(current_fp)
    os.chown(fingerprint_file, pw.pw_uid, pw.pw_gid)

    # Remove the seed staging directory — the rendered user-data contains
    # secrets in plaintext and is no longer needed once the ISO is built.
    shutil.rmtree(seed_dir, ignore_errors=True)
    ensure_common.log(f"  Built cloud-init ISO: {iso_path}")
