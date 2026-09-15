"""The provisioning a VM workload needs and a container workload never does.

NVRAM, virtiofs host directories, and the cloud-init seed ISO; the SSH
keypairs the seed carries are vm_ssh_keys. The cut is by substrate and it is exact:
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
import subprocess
import uuid
from pathlib import Path, PurePosixPath

from config_parser import parse_volume_spec, workload_root_dir
from workload_lib import (
    WORKLOAD_CONFIG_DIR, expand_volume_path, virtiofs_tags,
    workload_state_dir,
)
from egress_policy import vm_uses_inspect
from workload_addr import UID_MAX, UID_MIN, inspect_address
from egress_ca import (
    VM_CA_BUNDLE_AVAILABLE, CA_BUNDLE_PATH, CA_ENV_VARS, vm_ca_env,
    ca_cert_path,
)
from broker_config import vm_credential_env
from config_parser import SOCKET_DIR
from vm_defs import (
    VM_GUEST_HOME_BASE,
    VM_HOME_SELINUX_CONTEXT,
    VM_HOME_SELINUX_TYPES,
    SeedContractError,
    find_ovmf_vars,
)
from vm_provision import (
    MAX_HEAL_ATTEMPTS, PROVISION_UNVERIFIED, heal_attempts,
    read_provision_marker, should_heal, write_provision_marker,
)
from secrets_template import substitute_template
import ensure_common
from ensure_common import _provision_dir_secure
from vm_default_seed import (
    covers_guest_home,
    render_default_user_data,
    uncommented,
    virtiofs_mount_opts,
)
from vm_ssh_keys import (
    _read_ssh_pubkey,
    _read_vm_host_private_key,
    _read_vm_host_pubkey,
    _validated_guest_user,
    write_vm_known_hosts,
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


def _read_vm_egress_ca(name: str) -> str:
    """The egress CA certificate in PEM, or '' if this workload has none.

    '' is an ordinary answer, not an error: an egress = "open" workload never
    gets a CA, and generate_egress_ca only runs for filtered ones.
    """
    try:
        return ca_cert_path(workload_state_dir(name)).read_text()
    except OSError:
        return ""


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
    runtime_dir = SOCKET_DIR / name
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
        # This VM's own derived address on the shared dummy link (198.18.x.y
        # from the uid — the same address its inspect service would arm when
        # filtered). A passt guest cannot reach a service on its own host, so
        # a host service the VM must use (e.g. the forge's API, for a build
        # runner) is published on this address; the seed names it here —
        # derived, not invented, so it cannot drift from the allocation and
        # survives a re-provision that re-allocates the uid. Injected only for
        # passt VMs (no [vm.network].bridge): the address is armed at start by
        # workload-vm-svcaddr, which a bridged VM never does — it has its own
        # LAN identity and no need of the door. Guarded on the workload
        # range: a real _wl-<name> is always inside it, and a seed that
        # references the var without getting it fails loudly at render.
        net = config.get("vm", {}).get("network", {}) or {}
        if not net.get("bridge") and UID_MIN <= pw.pw_uid <= UID_MAX:
            template_vars.setdefault(
                "WORKLOADCTL_VM_INSPECT_ADDR", inspect_address(pw.pw_uid).v4)
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
        live = uncommented(user_data_text)

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
                and CA_BUNDLE_PATH not in live):
            raise SeedContractError(
                f"[vm.cloud_init].user_data_file for {name} never installs the "
                f"egress CA bundle at {CA_BUNDLE_PATH}, but this workload's "
                f"egress is filtered and inspected. A custom seed replaces the "
                f"built-in cloud-config, which is what would normally write it "
                f"and point the guest's HTTP clients at it -- without it the "
                f"guest cannot verify the certificates its own inspector "
                f"presents, and every HTTPS fetch fails as a bad certificate "
                f"rather than as a policy decision. Write the bundle from "
                f"${{WORKLOADCTL_VM_EGRESS_CA_B64}} (encoding: b64), add it to "
                f"the guest's system store with a ca_certs: block, and export "
                f"{', '.join(CA_ENV_VARS)} -- "
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
                # the mount options itself (virtiofs_mount_opts); template
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
                # Against `live`, not the raw text, for the reason uncommented
                # exists: workloads/vm-base/cloud-init/user-data carries this
                # very mount as a COMMENTED example, so a pin over the raw seed
                # would be satisfied by a copy of the reference that was
                # started and never uncommented — the false green this style
                # has to be watched for.
                if ("home_context" not in seed_provides
                        and covers_guest_home(guest_path, guest_home)
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
            opts_str = virtiofs_mount_opts(guest_path, opts_str, guest_home)
            mounts.append((tag, guest_path, "virtiofs", opts_str))
        user_data_text = render_default_user_data(
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
