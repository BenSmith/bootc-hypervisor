"""
vmlaunch.py — boot a VM the runtime harness owns, in dev fidelity mode.

The genuinely-new lifecycle layer of the runtime rung: it downloads+caches a
Fedora Cloud base image, seeds a cloud-init `wlrt` user, boots a copy-on-write
overlay under raw QEMU with a user-mode ssh port-forward, deploys the local
workloadctl RPM into the guest, snapshots a clean baseline, and hands back a
`VMTarget` the pytest checks drive unchanged.

gate mode boots the REAL bootc image instead: bootc-image-builder turns
`localhost/hypervisor-bootc:latest` (override via WLRT_GATE_IMAGE) into a
bootable qcow2 with the `wlrt` test user baked in, boots it under an emulated
TPM2 (swtpm), and hands back the same `VMTarget` with no rpm deploy (workloadctl
ships in the image). Checks never branch on mode.

Stdlib only. See docs/wip/test-suite-improvement-plan.md Part 1.
"""

import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_WORKLOADCTL = _HERE.parent.parent          # tests/runtime -> tests -> workloadctl
_LIB = _WORKLOADCTL / "lib"
_REPO_ROOT = _WORKLOADCTL.parent
for _p in (str(_HERE), str(_LIB)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import workload_lib  # noqa: E402
from vmtarget import VMTarget  # noqa: E402

CACHE_DIR = _HERE / ".cache"
FEDORA_VERSIONS = _REPO_ROOT / "fedora-versions.yml"

# Binaries the dev-mode boot needs beyond /dev/kvm.
_DEV_BINARIES = ("qemu-system-x86_64", "qemu-img", "cloud-localds", "ssh-keygen")

# gate mode source image (the real hypervisor bootc image) and the
# bootc-image-builder tool image that turns it into a bootable qcow2. The
# default is the CI push target — BIB pulls the freshest genuinely-shipped
# artifact straight off `registry.local`. Override with WLRT_GATE_IMAGE to point
# at a `localhost/…` local build instead (which reads root's container store).
_GATE_IMAGE = os.environ.get("WLRT_GATE_IMAGE",
                             "registry.local/hypervisor-bootc:latest")
_BIB_IMAGE = "quay.io/centos-bootc/bootc-image-builder:latest"


def missing_prereqs(mode: str) -> list[str]:
    """Return the missing prerequisites for `mode`, or [] if all present.

    Lets the pytest fixture skip cleanly (no /dev/kvm on a laptop is the
    default-safe outcome, not a failure) without importing pytest here."""
    missing: list[str] = []
    if not Path("/dev/kvm").exists():
        missing.append("/dev/kvm")
    for binary in _DEV_BINARIES:
        if shutil.which(binary) is None:
            missing.append(binary)
    if mode == "gate":
        # Reported so a gate run on a dev-only box skips with a clear message;
        # gate boot itself is B1b.
        for binary in ("podman", "swtpm"):
            if shutil.which(binary) is None:
                missing.append(binary)
    return missing


# ---------------------------------------------------------------------------
# Fedora version / cloud image resolution
# ---------------------------------------------------------------------------

def resolve_fedora_version() -> int:
    """Read `stable:` from fedora-versions.yml (the project's single source)."""
    if shutil.which("yq"):
        r = subprocess.run(["yq", ".stable", str(FEDORA_VERSIONS)],
                           capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip().isdigit():
            return int(r.stdout.strip())
    m = re.search(r'^stable:\s*(\d+)', FEDORA_VERSIONS.read_text(), re.M)
    if not m:
        raise RuntimeError(f"could not resolve stable Fedora version from {FEDORA_VERSIONS}")
    return int(m.group(1))


def _resolve_cloud_image_url(ver: int) -> str:
    """Resolve the newest Cloud Base qcow2 URL for `ver`.

    Respin (e.g. `-1.7`) is resolved, never hardcoded: an explicit
    WLRT_CLOUD_IMG_URL wins (air-gapped/CI mirrors); otherwise list the mirror
    image directory and pick the newest matching qcow2."""
    override = os.environ.get("WLRT_CLOUD_IMG_URL")
    if override:
        return override

    base = (f"https://dl.fedoraproject.org/pub/fedora/linux/releases/"
            f"{ver}/Cloud/x86_64/images/")
    try:
        with urllib.request.urlopen(base, timeout=30) as resp:
            listing = resp.read().decode(errors="replace")
    except Exception as e:  # noqa: BLE001 — surface a clear, actionable error
        raise RuntimeError(
            f"could not list Fedora mirror {base} to resolve the cloud-image "
            f"respin ({e}); set WLRT_CLOUD_IMG_URL to a direct qcow2 URL"
        ) from e

    pattern = re.compile(
        rf'Fedora-Cloud-Base-Generic-{ver}-[0-9.]+\.x86_64\.qcow2')
    names = sorted(set(pattern.findall(listing)))
    if not names:
        raise RuntimeError(
            f"no Fedora-Cloud-Base-Generic-{ver} qcow2 found at {base}; "
            f"set WLRT_CLOUD_IMG_URL"
        )
    return base + names[-1]  # lexically-highest respin is the newest


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(url, timeout=60) as resp, open(tmp, "wb") as f:
        shutil.copyfileobj(resp, f)
    tmp.rename(dest)


def _ensure_base_image(ver: int) -> Path:
    """Download+cache the Cloud Base qcow2 under CACHE_DIR; return its path."""
    url = _resolve_cloud_image_url(ver)
    dest = CACHE_DIR / url.rsplit("/", 1)[-1]
    if not dest.exists():
        _download(url, dest)
    return dest


# ---------------------------------------------------------------------------
# cloud-init seed
# ---------------------------------------------------------------------------

def _render_user_data(pubkey: str) -> str:
    """A #cloud-config that creates the `wlrt` user with NOPASSWD wheel and the
    ephemeral key, and installs the packages `just rpm-install` needs in-guest."""
    return (
        "#cloud-config\n"
        "hostname: wlrt\n"
        "users:\n"
        "  - name: wlrt\n"
        "    groups: [wheel]\n"
        "    sudo: \"ALL=(ALL) NOPASSWD:ALL\"\n"
        "    shell: /bin/bash\n"
        "    lock_passwd: true\n"
        "    ssh_authorized_keys:\n"
        f"      - {pubkey}\n"
        "packages:\n"
        "  - just\n"
        "  - rpm-build\n"
        "  - rpmdevtools\n"
        "  - dnf5-plugins\n"   # provides `dnf builddep` (F44 uses dnf5)
        "  - rsync\n"
        "  - python3\n"
    )


def _build_seed(run_dir: Path, pubkey: str) -> Path:
    user_data = run_dir / "user-data"
    meta_data = run_dir / "meta-data"
    seed = run_dir / "seed.img"
    user_data.write_text(_render_user_data(pubkey))
    meta_data.write_text("instance-id: wlrt\nlocal-hostname: wlrt\n")
    subprocess.run(
        ["cloud-localds", str(seed), str(user_data), str(meta_data)],
        check=True, capture_output=True, text=True,
    )
    return seed


# ---------------------------------------------------------------------------
# QEMU boot
# ---------------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _qemu_argv(*, disk, seed, tpm_sock, port, run_dir, mem_mib, vcpus, name):
    argv = [
        "qemu-system-x86_64",
        "-machine", "q35,accel=kvm", "-cpu", "host",
        "-m", str(mem_mib), "-smp", str(vcpus),
    ]
    # UEFI/OVMF when available (matches the VM-workload launch path); a fresh
    # writable VARS copy per run. Cloud images also boot on SeaBIOS, so fall
    # back rather than fail if OVMF is not installed.
    #
    # The VARS store is a *qcow2* pflash, not raw: `savevm` (the snapshot
    # primitive) requires every writable block device to support internal
    # snapshots, and a writable raw pflash aborts it ("does not support
    # snapshots"). qemu-img convert preserves the flash region's virtual size.
    code = workload_lib.find_ovmf_code()
    vars_tpl = workload_lib.find_ovmf_vars()
    if code and vars_tpl:
        nvram = run_dir / "nvram.qcow2"
        subprocess.run(
            ["qemu-img", "convert", "-O", "qcow2", str(vars_tpl), str(nvram)],
            check=True, capture_output=True, text=True,
        )
        argv += [
            "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
            "-drive", f"if=pflash,format=qcow2,file={nvram}",
        ]
    argv += ["-drive", f"file={disk},if=virtio,format=qcow2"]
    # dev mode carries a cloud-init seed (read-only data cloud-init only reads;
    # readonly=on keeps it out of savevm's writable-device set). gate mode bakes
    # the user in via bootc-image-builder and passes seed=None.
    if seed is not None:
        argv += ["-drive", f"file={seed},if=virtio,format=raw,readonly=on"]
    # gate mode attaches an emulated TPM2 (swtpm) so the bootc host image's
    # TPM-backed secret path is exercised; dev mode passes tpm_sock=None.
    if tpm_sock is not None:
        argv += [
            "-chardev", f"socket,id=chrtpm,path={tpm_sock}",
            "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
            "-device", "tpm-tis,tpmdev=tpm0",
        ]
    argv += [
        "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22",
        "-device", "virtio-net-pci,netdev=net0",
        "-serial", f"file:{run_dir / 'console.log'}",
        "-qmp", f"unix:{run_dir / 'qmp.sock'},server=on,wait=off",
        # -display none (not -nographic): serial+monitor are already routed to
        # the file/qmp sockets above, and QEMU 10.x rejects -nographic together
        # with -daemonize (they both want stdio).
        "-display", "none", "-no-reboot", "-name", name,
        "-pidfile", str(run_dir / "vm.pid"), "-daemonize",
    ]
    return argv


def _console_tail(run_dir: Path, n: int = 40) -> str:
    console = run_dir / "console.log"
    if not console.exists():
        return "(no console output)"
    lines = console.read_text(errors="replace").splitlines()
    return "\n".join(lines[-n:])


# ---------------------------------------------------------------------------
# gate mode: real bootc image via bootc-image-builder + swtpm
# ---------------------------------------------------------------------------

def _is_local_store_ref(ref: str) -> bool:
    """A `localhost/…` ref reads root's container store (storage bind); any other
    ref (the `registry.local` default) is pulled by BIB over the network."""
    return ref.startswith("localhost/")


def _ensure_bootc_image() -> str:
    """Resolve the gate source bootc image ref.

    A `localhost/…` override must already be in root's podman store (BIB reads it
    via the bound store) — a missing one is a hard error. The default
    `registry.local` ref is pulled by BIB itself, so there is nothing to
    pre-stage; return it as-is."""
    ref = _GATE_IMAGE
    if _is_local_store_ref(ref):
        if subprocess.run(["sudo", "podman", "image", "exists", ref]).returncode != 0:
            raise RuntimeError(
                f"gate image {ref!r} (WLRT_GATE_IMAGE) not found in the root "
                f"podman store; pull/build+tag it, or use the registry default"
            )
    return ref


def _render_bib_config(pubkey: str) -> str:
    """A bootc-image-builder blueprint that bakes the `wlrt` test user.

    No workload TOMLs are baked — the harness installs workloads at runtime via
    `workloadctl install`/`enable`. The NOPASSWD drop-in is required because
    VMTarget drives sudo non-interactively (`sudo -n`)."""
    return (
        "[[customizations.user]]\n"
        'name = "wlrt"\n'
        'groups = ["wheel"]\n'
        f'key = "{pubkey}"\n'
        "\n"
        "[[customizations.files]]\n"
        'path = "/etc/sudoers.d/wlrt-nopasswd"\n'
        'mode = "0440"\n'
        'data = "%wheel ALL=(ALL) NOPASSWD:ALL\\n"\n'
    )


def _build_gate_qcow2(run_dir: Path, image_ref: str, pubkey: str) -> Path:
    """Build a bootable qcow2 from the real bootc image; return disk.qcow2.

    Mirrors the root justfile `_build-qcow2` invocation shape (privileged podman,
    unconfined label, /store /rpmmd /output mounts, xfs rootfs). BIB reads the
    source image from root's container storage, so that bind is required for both
    modes (the pre-pulled `registry.local` image lives there). The registry
    default additionally gets `--network=host` (resolve the mDNS `.local` name so
    BIB can pull it if absent) and `--tls-verify=false` (Caddy-fronted https)."""
    bib = run_dir / "bib"
    output, store, rpmmd = bib / "output", bib / "store", bib / "rpmmd"
    for d in (output, store, rpmmd):
        d.mkdir(parents=True, exist_ok=True)
    config = bib / "config.toml"
    config.write_text(_render_bib_config(pubkey))

    registry_pull = not _is_local_store_ref(image_ref)
    podman_args = [
        "sudo", "podman", "run", "--privileged", "--pull=newer", "--rm",
        "--security-opt", "label=type:unconfined_t",
        "-v", f"{config}:/config.toml:ro",
        "-v", f"{output}:/output",
        "-v", f"{rpmmd}:/rpmmd",
        "-v", f"{store}:/store",
        "-v", "/var/lib/containers/storage:/var/lib/containers/storage",
    ]
    if registry_pull:
        podman_args += ["--network=host"]
    build_args = [
        "build",
        "--chown", f"{os.getuid()}:{os.getgid()}",
        "--output", "/output",
        "--rootfs", "xfs",
        "--rpmmd", "/rpmmd",
        "--store", "/store",
        "--type", "qcow2",
    ]
    if registry_pull:
        build_args += ["--tls-verify=false"]  # Caddy-fronted registry.local
    argv = podman_args + [_BIB_IMAGE] + build_args + [image_ref]
    r = subprocess.run(argv, capture_output=True, text=True, timeout=1800)
    if r.returncode != 0:
        raise RuntimeError(
            f"bootc-image-builder failed (rc={r.returncode}):\n"
            f"{r.stdout[-2000:]}\n{r.stderr[-2000:]}"
        )
    disk = output / "qcow2" / "disk.qcow2"
    if not disk.exists():
        raise RuntimeError(f"BIB reported success but {disk} is missing")
    return disk


def _start_swtpm(run_dir: Path) -> Path:
    """Start a swtpm socket daemon; return its control socket path.

    The daemon writes its pid to swtpm.pid in run_dir so poweroff/cleanup can
    reap it after QEMU exits."""
    tpm_state = run_dir / "tpm"
    tpm_state.mkdir(parents=True, exist_ok=True)
    sock = run_dir / "swtpm.sock"
    r = subprocess.run(
        ["swtpm", "socket", "--tpmstate", f"dir={tpm_state}",
         "--ctrl", f"type=unixio,path={sock}",
         "--tpm2", "--daemon", "--pid", f"file={run_dir / 'swtpm.pid'}"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"swtpm failed to start:\n{r.stderr or r.stdout}")
    return sock


# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------

def _deploy(target: VMTarget, key_path: Path, port: int) -> None:
    """Rsync the local tree into the guest and `just rpm-install` it.

    Mirrors conftest._deploy_workloadctl, but supplies rsync an explicit `-e
    ssh` transport carrying the port/key/host-key options — the base helper
    assumes a plain `user@host` dest that rsync can resolve on its own, which a
    port-forwarded key-auth guest is not."""
    target_dir = "clitest-src/workloadctl/"
    target.run(["mkdir", "-p", target_dir], sudo=False, check=True)
    ssh_transport = (
        f"ssh -p {port} -i {key_path} "
        f"-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "
        f"-o LogLevel=ERROR"
    )
    rsync_cmd = [
        "rsync", "-a", "--delete",
        "-e", ssh_transport,
        "--exclude=rpmbuild/", "--exclude=__pycache__/", "--exclude=*.pyc",
        "--exclude=.pytest_cache/", "--exclude=tests/runtime/.cache/",
        str(_WORKLOADCTL) + "/",
        f"{target.dest}:{target_dir}",
    ]
    r = subprocess.run(rsync_cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"rsync into guest failed:\n{r.stderr}")

    # Install the spec's BuildRequires from their single source of truth (the
    # spec), rather than enumerating them in the cloud-init list where they'd
    # drift. `just rpm-build` calls rpmbuild directly with no builddep step, so
    # a clean guest is missing e.g. python3-rpm-macros without this.
    bd = target.run(
        ["bash", "-c",
         "cd ~/clitest-src/workloadctl && sudo dnf builddep -y rpm/workloadctl.spec"],
        sudo=False, check=False, timeout=600,
    )
    if bd.rc != 0:
        raise RuntimeError(
            f"dnf builddep failed in guest (rc={bd.rc}):\n"
            f"{bd.stdout[-2000:]}\n{bd.stderr[-2000:]}"
        )

    res = target.run(
        ["bash", "-c", "cd ~/clitest-src/workloadctl && just rpm-install"],
        sudo=False, check=False, timeout=600,
    )
    if res.rc != 0:
        raise RuntimeError(
            f"just rpm-install failed in guest (rc={res.rc}):\n"
            f"{res.stdout[-2000:]}\n{res.stderr[-2000:]}"
        )


# ---------------------------------------------------------------------------
# launch
# ---------------------------------------------------------------------------

def launch(mode: str, *, mem_mib: int = 2048, vcpus: int = 2,
           deploy: bool = True) -> VMTarget:
    """Boot a runtime-harness VM in `mode` and return a live VMTarget.

    dev mode: cached Fedora Cloud overlay + cloud-init seed, then rpm-install.
    gate mode: real bootc image via bootc-image-builder + swtpm, no deploy.

    Raises RuntimeError (with the guest console tail) on boot/timeout failure.
    """
    if mode not in ("dev", "gate"):
        raise ValueError(f"unknown mode {mode!r} (expected 'dev' or 'gate')")

    missing = missing_prereqs(mode)
    if missing:
        raise RuntimeError(f"missing runtime prerequisites: {', '.join(missing)}")

    run_dir = Path(
        subprocess.run(["mktemp", "-d", "-t", "wlrt-run.XXXXXX"],
                       capture_output=True, text=True, check=True).stdout.strip()
    )
    try:
        key_path = run_dir / "id_ed25519"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_path),
             "-C", "wlrt"],
            check=True, capture_output=True, text=True,
        )
        pubkey = (run_dir / "id_ed25519.pub").read_text().strip()

        # Mode-specific disk / seed / TPM; the rest of the boot is identical.
        if mode == "dev":
            base = _ensure_base_image(resolve_fedora_version())
            disk = run_dir / "overlay.qcow2"
            subprocess.run(
                ["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2",
                 "-b", str(base), str(disk)],
                check=True, capture_output=True, text=True,
            )
            seed = _build_seed(run_dir, pubkey)
            tpm_sock = None
            do_deploy = deploy
        else:  # gate
            disk = _build_gate_qcow2(run_dir, _ensure_bootc_image(), pubkey)
            seed = None
            tpm_sock = _start_swtpm(run_dir)
            do_deploy = False  # workloadctl is baked into the bootc image

        port = _free_port()
        argv = _qemu_argv(disk=disk, seed=seed, tpm_sock=tpm_sock, port=port,
                          run_dir=run_dir, mem_mib=mem_mib, vcpus=vcpus,
                          name=f"wlrt-{mode}")
        qemu = subprocess.run(argv, capture_output=True, text=True)
        if qemu.returncode != 0:
            # Surface QEMU's own diagnostic (e.g. an incompatible flag combo)
            # rather than a bare CalledProcessError.
            raise RuntimeError(
                f"QEMU failed to launch (rc={qemu.returncode}):\n"
                f"{qemu.stderr.strip() or qemu.stdout.strip()}"
            )

        target = VMTarget(
            port=port, key_path=key_path,
            qmp_sock=run_dir / "qmp.sock", pid_path=run_dir / "vm.pid",
            run_dir=run_dir,
            swtpm_pid_path=(run_dir / "swtpm.pid") if tpm_sock else None,
        )
        try:
            target.wait_ready(timeout=240.0)
        except RuntimeError as e:
            raise RuntimeError(
                f"{e}\n--- guest console tail ---\n{_console_tail(run_dir)}"
            ) from e

        if do_deploy:
            # sshd answers before cloud-init finishes; its packages: module is
            # still installing the in-guest build deps (just, rpm-build, ...).
            # Block on cloud-init before deploying, or `just rpm-install` races
            # ahead of `just` existing (rc=127). --wait exits 0 (done) or 2
            # (done with recoverable warnings) — both mean "finished".
            target.run(["cloud-init", "status", "--wait"],
                       sudo=True, check=False, timeout=300)
            _deploy(target, key_path, port)

        target.snapshot("base")
        return target
    except Exception:
        # Boot/deploy failed before we could hand off a VMTarget that owns
        # cleanup — reap any QEMU we started and drop the run dir.
        _cleanup_run_dir(run_dir)
        raise


def _cleanup_run_dir(run_dir: Path) -> None:
    for pid_file in (run_dir / "vm.pid", run_dir / "swtpm.pid"):
        try:
            os.kill(int(pid_file.read_text().strip()), 15)
        except (OSError, ValueError):
            pass
    shutil.rmtree(run_dir, ignore_errors=True)
