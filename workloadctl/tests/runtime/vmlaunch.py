"""
vmlaunch.py — boot a VM the runtime harness owns, in dev fidelity mode.

The genuinely-new lifecycle layer of the runtime rung: it downloads+caches a
Fedora Cloud base image, seeds a cloud-init `wlrt` user, boots a copy-on-write
overlay under raw QEMU with a user-mode ssh port-forward, deploys the local
workloadctl RPM into the guest, snapshots a clean baseline, and hands back a
`VMTarget` the pytest checks drive unchanged.

gate mode (the real bootc image + swtpm) is B1b — `launch("gate")` raises
NotImplementedError for now.

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


def _qemu_argv(*, overlay, seed, port, run_dir, mem_mib, vcpus, name):
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
    argv += [
        "-drive", f"file={overlay},if=virtio,format=qcow2",
        # The cloud-init seed is read-only data (cloud-init only reads it);
        # readonly=on keeps it out of savevm's writable-device set.
        "-drive", f"file={seed},if=virtio,format=raw,readonly=on",
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
    gate mode: NotImplementedError (B1b).

    Raises RuntimeError (with the guest console tail) on boot/timeout failure.
    """
    if mode == "gate":
        raise NotImplementedError("gate mode is B1b; use dev mode")
    if mode != "dev":
        raise ValueError(f"unknown mode {mode!r} (expected 'dev' or 'gate')")

    missing = missing_prereqs(mode)
    if missing:
        raise RuntimeError(f"missing runtime prerequisites: {', '.join(missing)}")

    ver = resolve_fedora_version()
    base = _ensure_base_image(ver)

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
        seed = _build_seed(run_dir, pubkey)

        overlay = run_dir / "overlay.qcow2"
        subprocess.run(
            ["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2",
             "-b", str(base), str(overlay)],
            check=True, capture_output=True, text=True,
        )

        port = _free_port()
        argv = _qemu_argv(overlay=overlay, seed=seed, port=port, run_dir=run_dir,
                          mem_mib=mem_mib, vcpus=vcpus, name=f"wlrt-{mode}")
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
        )
        try:
            target.wait_ready(timeout=240.0)
        except RuntimeError as e:
            raise RuntimeError(
                f"{e}\n--- guest console tail ---\n{_console_tail(run_dir)}"
            ) from e

        if deploy:
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
    pid_file = run_dir / "vm.pid"
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, 15)
    except (OSError, ValueError):
        pass
    shutil.rmtree(run_dir, ignore_errors=True)
