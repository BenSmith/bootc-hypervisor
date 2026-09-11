"""A VM's disks, built: system.qcow2 from one of three image sources, and
data.qcow2 alongside it.

The system disk is reconstructible and lives in state/; the data disk is the
precious one and lives in the backup-captured data/ subtree. An update rotates
the live system disk out first (vm_disk_generations) and puts it back if the
build fails, so the service always has a disk to start from.
"""
import json
import os
import pwd
import shutil
import subprocess
from pathlib import Path

from helper_main import log
from vm_disk_generations import rotate_generations
from vm_image_fetch import download_cloud_image
from workload_lib import load_workload_config, workload_data_dir, workload_state_dir


def _probe_image_format(path: Path) -> str | None:
    """Detect the on-disk format of an image via `qemu-img info`. Returns
    None (let qemu-img autodetect) if the probe fails or is inconclusive."""
    try:
        result = subprocess.run(
            ["qemu-img", "info", "--output=json", str(path)],
            check=True, capture_output=True, text=True,
        )
        info = json.loads(result.stdout)
        return info.get("format")
    except Exception:
        # Best-effort probe only -- any failure (missing binary, bad JSON,
        # a test double returning a non-string stdout, etc.) just falls
        # back to qemu-img autodetect.
        return None


def build_from_cloud_image(url: str, checksum: str, home_dir: Path, system_disk: Path):
    source = download_cloud_image(url, checksum, home_dir)
    if source.suffix == ".qcow2":
        log("  Copying qcow2 to system disk (reflink if supported)...")
        try:
            subprocess.run(
                ["cp", "--reflink=auto", str(source), str(system_disk)],
                check=True
            )
        except subprocess.CalledProcessError:
            shutil.copy2(source, system_disk)
    else:
        # Convert raw/vmdk/vdi/etc to qcow2. Probe the actual source format
        # rather than assuming raw -- forcing -f raw on a vmdk/vdi source
        # corrupts the read.
        log("  Converting image to qcow2...")
        src_format = _probe_image_format(source)
        convert_cmd = ["qemu-img", "convert"]
        if src_format:
            convert_cmd += ["-f", src_format]
        convert_cmd += ["-O", "qcow2", str(source), str(system_disk)]
        subprocess.run(convert_cmd, check=True)
    log(f"  System disk ready: {system_disk}")


def build_from_local_image(local_path: str, system_disk: Path):
    src = Path(local_path)
    if not src.exists():
        raise FileNotFoundError(f"Local image not found: {src}")
    log(f"  Copying local image {src} → system disk (reflink if supported)...")
    try:
        subprocess.run(
            ["cp", "--reflink=auto", str(src), str(system_disk)],
            check=True
        )
    except subprocess.CalledProcessError:
        shutil.copy2(src, system_disk)
    log(f"  System disk ready: {system_disk}")


def build_from_bootc_image(image_ref: str, home_dir: Path, system_disk: Path):
    """Build system disk from a bootc container image using bootc-image-builder.

    Requires nested KVM (bare metal or host with nested=1). CI environments
    without nested KVM must skip this image source in integration tests.
    """
    if not shutil.which("bootc-image-builder"):
        raise RuntimeError(
            "bootc-image-builder not found. Install it with: "
            "rpm-ostree install bootc-image-builder"
        )

    build_dir = home_dir / ".bib-build"
    build_dir.mkdir(parents=True, exist_ok=True)

    log(f"  Building disk from bootc image {image_ref!r} via bootc-image-builder...")
    log("  This may take 10-30 minutes on first run.")

    result = subprocess.run(
        [
            "bootc-image-builder",
            "--type", "qcow2",
            "--output", str(build_dir),
            image_ref,
        ],
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"bootc-image-builder failed (exit {result.returncode})")

    # bib writes qcow2/<name>.qcow2 or disk.qcow2 depending on version
    candidates = list(build_dir.glob("**/*.qcow2"))
    if not candidates:
        raise RuntimeError(f"bootc-image-builder produced no .qcow2 file in {build_dir}")

    built = candidates[0]
    log(f"  bootc build complete: {built.name}")
    try:
        subprocess.run(["cp", "--reflink=auto", str(built), str(system_disk)], check=True)
    except subprocess.CalledProcessError:
        shutil.copy2(built, system_disk)
    log(f"  System disk ready: {system_disk}")


def create_data_disk(data_dir: Path, size: str):
    """Create data.qcow2 if it doesn't exist. Size format: '20G', '100M', etc.

    The precious data disk lives in the backup-captured data/ subtree, apart
    from the reconstructible system.qcow2 in state/.
    """
    data_dir.mkdir(parents=True, exist_ok=True)
    data_disk = data_dir / "data.qcow2"
    if data_disk.exists():
        return
    log(f"  Creating data disk: {data_disk.name} ({size})")
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", str(data_disk), size],
        check=True
    )


def build_system_disk(vm_cfg: dict, home_dir: Path, system_disk: Path):
    """Build system_disk from whichever image source [vm] names."""
    if vm_cfg.get("cloud_image_url"):
        build_from_cloud_image(
            vm_cfg["cloud_image_url"],
            vm_cfg["cloud_image_checksum"],
            home_dir,
            system_disk,
        )
    elif vm_cfg.get("local_image"):
        build_from_local_image(vm_cfg["local_image"], system_disk)
    elif vm_cfg.get("image"):
        build_from_bootc_image(vm_cfg["image"], home_dir, system_disk)
    else:
        raise ValueError("no image source configured in [vm]")


def _chown_to_workload(path: Path, name: str):
    # The build service runs as root; the disk must belong to the workload
    # user that QEMU runs as. A missing user or a foreign filesystem is not a
    # build failure.
    try:
        pw = pwd.getpwnam(f"_wl-{name}")
        os.chown(path, pw.pw_uid, pw.pw_gid)
    except (KeyError, OSError):
        pass


def build_disks(name: str, update: bool):
    """Build what `name` is missing: the system disk unless it exists (or
    `update` says rebuild it), and the data disk if [vm] sizes one.

    Raises on a failed system build, after restoring the rotated generation.
    """
    log(f"Building system disk for VM workload: {name}")
    config = load_workload_config(name)
    vm_cfg = config.get("vm", {})
    home_dir = workload_state_dir(name)
    home_dir.mkdir(parents=True, exist_ok=True)
    system_disk = home_dir / "system.qcow2"

    if system_disk.exists() and not update:
        # Fall through to the data disk: a data_disk_size added after first
        # enable still has to create data.qcow2 on the next start.
        log("  system.qcow2 already exists; skipping system disk build (use --update to rebuild)")
    else:
        rotated_to: Path | None = None
        if update and system_disk.exists():
            rotated_to = rotate_generations(home_dir, vm_cfg.get("rollback_keep", 2))
        try:
            build_system_disk(vm_cfg, home_dir, system_disk)
        except Exception:
            system_disk.unlink(missing_ok=True)
            if rotated_to is not None and rotated_to.exists():
                log(f"  Restoring previous generation: {rotated_to.name} → system.qcow2")
                rotated_to.rename(system_disk)
            raise
        _chown_to_workload(system_disk, name)

        # The Fedora Cloud qcow2 is ~5GB; builds that write large artifacts
        # need more. cloud-init's growpart expands the partition on first boot.
        system_disk_size = vm_cfg.get("system_disk_size", "")
        if system_disk_size:
            log(f"  Resizing system disk to {system_disk_size}...")
            subprocess.run(
                ["qemu-img", "resize", str(system_disk), system_disk_size],
                check=True,
            )
            log(f"  System disk resized to {system_disk_size}")

    data_disk_size = vm_cfg.get("data_disk_size", "")
    if data_disk_size:
        data_dir = workload_data_dir(name)
        create_data_disk(data_dir, data_disk_size)
        _chown_to_workload(data_dir / "data.qcow2", name)

    log(f"Build complete for {name}")
