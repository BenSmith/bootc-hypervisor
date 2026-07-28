"""
test_data.py — backup and restore verbs.

Covers: backup (single + --all + --json), restore (--enable + --force).
Both substrates (container + VM).

backup/restore must be run as a pair against a purgeable fixture.
"""

import json
import time

import pytest

from fixtures import poll_vm_reachable
from target import Target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BACKUP_DIR = "/var/lib/workloads/backups"


def _find_backup(target: Target, workload_name: str) -> str | None:
    """Return the path of the most recent backup archive for a workload, or None."""
    r = target.run(
        ["bash", "-c",
         f"ls -1t {BACKUP_DIR}/{workload_name}-*.tar.zst 2>/dev/null | head -1"],
        sudo=True, check=False,
    )
    path = r.stdout.strip()
    return path if path else None


def _archive_exists(target: Target, path: str) -> bool:
    return target.remote_path_exists(path)


# ---------------------------------------------------------------------------
# backup — containers
# ---------------------------------------------------------------------------

class TestBackupContainer:
    @pytest.mark.mutating
    def test_backup_single(self, target, fresh_single, record_property):
        """backup creates an archive for a running workload."""
        record_property("cell", "backup/container")
        r = target.wl(f"backup {fresh_single}", check=True, timeout=120)
        assert r.rc == 0
        assert "Traceback" not in r.stderr

        archive = _find_backup(target, fresh_single)
        assert archive, f"No backup archive found for {fresh_single}"
        assert _archive_exists(target, archive), f"Archive {archive} does not exist"

    @pytest.mark.mutating
    def test_backup_json(self, target, fresh_single, record_property):
        """backup --json returns structured output with archive path."""
        record_property("cell", "backup/container")
        r = target.wl(f"backup --json {fresh_single}", check=True, timeout=120)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert "backups" in data
        assert len(data["backups"]) >= 1
        entry = data["backups"][0]
        assert "workload" in entry
        assert "archive" in entry
        assert "size_bytes" in entry
        assert entry["size_bytes"] > 0

    @pytest.mark.mutating
    def test_backup_output_path(self, target, fresh_single, record_property):
        """backup --output writes to a specified path."""
        record_property("cell", "backup/container")
        output_path = f"/tmp/clitest-backup-{fresh_single}.tar.zst"
        try:
            r = target.wl(
                f"backup --output {output_path} {fresh_single}",
                check=True, timeout=120,
            )
            assert r.rc == 0
            assert _archive_exists(target, output_path), f"Archive not at {output_path}"
        finally:
            target.run(["rm", "-f", output_path], sudo=True, check=False)

    @pytest.mark.mutating
    def test_backup_crash_consistency(self, target, fresh_single, record_property):
        """backup --consistency crash creates archive without stopping the service."""
        record_property("cell", "backup/container")
        # Service must remain active during a crash-consistent backup
        r = target.wl(f"backup --consistency crash {fresh_single}", check=True, timeout=120)
        assert r.rc == 0
        # Service still running
        svc_r = target.run(
            ["systemctl", "is-active", f"workload-{fresh_single}.service"],
            sudo=False, check=False,
        )
        assert svc_r.stdout.strip() == "active", "Service stopped during crash-consistent backup"

    @pytest.mark.mutating
    def test_backup_all(self, target, fresh_single, record_property):
        """backup --all backs up all workloads without crashing."""
        record_property("cell", "backup_all/any")
        r = target.wl("backup --all", check=True, timeout=300)
        assert r.rc == 0
        assert "Traceback" not in r.stderr


# ---------------------------------------------------------------------------
# backup — VM
# ---------------------------------------------------------------------------

@pytest.mark.vm
@pytest.mark.slow
class TestBackupVM:
    def test_backup_vm(self, target, fresh_vm, record_property):
        """backup a stopped VM workload."""
        record_property("cell", "backup/vm")
        # Stop VM first (backup requires it stopped for VMs)
        target.wl(f"stop {fresh_vm}", check=False, timeout=30)
        time.sleep(5)

        r = target.wl(f"backup {fresh_vm}", check=True, timeout=300)
        assert r.rc == 0
        assert "Traceback" not in r.stderr

        archive = _find_backup(target, fresh_vm)
        assert archive, f"No backup archive for {fresh_vm}"

        # fresh_vm is torn down by its fixture finalizer; no need to restart

    def test_backup_vm_crash_consistency(self, target, clitest_vm, record_property):
        """backup --consistency crash on a running VM uses QMP-paused live copy."""
        record_property("cell", "backup_crash/vm")
        r = target.wl(f"backup --consistency crash {clitest_vm}", check=True, timeout=300)
        assert r.rc == 0, f"crash-consistent VM backup failed: {r.stderr}"
        assert "Traceback" not in r.stderr
        archive = _find_backup(target, clitest_vm)
        assert archive, f"No backup archive for {clitest_vm} after crash-consistent backup"


# ---------------------------------------------------------------------------
# restore
# ---------------------------------------------------------------------------

class TestRestore:
    @pytest.mark.mutating
    @pytest.mark.destructive
    def test_restore_container(self, target, record_property):
        """backup → disable --purge → restore re-enables the workload.

        Uses a minimal inline workload so we don't touch other fixtures.
        """
        record_property("cell", "restore/container")
        name = "clitest-restore-test"
        cfg_dir = f"/etc/workloads.d/{name}"
        toml_path = f"{cfg_dir}/workload.toml"
        toml_content = (
            f'[workload]\nname = "{name}"\nenabled = false\n\n'
            '[container]\nimage = "docker.io/library/caddy:2-alpine"\n'
        )
        archive_path = None
        try:
            # 1. Create and enable
            target.run(["mkdir", "-p", cfg_dir], sudo=True, check=True)
            target.put_content(toml_content, toml_path)
            target.wl(f"enable {name}", check=True, timeout=180)

            # 2. Back it up
            r = target.wl(f"backup --json {name}", check=True, timeout=120)
            data = json.loads(r.stdout)
            archive_path = data["backups"][0]["archive"]
            assert _archive_exists(target, archive_path)

            # 3. Disable --purge (removes user + home)
            target.wl(f"disable --purge {name}", check=True, timeout=60)
            time.sleep(2)

            # 4. Remove config dir (simulate clean slate)
            target.run(["rm", "-rf", cfg_dir], sudo=True, check=False)

            # 5. Restore --enable
            r = target.wl(
                f"restore --enable --force {archive_path}",
                check=True, timeout=300,
            )
            assert r.rc == 0
            assert "Traceback" not in r.stderr

            # 6. Verify the workload is listed
            r2 = target.wl("list --json", sudo=False, check=True)
            data2 = json.loads(r2.stdout)
            names = [w["name"] for w in data2["workloads"]]
            assert name in names, f"{name!r} not in workloads after restore"

        finally:
            target.wl(f"disable --purge {name}", check=False, timeout=60)
            target.run(["rm", "-rf", cfg_dir], sudo=True, check=False)
            if archive_path:
                target.run(["rm", "-f", archive_path], sudo=True, check=False)

    @pytest.mark.vm
    @pytest.mark.mutating
    @pytest.mark.destructive
    @pytest.mark.slow
    def test_restore_vm_round_trip(self, target, vm_with_data_disk, record_property):
        """backup → sentinel → purge → restore: the guest's data disk comes back.

        `restore` is the verb that decides whether "we have backups" is true, and
        its failure mode is unrecoverable — you find out at the moment the
        original is already gone. cmd_restore has no is_vm branch; it extracts and
        places the tree generically. This test is what says whether that is
        correct for a VM.

        The sentinel lives on the *data* disk, not in the guest's root
        filesystem: backup captures the data/ subtree only (system.qcow2 and its
        gen-N snapshots are state/, deliberately out of scope as reconstructible),
        so a sentinel anywhere else would be expected to vanish and would prove
        nothing either way. A sentinel is what separates a real restore from a
        re-provision that merely yields *a* working VM.
        """
        record_property("cell", "restore/vm")
        name = vm_with_data_disk
        token = f"clitest-sentinel-{int(time.time())}"
        cfg_dir = f"/etc/workloads.d/{name}"
        archive_path = None

        try:
            # Precondition: the data disk reached the guest and the seed's
            # first-boot runcmd formatted and mounted it at /data. Without that
            # the round-trip below would pass by restoring nothing.
            probe = target.wl_exec(name, "findmnt -no SOURCE /data",
                                   check=False, timeout=60)
            assert probe.rc == 0 and "vdb" in probe.stdout, (
                f"/data is not the data disk in the guest (findmnt said "
                f"{probe.stdout.strip()!r}) — this test cannot distinguish a "
                f"restore from a re-provision"
            )

            # The token is a filename, so every guest command stays flat argv.
            target.wl_exec(name, f"sudo touch /data/{token}", check=True, timeout=60)
            target.wl_exec(name, "sudo sync", check=True, timeout=60)

            # VMs back up stopped (the archive must not catch a live disk).
            target.wl(f"stop {name}", check=False, timeout=60)
            time.sleep(5)
            r = target.wl(f"backup --json {name}", check=True, timeout=300)
            archive_path = json.loads(r.stdout)["backups"][0]["archive"]
            assert _archive_exists(target, archive_path)

            target.wl(f"disable --purge {name}", check=True, timeout=180)
            target.run(["rm", "-rf", cfg_dir], sudo=True, check=False)
            assert not target.remote_path_exists(f"/var/lib/workloads/{name}"), (
                "purge left the workload tree behind; the restore below would be "
                "reading the original, not the archive"
            )

            r = target.wl(f"restore --enable --force {archive_path}",
                          check=True, timeout=600)
            assert "Traceback" not in r.stderr

            reachable = poll_vm_reachable(target, name, timeout=600)
            assert reachable is not None and reachable.rc == 0, (
                f"{name!r} not reachable after restore: "
                f"{'' if reachable is None else reachable.stdout + reachable.stderr}"
            )

            # The restored disk already carries a filesystem, so the seed's
            # blkid guard must leave it alone and fstab must mount it — the
            # round-trip covers that guard as well as the archive contents.
            mount = target.wl_exec(name, "findmnt -no SOURCE /data",
                                   check=False, timeout=60)
            assert mount.rc == 0 and "vdb" in mount.stdout, (
                f"the restored data disk is not mounted at /data (findmnt said "
                f"{mount.stdout.strip()!r}) — first boot may have reformatted it"
            )
            read = target.wl_exec(name, "ls /data", check=False, timeout=60)
            assert read.rc == 0, f"cannot read /data after restore: {read.stderr}"
            assert token in read.stdout, (
                f"sentinel missing from the restored data disk — /data holds "
                f"{read.stdout.split()!r}, expected {token!r}"
            )
        finally:
            if archive_path:
                target.run(["rm", "-f", archive_path], sudo=True, check=False)

    def test_restore_missing_archive_fails(self, target, record_property):
        """restore with a nonexistent archive exits nonzero cleanly."""
        record_property("cell", "restore/error")
        r = target.wl(
            "restore /tmp/clitest-nosucharchive.tar.zst",
            check=False, timeout=15,
        )
        assert r.rc != 0
        assert "Traceback" not in r.stderr
