"""
test_runtime_vm_virtiofs.py — B6 runtime check: a `[vm]` workload's virtiofs
share is actually usable by the guest, and the sidecar serving it is unprivileged.

WHY THIS EXISTS. The unit tests around a virtiofs share are all about the *text*
of the unit — that the flags are spelled right, that the id ranges partition,
that the sidecar does not declare RuntimeDirectory. A rendered unit can be
correct in every one of those ways while the share it produces is broken, and
the breakages are not subtle once a guest touches them:

  * an id map that lets a guest create host files owned by any uid it names,
    root included, so a setuid-root binary planted from the guest lands on the
    host as `-rwsr-xr-x root root`;
  * a missing SELinux class — `ln -s` returning EPERM under enforcing while
    every read, write, create and delete around it succeeds, or `mv` between two
    directories denied for want of dir:reparent;
  * a root-owned pid file in /run stopping the unprivileged daemon from
    starting, with an error that reads as a policy fault.

None of that is reachable without a guest writing to a real share, so the checks
here are about *behaviour under a guest* rather than shape.

Same gates and nested-KVM shape as test_runtime_vm_smoke.py: default-safe skips
without nested /dev/kvm or the VM toolchain (this really runs under gate mode).
"""

import pytest

from fixtures import (
    dump_journal,
    _enable_workload, _install_toml, _purge_workload,
    poll_vm_reachable, skip_if_no_kvm, skip_if_no_vm_toolchain,
)

pytestmark = [pytest.mark.runtime, pytest.mark.slow]

WORKLOAD = "rt-vm-virtiofs"
USER = f"_wl-{WORKLOAD}"
SIDECAR = f"workload-{WORKLOAD}-virtiofs-mnt-share.service"
HOST_SHARE = f"/var/lib/workloads/{WORKLOAD}/data/share"
GUEST_SHARE = "/mnt/share"
SOCKET = f"/run/workload-vm/{WORKLOAD}/virtiofs-mnt-share.sock"


def _dump_denials(target):
    """Print the guest's recent audit denials alongside the journal.

    Added because a gate failure here could not be diagnosed without it: the
    sidecar died with `Mmap(PermissionDenied)` and the journal dump showed the
    error but nothing about whether SELinux caused it. For a daemon whose whole
    design is "unprivileged, confined by policy", a denial is the single most
    likely explanation and the one thing the harness was not capturing.

    Best-effort and never raises — this runs on a path that is already failing,
    and losing the real error behind a diagnostic's own exception is a bad
    trade. Plain grep rather than ausearch: ausearch's own time filters have
    been unreliable enough to hide records that were sitting in the log.
    """
    for pattern in ("wlvfsd", "virtiofsd", "denied"):
        try:
            r = target.run(["grep", "-a", "-m", "25", pattern,
                            "/var/log/audit/audit.log"],
                           sudo=True, check=False, timeout=60)
            if r.stdout.strip():
                print(f"----- audit.log matches for {pattern!r} -----")
                print(r.stdout[-4000:])
        except Exception as exc:  # noqa: BLE001 - diagnostics must not mask
            print(f"----- could not read audit.log for {pattern!r}: {exc}")


@pytest.fixture(scope="module")
def vm(target):
    """Boot the share-carrying VM once for the whole module.

    A nested boot plus a possible cold cloud-image fetch is the most expensive
    thing in the rung; these checks are independent reads of one running guest,
    so they share it rather than paying for it each.
    """
    skip_if_no_kvm(target)
    skip_if_no_vm_toolchain(target)

    try:
        _install_toml(target, f"{WORKLOAD}.toml")
        try:
            _enable_workload(target, WORKLOAD, timeout=900, expect_container=False)
        except Exception:
            dump_journal(target, WORKLOAD, extra_units=[SIDECAR])
            _dump_denials(target)
            raise

        reached = poll_vm_reachable(target, WORKLOAD, token="virtiofs-up",
                                    timeout=300)
        if not (reached and reached.rc == 0 and "virtiofs-up" in reached.stdout):
            dump_journal(target, WORKLOAD, extra_units=[SIDECAR])
            _dump_denials(target)
        assert reached is not None and reached.rc == 0, (
            f"`workloadctl exec {WORKLOAD}` never reached the guest "
            f"(rc={None if reached is None else reached.rc})"
        )
        yield target
    finally:
        _purge_workload(target, WORKLOAD)


def _guest(target, *argv, check=True):
    """One guest command as plain argv.

    Never a compound `sh -c "… && …"`: that does not survive the double SSH hop
    (harness → host → guest) intact — the same constraint test_runtime_vm_hostkey
    hit and documents.
    """
    return target.wl_exec(WORKLOAD, list(argv), sudo=True, check=check, timeout=120)


def test_sidecar_is_active_and_the_guest_has_the_share_mounted(vm):
    """The two halves have to meet: a sidecar that is up but that the guest never
    mounted looks identical to a working share until something reads it."""
    r = vm.run(["systemctl", "is-active", SIDECAR], sudo=False, check=False)
    if r.stdout.strip() != "active":
        dump_journal(vm, WORKLOAD, extra_units=[SIDECAR])
    assert r.stdout.strip() == "active", (
        f"{SIDECAR} is {r.stdout.strip()!r}, expected active")

    # `stat -f -c %T` reports the filesystem type of the mount point. virtiofs
    # presents as fuse; if cloud-init never mounted it this is the guest's own
    # root filesystem instead, and every write below would silently land in the
    # guest's disk rather than the share.
    r = _guest(vm, "stat", "-f", "-c", "%T", GUEST_SHARE)
    assert "fuse" in r.stdout, (
        f"{GUEST_SHARE} is not a virtiofs mount in the guest (stat -f says "
        f"{r.stdout.strip()!r}) — cloud-init did not mount the volume")


def test_sidecar_runs_unprivileged_with_no_capabilities(vm):
    """The privilege claim, measured on the running process rather than read off
    the unit file. virtiofsd would need CAP_SETUID/CAP_SETGID to impersonate the
    calling guest user per request; the id map means there is no caller to
    impersonate, so there is nothing for it to be privileged for."""
    r = vm.run(["systemctl", "show", "-p", "MainPID", "--value", SIDECAR],
               sudo=False, check=True)
    pid = r.stdout.strip()
    assert pid and pid != "0", f"{SIDECAR} has no MainPID"

    status = vm.run(["cat", f"/proc/{pid}/status"], sudo=True, check=True).stdout
    fields = {}
    for line in status.splitlines():
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()

    # Real uid, effective uid, saved uid, fs uid — all four, so a daemon that
    # merely dropped its effective uid would still fail this.
    uid_line = fields.get("Uid", "")
    assert uid_line, "no Uid line in /proc/<pid>/status"
    expect_uid = vm.run(["id", "-u", USER], sudo=False, check=True).stdout.strip()
    assert uid_line.split() == [expect_uid] * 4, (
        f"virtiofsd runs as uid(s) {uid_line!r}, expected {expect_uid} throughout "
        f"— it is not the workload user")

    for field in ("CapPrm", "CapEff", "CapBnd"):
        assert fields.get(field) == "0" * 16, (
            f"virtiofsd holds capabilities: {field}={fields.get(field)!r}. "
            f"The empty bounding set is what makes the SELinux module's absent "
            f"capability rules correct rather than merely unused.")


def test_guest_can_use_every_kind_of_node_a_filesystem_has(vm):
    """The classes the SELinux module grants, exercised for real.

    Each of these was at some point denied while the share otherwise looked
    fine. Plain coreutils only, one command per call — see _guest().
    """
    _guest(vm, "rm", "-rf", f"{GUEST_SHARE}/rt")
    _guest(vm, "mkdir", "-p", f"{GUEST_SHARE}/rt/a", f"{GUEST_SHARE}/rt/b")

    # file: create, write, link
    _guest(vm, "cp", "/etc/hostname", f"{GUEST_SHARE}/rt/a/f")
    _guest(vm, "ln", f"{GUEST_SHARE}/rt/a/f", f"{GUEST_SHARE}/rt/a/hard")
    # lnk_file: create, read
    _guest(vm, "ln", "-s", "f", f"{GUEST_SHARE}/rt/a/sym")
    r = _guest(vm, "readlink", f"{GUEST_SHARE}/rt/a/sym")
    assert r.stdout.strip() == "f", "symlink in the share does not read back"
    # fifo_file: create
    _guest(vm, "mkfifo", f"{GUEST_SHARE}/rt/a/fifo")
    # dir:setattr — cloud-init's chown of a HOME is this permission
    _guest(vm, "chmod", "750", f"{GUEST_SHARE}/rt/a")
    # dir:rename + dir:reparent — a move *between* directories needs both
    _guest(vm, "mv", f"{GUEST_SHARE}/rt/a/f", f"{GUEST_SHARE}/rt/b/moved")
    # …and the removals, because create-without-unlink is the same bug smaller
    _guest(vm, "rm", "-f", f"{GUEST_SHARE}/rt/a/sym", f"{GUEST_SHARE}/rt/a/fifo")
    _guest(vm, "rm", "-rf", f"{GUEST_SHARE}/rt")


def test_everything_the_guest_creates_is_owned_by_the_workload_user(vm):
    """The security property, from the host side.

    Without the id map a guest chooses the owner of the files it creates, root
    included — measured once as a `-rwsr-xr-x root root` binary appearing on the
    host filesystem, which `backup` would then carry into an archive. Here the
    guest's own root asks for root ownership explicitly and must not get it.
    """
    _guest(vm, "rm", "-rf", f"{GUEST_SHARE}/own")
    _guest(vm, "mkdir", f"{GUEST_SHARE}/own")
    _guest(vm, "cp", "/etc/hostname", f"{GUEST_SHARE}/own/asroot")
    # Run as the guest's root and ask for root:root explicitly.
    _guest(vm, "sudo", "chown", "0:0", f"{GUEST_SHARE}/own/asroot")
    # And the setuid bit, the other half of the original finding.
    _guest(vm, "sudo", "chmod", "4755", f"{GUEST_SHARE}/own/asroot")

    r = vm.run(["stat", "-c", "%U %G", f"{HOST_SHARE}/own/asroot"],
               sudo=True, check=True)
    assert r.stdout.strip() == f"{USER} {USER}", (
        f"a guest asked for root:root and the host file is {r.stdout.strip()!r} "
        f"— the id map is not squashing")

    _guest(vm, "rm", "-rf", f"{GUEST_SHARE}/own")


def test_a_stale_root_owned_pid_file_does_not_block_the_sidecar(vm):
    """The upgrade path, which /run being a tmpfs hides on any host that reboots.

    The root-era sidecar leaves a root-owned 0600 <socket>.pid behind. virtiofsd
    opens that exact path O_CREAT|O_WRONLY, so the unprivileged daemon dies with
    "Error creating pid file … Permission denied" — which reads as an SELinux
    problem and is not one. The unit's ExecStartPre clears both names; this
    proves it, by planting the file the old version would have left.
    """
    vm.run(["systemctl", "stop", SIDECAR], sudo=True, check=False)
    vm.run(["rm", "-f", SOCKET, f"{SOCKET}.pid"], sudo=True, check=False)
    vm.run(["sh", "-c", f"echo 12345 > {SOCKET}.pid"], sudo=True, check=True)
    vm.run(["chown", "root:root", f"{SOCKET}.pid"], sudo=True, check=True)
    vm.run(["chmod", "600", f"{SOCKET}.pid"], sudo=True, check=True)

    r = vm.run(["systemctl", "start", SIDECAR], sudo=True, check=False)
    if r.rc != 0:
        dump_journal(vm, WORKLOAD, extra_units=[SIDECAR])
    assert r.rc == 0, (
        f"{SIDECAR} would not start over a stale root-owned pid file — the "
        f"ExecStartPre that clears it is missing or ineffective")

    owner = vm.run(["stat", "-c", "%U", f"{SOCKET}.pid"], sudo=True, check=True)
    assert owner.stdout.strip() == USER, (
        f"{SOCKET}.pid is owned by {owner.stdout.strip()!r} after a restart, so "
        f"the stale file was reused rather than replaced")


def test_no_selinux_denials_for_the_sidecar(vm):
    """A share can work while generating a denial per start — the file-handle
    fallback did exactly that. Anything here is either a missing rule or a flag
    that should not be asking."""
    r = vm.run(["sh", "-c",
                "grep -a 'scontext=[^ ]*:wlvfsd_t' /var/log/audit/audit.log "
                "| grep -ac denied || true"],
               sudo=True, check=False)
    if r.rc != 0:
        pytest.skip("audit log not readable on this target")
    count = r.stdout.strip() or "0"
    assert count == "0", (
        f"{count} wlvfsd_t denial(s) in the audit log. Harvest them with the "
        f"domain permissive and dontaudit disabled before adding rules — see the "
        f"method note in security/workload-vm.cil.")
