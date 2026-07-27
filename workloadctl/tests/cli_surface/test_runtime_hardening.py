"""
test_runtime_hardening.py — C1 GAP check: the systemd sandbox directives on the
workload *system* unit are live on a real kernel, not just present in unit text.

The generator writes `ProtectSystem=strict`, `PrivateTmp=yes`,
`RestrictAddressFamilies=~AF_ALG AF_PACKET`, and a tight `ReadWritePaths` onto
every `workload-<name>.service` (generators/workload-generate). Unit-file text
proves nothing about enforcement: systemd could parse-and-ignore, a future refactor
could move the directive under a condition, or the sandbox could fail to apply on
the running kernel. This test enables a workload and asserts the sandbox is
genuinely in effect on the live main process:

  * `systemctl show` reports the effective (parsed, applied) directive values.
  * The main PID lives in a **private mount namespace** (distinct from PID 1).
  * `/usr` is **read-only** in that namespace (`ProtectSystem=strict` enforced),
    read straight from `/proc/<mainpid>/mountinfo`.

A second check covers the other hardening layer on the same workload: the podman
seccomp baseline. `seccomp-workload-baseline.json` gates `setns` behind
CAP_SYS_ADMIN, and whether that gate is *enforced* is invisible to a test that
reads the JSON — a name in the profile's plain allow list silently overrides the
cap-gated deny. Only a syscall on a real kernel can tell the difference.

Reuses the minimal rt-basic workload (single/pasta) — hardening is topology-
independent, so the smallest running unit is enough.

Marked `runtime`: only runs under `--target=vm:<mode>` (i.e. `just test-runtime`).
"""

import re

import pytest

from fixtures import _enable_workload, _install_toml, _purge_workload, dump_journal

pytestmark = pytest.mark.runtime

WORKLOAD = "rt-basic"
SERVICE = "workload-rt-basic.service"

# Calls setns(2) with a deliberately invalid fd, so the errno separates the two
# layers: EPERM (1) can only come from seccomp, while EBADF (9) means the call
# reached the kernel and failed its own fd check — i.e. seccomp let it through.
_SETNS_PROBE = (
    "import ctypes, ctypes.util\n"
    "libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)\n"
    "libc.setns(-1, 0)\n"
    "print(ctypes.get_errno())\n"
)

EPERM, EBADF = 1, 9


def _show(target, service, prop):
    """Return the effective value of one unit property via `systemctl show`."""
    r = target.run(
        ["systemctl", "show", service, "-p", prop, "--value"],
        sudo=True, check=True,
    )
    return r.stdout.strip()


def _governing_mount(mountinfo_text, path):
    """Return (mountpoint, options) of the mount that governs `path`.

    /proc/<pid>/mountinfo fields: [4]=mountpoint, [5]=per-mount options. The
    governing mount is the one whose mountpoint is the longest prefix of `path`
    (with `/` always a candidate). ProtectSystem=strict remounts the hierarchy
    read-only, so the mount covering /usr carries `ro` when the sandbox is live.
    """
    best_mp = None
    best_opts = None
    for line in mountinfo_text.splitlines():
        parts = line.split(" ")
        if len(parts) < 6:
            continue
        mp, opts = parts[4], parts[5]
        governs = mp == "/" or path == mp or path.startswith(mp.rstrip("/") + "/")
        if governs and (best_mp is None or len(mp) > len(best_mp)):
            best_mp, best_opts = mp, opts
    return best_mp, best_opts


def _seccomp_profile_from_unit(target, service):
    """The profile path the live unit actually passes to podman, or None."""
    r = target.run(["systemctl", "cat", service], sudo=True, check=True)
    m = re.search(r"--security-opt[= ]seccomp=(\S+)", r.stdout)
    return m.group(1) if m else None


def _setns_errno(target, profile, *, cap_sys_admin=False):
    """Run the setns probe in a container under `profile`; return its errno.

    `--rootfs /:O` reuses the host's own filesystem as a throwaway overlay rather
    than pulling an image: the guest ships python3 (workloadctl requires it) but
    the workload fixture image is caddy:2-alpine, which has neither python nor a
    compiler. Note --rootfs takes the command positionally, so every flag has to
    precede it.
    """
    argv = ["podman", "run", "--rm"]
    if cap_sys_admin:
        argv += ["--cap-add", "SYS_ADMIN"]
    argv += ["--security-opt", f"seccomp={profile}",
             "--rootfs", "/:O", "python3", "-c", _SETNS_PROBE]
    r = target.run(argv, sudo=True, check=True)
    return int(r.stdout.strip().splitlines()[-1])


def test_setns_is_denied_without_cap_sys_admin(target):
    """The baseline profile's CAP_SYS_ADMIN gate on `setns` is enforced on a real
    kernel, applied through the path the units really use.

    The unit-level test (tests/test_seccomp_baseline.py) can only assert the JSON.
    It cannot see that a name in the plain allow list silently overrides the
    cap-gated deny — which is exactly what happened here: `setns` sat in both, and
    the gate was inert, so every workload could join an existing namespace given
    an fd. Asserting *both* directions is what makes this meaningful: EPERM alone
    would also pass for a profile that denies everything.
    """
    _install_toml(target, "rt-basic.toml")
    try:
        try:
            _enable_workload(target, WORKLOAD, timeout=180)
        except Exception:
            dump_journal(target, WORKLOAD)
            raise

        profile = _seccomp_profile_from_unit(target, SERVICE)
        assert profile, (
            f"{SERVICE} passes no --security-opt seccomp= to podman; the baseline "
            f"profile is not being applied at all"
        )
        exists = target.run(["test", "-f", profile], sudo=True, check=False)
        assert exists.rc == 0, f"unit names a seccomp profile that is absent: {profile}"

        capless = _setns_errno(target, profile)
        with_cap = _setns_errno(target, profile, cap_sys_admin=True)
        print(f"\n----- setns under {profile} -----\n"
              f"capless errno={capless} (want {EPERM}/EPERM)\n"
              f"CAP_SYS_ADMIN errno={with_cap} (want {EBADF}/EBADF)\n"
              f"---------------------------------")

        assert capless == EPERM, (
            f"setns returned errno {capless}, not EPERM: the CAP_SYS_ADMIN gate in "
            f"{profile} is not enforced (errno {EBADF}/EBADF means the syscall "
            f"reached the kernel, i.e. an ungated allow is overriding the gate)"
        )
        assert with_cap == EBADF, (
            f"setns returned errno {with_cap} with CAP_SYS_ADMIN, not EBADF: the "
            f"profile denies it even *with* the capability, so the gate is a "
            f"blanket deny rather than a gate"
        )
    finally:
        _purge_workload(target, WORKLOAD)


def test_workload_unit_sandbox_live(target):
    """The workload system unit's sandbox directives are applied and enforced:
    ProtectSystem=strict, PrivateTmp, RestrictAddressFamilies, a private mount
    namespace, and a read-only /usr in that namespace."""
    _install_toml(target, "rt-basic.toml")
    try:
        try:
            _enable_workload(target, WORKLOAD, timeout=180)
        except Exception:
            dump_journal(target, WORKLOAD)
            raise

        # --- effective (parsed + applied) directive values on the live unit ---
        protect_system = _show(target, SERVICE, "ProtectSystem")
        private_tmp = _show(target, SERVICE, "PrivateTmp")
        raf = _show(target, SERVICE, "RestrictAddressFamilies")
        rwp = _show(target, SERVICE, "ReadWritePaths")
        main_pid = _show(target, SERVICE, "MainPID")

        print(f"\n----- {SERVICE} sandbox properties -----\n"
              f"ProtectSystem={protect_system}\nPrivateTmp={private_tmp}\n"
              f"RestrictAddressFamilies={raf}\nReadWritePaths={rwp}\n"
              f"MainPID={main_pid}\n----------------------------------------")

        assert protect_system == "strict", (
            f"ProtectSystem not strict on {SERVICE}: {protect_system!r}"
        )
        # PrivateTmp is enabled (rendered "yes"/"true"/"connected" across systemd
        # versions); only the disabled sentinels fail.
        assert private_tmp not in ("no", "false", ""), (
            f"PrivateTmp not enabled on {SERVICE}: {private_tmp!r}"
        )
        # Deny-list is rendered with a leading '~' and names the denied families.
        assert "AF_ALG" in raf and "AF_PACKET" in raf, (
            f"RestrictAddressFamilies does not deny AF_ALG/AF_PACKET: {raf!r}"
        )
        # ReadWritePaths carves out the workload's own tree + its user runtime dir.
        assert WORKLOAD in rwp and "/run/user/" in rwp, (
            f"ReadWritePaths missing workload root or /run/user/: {rwp!r}"
        )

        assert main_pid.isdigit() and int(main_pid) > 0, (
            f"no MainPID for {SERVICE} (got {main_pid!r})"
        )

        # --- private mount namespace: main PID != PID 1's mount ns ---
        wl_ns = target.run(["readlink", f"/proc/{main_pid}/ns/mnt"],
                           sudo=True, check=True).stdout.strip()
        init_ns = target.run(["readlink", "/proc/1/ns/mnt"],
                             sudo=True, check=True).stdout.strip()
        assert wl_ns and wl_ns != init_ns, (
            f"MainPID {main_pid} shares PID 1's mount namespace "
            f"({wl_ns!r} == {init_ns!r}) — sandbox not applied"
        )

        # --- ProtectSystem=strict enforced: /usr is read-only in that ns ---
        mountinfo = target.run(["cat", f"/proc/{main_pid}/mountinfo"],
                               sudo=True, check=True).stdout
        mp, opts = _governing_mount(mountinfo, "/usr")
        print(f"----- mount governing /usr in MainPID ns -----\n{mp} {opts}\n"
              f"----------------------------------------------")
        assert opts is not None, (
            f"could not find a mount governing /usr in /proc/{main_pid}/mountinfo"
        )
        assert "ro" in opts.split(","), (
            f"/usr is not read-only in the workload namespace (mount {mp} opts "
            f"{opts!r}) — ProtectSystem=strict not enforced"
        )
    finally:
        _purge_workload(target, WORKLOAD)
