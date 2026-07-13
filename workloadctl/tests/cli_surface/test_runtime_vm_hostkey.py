"""
test_runtime_vm_hostkey.py — S1 runtime proof: the VM SSH host-key pin is
load-bearing (a swapped guest host key is *refused*, no TOFU).

Unit tests already prove the CLI builds the SSH command with
`StrictHostKeyChecking=yes` + a per-workload `vm_known_hosts`, and that the
host keypair is generated + injected into the guest seed. What no unit test can
prove is the end-to-end security property on a real boot: that when the guest
presents a *different* host key than the one pinned, `workloadctl exec` actually
refuses to connect instead of silently trusting it.

This is the swap-key-refuses proof the S1 DoD deferred to the runtime harness:

  1. Positive — after boot, `workloadctl exec` succeeds. Because the CLI uses
     StrictHostKeyChecking=yes, a success means the guest presented exactly the
     key the harness pinned (no first-use trust prompt bypass).
  2. Negative — re-key the guest's SSH host key (simulating a re-provisioned or
     MITM'd host), then `workloadctl exec` must *fail*. The pin no longer
     matches, so ssh aborts with host-key verification failure. If exec instead
     succeeded, the pin would be cosmetic — that is the regression this guards.

Same gates + nested-KVM shape as test_runtime_vm_smoke.py: default-safe skips
without nested /dev/kvm or the VM toolchain (runs under gate mode).
"""

import time

import pytest

from fixtures import (
    _install_toml, _purge_workload, _enable_workload,
    poll_vm_reachable, skip_if_no_kvm, skip_if_no_vm_toolchain,
)

pytestmark = [pytest.mark.runtime, pytest.mark.slow]

WORKLOAD = "rt-vm"


def _dump_journal(target, name):
    r = target.run(
        ["journalctl", "--no-pager", "-n", "100", "-u", f"workload-{name}.service"],
        sudo=True, check=False,
    )
    print(f"\n----- journalctl -u workload-{name}.service (tail) -----\n"
          f"{r.stdout}\n{r.stderr}\n--------------------------------------------------------")


def test_vm_ssh_hostkey_swap_is_refused(target):
    """Boot a VM, prove exec works against the pinned key, re-key the guest,
    then prove exec now refuses the changed key."""
    skip_if_no_kvm(target)
    skip_if_no_vm_toolchain(target)

    _install_toml(target, "rt-vm.toml")
    try:
        try:
            _enable_workload(target, WORKLOAD, timeout=900, expect_container=False)
        except Exception:
            _dump_journal(target, WORKLOAD)
            raise

        # (1) Positive: exec reaches the guest. StrictHostKeyChecking=yes means
        # this only succeeds if the guest presented the pinned host key.
        good = poll_vm_reachable(target, WORKLOAD, token="rt-vm-pinned", timeout=300)
        if not (good and good.rc == 0 and "rt-vm-pinned" in good.stdout):
            _dump_journal(target, WORKLOAD)
        assert good is not None and good.rc == 0 and "rt-vm-pinned" in good.stdout, (
            f"`workloadctl exec {WORKLOAD}` never reached the guest with the pinned "
            f"host key (last rc={None if good is None else good.rc}):\n"
            f"{'' if good is None else good.stdout}\n{'' if good is None else good.stderr}"
        )

        # Re-key the guest's ed25519 host key (the pinned type), then bounce sshd.
        # Issue each step as its own simple-argv exec: a compound `sh -c "… && …"`
        # string does not survive the double SSH hop (harness→host→guest) intact,
        # so the pieces are run separately. Removing the old key first means
        # ssh-keygen won't stop on an interactive overwrite prompt.
        target.wl_exec(
            WORKLOAD,
            ["sudo", "rm", "-f",
             "/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_ed25519_key.pub"],
            sudo=True, check=True, timeout=60,
        )
        # `ssh-keygen -A` regenerates just the now-missing ed25519 host key with
        # an empty passphrase — no `-N ""` empty-string argv element, which
        # `workloadctl exec`'s SSH hop to the guest silently drops (ssh joins argv
        # with spaces, so an empty arg vanishes and mangles the flags).
        target.wl_exec(
            WORKLOAD, ["sudo", "ssh-keygen", "-A"],
            sudo=True, check=True, timeout=60,
        )
        # Restart sshd detached (it drops this very SSH session, which would
        # otherwise make the exec itself report failure and mask the result).
        target.wl_exec(
            WORKLOAD,
            ["sudo", "systemd-run", "--collect", "--unit=rt-vm-rekey",
             "systemctl", "restart", "sshd"],
            sudo=True, check=True, timeout=60,
        )

        # (2) Negative: with a changed host key, the pin no longer matches, so
        # exec must fail. Poll for the failure to appear (sshd restart lag), then
        # assert it is a host-key rejection — never a silent success.
        deadline = time.monotonic() + 120
        refused = None
        while time.monotonic() < deadline:
            refused = target.wl_exec(
                WORKLOAD, "echo rt-vm-should-not-run",
                sudo=True, check=False, timeout=60,
            )
            # A clean success here would be the security failure we're guarding.
            if refused.rc != 0 and "rt-vm-should-not-run" not in refused.stdout:
                break
            time.sleep(5)

        assert refused is not None, "no exec result captured after re-key"
        assert refused.rc != 0 and "rt-vm-should-not-run" not in refused.stdout, (
            "`workloadctl exec` connected to the guest AFTER its host key changed "
            "— the pin is not load-bearing (TOFU/host-key-check bypass regression):\n"
            f"rc={refused.rc}\nstdout={refused.stdout}\nstderr={refused.stderr}"
        )
        # Sanity: the failure is a host-key rejection, not some unrelated error.
        combined = (refused.stdout + refused.stderr).lower()
        assert any(s in combined for s in (
            "host key verification failed",
            "remote host identification has changed",
            "known_hosts",
        )), (
            "exec failed after re-key, but not with a host-key verification error "
            f"— unexpected failure mode:\nrc={refused.rc}\n"
            f"stdout={refused.stdout}\nstderr={refused.stderr}"
        )
    finally:
        _purge_workload(target, WORKLOAD)
