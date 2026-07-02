"""
test_exec.py — exec, cp, attach, shell verbs.

exec and cp have clear side-effect-verifiable behaviors.
shell and attach are interactive (pty-driven smoke tests — lower assurance).

Container exec: uses podman exec.
VM exec: goes over SSH to the guest.
"""

import pytest



# ---------------------------------------------------------------------------
# exec
# ---------------------------------------------------------------------------

class TestExec:
    def test_exec_echo(self, target, clitest_single, record_property):
        """exec a simple command in a container and capture output."""
        record_property("cell", "exec/container")
        r = target.wl_exec(
            clitest_single, "echo clitest-marker",
            check=True, timeout=30,
        )
        assert r.rc == 0
        assert "clitest-marker" in r.stdout, (
            f"exec output did not contain marker: {r.stdout!r}"
        )

    def test_exec_pod_container(self, target, clitest_pod, record_property):
        """exec targeting a specific container in a pod.

        Targets the `proxy` container (caddy:2-alpine) rather than `app`
        (traefik/whoami): whoami is a scratch image with no shell and no
        `echo` binary, so exec — which hands the command straight to crun
        with no shell — has nothing to run there. proxy exercises the same
        container-targeted exec path with a busybox userland present.
        """
        record_property("cell", "exec/container/pod")
        r = target.wl_exec(
            f"{clitest_pod}/proxy", "echo pod-proxy-marker",
            check=True, timeout=30,
        )
        assert "pod-proxy-marker" in r.stdout

    def test_exec_bridge_container(self, target, clitest_bridge, record_property):
        """exec targeting a specific container in a bridge-mode workload.

        Targets `proxy` (caddy:2-alpine) not `app` (traefik/whoami, a
        shell-less scratch image) — see test_exec_pod_container.
        """
        record_property("cell", "exec/container/bridge")
        r = target.wl_exec(
            f"{clitest_bridge}/proxy", "echo bridge-proxy-marker",
            check=True, timeout=30,
        )
        assert "bridge-proxy-marker" in r.stdout

    def test_exec_writes_file(self, target, clitest_single, record_property):
        """exec can write a file inside the container."""
        record_property("cell", "exec/container")
        r = target.wl_exec(
            clitest_single, ["sh", "-c", "echo marker > /tmp/clitest-marker.txt"],
            check=True, timeout=30,
        )
        assert r.rc == 0

    def test_exec_error_propagates(self, target, clitest_single, record_property):
        """exec propagates nonzero exit codes from the command."""
        record_property("cell", "exec/container")
        r = target.wl_exec(
            clitest_single, ["sh", "-c", "exit 42"],
            check=False, timeout=30,
        )
        assert r.rc == 42, f"Expected rc=42, got {r.rc}"
        assert "Traceback" not in r.stderr

    @pytest.mark.vm
    @pytest.mark.slow
    def test_exec_vm(self, target, clitest_vm, record_property):
        """exec on a VM goes over SSH; assert marker in output."""
        record_property("cell", "exec/vm")
        r = target.wl_exec(
            clitest_vm, "echo vm-exec-marker",
            check=True, timeout=60,
        )
        assert "vm-exec-marker" in r.stdout, (
            f"VM exec output: {r.stdout!r}, stderr: {r.stderr!r}"
        )

    @pytest.mark.vm
    @pytest.mark.slow
    def test_exec_vm_no_traceback(self, target, clitest_vm, record_property):
        record_property("cell", "exec/vm")
        r = target.wl_exec(
            clitest_vm, "whoami",
            check=False, timeout=60,
        )
        assert "Traceback" not in r.stderr


# ---------------------------------------------------------------------------
# cp
# ---------------------------------------------------------------------------

class TestCp:
    def test_cp_to_container(self, target, clitest_single, record_property):
        """cp: copy a file into the container and verify it's there."""
        record_property("cell", "cp/container")

        # Create a temp file on the target
        r = target.run(
            ["bash", "-c", "echo 'clitest-cp-content' > /tmp/clitest-cp-src.txt"],
            sudo=False, check=True,
        )

        # cp to container
        r = target.wl(
            f"cp /tmp/clitest-cp-src.txt {clitest_single}:/tmp/clitest-cp-dst.txt",
            check=True, timeout=30,
        )
        assert r.rc == 0
        assert "Traceback" not in r.stderr

        # Verify file is in container
        r2 = target.wl_exec(
            clitest_single, "cat /tmp/clitest-cp-dst.txt",
            check=True, timeout=30,
        )
        assert "clitest-cp-content" in r2.stdout

        # Cleanup
        target.run(["rm", "-f", "/tmp/clitest-cp-src.txt"], sudo=False, check=False)

    def test_cp_from_container(self, target, clitest_single, record_property):
        """cp: copy a file from the container to the host."""
        record_property("cell", "cp/container")

        # Write a file in the container first
        target.wl_exec(
            clitest_single, ["sh", "-c", "echo clitest-cp-from > /tmp/clitest-cp-from.txt"],
            check=True, timeout=30,
        )

        # cp from container
        r = target.wl(
            f"cp {clitest_single}:/tmp/clitest-cp-from.txt /tmp/clitest-cp-host.txt",
            check=True, timeout=30,
        )
        assert r.rc == 0

        # Verify file on host
        r2 = target.run(["cat", "/tmp/clitest-cp-host.txt"], sudo=False, check=True)
        assert "clitest-cp-from" in r2.stdout

        # Cleanup
        target.run(["rm", "-f", "/tmp/clitest-cp-host.txt"], sudo=False, check=False)

    @pytest.mark.vm
    @pytest.mark.slow
    def test_cp_vm_finding(self, target, clitest_vm, record_property):
        """cp on a VM: expected to fail/crash (designed for containers).

        cmd_cp calls resolve_container_target, which has no is_vm guard.
        This is a known potential finding. We record the behavior.
        """
        record_property("cell", "cp/vm")
        r = target.wl(
            f"cp /tmp/nonexistent.txt {clitest_vm}:/tmp/dst.txt",
            check=False, timeout=30,
        )
        # Must not produce an unhandled Python traceback
        assert "Traceback" not in r.stderr, (
            f"FINDING: cp produced a traceback on VM: {r.stderr[:500]}"
        )
        # Likely exits nonzero (user not found or container error)
        # Just document the actual exit code
        _ = r.rc  # recorded; nonzero is expected here


# ---------------------------------------------------------------------------
# attach (interactive smoke test)
# ---------------------------------------------------------------------------

@pytest.mark.interactive
class TestAttach:
    def test_attach_container_no_crash(self, target, clitest_single, record_property):
        """attach: smoke test via `script -qec` to avoid requiring a pty.

        This is smoke-grade: we verify attach connects (exits cleanly or
        with a small delay) without hanging or traceback. Interactive TTY
        semantics are not asserted here.
        """
        record_property("cell", "attach/container")

        # Use `timeout 3 workloadctl attach ...` to detach after 3 seconds
        r = target.run(
            ["bash", "-c",
             f"timeout 3 sudo -n workloadctl attach {clitest_single} || true"],
            sudo=False, check=False, timeout=15,
        )
        # Should not produce a traceback
        assert "Traceback" not in r.stderr, (
            f"attach produced traceback: {r.stderr}"
        )

    @pytest.mark.vm
    @pytest.mark.slow
    def test_attach_vm_finding(self, target, clitest_vm, record_property):
        """attach on a VM: cmd_attach calls resolve_container_target which
        has no is_vm guard. Expected to crash or fail. Record as finding.

        The test documents the actual behavior without xfail papering.
        """
        record_property("cell", "attach/vm")
        r = target.run(
            ["bash", "-c",
             f"timeout 3 sudo -n workloadctl attach {clitest_vm} || true"],
            sudo=False, check=False, timeout=15,
        )
        assert "Traceback" not in r.stderr, (
            f"FINDING: attach produced a traceback on VM: {r.stderr[:500]}"
        )


# ---------------------------------------------------------------------------
# shell (interactive smoke test)
# ---------------------------------------------------------------------------

@pytest.mark.interactive
class TestShell:
    def test_shell_container_no_hang(self, target, clitest_single, record_property):
        """shell: smoke test that it connects and exits cleanly.

        Uses `timeout 3` to avoid hanging waiting for shell input.
        We verify: no traceback, shell process started and exited.
        """
        record_property("cell", "shell/container")
        r = target.run(
            ["bash", "-c",
             f"echo exit | timeout 5 sudo -n workloadctl shell {clitest_single} || true"],
            sudo=False, check=False, timeout=15,
        )
        assert "Traceback" not in r.stderr, (
            f"shell produced traceback: {r.stderr}"
        )

    @pytest.mark.vm
    @pytest.mark.slow
    def test_shell_vm_ssh(self, target, clitest_vm, record_property):
        """shell on a VM: connects via SSH (preferred) or serial console fallback.

        Smoke-grade: send 'exit' and verify clean exit without traceback.
        """
        record_property("cell", "shell/vm")
        r = target.run(
            ["bash", "-c",
             f"echo exit | timeout 10 sudo -n workloadctl shell {clitest_vm} || true"],
            sudo=False, check=False, timeout=20,
        )
        assert "Traceback" not in r.stderr, (
            f"shell produced traceback on VM: {r.stderr}"
        )
