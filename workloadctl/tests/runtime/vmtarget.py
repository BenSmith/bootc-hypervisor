"""
vmtarget.py — a booted-VM execution target for the runtime rung.

VMTarget subclasses the cli_surface `Target` so every existing check runs
against it unchanged; it only differs in how SSH connects (an ssh port-forward
to a local QEMU guest, key auth, throwaway host key) and adds the
snapshot/revert/poweroff lifecycle the runtime harness needs to reset guest
state between check groups in ~1s instead of re-booting.

Stdlib only (see docs/wip/test-suite-improvement-plan.md dependency policy: the
launcher/lifecycle layer stays stdlib and reuses the lib QMPClient rather than
adding a second QMP implementation).
"""

import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

# Reuse the harness Target contract and the lib QMP client.
_HERE = Path(__file__).resolve().parent
_CLI_SURFACE = _HERE.parent / "cli_surface"
_LIB = _HERE.parent.parent / "lib"
for _p in (str(_CLI_SURFACE), str(_LIB)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from target import RunResult, Target  # noqa: E402
from workload_lib import QMPClient  # noqa: E402


class VMTarget(Target):
    """A `Target` backed by a locally-booted QEMU guest.

    The guest is reached over an ssh port-forward (`-p <port>`) with the
    ephemeral key the launcher generated; host-key checking is disabled because
    the guest identity is established by the launcher owning the boot, not by a
    known_hosts pin. snapshot/revert drive QEMU's monitor via the lib QMPClient.
    """

    def __init__(self, *, port, key_path, qmp_sock, pid_path, run_dir,
                 user="wlrt", host="127.0.0.1", swtpm_pid_path=None):
        super().__init__(dest=f"{user}@{host}")
        self._setup_mux()
        # SSH options injected into every master + session ssh invocation.
        self._ssh_opts = [
            "-p", str(port),
            "-i", str(key_path),
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "StrictHostKeyChecking=no",
            "-o", "LogLevel=ERROR",
        ]
        self._qmp_sock = str(qmp_sock)
        self._pid_path = str(pid_path)
        self._run_dir = str(run_dir)
        # Retained so a kept-alive VM (WLRT_KEEP_VM) can print a working
        # reconnect command for manual inspection.
        self.ssh_port = int(port)
        self.key_path = str(key_path)
        # gate mode only: the swtpm daemon backing the emulated TPM2, reaped
        # after QEMU exits.
        self._swtpm_pid_path = str(swtpm_pid_path) if swtpm_pid_path else None

    # ------------------------------------------------------------------
    # SSH plumbing (override to inject port/key; reconnect-tolerant master)
    # ------------------------------------------------------------------

    def _ensure_master(self):
        """(Re)establish the ControlMaster, tolerating a dead master.

        Unlike the base Target — which starts the master exactly once — this
        restarts it whenever it has died. That makes the same code path handle
        both the boot-time race (sshd not up yet) and the post-revert desync
        (loadvm restores the guest to before the TCP handshake), so callers can
        just retry `run(["true"])` until it succeeds.
        """
        with self._lock:
            alive = (
                self._master_proc is not None
                and self._master_proc.poll() is None
            )
            if self._started and alive:
                return
            if not self._ctl_dir:
                self._setup_mux()
            # A stale control socket from a dead master blocks a new master.
            try:
                if self._ctl_path and os.path.exists(self._ctl_path):
                    os.unlink(self._ctl_path)
            except OSError:
                pass
            self._master_proc = subprocess.Popen(
                [
                    "ssh",
                    "-o", "ControlMaster=yes",
                    "-o", f"ControlPath={self._ctl_path}",
                    "-o", "ControlPersist=600",
                    *self._ssh_opts,
                    "-o", "BatchMode=yes",
                    "-o", "ConnectTimeout=15",
                    "-N",
                    self.dest,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._started = True

    def run(self, cmd, *, sudo=False, check=True, input=None, timeout=300,
            env=None) -> RunResult:
        """Run a command in the guest over the multiplexed ssh connection.

        VMTarget is always remote (no `local` branch), so this mirrors the base
        remote path with the port/key ssh options injected."""
        cmd_list = list(cmd) if isinstance(cmd, list) else shlex.split(cmd)
        if sudo:
            cmd_list = ["sudo", "-n"] + cmd_list

        self._ensure_master()
        ssh_base = [
            "ssh",
            "-o", f"ControlPath={self._ctl_path}",
            "-o", "ControlMaster=no",
            *self._ssh_opts,
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=15",
            self.dest,
        ]
        remote_cmd = " ".join(shlex.quote(str(a)) for a in cmd_list)
        result = subprocess.run(
            ssh_base + [remote_cmd],
            capture_output=True, text=True, input=input, timeout=timeout,
        )
        r = RunResult(rc=result.returncode, stdout=result.stdout,
                      stderr=result.stderr)
        if check and r.rc != 0:
            raise AssertionError(
                f"Command failed (rc={r.rc}):\n"
                f"  cmd: {' '.join(str(x) for x in cmd_list)}\n"
                f"  stdout: {r.stdout[:2000]}\n"
                f"  stderr: {r.stderr[:2000]}"
            )
        return r

    # ------------------------------------------------------------------
    # Readiness
    # ------------------------------------------------------------------

    def connect_hint(self) -> str:
        """A standalone ssh command that reaches this guest (for WLRT_KEEP_VM)."""
        return (
            f"ssh -p {self.ssh_port} -i {self.key_path} "
            f"-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "
            f"{self.dest}"
        )

    def wait_ready(self, timeout: float = 240.0):
        """Block until the guest answers ssh, retrying the master as needed."""
        deadline = time.monotonic() + timeout
        while True:
            r = self.run(["true"], sudo=False, check=False, timeout=20)
            if r.rc == 0:
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"guest did not become SSH-ready within {timeout:.0f}s"
                )
            time.sleep(2)

    # ------------------------------------------------------------------
    # Snapshot / revert (QMP HMP savevm/loadvm)
    # ------------------------------------------------------------------

    def _hmp(self, command_line: str) -> str:
        """Issue one HMP command over QMP; raise on a non-empty (error) reply.

        savevm/loadvm return an empty string on success and an error message
        otherwise (human-monitor-command yields unstructured text). vCPUs pause
        for ~1–3s during the operation, so allow a generous recv timeout."""
        with QMPClient() as q:
            q.connect(self._qmp_sock, timeout=15.0, recv_timeout=60.0)
            q.negotiate()
            reply = q.execute("human-monitor-command",
                              {"command-line": command_line})
        if "error" in reply:
            raise RuntimeError(f"QMP error for {command_line!r}: {reply['error']}")
        out = reply.get("return", "")
        if isinstance(out, str) and out.strip():
            raise RuntimeError(f"HMP {command_line!r} failed: {out.strip()}")
        return out or ""

    def snapshot(self, tag: str = "base") -> None:
        self._hmp(f"savevm {tag}")

    def revert(self, tag: str = "base") -> None:
        """Restore the guest to `tag` and reconnect ssh before returning.

        loadvm rewinds the guest to the snapshot instant, desynchronising the
        host-side TCP/ssh state. Tear the ssh master down, then block until the
        guest answers again so no check ever observes a half-reverted target."""
        self._hmp(f"loadvm {tag}")
        self.close()          # drop the now-stale ssh master + control dir
        self._setup_mux()     # fresh control path for the reconnect
        self._started = False
        self.wait_ready(timeout=120.0)

    # ------------------------------------------------------------------
    # Teardown
    # ------------------------------------------------------------------

    def poweroff(self) -> None:
        """Terminate the guest and clean up the run directory."""
        try:
            with QMPClient() as q:
                q.connect(self._qmp_sock, timeout=5.0)
                q.negotiate()
                q.execute("quit")   # terminates QEMU immediately and cleanly
        except Exception:
            # Fall back to SIGTERM on the pidfile if the monitor is unreachable.
            try:
                pid = int(Path(self._pid_path).read_text().strip())
                os.kill(pid, signal.SIGTERM)
            except (OSError, ValueError):
                pass
        # Reap the swtpm daemon (gate mode) — it does not exit with QEMU.
        if self._swtpm_pid_path:
            try:
                os.kill(int(Path(self._swtpm_pid_path).read_text().strip()),
                        signal.SIGTERM)
            except (OSError, ValueError):
                pass
        self.close()
        if self._run_dir:
            shutil.rmtree(self._run_dir, ignore_errors=True)
