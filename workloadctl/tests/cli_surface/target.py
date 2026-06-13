"""
target.py — SSH-backed (or local) execution target for the CLI-surface harness.

The Target object wraps every command that runs on the system under test.
It uses SSH ControlMaster/ControlPersist so the suite's hundreds of small
SSH calls share one authenticated connection (critical for performance).

Usage:
    target = Target.from_dest("user@host")
    result = target.run("workloadctl list")
    target.put("/local/path", "/remote/path")
"""

import os
import shlex
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RunResult:
    rc: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.rc == 0

    def check(self, cmd: str = ""):
        if self.rc != 0:
            raise subprocess.CalledProcessError(
                self.rc, cmd,
                output=self.stdout,
                stderr=self.stderr,
            )
        return self


@dataclass
class Target:
    """Abstraction over local or remote execution."""

    dest: str  # e.g. "user@host" or "local"

    # SSH multiplexing state (remote only)
    _ctl_dir: str = field(default="", repr=False)
    _ctl_path: str = field(default="", repr=False)
    _master_proc: object = field(default=None, repr=False)
    _lock: object = field(default_factory=threading.Lock, repr=False)
    _started: bool = field(default=False, repr=False)

    # Capability cache
    _caps: dict | None = field(default=None, repr=False)

    @classmethod
    def from_dest(cls, dest: str) -> "Target":
        t = cls(dest=dest)
        if dest != "local":
            t._setup_mux()
        return t

    # ------------------------------------------------------------------
    # SSH multiplexing
    # ------------------------------------------------------------------

    def _setup_mux(self):
        """Create the ControlMaster socket directory and launch the master."""
        self._ctl_dir = tempfile.mkdtemp(prefix="wlctl-ssh-mux-")
        self._ctl_path = os.path.join(self._ctl_dir, "ctl")

    def _ensure_master(self):
        """Lazily start the SSH master process on first use."""
        with self._lock:
            if self._started:
                return
            self._started = True
            proc = subprocess.Popen(
                [
                    "ssh",
                    "-o", "ControlMaster=yes",
                    "-o", f"ControlPath={self._ctl_path}",
                    "-o", "ControlPersist=600",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "BatchMode=yes",
                    "-o", "ConnectTimeout=15",
                    "-N",  # no command — just hold the master open
                    self.dest,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._master_proc = proc

    def close(self):
        """Tear down the SSH master connection."""
        if self._master_proc is not None:
            try:
                subprocess.run(
                    ["ssh", "-o", f"ControlPath={self._ctl_path}",
                     "-O", "exit", self.dest],
                    capture_output=True, timeout=5,
                )
            except Exception:
                pass
            try:
                self._master_proc.wait(timeout=5)
            except Exception:
                self._master_proc.kill()
            self._master_proc = None
        if self._ctl_dir and os.path.isdir(self._ctl_dir):
            shutil.rmtree(self._ctl_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # Core run
    # ------------------------------------------------------------------

    def run(
        self,
        cmd: str | list,
        *,
        sudo: bool = False,
        check: bool = True,
        input: str | None = None,
        timeout: int = 300,
        env: dict | None = None,
    ) -> RunResult:
        """Run a command on the target.  Returns RunResult."""

        # Build the command string / list
        if isinstance(cmd, list):
            cmd_list = cmd
        else:
            cmd_list = shlex.split(cmd)

        if sudo:
            cmd_list = ["sudo", "-n"] + cmd_list

        if self.dest == "local":
            result = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                input=input,
                timeout=timeout,
                env={**os.environ, **(env or {})},
            )
        else:
            self._ensure_master()
            ssh_base = [
                "ssh",
                "-o", f"ControlPath={self._ctl_path}",
                "-o", "ControlMaster=no",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=15",
                self.dest,
            ]
            # Join the remote command with proper quoting
            remote_cmd = " ".join(shlex.quote(str(a)) for a in cmd_list)
            full_cmd = ssh_base + [remote_cmd]
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                input=input,
                timeout=timeout,
            )

        r = RunResult(rc=result.returncode, stdout=result.stdout, stderr=result.stderr)
        if check and r.rc != 0:
            raise AssertionError(
                f"Command failed (rc={r.rc}):\n"
                f"  cmd: {' '.join(str(x) for x in cmd_list)}\n"
                f"  stdout: {r.stdout[:2000]}\n"
                f"  stderr: {r.stderr[:2000]}"
            )
        return r

    def wl(self, args: str | list, *, sudo: bool = True, check: bool = True,
            input: str | None = None, timeout: int = 300) -> RunResult:
        """Convenience: run `workloadctl <args>` with sudo by default."""
        if isinstance(args, list):
            cmd = ["workloadctl"] + args
        else:
            cmd = "workloadctl " + args
        return self.run(cmd, sudo=sudo, check=check, input=input, timeout=timeout)

    def wl_exec(self, workload_ref: str, command: str | list, *,
                sudo: bool = True, check: bool = True,
                input: str | None = None, timeout: int = 300) -> RunResult:
        """Run `workloadctl exec <workload> -- <command...>`.

        workloadctl's exec is workload-first (`exec <workload> [--] <command>`),
        matching docker/podman/kubectl. The explicit `--` keeps leading-dash
        command flags from being parsed as workloadctl options.
        """
        if isinstance(command, str):
            command = shlex.split(command)
        cmd = ["workloadctl", "exec", workload_ref, "--", *command]
        return self.run(cmd, sudo=sudo, check=check, input=input, timeout=timeout)

    # ------------------------------------------------------------------
    # File transfer
    # ------------------------------------------------------------------

    def put(self, local_path: str | Path, remote_path: str):
        """Copy a local file to the target (as root via tee+sudo)."""
        local_path = Path(local_path)
        content = local_path.read_bytes()
        # Use sudo tee to write as root
        self.run(
            ["sudo", "tee", remote_path],
            sudo=False,  # already have sudo in the command
            input=content.decode(errors="replace"),
            check=True,
        )

    def put_content(self, content: str, remote_path: str):
        """Write string content to a remote path as root."""
        self.run(
            ["sudo", "tee", remote_path],
            sudo=False,
            input=content,
            check=True,
        )

    def read(self, remote_path: str) -> str:
        """Read a remote file's content."""
        r = self.run(["cat", remote_path], sudo=True, check=True)
        return r.stdout

    def remote_path_exists(self, remote_path: str) -> bool:
        """Check whether a path exists on the remote."""
        r = self.run(["test", "-e", remote_path], sudo=True, check=False)
        return r.rc == 0

    # ------------------------------------------------------------------
    # Capability detection
    # ------------------------------------------------------------------

    @property
    def capabilities(self) -> dict:
        if self._caps is None:
            self._caps = self._detect_capabilities()
        return self._caps

    def _detect_capabilities(self) -> dict:
        caps = {}
        caps["has_kvm"] = self.run(["test", "-e", "/dev/kvm"], sudo=False, check=False).rc == 0
        caps["has_tpm2"] = self.run(["test", "-e", "/dev/tpmrm0"], sudo=False, check=False).rc == 0

        # Check for br0 bridge
        r = self.run(["ip", "link", "show", "br0"], sudo=False, check=False)
        caps["has_br0"] = r.rc == 0

        # Systemd version
        r = self.run(["systemctl", "--version"], sudo=False, check=False)
        caps["systemd_version_raw"] = r.stdout.strip().splitlines()[0] if r.ok else "unknown"

        # Podman version
        r = self.run(["podman", "--version"], sudo=False, check=False)
        caps["podman_version_raw"] = r.stdout.strip() if r.ok else "unknown"

        # workloadctl installed
        r = self.run(["which", "workloadctl"], sudo=False, check=False)
        caps["has_workloadctl"] = r.rc == 0

        return caps

    def __repr__(self):
        return f"Target(dest={self.dest!r})"
