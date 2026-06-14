"""Typed CLI wrapper for podman invocations.

Replaces ad-hoc subprocess.run(["podman", ..., "--format", "{{.X}}"]) calls
with typed methods that use --format json under the hood. The CLI subprocess
pattern is preserved; only parsing/typing changes.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Iterable


# Matches logind GC'ing /run/user/<uid> out from under a live workload.
# Pattern: lstat /run/user/<digits>: no such file
_RUNTIME_DIR_MISSING_RE = re.compile(
    r"lstat\s+/run/user/(\d+):\s+no such file",
    re.IGNORECASE,
)


_NOT_FOUND_PHRASES = (
    "no such container",
    "no such image",
    "image not known",
    "image not found",
    "no such network",
    "unable to find",
)


class PodmanError(Exception):
    def __init__(self, returncode: int, stderr: str, args: Iterable[str]):
        self.returncode = returncode
        self.stderr = stderr
        self.args = tuple(args)
        joined = " ".join(self.args)
        super().__init__(
            f"podman {joined} failed ({returncode}): {stderr.strip()}"
        )


def _is_not_found(stderr: str) -> bool:
    s = stderr.lower()
    return any(p in s for p in _NOT_FOUND_PHRASES)


class Podman:
    """Typed wrapper around the `podman` CLI for one user (or root)."""

    def __init__(
        self,
        username: str | None,
        uid: int,
        home_dir: str | Path | None,
        timeout: float | None = None,
    ):
        self._username = username
        self._uid = uid
        self._home_dir = str(home_dir) if home_dir is not None else None
        self._timeout = timeout

    @classmethod
    def for_root(cls, timeout: float | None = None) -> "Podman":
        """Talk to the system (root) podman store. No sudo prefix."""
        return cls(username=None, uid=0, home_dir=None, timeout=timeout)

    @classmethod
    def for_user(
        cls,
        username: str,
        uid: int,
        home_dir: str | Path,
        timeout: float | None = None,
    ) -> "Podman":
        """Talk to a workload user's rootless podman via sudo -n -u."""
        return cls(
            username=username, uid=uid, home_dir=home_dir, timeout=timeout
        )

    # ---------------- internal -----------------

    def _build_cmd(self, *args: str) -> list[str]:
        cmd: list[str] = []
        if self._username is not None:
            cmd += [
                "sudo", "-n",
                "-u", self._username,
                "-E", f"XDG_RUNTIME_DIR=/run/user/{self._uid}",
                "-E", f"HOME={self._home_dir}",
            ]
        cmd += ["podman", "--log-level=error", *args]
        return cmd

    def _ensure_runtime_dir(self) -> None:
        """Best-effort: re-assert linger and wait for /run/user/<uid> to appear.

        Called when a podman invocation fails with the runtime-dir-missing
        signature.  Swallows all exceptions — if we can't fix it, the
        subsequent retry will fail and fall through to normal error handling.
        """
        try:
            subprocess.run(
                ["loginctl", "enable-linger", str(self._uid)],
                capture_output=True,
                timeout=5,
            )
        except Exception:
            pass

        runtime_dir = f"/run/user/{self._uid}"
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if os.path.isdir(runtime_dir):
                return
            time.sleep(0.1)

    def _run(
        self,
        *args: str,
        json_out: bool = False,
        allow_missing: bool = False,
        check: bool = True,
    ):
        def _exec() -> subprocess.CompletedProcess:
            return subprocess.run(
                self._build_cmd(*args),
                capture_output=True, text=True, cwd="/tmp",
                timeout=self._timeout,
            )

        proc = _exec()

        # Part B: self-healing retry on runtime-dir-missing (user podman only).
        if (
            proc.returncode != 0
            and self._username is not None
            and not (allow_missing and _is_not_found(proc.stderr))
        ):
            m = _RUNTIME_DIR_MISSING_RE.search(proc.stderr)
            if m and m.group(1) == str(self._uid):
                self._ensure_runtime_dir()
                proc = _exec()  # exactly one retry

        if proc.returncode != 0:
            if allow_missing and _is_not_found(proc.stderr):
                return None
            if check:
                raise PodmanError(proc.returncode, proc.stderr, args)
            return proc
        if json_out:
            text = proc.stdout.strip()
            if not text or text == "null":
                return None
            return json.loads(proc.stdout)
        return proc

    # ---------------- structured reads -----------------

    def image_id(self, ref: str) -> str:
        """Return image ID, or '' if not found in this store."""
        out = self._run(
            "inspect", "--type=image", "--format=json", ref,
            json_out=True, allow_missing=True,
        )
        if not out:
            return ""
        return out[0].get("Id", "")

    def image_info(self, ref: str) -> dict | None:
        """Full inspect dict for an image, or None if not found."""
        out = self._run(
            "inspect", "--type=image", "--format=json", ref,
            json_out=True, allow_missing=True,
        )
        return out[0] if out else None

    def container_inspect(self, name: str) -> dict | None:
        """Full inspect dict for a container, or None if not found."""
        out = self._run(
            "inspect", "--type=container", "--format=json", name,
            json_out=True, allow_missing=True,
        )
        return out[0] if out else None

    def container_health(self, name: str) -> str | None:
        """Container health status, or None if no healthcheck / not found."""
        info = self.container_inspect(name)
        if info is None:
            return None
        state = info.get("State") or {}
        health = state.get("Health") or {}
        status = health.get("Status")
        return status or None

    def container_status(self, name: str) -> str | None:
        """Container status string, or None if not running / not found."""
        rows = self.list_containers(filters={"name": name})
        for c in rows:
            names = c.get("Names") or []
            if name in names:
                return c.get("Status")
        return None

    def container_exists(self, name: str) -> bool:
        return self.container_inspect(name) is not None

    def list_containers(
        self,
        *,
        all: bool = True,
        filters: dict[str, str] | None = None,
    ) -> list[dict]:
        """List containers (all by default). Each entry is the raw `ps` JSON."""
        args = ["ps", "--format=json"]
        if all:
            args.append("--all")
        if filters:
            for k, v in filters.items():
                args += ["--filter", f"{k}={v}"]
        out = self._run(*args, json_out=True)
        return out or []

    def network_exists(self, name: str) -> bool:
        proc = self._run("network", "exists", name, check=False)
        return proc.returncode == 0

    # ---------------- mutators (raise on failure) -----------------

    def tag(self, src: str, dst: str) -> None:
        self._run("tag", src, dst)

    def pull(self, ref: str) -> None:
        self._run("pull", ref)

    def network_create(self, name: str) -> None:
        self._run("network", "create", name)

    # ---------------- escape hatch -----------------

    def run(
        self,
        *args: str,
        capture_output: bool = False,
        check: bool = False,
        input: str | bytes | None = None,
        cwd: str = "/tmp",
    ) -> subprocess.CompletedProcess:
        """Run an arbitrary podman command (e.g. exec, stats, cp, attach)."""
        return subprocess.run(
            self._build_cmd(*args),
            capture_output=capture_output, text=True, check=check,
            input=input, cwd=cwd,
        )
