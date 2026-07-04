"""Typed CLI wrapper for podman invocations.

Replaces ad-hoc subprocess.run(["podman", ..., "--format", "{{.X}}"]) calls
with typed methods that use --format json under the hood. The CLI subprocess
pattern is preserved; only parsing/typing changes.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Iterable

from service_runtime import ensure_runtime_dir


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
        self.cmd_args = tuple(args)
        joined = " ".join(self.cmd_args)
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
        """Best-effort: make linger genuinely effective and wait for it.

        Called when a podman invocation fails with the runtime-dir-missing
        signature. Delegates to the shared `service_runtime.ensure_runtime_dir`
        — the same enable-linger + start `user@<uid>.service` + poll-on-
        manager-active logic used by the CLI restart paths. Uses a 5s deadline
        (the read path retries once and should fail fast) vs. the restart
        path's default 8s. Swallows all errors — if it can't fix it, the
        subsequent retry falls through to normal error handling.
        """
        ensure_runtime_dir(self._uid, timeout=5.0)

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

    def container_healths(self, names: Iterable[str]) -> dict[str, str | None]:
        """Health status per container, via ONE inspect for all names.

        Containers that don't exist are absent from the result; podman exits
        nonzero on a partial batch but still prints the found subset, so we
        parse stdout ourselves instead of going through json_out/check.
        """
        names = list(names)
        if not names:
            return {}
        proc = self._run(
            "inspect", "--type=container", "--format=json", *names, check=False)
        try:
            infos = json.loads(proc.stdout) or []
        except (json.JSONDecodeError, TypeError):
            return {}
        result: dict[str, str | None] = {}
        for info in infos:
            cname = (info.get("Name") or "").lstrip("/")
            health = (info.get("State") or {}).get("Health") or {}
            result[cname] = health.get("Status") or None
        return result

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

    def commit(self, container: str, image_ref: str) -> None:
        """Commit a container's writable layer to a local image snapshot."""
        self._run("commit", container, image_ref)

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
        """Run an arbitrary podman command (e.g. exec, stats, cp, attach).

        This is the deliberate escape hatch for verbs that don't warrant a
        typed structured-read/write method above. It still carries every
        caller through the same sudo -u / XDG_RUNTIME_DIR / HOME identity as
        the typed methods (via `_build_cmd`), so it's a thin convenience, not
        a raw subprocess call. Boundary note (B13): a couple of call sites
        legitimately bypass even this — `cmd_lifecycle._transfer_one_image`
        needs a `TMPDIR` override this class doesn't expose (podman load's
        temp files must land somewhere the target user can write), and the
        exporter builds a `Podman.for_user(...)` instance straight from a
        `pwd.getpwnam()` lookup because it has no `WorkloadConfig` to hand
        this class. Both are documented at their call sites rather than
        grown into this API, which isn't worth complicating for two sites.
        """
        return subprocess.run(
            self._build_cmd(*args),
            capture_output=capture_output, text=True, check=check,
            input=input, cwd=cwd,
        )
