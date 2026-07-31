"""Typed CLI wrapper for podman invocations.

Replaces ad-hoc subprocess.run(["podman", ..., "--format", "{{.X}}"]) calls
with typed methods that use --format json under the hood. The CLI subprocess
pattern is preserved; only parsing/typing changes.
"""

from __future__ import annotations

import json
import os
import pwd
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

# logind records enabled-linger as an (unprivileged-readable) empty file named
# for the user here. Presence == linger is on. Used to keep the read-path
# self-heal from ever *enabling* linger (see _ensure_runtime_dir).
_LINGER_DIR = Path("/var/lib/systemd/linger")


_NOT_FOUND_PHRASES = (
    "no such container",
    "no such image",
    "image not known",
    "image not found",
    "no such network",
    "unable to find",
)


class _Unset:
    """Sentinel: the drop-privs decision has not been made yet (None is an
    answer — 'use sudo' — so it can't double as 'not computed')."""


_UNSET = _Unset()


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
        self._privs: dict | None | _Unset = _UNSET

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
        """Talk to a workload user's rootless podman as that user.

        How it becomes them depends on who we already are: a root caller
        setuids in the child (see `_compute_drop_privs`), anyone else goes
        through `sudo -n -u`. Both land on the same identity and env.
        """
        return cls(
            username=username, uid=uid, home_dir=home_dir, timeout=timeout
        )

    # ---------------- internal -----------------

    def _identity_env(self) -> dict[str, str]:
        """The env every workload-user invocation needs, sudo or not."""
        return {
            "XDG_RUNTIME_DIR": f"/run/user/{self._uid}",
            "HOME": str(self._home_dir),
            # Point podman at the workload user's own session bus so it
            # drives cgroup placement through that user's systemd manager
            # (user@<uid>.service, which owns the delegated workloads.slice
            # subtree). Without it, rootless crun writes the container's
            # cgroup.procs directly; when the caller is in a foreign
            # session cgroup (e.g. an admin's login), the two cgroups' only
            # common ancestor is the root cgroup, which the unprivileged
            # workload user cannot write -> `podman exec` fails with
            # "write to .../cgroup.procs: Permission denied". The bulk of
            # calls (ps/inspect/pull) don't migrate cgroups and never hit
            # this, which is why only exec/shell surfaced it.
            "DBUS_SESSION_BUS_ADDRESS":
                f"unix:path=/run/user/{self._uid}/bus",
        }

    def _drop_privs_kwargs(self) -> dict | None:
        """Cached `_compute_drop_privs()` — one pwd/group lookup per instance.

        Cached rather than recomputed because `_build_cmd()` also consults it
        (to decide whether to prefix sudo at all), so a single podman call
        asks twice, and callers like the exporter make one instance per
        workload per tick.
        """
        if isinstance(self._privs, _Unset):
            self._privs = self._compute_drop_privs()
        return self._privs

    def _compute_drop_privs(self) -> dict | None:
        """subprocess kwargs that become the workload user *without* sudo.

        Returns None when sudo is still the right tool — i.e. whenever we are
        not already root, since then becoming another user is a privilege
        *escalation* and only sudo can grant it.

        Why this exists (Q6-X): sudo emits ~6 audit records per invocation
        (measured: 10 calls -> 60 lines in audit.log; the same loop through
        this path -> 0). `workload-exporter` runs one call per health-checked
        workload every 30s as root, which put three workloads at ~21,500
        audit records apiece at the top of a host's journal and drowned real
        failures — the reason a journal survey had to abandon ranking by
        frequency. Nothing about sudo was load-bearing here: the caller is
        already root, so this is a plain setuid, and PAM/logind do not create
        the runtime dir for a sudo -u call either (verified: with linger off
        and /run/user/<uid> absent, both paths fail with the identical
        `lstat /run/user/<uid>: no such file` that _ensure_runtime_dir
        already retries on).

        Groups are set explicitly. `user=` alone would leave the child
        carrying *root's* gid and supplementary groups; getgrouplist()
        reproduces what sudo's initgroups() would have set, which matters for
        workload users that hold `video`/`render` for GPU access.
        """
        if self._username is None or os.geteuid() != 0:
            return None
        try:
            pw = pwd.getpwnam(self._username)
            groups = os.getgrouplist(self._username, pw.pw_gid)
        except (KeyError, OSError):
            return None  # unknown user: let sudo produce the error
        return {
            "user": pw.pw_uid,
            "group": pw.pw_gid,
            "extra_groups": groups,
            "env": {
                **os.environ,
                **self._identity_env(),
                # sudo would have set these from the target passwd entry.
                "USER": self._username,
                "LOGNAME": self._username,
            },
        }

    def _build_cmd(self, *args: str) -> list[str]:
        cmd: list[str] = []
        if self._username is not None and self._drop_privs_kwargs() is None:
            env = self._identity_env()
            cmd += [
                "sudo", "-n",
                "-u", self._username,
                "-E", f"XDG_RUNTIME_DIR={env['XDG_RUNTIME_DIR']}",
                "-E", f"HOME={env['HOME']}",
                "-E", f"DBUS_SESSION_BUS_ADDRESS={env['DBUS_SESSION_BUS_ADDRESS']}",
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

        Gated on the user's linger already being enabled: this heals a runtime
        dir that logind GC'd out from under a *lingering* (enabled) workload —
        it must never *enable* linger. A read path (status/list) inspects every
        workload, disabled ones included, and their runtime dir is legitimately
        absent; enable-linger is a privileged polkit (set-user-linger) mutation
        that would otherwise prompt when the read runs unprivileged, or silently
        re-linger a workload the operator disabled when it runs as root.
        """
        if self._username is None:
            return
        if not (_LINGER_DIR / self._username).exists():
            return
        ensure_runtime_dir(self._uid, timeout=5.0)

    def _spawn(self, args: Iterable[str], **kwargs) -> subprocess.CompletedProcess:
        """The single place a podman child process is created.

        Falls back to sudo if the setuid spawn is refused — a caller running
        as root but without CAP_SETUID/CAP_SETGID (a unit with a narrowed
        CapabilityBoundingSet) can't become the workload user itself, and
        subprocess reports that as a PermissionError raised in the parent.
        The fallback is sticky so it costs one failed spawn per instance.
        """
        args = tuple(args)
        privs = self._drop_privs_kwargs()
        try:
            return subprocess.run(self._build_cmd(*args), **kwargs, **(privs or {}))
        except PermissionError:
            if privs is None:
                raise
            self._privs = None
            return subprocess.run(self._build_cmd(*args), **kwargs)

    def _run(
        self,
        *args: str,
        json_out: bool = False,
        allow_missing: bool = False,
        check: bool = True,
    ):
        def _exec() -> subprocess.CompletedProcess:
            return self._spawn(
                args,
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
        caller through the same user / XDG_RUNTIME_DIR / HOME identity as
        the typed methods (via `_spawn`), so it's a thin convenience, not
        a raw subprocess call. Boundary note (B13): a couple of call sites
        legitimately bypass even this — `provisioning.transfer_one_image`
        needs a `TMPDIR` override this class doesn't expose (podman load's
        temp files must land somewhere the target user can write), and the
        exporter builds a `Podman.for_user(...)` instance straight from a
        `pwd.getpwnam()` lookup because it has no `WorkloadConfig` to hand
        this class. Both are documented at their call sites rather than
        grown into this API, which isn't worth complicating for two sites.
        """
        return self._spawn(
            args,
            capture_output=capture_output, text=True, check=check,
            input=input, cwd=cwd,
        )
