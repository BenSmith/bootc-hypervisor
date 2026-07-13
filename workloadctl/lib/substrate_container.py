"""
substrate_container — the container substrate.

Implements the Substrate port for single / pod / bridge container workloads,
backed by one rootless podman instance per workload user.

Optional primitives implemented here: resource_usage, endpoints, reprovision.
``logs`` uses the base default (the service journal is the host journal).
"""

from __future__ import annotations

import datetime
import json
import subprocess
import sys
import time
from pathlib import Path

from backup import backup_impl, print_backup_size
from podman import PodmanError
from service_runtime import ensure_runtime_dir, restart_workload_service
from substrate import (
    LifecycleError,
    NotApplicable,
    ProvisionFailed,
    Substrate,
    podman_stat_row,
    rollback_tag,
    service_active,
)
from workload_lib import workload_service_units
from workloadctl_core import resolve_container_target


def _interactive_exec_flags() -> list[str]:
    """Interactivity flags for `podman exec`: always keep stdin open (-i), but
    only allocate a pseudo-TTY (-t) when stdin is a real terminal.

    Passing -t without a TTY hangs on piped input. Without -t, scripted /
    non-interactive callers use a plain no-pty exec path, which is robust.
    """
    return ["-i", "-t"] if sys.stdin.isatty() else ["-i"]


def _accessible_at_config(config) -> list:
    """Compute accessible host:port → container:port endpoint list from TOML ports.

    Returns a list of dicts with keys ``host`` (display string) and
    ``container`` (container port string or None for host-network workloads).
    """
    ports = config.get_ports()
    network_mode = config.get_network_mode()
    result: list[dict] = []
    if not ports:
        return result
    if network_mode == "host":
        for port_spec in ports:
            port = port_spec.split(":")[-1].split("/")[0]
            result.append({"host": f"localhost:{port}", "container": None})
    else:
        for port_spec in ports:
            parts = port_spec.split("/")[0].split(":")
            if len(parts) == 3:
                ip, host_port, container_port = parts
                host = ip or "localhost"
                host_disp = f"{host}:{host_port}" if host_port else f"{host}:(dynamic)"
                result.append({"host": host_disp, "container": container_port})
            elif len(parts) == 2:
                host_port, container_port = parts
                host_disp = f"localhost:{host_port}" if host_port else "localhost:(dynamic)"
                result.append({"host": host_disp, "container": container_port})
            else:
                result.append({"host": f"localhost:{parts[0]}", "container": None})
    return result


class ContainerSubstrate(Substrate):
    """Substrate for single / pod / bridge container workloads.

    Implements the optional primitives resource_usage, endpoints,
    reprovision (see the overrides below); logs uses the base default.
    """

    # ── required primitives ───────────────────────────────────────────────────

    def liveness(self) -> dict:
        active, state = service_active(self.config.service_name)
        service_state = state or "unknown"

        container_running = False
        container_status_str = None
        if active and self.manager.user_exists(self.config):
            podman = self.manager.podman(self.config)
            names = self.config.podman_targets()
            statuses = []
            for cname in names:
                status = podman.container_status(cname)
                statuses.append(status)
            # For multi-container workloads, "running" means every named
            # container is up — a partially-down pod is not healthy. For a
            # single container, this collapses to that one's status.
            container_running = bool(statuses) and all(statuses)
            # Surface the first running container's status string for display.
            container_status_str = next((s for s in statuses if s), None)

        healthy = active and container_running
        return {
            "service_active": active,
            "service_state": service_state,
            "container_running": container_running,
            "container_status": container_status_str,
            "healthy": healthy,
        }

    def container_liveness(self) -> list[dict]:
        """Per-container liveness rows in container_names() order.

        Each row: ``{container, podman_name, unit, service_active,
        service_state, status, running, healthy}``. Single-container workloads
        yield one row keyed on the main service and the bare container name;
        multi-container yield one row per member with its own
        ``workload-<name>-<ctr>.service`` unit. The running check needs the
        rootless podman store, so an absent workload user leaves every row
        not-running. This is the single source the per-container health and
        diagnose paths consume instead of re-deriving the name/unit math.
        """
        if self.config.is_multi:
            # Per-container .service names from the run-file model (container_names
            # order), so this never re-derives the workload-<name>-<ctr>.service
            # formula the generator owns.
            units = workload_service_units(self.config, roles={"container"})
            rows_meta = [
                (c, self.config.podman_container_name(c), unit)
                for c, unit in zip(self.config.container_names(), units)
            ]
        else:
            rows_meta = [
                (self.config.name, self.config.container_name,
                 self.config.service_name)
            ]

        podman = None
        if self.manager.user_exists(self.config):
            podman = self.manager.podman(self.config)

        rows = []
        for cname, podman_name, unit in rows_meta:
            active, state = service_active(unit)
            status = podman.container_status(podman_name) if podman else None
            running = bool(status)
            rows.append({
                "container": cname,
                "podman_name": podman_name,
                "unit": unit,
                "service_active": active,
                "service_state": state or "unknown",
                "status": status,
                "running": running,
                "healthy": active and running,
            })
        return rows

    def resource_usage(
        self,
        target_names: list[str],
        *,
        no_stream: bool = True,
        json_out: bool = False,
        follow: bool = False,
    ):
        podman = self.manager.podman(self.config)
        if json_out:
            result = podman.run(
                "stats", "--no-stream", "--format", "json",
                *target_names, capture_output=True,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return []
            raw = json.loads(result.stdout)
            return [
                podman_stat_row(row, self.config, target_names)
                for row in (raw if isinstance(raw, list) else [raw])
            ]
        elif follow:
            podman.run("stats", *target_names, check=True)
        else:
            podman.run("stats", "--no-stream", *target_names, check=True)
        return None

    def capture(
        self,
        output: Path,
        *,
        consistency: str = "cold",
        quiet: bool = False,
    ) -> int:
        """Create a backup archive.  Returns archive size in bytes.

        cold → stop service before copy; crash → copy while running (no stop).
        """
        no_stop = consistency == "crash"
        backup_impl(self.config, output, no_stop=no_stop, quiet=quiet, vm=False)
        size = output.stat().st_size
        if not quiet:
            print_backup_size(output, size)
        return size

    def gating_units(self) -> list[str]:
        return []

    def exec(
        self,
        argv: list[str],
        *,
        container: str | None = None,
    ) -> int:
        target = resolve_container_target(self.config, container, self.config.name)
        result = self.manager.run_podman_exec(
            self.config, [*_interactive_exec_flags(), target, *argv]
        )
        return result.returncode

    def open_shell(
        self,
        *,
        container: str | None = None,
        console: bool = False,
    ) -> None:
        if console:
            raise NotApplicable(
                "containers have no serial console; use 'shell' or 'exec' instead"
            )

        target = resolve_container_target(self.config, container, self.config.name)

        env = self.config.config.get("container", {}).get("environment", {})
        container_user = env.get("CONTAINER_USER")
        container_uid = env.get("CONTAINER_UID")

        exec_opts = _interactive_exec_flags()
        if container_user:
            uid = container_uid or "1000"
            home = f"/home/{container_user}"
            exec_opts.extend([
                "--user", container_user, "--workdir", home,
                "--env", f"HOME={home}",
                "--env", f"XDG_RUNTIME_DIR=/run/user/{uid}",
                "--env", f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
            ])
        elif container_uid:
            exec_opts.extend([
                "--user", container_uid,
                "--env", f"XDG_RUNTIME_DIR=/run/user/{container_uid}",
                "--env", f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{container_uid}/bus",
            ])

        print(f"Opening shell in {target}...")
        print()
        # Try bash first, fall back to sh only if bash isn't available in the image.
        # 127 = command not found; any other non-zero is propagated from the user's
        # last command (e.g. 130 after ^C), not a reason to relaunch.
        result = self.manager.run_podman_exec(self.config, [*exec_opts, target, "/bin/bash"])
        if result.returncode == 127:
            self.manager.run_podman_exec(self.config, [*exec_opts, target, "/bin/sh"], check=True)

    def lifecycle(self, action: str) -> None:
        """Unified lifecycle for containers: start / stop / restart / reboot."""
        if action == "start":
            # Re-pin /run/user/<uid> and tolerate runtime-dir / start-limit
            # thrash (a bare `systemctl start` doesn't re-run the setup oneshot,
            # so a GC'd runtime dir fails ExecStart with 226/NAMESPACE, and a
            # recycled unit name may carry a start-limit lockout).
            if self.manager.user_exists(self.config):
                try:
                    restart_workload_service(
                        self.config.uid, self.config.service_name, action="start"
                    )
                except subprocess.CalledProcessError as e:
                    raise LifecycleError(e.returncode or 1)
            else:
                result = subprocess.run(["systemctl", "start", self.config.service_name])
                if result.returncode != 0:
                    raise LifecycleError(result.returncode)
        elif action == "stop":
            result = subprocess.run(["systemctl", "stop", self.config.service_name])
            if result.returncode != 0:
                raise LifecycleError(result.returncode)
        elif action == "restart":
            # A bounce: the container is re-created from its existing overlay by
            # the unit's own ExecStartPre. Snapshotting a pet's overlay and
            # dropping the container is reprovision(recreate=True), not this.
            if self.manager.user_exists(self.config):
                try:
                    restart_workload_service(self.config.uid, self.config.service_name)
                except subprocess.CalledProcessError as e:
                    raise LifecycleError(e.returncode or 1)
            else:
                result = subprocess.run(["systemctl", "restart", self.config.service_name])
                if result.returncode != 0:
                    raise LifecycleError(result.returncode)
        elif action == "reboot":
            result = self.manager.run_podman_exec(
                self.config,
                [self.config.container_name, "systemctl", "soft-reboot"],
            )
            if result.returncode != 0:
                print("Error: soft-reboot failed. Is this a systemd container?", file=sys.stderr)
                raise LifecycleError(1)
            print(f"✓ Workload '{self.config.name}' soft-rebooted (overlay preserved)")
        else:
            raise ValueError(f"Unknown lifecycle action: {action!r}")

    def endpoints(self) -> list:
        """Return published port endpoints from the TOML declaration."""
        return _accessible_at_config(self.config)

    def _pet_snapshot_and_remove(self, pod, container_name: str) -> None:
        """Commit the pet container's overlay to a timestamped local snapshot,
        then remove the container so the next start rebuilds it from the image.

        The snapshot is saved under ``localhost/workload-snapshot/<name>`` with
        a UTC-timestamp tag so it is easy to identify and prune manually.
        A failure to commit (e.g. container not running / never started) is
        non-fatal — we log and continue so the destroy still proceeds.
        """
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        repo = f"localhost/workload-snapshot/{self.config.name}"
        snapshot_ref = f"{repo}:{ts}"
        committed = False
        try:
            pod.commit(container_name, snapshot_ref)
            committed = True
            print(f"  ✓ Pet snapshot saved: {snapshot_ref}")
        except Exception as exc:
            print(
                f"  ⚠ Pet snapshot failed (overlay may not exist yet): {exc}",
                file=sys.stderr,
            )
        # Bound the snapshot repository so deliberate rebuilds don't leak disk
        # forever (the VM path has rollback_keep; pets had no analog). Only
        # prune after a fresh commit succeeded — nothing new was added otherwise.
        if committed:
            self._prune_pet_snapshots(pod, repo, self.config.snapshot_keep)
        # Remove the container so the service's ExecStartPre=-podman create
        # runs fresh on next start, picking up the (possibly new) image.
        pod.run("rm", "-f", container_name)

    @staticmethod
    def _prune_pet_snapshots(pod, repo: str, keep: int) -> None:
        """Keep only the newest ``keep`` snapshots under ``repo``, remove the rest.

        Snapshot tags are UTC timestamps (``%Y%m%dT%H%M%SZ``) which sort
        lexicographically in chronological order, so the lexically largest tags
        are the most recent. Best-effort: every failure here is logged and
        swallowed so pruning can never block the destroy it follows.
        """
        try:
            listed = pod.run(
                "images", "--format", "{{.Tag}}", repo, capture_output=True,
            )
            if listed.returncode != 0:
                return
            tags = sorted(t for t in listed.stdout.split() if t)
            stale = tags[:-keep] if len(tags) > keep else []
            for tag in stale:
                ref = f"{repo}:{tag}"
                removed = pod.run("rmi", ref, capture_output=True)
                if removed.returncode == 0:
                    print(f"  ✓ Pruned old pet snapshot: {ref}")
        except Exception as exc:
            print(f"  ⚠ Pet snapshot prune skipped: {exc}", file=sys.stderr)

    def reprovision(self, *, force: bool = False, recreate: bool = False):
        if recreate:
            # recreate path: skip pull, just restart to recreate the overlay.
            print(f"Recreating {self.config.name}...")
            # pet honoring is single-mode only — the generator falls back to
            # cattle units for pod/bridge, so the substrate must too (otherwise
            # we'd commit/rm a container name that doesn't exist for multi).
            if (self.config.lifecycle == "pet" and not self.config.is_multi
                    and self.manager.user_exists(self.config)):
                # For pet: snapshot the overlay then remove the container so the
                # next start re-creates it from the image.
                pod = self.manager.podman(self.config)
                self._pet_snapshot_and_remove(pod, self.config.container_name)
            self._restart_or_fail()
            return None

        specs = self.config.container_specs()
        if all(pull == "never" for _, _, pull in specs):
            raise NotApplicable(
                f"{self.config.name} uses pull=never (local image) — build it manually"
            )

        print(f"Updating {self.config.name}...")

        if not self.manager.user_exists(self.config):
            print(f"  Skipping: user {self.config.username} does not exist (workload not enabled?)")
            return None

        pod = self.manager.podman(self.config)
        old_ids: dict[str, str] = {}
        changed = False

        for cname, image, pull in specs:
            old_id = pod.image_id(image)
            if not old_id:
                # A just-(re)started rootless store can transiently report an empty
                # inspect even though the image is present — re-pin and retry briefly
                # before giving up.
                ensure_runtime_dir(self.config.uid)
                for _ in range(10):
                    time.sleep(0.5)
                    old_id = pod.image_id(image)
                    if old_id:
                        break
            old_ids[cname] = old_id
            if pull == "never":
                continue
            try:
                pod.pull(image)
            except PodmanError as e:
                print(f"  ✗ Failed to pull {image}: {e.stderr}", file=sys.stderr)
                raise ProvisionFailed(f"pull failed for {image}")
            new_id = pod.image_id(image)
            if old_id != new_id:
                changed = True
                label = (
                    f"{self.config.name}/{cname}" if self.config.is_multi
                    else self.config.name
                )
                print(f"  {label}: {(old_id or 'none')[:12]} → {(new_id or 'unknown')[:12]}")

        if not changed and not force:
            print("  ✓ Already up to date")
            return None

        # Tag old images for rollback before restarting
        for cname, image, pull in specs:
            old_id = old_ids.get(cname)
            if old_id:
                pod.tag(
                    old_id,
                    rollback_tag(self.config.name, cname if self.config.is_multi else None),
                )

        if self.config.lifecycle == "pet" and not self.config.is_multi:
            # Snapshot and remove the pet container so the restart picks up the
            # new image (ExecStartPre=-podman create rebuilds from the new pull).
            # Single-mode only, matching the generator's pet fallback.
            self._pet_snapshot_and_remove(pod, self.config.container_name)

        self._restart_or_fail()
        print(f"  ✓ {self.config.name}: restarted")

        return (self.config, old_ids)

    def _restart_or_fail(self) -> None:
        """Restart the workload service, mapping a hard failure to ProvisionFailed.

        restart_workload_service() raises CalledProcessError once its retries are
        exhausted; a unit that won't come back up is an operator condition, so it
        has to reach the caller as ProvisionFailed rather than an unmapped
        exception that the CLI would report as a workloadctl bug.
        """
        try:
            if self.manager.user_exists(self.config):
                restart_workload_service(self.config.uid, self.config.service_name)
            else:
                subprocess.run(
                    ["systemctl", "restart", self.config.service_name], check=True
                )
        except subprocess.CalledProcessError:
            print(f"  ✗ Restart failed for {self.config.name}", file=sys.stderr)
            raise ProvisionFailed(f"restart failed for {self.config.name}")

    def rollback_targets(self) -> list:
        """Return available container rollback targets (saved image tags)."""
        pod = self.manager.podman(self.config)
        targets = []
        for cname, image in self.config.container_images():
            tag = rollback_tag(
                self.config.name, cname if self.config.is_multi else None
            )
            rollback_id = pod.image_id(tag)
            if not rollback_id:
                continue
            current_id = pod.image_id(image)
            label = (
                f"{self.config.name}/{cname}" if self.config.is_multi
                else self.config.name
            )
            targets.append({
                "label": label,
                "tag": tag,
                "image": image,
                "current_id": current_id,
                "rollback_id": rollback_id,
            })
        return targets

    def rollback_to(self, target: dict) -> None:
        """Apply a single rollback target from rollback_targets()."""
        pod = self.manager.podman(self.config)
        try:
            pod.tag(target["tag"], target["image"])
        except PodmanError as e:
            print(
                f"Error: Failed to retag rollback image for {target['label']}: {e.stderr}",
                file=sys.stderr,
            )
            raise LifecycleError(1)
        current_id = target.get("current_id")
        rollback_id = target["rollback_id"]
        print(
            f"  {target['label']}: {current_id[:12] if current_id else 'unknown'} → {rollback_id[:12]}"
        )

    def rollback(self) -> None:
        """Roll back all containers to their previous images and restart."""

        targets = self.rollback_targets()
        have_any_tag = bool(targets) or self._has_any_rollback_tag()

        if not have_any_tag:
            print(
                f"Error: No rollback image found for {self.config.name}",
                file=sys.stderr,
            )
            print(
                "  (rollback images are created automatically by 'workloadctl update')",
                file=sys.stderr,
            )
            raise LifecycleError(1)

        if not targets:
            print(f"Already running the rollback image(s) for {self.config.name}")
            return

        for target in targets:
            self.rollback_to(target)

        restart_workload_service(self.config.uid, self.config.service_name)
        print(f"✓ Rolled back {self.config.name}")

    def control(self, argv: list[str]) -> int:
        """Run ``podman <argv>`` as the workload user via the rootless wrapper."""
        result = self.manager.run_podman(self.config, *argv)
        return result.returncode

    def _has_any_rollback_tag(self) -> bool:
        """Return True if any rollback tag exists (even if already applied)."""
        pod = self.manager.podman(self.config)
        for cname, _image in self.config.container_images():
            tag = rollback_tag(
                self.config.name, cname if self.config.is_multi else None
            )
            if pod.image_id(tag):
                return True
        return False
