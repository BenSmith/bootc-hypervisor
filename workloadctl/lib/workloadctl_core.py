"""
workloadctl_core — shared types, helpers, and manager used by all cmd modules.

Import chain:
    workload_lib, podman  (no changes)
        ↑
    workloadctl_core      (this file)
        ↑
    cmd_*.py modules
        ↑
    bin/workloadctl       (thin entry point)
"""

import datetime
import os
from pathlib import Path
import pwd
import sys
import tomllib

from workload_lib import (
    expand_volume_path,
    infer_workload_kind,
    infer_workload_mode,
    iter_workloads,
    normalize_containers,
    validate_workload_name,
    WORKLOAD_BUNDLES_DIR,
    workload_config_dir,
    workload_config_path,
    workload_is_enabled,
    VM_BRIDGE_NAME,
    workload_container_name,
    workload_data_dir,
    workload_home_dir,
    workload_service_name,
    workload_state_dir,
    workload_username,
)
from podman import Podman

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_workload_ref(ref: str) -> tuple[str, str | None]:
    """Parse 'workload[/container]' into (workload, container_or_None)."""
    if "/" in ref:
        wl, ctr = ref.split("/", 1)
        return wl, ctr
    return ref, None


def resolve_container_target(config, container, workload):
    """Resolve a (workload, container) ref to a podman container name.

    For single-container workloads, `container` must be None. For
    multi-container workloads, `container` is required; a bare workload name
    raises UsageError (mapped to exit 2) with the list of available
    containers.
    """
    if not config.is_multi:
        if container is not None:
            print(f"Error: workload '{workload}' is single-container; "
                  f"drop the '/{container}' suffix.", file=sys.stderr)
            raise UsageError(f"'{workload}' is single-container")
        return config.container_name
    names = config.container_names()
    if container is None:
        print(f"Error: workload '{workload}' has multiple containers; "
               "specify with NAME/CTR.", file=sys.stderr)
        print(f"  Available: {', '.join(names)}", file=sys.stderr)
        raise UsageError(f"'{workload}' requires a container name")
    if container not in names:
        print(f"Error: container '{container}' not in workload '{workload}'. "
              f"Available: {', '.join(names)}", file=sys.stderr)
        raise UsageError(f"container '{container}' not in '{workload}'")
    return config.podman_container_name(container)


def format_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == units[-1]:
            return f"{f:.1f} {u}"
        f /= 1024
    return f"{n} B"


def format_created(ts: str | int | None) -> str:
    """Render podman's image Created (Unix int or ISO string) as 'N days ago'."""
    if ts is None or ts == "":
        return "unknown"
    try:
        if isinstance(ts, (int, float)):
            created = datetime.datetime.fromtimestamp(int(ts))
        else:
            s = str(ts).rstrip("Z").split(".")[0]
            try:
                created = datetime.datetime.fromisoformat(s)
            except ValueError:
                created = datetime.datetime.fromtimestamp(int(float(ts)))
        delta = datetime.datetime.now() - created
        days = delta.days
        if days >= 1:
            return f"{days} day{'s' if days != 1 else ''} ago"
        hours = delta.seconds // 3600
        if hours >= 1:
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        minutes = max(1, delta.seconds // 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    except Exception:
        return "unknown"


def created_unix(ts) -> int | None:
    """Convert podman Created field (int, ISO string, or float string) to Unix int."""
    if ts is None or ts == "":
        return None
    try:
        if isinstance(ts, (int, float)):
            return int(ts)
        s = str(ts).rstrip("Z").split(".")[0]
        try:
            parsed = datetime.datetime.fromisoformat(s)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=datetime.timezone.utc)
            return int(parsed.timestamp())
        except ValueError:
            return int(float(ts))
    except Exception:
        return None


def parse_size_bytes(s) -> int:
    """Parse podman size strings like '1.23 GB', '456B', '0 B' to bytes."""
    if isinstance(s, int):
        return s
    s = str(s).strip()
    sl = s.lower()
    for suffix, mul in [("tib", 1024**4), ("gib", 1024**3), ("mib", 1024**2),
                         ("kib", 1024), ("tb", 10**12), ("gb", 10**9),
                         ("mb", 10**6), ("kb", 10**3), ("b", 1)]:
        if sl.endswith(suffix):
            try:
                return int(float(s[:-len(suffix)].strip()) * mul)
            except ValueError:
                return 0
    try:
        return int(float(s))
    except ValueError:
        return 0


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class UsageError(Exception):
    """Raised for a CLI usage error whose message has already been printed.

    Maps to exit code 2 (argparse's own convention for usage errors) in the
    __main__ except-ladder of bin/workloadctl.
    """


class WorkloadMasked(Exception):
    """Raised when a workload config is masked (symlinked to /dev/null)."""
    def __init__(self, name: str):
        self.name = name
        super().__init__(f"Workload '{name}' is masked.")


class WorkloadUserNotFound(Exception):
    """Raised when a workload's system user does not exist yet."""
    def __init__(self, name: str):
        self.name = name
        super().__init__(
            f"User not found for workload '{name}'. "
            f"Run 'workloadctl enable {name}' first."
        )


def toml_string(value: str) -> str:
    """Return a TOML-safe double-quoted string literal."""
    result = value.replace('\\', '\\\\').replace('"', '\\"')
    result = result.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    result = ''.join(f'\\u{ord(c):04x}' if ord(c) < 0x20 else c for c in result)
    return '"' + result + '"'


def require_root():
    """Ensure running as root"""
    if os.geteuid() != 0:
        print("Error: This command must be run as root (use sudo)", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# WorkloadConfig
# ---------------------------------------------------------------------------

class WorkloadConfig:
    """Represents a workload configuration file"""

    def __init__(self, name: str):
        self.path = workload_config_path(name)

        # Masked workload: symlink to /dev/null (same semantics as systemd masking)
        if self.path.is_symlink() and self.path.resolve() == Path('/dev/null'):
            raise WorkloadMasked(name)

        if not self.path.exists():
            raise FileNotFoundError(f"Config not found: {self.path}")

        with open(self.path, "rb") as f:
            self.config = tomllib.load(f)

        config_name = self.config["workload"]["name"]

        if config_name != name:
            raise ValueError(f"Workload name '{config_name}' must match directory '{name}'")

        validate_workload_name(config_name)

    @property
    def name(self) -> str:
        return self.config["workload"]["name"]

    @property
    def kind(self) -> str:
        return infer_workload_kind(self.config)

    @property
    def is_vm(self) -> bool:
        return self.kind == "vm"

    @property
    def image(self) -> str:
        if self.is_vm:
            vm = self.config.get("vm", {})
            return (vm.get("image") or vm.get("cloud_image_url")
                    or vm.get("local_image") or "(vm)")
        return self.config["container"]["image"]

    @property
    def enabled(self) -> bool:
        # Enabled-ness lives in a marker file, not workload.toml (see
        # workload_lib.workload_enabled_marker).
        return workload_is_enabled(self.name)

    @property
    def lifecycle(self) -> str:
        """Lifecycle policy: "pet" or "cattle" (default).

        "cattle" (the default) means the container overlay is ephemeral —
        destroyed on every stop/start via ``--rm``.  "pet" preserves the
        writable overlay across reboots and bootc updates by using a
        create-once / start-stop pattern (no ``--rm``).  A "pet" VM skips
        system.qcow2 generation rotation so the durable disk is never
        replaced by workloadctl update/reprovision.
        """
        return self.config.get("workload", {}).get("lifecycle", "cattle")

    @property
    def snapshot_keep(self) -> int:
        """How many pet-lifecycle overlay snapshots to retain (default 3).

        Each destructive verb (update/recreate) on a pet container commits the
        writable overlay to ``localhost/workload-snapshot/<name>:<ts>`` before
        rebuilding. Without a bound these accumulate forever; this caps the
        repository to the newest N, with older snapshots pruned after each new
        commit. Invalid values fall back to the default so a bad config never
        crashes a destroy (the validator surfaces the error separately).
        """
        val = self.config.get("workload", {}).get("snapshot_keep", 3)
        if not isinstance(val, int) or isinstance(val, bool) or val < 1:
            return 3
        return val

    @property
    def bundle(self) -> str:
        """The bundle (kind) this workload draws shared control files from.

        Control-file lookups all resolve under
        `/usr/share/workloadctl/workloads/<bundle>/`: the build context
        (Containerfile/`build.sh`), the host `setup.sh` (`[host].setup`), and
        the SELinux CIL (`policy.cil`). Defaults to the workload name, so a
        single shipped instance needs no `bundle` field; `duplicate`/`init`
        set it to the source's resolved bundle so a copy shares one control
        tree without copying it. Goes straight into a filesystem path, which is
        why `bundle_dir` (the single point where it becomes a path) validates it
        against NAME_PATTERN before any control file is resolved or executed.
        """
        val = self.config.get("workload", {}).get("bundle")
        return val if val else self.name

    @property
    def selinux_policy(self) -> bool:
        """Whether this workload ships a per-workload SELinux type (wl_<name>.process).

        When set, enable/disable load/remove the bundle's CIL policy
        (`policy.cil`) as a name-keyed module, and the generator labels the
        container with the matching type. Boolean-only — the bundle the CIL is
        sourced from is the resolved `[workload] bundle` (see `selinux_bundle`),
        which subsumes the old string form of this field.
        """
        return bool(self.config.get("security", {}).get("selinux_policy", False))

    @property
    def selinux_bundle(self) -> str | None:
        """Bundle dir to source the CIL (`policy.cil`) from, or None if policy off.

        Sources from the resolved `bundle` (defaults to the workload name); the
        loaded module and container label stay keyed to the workload *name*
        (`wl_<name>.process`) so teardown is 1:1 per enabled instance.
        """
        return self.bundle if self.selinux_policy else None

    @property
    def bundle_dir(self) -> Path:
        """The shipped /usr control-file tree for this workload's bundle.

        This property is the single point where the `bundle` field becomes a
        filesystem path — and that path is read *and executed as root* (build
        context, `[host].setup`, `policy.cil`). So validate here: anything that
        isn't a plain workload-style name (a stray `..`, a typo, an underscored
        SELinux type name) is rejected before it can redirect control-file
        resolution outside the bundles tree. Construction stays lenient (callers
        like `validate`/`info` can still inspect a bad bundle); the guarantee is
        that no path is ever *built* from an unvalidated bundle.
        """
        bundle = self.bundle
        try:
            validate_workload_name(bundle)
        except ValueError as e:
            hint = ""
            if "_" in bundle:
                hint = (f" — did you mean {bundle.replace('_', '-')!r}? the "
                        f"bundle is a directory name and uses hyphens, not the "
                        f"underscores of the SELinux type name")
            raise ValueError(f"Invalid [workload] bundle {bundle!r}: {e}{hint}")
        return WORKLOAD_BUNDLES_DIR / bundle

    @property
    def override_dir(self) -> Path:
        """The operator's /etc/workloads.d/<name>/ control-file override tree.

        Lazy: usually absent. `edit <name> <file>` seeds a copy-on-write
        override here; resolve_control_file prefers it over the shipped bundle.
        Keyed on *name* (not bundle) so a duplicate overrides independently of
        its source. Resolves via workload_config_dir() so tests patching the
        config dir are honored.
        """
        return workload_config_dir() / self.name

    def resolve_control_file(self, relpath: str) -> Path:
        """Resolve a bundle control file (build.sh, policy.cil, [host].setup, …)
        through the lazy-override chain: the operator's
        /etc/workloads.d/<name>/<relpath> wins if it exists, else the shipped
        /usr bundle default. An absolute path bypasses resolution.

        This is the single chokepoint every control-file lookup goes through so
        overrides apply uniformly — the /usr→/etc vendor→admin drop-in idiom
        (systemd's `systemctl edit`/`cat`). See docs/wip/workload-bundles.md
        "Control files — lazy override".
        """
        return self.resolve_control_file_with_source(relpath)[0]

    def resolve_control_file_with_source(self, relpath: str) -> tuple[Path, str]:
        """Like resolve_control_file but also returns the winning source:
        "etc" (operator override), "usr" (shipped default), or "abs" (a verbatim
        absolute path) — the merged-view truth `info --files` reports.

        This is the single chokepoint every control-file lookup goes through,
        and a resolved relative path is read *and executed as root* (build
        Containerfile/`[build].script`, `[host].setup`, `policy.cil`). So any
        `..` traversal is rejected here — not just for `bundle` (validated in
        `bundle_dir`), but for the relpath too, so a `[build] containerfile =
        "../../etc/x"` or `script`/`setup` can't redirect resolution outside the
        bundle/override trees. An absolute path is taken verbatim (the documented
        escape hatch for a fully-qualified setup/script path) and reported as
        "abs" — neither an override nor a shipped default.
        """
        p = Path(relpath)
        if p.is_absolute():
            return p, "abs"
        if ".." in p.parts:
            raise ValueError(
                f"control-file path {relpath!r} must be relative with no '..' "
                f"components (it resolves under the bundle/override tree)"
            )
        override = self.override_dir / relpath
        if override.exists():
            return override, "etc"
        return self.bundle_dir / relpath, "usr"

    # --- [build]: image build context (see lib/imagebuild.py) --------------

    @property
    def build_config(self) -> dict:
        return self.config.get("build", {})

    @property
    def build_script(self) -> str | None:
        """Escape-hatch build script (`[build] script`). When set, `build` runs
        it against the merged context instead of the built-in podman builder.
        Resolved through the override chain like any other control file."""
        return self.build_config.get("script") or None

    @property
    def build_containerfile(self) -> str:
        """Containerfile name within the (merged) build context. Default
        `Containerfile`. Relative — it names a file inside the context dir."""
        return self.build_config.get("containerfile", "Containerfile")

    @property
    def build_args(self) -> dict:
        """Static `--build-arg` defaults (`[build] args`)."""
        return self.build_config.get("args", {}) or {}

    @property
    def build_arg_env(self) -> list:
        """Host env var names forwarded as `--build-arg` when set
        (`[build] arg_env`); the transient override for a knob like an RPM URL
        or GPU type. Env value wins over the `args` default. Build args land in
        image history — keep these non-sensitive (use a secret, not arg_env, for
        anything confidential)."""
        return self.build_config.get("arg_env", []) or []

    @property
    def build_target(self) -> str | None:
        """Optional multi-stage `--target` (`[build] target`)."""
        return self.build_config.get("target") or None

    def build_images(self) -> list[str]:
        """Distinct `pull = never` images this workload builds locally, in TOML
        order. The built image is tagged exactly as `[container].image`, so a
        pull=never container always matches what gets built — there is no
        separate build-tag to drift out of sync."""
        seen: list[str] = []
        for _cname, image, pull in self.container_specs():
            if pull == "never" and image not in seen:
                seen.append(image)
        return seen

    def has_build_context(self) -> bool:
        """True if there's a local image to build and a Containerfile resolves
        (in the /etc override or the /usr bundle). Gates the built-in builder."""
        return bool(self.build_images()) and \
            self.resolve_control_file(self.build_containerfile).exists()

    @property
    def username(self) -> str:
        return workload_username(self.name)

    @property
    def uid(self) -> int:
        """Get UID from passwd database."""
        try:
            return pwd.getpwnam(self.username).pw_uid
        except KeyError:
            raise WorkloadUserNotFound(self.name)

    @property
    def gid(self) -> int:
        """Get primary GID from passwd database."""
        try:
            return pwd.getpwnam(self.username).pw_gid
        except KeyError:
            raise WorkloadUserNotFound(self.name)

    @property
    def service_name(self) -> str:
        return workload_service_name(self.name)

    @property
    def container_name(self) -> str:
        return workload_container_name(self.name)

    @property
    def home_dir(self) -> Path:
        return workload_home_dir(self.name)

    @property
    def state_dir(self) -> Path:
        """Reconstructible state subtree (= $HOME / podman graphroot / VM disks)."""
        return workload_state_dir(self.name)

    @property
    def data_dir(self) -> Path:
        """Precious data subtree ('./' volume anchors resolve here; backup-captured)."""
        return workload_data_dir(self.name)

    @property
    def vm_bridge(self) -> str:
        return self.config.get("vm", {}).get("network", {}).get("bridge", VM_BRIDGE_NAME)

    def get_network_mode(self) -> str:
        return self.config.get("network", {}).get("mode", "pasta")

    def get_ports(self) -> list[str]:
        return self.config.get("network", {}).get("ports", [])

    def get_volumes(self) -> list[str]:
        return self.config.get("storage", {}).get("volumes", [])

    def get_extra_groups(self) -> list[str]:
        return self.config.get("security", {}).get("extra_groups", [])

    def has_health_check(self) -> bool:
        """True if any container in this workload has a health check."""
        for c in normalize_containers(self.config):
            if c.get("container", {}).get("health", {}).get("cmd"):
                return True
        return False

    def container_health_blocks(self) -> list[tuple[str, str, dict]]:
        """Return [(container-local-name, podman-name, health-dict), ...] for
        every container with a non-empty health.cmd. The podman-name is what
        `podman inspect` and container_health() use; for single-container
        workloads that's self.container_name."""
        result = []
        for c in normalize_containers(self.config):
            health = c.get("container", {}).get("health", {})
            if not health.get("cmd"):
                continue
            local = c.get("name", self.name)
            podman_name = self.podman_container_name(local)
            result.append((local, podman_name, health))
        return result

    @property
    def is_multi(self) -> bool:
        return "containers" in self.config

    @property
    def mode(self) -> str:
        return infer_workload_mode(self.config)

    def container_names(self) -> list[str]:
        """Ordered list of container names. For single workloads, [name]."""
        if self.is_multi:
            return [c["name"] for c in self.config["containers"]]
        return [self.name]

    def sub_service_names(self) -> list[str]:
        """systemd unit names for each container (multi) or [service_name]."""
        if not self.is_multi:
            return [self.service_name]
        return [f"workload-{self.name}-{c}.service" for c in self.container_names()]

    def container_image(self, container_name: str) -> str:
        """Image for a given container name. For single workloads, self.image."""
        if not self.is_multi:
            return self.image
        for c in self.config["containers"]:
            if c["name"] == container_name:
                return c["container"]["image"]
        raise KeyError(f"container '{container_name}' not in workload '{self.name}'")

    def container_images(self) -> list[tuple[str, str]]:
        """Return [(container_name, image), ...]."""
        return [(c, self.container_image(c)) for c in self.container_names()]

    def container_specs(self) -> list[tuple[str, str, str]]:
        """Return [(container_name, image, pull_policy), ...] for every container.

        For single-container workloads this is a one-element list built from
        the top-level [container] block.
        """
        if self.is_multi:
            return [(c["name"], c["container"]["image"],
                     c["container"].get("pull", "missing"))
                    for c in self.config["containers"]]
        return [(self.name, self.image,
                 self.config.get("container", {}).get("pull", "missing"))]

    def all_volumes(self) -> list[str]:
        """Volume specs across every container (single: [storage].volumes)."""
        if not self.is_multi:
            return self.get_volumes()
        vols: list[str] = []
        for c in self.config["containers"]:
            vols.extend(c.get("storage", {}).get("volumes", []))
        return vols

    def podman_container_name(self, container_name: str) -> str:
        """Podman --name for a given container."""
        if not self.is_multi:
            return self.container_name
        return f"workload-{self.name}-{container_name}"

    def podman_targets(self) -> list[str]:
        """Podman --name for every container this workload runs, in
        container_names() order. Collapses the recurring
        `[podman_container_name(c) for c in ...] if is_multi else [container_name]`
        ternary used by liveness/stats/health/diagnose call sites."""
        if self.is_multi:
            return [self.podman_container_name(c) for c in self.container_names()]
        return [self.container_name]

    def get_required_files(self) -> list[dict]:
        """Return list of {path, hint} dicts from [setup].required_files."""
        entries = self.config.get("setup", {}).get("required_files", [])
        result = []
        for entry in entries:
            if "path" not in entry:
                continue
            path = entry["path"]
            # Resolve workload-relative anchors (./ @/ data/ state/) through the
            # SAME logic as volume mounts so a required file lands where its
            # volume actually mounts it. A bare path (no ':') round-trips through
            # expand_volume_path as just the expanded host. Without this, a
            # precious "./config.json" required-file resolved to state/ for the
            # preflight auto-copy while its volume mounted from data/ — they
            # diverged and the container mounted a missing path.
            path = expand_volume_path(path, str(self.home_dir))
            result.append({"path": path, "hint": entry.get("hint")})
        return result


# ---------------------------------------------------------------------------
# WorkloadManager
# ---------------------------------------------------------------------------

class WorkloadManager:
    """Manages workload operations"""

    def __init__(self):
        self.workload_dir = workload_config_dir()

    def run_podman_exec(self, config: WorkloadConfig, args,
                        check=False, capture_output=False):
        """Run `podman exec <args>` against a workload container.

        Under ADR 001 option 1b, containers run inside the user manager
        (user@<uid>.service → workloads.slice), so crun's cgroup migration stays
        within the delegated subtree and plain sudo -u exec works without any
        cgroup placement shim.
        """
        return self.podman(config).run("exec", *args,
                                       check=check, capture_output=capture_output)

    def run_podman(self, config: WorkloadConfig, *args, check=False,
                  capture_output=False):
        """Run an arbitrary podman subcommand as the workload user."""
        return self.podman(config).run(*args, check=check,
                                       capture_output=capture_output)

    def podman(self, config: WorkloadConfig) -> Podman:
        """Return a memoized Podman wrapper for this workload's user."""
        if not hasattr(self, "_podman_clients"):
            self._podman_clients: dict[int, Podman] = {}
        if config.uid not in self._podman_clients:
            self._podman_clients[config.uid] = Podman.for_user(
                config.username, config.uid, config.home_dir
            )
        return self._podman_clients[config.uid]

    def get_image_id(self, config: WorkloadConfig) -> str:
        """Get current image ID. Returns '' if image not present.

        Raises PodmanError on unexpected failures (sudo, malformed output, etc.)
        """
        return self.podman(config).image_id(config.image)

    def get_all_configs(self, enabled_only=False) -> list[WorkloadConfig]:
        """Get all workload configs"""
        configs = []
        for name, path in iter_workloads():
            try:
                config = WorkloadConfig(name)
                if not enabled_only or config.enabled:
                    configs.append(config)
            except WorkloadMasked:
                pass  # Intentionally masked; not a warning
            except Exception as e:
                print(f"Warning: Failed to load {path.name}: {e}", file=sys.stderr)
        return configs

    def user_exists(self, config: WorkloadConfig) -> bool:
        """Check if workload user exists"""
        try:
            pwd.getpwnam(config.username)
            return True
        except KeyError:
            return False
