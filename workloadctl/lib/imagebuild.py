"""
imagebuild — image build orchestration for `workloadctl build`.

Two modes, selected by the TOML:

  - `[build] script` set → escape hatch: run the script against the *merged*
    build context (override-correct, unlike a self-locating `build.sh`).
  - otherwise            → built-in builder: `podman build` the merged context
    for each `pull = never` image, tagging it exactly as `[container].image`.

The **merged context** is the build analogue of `info --files`: the shipped
`/usr` bundle tree with the operator's `/etc/workloads.d/<name>/` overrides laid
on top, file by file. Materializing it is what makes overriding a `Containerfile`
(or a `COPY`-ed asset) actually take effect — the original self-locating
`build.sh` pinned the context to wherever the script resolved, silently ignoring
overrides. See docs/workloads.md "Customizing control files".
"""
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from podman import Podman, PodmanError

# workloadctl-owned control files never belong in a build context — a bare
# `COPY . /` in a Containerfile would otherwise sweep them into the image.
# ".enabled" is the enabled-marker (workload_lib.ENABLED_MARKER_NAME) that the
# override dir carries for an enabled workload; keep it out of the build context
# so a `COPY . /` Containerfile can't sweep control files into the image.
_CONTEXT_EXCLUDE = {"workload.toml", "build.sh", "policy.cil", ".enabled"}


def _proxy_build_args() -> list:
    """Forward the host's proxy env as build-args (universal boilerplate the old
    per-bundle build.sh scripts all carried)."""
    args = []
    for var in ("http_proxy", "https_proxy", "no_proxy"):
        val = os.environ.get(var) or os.environ.get(var.upper())
        if val:
            args += ["--build-arg", f"{var}={val}"]
    return args


def assemble_build_args(config, job=None) -> list:
    """`--build-arg` list: the job's args (resolved wholesale by `build_jobs()`
    — a `[containers.build].args` *replaces* `[build].args`, no merge; without a
    job, the workload-level `[build].args`), overridden by `[build].arg_env`
    host env when set, plus auto-forwarded proxy vars. `arg_env` is deliberately
    workload-level — the transient host-env override knob applies to every
    image's build; there is no per-container arg_env.

    SECURITY: `--build-arg` values are recorded in the image's build history
    (`podman history`). These are meant for non-sensitive knobs — RPM URLs, GPU
    type, proxy endpoints — so never route a secret through `args`/`arg_env`;
    use a workloadctl secret (tmpfs at runtime), not a build arg, for anything
    confidential.
    """
    merged = dict(job.args if job is not None else config.build_args)
    for name in config.build_arg_env:
        val = os.environ.get(name)
        if val is not None:
            merged[name] = val
    args = []
    for k, v in merged.items():
        args += ["--build-arg", f"{k}={v}"]
    args += _proxy_build_args()
    return args


def materialize_build_context(config) -> Path:
    """Assemble the merged (/usr + /etc overlay) build context into a fresh temp
    dir and return it. Caller owns cleanup (rmtree). Control files are stripped
    so they can't leak into the image via `COPY .`."""
    tmp = Path(tempfile.mkdtemp(prefix=f"wl-build-{config.name}-"))
    if config.bundle_dir.is_dir():
        shutil.copytree(config.bundle_dir, tmp, dirs_exist_ok=True)
    if config.override_dir.is_dir():
        # Overlay: operator overrides win file-by-file over the shipped tree.
        shutil.copytree(config.override_dir, tmp, dirs_exist_ok=True)

    exclude = set(_CONTEXT_EXCLUDE)
    setup = config.config.get("host", {}).get("setup", "")
    if setup and not Path(setup).is_absolute():
        exclude.add(setup)
    for name in exclude:
        p = tmp / name
        if p.is_file():
            p.unlink()
    return tmp


def _podman_build(context: Path, containerfile: str, tag: str,
                  build_args: list, target) -> int:
    cmd = ["podman", "build", "-f", str(context / containerfile), "-t", tag,
           *build_args]
    if target:
        cmd += ["--target", target]
    cmd.append(str(context))
    return subprocess.run(cmd).returncode


def build_image(config) -> int:
    """Built-in builder: `podman build` the merged context once per distinct
    pull=never image, each with its own Containerfile/target (resolved per
    container via `build_jobs()`). Returns the first non-zero exit code, or 0.

    A single merged context serves every image — all Containerfiles and assets
    live in the one bundle dir, each built with `-f <its containerfile>`."""
    jobs = config.build_jobs()
    if not jobs:
        print(f"Error: no pull=never image to build for '{config.name}'")
        return 1

    context = materialize_build_context(config)
    try:
        overlaid = " + /etc overrides" if config.override_dir.is_dir() else ""
        for job in jobs:
            if not (context / job.containerfile).exists():
                print(f"Error: Containerfile '{job.containerfile}' not found in "
                      f"the build context for '{config.name}'")
                return 1
            print(f"Building {job.image}  (context: {config.bundle_dir}"
                  f"{overlaid}, -f {job.containerfile})")
            rc = _podman_build(context, job.containerfile, job.image,
                               assemble_build_args(config, job), job.target)
            if rc != 0:
                return rc
        # Muscle-memory alias: a single-image workload's build is also
        # reachable as localhost/<name>:latest even when [container].image
        # names the registry ref the fleet consumes. The build tag itself
        # (job.image, in root's store) is the local override the next
        # enable/update transfers; the alias is convenience only, so a tag
        # failure warns rather than failing the build.
        if len(jobs) == 1:
            alias = f"localhost/{config.name}:latest"
            if jobs[0].image != alias:
                try:
                    Podman.for_root().tag(jobs[0].image, alias)
                except PodmanError as e:
                    print(f"Warning: could not alias {jobs[0].image} as {alias}: {e}")
        return 0
    finally:
        shutil.rmtree(context, ignore_errors=True)


def run_build_script(config) -> int:
    """Escape hatch: run `[build].script` against the merged context. The script
    is handed the context dir and target tag as argv plus `WL_BUILD_*` env, so it
    builds the override-resolved context rather than self-locating its own dir
    (which is precisely what broke override resolution in the old build.sh)."""
    script = config.resolve_control_file(config.build_script)
    if not script.exists():
        print(f"Error: [build].script not found: {script}")
        return 1
    images = config.build_images()
    tag = images[0] if images else config.image
    context = materialize_build_context(config)
    try:
        env = dict(os.environ)
        env["WL_BUILD_CONTEXT"] = str(context)
        env["WL_TAG"] = tag
        env["WL_IMAGE"] = tag
        return subprocess.run([str(script), str(context), tag], env=env).returncode
    finally:
        shutil.rmtree(context, ignore_errors=True)
