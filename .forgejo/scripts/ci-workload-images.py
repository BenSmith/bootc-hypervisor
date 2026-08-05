#!/usr/bin/env python3
"""CI helper: build workload container images straight from the repo tree and
push them to the homelab registry.

This is glue for `.forgejo/workflows/build-workload-images.yml`. It reuses
workloadctl's own build machinery (lib/imagebuild.py) rather than
reimplementing Containerfile / build-arg / target / context-exclusion handling,
so a CI build is byte-for-byte what `workloadctl build <name>` produces. The
two env overrides below repoint that machinery at the checked-out
`workloadctl/workloads/` tree instead of the installed /usr + /etc trees:

  WORKLOAD_CONFIG_DIR   → where WorkloadConfig(name) reads <name>/workload.toml
  WORKLOAD_BUNDLES_DIR  → the bundle_dir build context (the shipped /usr tree)

In CI there is no /etc operator override, so the "merged context" collapses to
the pristine bundle — exactly the artifact we want to publish.

Subcommands:
  list                    emit a JSON array of buildable workload names (for the
                          job matrix), honouring SELECT / CHANGED_FILES env.
  build <name>            build the workload's pull=never image(s), tag each for
                          the registry, and append the registry refs to the file
                          named by REFS_OUT (one per line) for the push step.

Variants (`[[build.variants]]`) let one bundle publish more than one image from
the same context — e.g. a vulkan default plus a cuda build. This is a
*publishing* concern, not a build-machinery one: a host builds only the variant
it needs, using the same `[build].arg_env` override a human would type, so
`workloadctl build` deliberately stays single-image and is unaffected. CI is the
only consumer that needs all of them at once, which is why this lives here and
not in lib/.

`build` must run as root (podman build into the root store, matching the
hypervisor image pipeline); the workflow invokes it under sudo.
"""
import contextlib
import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKLOADS_TREE = REPO_ROOT / "workloadctl" / "workloads"

# Repoint workloadctl's path resolution at the checked-out tree BEFORE importing
# the lib (both constants are read at import time).
os.environ.setdefault("WORKLOAD_CONFIG_DIR", str(WORKLOADS_TREE))
os.environ.setdefault("WORKLOAD_BUNDLES_DIR", str(WORKLOADS_TREE))

sys.path.insert(0, str(REPO_ROOT / "workloadctl" / "lib"))

import imagebuild  # noqa: E402
from workloadctl_core import WorkloadConfig  # noqa: E402

REGISTRY = os.environ.get("REGISTRY", "registry.local")


def _load(name: str):
    """Return a WorkloadConfig, or None if it can't load (masked/invalid)."""
    try:
        return WorkloadConfig(name)
    except Exception:
        return None


def _is_buildable(name: str) -> bool:
    cfg = _load(name)
    if not cfg or cfg.is_vm:
        return False
    # has_build_context() resolves bundle_dir/containerfile and can raise
    # ValueError on a malformed [workload].bundle or a traversal-laden
    # [build].containerfile. Treat that like a failed load (skip, don't crash)
    # so one bad bundle can't take down the whole CI matrix.
    try:
        return cfg.has_build_context()
    except Exception:
        return False


def _all_buildable() -> list[str]:
    names = sorted(p.parent.name for p in WORKLOADS_TREE.glob("*/workload.toml"))
    return [n for n in names if _is_buildable(n)]


def _registry_ref(image: str) -> str:
    """localhost/<x>:<tag> -> <REGISTRY>/workloads/<x>:<tag>.

    The `workloads/` path namespaces self-built images in the registry away
    from the bootc images (hypervisor-bootc, fedora-bootc-minimal) and the
    pull-through upstream caches — and, being a real path component, it is
    what policy.json's `registry.local/workloads` sigstoreSigned scope
    matches (a flat name-prefix like `workload-<x>` is not scopeable). An
    image whose [container].image already names the registry (the
    zot-consuming bundles) passes through unchanged — the build tagged it
    push-ready.
    """
    if image.startswith(f"{REGISTRY}/"):
        return image
    ref = image
    if ref.startswith("localhost/"):
        ref = ref[len("localhost/"):]
    return f"{REGISTRY}/workloads/{ref}"


def _split_ref(ref: str) -> tuple[str, str]:
    """Split an image ref into (repo, tag).

    A plain `rsplit(":")` is wrong: `registry.local:5000/workloads/x` has a
    port and no tag. Only a colon *after* the last slash separates a tag.
    """
    slash = ref.rfind("/")
    colon = ref.rfind(":")
    if colon > slash:
        return ref[:colon], ref[colon + 1:]
    return ref, ""


def _variant_ref(ref: str, suffix: str) -> str:
    """`registry.local/workloads/x:latest` + `cuda` -> `.../x:cuda`."""
    repo, _tag = _split_ref(ref)
    return f"{repo}:{suffix}"


def _variants(cfg) -> list[dict]:
    """`[[build.variants]]` entries — extra images built from the same context.

    Each is `{suffix, args}`. The default build (Containerfile ARG defaults,
    tagged as `[container].image`) is always produced; variants are additional
    tags built with different `--build-arg` values.
    """
    return list((cfg.build_config or {}).get("variants") or [])


def _validate_variants(cfg, variants: list[dict]) -> str | None:
    """Error message for a malformed variants table, else None.

    The arg_env check is the load-bearing one. Variant args are applied by
    exporting them and letting `assemble_build_args` pick them up, and it only
    consults the environment for names listed in `[build].arg_env`. An arg
    outside that list is silently dropped — which would not fail the build, it
    would publish a variant tag holding a byte-identical copy of the default.
    A tag that lies about its contents is worse than a broken build, so this
    refuses up front.
    """
    declared = set(cfg.build_arg_env)
    seen: set[str] = set()
    for i, v in enumerate(variants):
        if not isinstance(v, dict):
            return f"variant #{i} is not a table"
        suffix = str(v.get("suffix") or "").strip()
        if not suffix:
            return f"variant #{i} has no 'suffix'"
        if "/" in suffix or ":" in suffix:
            return f"variant suffix {suffix!r} may not contain '/' or ':'"
        if suffix == "latest":
            return "variant suffix 'latest' collides with the default build"
        if suffix in seen:
            return f"duplicate variant suffix {suffix!r}"
        seen.add(suffix)
        args = v.get("args") or {}
        if not args:
            return f"variant {suffix!r} sets no 'args' — it would copy the default"
        undeclared = sorted(set(args) - declared)
        if undeclared:
            return (
                f"variant {suffix!r} sets {undeclared}, which "
                f"[build].arg_env does not declare — those args would be "
                f"ignored and the variant would be a copy of the default"
            )
    return None


@contextlib.contextmanager
def _env_overrides(values: dict):
    """Temporarily export `values`, restoring the prior environment on exit."""
    prior = {k: os.environ.get(k) for k in values}
    os.environ.update({k: str(v) for k, v in values.items()})
    try:
        yield
    finally:
        for k, old in prior.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old


def _tag(image: str, ref: str) -> int:
    """`podman tag`, skipping the no-op when the build already produced `ref`
    (a bundle whose [container].image names the registry directly)."""
    if image == ref:
        return 0
    return subprocess.run(["podman", "tag", image, ref]).returncode


def cmd_list() -> int:
    buildable = _all_buildable()

    select = os.environ.get("SELECT", "").strip()
    if select and select.lower() != "all":
        wanted = [s for s in select.replace(",", " ").split()]
        names = [n for n in wanted if n in buildable]
    elif os.environ.get("CHANGED_FILES", "").strip():
        touched = set()
        for line in os.environ["CHANGED_FILES"].splitlines():
            parts = Path(line.strip()).parts
            # workloadctl/workloads/<name>/...
            if len(parts) >= 3 and parts[0] == "workloadctl" and parts[1] == "workloads":
                touched.add(parts[2])
        names = [n for n in buildable if n in touched]
    else:
        names = buildable

    print(json.dumps(names))
    return 0


def cmd_build(name: str) -> int:
    cfg = _load(name)
    if cfg is None:
        print(f"Error: cannot load workload '{name}'", file=sys.stderr)
        return 1
    if cfg.is_vm or not cfg.has_build_context():
        print(f"Error: '{name}' has no buildable image", file=sys.stderr)
        return 1

    variants = _variants(cfg)
    err = _validate_variants(cfg, variants)
    if err is not None:
        print(f"Error: {name}: {err}", file=sys.stderr)
        return 1

    refs: list[str] = []

    # Variants BEFORE the default, and the ordering is load-bearing. Every
    # build tags its result as [container].image, so whichever runs last owns
    # that tag — and it must be the default, since that is what hosts consume
    # as :latest. Each variant's own tag keeps its image alive after the
    # default build moves :latest off it.
    for v in variants:
        suffix = v["suffix"]
        with _env_overrides(v.get("args") or {}):
            rc = imagebuild.build_image(cfg)
        if rc != 0:
            print(f"Error: {name}: variant {suffix!r} failed to build", file=sys.stderr)
            return rc
        for image in cfg.build_images():
            ref = _variant_ref(_registry_ref(image), suffix)
            rc = _tag(image, ref)
            if rc != 0:
                return rc
            refs.append(ref)

    # Full parity with `workloadctl build`: builds each pull=never image and
    # tags it exactly as [container].image (localhost/<name>:latest).
    rc = imagebuild.build_image(cfg)
    if rc != 0:
        return rc

    for image in cfg.build_images():
        ref = _registry_ref(image)
        rc = _tag(image, ref)
        if rc != 0:
            return rc
        refs.append(ref)

    refs_out = os.environ.get("REFS_OUT")
    if refs_out:
        with open(refs_out, "a") as f:
            for ref in refs:
                f.write(ref + "\n")
    for ref in refs:
        print(f"tagged {ref}", file=sys.stderr)
    return 0


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    if argv[1] == "list":
        return cmd_list()
    if argv[1] == "build":
        if len(argv) < 3:
            print("usage: ci-workload-images.py build <name>", file=sys.stderr)
            return 2
        return cmd_build(argv[2])
    print(f"unknown subcommand: {argv[1]}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
