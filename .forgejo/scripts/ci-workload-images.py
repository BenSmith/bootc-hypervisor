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

`build` must run as root (podman build into the root store, matching the
hypervisor image pipeline); the workflow invokes it under sudo.
"""
import json
import os
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
    """localhost/<x>:<tag> -> <REGISTRY>/workload-<x>:<tag>.

    The `workload-` prefix namespaces self-built images in the registry away
    from the bootc images (hypervisor-bootc, fedora-bootc-minimal) and the
    pull-through upstream caches.
    """
    ref = image
    if ref.startswith("localhost/"):
        ref = ref[len("localhost/"):]
    return f"{REGISTRY}/workload-{ref}"


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

    # Full parity with `workloadctl build`: builds each pull=never image and
    # tags it exactly as [container].image (localhost/<name>:latest).
    rc = imagebuild.build_image(cfg)
    if rc != 0:
        return rc

    refs = []
    for image in cfg.build_images():
        ref = _registry_ref(image)
        import subprocess
        r = subprocess.run(["podman", "tag", image, ref])
        if r.returncode != 0:
            return r.returncode
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
