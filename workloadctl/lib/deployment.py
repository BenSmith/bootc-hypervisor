"""
deployment — which ostree deployment a workload's /var state belongs to.

On an ostree/bootc host `/etc` is per-deployment and `/var` is shared by every
deployment. Every piece of workload *identity* lives in `/etc` (the TOML under
`workloads.d/`, the `_wl-*` line in `passwd`, the range in `subuid`); every piece
of *precious state* lives in `/var`. So `bootc rollback` — which deletes nothing —
takes a workload's identity away while its state stays behind, and `cleanup`'s
definition of an orphan ("state whose workload has no config at all") is then
satisfied by state that is not orphaned, merely invisible from where you booted.
Observed on onepiece 2026-07-28: two workloads present on the booted deployment
and absent from the rollback target, with their `/var` trees owned by UIDs that
would not resolve after a rollback.

The fix is to make `/var` self-describing. `workload-ensure-user` stamps each
workload root with the deployment that last provisioned it, and `cleanup` reads
the stamp back before calling anything an orphan:

| config present? | marker             | verdict                                    |
|-----------------|--------------------|--------------------------------------------|
| yes             | —                  | not an orphan *(unchanged)*                |
| no              | absent             | orphan — pre-marker or hand-made state     |
| no              | deployment == booted | orphan — the config was deleted here      |
| no              | deployment exists, not booted | **skip** — another deployment's  |
| no              | deployment gone    | orphan — defunct                           |

The `== booted` row is load-bearing: without it, deleting a TOML on the booted
deployment leaves a marker naming a deployment that still exists, and cleanup
would skip the ordinary case it exists for.

Nothing here ever *causes* a sweep. Every uncertainty — no `/ostree` at all (a
plain-RPM host; workloadctl is deliberately bootc-independent), an unreadable or
corrupt marker, a cmdline we can't resolve — resolves to "we can't say", which
leaves the caller with exactly the behavior it had before this module existed.

Deliberately NOT in the marker: the workload's UID and subordinate range. Those
are derivable (the owning UID of `<root>/data` *is* the answer, one stat away)
and a copy in a file could only go stale and compete with `/etc/subuid`. The
rollback hazard they would have covered is handled at allocation time instead, by
`claim_uid()` adopting the existing owner.

Full rationale, including the four ways deployment identity can be got wrong:
docs/adr/005-var-state-deployment-provenance.md.
"""

import json
import os
from pathlib import Path, PurePosixPath
import re

from workload_lib import replace_file_atomically

# Where a workload root records the deployment that last provisioned it. Sits in
# the root itself, which is root-owned (state/ and data/ below it are chowned to
# the workload user) — so the workload cannot rewrite the stamp that decides
# whether its own state may be swept.
PROVENANCE_NAME = "provenance.json"

OSTREE_DEPLOY_ROOT = Path("/ostree/deploy")
PROC_CMDLINE = Path("/proc/cmdline")

# A deployment directory basename: <commit-checksum>.<serial>, e.g.
# "4f46afe780e6…a08.0". Checksums are sha256, hence 64 hex; the serial
# distinguishes repeated deployments of one commit. Matching this shape is also
# what makes an id safe to interpolate into the glob below.
_DEPLOYMENT_ID_RE = re.compile(r"\A[0-9a-f]{64}\.[0-9]+\Z")


def booted_deployment_id() -> str | None:
    """The booted deployment's `<csum>.<serial>`, or None if it can't be read.

    Resolved from the kernel cmdline's `ostree=` value, which is a symlink into
    the deployment tree — `/ostree/boot.1/default/<BOOT-csum>/0` ->
    `../../../deploy/default/deploy/<DEPLOY-csum>.0`. Verified on onepiece
    2026-07-29.

    Three near-misses, each of which yields code that looks right:

      - the `ostree=` value's own csum is the **boot** checksum, not the
        deployment checksum. Only the resolved link gives the deployment id.
      - identifying the booted deployment by inode against `/` does not work:
        on onepiece `/` is device 36 and the deployment dir is on 64512.
      - `.origin` is not an identity — both deployments there carry the same
        `container-image-reference`; only the csum differs. Nor is bootc's
        `imageDigest`, which is a different identifier entirely.

    None on any host that isn't ostree-booted, and on any shape we don't
    recognize — callers must read that as "unknown", never as "no deployment".
    """
    try:
        cmdline = PROC_CMDLINE.read_text()
    except OSError:
        return None
    link = next((tok[len("ostree="):] for tok in cmdline.split()
                 if tok.startswith("ostree=")), None)
    if not link:
        return None
    try:
        target = os.readlink(link)
    except OSError:
        return None
    # The link is relative (../../../deploy/...); .name works either way, and
    # avoids depending on /sysroot being traversable, which realpath() would.
    ident = PurePosixPath(target).name
    return ident if _DEPLOYMENT_ID_RE.match(ident) else None


def deployments_readable() -> bool:
    """Whether this host can answer "does deployment X still exist?" at all.

    False on a plain-RPM host. Callers must gate the whole deployment rule on
    this rather than treating an unreadable tree as "every deployment is gone" —
    that inversion turns a missing directory into a licence to delete /var.
    """
    return OSTREE_DEPLOY_ROOT.is_dir()


def deployment_exists(deployment_id: str) -> bool:
    """Whether `<id>` is still deployed under any stateroot.

    Globs `*/deploy/<id>` because the stateroot is a real variable, not always
    `default`: hardcoding it is correct on a one-stateroot host and quietly
    wrong on a two-stateroot one. That matters here because `/var` may be shared
    across stateroots — a separate `/var` filesystem is a normal bootc layout
    (onepiece mounts /dev/mapper/os-var at /var) and this repo prescribes
    neither layout, shipping an empty kickstart so partitioning stays an
    interactive choice.
    """
    if not deployment_id or not _DEPLOYMENT_ID_RE.match(deployment_id):
        return False
    return any(OSTREE_DEPLOY_ROOT.glob(f"*/deploy/{deployment_id}"))


def marker_path(root: Path) -> Path:
    """Path of the provenance marker inside a workload's /var root."""
    return Path(root) / PROVENANCE_NAME


def read_marker(root: Path) -> dict | None:
    """The workload root's provenance marker, or None if there isn't a usable one.

    Absent, unreadable, corrupt and "not a JSON object" all collapse to None:
    the marker's only job is to *withhold* a deletion, so anything we can't
    parse must fall back to the pre-marker behavior rather than guess.
    """
    try:
        data = json.loads(marker_path(root).read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def write_marker(root: Path, name: str) -> bool:
    """Stamp `root` with the deployment provisioning it now. True if it changed.

    Rewritten on every `workload-ensure-user` run, not just the first, and that
    is the semantics the cleanup rule needs: the marker means "the deployment
    that last provisioned this state", not "the one that created it". With
    create-only semantics the ordinary case breaks — a workload created under A,
    carried forward to B by the /etc merge, then deleted under B would still
    name A, and A still exists as the rollback target, so cleanup would skip the
    plain "operator removed a TOML" sweep it exists for.

    Unchanged content is not rewritten, so a boot that provisions nothing new
    doesn't dirty /var. `deployment` is null off ostree; the reader treats that
    the same as no marker at all.
    """
    payload = {"name": name, "deployment": booted_deployment_id()}
    if read_marker(root) == payload:
        return False
    replace_file_atomically(
        marker_path(root),
        json.dumps(payload, indent=2) + "\n",
        default_mode=0o644,
        owner=(0, 0),
    )
    return True


def other_deployments_state(root: Path, name: str) -> str | None:
    """The *other* deployment that owns this state, or None if we may judge it.

    A non-None return is the one and only reason to spare state that otherwise
    looks orphaned; every other outcome — no ostree, no marker, a marker for a
    different workload, a marker naming the booted deployment, a marker naming a
    deployment that no longer exists — returns None and leaves the caller's
    existing orphan logic untouched.

    Two known residuals, both confirmed against ostree's `allocate_deployserial`
    (ostree-sysroot-deploy.c): it starts at serial 0 and bumps only past serials
    of deploy dirs that *currently exist* for that csum, consulting the directory
    listing and never any history.

      - Pruning frees a serial, so redeploying a pruned commit reuses
        `<csum>.0` and revives a marker that pointed at the pruned deployment.
      - The scan is per-osname, so two stateroots can hold the same
        `<csum>.<serial>` — and `deployment_exists` globs across stateroots on
        purpose, because /var may be shared between them.

    Both spare state that could have been swept, i.e. both err toward never
    deleting, which is the direction every uncertainty here resolves to.
    """
    if not deployments_readable():
        return None
    marker = read_marker(root)
    if marker is None:
        return None
    # A marker naming a different workload is a copied or renamed tree, not a
    # provenance record for what is in front of us. Don't let it block a sweep.
    if marker.get("name") != name:
        return None
    stamped = marker.get("deployment")
    if not isinstance(stamped, str) or stamped == booted_deployment_id():
        return None
    return stamped if deployment_exists(stamped) else None
