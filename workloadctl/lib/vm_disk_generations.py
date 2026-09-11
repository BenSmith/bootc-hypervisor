"""The system disk's generations: rotate the live one out, keep a bounded few.

Every generation is a full copy of system.qcow2 at the moment an update
replaced it. The freshest is the restore point for the build that made it, so
it is never pruned; `keep` bounds the older ones alongside it.
"""
from pathlib import Path

from helper_main import log


def rotate_generations(home_dir: Path, keep: int) -> Path | None:
    """Rename existing system.qcow2 to system.qcow2.gen-N and prune old gens.

    Returns the path the active disk was rotated to (so callers can restore
    it on build failure), or None if there was nothing to rotate.
    """
    system_disk = home_dir / "system.qcow2"
    if not system_disk.exists():
        return None

    # Find existing gen files
    gens = sorted(
        int(p.suffix[5:])
        for p in home_dir.glob("system.qcow2.gen-*")
        if p.suffix[5:].isdigit()
    )
    next_gen = (max(gens) + 1) if gens else 1

    target = home_dir / f"system.qcow2.gen-{next_gen}"
    log(f"  Rotating system.qcow2 → {target.name}")
    system_disk.rename(target)

    # Prune oldest gens beyond retention limit. Never prune the generation we
    # just created — it's the only restore point if this build fails — so it is
    # excluded from the candidate set below and always kept. `keep` therefore
    # bounds the number of *older* generations retained alongside it, leaving
    # keep + 1 system.qcow2.gen-* files in total (matches vm.rollback_keep docs).
    all_gens = sorted(
        int(p.suffix[5:])
        for p in home_dir.glob("system.qcow2.gen-*")
        if p.suffix[5:].isdigit() and int(p.suffix[5:]) != next_gen
    )
    to_prune = all_gens[:-keep] if len(all_gens) > keep else []
    for gen_n in to_prune:
        old = home_dir / f"system.qcow2.gen-{gen_n}"
        log(f"  Pruning old generation: {old.name}")
        old.unlink(missing_ok=True)
    return target
