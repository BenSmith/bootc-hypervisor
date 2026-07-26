# ADR 003: VM rollback is non-destructive (rotate, don't consume)

**Status:** **Implemented** 2026-07-03 (code review 2026-07 follow-up, item D2).
Implemented 2026-07-03 (carded as B17) — `VMSubstrate.rollback_to` rotates the
current disk out to a new generation before swapping the target in; `rollback_keep`
prunes the rotated-out disk like any other generation.

**Date:** 2026-07-03.

## Context

VM rollback and container rollback diverge:

- **Container** `rollback_to` (`substrate.py`) retags the saved rollback image as the
  working image (`pod.tag(...)`) — both the current and the rolled-back image survive,
  so a subsequent roll-forward is possible.
- **VM** `rollback_to` (`substrate.py`, VMSubstrate) is
  `gen_path.replace(system.qcow2)` — a rename that (a) **overwrites** the current
  `system.qcow2` without saving it and (b) **consumes** the `gen-N` snapshot (moves it
  away). Net effect: the pre-rollback state is destroyed, the generation list shrinks
  by one per rollback, and there is no roll-forward.

The only comment at that call site explains why the VM is stopped first (QEMU holds
the qcow2 open; renaming it out from under a running guest is unsafe). Nothing
justifies the destructive *consume*. `rollback_keep` already bounds how many
generations are retained on update, so disk usage is not the rationale. The behavior
reads as an incidental `.replace()` shortcut, not a deliberate design.

## Decision

**VM rollback is non-destructive, matching container rollback semantics.**

Before activating the target generation, **rotate the current `system.qcow2` out to a
new generation** (e.g. `system.qcow2.gen-<next>`), then swap the target in. The
generation list is preserved (modulo `rollback_keep` pruning), and roll-forward is
possible.

## Rationale

Rollback should be reversible; a destructive rollback that also shrinks the recovery
set is a footgun, especially for pet VMs whose disk is the durable payload. Container
rollback already gets this right — the two substrates should behave consistently.
`rollback_keep` provides the disk bound, so keeping the pre-rollback disk as a
generation is safe and pruned normally.

## Consequences

- Each rollback adds one generation (the rotated-out current disk); `rollback_keep`
  pruning must apply to the rotated disk like any other generation.
- `rollback_targets()` will list the rotated-out disk as a normal generation.
- Implemented in `VMSubstrate.rollback_targets()` / `apply_rollback()`
  (`lib/substrate_vm.py`).
