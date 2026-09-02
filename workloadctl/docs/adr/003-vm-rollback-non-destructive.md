# ADR 003: VM rollback is non-destructive (rotate, don't consume)

**Status:** Implemented. `VMSubstrate.rollback_to()` rotates the current disk out
to a new generation before swapping the target in; `rollback_keep` prunes the
rotated-out disk like any other generation.

## Context

VM rollback and container rollback diverged:

- **Container** `rollback_to` retags the saved rollback image as the working
  image, so both the current and the rolled-back image survive and a subsequent
  roll-forward is possible.
- **VM** `rollback_to` was `gen_path.replace(system.qcow2)` — a rename that
  **overwrote** the current `system.qcow2` without saving it and **consumed** the
  `gen-N` snapshot. The pre-rollback state was destroyed, the generation list
  shrank by one per rollback, and there was no roll-forward.

The only comment at that call site explained why the VM is stopped first (QEMU
holds the qcow2 open; renaming it out from under a running guest is unsafe).
Nothing justified the destructive consume. `rollback_keep` already bounds how
many generations are retained on update, so disk usage was not the rationale.
The behaviour read as an incidental `.replace()` shortcut, not a design.

## Decision

**VM rollback is non-destructive, matching container rollback semantics.**
Before activating the target generation, rotate the current `system.qcow2` out to
a new `system.qcow2.gen-<next>`, then swap the target in. The generation list is
preserved (modulo `rollback_keep` pruning) and roll-forward is possible.

## Rationale

Rollback should be reversible; a destructive rollback that also shrinks the
recovery set is a footgun, especially for pet VMs whose disk is the durable
payload. Container rollback already got this right, and two substrates behind one
CLI verb should not differ in whether the verb loses data. `rollback_keep`
provides the disk bound, so keeping the pre-rollback disk as a generation is safe
and pruned normally.

## Consequences

- Each rollback adds one generation (the rotated-out current disk), which
  `rollback_keep` prunes like any other — except the rotated one itself, which is
  exempt from the prune of that same run so a rollback cannot delete the state it
  just preserved.
- `rollback_targets()` lists the rotated-out disk as a normal generation.
- Rotation opens a window where `system.qcow2` does not exist: if swapping the
  target in fails (ENOSPC, permissions), `rollback_to` renames the rotated disk
  back before surfacing the error, so a failed rollback still leaves a bootable VM.
- Implemented in `VMSubstrate.rollback_targets()` / `rollback_to()`
  (`lib/substrate_vm.py`).
