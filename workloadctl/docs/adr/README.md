# Architecture decision records

One file per decision, numbered in the order they were taken. Each answers "why
is it built this way, and what did we give up" — the reasoning that does not
survive in the code itself.

## The house rule

These are maintained as **living records, not an append-only log**. The strict
ADR convention treats an accepted record as immutable and forbids editing it;
that rule exists to preserve what was believed at the time, and `git log -p`
already preserves it here. What immutability cost this directory was the thing an
ADR is actually read for — before this rule was adopted, the current state of a
decision could only be recovered by reconciling a body against three amendments
written months apart.

So:

- **A changed decision gets a new ADR**, and the old one's status line points at
  it. This is the part of the convention that carries real weight: a reversal has
  its own argument and deserves its own record. ADR 006's proxy becoming ADR 008's
  inspector is the worked example.
- **A correction to a decision already made gets folded in.** "The drop-in alone
  does not migrate the manager" is not a new decision, it is the same decision
  described accurately. Edit it in place; do not append an amendment.
- **Keep how a claim was arrived at; drop the ceremony around it.** That a number
  was measured rather than reasoned changes how much a reader should trust it, so
  say so. Run logs, pass counts, verification dates and host names are provenance
  git already holds — leave them out.
- **The status line is one line.** If it needs a changelog, a new ADR is owed.

## Shape

Title, one-line status, then Context / Decision / Rationale / Consequences. Two
optional sections earn their place when there is something to put in them: what
the mechanism actually requires (constraints invisible from the config), and what
running it corrected (findings that would not fail a unit test — those are the
traps worth the most to a later reader).

## The records

| # | Decision | Status |
|---|---|---|
| [001](001-container-cgroup-placement.md) | Container cgroup placement: redirect each workload's user manager into `workloads.slice` | implemented |
| [002](002-vm-bridge-host-level-network-config.md) | VM managed-bridge config is host-level, not per-VM | superseded by 006 |
| [003](003-vm-rollback-non-destructive.md) | VM rollback rotates the current disk out instead of consuming it | implemented |
| [004](004-secret-export-versioned-crypto.md) | `secret export` uses a versioned, integrity-protected format | implemented |
| [005](005-var-state-deployment-provenance.md) | `/var` state records the deployment that provisioned it | implemented |
| [006](006-vm-networking-passt-not-managed-bridge.md) | VM networking uses passt; the workload uid is the network identity | implemented |
| [007](007-per-workload-credential-broker.md) | Credentials live in a per-workload broker, selected per host | implemented |
| [008](008-transparent-egress-inspection.md) | VM egress is inspected transparently, and terminated by default | implemented |
