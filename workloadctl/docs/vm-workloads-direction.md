# VM workloads: bootc-guest direction (design)

Status: **direction**, not yet implemented. Captures where VM workloads should
head and why. Companion to `workload-bundles.md`.

## Where we are

A `[vm]` workload boots a stock Fedora Cloud image and uses cloud-init's
user-data to *provision* it at first boot: clone the hypervisor repo, build the
workloadctl RPM in-VM, install the sidecar workloads (forgejo/caddy/alloy/avahi)
which then run as containers via an in-VM workloadctl. Disk model is good:
disposable `system.qcow2` (rebuilt on `update`, generational `.gen-N` rollback)
+ durable `data.qcow2` (survives rebuilds, removed only by `disable --purge`).

The Fedora-Cloud-plus-bootstrap approach was a **deliberate soft surface for
prototyping** the VM-workload concept. It worked; now graduate it.

## The inconsistency to fix

The host is rigorously immutable/declarative (bootc). The VM guest is
imperative-bootstrap-on-first-boot — its real "image" is "Fedora Cloud + a build
script." Every `update` re-clones and rebuilds from repo HEAD: slow, network-
dependent, not reproducible unless everything is pinned.

## Direction: make the guest a bootc image too

We already build bootc qcow2s. If the guest *is* one:

- **cloud-init shrinks from provisioning to config-seeding.** workloadctl and the
  workload TOMLs bake into the image (same as the host); cloud-init only seeds
  genuinely per-instance bits — hostname, otel host, runner token.
- **The guest gets the host's update story.** `bootc upgrade` + rollback inside,
  instead of bespoke "rotate system.qcow2 + re-bootstrap." The generational disk
  rollback becomes belt-and-suspenders rather than the primary path. Update/
  rollback becomes uniform across host and guest.
- **No runtime build.** The fragile clone-and-compile-at-boot disappears;
  workloadctl is already in the image.
- **It reuses the pattern we already run.** Host images are a layered chain
  (`fedora-bootc-minimal → hypervisor-bootc → nvidia/amd`). A guest is just
  another branch off the base.

Cost: building/publishing a guest image (more CI), and the cloud-init
`template_vars` convenience narrows to real config seeding. Same trade we already
made for the host, for the same reasons.

## The runner question

Today the forge VM also runs a native forgejo-runner so `podman build` works
without container-in-container. An *external* native runner was tried and judged
"more involved" — largely because it meant a second machine that imperatively
built its own environment plus the registration dance.

Reframe:

- **Contention is not the reason to split.** Single operator, no concurrent
  build-vs-browse — that argument is dead.
- **Lifecycle/fate is the real reason.** Forge = durable stateful pet (holds git
  data, wants to be boring/always-up). Runner = disposable stateless cattle
  (churned often, rebuilt freely). Bundling opposite lifecycles shares their
  fate (a bad build can wedge the forge UI you'd use to cancel it) and their
  update cadence (runner tooling churn risks the repo store).
- **bootc changes the calculus.** The reason all-in-one won was bootstrap
  complexity, which bootc removes for *both* topologies. As a bootc layer a
  runner becomes thin (`base → +podman +forgejo-runner +registry-CA-trust`), and
  the `[vm]` TOML already supports runner-only VMs (`REGISTER_RUNNER`/
  `FORGEJO_URL`). So the split drops to "one more thin layer + one more TOML."

### Plan

1. **Build the forge as a bootc guest first** — the agreed win and the bigger
   lift.
2. **Keep the runner integrated for now, but as a separable layer, not welded.**
   Structure the images as base + forge layer + runner layer (currently
   co-installed) so the runner can be lifted into its own image/VM later with no
   rework.
3. **Split when a real trigger appears** — a build wedges the forge once, or you
   want fresh-per-job runners. Endpoint worth pointing the seam at: ephemeral
   forgejo-runner + the already-disposable `system.qcow2` = "runner as true
   cattle," reset per job or on a cadence.

Net: bootc-guest makes both the integrated VM cleaner *and* the eventual split
cheap, so the runner decision can be deferred instead of pre-paid either way.

## Related things to watch (not VM-specific)

- **Backup/restore parity** is the weakest-tested, highest-pain surface — now
  spanning container volumes (tar), VM qcow2 (needs guest-agent fsfreeze + QMP
  quiesce), and the host. Most likely place the VM path silently lacks the
  container path's features.
- **Three rollback mechanisms** (container image / VM qcow2 / host bootc) with no
  unified mental model — bootc-guest collapses the VM one into the host one.
- **Observability parity** — confirm the metrics exporter covers VMs and
  multi-container pods, not just single containers.
- **No reconciliation loop** — state converges to TOML only on manual
  `recreate`/`update`. Almost certainly correct for a homelab, but should be a
  deliberate choice.
