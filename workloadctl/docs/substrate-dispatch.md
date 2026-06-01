# Substrate dispatch & the day-2 verb surface (design)

Status: **proposal** — not yet implemented. Captures decisions reached while
working out why VM verbs aren't at parity with container verbs, and the
architecture that fixes it at the source. Companion to `workload-bundles.md`
(install surface) and `vm-workloads-direction.md` (guest image). This doc is the
*operating* surface.

## Problem

"What substrate is this workload?" is not first-class. It exists only as the
`WorkloadConfig.is_vm` boolean (`lib/workload_lib.py:242`), tested ad hoc at ~15
sites across `bin/workloadctl`. Each day-2 verb hand-rolls its own
`if config.is_vm: … else: …`, and four verbs forgot to:

| Verb | VM-aware? | What actually happens on a VM |
|---|---|---|
| `status` `list` `logs` `shell` `exec` `info` `update` `rollback` `recreate` `reboot` | yes | branches correctly |
| `stats` | **no** | **broken** — builds container targets from `container_names()` (empty for a VM) and runs `podman stats` at a container that doesn't exist → empty/error |
| `health` | **no** | **wrong answer** — checks 1–2 (service active, user exists) are valid, but check 3 queries `podman.container_status(config.container_name)` (`bin/workloadctl:3626`); a VM has no container, so a *running* VM always reports **unhealthy** |
| `backup` / `restore` | **no** | **correct-but-unsafe-and-wasteful** — `_backup_one` tars the entire `home_dir` (`bin/workloadctl:3769`), which happens to include `system.qcow2`/`data.qcow2`/`nvram.fd`/SSH key. Default path `systemctl stop`s first → a clean *cold* backup by luck. But it also captures the **rebuildable** `system.qcow2`/`.gen-N`/`.image-cache` (the junk-drawer waste), and `--no-stop` tars a **live qcow2 with no fsfreeze/QMP quiesce** → possibly-corrupt image |

The indictment is not the gap, it's that **each VM-unaware verb fails
*differently*** — broken, wrong, or unsafe-by-luck. Nobody decided `health`
should false-negative or that `--no-stop` should risk corruption; those are
accidents of falling through to container-shaped code. With no explicit
substrate dispatch, every verb independently lands somewhere random on the
spectrum from "errors out" to "works by coincidence."

## Goal

Make **substrate** a first-class dimension, orthogonal to the **verb**
dimension, so that:

1. Every `(verb, substrate)` cell is *answered* — a real implementation or an
   explicit, self-documenting "not applicable." **No empty cell, no
   fall-through.**
2. Common (substrate-invariant) verb logic is written once; only the genuinely
   substrate-specific delta is per-substrate.
3. The seam is structured so a verb *could* later be reimplemented with fewer
   dependencies (no Python interpreter) for bootc image-size / minimal-context
   reasons — **kept possible, not built now** (see Non-goals).

## Scope / non-goals

- **CLI/model layer only.** The early-boot generator stays exactly as dumb as it
  is (shell → Python, fast, exit 0, read-only `/var`, no `stat()` fan-out — see
  `llms.txt`). Substrate dispatch lives in the *CLI*, never in the boot path.
- **Polyglot verbs are not built now.** The motivation (bootc size, running a
  verb in a minimal context — initramfs, stripped container, pre-RPM guest) is
  real but parked. We only keep the *contract* language-agnostic so the door
  stays open. Default everything to in-process Python.
- **No reconciler.** State still converges to TOML only on manual
  `recreate`/`update`. This doc does not add a daemon; it does add the
  *visibility* (drift, liveness) that makes the no-reconciler choice livable.
- **Single operator, no migration burden** — same operating context as the
  companion docs.

## Architecture: three layers joined by a router

The trap to avoid: modularizing **by verb** while each verb keeps its own
internal `if substrate == vm`. That doesn't remove the 15 scattered checks — it
relocates them into 15 files, and the capability matrix gets *harder* to enforce
because no single place sees all of it.

So split into two module families joined by a router:

```
verb layer (substrate-INVARIANT)   router / matrix          substrate port (substrate-VARIANT)
─────────────────────────────────  ─────────────────────    ──────────────────────────────────
cmd_status  cmd_stats  cmd_backup  parse args               class Substrate(ABC):
cmd_logs    cmd_health …           resolve substrate            liveness()  resource_usage()
  │                                  from DECLARATION            logs()  exec()  lifecycle()
  │ compose primitives               (TOML, cheap, pure)         reprovision()  capture()
  ▼                                 look up (verb,substrate)     rollback_targets()  …
  Substrate primitives  ◄───────────in the matrix; invoke    ContainerSubstrate / PodSubstrate
                                     or report N/A+reason     BridgeSubstrate / VMSubstrate
```

### Verb categorization

- **Substrate-invariant** (touch TOML/users/creds, not execution — *not* on the
  port): `list`, `validate`, `edit`, `create`, `secret`, `cleanup`, `uid_map`,
  `catalog`/`init`/`duplicate`.
- **Substrate-variant** (genuinely differ — composed from port primitives):
  `status`, `health`, `stats`, `logs`, `shell`, `exec`, `start`/`stop`/`reboot`,
  `update`/`recreate`, `rollback`, `backup`/`restore`, `ports`, `attach`.

### The narrow waist: capabilities, not a method-per-verb

A `Substrate` interface with one method per command produces a ~20-method
interface where each method is mostly copy-pasted scaffolding around a small
delta (`VMSubstrate.status` and `ContainerSubstrate.status` both re-read service
state and format identical output). Instead the port exposes a **small set of
primitives**, and verbs are written **once** and compose them:

```python
class Substrate(ABC):
    def liveness(self) -> Liveness: ...          # running/ready/degraded/down → status, health, list
    def resource_usage(self) -> Usage: ...       # → stats
    def logs(self, opts) -> Iterator[str]: ...   # → logs
    def exec(self, argv): ...                    # → exec, shell, cp
    def open_shell(self): ...
    def lifecycle(self, action): ...             # start/stop/restart/reboot
    def reprovision(self): ...                   # → update/recreate (pull+recreate vs rebuild qcow2)
    def rollback_targets(self) -> list[Target]: ...  # → rollback --list (discoverability)
    def rollback_to(self, target): ...
    def capture(self, consistency) -> Artifact: ...  # → backup (VM impl owns fsfreeze+QMP)
    def endpoints(self): ...                     # → ports
```

`cmd_status` becomes one function: call `substrate.liveness()`, format, exit.
`cmd_backup` calls `substrate.capture(consistency)` — and the VM's `capture` is
the *only* place a VM disk is read, so it owns fsfreeze/QMP quiesce and the
`--no-stop` corruption path becomes **impossible to write** (no code path
bypasses the substrate's own quiesce).

Three payoffs over a method-per-verb interface:

1. **Verbs stay DRY** — arg-parsing, formatting, exit codes live once.
2. **~10 stable primitives, not ~20 churning verbs** — adding a verb usually
   composes existing primitives without touching the interface.
3. **The matrix is *computed*, not maintained** — see below.

This port is also where the first-class concepts from earlier discussion get
*bodies*: `liveness()` **is** the unified liveness vocabulary; `rollback_targets()`
**is** rollback discoverability; `capture(consistency)` **is** the
crash-consistent-vs-app-consistent backup contract.

### Computed capability matrix

A verb declares the primitives it needs. The router checks the resolved
substrate provides them; a missing primitive is an explicit `NotApplicable`
(not an absent method), so the router reports a *reason*:

```
$ workloadctl stats my-vm
stats: not applicable for VMs (no resource_usage primitive)
```

The empty cell becomes structurally impossible **and** self-documenting. This is
the single property that would have caught all three of today's bugs at author
time.

### Dispatch on declaration, not runtime state

The router resolves the substrate from the **TOML** (presence of `[vm]` —
already `config.is_vm`), never from live state (`podman ps`, QMP). The moment the
router queries runtime state to route, verb logic bleeds into it. Router =
cheap, pure, declaration-only. Verbs read runtime state *after* dispatch.

### Keeping the polyglot door open (parked)

Verbs are the language-swappable seam. Designing each verb as a function of
`(parsed args, substrate primitives) → (effects, output)` with crisp boundaries
is *the same discipline* that makes them unit-testable — specify a verb tightly
enough to be a Go binary and you've specified it tightly enough to test with a
fake substrate. Default boundary is in-process Python import; the contract is
kept exec-friendly (stdin/stdout/exit-code shaped) so the router could later exec
an external "verb provider" where bootc size / minimal context justify it. Note
the project already runs this pattern — the shell generator execs the Python
`workload-generate`. Not built now.

## Testability

Today `cmd_` functions reach straight into `subprocess`/podman/systemd/qemu, so
unit-testing means mocking subprocess everywhere. After the split:

- **Verbs** test against a *fake* `Substrate` — assert decision logic and output
  formatting with no podman/qemu.
- **Substrates** test one fake arg set across every primitive — one place to
  audit "does `VMSubstrate` answer every cell."

## Command surface: rationalize columns before building rows

Substrate dispatch fixes the matrix *rows*. Before lifting verbs through the
port, prune and merge the *columns* — every verb you delete or fold is one fewer
orchestrator the port has to support. Lifting `ports`/`uid-map`/`ps` into
per-substrate methods and *then* merging them into `status` means porting verbs
you were about to delete. **Prune columns, then build rows.**

### `validate` vs `verify` — rename, don't merge

Not redundant; the *names* are. They sit on opposite sides of the
declaration/runtime line:

- **`validate`** — static, no root, checks the *declaration* (TOML schema,
  required fields), supports `--all`, runs pre-enable. Substrate-invariant.
- **`verify`** — requires root, checks the *enabled runtime plumbing* (user,
  subuid/subgid, linger, image) and emits `fix=` suggestions. Post-enable
  diagnostic.

The boundary is real and useful; "validate"/"verify" are English near-synonyms
that don't carry the config-vs-runtime axis. Fix is naming: keep `validate` for
config; rename `verify` → `diagnose`/`doctor` (also signals "emits fixes"). Do
**not** merge them.

### Inspection sprawl — collapse facets, keep semantics

Eleven read-only verbs (`list`, `status`, `info`, `health`, `stats`, `ps`,
`ports`, `images`, `uid-map`, `verify`, `validate`) force the operator to
remember *which verb surfaces which facet*. Rule for what survives:

- **Keep** verbs with distinct *semantics*, not just a distinct view:
  `health` (pass/fail **exit code** — scriptable), `stats` (live **streaming**),
  `list` (all-workloads vs one), `validate`/`diagnose` (the two checks above).
- **Fold** pure facets into `status`/`info` sections or flags: `ports`,
  `uid-map`, `ps`. These are "show me facet X of one workload" — make *facet*
  first-class (a section), not a separate verb.

This is the same first-class move as `bundle` and `Substrate`, on the inspection
columns: the relationship "which facet lives where" gets one home (`status`/`info`
sections) instead of living in the operator's head.

### Lifecycle & interact — discoverability, not deletion

`reboot` (keeps overlay) vs `recreate` (destroys overlay) vs `update` vs
`enable`≠`start`: real distinctions, under-discoverable. `shell`/`exec`/`attach`
are three doors in. These are mostly fine; flag `attach` as a disuse suspect.

### Disuse is empirical, and it's the operator's call

For a single-operator tool the honest test of a verb is "reached for it in months
of use," not a priori tidiness. Suspects to confirm against actual usage
(shell history / observation), not delete on aesthetics: `attach`, `ps`, `ports`,
`uid-map`, `network`, `cp`.

## Lifecycle: pet vs cattle as a declared policy

### Problem (the motivating case)

Containers are **cattle by construction**: the generator appends `--rm`
(`generators/workload-generate:705`) and `ExecStart`s a fresh `podman run`, so the
writable overlay is destroyed on every service stop and rebuilt from the image on
every start. This fires on a *plain reboot*, not just `update`. Combined with the
overlay being **invisible** (nothing ever surfaces "what have you changed that
isn't in the image"), the failure mode for the VNC desktop is: tweak system
things live → don't codify them into the Containerfile → reboot or hypervisor
update → weeks of accumulated, undeclared state silently and totally gone.

VMs are the opposite by construction (`data.qcow2` durable, `system.qcow2`
generational). So the substrate already silently *decided* pet-vs-cattle — and
the desktop workloads push containers right into the gap.

### Two questions wearing one name

1. **Substrate reality** — containers lean cattle (immutable image + ephemeral
   overlay + declared volumes); VMs lean pet (a durable disk that accumulates
   state). Already true, just unnamed.
2. **Lifecycle intent** — what the operator *wants* this workload to be, and what
   the verbs should *enforce*. Today implicit; the verbs assume cattle and
   silently destroy state.

Make intent first-class — same move as `bundle` and `Substrate`:

```toml
[workload]
lifecycle = "pet"   # or "cattle" (default)
```

`lifecycle` is a **policy the `Substrate` port honors per-substrate**, not a
mechanism: a VM honors "pet" natively (don't rotate `system.qcow2`, keep
`data.qcow2`); a container honors it via overlay-reuse + snapshot-on-destroy (see
below) and *warns* that full-fidelity pet (installed packages, whole-system
mutation) really wants a VM.

### The fix has two halves — you want both

**Half 1 — *see* it (capture loop back to declarative).** The `diff`/drift verb
(the missing day-2 verb, below) is, for a container, `podman diff <container>` —
every file added/changed/deleted in the overlay vs the image. This turns silent
drift into a reviewable list you fold into the Containerfile / bundle `setup.sh`
on your schedule. The tool's job is not to bless permanent drift; it is to make
drift visible enough that **codifying it is easy instead of forgotten**. The
desktop container is this verb's killer use case.

**Half 2 — *keep* it until codified (persistence + safety net).**

| | Mechanism | Persists | Caveat |
|---|---|---|---|
| A | volume durable paths (`data/`) | session/files/dotfiles | not packages / root-fs changes |
| B | **reuse overlay** — `podman create` once + `start`/`stop`, drop `--rm` | whole overlay across **reboots and bootc updates** (graphroot is under `/var`, which survives) | lost only on explicit `recreate`/`update` |
| C | commit-on-stop → local image | everything | unbounded growth, no reproducibility — escape hatch |
| D | make it a VM | everything, natively | heavier; the natural home for whole-system pets |
| E | **CRIU** checkpoint/restore (`podman container checkpoint`/`restore`, `--export`/`--import` to migrate) | live runtime state incl. process tree + **memory**, not just disk | **headless/CPU-bound only** — can't checkpoint device state (GPU/DRM/KMS, audio, open hardware fds), so desktop workloads can't use it; rootless adds friction. Good for migrating/snapshotting headless jobs, not the desktop-pet case. |

For a container `lifecycle = "pet"` means **B + snapshot-before-destroy**:
`podman commit` the overlay to a timestamped local image before any destructive
verb, so even a deliberate `recreate` onto an improved image is recoverable
("weeks gone" → "restore the pre-update snapshot").

### Declared consequence

Pet reclassifies the workload's `home/`: the bundles doc treats the graphroot as
*rebuildable, backup-skip*, but a pet's overlay is **precious, backup-included**.
The flag carries this implication explicitly (pet ⇒ reuse container +
snapshot-on-destroy + back up `home/`) — not a surprise.

### The sustainable loop

Persist short-term (B) so nothing is lost → periodically `diff` and codify the
keepers into the Containerfile → *then* `recreate` onto the improved image with no
loss. A pet that can rejoin the herd on your schedule, instead of one you're
afraid to reboot.

## Migration: start coarse, let the waist emerge

Do **not** design the perfect ten primitives up front; you'll guess wrong. Strangler-fig:

1. **First cut — lift each `cmd_` body into a per-substrate method almost
   verbatim.** Coarse, some duplication, but the seam goes in cheaply and *each
   lift fixes its parity bug as it lands* (`health` migrates → false-negative
   fixed in the same commit; `stats` → broken path fixed; `backup` →
   `--no-stop` hazard closed). The working system on `main` is never worse.
2. **Watch the duplication.** When `VMSubstrate.status` and
   `ContainerSubstrate.status` are 90% identical, the shared 90% *is* the verb
   orchestrator and the 10% delta *is* the primitive. Extract then.
3. **The narrow waist is the destination, not the starting line.** You arrive at
   the ten primitives by refactoring toward them, guided by where the shared
   code actually is.

## Relationship to the other two designs

All three docs are the same move — **give an implicit relationship a name and a
single home** — on different surfaces:

| Doc | Implicit relationship made first-class | Surface |
|---|---|---|
| `workload-bundles.md` | derives-from (`bundle`), rebuildable-vs-durable (`home/` vs `data/`) | install / layout |
| this doc | substrate (`Substrate` port + computed matrix) | day-2 / operating |
| `vm-workloads-direction.md` | guest update story (bootc, collapses VM rollback into host rollback) | image chain |

They share a model vocabulary (substrate, identity/bundle, state class) but roll
out independently: one model, three rollouts. Welding them into a single
big-bang branch is how a homelab redesign dies unmerged.

## Suggested sequencing

0. **Rationalize the command surface first** (prune columns before building
   rows): rename `verify` → `diagnose`, fold `ports`/`uid-map`/`ps` into
   `status`/`info` sections, confirm disuse suspects against actual usage. Cheap,
   breaks little, and shrinks the set of verbs the port must support.
1. **Define `Substrate` (coarse, verb-shaped) + router + the computed-N/A
   mechanism.** Migrate the three broken verbs first (`stats`, `health`,
   `backup`/`restore`) — highest pain, each lands a fix.
2. **Migrate the rest of the variant verbs**, watching for the shared
   scaffolding.
3. **Extract the narrow-waist primitives** once the deltas are visible; add
   `rollback --list`/targets and a unified `liveness` vocabulary as the first
   primitives that pay for themselves.
4. **Drift visibility + `lifecycle` policy** — the `diff` verb (running vs
   declared; for a container, `podman diff`) makes the no-reconciler choice
   honest *and* is the capture loop for pet workloads. Pair it with the
   `lifecycle = "pet"` field honored per-substrate (container: reuse overlay +
   snapshot-on-destroy; VM: native). The VNC desktop is the motivating case, so
   this can land early if that pain dominates — otherwise after the parity
   fixes.
