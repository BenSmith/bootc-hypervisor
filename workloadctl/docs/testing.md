# Testing

The standard this suite is held to, and how to decide what a new test should
look like. Cite this doc when adding or reviewing tests.

## The rung model

| Rung | Proves | Fails when | Where it runs |
|---|---|---|---|
| 1 Logic | parsing/UID/tag/volume/secret/quoting/run-file math | a real logic bug | `just test-unit`, in-process |
| 2 Generation | the generator emits the right unit *text* | intent change **or** bug | `just test`, in-process |
| 3 Runtime | the unit boots & the workload runs correctly | the world moved under you (podman/systemd/pasta) | `just test-runtime`, harness-owned VM (`--target=vm:dev\|gate`) |

Rung 2 is the cheapest to write and the easiest to over-populate — it's where
test *count* is highest and value per test is lowest, because most rung-2
assertions only prove "the string didn't change," not "the string is right."
Rung 3 is the one that catches drift underneath the tool (a Fedora bump to
systemd/podman/pasta silently breaking a load-bearing invariant like cgroup
placement or the pasta stale-pause fix). It lives in `tests/cli_surface/`
as the `runtime`-marked checks (`test_runtime_*.py`), which boot a fresh,
harness-owned VM — **dev** mode (cached Fedora Cloud + local RPM) or **gate**
mode (the real bootc image under swtpm). A throwaway per-run guest is what
keeps these honest: they exercise tight enable/purge sequences that would trip
host-persistence races (UID recycling, stale runtime dirs) on a long-lived
host. When adding a test, know which rung it's proving and don't let rung 2
stand in for rung 3.

Outside the model entirely is `tests/manual/`: checks that need root and boot
VMs of their own, so nothing automatic runs them — see that directory's README.
They are not a fourth rung but an admission that a rung-3 harness cannot reach
everything (`broker_rig.py` boots four guests at once to tell them apart by uid).
Write one only when the property genuinely cannot be proven by a harness-owned
VM, and record when it was last run, because nothing else will notice it rotting.

## The deletion heuristic

Before writing (or keeping) a test, ask: **"if I delete this test, what real
bug reaches production?"**

- If you can name a concrete bug — a wrong UID, a missing `ExecStartPre`, a
  secret landing in `/proc/*/cmdline` — the test earns its keep.
- If the honest answer is "none, it would just let an intentional edit pass
  silently instead of requiring an update to this assertion," it's a
  **change-detector**, not a **contract**: it protects the exact current
  wording of the generator's output, not a behavior anyone relies on. These
  are prime candidates for deletion or folding into a structural oracle
  (below) once one exists to subsume them.
- A test that asserts a warning is emitted for a config mistake is a
  contract, not a change-detector, even though it's checking a string —
  the warning firing (or not) is the behavior a user depends on.

Be conservative when in doubt: mark it CONTRACT and keep it. The cost of one
extra assertion is low; the cost of deleting real coverage silently is not.

## Oracle vs. contract vs. snapshot

Three different shapes of assertion, used for different jobs — don't reach
for the wrong one:

- **Contract test** — asserts one specific, documented behavior a user or
  another part of the system relies on ("`userns=host` emits a warning",
  "a `[vm]` config never emits `[container]` directives"). Narrow and
  intentional; write these by hand per behavior.
- **Structural oracle** — one parametrized test that checks *shape* across a
  matrix of configs (parses as valid systemd, has the required sections,
  contains no generator-owned directive the config didn't request) without
  pinning exact text. Use this to replace a pile of near-duplicate `assertIn`
  change-detectors with one assertion that still catches the same class of
  bug (a malformed section, a leaked internal directive) without breaking on
  every wording change.
- **Snapshot test** — pins exact byte-for-byte output for a small, curated
  set of representative configs. Use sparingly, only where the exact text
  genuinely matters (e.g. regression-locking a specific bug fix); it is the
  most brittle of the three and the easiest to accumulate as change-detector
  mass if over-used.

Reach for contract or oracle by default. Reach for snapshot only when the
literal text is the thing under test.

### Don't commit rendered units — render a baseline instead

Byte-for-byte fixtures for the shipped bundles do not belong in the tree, for two
reasons that will apply again to whatever tempts you next:

- **The output is regenerable in ~0.2s** from the same TOMLs, byte-identically.
  Committing output that cheap to recompute buys nothing a command cannot.
- **An exhaustive corpus that only warns on drift goes stale**, and one that fails
  on drift makes every intentional generator change a two-step ritual. Neither is
  a good trade at this size — with ~70 commits touching the generator or
  `workloads/` in six months, staleness wins by default.

What such a corpus is genuinely for — making a large generator refactor
reviewable — needs nothing committed, because a baseline renders at any commit:

```bash
just snapshot-baseline /tmp/before     # on the pre-refactor commit
# ...refactor...
just snapshot-baseline /tmp/after
diff -ru /tmp/before/units /tmp/after/units
```

`normalize_baseline()` masks the allocated UID, the render dir and the config dir,
so two renders differ only where behavior differs — two baselines taken into
different directories come out byte-identical.

The shipped bundles do get a test, `tests/test_shipped_bundles.py`, asserting
existence rather than text: the generator exits 0 with every bundle enabled at
once, and each bundle gets its sysusers conf plus every unit its mode implies.
That check matters because it is the only one that runs the generator over the
**real** bundles — the
20-fixture matrix in `test_generator_snapshot.py` is synthetic, so it cannot catch
a shipped TOML that crashes the generator or silently drops a per-container unit.

Unit *shape* is enforced by the structural oracle (`test_unit_oracle.py`), and
`test_generator_snapshot.py` gates every fixture through `systemd-analyze verify`.
Neither commits golden files either.

## Ground rules

- **Stdlib-only for shipped code.** `lib/`, `bin/`, `generators/`,
  `libexec/`, and the `unittest` suites under `tests/` depend on stdlib +
  `tomllib` only — no third-party packages (see `llms.txt` "Stdlib-only
  constraint"). The out-of-band acceptance harness (`tests/cli_surface/`) is
  the one exception: it's pytest, because it never ships in the RPM.
- **No GPU, no TPM assumed.** Tests must pass on a plain dev box. Gate any
  hardware-dependent assertion behind a capability check (`shutil.which`,
  `/dev/kvm`, TPM2 presence) and skip cleanly when the capability is absent
  — never fail the suite because a dev box lacks a GPU or a TPM.
