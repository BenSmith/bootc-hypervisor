# workloadctl CLI-surface acceptance harness

End-to-end acceptance tests for `workloadctl`. Provisions real workload
fixtures, runs every verb against every applicable substrate, and prints a
**verb × substrate PASS/FAIL/SKIP/NA matrix**.

Runs on a controller (your dev host). Executes everything over SSH against a
target Fedora system (specified with `--target=user@host`). Nothing is
installed on the target beyond what `workloadctl` already ships.

The same harness also hosts the **runtime rung** (`test_runtime_*.py`,
`runtime`-marked): checks that boot a fresh, harness-owned VM
(`--target=vm:<mode>`, see below) and assert live runtime invariants
(effective linger, cgroup placement, secret secrecy, the pasta stale-pause
fix, …). Those tests are meaningful *only* against a throwaway VM, so
`conftest.py` deselects every `runtime`-marked test unless the target starts
with `vm:` — running the suite against a plain `user@host`/`local` target
skips them automatically.

## Prerequisites

### Controller (where you run pytest)

```
pip install --user pytest
```

Optional for HTML reports:
```
pip install --user pytest-html
```

### Target

- `sshd` running, controller's SSH key authorized
- Passwordless sudo configured
- `workloadctl` installed (via RPM or `--deploy` flag below)
- For VM cells: `/dev/kvm` present (bare metal or nested KVM)
- For `clitest-vm-bridged` cell: `br0` bridge up

## Running

`--target` is required. All invocations from the repo root (or workloadctl/).

```sh
# Run everything against a target host
pytest workloadctl/tests/cli_surface/ --target=user@host

# Or via just (from workloadctl/)
just test-cli user@host

# Run against controller directly (no SSH)
pytest workloadctl/tests/cli_surface/ --target=local

# Deploy current workloadctl tree to target first, then test
pytest workloadctl/tests/cli_surface/ --target=user@host --deploy

# Deploy to a VM by IP
pytest workloadctl/tests/cli_surface/ --target=user@<vm-ip> --deploy

# Container tests only (skip VM — much faster)
pytest workloadctl/tests/cli_surface/ --target=user@host -m "not vm and not slow"

# VM substrate only
pytest workloadctl/tests/cli_surface/ --target=user@host -m vm

# Just the secret area
pytest workloadctl/tests/cli_surface/test_secret.py --target=user@host

# One verb group, one topology
pytest workloadctl/tests/cli_surface/ --target=user@host -k "lifecycle and single"

# One verb, all substrates
pytest workloadctl/tests/cli_surface/ --target=user@host -k recreate

# Introspection verbs only (read-only, fast)
pytest workloadctl/tests/cli_surface/test_introspect.py --target=user@host

# Skip slow tests (VM boot, image pull)
pytest workloadctl/tests/cli_surface/ --target=user@host -m "not slow"

# With HTML report
pytest workloadctl/tests/cli_surface/ --target=user@host --html=report.html --self-contained-html
```

### Runtime rung

The `runtime`-marked checks boot a VM the harness owns and tears down per run,
so they never touch a long-lived host (and can't trip host-persistence races
like UID recycling). Two fidelity modes, selected by `--target=vm:<mode>`:

- **dev** (`vm:dev`) — a cached Fedora Cloud image + the local workloadctl RPM,
  rsynced in and `just rpm-install`ed. Fast; the default.
- **gate** (`vm:gate`) — the *real* hypervisor bootc image, built via
  bootc-image-builder and booted under swtpm (emulated TPM2). Highest fidelity;
  exercises the shipped image and the TPM-backed secret path.

```sh
just test-runtime                 # WLRT_MODE=dev (default)
WLRT_MODE=gate just test-runtime  # gate
just test-all-runtime [target]    # CLI surface + runtime rung (dev + gate), on a KVM host
just test-all-runtime-remote HOST # same, driven from your laptop against a prepared host (e.g. tp)
```

Both skip cleanly on a box without `/dev/kvm` + QEMU (and gate additionally
needs OVMF + swtpm + the source images). The harness lives in
`../runtime/` (`vmlaunch.py` boots/snapshots the guest, `vmtarget.py` is the
`VMTarget`). Set `WLRT_KEEP_VM=1` to leave a failed run's guest running for
inspection.

## Layout

```
workloadctl/tests/cli_surface/
  conftest.py             --target/--deploy options, Target fixture,
                          session purge, matrix-summary hook
  target.py               Target abstraction (run/put/capabilities)
  fixtures.py             workload-provisioning pytest fixtures
  workloads/              fixture TOMLs (clitest-*.toml)
  test_introspect.py      list, info, status, health, diagnose, validate,
                          drift, logs, stats, images
                          (ports/uid-map data tested via info --json)
  test_lifecycle.py       create, enable, start, stop, disable(+--purge),
                          edit, reboot, recreate
  test_exec.py            exec, cp, attach, shell
  test_secret.py          secret create/list/show/rotate/export/import/delete
  test_data.py            backup(+--all/--no-stop), restore
  test_update_rollback.py update(+--all/--force), rollback
  test_network.py         network create
  test_cleanup.py         cleanup (dry-run + --apply + --json)
  test_runtime_*.py       runtime rung — boot a VM, assert live invariants:
                          smoke, hardening, caps, cgroup, config_drift,
                          health, linger_runtime_dir, notify_misattribution,
                          pasta, pod_reenable, secret, secret_tmpfs, vm_smoke,
                          vm_hostkey (S1 pin), vm_restart (O6 on-reboot)
  workloads/rt-*.toml     runtime-rung fixtures (rt-basic/caps/notify/pod/vm/
                          vm-reboot)
  README.md               this file
```

## Markers

| Marker        | Meaning                                        |
|---------------|------------------------------------------------|
| `container`   | Exercises the container substrate              |
| `vm`          | Requires `/dev/kvm` (skips otherwise)          |
| `slow`        | Long-running: VM boot, image pull              |
| `interactive` | Pty/shell smoke tests (lower assurance)        |
| `mutating`    | Modifies workload state                        |
| `destructive` | Permanently removes state (purge, delete)      |
| `runtime`     | Boots a harness-owned VM; auto-deselected unless `--target=vm:<mode>` |

## Options

| Option       | Default  | Description                              |
|--------------|----------|------------------------------------------|
| `--target`   | required | SSH destination (`user@host`), `local`, or `vm:<dev\|gate>` (runtime rung) |
| `--deploy`   | off      | rsync + rpm-install before testing       |
| `--key-type` | `auto`   | Secret encryption: auto/tpm2/host        |

## Fixture scoping (shared vs. fresh)

Provisioning a workload (enable → wait active → wait container up → purge) is
the dominant cost in this suite, so workload fixtures come in two flavours:

- **Shared, session-scoped** — `clitest_single`, `clitest_pod`,
  `clitest_bridge`, `clitest_host`. Provisioned once per session and reused by
  every *read-only* test (introspection, exec/cp, logs, cleanup-no-orphan, …).
  These tests never mutate the workload, so one instance serves all of them.
- **Fresh, function-scoped** — `fresh_single`, `fresh_bridge`. A brand-new,
  isolated workload per test, for *mutating* tests (stop/start/recreate/edit,
  backup, update/rollback, network create). They use distinct names + host
  ports (`clitest-fresh-*`) so a fresh instance can run alongside the long-lived
  shared one without colliding.

When adding a test: if it only inspects a workload, request the shared
`clitest_*` fixture; if it changes workload state, request a `fresh_*` fixture
(add one for the topology if it doesn't exist yet).

## Idempotency

A session-scoped autouse fixture purges all `clitest-*` workloads at session
start and end. Running twice back-to-back is safe. The user's `alloy.toml`
and any other non-`clitest-*` workloads are never touched.

## Matrix output

At the end of the run, pytest prints a `verb × substrate` matrix:

```
================== verb × substrate matrix ==================
VERB           container   vm
------------------------------------------------------------
backup         PASS        PASS
cleanup        PASS        —
create         PASS        —
...
stats          PASS        PASS (exit 0, N/A message)
```

Cells marked `FAIL` are likely workloadctl bugs (e.g. an unguarded verb
crashing on the wrong substrate). A findings section lists them.

An empty cell means *nobody declared it*, not "untested" — the matrix is
hand-declared, and which cells actually run depends on the host and the marker
filter. What is not optional is the declaration: `matrix_cells.py` lists every
cell this harness must declare, and `tests/test_cli_surface_matrix.py` (rung 1,
so it runs in the normal `just test` with no target and no KVM) fails if the
declarations drift from it in either direction. Adding coverage is two lines —
the test, and its cell in `matrix_cells.py`; removing coverage cannot be silent.
Cells built at runtime (f-strings, e.g. the parametrized topology test) are
invisible to that scan, so they are registered in `DYNAMIC_CELLS` instead.

## Fixture TOMLs

All test workloads are named `clitest-<topology>` and live in `workloads/`.
They are installed to `/etc/workloads.d/` on the target at test setup and
removed at teardown. The user's `alloy.toml` is never touched.

| Fixture               | Topology                    | Port   |
|-----------------------|-----------------------------|--------|
| `clitest-single.toml` | single container, pasta net | 19080  |
| `clitest-pod.toml`    | pod mode, 2 containers      | 19081  |
| `clitest-bridge.toml` | bridge mode, 2 containers   | 19082  |
| `clitest-host.toml`   | single, host networking     | 19083  |
| `clitest-secret.toml` | single, references secret   | 19084  |
| `clitest-broken.toml` | invalid schema (negative)   | —      |
| `clitest-vm.toml`     | VM, NAT bridge              | —      |
| `clitest-vm-bridged`  | VM, br0 LAN bridge          | —      |

Runtime-rung fixtures (`rt-*.toml`, used only by `test_runtime_*.py` in a VM):

| Fixture         | Purpose                                      |
|-----------------|----------------------------------------------|
| `rt-basic.toml` | baseline single container (most runtime checks) |
| `rt-caps.toml`  | capability/hardening assertions              |
| `rt-notify.toml`| `Type=notify` misattribution regression      |
| `rt-pod.toml`   | pod-mode re-enable                           |
| `rt-vm.toml`    | nested `[vm]` workload smoke; SSH host-key pin (S1) |
| `rt-vm-reboot.toml` | `[vm].restart="on-reboot"` reboot-vs-poweroff (O6) |

## Notes on interactive verbs

`shell` and `attach` are smoke-tested via `echo exit | timeout N workloadctl ...`
or `timeout N ... || true`. They verify: no Python traceback, process exits.
Full interactive assertion is not possible in a subprocess harness; these are
explicitly marked `interactive` and documented as smoke-grade.
