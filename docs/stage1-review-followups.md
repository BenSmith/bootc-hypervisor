# Stage 1 review follow-ups (from review of `16b0bc7`, 2026-06-12)

Review of the Stage 1 un-split commit (`16b0bc7`, ADR 001 option 1b) found the
implementation correct and complete; these are the misses. Work on a branch off
`caps-and-security`. **Do not touch `main`.** Each numbered item is one commit.
Run `cd workloadctl && just test` after each; behavior changes get a regression
test.

## 1. Dead code: `build_resource_directives()`

`workloadctl/generators/workload-generate:272` (current HEAD). Stage 1 removed
its only caller (workload-unit resource directives moved to the
`user@<uid>.service.d` drop-in) but left the ~70-line function behind. Delete
it. Verify with a grep that nothing references it; no test changes expected.

## 2. Stale split-era comments in the exec path

`workloadctl/lib/cmd_interact.py:135-137` — `_interactive_exec_flags()` still
justifies its `-t`/no-`-t` behavior in terms of `--cgroups=split` and "the
split healthcheck", both deleted in Stage 1. The *behavior* is still correct
(no pty for non-tty stdin); rewrite the comment to give the current rationale
(piped input hangs with `-t`; plain no-pty exec is the robust scripted path).
Grep the rest of `lib/` and `bin/` for other prose references to
`--cgroups=split` / split healthcheck and fix any stragglers (code references
are already gone — this is comments/docstrings only).

## 3. ~~Spec dropped the `workloadctl.repo` yum repo~~ — resolved, no action

Commit `16b0bc7` also deleted the `/etc/yum.repos.d/workloadctl.repo` file from
the spec. Confirmed with the user 2026-06-12: intentional. Nothing to do.

## 4. Health: detect a user manager outside `workloads.slice`

Gap: `Slice=workloads.slice` only binds when `user@<uid>.service` (re)starts.
`workloadctl enable` regenerates units + daemon-reloads but never restarts the
user manager — correct for fresh enables (manager doesn't exist yet), but if a
workload user's manager is already running under `user.slice` (e.g. a PAM
session as `_wl-X` started it before the drop-in existed), the payload silently
lands outside `workloads.slice` and no cap binds.

Add a placement check to `cmd_health` (container workloads only, user exists,
service active): run
`systemctl show user@<uid>.service -p Slice --value` and compare against the
workload's configured slice (`[resources] slice`, default `workloads.slice`).
Mismatch → an unhealthy check entry, message suggesting
`systemctl restart user@<uid>.service` (after stopping the workload). Skip the
check (don't fail) when `user@<uid>` isn't running. Follow the existing
`health_data["checks"]` shape in `workloadctl/lib/cmd_inspect.py`; add a test
mocking the systemctl call (see how existing health tests mock subprocess).

## 5. Drift: include the `user@<uid>.service.d` drop-ins

`workloadctl/lib/cmd_drift.py` globs only `workload-*.service`, so the
drop-ins — now load-bearing config (slice redirect + all workload-level caps)
— are invisible to `workloadctl drift`. Extend the comparison to
`user@*.service.d/50-workload.conf` under both the temp generate dir and
`/run/systemd/system` (same orphan detection: a live drop-in with no generated
counterpart is drift). Keep the existing tmpdir-prefix normalization in mind —
drop-in content doesn't embed paths today, but normalize anyway for safety.
Extend `tests/test_substrate.py::TestCmdDrift` (drifted drop-in detected;
orphan drop-in detected; in-sync run still exits 0).

## 6. Record the Type=notify re-test status in llms.txt

Plan §1.6 asked for the `Type=notify`/`--sdnotify=conmon` caveat to be
*re-tested under the 1b topology* and the result recorded; llms.txt still
carries the pre-1b text verbatim. **Do not change the default `Type=exec`.**
If a re-test on tp isn't feasible in this pass, add one sentence to the
llms.txt caveat noting it has not been re-tested under 1b and the default
stands. (The old breakage was linger + conmon cgroup migration; the topology
changed, so the result is genuinely unknown.)

## 7. Docs: who performs `on_failure` actions now

`--health-on-failure` used to be pinned to `none` with the action driven by
the (deleted) system-manager healthcheck shim; now podman performs the action
natively from the user manager. Semantics shifted: `restart` is podman
restarting the *container* in place; `kill` kills the container and relies on
the unit's `Restart=on-failure`/`RestartSec=5s` to recover (the
podman-documented pattern for systemd-managed containers). Check
`workloadctl/docs/schema-reference.toml` (`[container.health]` section) and
`docs/workloads.md` and make sure they say which actor performs each action;
add it if absent.

## Still-open verification items — resolved 2026-06-12

- ✅ **Hardening inheritance (ADR spike item 5):** `ProtectSystem=strict` and
  `RestrictAddressFamilies=~AF_ALG AF_PACKET` confirmed on the system unit's
  podman client process. `/usr` is EROFS in the system unit's private mount
  namespace; `Seccomp_filters: 2` active on the podman client PID. The container
  payload has its own mount namespace (different inode) and its own OCI seccomp
  (Seccomp_filters: 3). This was true under split too — clarified in the ADR.
  Recorded in `workloadctl/docs/adr/001-container-cgroup-placement.md` spike item 5.

- ✅ **Health-verified update/rollback (plan §1.4):** `workloadctl update alloy
  --force` restarted the service and waited for podman's native healthcheck under
  real non-split generated units — `✓ alloy: healthy` confirmed. `workloadctl
  rollback` command functional. The `user_manager_placement` check (punchlist
  item 4) also verified live: `user@10008.service in workloads.slice` healthy.
  Recorded in the ADR.
