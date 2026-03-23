# Generator Rewrite: Obstacles and Solutions

The workload generator was originally a Python script installed directly as a systemd generator at `/usr/lib/systemd/system-generators/workload-generator`. It was rewritten into a two-stage architecture:

1. **Shell wrapper** (`generators/workload-generator-wrapper`) — installed as the systemd generator, creates a oneshot service
2. **Python script** (`generators/workload-generate`) — installed at `/usr/libexec/workload-generate`, runs as a normal service

This document records every obstacle encountered during the rewrite.

---

## 1. systemd 258 generator sandbox freeze

**Problem:** systemd 258 runs generators inside a sandboxed namespace. The Python script triggered "Failed to fork off sandboxing environment: Protocol error" — PID 1 froze entirely, preventing boot. There is no runtime knob to disable generator sandboxing (see [systemd/systemd#39354](https://github.com/systemd/systemd/issues/39354)).

**Solution:** Replace the Python generator with a minimal shell wrapper that runs in under a millisecond. The wrapper creates a `workload-generate.service` oneshot that runs the Python logic later, outside the generator sandbox.

## 2. NSS/userdbd D-Bus timeout

**Problem:** The Python script calls `pwd.getpwnam()` and `pwd.getpwall()` to look up existing users. On systemd 258+, `nss-systemd` tries to contact `systemd-userdbd` via D-Bus for these lookups. Since generators (and the early oneshot) run before userdbd is available, each NSS call blocks for ~45 seconds waiting for D-Bus, then the cumulative timeout cascades into a fatal boot freeze.

**Solution:** Set `SYSTEMD_NSS_BYPASS_BUS=1` in the environment before any `pwd` calls. This tells nss-systemd to skip D-Bus and fall back to reading `/etc/passwd` directly.

## 3. SELinux `systemd_generic_generator_t` restrictions

**Problem:** Generators run under `systemd_generic_generator_t` SELinux context, which only permits writes to the generator output directories (argv[1-3]). The original generator wrote sysusers configs to `/run/sysusers.d/`, causing AVC denials.

**Solution:** Write sysusers configs to the generator output directory (`/run/systemd/system/`) instead. Once moved to the oneshot service pattern, this constraint no longer applies, but we kept the output in `/run/systemd/system/` for simplicity.

## 4. Generator /var access blocked at boot

**Problem:** The original generator accessed `/var/lib/workloads/` for UID tracking files (`.assigned-uid`) and used a lockfile at `/var/lock/workload-uid.lock`. Generators run before `/var` is mounted, so all these writes failed silently or caused errors. This also triggered SELinux AVCs since generators aren't allowed to write to `/var`.

**Solution:** Removed all `/var` access from the generator. UID lookup uses only `pwd.getpwnam()` (reads `/etc/passwd`). UID allocation for new workloads is done in-memory by `get_next_uid()`. User creation and all `/var` writes are deferred to `workload-ensure-user`, which runs at service start time when `/var` is available.

## 5. Both Python files treated as generators

**Problem:** After creating `workload-generate` alongside the original `workload-generator` in the `generators/` directory, the Containerfile initially installed both to `/usr/lib/systemd/system-generators/`. systemd ran both as generators.

**Solution:** Install only the shell wrapper as a generator. The Python script goes to `/usr/libexec/workload-generate` and is invoked by the oneshot service.

## 6. User= chicken-and-egg

**Problem:** systemd resolves `User=` in service files BEFORE running any `ExecStartPre` commands — even those with the `+` (root) prefix. If the workload user doesn't exist yet, the service fails immediately with error 217/USER. This made it impossible to create the user and run the workload in a single service.

**Solution:** Two-service pattern per workload:
- **Setup service** (`workload-{name}-setup.service`) — runs as root, calls `systemd-sysusers` and `workload-ensure-user` to create the user
- **Main service** (`workload-{name}.service`) — has `Requires=` and `After=` on the setup service, guaranteeing the user exists before systemd evaluates `User=`

## 7. systemd-sysusers UID range syntax

**Problem:** The sysusers config used range syntax `10000-52948` for UID allocation. systemd-sysusers does not support range syntax — it expects a specific numeric UID or `-` for auto-allocation. Error: "Failed to parse UID: '10000-52948'".

**Solution:** Implemented `get_next_uid()` in the Python script to allocate specific UIDs. It scans `/etc/passwd` for UIDs already in the 10000-52948 range and picks the next free one, tracking allocations within the current run to avoid collisions.

## 8. EnvironmentFile missing at boot

**Problem:** `EnvironmentFile=/run/workload-env/workload-{name}.env` caused service startup failure because the file doesn't exist until the setup service creates it.

**Solution:** Added the `-` prefix: `EnvironmentFile=-/run/workload-env/workload-{name}.env`. The dash makes the file optional — systemd silently continues if it's missing.

## 9. ProtectSystem=strict blocking rootless podman

**Problem:** `ProtectSystem=strict` makes the entire filesystem read-only except `/dev`, `/proc`, `/sys`. Rootless podman needs to write to `/run/user/{uid}/` for its XDG_RUNTIME_DIR, which was blocked.

**Solution:** Added `/run/user/` to `ReadWritePaths` in the generated service files.

## 10. Docker Hub pull timeouts

**Problem:** The test VM pulled container images from Docker Hub. With a 300-second VM timeout, image pulls frequently timed out or hit rate limits, causing test failures unrelated to the code under test.

**Solution:** Switched test workloads to use a local registry at `192.168.0.64:5000` with `pull = "missing"` (only pull if not already present).

## 11. Insecure registry configuration

**Problem:** The local registry runs over HTTP, but podman defaults to requiring HTTPS for all registries.

**Solution:** Added a `registries.conf.d/local-registry.conf` in the test VM Containerfile:
```
[[registry]]
location = "192.168.0.64:5000"
insecure = true
```

## 12. Per-user container storage

**Problem:** Rootless podman stores images per-user. Pulling an image as one user doesn't make it available to other users. The test script initially only pulled once, so most workload users had no image available.

**Solution:** Pre-pull the container image for each workload user individually before starting services.

## 13. runuser chdir permission denied

**Problem:** `sudo -u _wl-foo podman exec ...` (and `runuser -u`) failed with "cannot chdir to /var/home/ben: Permission denied". These commands try to chdir to the *caller's* current working directory, which the workload user can't access.

**Solution:** Explicitly `cd "$home"` to the workload user's home directory before calling `runuser -u`:
```bash
cd "$home" && runuser -u "$user" -- env XDG_RUNTIME_DIR="/run/user/${uid}" \
    podman exec "workload-${name}" "$@"
```

## 14. Secret leakage false positive in tests

**Problem:** The test for secret leakage (`grep -r "$secret" /proc/*/cmdline`) always found matches because grep's own process contains the secret string as a command-line argument, visible in `/proc/self/cmdline`.

**Solution:** Read the secret pattern from a temp file (`grep -f`) so it never appears in grep's argv, and exclude `/proc/self/` and `/proc/thread-self/` from results:
```bash
tmpf=$(mktemp)
echo -n "$secret" > "$tmpf"
grep -r -f "$tmpf" --include='cmdline' -l /proc/*/cmdline 2>/dev/null \
    | grep -v -E '^/proc/(self|thread-self)/'
rm -f "$tmpf"
```

## 15. Oneshot service ordering

**Problem:** The initial oneshot service was ordered `Before=sysinit.target`, which is too early — `/etc/passwd` may not be writable yet and basic system services aren't available.

**Solution:** Changed to `After=sysinit.target Before=basic.target`, ensuring the filesystem is fully set up before the generator service runs, while still completing before most services start.

## 16. Podman build caching

**Problem:** After modifying `run-vm-tests.sh`, rebuilding the test VM image with `podman build` used cached layers and didn't pick up the changes.

**Solution:** Added `--no-cache` to the `podman build` command in the test-vm-build recipe.

## 17. Shell wrapper for secret env vars replaced by workload-write-env

**Problem:** The original generator embedded secrets directly into the `ExecStart` command line using a shell wrapper (`/bin/sh -c "exec podman run --env KEY=\"$(<${CREDENTIALS_DIRECTORY}/name)\" ..."`). This was fragile — it required careful double-quote escaping for systemd, nested credential existence checks in the shell wrapper, and the secrets appeared in `/proc/*/cmdline` since they were command-line arguments to podman.

**Solution:** Created a separate `workload-write-env` helper that runs as `ExecStartPre=+` (root). It reads `${SECRET:name}` references from the TOML config, resolves them from `$CREDENTIALS_DIRECTORY`, and writes `KEY=value` lines to a file at `/run/workload-env/workload-{name}.secrets` (mode 600, owned by the workload user). The generator now passes `--env-file` pointing to this file instead of inlining secrets. Plain (non-secret) env vars continue to use `--env` arguments.

## 18. Generator must never block boot

**Problem:** Any unhandled exception in the generator (or the oneshot that replaced it) would block boot entirely. A bug in workload config parsing, a missing import, or a filesystem error could make the system unbootable.

**Solution:** The main() function is wrapped in try/finally and always exits 0. Per-workload errors are caught individually so one broken config doesn't prevent other workloads from generating. The shell wrapper generator also always succeeds — it just creates a service file, which can fail gracefully later. Additionally, an `emergency.target.d` drop-in ensures the emergency shell remains accessible for recovery.

## 19. Credential files don't exist at first boot

**Problem:** TPM-encrypted credentials (`/etc/credstore.encrypted/`) don't exist until they're created after the first boot with a working TPM. Services with `LoadCredentialEncrypted=` that referenced these files failed on first boot, and the failure propagated through `Requires=` to block dependent services.

**Solution:** In the test script, credentials are encrypted after boot, then all workload services and their setup services are stopped, reset-failed, and restarted via `daemon-reload`. This simulates the real workflow where credentials are provisioned after initial image deployment.

## 20. libvirt console log file permissions

**Problem:** Pre-creating the serial console log file before `virt-install` caused permission errors because libvirt's qemu user couldn't write to a file owned by the calling user.

**Solution:** Let libvirt create the console log file itself via `--serial file,path="$CONSOLE_LOG"`, then tail it after VM creation. The cleanup trap removes the file on exit.

## 21. bootc kargs.d format

**Problem:** Attempted to add `console=ttyS0` kernel argument via bootc's `kargs.d` configuration. Tried `[kargs]` (invalid — bootc expects a string list, not a TOML map) and `[[kargs]]` (also invalid). The format wasn't well-documented.

**Solution:** Removed the kargs.d file entirely. bootc-image-builder already adds `console=ttyS0` by default for qcow2 images, so the serial console works without explicit configuration.
