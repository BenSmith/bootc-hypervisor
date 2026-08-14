# virtual-forgejo

A single Fedora 44 VM that runs both Forgejo (containerized via
workloadctl inside the VM) and a native `forgejo-runner` systemd
service. Replaces the older two-VM split (`forgejo-vm` + `runner-vm`):
co-locating runner and forge lets the runner do `podman build` without
container-in-container, and saves a VM.

```
host (workloadctl)
└── workload-virtual-forgejo.service     [VM, raw QEMU]
    ├── workloadctl inside the VM
    │   ├── workload-forgejo.service     [container: codeberg.org/forgejo/forgejo]
    │   └── workload-caddy.service       [container: localhost/caddy — TLS for virtual-forgejo.local]
    │   # mDNS (publish <hostname>.local + resolve remote .local): systemd-resolved
    └── forgejo-runner.service           [native systemd unit]
```

## Provisioning

The default flow brings Forgejo up but does **not** register the native
runner on first boot — when this VM hosts Forgejo itself, there's no
admin yet to mint a registration token. You either (a) bring Forgejo up
empty, do the web installer, mint a token, then enable the runner; or
(b) point this VM's runner at a pre-existing Forgejo by overriding the
template vars.

1. **(Optional) override defaults** in `virtual-forgejo.toml`:

   - `[vm.network].bridge` — unset by default, meaning passt: **no bridge, and
     the guest is assigned the host's address**, so nothing on the LAN can
     reach it directly. Set it to your own LAN bridge (e.g. `br0`) to give the
     VM a real LAN identity — read the note in `workload.toml`, because the
     Caddy in this bundle serves `https://virtual-forgejo.local` and assumes
     one. You provision that bridge yourself, and a bridged VM is unfiltered:
     host egress policy cannot reach it.
   - `[vm.cloud_init.template_vars]`:
     - `HYPERVISOR_REPO_URL`, `RUNNER_VERSION` — usually leave alone.
     - `FORGEJO_URL` — runner registers against this URL. Defaults to the
       in-VM `https://virtual-forgejo.local`. Point elsewhere if registering
       against an existing Forgejo.
     - `REGISTER_RUNNER` — `"true"` to attempt registration on first boot,
       `"false"` (the default) to skip. Set to `"true"` only when
       `FORGEJO_URL` already exists AND the credstore has a token (step 2).
     - `ALLOY_CENTRAL_HOST` — hostname/IP of the otel-lgtm host. Leave empty
       (the default) to skip provisioning Alloy entirely. Set non-empty to
       ship VM metrics + journal + OTLP traces to that backend.
     - `ALLOY_HOST_LABEL` / `ALLOY_ROLE_LABEL` — `host.name` / `host.role`
       labels stamped on outbound signals. Defaults `virtual-forgejo` / `ci`.

2. **(If `REGISTER_RUNNER = "true"`)** drop the runner registration
   token into the systemd credstore so it survives reboots and never
   lands in the seed ISO unencrypted:

   ```sh
   # Logged-in Forgejo admin: Site Administration → Actions → Runners →
   # "Create new Runner" gives a one-shot, site-scoped token. (The
   # per-user/org/repo Settings → Actions → Runners pages mint
   # *scoped* tokens — use those only if you want the runner attached
   # to that scope; a site-wide token is the default for native:host.)
   # Then:
   sudo systemd-creds encrypt \
     --name=runner-token \
     - /etc/credstore.encrypted/runner-token <<< 'PASTE-TOKEN-HERE'
   sudo chmod 0600 /etc/credstore.encrypted/runner-token
   ```

   workloadctl decrypts this at ISO build time and substitutes
   `${SECRET?runner-token}` in `cloud-init/user-data`. Leaving the
   credstore entry absent is fine when `REGISTER_RUNNER="false"` —
   the optional-secret form resolves to an empty string and the
   bootstrap skips the registration block.

2b. **(Optional) shared homelab CA.** By default the VM's Caddy uses its
   own self-signed per-host CA, so clients must import the cert it serves
   at `https://${FORGEJO_HOSTNAME}/caddy-root.crt`. To instead have Caddy
   mint its cert under the **shared homelab root** (so any client that
   already trusts that one root trusts the forge), seed both the public
   cert and the private key as base64 credstore secrets — a multi-line PEM
   breaks YAML `write_files`, so store `base64 -w0`:

   ```sh
   base64 -w0 homelab-root.crt | sudo systemd-creds encrypt \
     --name=homelab-root-crt - /etc/credstore.encrypted/homelab-root-crt
   base64 -w0 homelab-root.key | sudo systemd-creds encrypt \
     --name=homelab-root-key - /etc/credstore.encrypted/homelab-root-key
   sudo chmod 0600 /etc/credstore.encrypted/homelab-root-{crt,key}
   ```

   (or `workloadctl secret create homelab-root-crt < <(base64 -w0 …)`).
   Both present → step 7 configures Caddy's `pki` to root at the shared
   CA, mounts the cert/key, trusts the root in the guest, and serves the
   shared root at `/caddy-root.crt`. Either absent → self-signed fallback.

3. **Enable the workload**:

   Once `workloadctl` is installed via the RPM, the support tree at
   `/usr/share/workloadctl/workloads/virtual-forgejo/` is already on disk —
   only the TOML needs to land in `/etc/workloads.d/`:

   ```sh
   sudo cp /usr/share/doc/workloadctl/examples/virtual-forgejo.toml \
       /etc/workloads.d/
   sudo workloadctl enable virtual-forgejo
   ```

   For a dev checkout without the RPM installed, the TOML's
   `user_data_file` path needs to point at the repo copy instead of
   `/usr/share/workloadctl/workloads/...`. Easiest: copy the TOML and the
   support tree to matching paths, e.g.:

   ```sh
   sudo install -d /etc/workloads.d/virtual-forgejo
   sudo install -m 0644 workloads.d/virtual-forgejo.toml \
       /etc/workloads.d/virtual-forgejo/workload.toml
   sudo install -d /usr/share/workloadctl/workloads
   sudo cp -a workloads/virtual-forgejo /usr/share/workloadctl/workloads/
   sudo workloadctl enable virtual-forgejo
   ```

   First boot takes a few minutes — cloud-init clones the hypervisor
   repo, builds workloadctl from source, builds the Caddy
   container image, and downloads the runner binary. Watch progress
   with:

   ```sh
   sudo workloadctl exec virtual-forgejo -- tail -f /var/log/virtual-forgejo-bootstrap.log
   ```

4. **First-time Forgejo setup**: hit `https://virtual-forgejo.local/` from a
   machine on the same LAN, accept the Caddy local-CA cert (or trust it
   in the OS), and complete the install wizard. The seeded
   The seeded `app.ini` (generated from `cloud-init/user-data` at ISO build
   time) already points Forgejo at `${FORGEJO_HOSTNAME}` with SQLite for storage.

5. **(If first boot skipped registration)** mint a runner token through
   Site Administration → Actions → Runners → "Create new Runner", then
   register from inside the VM:

   ```sh
   sudo workloadctl exec virtual-forgejo -- bash -c '
     cd /var/lib/forgejo-runner &&
     /usr/local/bin/forgejo-runner register \
       --no-interactive \
       --instance https://virtual-forgejo.local \
       --token PASTE-TOKEN-HERE \
       --name virtual-forgejo-runner \
       --labels native:host &&
     systemctl enable --now forgejo-runner.service
   '
   ```

   The `cd` matters: `register` writes the `.runner` registration
   file into the current directory, and `forgejo-runner.service` has
   `WorkingDirectory=/var/lib/forgejo-runner` — running `register`
   from anywhere else leaves the daemon failing with
   `open .runner: no such file or directory`. If that happens, just
   `mv` the file to `/var/lib/forgejo-runner/.runner` (chmod 0600).

   Registration tokens are single-use and short-lived. If `register`
   returns `invalid_argument: runner registration token not found`,
   the token was already consumed or expired — mint a fresh one and
   try again immediately.

   If you'd rather have first-boot do this automatically next time, set
   `REGISTER_RUNNER = "true"` in the TOML, seed the credstore (step 2),
   and re-run `workloadctl enable virtual-forgejo` — the seed-ISO
   fingerprint includes the user-data mtime, so editing the TOML alone
   isn't enough to trigger a rebuild; touch `cloud-init/user-data`.

6. **Smoke-test the runner**: create a throwaway repo (tick
   "Initialize Repository"), make sure Actions is enabled under repo
   Settings → Advanced, and add `.forgejo/workflows/smoke.yml`:

   ```yaml
   on: [push, workflow_dispatch]
   jobs:
     smoke:
       runs-on: native
       steps:
         - run: |
             echo "hello from $(hostname)"
             uname -a
             id
   ```

   `runs-on: native` matches the `native:host` label the runner
   registered with (label name before the colon). Committing the
   file triggers the job; it should appear under the repo's Actions
   tab and finish within a couple seconds. If it sits in "Waiting",
   the label doesn't match — check Site Admin → Actions → Runners
   that the runner shows `native:host` exactly.

## Files

- `cloud-init/user-data` — `#cloud-config` for the VM. `${VAR}` /
  `${SECRET:name}` (required) / `${SECRET?name}` (optional, → "" if
  absent) placeholders are filled by workloadctl at ISO build time.
  No YAML library needed — text substitution only.
- `workloads/*.toml` — the three sidecar workload definitions. The bootstrap
  installs these into `/etc/workloads.d/` inside the VM. `Caddyfile` and
  `app.ini` are generated from `cloud-init/user-data` write_files entries
  (substituted at ISO build time) so they are not checked in as separate files.
- `forgejo-runner.service` — native systemd unit dropped into
  `/etc/systemd/system/` during bootstrap.

## Rotating the runner token

If the registration token expires before first boot, re-encrypt over
the same credstore path and rebuild the seed ISO:

```sh
sudo systemd-creds encrypt --name=runner-token \
  - /etc/credstore.encrypted/runner-token <<< 'NEW-TOKEN'
sudo workloadctl disable virtual-forgejo
sudo workloadctl enable  virtual-forgejo
```

The fingerprint on the seed ISO incorporates the user-data file's
mtime, so any edit to `cloud-init/user-data` also triggers a rebuild.
