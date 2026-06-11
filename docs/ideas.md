# Hypervisor & Workload System - Ideas & Directions

> Idea capture and planning. No commitment.

**Last Updated:** 2026-05-07

---

### LLM Inference Workloads
**Why:** It makes me sad to have unused fancy hardware
- **Effort:** Small (just workload configs)
- **Value:** High (utilize hardware)
- **Interest:** High

**Options:**
- Ollama (easiest, good API)
- llama.cpp (lightweight)
- text-generation-webui (feature-rich)
- vLLM (production serving)

**Notes:**
- **Config:** Straightforward - GPU passthrough, host networking for API
- **Status:** Ready to start

---

### Dev Container Workloads
**Why:** Use big computer for remote development
- **Effort:** Small-Medium (per stack)
- **Value:** High (useful for actual work)
- **Interest:** High

**Stacks to create:**
- Node.js/TypeScript (single container)
- Python (single container)
- Rust (single container)
- Full-stack (needs multi-container: app + postgres + redis)

**Integration:** Could use with VSCode Remote-SSH or direct SSH
**Next action:** Create simple Node.js dev container
**Status:** Ready to start

---

### Home Assistant
**Why:** useful for home automation
- **Effort:** Small (1-2 days)
- **Value:** High
- **Interest:** Medium

**Value proposition:**
- User handles: Home automation logic, device integrations (Zigbee/Z-Wave/WiFi)
- We handle: Compute infrastructure (deployment, auto-restart, reliability, USB passthrough)
- User never thinks about: systemd, docker, networking, boot reliability

**Boundary:** Don't get into device management - stay in infrastructure lane

**Status:** Ready enough

---

### cloud-init ISO in tmpfs (S2 follow-up)

**Why:** VM cloud-init template mode decrypts secrets and renders them into
`cloud-init.iso`, which lives at `/var/lib/workloads/<name>/cloud-init.iso`
(0640, inside a 0700 home). The cheap fix (2026-06-11) tightened the seed
dir perms and deleted it after ISO build, so the persistent risk is just the
ISO itself. Threat: offline disk read of `/var` without TPM.

**Proposal:** Point the QEMU cdrom at `/run/workloads/<name>/cloud-init.iso`
instead of the home dir. `workload-ensure-user` already runs at `ExecStartPre`
(service start), so it rebuilds the ISO into tmpfs each boot — no plaintext
on persistent disk. The fingerprint check still avoids unnecessary rebuilds
(fingerprint file stays in the home dir).

**Changes needed:**
- Generator: emit cdrom path as `/run/workloads/<name>/cloud-init.iso`
- `workload-ensure-user`: write ISO there instead of home; create the `/run`
  dir if absent (tmpfiles.d or ensure-user itself)
- Update unit snapshot tests

**Effort:** Small-medium (~20-40 lines across two files + snapshots).
**Value:** Eliminates persistent plaintext ISO for template-mode VMs.
**Prerequisite:** Only worth doing if the threat model includes offline disk
access without TPM.

---

## Random Ideas (Unsorted)

*Quick capture spot - organize into sections above during review*

- Web UI for workload management
- Workload health monitoring with alerts (email/webhook on failures)
- Game server workloads (Valheim, Factorio, etc.)
- Import docker-compose files to workload TOML (migration tool)
- Ansible integration for provisioning (manage workloads as code)
- Workload dependency management (start B after A)
- Secrets rotation automation (auto-rotate credentials periodically)
- Workload migration tools (move between hosts)
- Generate seccomp profile instead of static, so it will handle changes in the distribution policies
- Scheduled image updates: systemd timer that runs `workloadctl update --all` periodically.
  Pulls newer images for updatable workloads (skip pull=never), restarts only if image changed.
  Could add configurable schedule, notification on updates, and update log.
- Workloads get LVM provisioned to cap or flex storage
- make missing host setup script an error not a warning
- put all control surfaces in wireguard/vpn
- build all container workload images and host locally?

### Separate `kind` from `name` in workload TOMLs
**Why:** Today `[workload].name` is used as both the instance identifier *and*
the lookup key for shared support assets (container build trees under
`/usr/share/workloadctl/containers/<name>/`, VM support trees under
`/usr/share/workloadctl/vms/<name>/`, default relative paths, etc.). That
conflates "what is this instance called" with "what kind of workload is
this," so running two instances of one kind (e.g. samba as `files` and
`archive`, or a second virtual-forgejo as `git`) requires either renaming
the on-disk support tree or overriding every kind-derived path explicitly
in the instance TOML with absolute paths.

**Proposal:** Add an optional `kind = "<name>"` field. If set, all default
lookups for shared assets resolve under `<kind>` instead of `<name>`;
per-instance state (`/var/lib/workloads/<name>/`, `_wl-<name>` sysuser,
`workload-<name>.service`) still uses `<name>`. Absent `kind`, behavior is
unchanged (kind defaults to name) — fully backwards compatible. The
absolute-path escape hatch remains for one-off mix-and-match cases.

**Effort:** Medium — every name-derivation point in workloadctl (and the
generators) needs to learn the kind/name split. Mostly mechanical.

**Value:** Unblocks N:1 instance:kind cleanly. Today's only path is
copy-paste the support tree under a new name, which fragments updates.

### Extend `template_vars` substitution to `.tmpl` files in the support tree
**Why:** Today `[vm.cloud_init.template_vars]` in an instance TOML feeds
substitutions into `user_data_file` only. Files in the support tree
(e.g. `vms/virtual-forgejo/workloads/avahi.toml`) are copied verbatim,
so anything per-instance has to be inlined into cloud-init's `write_files`
to pick up substitution — bloating user-data and making the workload
config not browsable as its own file. Concrete example: avahi.toml
hardcodes `ALIASES = "virtual-forgejo"`; running a second instance as
`git.local` requires that string to vary per instance.

**Proposal:** Workloadctl walks the kind's support tree at ISO build
time; any file ending in `.tmpl` is processed with the instance's
`template_vars` dict (same engine as user-data) and packed into the
ISO with the suffix stripped. So `workloads/avahi.toml.tmpl` becomes
`workloads/avahi.toml` in the ISO, with `${FORGEJO_HOSTNAME}` filled
in. Non-`.tmpl` files stay verbatim. The kind owns the templates;
the instance TOML owns the values.

**Effort:** Small — single substitution pass over the support tree
during ISO build, mirrors what already happens for user-data.

**Value:** Per-instance config for VM workloads without bloating
cloud-init or copy-pasting support trees. Composes well with the
proposed `kind` field above (one support tree, many instances, each
with its own values).

### Unified TLS: internal CA or Let's Encrypt instead of per-host Caddy CAs
**Why:** Today every Caddy instance uses `local_certs`, i.e. mints its
own internal CA on first boot. Every workload that needs TLS ends up
with its own root, so:

- Each new VM/container forces clients to fetch and trust yet another
  CA cert (the `REGISTRY_CA_URL` pattern in virtual-forgejo's bootstrap
  is a symptom — fetch zamd's Caddy root over plain HTTP, trust it,
  done; repeat for every new service).
- Browsers, mobile devices, and external machines never trust these
  roots without manual install per device. Practically that means
  the internal services aren't reachable from a phone or a laptop
  someone brought from outside.
- Rotating any one CA breaks every client that trusted it.
- The mesh of "who trusts which CA for which name" grows quadratically
  and is invisible — nothing inventories it.

**Options:**

1. **Single internal root CA + ACME issuer (recommended).** Run a
   `step-ca` (smallstep) workload as one of the workloadctl-managed
   services. Every Caddy points its tls issuer at that ACME endpoint
   instead of `local_certs`. One root cert distributed once (baked
   into the host trust store, sysusers' trust stores, runner trust
   stores, optionally pushed to phones via a profile). Per-service
   certs auto-rotate over ACME without per-host CA proliferation.
   Trade-off: one more workload to operate; root key becomes a real
   asset to protect.

2. **Let's Encrypt with a real domain via DNS-01.** Buy/own a
   public domain (e.g. `miniverse.example.com`); each workload gets
   `<name>.miniverse.example.com`; Caddy uses DNS-01 against the
   DNS provider's API to mint publicly-trusted certs. Zero CA-trust
   plumbing on any client, ever. Works from any device, anywhere.
   Trade-off: requires a public domain and a DNS provider with API
   support, plus credentials distributed to every Caddy that needs
   to mint. Names are public DNS even if the IPs aren't.

3. **Hybrid: internal CA for `.local`, Let's Encrypt for `.public`.**
   `git.local` keeps Caddy `local_certs` (or option 1's step-ca) for
   LAN-only access; external-facing names use Let's Encrypt. More
   moving parts but matches mental model of "internal vs external."

**My lean:** (1) for self-contained homelab; (2) if a public domain
is already in play. Avoid the status quo as the fleet grows past
~5 services.

**Effort:** (1) is a new workload + Caddyfile template change across
the fleet, medium. (2) is mostly a Caddyfile change plus credential
delivery, smaller per-workload but requires the domain decision.

**Value:** Eliminates the "fetch the new CA over plain HTTP" dance
on every new service, makes the fleet reachable from unmodified
client devices, scales with N services instead of N^2 trust edges.
