# Hypervisor & Workload System - Ideas & Directions

> Idea capture and planning. No commitment.

**Last Updated:** 2026-06-27

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
- Workloads get LVM provisioned to cap or flex storage
- make missing host setup script an error not a warning
- put all control surfaces in wireguard/vpn

### Extend `template_vars` substitution to `.tmpl` files in the support tree
**Why:** Today `[vm.cloud_init.template_vars]` in an instance TOML feeds
substitutions into `user_data_file` only. Files in a bundle's support tree
(e.g. `workloads/virtual-forgejo/workloads/caddy.toml`) are copied verbatim,
so anything per-instance has to be inlined into cloud-init's `write_files`
to pick up substitution — bloating user-data and making the workload
config not browsable as its own file. Concrete example: a support-tree
config that hardcodes a hostname/alias has to vary per instance when the
same bundle is run as a second instance.

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
cloud-init or copy-pasting support trees. Composes with the `bundle`
field — one bundle's support tree
(`/usr/share/workloadctl/workloads/<bundle>/`), many instances, each
with its own values.

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

### App-consistent online VM backup (guest fsfreeze + QMP quiesce)
**Why:** `VMSubstrate.capture()` already ships a *crash-consistent* live VM
backup via `backup --consistency crash` (QMP-only — pause vCPUs, copy the durable
disk, resume; journaling FS recovers on boot). That's safe but apps with in-flight
state (a DB mid-transaction) can still be torn. An *app-consistent* backup quiesces
the guest first so the on-disk image is clean at the application layer — the
real "online backup."

- **Effort:** Medium-Large — spans host + guest + image chain.
- **Value:** Medium (crash-consistent already closes the corruption hazard;
  this is the upgrade for stateful guests).
- **Interest:** Deferred until the bootc-guest migration lands.

**Mechanism:** in `VMSubstrate.capture(consistency="app")` —
`guest-fsfreeze-freeze` → QMP snapshot/copy of `data.qcow2` → `guest-fsfreeze-thaw`.

**Blocked on two prerequisites (the reason it's parked):**
1. **Host:** add an `org.qemu.guest_agent.0` virtio-serial channel to the QEMU
   argv in the VM launch helper (`libexec/workload-vm-*`).
2. **Guest:** `qemu-guest-agent` installed + enabled in the VM image — trivial
   once the guest is a bootc image we control ([[project-vm-bootc-guest]]),
   another bootstrap step on the current Fedora-Cloud+cloud-init guest.

**When picked up:** add `app` as a third level to the existing
`backup --consistency {cold,crash}` flag — the selection seam already exists, so
this is purely filling in the `app` branch + the guest-agent plumbing. Degrade to
a clear error when the guest agent is absent.

### Pet overlay drift capture (`podman diff` → codify)
**Why:** `lifecycle = "pet"` (shipped) keeps a container's writable overlay across
reboots (create-once, no `--rm`), but the accumulated changes are *invisible* —
nothing surfaces "what have you changed live that isn't in the image." The failure
mode: tweak a pet desktop live, never fold it into the Containerfile, then a
deliberate `recreate`/`update` onto a new image silently drops weeks of undeclared
state. (The snapshot-on-destroy safety net softens this but doesn't make the drift
*reviewable*.)

**Not the same as the shipped `drift` verb.** `workloadctl drift` compares
*generated-vs-deployed systemd unit files* (is the running unit in sync with the
TOML). This is a different axis: *overlay-vs-image filesystem drift* (what the
running container changed on disk vs the base image). Keep both — they answer
different questions. An earlier design note conflated them; this entry is the
de-conflation.

**Proposal:** a verb — e.g. `workloadctl changes <wl>` or `drift --overlay <wl>` —
that runs `podman diff <container>` for a pet's overlay and presents the
added/changed/deleted paths vs the base image as a reviewable list. The point is
the capture loop: persist short-term (overlay reuse + snapshot-on-destroy, both
shipped) so nothing is lost → periodically review the diff and codify the keepers
into the Containerfile / bundle `setup.sh` → then `recreate` onto the improved
image with no loss. A pet that can rejoin the herd on your schedule instead of one
you're afraid to reboot. The desktop/VNC pet is the killer use case.

**Effort:** Small-Medium — `podman diff` is one call; the value is in presentation
(filter the noise: package caches, logs, `/tmp`, runtime dirs) and wiring it to the
pet lifecycle so it's offered where it matters.

**Value:** Turns silent pet drift into a reviewable, codifiable list — closes the
"afraid to reboot the pet" gap. Composes directly with `lifecycle = "pet"` and the
snapshot-on-destroy net (both already shipped); this is the missing *visibility*
half.
