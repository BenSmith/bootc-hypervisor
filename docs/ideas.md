# Hypervisor & Workload System - Ideas & Directions

> Idea capture and planning. No commitment.

**Last Updated:** 2026-06-27

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
- Game server workloads (Valheim, Factorio, etc.)
- Import docker-compose files to workload TOML (migration tool)
- Secrets rotation automation (auto-rotate credentials periodically)
- Generate seccomp profile instead of static, so it will handle changes in the distribution policies
- Workloads get LVM provisioned to cap or flex storage
- make missing host setup script an error not a warning
- put all control surfaces in wireguard/vpn

### Unified TLS: hybrid internal CA + Let's Encrypt
**Why:** Today every Caddy uses `local_certs`, minting its own internal
CA on first boot. The fetch-the-root-over-plain-HTTP dance is already
copy-pasted across several setup scripts (virtual-forgejo, wayfire,
sunshine). Two distinct problems hide in here, and they don't want the
same fix:

1. **Service-to-service trust** (Caddy → registry, runner → forge).
   You control both ends — this is *mostly already solved* by baking
   one root into the image/sysuser trust stores. Cheap.
2. **Unmodified client devices** (phones, guest laptops). This is the
   real unmet need. An internal root does *not* solve it: a phone needs
   a manual profile install + (iOS) flipping Full Trust, Android won't
   trust user CAs in apps at all, and the leaf certs must satisfy
   Apple's SAN/EKU/≤398-day rules. Per device, redone on every rotation.
   Guests' devices are a non-starter.

**Proposal — hybrid, split by who needs to trust the name:**

- **Internal mesh → one internal root CA.** Collapse the per-host
  `local_certs` proliferation into a single root (a `step-ca` workload,
  or just one shared root baked into the trust stores we already
  control). Service-to-service TLS auto-rotates; one root, distributed
  once to hosts/runners/sysusers. Kills the per-service fetch-the-root
  dance for everything we own both ends of.
- **Device-facing names → Let's Encrypt.** For the *small* set of names
  a phone or guest laptop must reach, get publicly-trusted certs via a
  real domain + DNS-01. Zero client trust plumbing, works from any
  device with nothing installed. Only these names need the domain +
  DNS API creds, so the blast radius is small.

The key sizing question: **which names actually need to be trusted by
devices we don't control?** If that set is small (likely), we don't
over-build an internal CA trying to cover phones it can't cover anyway —
we just put those few names on Let's Encrypt.

**Decision gate:** do we own / want a public domain? If yes, the
device-facing half is straightforward. If no, the device-facing problem
has no clean answer (internal CA can't reach unmodified phones), so
the hybrid degrades to "internal root for everything, accept manual
per-device trust for the rare external case."

**Effort:** Medium. Internal root is a new workload (or shared-root
config) + a Caddyfile issuer change across the fleet. Device-facing
half is mostly a Caddyfile change + DNS creds for the handful of names,
gated on the domain decision.

**Value:** Ends the fetch-the-CA-over-HTTP dance, scales with N services
instead of N² trust edges, and — via the Let's Encrypt half — actually
makes the chosen names reachable from a phone, which an internal CA
alone never does.

### App-consistent online VM backup (guest fsfreeze + QMP quiesce)
**Why:** `VMSubstrate.capture()` already ships a *crash-consistent* live VM
backup via `backup --consistency crash` (QMP-only — pause vCPUs, copy the durable
disk, resume; journaling FS recovers on boot). That's safe but apps with in-flight
state (a DB mid-transaction) can still be torn. An *app-consistent* backup quiesces
the guest first so the on-disk image is clean at the application layer — the
real "online backup."

- **Effort:** Medium-Large — spans host + guest + image chain.
- **Value:** Medium (crash-consistent already closes the corruption hazard;
  this is the upgrade for guests whose app-state can't survive a torn image).
- **Interest:** Deferred until a workload actually needs it — i.e. a guest whose
  on-disk app-state tears under crash-consistency (today's forge recovers cleanly,
  so nothing demands it). The bootc-guest migration is a *prerequisite*, not the
  trigger: it makes the guest-agent plumbing trivial, but doesn't by itself create
  a reason to build this.

**Mechanism:** in `VMSubstrate.capture(consistency="app")` —
`guest-fsfreeze-freeze` → QMP snapshot/copy of `data.qcow2` → `guest-fsfreeze-thaw`.

**Blocked on two prerequisites (the reason it's parked):**
1. **Host:** add an `org.qemu.guest_agent.0` virtio-serial channel to the QEMU
   argv in the VM launch helper (`libexec/workload-vm-*`).
2. **Guest:** `qemu-guest-agent` installed + enabled in the VM image — trivial
   once the guest is a bootc image we control (`docs/wip/vm-workloads-direction.md`),
   another bootstrap step on the current Fedora-Cloud+cloud-init guest.

**When picked up:** add `app` as a third level to the existing
`backup --consistency {cold,crash}` flag — the selection seam already exists, so
this is purely filling in the `app` branch + the guest-agent plumbing. Degrade to
a clear error when the guest agent is absent.

### Make pets rebasable by partitioning state (volume = `/var`, image = `/usr`)
**Why:** `lifecycle = "pet"` (shipped) keeps a container's writable overlay across
reboots, which makes the pet *afraid to reboot*: a deliberate `recreate`/`update`
onto a new image drops everything in the overlay. The instinct is "just rebase
onto the new base and keep my changes" — which is exactly how bootc already
upgrades the host. The reason it works for the host is the state split: read-only
`/usr` is replaced wholesale, `/var` persists untouched, `/etc` is 3-way merged.
A pet that keeps precious state in its ephemeral overlay has none of that, so
there's nothing to rebase — recreate just loses it.

**The key realization:** "rebase onto a new container" is not a missing podman
feature — it's the *already-shipped* `recreate` onto a rebuilt image, **provided
precious state lives in a persistent volume instead of the overlay.** Stacking the
overlay onto a new base is *not* a rebase: containers have no 3-way merge, so a
touched path would silently shadow the new base's version (masking the very base
update you upgraded for) with no conflict surfaced. The clean equivalent is the
bootc split, applied to the pet:

- **Reproducible stuff → the image.** Rebuilds fresh, takes base/CVE updates,
  rebases cleanly. (The pet's read-only `/usr`.)
- **Precious state → a persistent volume.** Rides through `recreate` untouched.
  (The pet's `/var`.)
- **Config →** ideally 3-way merged, which containers can't do — so keep it
  minimal and in the image.

Partition the pet that way and **`recreate` onto the new image *is* the rebase**:
the volume rides along, the overlay is disposable, drift no longer matters because
nothing precious lives in the overlay. The desktop/VNC pet — the canonical
"afraid to reboot" case — falls right out: user-data in a persistent `/home`
volume → recreate onto a patched base → state intact, base fresh.

**Proposal:** make the partitioning the *default shape* of a pet rather than
something the user has to get right by hand — e.g. a pet declares its precious
paths and workloadctl ensures they're volume-backed (and warns when a pet is
accumulating state in the overlay instead). The drift problem then dissolves into
a config-correctness problem: a pet is reboot-safe iff its precious state is
volume-partitioned.

**Effort:** Medium — mostly convention + a guardrail (detect/own the precious-path
volumes for a pet), not new runtime machinery; `recreate` already does the rebase.

**Value:** Turns "afraid to reboot the pet" into "recreate is a clean rebase,"
using the same state-split discipline bootc uses for the host. Composes with
`lifecycle = "pet"` and volumes (both shipped).

**Codification half — capture provisioning *actions*, not filesystem state.** The
partitioning above handles precious *runtime* state (→ volume). The complement is
the residual that genuinely belongs in the image: a deliberate `dnf install`, a
`systemctl enable`, an `/etc` edit on a long-lived server pet. To fold those back
you want a record of *what you did*, and the right capture is action-oriented, not
a state diff:

- **State capture (`podman diff`) is the wrong tool** — paths-only, post-hoc, and
  on a desktop ~99% noise (caches, logs, `/tmp`). It tells you *that* a path
  changed, never *what you ran* or *why*. (This is why the earlier
  diff-and-codify idea was dropped.)
- **Action capture records the commands as you run them** — high signal because it
  captures intent, and `dnf install foo` / `systemctl enable bar` map almost
  line-for-line onto Containerfile `RUN`s. The noise never enters the record
  because you never typed it.

**Proposal — a passive provisioning journal, default-on for pets.** Don't make it
a verb you remember to invoke: you don't know which session mattered until after
it's over, so opt-in misses the unplanned 11pm fix that *is* the drift failure
mode. Instead the journal accumulates automatically. When you're ready to codify,
you mine it into `setup.sh` / a Containerfile `RUN` block. Pair it with the one
genuinely useful slice of `podman diff`: list changed files under `/etc` (filtered,
no caches) and dump their *contents* (not just paths), so editor-made config
changes can be dropped into the bundle as files.

This makes **both halves passive** — the volume rides along without being asked,
the journal accumulates without being asked — and you harvest each retroactively.
Same spirit as the snapshot-on-destroy net: capture cheaply, decide value later.

**Mechanism — bind-mount the histfile (no capture wrapper).** Mount one host file
onto the shell's `HISTFILE` path in the pet. A plain shell history file is a
perfectly good artifact on its own, and the bind-mount means *every* shell writes
to it — `podman exec` sessions **and the terminal opened inside the VNC desktop
itself** — with no `workloadctl shell --record` wrapper to invoke. That last part
matters: in-container terminal work in a GUI pet gets journaled too; only true GUI
clicks escape.

**Where it lands:** `/var/lib/workloads/<name>/` — the durable per-workload root,
but *outside* the reconstructible `state/` subtree (the `$HOME`/graphroot that
`recreate` discards). So the journal survives the very `recreate` whose drift it's
meant to help you codify. It's also already `container_file_t`-labeled, so the
bind-mount needs no SELinux relabel.

**Make-or-break details (a bare mount silently under-captures):**
- **Incremental write, or nothing lands until clean exit.** Bash flushes `HISTFILE`
  only on clean shell *exit* by default — a killed shell or stopped container loses
  everything in memory. Inject `shopt -s histappend` + `PROMPT_COMMAND='history -a'`
  via the image's `/etc/bashrc` for line-by-line durability.
- **Disable truncation, or it eats the journal.** Default bash truncates `HISTFILE`
  to `HISTFILESIZE` on exit — i.e. deletes your accumulated provisioning history.
  Set `HISTFILESIZE=-1`. Add `HISTTIMEFORMAT` so each line is timestamped (turns a
  flat list into a real *when-did-I* journal).
- **Rootless ownership — pre-create, don't `:U`.** A single bind-mounted file hits
  the [[project_rootless_U_mount_chown]] trap: `:U` chown fails for the keep-id
  user. Pre-create the file host-side with the right owner/mode and plain-mount it.

**Constraints that keep default-on safe:**
- **Command stream, not full PTY.** History only, not a `script`-style session —
  cheaper, and it doesn't slurp terminal noise or passwords typed to a `read`
  prompt. The commands are exactly what becomes `RUN` lines anyway.
- **Private, not shipped.** The journal stays host-side under `/var/lib/workloads`;
  it is never part of the bundle that gets pushed (tokens can land on argv).
- **Escape hatch inverts:** the explicit flag is `--no-record` for "I'm about to
  type a secret," not `--record` to opt in. Useful-by-default, down-shift
  deliberately.

**Limits (honest):** the journal only sees what flows through a shell — true GUI
clicks in a VNC desktop and out-of-band edits won't be captured, and for those the
changed-`/etc`-content extraction is the backstop. Which reinforces the split: the
desktop pet wants a persistent *volume* (partitioning), the server pet wants the
*provisioning journal* — partitioning decides "what should be a volume," this
decides "what should be a build step."

> Distinct from the shipped `drift` verb, which compares generated-vs-deployed
> systemd unit files — a different axis (config-vs-running, not state-vs-image).
