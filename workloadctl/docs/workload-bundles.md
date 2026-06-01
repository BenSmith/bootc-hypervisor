# Workload bundles & filesystem layout (design)

Status: **proposal** — not yet implemented. Captures decisions reached while
reworking how workloads are shipped, enabled, customized, and duplicated.

## Problem

Today a workload is split across four trees with the workload *name* hardwired
into lookups against immutable `/usr`:

- `/usr/share/doc/workloadctl/examples/<name>.toml` — the example declaration (docdir)
- `/usr/share/workloadctl/containers/<name>/` — control files (`Containerfile`,
  `build.sh`, `setup.sh`, `<name>.te`, config templates)
- `/etc/workloads.d/<name>.toml` — the *only* place `enable` reads
- `/var/lib/workloads/<name>/` — the workload user's `$HOME`, doing triple duty
  as podman image storage, `./`-volume base, and config-template drop point

Consequences:

- **Enabling a shipped workload** means manually `cp`-ing the example out of
  docdir into `/etc/workloads.d/` — there is no command for it, and the catalog
  is invisible to the CLI (`get_all_configs` only globs `/etc`).
- **Customizing** means copying read-only control files somewhere writable,
  editing, and repointing the TOML — and because build/setup/SELinux lookups are
  all keyed on `containers/{name}`, a renamed copy breaks in several places at
  once (`build.sh` path, `[host].setup` resolution, `module <name>` in the `.te`).
- **`/var/lib/workloads/<name>/` is a junk drawer.** On a live box, alloy's dir
  is 505 MB — 100% podman layer storage — sitting beside the 6.6 KB config file
  that actually matters, because `HOME=` points at the dir root.

## Scope / non-goals

Decisions below assume the **actual** operating context, not a general-purpose
audience:

- Single operator, primarily a single host.
- **No migration burden** — existing TOMLs/dirs get adjusted by hand, once.
- **No cross-host portability requirement** for workload identity (UIDs stay
  host-allocated; see below).
- **Not bound to systemd semantics** — we borrow the override *idea* where it
  helps, but don't owe systemd conformance.

## Layout

```
/usr/share/workloadctl/workloads/<bundle>/   # pristine shipped bundle (read-only)
    workload.toml                            #   the template declaration
    Containerfile  build.sh                  #   control files (any subset)
    setup.sh  <bundle>.te  *.conf templates  #   that the bundle needs

/etc/workloads.d/<name>.toml                 # the authoritative declaration

/var/lib/workloads/<name>/
    base/        # writable control-file OVERRIDES; empty until you customize
    home/        # passwd home for _wl-<name> → podman graphroot/runroot
    data/        # persistent app data; "./"-volumes resolve here
    exports/     # outward-facing shares (smb, downloads, …) — convention
```

Two consolidations vs. today:

1. The shipped bundle co-locates the declaration **and** its control files under
   one `workloads/<bundle>/` dir (replacing the docdir-examples + `containers/`
   split). The RPM `%install` changes accordingly.
2. `/var/lib/workloads/<name>/` stops being `$HOME` directly; `$HOME` moves to
   the `home/` subdir, isolating the large, rebuildable podman storage from
   precious data.

## Resolution

Three different kinds of file resolve three different ways. **Only the state
paths are name-derived; the boot-path generator computes nothing else.**

### Declaration (the TOML) — no runtime merge

`/etc/workloads.d/<name>.toml` is authoritative. The `/usr` bundle's
`workload.toml` is only a *template* that `init`/`duplicate` copies from. There
is no `/etc`-over-`/usr` live overlay for the TOML — once copied, the `/etc` file
is the workload.

### Control files — lazy override, keyed on `bundle`

A workload's TOML carries an optional identity field:

```toml
[workload]
name   = "wayfire-bob"
bundle = "vncdesktop-wayfire"   # defaults to `name` if omitted
```

For control file `F` (e.g. `setup.sh`, `Containerfile`, the `.te`):

1. `/var/lib/workloads/<name>/base/F` — operator override (usually absent)
2. `/usr/share/workloadctl/workloads/<bundle>/F` — shipped default

First hit wins. Absolute paths in the TOML bypass resolution entirely.

`bundle` is the key fix for the name-coupling problem: lookups key off an
*explicit field*, not the workload name. That makes a renamed copy
(`wayfire-bob` deriving from `vncdesktop-wayfire`) resolve its control files with
**no copying** — and `base/` stays empty until the operator actually overrides
something, exactly the lazy `/usr`→override behavior we wanted.

### State — computed, name-derived

No resolution; pure functions of `<name>`:

| Logical | Path |
|---|---|
| `$HOME` (podman storage) | `/var/lib/workloads/<name>/home` |
| `./` volume base | `/var/lib/workloads/<name>/data` |
| exports | `/var/lib/workloads/<name>/exports` |

`./foo` now expands to `…/data/foo` (was `…/<name>/foo`). No migration: the
handful of live TOMLs and shipped examples get rewritten by hand.

## `duplicate` (and `init`)

"Run two wayfires" is the degenerate case of one verb. **Name uniqueness is the
only hard requirement; everything else is shareable, and sharing is just the
absence of an override.**

```
sudo workloadctl duplicate vncdesktop-wayfire wayfire-bob
```

| Piece | Action |
|---|---|
| `/etc/workloads.d/<new>.toml` | copy source TOML, rewrite `name`, set `bundle` to the source |
| `base/` | **not** copied — falls through to the shared `/usr` bundle until edited |
| `home/` | fresh/empty — never copied (subuid-mapped storage; re-pull/rebuild) |
| `data/` | empty by default; `--clone-data` to seed from source |
| user / UID / subuid | allocated fresh on enable (first-free, host-local) |
| image | whatever the new TOML says — shared by default, diverge by editing one line |
| SELinux policy | covered by the shared bundle/`.te` until a copy overrides it |

`init <name>` is the same operation with the source being a `/usr` catalog entry
instead of a live workload. `workloadctl catalog` lists shippable bundles.

There is **no share-vs-fork mode** on the operation: it always produces a copy
that initially points at the same image/policy via explicit TOML fields +
`bundle` fall-through. Divergence (a pinned image tag, a custom Containerfile in
`base/`) is an ordinary `edit` afterward.

## Things deliberately left as-is

- **Image sharing is operator-decided, not a footgun.** The image tag is an
  explicit field per TOML; two copies on `:latest` share a mutable tag because
  the operator wrote that. Optional future polish: a lint warning two enabled
  workloads point at the same mutable tag. Not required.
- **UIDs stay host-allocated** (first-free, `allocate_uid`). Fine for a single
  host. The only consequence is that a cross-host `restore` must re-chown
  `data/`/`exports/` to the destination's UID — a restore-path detail, only if
  that ever happens. No UID pinning, no identity field in the bundle.
- **The env file stays in `/run`** (`/run/workload-env/workload-<name>.env`).
  It's regenerated each boot; it does not need a `/var` home.

## Constraints for implementation

- **Keep the early-boot generator dumb.** The shell generator and the Python
  `workload-generate` run `After=sysinit Before=basic.target`, must be fast, must
  exit 0, and must not touch `/var`. Control-file *override resolution* lives in
  the CLI (`build`, `enable`'s host-setup) — **not** in the boot path. The
  generator only ever computes the name-derived `home/`/`data/` paths it already
  computes. Richer layout must not add `stat()` fan-out or new failure modes to
  the must-not-fail path.
- **`backup`** should grab TOML + `base/` + `data/` + `exports/` and skip
  `home/` (rebuildable). Named subdirs make this precise instead of a guess.

## SELinux: per-workload types (security fix, can land independently)

**Decided.** Every shipped `.te` today writes its `allow` rules against the
shared `container_t`/`container_init_t` domains, so loading any module widens
**every** container on the host — `semodule` load is global. Blast radius is
real: the game-streaming modules grant `/dev/input` read (keylogging),
`/dev/uinput` (input injection), and `execheap`/`execmod`/`mmap_zero` (W^X
bypass) to all containers; the desktop/alloy modules add device/journal access.
This is a live regression, independent of the bundle work.

Fix: each workload that needs extra rights gets its **own** type
(`wl_<name>_t`), attributed into the container domain, with the `allow` rules
moved onto that type. The container launches with
`--security-opt label=type:wl_<name>_t`. `container_t` stays stock for everything
else.

- The generic `[security].security_opt` passthrough already exists
  (`workload-generate:747`); the missing pieces are (a) defining the type in the
  policy and (b) auto-injecting the label on enable.
- Systemd-in-container workloads fold their `container_init_t` rules onto the
  single custom type (the whole container runs as that type). The automatic
  `container_init` transition under a custom label is the finicky part —
  test per workload; lean on `udica` to generate the policy from a running
  container rather than hand-writing.
- Resolves the duplicate-naming question: a copy gets its own `wl_<name>_t`, so
  two instances don't share a widened domain, and copies that need no extra
  rights get none. Per-workload confinement by construction.
- Can and should ship **before** the layout reshape; it depends on none of it.

### Key the type on `name`, not `bundle`

Running two of something forces a decision the `wl_<name>_t` shorthand glosses:
two wayfires (`wayfire-alice`, `wayfire-bob`, both `bundle =
vncdesktop-wayfire`) could either **share** one `wl_vncdesktop-wayfire_t` or get
a type **each**. Key it on **`name`** (one type per *instance*).

Bundle-keying is tempting — the `.te` *source* already resolves by `bundle`
(it's a control file) — but it silently reintroduces the refcount problem
per-workload types exist to kill: `semodule -r wl_vncdesktop-wayfire_t` is safe
only once the *last* instance on that bundle is disabled, so you're refcounting
again, just at the bundle level instead of the global `container_t` level. The
decidable-teardown property requires **1 type ⇄ 1 enabled workload**. So the
type is named after the instance; the `.te` is sourced from the bundle.

### The `.te` is a per-bundle template, instantiated at enable

Consequence of name-keying: the bundle no longer ships a final loadable module —
it ships a **template** with the instance identity left as a placeholder. SELinux
itself has no template syntax (`.te` files are static); the markers below are just
an enable-time string substitution, reusing the repo's existing
`__UID__`/`__SVCDIR__` placeholder convention. The whole type/module identifier is
the placeholder, so the `wl_`/`_t` affixing and sanitization live in the
substitution code, not in the bundle author's `.te`:

```
module __WL_MODULE__ 1.0;
type __WL_TYPE__;
typeattribute __WL_TYPE__ container_domain;
allow __WL_TYPE__ ... ;
```

where `__WL_TYPE__` → `wl_<sanitized-name>_t` and `__WL_MODULE__` →
`wl_<sanitized-name>`. `enable` performs the substitution, compiles, loads
`wl_<name>`, and injects
`--security-opt label=type:wl_<name>_t`. (Alternatively generate fresh per
instance with `udica` from the running container — more robust for the
systemd-in-container `container_init` transition, heavier.) This substitution is
**enable-time CLI work, not boot path** — the generator stays dumb, same
discipline as the rest of this doc.

### What duplicating actually buys (and doesn't)

`duplicate wayfire-alice wayfire-bob` → bob gets his own module/type from the
shared bundle template: one extra `semodule -i` on enable, one `semodule -r` on
disable, no `.te` copy, independently removable, orphan-reconcile works verbatim.

Be honest about the benefit for *identical* copies, though: two instances of the
same bundle have identical rule needs, so `wl_wayfire_alice_t` and
`wl_wayfire_bob_t` are **byte-identical in granted rights**. The win is *not*
"alice can't do what bob can" — it's (1) clean ownership/teardown (disabling bob
removes exactly bob's grants) and (2) the host's *other* containers stay
unwidened. Differential privilege only matters across *different* bundles (the
common case across the herd), not within a duplicated pair.

### Gotcha: type-identifier sanitization

SELinux type identifiers allow `[a-zA-Z0-9_]` only — **no hyphens**. Every
workload name here is hyphenated (`vncdesktop-wayfire`), and today's `.te`s dodge
this only because they declare *stock* types (`container_init_t`), never their
own. Declaring `wl_<name>_t` means sanitizing `wayfire-bob` → `wl_wayfire_bob_t`.
No collision guard is needed: `NAME_PATTERN` is `^[a-z][a-z0-9-]*$`
(`workload_lib.py:33`) — names contain no underscores — so hyphen→underscore is
injective and two distinct names can never map to the same type. The sanitize
belongs in the same enable-time step that allocates the UID and the per-instance
SSH key — another fresh-per-instance identity.

Net rule: **type keyed on `name`, sourced from a per-`bundle` template,
instantiated + sanitized + label-injected at enable, torn down 1:1 on disable.**

## VM workloads in the bundle model

A `[vm]` workload fits the bundle model better than a naive "fold `vms/` into
`workloads/`" suggests — the three-way resolution split (declaration / control
file / state) holds almost verbatim. Companion: `vm-workloads-direction.md`,
which graduates the guest to a bootc image.

Today a VM stores everything flat under `/var/lib/workloads/<name>/`:
`system.qcow2`(+`.gen-N`), `data.qcow2`, `nvram.fd`, `cloud-init.iso`,
`.ssh/id_ed25519`, `.image-cache/`. The mapping onto bundle concepts:

| Bundle concept | Container | VM |
|---|---|---|
| **Declaration** (`/etc`, authoritative) | `[container]`/`[[containers]]` | `[vm]` — identical |
| **Control file** (lazy override, keyed on `bundle`) | Containerfile, build.sh, setup.sh, `.te`, `*.conf` | the cloud-init user-data template (`[vm.cloud_init]`) |
| **State → `home/`** (rebuildable, backup-skip) | podman graphroot | `system.qcow2`+`.gen-N`, `cloud-init.iso`, `nvram.fd`, `.image-cache/` |
| **State → `data/`** (durable, backup) | `./`-volumes | `data.qcow2` |
| **Image ref** (shared, diverge by editing) | image tag | `image` / `cloud_image_url` |

`duplicate` generalizes almost exactly. "Run two forges" decomposes the same way
a container copy does: copy TOML + set `bundle`, `home/` (system disk) fresh,
`data/` empty-or-`--clone-data`, image shared by default. Only two mechanisms
differ — clone-data is `qemu-img` not tar, and the fresh-on-enable *UID* has a
VM twin in the fresh-on-enable *SSH key*. That parallelism is evidence the
bundle model is the right frame for VMs, not a forced fit.

The backup rule ("grab `data/`, skip `home/`") then handles VMs correctly by
construction: `data.qcow2` is durable, `system.qcow2` is rebuildable. Caveat
(see `vm-workloads-direction.md`): a *live* qcow2 backup needs guest-agent
fsfreeze + QMP quiesce, so the `data/` grab is not a plain tar for VMs.

### Where it genuinely diverges (decide during build)

- **Control-file surface is asymmetric, and bootc-guest widens it.** A container
  bundle is self-contained and *locally buildable* (`build.sh` + Containerfile in
  the bundle). A VM bundle's heavy artifact — the guest image — lives in a
  registry, built by the host image CI chain ("just another branch off the
  base"). So the `base/` override lever has **no VM analog for the image**:
  forking a VM guest means adding a layer to the image chain, not dropping a
  `Containerfile` in `base/`. The only override-able VM control file is the
  cloud-init seed. State this plainly so nobody expects `base/Containerfile` to
  do anything for a VM.
- **`build <name>` means something different for a VM.** There is no local image
  build; the equivalent work is "provision `system.qcow2` from the image
  source," which `enable`/`update` already do. Decide whether `build <vm>` is a
  no-op or an alias for that disk-provision step.
- **SSH key / seed placement** (the bullet this section replaces). The
  `cloud-init.iso` is rebuildable → `home/`. The `.ssh/id_ed25519` is the only
  *durable per-instance secret*: regenerable-on-recreate in principle (re-seed
  via a fresh ISO), but losing it is painful if the guest is unreachable to
  re-seed. So it lands in `data/`, or — preferred — is managed as a
  `systemd-creds` secret like the rest of the secret story, not a bare file
  under the dir root.

### Not covered by the SELinux fix

The per-workload-type fix below (`wl_<name>_t`, `--security-opt label=type:`) is
a *container* mechanism and does not transfer. Raw QEMU under a systemd unit is
not automatically svirt-MCS-isolated the way a libvirt VM is, so **VM
confinement is its own unaddressed question** — flagged here, not solved by the
`wl_<name>_t` work.

## Open details (decide during build)

- **`base/` SELinux labeling** — control files (Containerfiles, `.te`) likely
  want different labeling than the `container_file_t` blanket on `data/`/`home/`.

## CLI surface (delta)

- `workloadctl catalog` — list shippable bundles under `/usr/.../workloads/`
- `workloadctl init <bundle> [as <name>]` — instantiate a catalog bundle into `/etc`
- `workloadctl duplicate <src> <new>` — copy a live workload (alias: `clone`)
- `workloadctl build <name>` — resolve and run the bundle's build context
- `workloadctl edit <name>` — surface the whole bundle (TOML + any `base/` overrides)

## Suggested sequencing

1. **Catalog + `init`/`duplicate`** — boot-path-free, breaks nothing, delivers
   most of the felt "enable / run-two" pain. Ship first.
2. **`/var` subdir reshape + `bundle` resolution + `./`→`data/`** — touches the
   generator and volume expansion; validate boot carefully.
3. **`build`/`edit` ergonomics + SELinux module-naming cleanup.**
