# Sunshine Streaming Workload — Implementation Notes

This document covers the design decisions, pitfalls, and debugging lessons
learned while deploying a headless desktop + Sunshine game streaming container
as a rootless podman workload on a Fedora bootc (immutable) system with SELinux
enforcing.

---

## Architecture Overview

The container runs a full systemd init that starts:

1. **container-bootstrap.service** — one-shot first-boot user/group creation
2. **polkit-stub.service** — D-Bus polkit substitute (real polkitd can't run rootless)
3. **seatd.service** — libseat session so wayfire's libinput backend can open input devices
4. **wayfire.service** — headless Wayland compositor (`WLR_BACKENDS=headless,libinput`)
5. **wayfire-wayland-ready.service** — oneshot barrier; blocks until the Wayland socket exists
6. **sunshine.service** — game streaming server (captures display via wlr-screencopy)
7. **wayvnc.service** — VNC fallback for debugging (not enabled; no auth, binds all interfaces)
8. **Audio stack** — pipewire.service + wireplumber.service + pipewire-pulse.service
9. **Steam Big Picture** — launched from wayfire's autostart

Anything needing the display orders itself `After=wayfire-wayland-ready.service`
rather than after `wayfire.service`, because the compositor's unit is up before
its socket is.

The host hypervisor system manages the container as a workload:
- Dedicated `_wl-sunshine-streaming` system user (UID 10000+)
- Rootless podman with `userns=keep-id`
- Persistent home volume at `/var/lib/workloads/sunshine-streaming/home`
- Host `setup.sh` loads the uinput module, installs the udev relay, mints the
  web UI's TLS cert, and advertises the host over mDNS. SELinux policy is loaded
  by `workloadctl enable` from `[security].selinux_policy`, not by the script.

---

## Podman 5.x: userns and uidmap Mutual Exclusivity

**Problem**: Podman 5.x rejects combining `--userns=keep-id` with
`--uidmap`/`--gidmap` flags:

```
Error: --userns and --uidmap/--gidmap are mutually exclusive
```

**Root cause**: The `+` prefix on uidmap/gidmap entries (`+UID:@UID:1`) already
implies keep-id semantics. Podman 5.x enforces this by rejecting the redundant
`--userns` flag.

**Fix**: The generator omits `--userns=keep-id` when `+`-prefixed maps are
present. The maps themselves provide the keep-id behavior:

```python
needs_auto_maps = (
    userns_mode.startswith("keep-id")
    and (extra_groups or extra_uidmaps or extra_gidmaps)
)
if needs_auto_maps:
    # +UID implies keep-id — don't pass --userns
    podman_args.append(f"--uidmap +{uid}:@{uid}:1")
    podman_args.append(f"--gidmap +{gid}:@{gid}:1")
    # ...
else:
    podman_args.append(f"--userns={userns_mode}")
```

**Key insight**: `userns=host` was NOT the answer for this container. The `+`
prefix on maps addresses supplementary group mapping while preserving keep-id
security (no container root access).

---

## Supplementary Group GID Delegation

**Problem**: Podman's `--gidmap +GID:@GID:1` requires the GID to be delegated
in `/etc/subgid`. Host group membership alone is insufficient:

```
Error: parent ID GID 39 is not mapped/delegated
```

**Root cause**: `@GID` syntax tells podman "map this GID from the host into the
container's user namespace". This requires an entry in `/etc/subgid` that
delegates that specific GID to the workload user, even if the user is already a
member of the group.

**Fix**: `workload-ensure-user` now adds individual GID entries to both
`/etc/subuid` and `/etc/subgid` for every group in `extra_groups`:

```
_wl-sunshine-streaming:600100000:65536  # main subuid range (this UID's; see docs/workloads.md)
_wl-sunshine-streaming:39:1           # video (GID 39)
_wl-sunshine-streaming:63:1           # audio (GID 63)
_wl-sunshine-streaming:104:1          # render (GID 104)
_wl-sunshine-streaming:105:1          # input (GID 105)
```

After modifying these files, `podman system migrate` must be run for the
workload user to pick up the new mappings. The script does this automatically.

The `--group-add=keep-groups` flag passes all host supplementary groups into
the container process.

---

## Container PID Limit (tasks_max vs --pids-limit)

**Problem**: Steam crashed with `failed to spawn thread: Resource temporarily
unavailable` despite `TasksMax=16384` in the systemd unit.

**Root cause**: `tasks_max` in the workload config only set systemd's
`TasksMax=` directive on the service unit. Podman independently defaults
`--pids-limit` to 2048 inside the container. The systemd limit was never
reached; the podman limit was.

**Fix**: The generator now sets both:
- `TasksMax={tasks_max}` in the systemd service unit
- `--pids-limit={tasks_max}` in the podman run command

Steam Big Picture + steamwebhelper (Chromium) + Proton easily exceed 4096
tasks. 16384 is comfortable.

**Verification**:
```bash
# Systemd limit
systemctl show workload-sunshine-streaming --property=TasksMax

# Podman limit
podman inspect -f '{{.HostConfig.PidsLimit}}' workload-sunshine-streaming
```

---

## CSRF Protection for Sunshine Web UI

**Problem**: Sunshine's web UI at `https://<host>:47990` returned CSRF errors
when accessed by IP address. `origin_web_ui_allowed=wan` is unreliable across
Sunshine versions.

**First attempt**: Add `csrf_allowed_origins` in the container-bootstrap
one-shot service. Failed because `hostname -I` returned empty — the bootstrap
runs at `After=sysinit.target`, before the network is fully up.

**Fix**: Moved CSRF setup into `/usr/local/bin/sunshine-prestart`, which runs as
`ExecStartPre` in `sunshine.service`. At that point the network is guaranteed up
(sunshine starts well after boot). Every input it reads can change between
restarts, so it rewrites rather than appends — it strips the lines it owns
(`port=`, `adapter_name=`, `encoder=`, `csrf_allowed_origins=`, `cert=`,
`pkey=`) from the user's sunshine.conf and re-derives them:

- **origins** from `hostname -I`, plus localhost and hostname variants
- **adapter_name + encoder** from the PCI vendor of the visible render node
  (`0x10de` → nvenc, `0x1002`/`0x8086` → vaapi). With `gpu` pinned in the TOML
  only one `/dev/dri/renderD*` is mounted, so the loop selects that GPU.
- **cert/pkey** when `setup.sh` minted a Homelab-CA-signed pair (mounted
  read-only at `/etc/sunshine/tls`); absent, Sunshine self-signs.

```bash
# /usr/local/bin/sunshine-prestart (ExecStartPre in sunshine.service)
WEB_PORT=$((SUNSHINE_PORT + 1))
ORIGINS=""
for ip in $(hostname -I 2>/dev/null); do
    [ -n "$ORIGINS" ] && ORIGINS="${ORIGINS},"
    ORIGINS="${ORIGINS}https://${ip}:${WEB_PORT}"
done
ORIGINS="${ORIGINS},https://localhost:${WEB_PORT},https://$(hostname):${WEB_PORT}"
echo "csrf_allowed_origins=${ORIGINS}" >> "$CONF"
```

The web UI port is not a constant: it is `SUNSHINE_PORT + 1`, and
`SUNSHINE_PORT` is settable per instance so two Sunshine hosts can share a
machine's port space (host networking).

**Config file hierarchy**:
- System defaults: `/etc/sunshine/sunshine.conf` (baked into image, read-only)
- User overrides: `/home/desktop/.config/sunshine/sunshine.conf` (persistent volume)
- Sunshine merges both; user config takes precedence

---

## Input from Moonlight Clients

There is no input-injection bridge in this bundle. Sunshine creates uinput
devices (mouse/keyboard/touch/pen/gamepad) when a Moonlight client connects, and
wayfire's libinput backend consumes them natively — `WLR_BACKENDS` is
`headless,libinput`, `seatd` supplies the libseat session, and the host udev
database is bind-mounted read-only at `/run/udev` for the property lookups.

**Pitfall**: libinput only learns about a device from a udev netlink *hotplug*
event, and those don't survive the crossing into the container. libudev requires
the sender UID to be 0, and the host udevd's UID 0 maps to an unprivileged
("nobody") UID inside the container's user namespace, so the events are dropped
— devices created after the container started are invisible, which is every
device Sunshine makes.

The container can't re-broadcast them itself: with host networking the netlink
socket lives in the host's network namespace, where a rootless container has no
`CAP_NET_ADMIN`. Hence the host-side `udev-relay` that `setup.sh` installs as a
service: it re-broadcasts the host's input events with the sender UID declared
(via `SCM_CREDENTIALS`) as the host UID that the container's UID 0 maps to, read
from the live container's `/proc/<pid>/uid_map`. It relays only virtual (uinput)
devices, and the UID filter that makes it work also stops it looping on its own
broadcasts. See the module docstring in `udev-relay` for the wire format.

---

## Steam pressure-vessel / bubblewrap (srt-bwrap)

**Problem**: Steam's runtime launcher (pressure-vessel) uses bubblewrap
(srt-bwrap) to create a nested sandbox inside the container. This caused
multiple failures.

### Wayland socket conflict

**Symptom**: `bwrap: Can't make symlink at /run/user/1000/wayland-0:
destination exists and is not a symlink`

**Root cause**: `PRESSURE_VESSEL_FILESYSTEMS_RW="$XDG_RUNTIME_DIR"` mounted
the entire runtime directory into bwrap's sandbox, including the real Wayland
socket. When bwrap then tried to create a symlink at the same path for its own
Wayland forwarding, it found the real socket blocking the path.

**Fix**: Remove `PRESSURE_VESSEL_FILESYSTEMS_RW`. Pressure-vessel already
knows how to forward the Wayland socket on its own via the `WAYLAND_DISPLAY`
environment variable.

### steamwebhelper Chromium sandbox

**Symptom**: `Failed creating offscreen shared JS context` — Steam's UI
(steamwebhelper, which is Chromium-based) crashes on startup.

**Fix**: Set `STEAM_DISABLE_BROWSER_SANDBOX=1` in the environment. The
Chromium sandbox tries to `clone(CLONE_NEWUSER)` which can't nest inside the
container's already-nested user namespace.

### Missing 32-bit libraries

**Symptom**: `missing following 32-bit libraries: libbz...`

**Fix**: Steam itself installs 32-bit dependencies on first run. The
`steam` RPM from RPMFusion pulls in the required compat libraries. If
warnings persist, Steam's built-in Steam Linux Runtime provides them via
pressure-vessel.

---

## SELinux Policy (policy.cil)

This was the most iterative and time-consuming part of the deployment. The
container ships a per-workload SELinux type, `wl_sunshine_streaming.process`
(via `[security].selinux_policy`). The rule discovery below was done against
`container_init_t` (the stock systemd-container PID 1 context) and the same
rules now apply to the workload's own type. Every new component surfaced new
denials.

### Debugging technique

1. Check for denials: `sudo ausearch -m avc -ts recent -i | grep denied`
2. Disable dontaudit rules to reveal hidden denials: `sudo semodule -DB`
3. Re-enable when done: `sudo semodule -B`
4. The `-i` flag on `ausearch` converts timestamps to human-readable format

### Permission categories

**Input devices** (`event_device_t`):
- Sunshine creates virtual input devices via `/dev/uinput`
- wayfire's libinput backend reads evdev events from `/dev/input/eventX`
- Both paths are labeled `event_device_t` on Fedora
- Permissions: `chr_file { open read write ioctl getattr }`, `dir { open read search getattr }`

**Udev database** (`udev_var_run_t`):
- libdrm, mesa, and ALSA query device properties from `/run/udev`
- Permissions: `dir`, `file`, `sock_file { getattr }`, `lnk_file { read getattr }`

**Bubblewrap filesystem operations**:
- `srt-bwrap` remounts `cgroup_t`, `pstore_t`, `bpf_t`, `tmpfs_t` filesystems
  as part of sandbox setup
- Mounts a new `devpts_t` filesystem inside the sandbox
- Bind-mounts over PipeWire sockets (`container_file_t:sock_file mounton`)
  and potentially `user_tmp_t:sock_file mounton`

**Steam IPC** (`user_tmp_t`):
- Steam uses `/tmp` for IPC sockets and temp files
- Needs broad dir/sock_file/file access on `user_tmp_t`

**Wine/Proton**:
- `execmod` on `container_file_t:file` — ntdll.dll has text relocations
- `execheap` on `self:process` — Wine's heap allocator marks pages executable
- `mmap_zero` on `self:memprotect` — wine-preloader maps the zero page for
  Windows NULL-pointer region compatibility (note: `mmap_zero` is in the
  `memprotect` class, not `process`)
- Note: `execmem` and `execstack` are already granted by the base
  `container-selinux` policy

### Hidden denials (dontaudit rules)

The base container-selinux policy includes `dontaudit` rules that silently
suppress certain AVCs. This means `ausearch` shows nothing even though
operations are being denied. To reveal these:

```bash
# Disable dontaudit rules (reveals all denials)
sudo semodule -DB

# Reproduce the issue, then check AVCs
sudo ausearch -m avc -ts recent -i | grep denied

# Re-enable dontaudit rules when done
sudo semodule -B
```

This was critical for discovering the `container_init_t` denials — without
disabling dontaudit, only `container_t` denials were visible, but the container
runs systemd so all processes use `container_init_t`.

### Policy installation on bootc

The policy is a udica-style CIL block (`policy.cil` in this bundle) loaded by
`workloadctl enable` (via `[security].selinux_policy`) — no `checkmodule`
compile step; CIL loads directly. It writes to `/var/lib/selinux`, which is
writable on bootc systems (only `/usr` is immutable). Roughly what enable does:

```bash
# __WL_MODULE__ -> wl_sunshine_streaming, then:
sudo semodule -i wl_sunshine_streaming.cil /usr/share/udica/templates/*.cil
```

**Key gotcha:** because the container runs systemd (`--systemd=always`), the
type must be attributed into `container_init_domain`
(`(typeattributeset container_init_domain (process))` in the CIL) — without it
systemd-as-PID1 exits 255 with *no AVCs* (it's a missing attribute, not a denied
rule). `(blockinherit container)` alone gives a `container_t`-equivalent, which
is not init-capable. `setup.sh` handles only the non-SELinux prerequisites: the
uinput module load, the udev relay, the TLS cert, and the mDNS advertisement.
The `/dev/uinput` group-access udev rule and the module autoload config are
image-owned (`/usr/lib/udev/rules.d/72-uinput-input.rules`,
`/usr/lib/modules-load.d/uinput.conf`), so they persist across bootc upgrades.

### SELinux research sources

- [container-selinux container.te](https://github.com/containers/container-selinux/blob/main/container.te) — base policy for container types
- [wine_selinux(8)](https://man.docs.euro-linux.com/EL%206%20ELS/selinux-policy-doc/wine_selinux.8.en.html) — Wine process memory requirements
- [Red Hat Bugzilla #870652](https://bugzilla.redhat.com/show_bug.cgi?id=870652) — wine-preloader mmap_zero
- [Red Hat Bugzilla #2293851](https://bugzilla.redhat.com/show_bug.cgi?id=2293851) — wine-preloader execheap
- [bubblewrap issue #269](https://github.com/containers/bubblewrap/issues/269) — bwrap SELinux mount/remount denials
- [steam-runtime issue #640](https://github.com/ValveSoftware/steam-runtime/issues/640) — pressure-vessel permission denied

---

## Audio Setup

**Problem**: No audio output despite `/dev/snd` being mapped into the container.

**Root cause**: The workload user wasn't in the `audio` group, so the
container process couldn't access `/dev/snd/*` devices (owned by `audio`,
GID 63).

**Fix**:
1. Added `audio` to `extra_groups` in the workload TOML
2. Added `/dev/snd` to `devices` list
3. The container does NOT use host PipeWire/PulseAudio — it runs its own stack
   as three systemd units (`pipewire`, `wireplumber`, `pipewire-pulse`), each
   started as the container user after `container-bootstrap.service`
4. WirePlumber auto-detects the ALSA devices under `/dev/snd`; there is no
   card-selection config to maintain

`audio = true` is deliberately *not* set in the TOML: that flag bind-mounts the
host's PipeWire/Pulse sockets in, which would put a second sound server in front
of the one this container runs. `/dev/snd` comes in as a `[storage]` volume
rather than a `--device` because it is a directory whose node list changes across
reboots.

---

## Container Log Access

Getting logs out of the container proved surprisingly difficult.

**Use `workloadctl logs sunshine-streaming`.** Units run with
`--log-driver=passthrough`, so `podman logs` fails outright; journald attributes
the app's output to the rootless user manager's cgroup rather than the workload
unit, and `workloadctl logs` is what ORs the right journal filters together. Raw
per-service output: `journalctl -t sunshine` (or `-t wayfire`, `-t wireplumber`,
… — every unit in the image sets its own `SyslogIdentifier`).

**What doesn't work**:
- `journalctl -M <machine>` — rootless containers aren't registered as machines
- `podman logs` with `--log-driver=journald` — sends to host journal but
  `CONTAINER_NAME=` filter returns nothing
- `podman exec` — fails with cgroup permission errors via sudo
- Direct journal file access — container uses volatile journal (no on-disk files)

**For anything that isn't the journal** — reading Steam's log files, poking at
container state — go in with `nsenter` via the container's init PID:

```bash
# Get the container's init PID
PID=$(cd /tmp && sudo -u _wl-sunshine-streaming \
    XDG_RUNTIME_DIR=/run/user/10000 \
    podman inspect -f '{{.State.Pid}}' workload-sunshine-streaming)

# Run commands inside the container's namespaces
sudo nsenter -t $PID -m -p -- <command>
```

**Note**: `cd /tmp` is required because `sudo -u` fails if the current working
directory isn't readable by the target user.

**Note**: `systemctl` doesn't work via nsenter (no dbus connection), but
direct file reads work fine.

### Steam log locations (inside container)

| Path | Contents |
|------|----------|
| `/home/desktop/.steam/steam/logs/bootstrap_log.txt` | Steam startup/update log |
| `/home/desktop/.steam/steam/logs/console-linux.txt` | Main runtime log (most useful) |
| `/home/desktop/.steam/steam/logs/webhelper.txt` | steamwebhelper/CEF log |
| `/home/desktop/.steam/steam/logs/webhelper-linux.txt` | pressure-vessel/bwrap launch log |
| `/home/desktop/.steam/steam/logs/webhelper_gpu.txt` | GPU-related webhelper log |
| `/tmp/dumps/` | Crash dumps (often 0-byte when minidumps disabled) |

### Sunshine config locations

| Path | Purpose |
|------|---------|
| `/etc/sunshine/sunshine.conf` | System defaults (in image, read-only) |
| `/home/desktop/.config/sunshine/sunshine.conf` | User overrides (persistent volume) |

---

## Bootc / Immutable OS Considerations

The target system runs Fedora bootc, which has a read-only `/usr`. This
affects deployment in several ways:

- **No live file edits**: Can't modify container rootfs files via `nsenter` +
  `sed` — fuse-overlayfs returns "Value too large for defined data type"
- **Generator updates**: The workload generator lives in `/usr/libexec/` and
  can only be updated by rebuilding the bootc image. For testing, manual
  workarounds (like podman's `containers.conf.d` on `/etc`) can bridge the gap.
- **SELinux policy**: `semodule` writes to `/var/lib/selinux` which IS
  writable. Policy updates work without a reimage.
- **Testing workflow**: Edit on dev machine → rebuild container image → rebuild
  bootc image → `bootc upgrade` on target → disable --purge → enable

---

## Workload Configuration Reference

### Firewall ports

Every port Sunshine uses derives from the base port, so don't hardcode them —
`setup.sh` prints the exact `firewall-cmd` invocation for the instance's base at
the end of `enable`. At the default base of 47989 that is:

```bash
sudo firewall-cmd --permanent \
    --add-port={47984,47989,47990,48010}/tcp \
    --add-port=47998-48000/udp
sudo firewall-cmd --reload
```

| Offset from base | Default | Purpose |
|------------------|---------|---------|
| base − 5 | 47984/tcp | HTTPS API |
| base | 47989/tcp | Base port |
| base + 1 | 47990/tcp | Web UI (HTTPS) |
| base + 21 | 48010/tcp | RTSP |
| base + 9 … +11 | 47998-48000/udp | Video/audio/input |

The UDP range is the one that gets forgotten: pairing succeeds without it, then
the stream dies.

### Key environment variables

| Variable | Value | Purpose |
|----------|-------|---------|
| `STEAM_DISABLE_BROWSER_SANDBOX` | `1` | Disable Chromium sandbox in steamwebhelper (can't nest user namespaces) |
| `CONTAINER_USER` | `desktop` | Container user name |
| `CONTAINER_UID` | `1000` | Container user UID |
| `CONTAINER_GID` | `1000` | Container user GID |
| `DESKTOP_RESOLUTION` | `1920x1080` | Headless output mode, applied by `wlr-randr` from wayfire's autostart |
| `SUNSHINE_PORT` | unset (47989) | Base port. Set only to coexist with another Sunshine host on the same machine; `setup.sh` reads it from the instance TOML and advertises that base over mDNS |

### Capabilities

The container requires these capabilities beyond the default set:

- `SYS_NICE` — Steam adjusts process priorities
- `SYS_CHROOT` — bubblewrap uses chroot for sandbox setup
- `SETUID`/`SETGID`/`SETPCAP`/`SETFCAP` — container-bootstrap creates users, sets capabilities
- `CHOWN`/`DAC_OVERRIDE`/`FOWNER`/`FSETID` — ownership management during bootstrap
- `KILL` — process management
- `NET_BIND_SERVICE` — Sunshine binds to ports < 1024 (if needed)
