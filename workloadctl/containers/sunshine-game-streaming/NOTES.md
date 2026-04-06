# Sunshine Game Streaming Workload — Implementation Notes

This document covers the design decisions, pitfalls, and debugging lessons
learned while deploying a headless desktop + Sunshine game streaming container
as a rootless podman workload on a Fedora bootc (immutable) system with SELinux
enforcing.

---

## Architecture Overview

The container runs a full systemd init that starts:

1. **container-bootstrap.service** — one-shot first-boot user/group creation
2. **polkit-stub.service** — D-Bus polkit substitute (real polkitd can't run rootless)
3. **labwc.service** — headless Wayland compositor (`WLR_BACKENDS=headless`)
4. **sunshine.service** — game streaming server (captures display via wlr-screencopy)
5. **wayvnc.service** — VNC fallback for debugging
6. **sunshine-input-bridge.service** — evdev-to-Wayland input injection
7. **Audio stack** — PipeWire + WirePlumber + pipewire-pulse (started from labwc autostart)
8. **Steam Big Picture** — launched from labwc autostart

The host hypervisor system manages the container as a workload:
- Dedicated `_wl-sunshine-game-streaming` system user (UID 10000+)
- Rootless podman with `userns=keep-id`
- Persistent home volume at `/var/lib/workloads/sunshine-game-streaming/home`
- Host `setup.sh` configures uinput kernel module, udev rules, and SELinux policy

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
_wl-sunshine-game-streaming:100000:65536   # main subuid range
_wl-sunshine-game-streaming:39:1           # video (GID 39)
_wl-sunshine-game-streaming:63:1           # audio (GID 63)
_wl-sunshine-game-streaming:104:1          # render (GID 104)
_wl-sunshine-game-streaming:105:1          # input (GID 105)
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
systemctl show workload-sunshine-game-streaming --property=TasksMax

# Podman limit
podman inspect -f '{{.HostConfig.PidsLimit}}' workload-sunshine-game-streaming
```

---

## CSRF Protection for Sunshine Web UI

**Problem**: Sunshine's web UI at `https://<host>:47990` returned CSRF errors
when accessed by IP address. `origin_web_ui_allowed=wan` is unreliable across
Sunshine versions.

**First attempt**: Add `csrf_allowed_origins` in the container-bootstrap
one-shot service. Failed because `hostname -I` returned empty — the bootstrap
runs at `After=sysinit.target`, before the network is fully up.

**Fix**: Moved CSRF setup to a dedicated `sunshine-csrf-setup` script that runs
as `ExecStartPre` in `sunshine.service`. At that point the network is
guaranteed up (sunshine starts well after boot). The script:

1. Strips any existing `csrf_allowed_origins` line (IPs may change between restarts)
2. Builds the origins list from `hostname -I`
3. Appends localhost and hostname variants
4. Writes the result to the user's sunshine.conf

```bash
# /usr/local/bin/sunshine-csrf-setup (runs as ExecStartPre in sunshine.service)
ORIGINS=""
for ip in $(hostname -I); do
    [ -n "$ORIGINS" ] && ORIGINS="${ORIGINS},"
    ORIGINS="${ORIGINS}https://${ip}:47990"
done
ORIGINS="${ORIGINS},https://localhost:47990,https://$(hostname):47990"
echo "csrf_allowed_origins=${ORIGINS}" >> "$CONF"
```

**Config file hierarchy**:
- System defaults: `/etc/sunshine/sunshine.conf` (baked into image, read-only)
- User overrides: `/home/desktop/.config/sunshine/sunshine.conf` (persistent volume)
- Sunshine merges both; user config takes precedence

---

## Keyboard Modifier Keys (Shift, Ctrl, Alt)

**Problem**: Typing in the Moonlight client produced characters but modifier
keys had no effect — Shift didn't produce uppercase, Ctrl+C didn't work, pipe
character (`|`) appeared as backslash.

**Root cause**: The Wayland `zwp_virtual_keyboard_v1` protocol requires
explicit `modifiers` events (opcode 2) in addition to `key` events (opcode 1).
The input bridge was only sending key events.

**Fix**: Added xkb state tracking to the keyboard handler. After each key
event, the bridge:

1. Updates an xkb state machine with the key press/release
2. Serializes the modifier state (depressed, latched, locked, layout)
3. If modifiers changed, sends a `modifiers` event to the compositor

```python
direction = XKB_KEY_DOWN if ev_value == 1 else XKB_KEY_UP
xkb_lib.xkb_state_update_key(xkb_state, ev_code + 8, direction)
mods = (
    xkb_lib.xkb_state_serialize_mods(xkb_state, XKB_MOD_DEPRESSED),
    xkb_lib.xkb_state_serialize_mods(xkb_state, XKB_MOD_LATCHED),
    xkb_lib.xkb_state_serialize_mods(xkb_state, XKB_MOD_LOCKED),
    xkb_lib.xkb_state_serialize_mods(xkb_state, XKB_LAYOUT_EFFECTIVE),
)
if mods != prev_mods:
    conn.send(_msg(kb_id, 2, _u32(mods[0]), _u32(mods[1]),
                   _u32(mods[2]), _u32(mods[3])))
    prev_mods = mods
```

**Pitfall**: `XKB_LAYOUT_EFFECTIVE` is `128` (1 << 7), NOT `64` (which is
`XKB_LAYOUT_LOCKED`). Using the wrong value causes the compositor to
misinterpret layout state.

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

## SELinux Policy (sunshine-devices.te)

This was the most iterative and time-consuming part of the deployment. The
container runs under `container_init_t` (systemd container PID 1 context),
which has fewer permissions than a standard process. Every new component
surfaced new denials.

### Debugging technique

1. Check for denials: `sudo ausearch -m avc -ts recent -i | grep denied`
2. Disable dontaudit rules to reveal hidden denials: `sudo semodule -DB`
3. Re-enable when done: `sudo semodule -B`
4. The `-i` flag on `ausearch` converts timestamps to human-readable format

### Permission categories

**Input devices** (`event_device_t`):
- Sunshine creates virtual input devices via `/dev/uinput`
- The input bridge reads evdev events from `/dev/input/eventX`
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

The SELinux policy module is compiled from the `.te` source and installed via
`semodule`. This writes to `/var/lib/selinux` which is writable on bootc
systems (only `/usr` is immutable). The `setup.sh` script handles compilation
and installation:

```bash
checkmodule -M -m -o sunshine-devices.mod sunshine-devices.te
semodule_package -o sunshine-devices.pp -m sunshine-devices.mod
sudo semodule -i sunshine-devices.pp
```

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
3. The container does NOT use host PipeWire/PulseAudio — it runs its own
   PipeWire stack internally, configured in the labwc autostart script
4. PipeWire is configured to use ALSA directly, auto-detecting the analog
   output card

The autostart script dynamically discovers the ALSA card:
```bash
while IFS= read -r line; do
    n=$(echo "$line" | sed -n 's/^card \([0-9]*\):.*/\1/p')
    if [ -n "$n" ] && echo "$line" | grep -qi analog; then
        card_num="$n"
        alsa_card="hw:$card_num,0"
        break
    fi
done < <(aplay -l 2>/dev/null)
```

---

## Container Log Access

Getting logs out of the container proved surprisingly difficult.

**What doesn't work**:
- `journalctl -M <machine>` — rootless containers aren't registered as machines
- `podman logs` with `--log-driver=journald` — sends to host journal but
  `CONTAINER_NAME=` filter returns nothing
- `podman exec` — fails with cgroup permission errors via sudo
- Direct journal file access — container uses volatile journal (no on-disk files)

**What works**: `nsenter` via the container's init PID:

```bash
# Get the container's init PID
PID=$(cd /tmp && sudo -u _wl-sunshine-game-streaming \
    XDG_RUNTIME_DIR=/run/user/10000 \
    podman inspect -f '{{.State.Pid}}' workload-sunshine-game-streaming)

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

Sunshine requires the following ports:

```bash
sudo firewall-cmd --permanent \
    --add-port={47984,47989,47990,48010}/tcp \
    --add-port=47998-48000/udp
sudo firewall-cmd --reload
```

- 47990/tcp — Sunshine web UI (HTTPS)
- 47984/tcp — HTTPS API
- 47989/tcp — RTSP
- 48010/tcp — Control
- 47998-48000/udp — Video/audio streaming

### Key environment variables

| Variable | Value | Purpose |
|----------|-------|---------|
| `STEAM_DISABLE_BROWSER_SANDBOX` | `1` | Disable Chromium sandbox in steamwebhelper (can't nest user namespaces) |
| `CONTAINER_USER` | `desktop` | Container user name |
| `CONTAINER_UID` | `1000` | Container user UID |
| `CONTAINER_GID` | `1000` | Container user GID |

### Capabilities

The container requires these capabilities beyond the default set:

- `SYS_NICE` — Steam adjusts process priorities
- `SYS_CHROOT` — bubblewrap uses chroot for sandbox setup
- `SETUID`/`SETGID`/`SETPCAP`/`SETFCAP` — container-bootstrap creates users, sets capabilities
- `CHOWN`/`DAC_OVERRIDE`/`FOWNER`/`FSETID` — ownership management during bootstrap
- `KILL` — process management
- `NET_BIND_SERVICE` — Sunshine binds to ports < 1024 (if needed)
