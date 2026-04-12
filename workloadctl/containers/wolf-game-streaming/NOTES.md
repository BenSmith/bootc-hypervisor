# wolf-game-streaming — implementation notes

Things that aren't obvious from reading the code, captured here so the next
person doesn't have to rediscover them.

## What's Wolf?
https://github.com/games-on-whales/wolf is a game streaming server that
supports [the Moonlight protocol](https://moonlight-stream.org). It is 
designed to stream multiple game streams from a Linux host to a client 
device over a network connection. It is able to use the GPU of the host
to both render the game and encode the stream, without an intermediate copy.

### Wolf in workloadctl

Unlike Wolf's typical operation, this implementation does not spawn multiple
game streams. If multiple streams are desired, one can make multiple workload
instances. I do not know how well this will share GPU resources.

## Architecture: why gamescope is nested under Wolf

Wolf's compositor is `gst-wayland-display`, which **intentionally has no
XWayland**. Per the upstream Wolf docs, X11 apps like Steam are expected to
run under a nested **gamescope** session, which:

- Provides its own XWayland to its children
- Enforces fullscreen
- Scales the game's framebuffer to the compositor output
- Reports lifecycle events back to Steam (`-e` / `--steam`)

So the call chain is: Wolf → `gst-wayland-display` (wayland compositor) →
gamescope (wayland client of Wolf, also a wayland+XWayland compositor for
its children) → Steam (X11 client of gamescope).

The zero-copy DMA-BUF pipeline (Steam → gamescope vulkan blit → 
DMA-BUF surface → Wolf → VAAPI encode) needs the wayland backend, we use 
--backend wayland we don't rely on auto-detection. With any other backend 
(SDL, headless) gamescope would pixel-copy and the fastest path would be lost.

Wolf exports `GAMESCOPE_WIDTH/HEIGHT/REFRESH` from the Moonlight client's
requested stream parameters. `steam-launcher.sh` passes these straight
through to `gamescope -W -H -r`. 

## bwrap capability drop

Steam's runtime uses `pressure-vessel` / `bwrap`, which **refuses to run
with any capabilities in its permitted set** when not setuid and without
file caps. Podman's `--cap-add` puts caps in our ambient set, which would
propagate to bwrap on exec.

`steam-launcher.sh` therefore wraps gamescope with:

```
setpriv --ambient-caps=-all --inh-caps=-all --bounding-set=-all -- gamescope ...
```

The capabilities listed in `wolf-game-streaming.toml` are still needed by
Wolf itself (input forwarding, port binding, sandbox setup) — they're
dropped only for the gamescope/Steam subtree.

## Wolf `set_session_id_context` default

`src/moonlight-server/rest/rest.hpp` declares
`bool set_session_id_context = false;` and Wolf never flips it. The
`Server<HTTPS>::after_bind()` branch that calls
`SSL_CTX_set_session_id_context()` seems to be unused, and Wolf's HTTPS
server runs with no session ID context set on its SSL_CTX.

OpenSSL only enforces this on session-resumption-capable client cert
handshakes. The first HTTPS request from a new client (the `/pair`
challenge) goes through fine — no resumption attempt. Every subsequent
request (`applist`, `serverinfo`, launch, etc.) tries to resume, OpenSSL
checks for a session ID context, finds none, and refuses with:

```
HTTPS error during request at <path> error code: 167772437 -
session id context uninitialized (SSL routines)
```

…which surfaces on the client as `QNetworkReply::SslHandshakeFailedError`.

`Containerfile` patches `rest.hpp` to flip the default to `true` via `sed`,
with a `grep -q` sanity check pinned against `WOLF_COMMIT`. One line, no
protocol caps, no behavioral change beyond making `after_bind()` 
do its job.

## Audio: Wolf's `start_audio_server`

`start_audio_server = true` in `config.toml` is a **per-app gate** that
controls whether Wolf's `create_virtual_sink` and `start_audio_producer`
run *at all*. It is not "should Wolf spawn pulse" — Wolf's
`setup_audio_server()` always tries to connect to an existing pulse via
`PULSE_SERVER` first, and tries to fall back to spawning a `pulseaudio` 
container (via `/var/run/docker.sock`, which is a challenge under
rootless podman) if that fails.

So the working pattern is:
1. `entrypoint.sh` runs pulseaudio in the container, exports `PULSE_SERVER`
2. `config.toml` sets `start_audio_server = true` so Wolf's per-app audio
   pipeline is active
3. Wolf's `setup_audio_server()` connects to our pulse via `PULSE_SERVER`
4. Wolf's `create_virtual_sink` calls `pa_context_load_module` against our
   pulse, creating a per-session null sink whose name is passed to the
   runner as `$PULSE_SINK`

If `start_audio_server = false`, Wolf skips both `create_virtual_sink` and
`start_audio_producer`, the sink never exists, and there's no audio
regardless of how perfectly your pulse is set up.

workloadctl's `extra_groups` does **not** need `audio` — the in-container 
pulse uses a unix socket and never touches `/dev/snd`.

## `WOLF_LOG_LEVEL=INFO` is required for pairing

Wolf logs the pairing URL (`http://<host>:47989/pin/#<secret>`) at INFO
level. Without that URL the user has no way to enter a PIN, so pairing
silently fails. Using log level `WARN` will not output the URL.

## UID remap: Steam refuses to run as root

The container's `USER` is `steam` at uid 1000. The workload uses
`userns = "keep-id:uid=1000,gid=1000"` so the host workload user is
remapped to uid 1000 inside the container. Steam refuses to launch as
root, and the upstream Wolf image convention is uid 1000. Bind-mounted
`/home/steam` is chowned on the host to the workload user, which appears
as uid 1000 inside.

When `extra_groups` is present the generator emits raw `--uidmap`/`--gidmap`
flags (mutually exclusive with `--userns` in podman 5.x), and honors the
`:uid=N,gid=N` suffix to remap the workload user to the requested
in-container uid rather than hardcoding the host UID.

## SELinux: wolf is non-systemd → container_t only

Wolf's entrypoint is a bash script — there is no systemd in this
container. All processes (Wolf, gamescope, Steam, bwrap, the game) run as
`container_t`.

`wolf-devices.te` allows `container_t` to:

- **Input devices**: read/write/ioctl on `event_device_t` (covers
  `/dev/uinput` for virtual device creation and `/dev/input/event*` for
  evdev forwarding from Moonlight clients)
- **Udev runtime database**: read `udev_var_run_t` (libdrm, mesa, ALSA all
  query device properties)
- **Steam bwrap sandbox**: `remount` on `cgroup_t`, `pstore_t`, `bpf_t`,
  `tmpfs_t`; `mount` on `devpts_t`; `mounton` on `container_file_t` and
  `user_tmp_t` sock_files (bind-mounting over PulseAudio sockets during
  sandbox setup)
- **Steam IPC**: full `user_tmp_t` access (Steam uses `/tmp` for IPC
  sockets and temp files)
- **Wine/Proton**: `execheap` and `mmap_zero` on self (Wine's PE loader
  needs executable heap and the NULL-page mapping for Windows binary
  compatibility); `execmod` on `container_file_t` files (ntdll.dll text
  relocations)

If you see new AVCs after a Wolf or Steam upgrade, the audit line will
identify which class is missing — add it to `container_t`.

## Capabilities required and why

| Capability | Why |
|---|---|
| `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID` | Steam runtime sandbox setup |
| `SETUID`, `SETGID` | bwrap user namespace setup (used before being dropped by `setpriv`) |
| `KILL` | Process management of Steam children |
| `NET_BIND_SERVICE` | Wolf binds to ports 47984/47989 |
| `SETFCAP`, `SETPCAP` | bwrap capability manipulation |
| `SYS_CHROOT` | bwrap chroot for sandbox |
| `SYS_NICE` | Process priority for the encode pipeline |

These are dropped from gamescope/Steam subtree by `setpriv` before exec
(see bwrap section above).

## Devices and bind mounts

- `/dev/uinput` — virtual input device creation
- `/dev/input` (bind mount) — evdev forwarding
- `/run/udev` (ro bind mount) — device property database
- `/dev/dri/renderD128` — VAAPI encode + Vulkan rendering
- `./config:/etc/wolf` — Wolf config persistence (key.pem, cert.pem,
  config.toml, apps-state)
- `./home:/home/steam` — Steam library and config persistence

`/run/udev` is read-only because we only need to query the database.

## Container build pinning

`Containerfile` pins everything by SHA/digest:

- Fedora base by digest
- Wolf, gst-wayland-display, gst-interpipe by commit SHA

These are pinned so the build is reproducible. There's a lot of moving parts.
Ideally I learn where the upstream stability points are for this to be simpler.

## Things deferred to future work

- **First-run splash**: When connected, Moonlight shows a blank black screen 
  until steam finishes downloading its updates. This can take a while (many minutes)
  depending on your network connection. It would be good to show a message about
  it until the download completes.
- **Nvidia GPU branch**: only the `amd` GPU type is currently wired up in
  `Containerfile`.
- **Pulse sink teardown**: the per-session null sinks created by Wolf's
  `create_virtual_sink` aren't cleaned up between sessions. Not yet a
  problem in practice but worth a `pactl unload-module` on session exit.
