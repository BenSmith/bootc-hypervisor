# Desktop Labwc Nested Container

Labwc Wayland compositor running nested as a window on your host Wayland
session. Uses wlroots' `wayland` backend — labwc becomes a Wayland client
of the host compositor, so there's no KMS takeover, no seatd, no input or
DRM device juggling. Managed by cosy.

Use this when you want a containerized openbox-style floating desktop you
can pop open in a window while still using your host desktop. For taking
over the physical display, see `desktop-labwc-kms`. For a Wayfire-based
nested desktop with effects/animations, see `desktop-wayfire-nested`.

## Setup

1. **Build the image:**
   ```bash
   cd containers/desktop-labwc-nested
   ./build.sh
   ```

2. **Create and start the container:**
   ```bash
   cosy create --audio --sudo --gpu --image localhost/desktop-labwc-nested:latest my-nested
   cosy start my-nested
   ```

   `--gpu` bind-mounts `/dev/dri` so wlroots can use the GLES2 renderer.
   Drop it for pure software rendering (wlroots falls back to pixman).

   The default cosy feature set includes `--display`, which detects your host
   `$WAYLAND_DISPLAY` and bind-mounts the socket into the container — that's
   what labwc connects to as its backend output.

   `--audio` forwards the host PipeWire socket so apps inside the nested
   desktop play through your host audio stack. No in-container PipeWire
   needed (unlike the KMS variant).

## How it works

- `WLR_BACKENDS=wayland` tells wlroots to open a Wayland window on the
  parent compositor instead of taking over a DRM device.
- `WLR_WL_OUTPUTS=1` creates one virtual output. Bump it to 2+ if you want
  multiple nested "monitors".
- `LIBSEAT_BACKEND=noop` — no seat management needed, there's no hardware
  to arbitrate.
- cosy's display feature mounts `$XDG_RUNTIME_DIR/wayland-N` from the host
  into `/run/user/$HOST_UID/` inside the container.

## Keybindings

From the baked-in `rc.xml`:

- `Super+Return` — foot terminal
- `Super+D` — fuzzel launcher
- `Super+Q` — close window
- `Super+F` — toggle fullscreen
- `Super+Escape` — exit labwc (stops the nested session)
- `Alt+Tab` — next window

## Troubleshooting

```bash
# Service status inside the container
podman exec my-nested systemctl status labwc

# Compositor log
podman exec my-nested journalctl -u labwc --no-pager

# If labwc fails with "failed to open wayland display", verify cosy
# forwarded the socket:
podman exec my-nested ls -la /run/user/$(id -u)/
```

If the nested window looks fuzzy on a HiDPI host, shrink it — wlroots'
wayland backend doesn't do fractional scaling of the inner surface yet.

## Customization

- **Labwc config:** `labwc-config/rc.xml` — keybindings, theme, window rules
- **Labwc autostart:** `labwc-config/autostart` — background, waybar, mako, cliphist
- **Waybar:** `labwc-config/waybar-config` — status bar
- **Foot:** `foot.ini` — terminal font, size, padding
- **Outputs:** change `WLR_WL_OUTPUTS` in `systemd/labwc.service`

User-level overrides (written inside the container's `$HOME`, which maps to
`~/.local/share/cosy/<name>/` on the host) win over the baked-in defaults
via native XDG layering:

- `~/.config/labwc/rc.xml` — labwc searches `$XDG_CONFIG_HOME/labwc/` first,
  then falls back to `/etc/xdg/labwc/`.
- `~/.config/waybar/config` — waybar's native XDG layering.
- `~/.config/foot/foot.ini` — foot's native XDG layering.

## Running heavy apps (Firefox, PyCharm, IDEs)

The service unit already sets `TasksMax=infinity`, so you won't hit systemd's
default 307-thread cap when JetBrains or Firefox fan out.

Other limits are set at `cosy create` time. Cosy passes unrecognized flags
through to `podman create`:

```bash
cosy create --audio --sudo --gpu \
    --shm-size=2g \
    --memory=8g \
    --image localhost/desktop-labwc-nested:latest my-nested
```

- **`--shm-size=2g`** — podman's default `/dev/shm` is 64 MB, too small for
  Firefox/Chromium IPC and WebRender. Bump to 2–4 GB for browsers.
- **`--memory=8g`** — hard cap on container RAM. Omit for no cap.
- **`--cpus=4`** — CPU quota. Omit for no cap.

Host-side concerns (rare, but check if you see mysterious thread/fork
failures):

- `sysctl user.max_user_namespaces` — must be non-zero.
- Your user's `user@UID.service` `TasksMax`:
  `systemctl --user show -p TasksMax`.
