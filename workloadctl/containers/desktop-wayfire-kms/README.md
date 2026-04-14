# Desktop Wayfire KMS Container

Wayfire Wayland compositor running a full desktop environment on the physical
display via KMS (Kernel Mode Setting). Use this when you're sitting at the
computer and want a containerized desktop with keyboard, mouse, and monitor
access. Managed by cosy, not the workload system.

## Setup

1. **Build the container:**
   ```bash
   cd containers/desktop-wayfire-kms
   ./build.sh
   ```

2. **Ensure seatd is running on the host:**
   ```bash
   sudo systemctl enable --now seatd
   ```

3. **Ensure your user is in the required groups:**
   ```bash
   sudo usermod -aG seat,input,video,render $USER
   ```
   Log out and back in for group changes to take effect.

4. **Create and start the container:**
   ```bash
   cosy create --kms --audio --sudo --image localhost/desktop-wayfire-kms:latest my-desktop
   ```

## How it works

See the [desktop-labwc-kms README](../desktop-labwc-kms/README.md) for details
on the user namespace, device access, and udev setup — the architecture is
identical. The only difference is the compositor binary and its configuration.

## Troubleshooting

```bash
# Check service status inside the container
podman exec my-desktop systemctl status wayfire

# View compositor log
podman exec my-desktop cat /var/log/wayfire.log

# If service fails with Result: resources after repeated failures
podman exec my-desktop systemctl reset-failed wayfire
podman exec my-desktop systemctl start wayfire
```

## Customization

- **Wayfire config:** `wayfire.ini` — plugins, keybindings, output settings
- **Foot:** `foot.ini` — terminal font, size, padding

The shell (panel, background, dock) is provided by **wf-shell**, which reads
`~/.config/wf-shell.ini` (user) and falls back to `/etc/xdg/wf-shell.ini`
(none shipped — wf-shell defaults apply). Launch `wcm` from a foot terminal
to tweak wayfire plugins via a GUI.

Also bundled: `swayidle` (idle management), `swaylock` (screen lock), and
`kanshi` (dynamic output configuration based on connected monitors). None
are wired into autostart by default — configure and launch them yourself.

User-level overrides written inside the container's `$HOME` (which maps to
`~/.local/share/cosy/<name>/` on the host) win over the baked-in defaults:

- `~/.config/wayfire/wayfire.ini` — seeded on first start with
  `@include /etc/xdg/wayfire.ini`, so wcm edits layer on top of the defaults.
- `~/.config/wf-shell.ini` — panel/dock/background settings.
- `~/.config/foot/foot.ini` — native XDG layering.

## Running heavy apps (Firefox, PyCharm, IDEs)

The service unit sets `TasksMax=infinity`, so you won't hit systemd's default
307-thread cap when JetBrains or Firefox fan out.

Other limits are set at `cosy create` time. Cosy passes unrecognized flags
through to `podman create`:

```bash
cosy create --kms --audio --sudo \
    --shm-size=2g \
    --memory=8g \
    --image localhost/desktop-wayfire-kms:latest my-desktop
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
