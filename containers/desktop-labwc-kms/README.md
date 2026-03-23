# Desktop Labwc KMS Container

Labwc Wayland compositor running a full desktop environment on the physical
display via KMS (Kernel Mode Setting). Use this when you're sitting at the
computer and want a containerized desktop with keyboard, mouse, and monitor
access. Managed by cosy, not the workload system.

## Setup

1. **Build the container:**
   ```bash
   cd containers/desktop-labwc-kms
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
   cosy create --kms --audio --sudo --image localhost/desktop-labwc-kms:latest my-desktop
   ```

## How it works

### User namespace and device access

cosy's user namespace maps the host user to the same UID inside the container
(e.g., host UID 1000 = container UID 1000). `--group-add keep-groups` preserves
the host user's supplementary GIDs (seat, video, render, input) on PID 1.

The compositor must run as a regular user, not container root — many userspace
apps misbehave as root. However, systemd's `User=` directive calls
`setgroups()`, which would wipe the inherited keep-groups. Instead, the service
uses `setpriv --reuid --regid --keep-groups` to drop privileges without calling
`setgroups()`, preserving the host device GIDs.

### Dynamic user identity

The bootstrap writes `/etc/cosy-user.env` with `COSY_UID`, `COSY_GID`,
`COSY_USER`, and `XDG_RUNTIME_DIR`. The compositor service reads this via
`EnvironmentFile=` — no hardcoded UIDs in the service file.

### Device enumeration

The host's udev database is mounted at `/run/udev:ro`. The container's libudev
reads this directly to enumerate input and DRM devices. `systemd-udevd` is
masked in the image to prevent it from conflicting with the read-only mount.

Input devices are passed via `--device /dev/input` (cosy's input feature,
enabled automatically by `--kms`). DRM devices are passed via the gpu feature.

### wlroots backends

`WLR_BACKENDS=drm,libinput` — both must be specified. Setting only `drm` skips
the libinput backend entirely: the display works but input is silently ignored.

### Logging

journald fails inside containers due to missing capabilities (218/CAPABILITIES).
The compositor logs to `/var/log/labwc.log` via `StandardOutput=file:`.

## cosy flags set by --kms

`--kms` is a composite feature that automatically enables:
- GPU access (DRM/render devices)
- Input devices (keyboards, mice, etc.)
- Host network (for seatd socket)
- systemd mode (systemd as PID 1)

It also disables the display feature (no Wayland/X11 socket forwarding — this
container *is* the display server).

## Troubleshooting

```bash
# Check service status inside the container
podman exec my-desktop systemctl status labwc

# View compositor log
podman exec my-desktop cat /var/log/labwc.log

# Verify input devices are visible
podman exec my-desktop ls /dev/input/

# Verify udev database is mounted
podman exec my-desktop ls /run/udev/data/

# Check process groups (host GIDs show as 65534 inside container)
podman exec my-desktop cat /proc/1/status | grep Groups

# If service fails with Result: resources after repeated failures
podman exec my-desktop systemctl reset-failed labwc
podman exec my-desktop systemctl start labwc
```

## Customization

- **Labwc config:** `labwc-config/rc.xml` — keybindings, window rules, theme
- **Autostart:** `labwc-config/autostart` — programs launched with the compositor
- **Waybar:** `labwc-config/waybar-config` — status bar configuration
