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
- **Waybar:** `waybar-config` — status bar configuration
