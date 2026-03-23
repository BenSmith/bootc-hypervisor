#!/bin/bash
set -e

# Set up XDG_RUNTIME_DIR
export XDG_RUNTIME_DIR=/run/user/$(id -u)
sudo mkdir -p "$XDG_RUNTIME_DIR"
sudo chown "$(id -u):$(id -g)" "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"

# Configure wlroots headless backend
export WLR_BACKENDS=headless
export WLR_HEADLESS_OUTPUTS=1
export WLR_LIBINPUT_NO_DEVICES=1

if [ -c /dev/dri/renderD128 ]; then
    export WLR_RENDER_DRM_DEVICE=/dev/dri/renderD128
fi

# Start labwc compositor under a D-Bus session (needed for waybar, clipboard, etc.)
dbus-run-session labwc &
LABWC_PID=$!

# Wait for Wayland socket
for i in {1..50}; do
    LOCKFILE=$(ls "$XDG_RUNTIME_DIR"/wayland-*.lock 2>/dev/null | head -n1)
    if [ -n "$LOCKFILE" ]; then
        export WAYLAND_DISPLAY=$(basename "$LOCKFILE" .lock)
        break
    fi
    sleep 0.1
done

if [ -z "$WAYLAND_DISPLAY" ]; then
    echo "ERROR: labwc did not create a Wayland socket"
    kill $LABWC_PID 2>/dev/null || true
    exit 1
fi

# Start wayvnc
wayvnc 0.0.0.0 5900 &
WAYVNC_PID=$!

cleanup() {
    kill $WAYVNC_PID 2>/dev/null || true
    kill $LABWC_PID 2>/dev/null || true
    exit 0
}

trap cleanup SIGTERM SIGINT

wait -n
cleanup
