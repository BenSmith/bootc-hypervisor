#!/bin/bash
set -e

export LIBSEAT_BACKEND=noop
export WLR_BACKENDS=headless
export WLR_HEADLESS_OUTPUTS=1
export WLR_LIBINPUT_NO_DEVICES=1
export XDG_RUNTIME_DIR=/run/user/$(id -u)

sudo mkdir -p "$XDG_RUNTIME_DIR"
sudo chown "$(id -u):$(id -g)" "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"

ls /dev/dri/renderD* 2>/dev/null | grep -q . || export LIBGL_ALWAYS_SOFTWARE=1

# Start labwc compositor under a D-Bus session (needed for waybar, clipboard, etc.)
dbus-run-session labwc &
LABWC_PID=$!

# Wait for Wayland socket
for i in {1..50}; do
    for sock in "$XDG_RUNTIME_DIR"/wayland-*; do
        [ -S "$sock" ] && export WAYLAND_DISPLAY=$(basename "$sock") && break 2
    done
    sleep 0.1
done

if [ -z "${WAYLAND_DISPLAY:-}" ]; then
    echo "ERROR: labwc did not create a Wayland socket"
    kill $LABWC_PID 2>/dev/null || true
    exit 1
fi

# Configure wayvnc authentication
WAYVNC_ARGS=""
if [ -n "${VNC_PASSWORD:-}" ]; then
    mkdir -p "$HOME/.config/wayvnc"
    VNC_USER=$(whoami)
    cat > "$HOME/.config/wayvnc/config" <<EOF
enable_auth=true
username=${VNC_USER}
password=${VNC_PASSWORD}
EOF
    chmod 600 "$HOME/.config/wayvnc/config"
    echo "VNC authentication enabled (username: ${VNC_USER})"
else
    echo "WARNING: VNC has no authentication — set VNC_PASSWORD to enable"
fi

wlr-randr --output HEADLESS-1 --custom-mode "${DESKTOP_RESOLUTION:-1920x1080}@60" || true

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
