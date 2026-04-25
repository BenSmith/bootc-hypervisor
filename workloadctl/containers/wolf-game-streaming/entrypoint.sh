#!/bin/bash
set -euo pipefail

WOLF_HOME="${WOLF_HOME:-/opt/wolf}"
WOLF_CFG_FOLDER="${WOLF_CFG_FOLDER:-/etc/wolf}"
if [ -z "${WOLF_RENDER_NODE:-}" ]; then
    for _drm in /dev/dri/renderD* /dev/dri/vkms-render; do
        [ -c "$_drm" ] && WOLF_RENDER_NODE="$_drm" && break
    done
    unset _drm
fi
WOLF_RENDER_NODE="${WOLF_RENDER_NODE:-}"

export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp/sockets}"

# ── Create runtime directories ──
mkdir -p "$XDG_RUNTIME_DIR"

# ── Copy default config if none exists ──
if [ ! -f "$WOLF_CFG_FOLDER/config.toml" ]; then
    echo "No config.toml found, copying default..."
    cp "$WOLF_HOME/default-config.toml" "$WOLF_CFG_FOLDER/config.toml"
fi

# ── Wolf environment ──
export WOLF_CFG_FILE="$WOLF_CFG_FOLDER/config.toml"
export WOLF_PRIVATE_KEY_FILE="$WOLF_CFG_FOLDER/key.pem"
export WOLF_PRIVATE_CERT_FILE="$WOLF_CFG_FOLDER/cert.pem"
export WOLF_RENDER_NODE
export WOLF_STOP_CONTAINER_ON_EXIT=TRUE
export WOLF_LOG_LEVEL="${WOLF_LOG_LEVEL:-INFO}"
export GST_DEBUG="${GST_DEBUG:-1}"
export RUST_LOG="${RUST_LOG:-WARN}"
export HOST_APPS_STATE_FOLDER="${WOLF_CFG_FOLDER}/apps-state"

# If there's a DRI render node, tell GStreamer GL about it
if [ -e "$WOLF_RENDER_NODE" ]; then
    export GST_GL_DRM_DEVICE="$WOLF_RENDER_NODE"
fi

# ── Start PulseAudio ──
# Wolf's built-in start_audio_server tries to launch a pulseaudio *docker
# container* via /var/run/docker.sock, which is a non-starter in rootless
# podman. Instead we run pulse here and point Wolf at it via PULSE_SERVER;
# steam-launcher creates the per-session null sink (whose name Wolf passes
# in via $PULSE_SINK) on-demand before exec'ing steam.
echo "Starting PulseAudio..."
pulseaudio --exit-idle-time=-1 \
    --load="module-native-protocol-unix" &

for i in $(seq 1 30); do
    if pactl info >/dev/null 2>&1; then
        echo "PulseAudio ready"
        break
    fi
    sleep 0.1
done

if ! pactl info >/dev/null 2>&1; then
    echo "PulseAudio failed to become ready after 3s — refusing to start Wolf with broken PULSE_SERVER" >&2
    exit 1
fi

export PULSE_SERVER="unix:${XDG_RUNTIME_DIR}/pulse/native"

mkdir -p "$HOST_APPS_STATE_FOLDER"

echo "Starting Wolf..."
exec wolf
