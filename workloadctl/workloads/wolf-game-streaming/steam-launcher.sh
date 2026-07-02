#!/bin/bash
# Launches Steam Big Picture inside gamescope, which is nested as a wayland
# client under Wolf's gst-wayland-display compositor.
#
# Wolf's compositor intentionally doesn't support XWayland — per the Wolf
# docs, X11 apps like Steam are expected to run under gamescope, which
# provides its own nested XWayland, handles fullscreen enforcement, scales
# the game's framebuffer to the compositor output, and reports lifecycle
# events back to Steam (-e).
#
# Wolf exports GAMESCOPE_WIDTH/HEIGHT/REFRESH from the Moonlight client's
# requested stream parameters — we pass these straight through. No manual
# Xwayland startup, no xrandr, no window-manager dance.
set -euo pipefail

: "${WAYLAND_DISPLAY:?WAYLAND_DISPLAY must be set by Wolf}"
: "${XDG_RUNTIME_DIR:?XDG_RUNTIME_DIR must be set}"

STREAM_WIDTH="${GAMESCOPE_WIDTH:-1920}"
STREAM_HEIGHT="${GAMESCOPE_HEIGHT:-1080}"
STREAM_REFRESH="${GAMESCOPE_REFRESH:-60}"

echo "[steam-launcher] gamescope ${STREAM_WIDTH}x${STREAM_HEIGHT}@${STREAM_REFRESH} on ${WAYLAND_DISPLAY}"

# Drop all capabilities — bwrap (used by Steam's runtime) refuses to run
# with any caps in its permitted set when not setuid and without file caps.
# podman's --cap-add puts caps in our ambient set, which would propagate to
# bwrap on exec; setpriv clears ambient/inheritable/bounding before gamescope
# starts steam's runtime.
exec setpriv --ambient-caps=-all --inh-caps=-all --bounding-set=-all -- \
    gamescope \
        --backend wayland \
        -W "${STREAM_WIDTH}" \
        -H "${STREAM_HEIGHT}" \
        -r "${STREAM_REFRESH}" \
        -f \
        -e \
        -- steam -tenfoot -steamos
