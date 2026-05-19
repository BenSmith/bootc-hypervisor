#!/bin/bash
# Host setup for the jellyfin workload.
#
# Usage:
#   setup.sh enable   — configure host prerequisites
#   setup.sh disable  — remove host prerequisites
#
# Idempotent in both directions. Called by workloadctl enable/disable.
set -euo pipefail

SEBOOL="container_use_devices"

enable() {
    # Allow confined containers (container_t) to open device nodes such as the
    # GPU render node /dev/dri/renderD128. Without this, SELinux denies the
    # VAAPI device open and hardware transcoding silently falls back to CPU.
    if command -v getsebool >/dev/null 2>&1; then
        if getsebool "$SEBOOL" 2>/dev/null | grep -q ' off$'; then
            echo "  [host] Enabling SELinux boolean ${SEBOOL}..."
            setsebool -P "$SEBOOL" on
        else
            echo "  [host] SELinux boolean ${SEBOOL} already on (or SELinux disabled)"
        fi
    else
        echo "  [host] SELinux tooling not present — skipping ${SEBOOL}"
    fi
    echo "  [host] Setup complete"
}

disable() {
    # Intentionally leave container_use_devices on: it is a system-wide boolean
    # and other GPU workloads (game streaming, desktops) may depend on it.
    # Flipping it off here could break them.
    echo "  [host] Leaving SELinux boolean ${SEBOOL} unchanged (shared by other GPU workloads)"
}

case "${1:-}" in
    enable)  enable ;;
    disable) disable ;;
    *)
        echo "Usage: $0 {enable|disable}" >&2
        exit 1
        ;;
esac
