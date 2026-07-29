#!/bin/bash
# Host setup for the jellyfin workload.
#
# Usage:
#   setup.sh enable    — configure host prerequisites
#   setup.sh disable   — remove host prerequisites
#   setup.sh artifacts — print what enable() installs on the host (read-only)
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

artifacts() {
    # Nothing. This workload's only host effect is the system-wide SELinux
    # boolean above, which it deliberately does not own — disable() leaves it on
    # precisely because other GPU workloads depend on it. A shared boolean is
    # not this workload's artifact, and checking it here would report a healthy
    # host as broken the moment someone else legitimately relies on it.
    return 0
}

case "${1:-}" in
    enable)    enable ;;
    disable)   disable ;;
    artifacts) artifacts ;;
    *)
        echo "Usage: $0 {enable|disable|artifacts}" >&2
        exit 1
        ;;
esac
