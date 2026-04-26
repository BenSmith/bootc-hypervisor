#!/bin/bash
# Host setup for the desktop-vnc workload.
#
# Usage:
#   setup.sh enable   — load vkms kernel module
#   setup.sh disable  — no-op (vkms config left in place)
#
# Idempotent in both directions. Called by workloadctl enable/disable.
set -euo pipefail

MODULES_LOAD_CONF="/etc/modules-load.d/vkms.conf"
UDEV_RULE="/etc/udev/rules.d/70-vkms.rules"

enable() {
    echo "  [host] Configuring vkms kernel module..."
    echo "vkms" > "$MODULES_LOAD_CONF"
    cat > "$UDEV_RULE" <<'RULES'
SUBSYSTEM=="drm", KERNEL=="card*",    KERNELS=="vkms", SYMLINK+="dri/vkms"
SUBSYSTEM=="drm", KERNEL=="renderD*", KERNELS=="vkms", SYMLINK+="dri/vkms-render"
RULES
    udevadm control --reload-rules
    modprobe vkms
    # Re-fire drm uevents so the rule applies to an already-loaded vkms too.
    udevadm trigger --subsystem-match=drm
    udevadm settle
    if [ ! -e /dev/dri/vkms ]; then
        echo "  ERROR: /dev/dri/vkms not created by udev" >&2
        return 1
    fi
    echo "  [host] vkms ready: /dev/dri/vkms -> $(readlink /dev/dri/vkms)"
    echo "  [host] Host setup complete"
}

disable() {
    echo "  [host] Host teardown complete"
}

case "${1:-}" in
    enable)  enable ;;
    disable) disable ;;
    *)
        echo "Usage: $0 {enable|disable}" >&2
        exit 1
        ;;
esac
