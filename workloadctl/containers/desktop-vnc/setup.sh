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
SUBSYSTEM=="drm", DEVPATH=="*/platform/vkms/*", KERNEL=="card*",    SYMLINK+="dri/vkms"
SUBSYSTEM=="drm", DEVPATH=="*/platform/vkms/*", KERNEL=="renderD*", SYMLINK+="dri/vkms-render"
RULES
    udevadm control --reload-rules
    modprobe vkms
    udevadm trigger --subsystem-match=drm --settle
    if [ ! -e /dev/dri/vkms ] || [ ! -e /dev/dri/vkms-render ]; then
        echo "  ERROR: /dev/dri/vkms symlinks not created after udev settle" >&2
        return 1
    fi
    echo "  [host] vkms ready: /dev/dri/vkms, /dev/dri/vkms-render"
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
