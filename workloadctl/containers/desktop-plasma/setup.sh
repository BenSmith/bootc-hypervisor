#!/bin/bash
# Host setup for the desktop-plasma workload.
#
# Usage:
#   setup.sh enable   — install SELinux policy module, load vkms
#   setup.sh disable  — remove SELinux policy module
#
# Idempotent in both directions. Called by workloadctl enable/disable.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODULE_NAME="desktop-plasma"
MODULES_LOAD_CONF="/etc/modules-load.d/vkms.conf"
UDEV_RULE="/etc/udev/rules.d/70-vkms.rules"

WORK_DIR=""
cleanup() { [ -n "$WORK_DIR" ] && rm -rf "$WORK_DIR"; }
trap cleanup EXIT

enable() {
    # --- vkms virtual DRM device ---
    echo "  [host] Configuring vkms kernel module..."

    # Persist across reboots
    echo "vkms" > "$MODULES_LOAD_CONF"

    # Stable /dev/dri/vkms and /dev/dri/vkms-render symlinks, created by udev
    # whenever the vkms platform device appears (including after modprobe).
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

    # --- SELinux policy ---
    echo "  [host] Installing SELinux policy module..."
    TE_FILE="${SCRIPT_DIR}/${MODULE_NAME}.te"
    if [ ! -f "$TE_FILE" ]; then
        echo "  ERROR: SELinux policy source not found: $TE_FILE" >&2
        return 1
    fi
    WORK_DIR=$(mktemp -d)
    cp "$TE_FILE" "$WORK_DIR/"
    checkmodule -M -m -o "$WORK_DIR/${MODULE_NAME}.mod" "$WORK_DIR/${MODULE_NAME}.te"
    semodule_package -o "$WORK_DIR/${MODULE_NAME}.pp" -m "$WORK_DIR/${MODULE_NAME}.mod"
    semodule -i "$WORK_DIR/${MODULE_NAME}.pp"

    echo "  [host] Host setup complete"
}

disable() {
    echo "  [host] Removing SELinux policy module..."
    if semodule -l 2>/dev/null | grep -q "^${MODULE_NAME}"; then
        semodule -r "$MODULE_NAME"
    else
        echo "  [host] SELinux module '${MODULE_NAME}' not installed"
    fi
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
