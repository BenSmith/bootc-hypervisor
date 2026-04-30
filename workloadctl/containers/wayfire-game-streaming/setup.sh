#!/bin/bash
# Host setup for the wayfire-game-streaming workload.
#
# Usage:
#   setup.sh enable   — configure host prerequisites
#   setup.sh disable  — remove host prerequisites
#
# Idempotent in both directions. Called by workloadctl enable/disable.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODULE_NAME="wayfire-devices"
MODULES_LOAD="/etc/modules-load.d/uinput.conf"
UDEV_RULE="/etc/udev/rules.d/99-uinput-input.rules"
UDEV_RULE_LINE='KERNEL=="uinput", GROUP="input", MODE="0660"'

WORK_DIR=""
cleanup() { [ -n "$WORK_DIR" ] && rm -rf "$WORK_DIR"; }
trap cleanup EXIT

enable() {
    echo "  [host] Configuring uinput kernel module..."

    # Load module now if not loaded
    if ! lsmod | grep -q '^uinput'; then
        modprobe uinput
    fi

    # Persist at boot
    if [ ! -f "$MODULES_LOAD" ]; then
        echo 'uinput' > "$MODULES_LOAD"
    fi

    echo "  [host] Configuring udev rule for /dev/uinput..."
    if [ ! -f "$UDEV_RULE" ] || ! grep -qF "$UDEV_RULE_LINE" "$UDEV_RULE"; then
        echo "$UDEV_RULE_LINE" > "$UDEV_RULE"
        udevadm control --reload-rules
    fi

    # Apply rule to already-loaded device
    udevadm trigger --action=change /sys/class/misc/uinput 2>/dev/null || true

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
    echo ""
    echo "  NOTE: Sunshine requires the following firewall ports:"
    echo "    sudo firewall-cmd --permanent --add-port={47984,47989,47990,48010}/tcp --add-port=47998-48000/udp"
    echo "    sudo firewall-cmd --reload"
}

disable() {
    echo "  [host] Removing uinput boot configuration..."
    # Don't rmmod uinput — other services may depend on it even if this loaded it first.
    rm -f "$MODULES_LOAD"

    echo "  [host] Removing udev rule..."
    if [ -f "$UDEV_RULE" ]; then
        rm -f "$UDEV_RULE"
        udevadm control --reload-rules
    fi

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
