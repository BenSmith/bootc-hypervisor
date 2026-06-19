#!/bin/bash
# Host setup for the wolf-game-streaming workload.
#
# Usage:
#   setup.sh enable   — configure host prerequisites
#   setup.sh disable  — remove host prerequisites
#
# Idempotent in both directions. Called by workloadctl enable/disable.
#
# SELinux policy is handled separately via [security].selinux_policy (the
# wolf-game-streaming.cil per-workload type); this script only sets up the
# non-SELinux host prerequisites (the uinput device).
set -euo pipefail

MODULES_LOAD="/etc/modules-load.d/uinput.conf"
UDEV_RULE="/etc/udev/rules.d/99-uinput-input.rules"
UDEV_RULE_LINE='KERNEL=="uinput", GROUP="input", MODE="0660"'

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

    echo "  [host] Host setup complete"
    echo ""
    echo "  NOTE: Wolf requires the following firewall ports:"
    echo "    sudo firewall-cmd --permanent --add-port={47984,47989,48010}/tcp --add-port={47999,48100-48110,48200-48210}/udp"
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
