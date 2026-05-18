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
RELAY_SERVICE="wayfire-udev-relay.service"
RELAY_UNIT="/etc/systemd/system/${RELAY_SERVICE}"
WORKLOAD_USER="_wl-wayfire-game-streaming"

WORK_DIR=""
cleanup() { [ -n "$WORK_DIR" ] && rm -rf "$WORK_DIR"; return 0; }
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

    # Host-side udev relay. The container's libudev drops the host udevd's
    # hotplug events (sender UID maps to "nobody" in the container user
    # namespace), and a rootless host-networked container can't re-broadcast
    # them itself (no CAP_NET_ADMIN over the host net namespace). This host
    # service re-broadcasts input events with a corrected sender UID so
    # wayfire's libinput sees Sunshine's devices appear at runtime.
    echo "  [host] Installing udev input-event relay..."
    cat > "$RELAY_UNIT" <<UNIT
[Unit]
Description=Relay host udev input hotplug events into the wayfire-game-streaming container
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${SCRIPT_DIR}/udev-relay ${WORKLOAD_USER}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now "$RELAY_SERVICE"

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

    echo "  [host] Removing udev input-event relay..."
    if [ -e "$RELAY_UNIT" ]; then
        systemctl disable --now "$RELAY_SERVICE" 2>/dev/null || true
        rm -f "$RELAY_UNIT"
        systemctl daemon-reload
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
