#!/bin/bash
# Host setup for the vncdesktop-sway workload.
#
# Usage:
#   setup.sh enable   — install SELinux policy module
#   setup.sh disable  — remove SELinux policy module
#
# Idempotent in both directions. Called by workloadctl enable/disable.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODULE_NAME="vncdesktop-sway"
WORK_DIR=""
cleanup() { [ -n "$WORK_DIR" ] && rm -rf "$WORK_DIR"; return 0; }
trap cleanup EXIT

enable() {
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
        semodule -r "$MODULE_NAME" || true
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
