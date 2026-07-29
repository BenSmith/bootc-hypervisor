#!/bin/bash
# Host setup for the wolf-game-streaming workload.
#
# Usage:
#   setup.sh enable    — configure host prerequisites
#   setup.sh disable   — remove host prerequisites
#   setup.sh artifacts — print what enable() installs on the host (read-only)
#
# Idempotent in both directions. Called by workloadctl enable/disable.
#
# SELinux policy is handled separately via [security].selinux_policy (the
# wolf-game-streaming.cil per-workload type); this script only sets up the
# non-SELinux host prerequisites (the uinput device).
set -euo pipefail

enable() {
    # The uinput module autoload and the /dev/uinput group-access rule
    # (KERNEL=="uinput", GROUP="input", MODE="0660") ship in the hypervisor
    # image (/usr/lib/modules-load.d/uinput.conf +
    # /usr/lib/udev/rules.d/72-uinput-input.rules), so they persist across bootc
    # upgrades and can't be clobbered when a sibling streaming workload is
    # disabled. Just load the module now so /dev/uinput exists before the
    # container starts on a first enable that precedes a reboot; the image udev
    # rule already sets its perms to 0660 root:input.
    echo "  [host] Ensuring uinput kernel module is loaded..."
    modprobe uinput 2>/dev/null || true

    echo "  [host] Host setup complete"
    echo ""
    echo "  NOTE: Wolf requires the following firewall ports:"
    echo "    sudo firewall-cmd --permanent --add-port={47984,47989,48010}/tcp --add-port={47999,48100-48110,48200-48210}/udp"
    echo "    sudo firewall-cmd --reload"
}

disable() {
    # The uinput module autoload + /dev/uinput udev rule are image-owned and
    # shared by every game-streaming workload, so disable() leaves them in place.
    echo "  [host] Host teardown complete"
}

artifacts() {
    # Nothing. Every host prerequisite this workload relies on is image-owned
    # and shared with the other streaming workloads (the uinput module autoload
    # and its udev rule); the SELinux type comes from [security].selinux_policy,
    # which workloadctl installs and checks itself. Declaring a shared resource
    # would make two workloads each report the other's teardown as their own
    # fault.
    #
    # Silence with a zero exit means "installs nothing", which workloadctl reads
    # differently from an older bundle's nonzero "does not implement this".
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
