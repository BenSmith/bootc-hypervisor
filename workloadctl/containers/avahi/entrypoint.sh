#!/bin/bash
# Publishes mDNS A-record aliases for this host. Each alias in ALIASES is
# registered via `avahi-publish -a -R`, which suppresses the reverse PTR —
# without -R, N aliases on one IP all probe the same PTR (66.0.168.192…)
# and only the lexicographically-smallest one wins.
#
# Process tree: dbus-daemon -> avahi-daemon -> N x avahi-publish.
# Any subprocess exit tears the rest down so systemd restarts cleanly.
set -euo pipefail

ALIASES="${ALIASES:-}"

if [[ -z "${HOST_IP:-}" ]]; then
    HOST_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
fi
if [[ -z "$HOST_IP" ]]; then
    echo "avahi: could not detect host IP (set HOST_IP env var to override)" >&2
    exit 1
fi

ALIAS_NAMES=()
for raw in ${ALIASES//,/ }; do
    name="${raw%.local}"
    [[ -z "$name" ]] && continue
    ALIAS_NAMES+=("$name")
done
if [[ ${#ALIAS_NAMES[@]} -eq 0 ]]; then
    echo "avahi: ALIASES is empty, nothing to publish" >&2
    exit 1
fi

echo "avahi: publishing ${#ALIAS_NAMES[@]} alias(es) at $HOST_IP:"
for n in "${ALIAS_NAMES[@]}"; do
    echo "  $HOST_IP ${n}.local"
done

# Pre-create runtime dirs so the daemons can drop privileges and still write
# their sockets/pid files.
mkdir -p /run/avahi-daemon
chown avahi:avahi /run/avahi-daemon
mkdir -p /run/dbus

# dbus-daemon refuses to start without a machine-id.
if [[ ! -s /etc/machine-id ]]; then
    tr -d '-' < /proc/sys/kernel/random/uuid > /etc/machine-id
fi

PIDS=()
cleanup() {
    echo "avahi: shutting down" >&2
    kill "${PIDS[@]}" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

dbus-daemon --system --nofork &
PIDS+=($!)
for _ in {1..30}; do
    [[ -S /run/dbus/system_bus_socket ]] && break
    sleep 0.1
done

# avahi-daemon drops to the `avahi` user by default; that matches the user
# the system D-Bus policy grants ownership of org.freedesktop.Avahi to.
avahi-daemon --no-rlimits &
PIDS+=($!)
for _ in {1..50}; do
    [[ -S /run/avahi-daemon/socket ]] && break
    sleep 0.1
done

# -a address mode, -R no reverse PTR, -f wait for daemon if needed
for name in "${ALIAS_NAMES[@]}"; do
    avahi-publish -a -R -f "${name}.local" "$HOST_IP" &
    PIDS+=($!)
done

# If any background process dies we abandon the lot; systemd restarts us.
wait -n
echo "avahi: a subprocess exited unexpectedly" >&2
exit 1
