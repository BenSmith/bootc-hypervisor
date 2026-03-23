#!/bin/bash
set -e

WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_CONFIG="/etc/wireguard/${WG_INTERFACE}.conf"
SOCKS_PORT="${SOCKS_PORT:-1080}"

echo "VPN SOCKS5 proxy starting..."
echo "WireGuard interface: $WG_INTERFACE"
echo "SOCKS5 port: $SOCKS_PORT"

if [ ! -f "$WG_CONFIG" ]; then
    echo "ERROR: WireGuard config not found at $WG_CONFIG"
    exit 1
fi

cleanup() {
    echo "Shutting down..."
    kill "$MICROSOCKS_PID" 2>/dev/null || true
    wg-quick down "$WG_INTERFACE" || true
    exit 0
}

trap cleanup SIGTERM SIGINT SIGQUIT

echo "Bringing up WireGuard interface..."
wg-quick up "$WG_INTERFACE"

# Keep LAN routes accessible through the pre-VPN interface so the proxy
# can still reach local network addresses if needed.
DEFAULT_IFACE=$(ip route show default | grep -v "$WG_INTERFACE" | head -n1 | awk '{print $5}')
if [ -n "$DEFAULT_IFACE" ]; then
    ip route add 192.168.0.0/16 dev "$DEFAULT_IFACE" 2>/dev/null || true
    ip route add 10.0.0.0/8 dev "$DEFAULT_IFACE" 2>/dev/null || true
    ip route add 172.16.0.0/12 dev "$DEFAULT_IFACE" 2>/dev/null || true
    echo "Local networks excluded from VPN via $DEFAULT_IFACE"
fi

echo "Starting SOCKS5 proxy on port $SOCKS_PORT..."
microsocks -p "$SOCKS_PORT" &
MICROSOCKS_PID=$!

echo ""
echo "Verifying VPN connection..."
PUBLIC_IP=$(curl -s --max-time 10 --socks5 "127.0.0.1:$SOCKS_PORT" https://ipinfo.io/ip || echo "unavailable")
echo "Public IP via VPN: $PUBLIC_IP"

echo ""
echo "SOCKS5 proxy ready — use socks5://127.0.0.1:$SOCKS_PORT"
echo "  curl --socks5 127.0.0.1:$SOCKS_PORT https://ipinfo.io/ip"

while true; do
    if ! ip link show "$WG_INTERFACE" &>/dev/null; then
        echo "ERROR: WireGuard interface disappeared!"
        exit 1
    fi
    if ! kill -0 "$MICROSOCKS_PID" 2>/dev/null; then
        echo "ERROR: microsocks process died!"
        exit 1
    fi
    sleep 30
done
