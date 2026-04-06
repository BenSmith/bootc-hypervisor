#!/bin/bash
set -e

WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_CONFIG="/etc/wireguard/${WG_INTERFACE}.conf"

echo "WireGuard VPN starting..."
echo "Interface: $WG_INTERFACE"

if [ ! -f "$WG_CONFIG" ]; then
    echo "ERROR: WireGuard config not found at $WG_CONFIG"
    exit 1
fi

cleanup() {
    echo "Shutting down WireGuard..."
    wg-quick down "$WG_INTERFACE" || true
    echo "WireGuard stopped"
    exit 0
}

trap cleanup SIGTERM SIGINT SIGQUIT

echo "Bringing up WireGuard interface..."
wg-quick up "$WG_INTERFACE"

# Keep LAN routes accessible through the pasta interface (pre-VPN default route)
# so container can still reach local network addresses while VPN carries all other traffic.
DEFAULT_IFACE=$(ip route show default | grep -v "$WG_INTERFACE" | head -n1 | awk '{print $5}')
if [ -n "$DEFAULT_IFACE" ]; then
    ip route add 192.168.0.0/16 dev "$DEFAULT_IFACE" 2>/dev/null || true
    ip route add 10.0.0.0/8 dev "$DEFAULT_IFACE" 2>/dev/null || true
    ip route add 172.16.0.0/12 dev "$DEFAULT_IFACE" 2>/dev/null || true
    echo "Local networks excluded from VPN via $DEFAULT_IFACE"
fi

echo "WireGuard interface up!"
wg show "$WG_INTERFACE"

echo ""
echo "Checking public IP..."
PUBLIC_IP=$(curl -s --max-time 5 https://ipinfo.io/ip || echo "Could not determine IP")
echo "Public IP: $PUBLIC_IP"

echo ""
echo "VPN tunnel active. Monitoring connection..."
while true; do
    if ! ip link show "$WG_INTERFACE" &>/dev/null; then
        echo "ERROR: WireGuard interface disappeared!"
        exit 1
    fi
    sleep 30
done
