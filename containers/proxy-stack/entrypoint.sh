#!/bin/bash
set -e

WG_INTERFACE="${WG_INTERFACE:-wg0}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
WG_CONFIG="/etc/wireguard/${WG_INTERFACE}.conf"

if [ ! -f "$WG_CONFIG" ]; then
    echo "ERROR: WireGuard config not found at $WG_CONFIG"
    exit 1
fi

# Parse VPN DNS from WireGuard config. UPSTREAM_DNS env var overrides it.
# Pi-hole expects semicolon-separated upstreams; wg0.conf uses comma-separated.
if [ -n "$UPSTREAM_DNS" ]; then
    VPN_DNS="$UPSTREAM_DNS"
else
    VPN_DNS=$(grep -iE '^\s*DNS\s*=' "$WG_CONFIG" | head -n1 | sed 's/.*=\s*//' | tr -d ' ' | tr ',' ';')
    if [ -z "$VPN_DNS" ]; then
        echo "ERROR: No DNS server found in $WG_CONFIG and UPSTREAM_DNS not set"
        exit 1
    fi
fi

echo "Proxy stack starting..."
echo "WireGuard interface: $WG_INTERFACE"
echo "VPN upstream DNS: $VPN_DNS"
echo "SOCKS5 port: $SOCKS_PORT"

# Pi-hole reads this env var for its upstream DNS configuration
export PIHOLE_DNS_="$VPN_DNS"

cleanup() {
    echo "Shutting down..."
    [ -n "$SQUID_PID" ]    && kill "$SQUID_PID"    2>/dev/null || true
    [ -n "$MICROSOCKS_PID" ] && kill "$MICROSOCKS_PID" 2>/dev/null || true
    [ -n "$PIHOLE_PID" ]   && kill "$PIHOLE_PID"   2>/dev/null || true
    wg-quick down "$WG_INTERFACE" 2>/dev/null || true
    exit 0
}
trap cleanup SIGTERM SIGINT SIGQUIT

echo "Bringing up WireGuard..."
wg-quick up "$WG_INTERFACE"

# Keep LAN routes accessible through the pre-VPN interface.
DEFAULT_IFACE=$(ip route show default | grep -v "$WG_INTERFACE" | head -n1 | awk '{print $5}')
if [ -n "$DEFAULT_IFACE" ]; then
    ip route add 192.168.0.0/16 dev "$DEFAULT_IFACE" 2>/dev/null || true
    ip route add 10.0.0.0/8 dev "$DEFAULT_IFACE" 2>/dev/null || true
    ip route add 172.16.0.0/12 dev "$DEFAULT_IFACE" 2>/dev/null || true
    echo "Local networks excluded from VPN via $DEFAULT_IFACE"
fi

# Point the container's resolver at Pi-hole (starting next).
echo "nameserver 127.0.0.1" > /etc/resolv.conf

# Start Pi-hole (s6-overlay, manages FTL and lighttpd internally).
echo "Starting Pi-hole..."
/usr/bin/start.sh &
PIHOLE_PID=$!

# Wait for Pi-hole FTL to open port 53 before starting the proxy services.
echo "Waiting for Pi-hole DNS..."
for i in $(seq 1 30); do
    if bash -c 'echo >/dev/tcp/127.0.0.1/53' 2>/dev/null; then
        echo "Pi-hole DNS ready"
        break
    fi
    [ "$i" -eq 30 ] && echo "Warning: Pi-hole DNS not ready after 30s, continuing anyway"
    sleep 1
done

# Start microsocks SOCKS5 proxy.
echo "Starting microsocks..."
microsocks -p "$SOCKS_PORT" &
MICROSOCKS_PID=$!

# Initialize Squid cache dirs if needed, then start.
echo "Starting Squid..."
squid -z 2>/dev/null || true
rm -f /var/spool/squid/squid.pid
squid -N &
SQUID_PID=$!

echo ""
echo "Proxy stack ready:"
echo "  Squid proxy:   :3128 (HTTP/HTTPS cache → VPN)"
echo "  SOCKS5 proxy:  :$SOCKS_PORT (→ VPN)"
echo "  Pi-hole DNS:   :53   (DNS blocking → VPN upstream)"
echo "  Pi-hole admin: :80"

# Monitor all services; exit if any die so systemd restarts the unit.
while true; do
    if ! kill -0 "$PIHOLE_PID"     2>/dev/null; then echo "ERROR: Pi-hole died!";    cleanup; fi
    if ! kill -0 "$MICROSOCKS_PID" 2>/dev/null; then echo "ERROR: microsocks died!"; cleanup; fi
    if ! kill -0 "$SQUID_PID"      2>/dev/null; then echo "ERROR: Squid died!";      cleanup; fi
    sleep 15
done
