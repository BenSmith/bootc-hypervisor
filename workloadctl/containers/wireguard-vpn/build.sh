#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "Building WireGuard VPN container..."
podman build -t localhost/wireguard-vpn:latest .

echo ""
echo "Build complete! Image: localhost/wireguard-vpn:latest"
echo ""
echo "Next steps:"
echo "  sudo cp ~/Downloads/vpn.conf /var/lib/workloads/wireguard-vpn/wg0.conf"
echo "  sudo workloadctl enable wireguard-vpn"
