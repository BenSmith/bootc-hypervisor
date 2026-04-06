#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "Building VPN SOCKS5 proxy container..."
podman build -t localhost/socks5-vpn:latest .

echo ""
echo "Build complete! Image: localhost/socks5-vpn:latest"
echo ""
echo "Next steps:"
echo "  sudo cp ~/Downloads/vpn.conf /var/lib/workloads/socks5-vpn/wg0.conf"
echo "  sudo workloadctl enable socks5-vpn"
echo "  # Proxy binds to 127.0.0.1:1080 (local only by default)"
