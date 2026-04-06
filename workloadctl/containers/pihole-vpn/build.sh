#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "Building Pi-hole VPN container..."
podman build -t localhost/pihole-vpn:latest .

echo ""
echo "Build complete! Image: localhost/pihole-vpn:latest"
echo ""
echo "Next steps:"
echo "  sudo cp ~/Downloads/vpn.conf /var/lib/workloads/pihole-vpn/wg0.conf"
echo "  sudo workloadctl enable pihole-vpn"
echo "  sudo firewall-cmd --add-service=dns --add-service=http --permanent && sudo firewall-cmd --reload"
echo "  sudo workloadctl exec pihole-vpn pihole -g   # download blocklists (required)"
