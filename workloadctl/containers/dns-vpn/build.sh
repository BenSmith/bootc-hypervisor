#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "Building DNS-over-VPN proxy container..."
podman build -t localhost/dns-vpn:latest .

echo ""
echo "Build complete! Image: localhost/dns-vpn:latest"
echo ""
echo "Next steps:"
echo "  sudo cp ~/Downloads/vpn.conf /var/lib/workloads/dns-vpn/wg0.conf"
echo "  sudo workloadctl enable dns-vpn"
echo "  sudo firewall-cmd --zone=home --add-service=dns --permanent && sudo firewall-cmd --reload"
