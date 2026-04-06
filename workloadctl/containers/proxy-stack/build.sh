#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "Building proxy-stack container..."
podman build -t localhost/proxy-stack:latest .

echo ""
echo "Build complete! Image: localhost/proxy-stack:latest"
echo ""
echo "Next steps:"
echo "  sudo cp ~/Downloads/vpn.conf /var/lib/workloads/proxy-stack/wg0.conf"
echo "  podman run --rm localhost/proxy-stack:latest cat /usr/share/proxy-stack/squid.conf \\"
echo "    | sudo tee /var/lib/workloads/proxy-stack/squid.conf"
echo "  sudo workloadctl enable proxy-stack"
echo "  sudo firewall-cmd --add-service=dns --add-service=http --add-port=3128/tcp --permanent && sudo firewall-cmd --reload"
echo "  sudo workloadctl exec proxy-stack pihole -g   # download blocklists (required)"
