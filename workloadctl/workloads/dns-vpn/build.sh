#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HTTP_PROXY="${HTTP_PROXY:-}"
HTTPS_PROXY="${HTTPS_PROXY:-}"

echo "Building DNS-over-VPN proxy container..."
http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" \
podman build \
    --build-arg http_proxy="$HTTP_PROXY" \
    --build-arg https_proxy="$HTTPS_PROXY" \
    -t localhost/dns-vpn:latest "$SCRIPT_DIR"

echo ""
echo "Build complete! Image: localhost/dns-vpn:latest"
echo ""
echo "Next steps:"
echo "  sudo cp ~/Downloads/vpn.conf /var/lib/workloads/dns-vpn/wg0.conf"
echo "  sudo workloadctl enable dns-vpn"
echo "  sudo firewall-cmd --zone=home --add-service=dns --permanent && sudo firewall-cmd --reload"
