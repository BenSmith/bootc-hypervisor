#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HTTP_PROXY="${HTTP_PROXY:-}"
HTTPS_PROXY="${HTTPS_PROXY:-}"

echo "Building Pi-hole VPN container..."
http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" \
podman build \
    --build-arg http_proxy="$HTTP_PROXY" \
    --build-arg https_proxy="$HTTPS_PROXY" \
    -t localhost/pihole-vpn:latest "$SCRIPT_DIR"

echo ""
echo "Build complete! Image: localhost/pihole-vpn:latest"
echo ""
echo "Next steps:"
echo "  sudo cp ~/Downloads/vpn.conf /var/lib/workloads/pihole-vpn/wg0.conf"
echo "  sudo workloadctl enable pihole-vpn"
echo "  sudo firewall-cmd --add-service=dns --add-service=http --permanent && sudo firewall-cmd --reload"
echo "  sudo workloadctl exec pihole-vpn pihole -g   # download blocklists (required)"
