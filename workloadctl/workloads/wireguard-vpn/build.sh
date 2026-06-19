#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HTTP_PROXY="${HTTP_PROXY:-}"
HTTPS_PROXY="${HTTPS_PROXY:-}"

echo "Building WireGuard VPN container..."
http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" \
podman build \
    --build-arg http_proxy="$HTTP_PROXY" \
    --build-arg https_proxy="$HTTPS_PROXY" \
    -t localhost/wireguard-vpn:latest "$SCRIPT_DIR"

echo ""
echo "Build complete! Image: localhost/wireguard-vpn:latest"
echo ""
echo "Next steps:"
echo "  sudo cp ~/Downloads/vpn.conf /var/lib/workloads/wireguard-vpn/wg0.conf"
echo "  sudo workloadctl enable wireguard-vpn"
