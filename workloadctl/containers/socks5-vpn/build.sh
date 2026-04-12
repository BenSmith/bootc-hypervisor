#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HTTP_PROXY="${HTTP_PROXY:-}"
HTTPS_PROXY="${HTTPS_PROXY:-}"

echo "Building VPN SOCKS5 proxy container..."
http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" \
podman build \
    --build-arg http_proxy="$HTTP_PROXY" \
    --build-arg https_proxy="$HTTPS_PROXY" \
    -t localhost/socks5-vpn:latest "$SCRIPT_DIR"

echo ""
echo "Build complete! Image: localhost/socks5-vpn:latest"
echo ""
echo "Next steps:"
echo "  sudo cp ~/Downloads/vpn.conf /var/lib/workloads/socks5-vpn/wg0.conf"
echo "  sudo workloadctl enable socks5-vpn"
echo "  # Proxy binds to 127.0.0.1:1080 (local only by default)"
