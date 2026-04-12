#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HTTP_PROXY="${HTTP_PROXY:-}"
HTTPS_PROXY="${HTTPS_PROXY:-}"

echo "Building proxy-stack container..."
http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" \
podman build \
    --build-arg http_proxy="$HTTP_PROXY" \
    --build-arg https_proxy="$HTTPS_PROXY" \
    -t localhost/proxy-stack:latest "$SCRIPT_DIR"

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
