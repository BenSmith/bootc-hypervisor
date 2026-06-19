#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HTTP_PROXY="${HTTP_PROXY:-}"
HTTPS_PROXY="${HTTPS_PROXY:-}"

echo "Building Squid proxy container image..."
http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" \
podman build \
    --build-arg http_proxy="$HTTP_PROXY" \
    --build-arg https_proxy="$HTTPS_PROXY" \
    -t localhost/squid:latest "$SCRIPT_DIR"

echo ""
echo "Build complete! Image: localhost/squid:latest"
echo ""
echo "Next steps:"
echo "  sudo workloadctl enable squid"
echo "  sudo cp $SCRIPT_DIR/squid.conf /var/lib/workloads/squid/squid.conf"
echo "  sudo workloadctl enable squid"
echo "  sudo firewall-cmd --add-port=3128/tcp --permanent && sudo firewall-cmd --reload"
