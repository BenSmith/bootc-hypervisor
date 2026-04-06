#!/bin/bash
# Build the Squid proxy container image

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Use proxy if set in environment
HTTP_PROXY="${HTTP_PROXY:-}"
HTTPS_PROXY="${HTTPS_PROXY:-}"

echo "Building Squid proxy container image..."
if [[ -n "$HTTP_PROXY" ]]; then
    echo "Using proxy: $HTTP_PROXY"
fi
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
