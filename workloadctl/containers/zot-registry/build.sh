#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HTTP_PROXY="${HTTP_PROXY:-}"
HTTPS_PROXY="${HTTPS_PROXY:-}"

echo "Building Zot registry container image..."
http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" \
podman build \
    --build-arg http_proxy="$HTTP_PROXY" \
    --build-arg https_proxy="$HTTPS_PROXY" \
    -t localhost/zot-registry:latest "$SCRIPT_DIR"

echo ""
echo "Build complete! Image: localhost/zot-registry:latest"
echo ""
echo "Next steps:"
echo "  sudo cp $SCRIPT_DIR/config.json /var/lib/workloads/zot-registry/config.json"
echo "  sudo workloadctl enable zot-registry"
echo "  sudo firewall-cmd --add-port=5050/tcp --permanent && sudo firewall-cmd --reload"
