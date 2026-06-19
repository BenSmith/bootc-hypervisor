#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HTTP_PROXY="${HTTP_PROXY:-}"
HTTPS_PROXY="${HTTPS_PROXY:-}"

echo "Building Caddy container image..."
http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" \
podman build \
    --build-arg http_proxy="$HTTP_PROXY" \
    --build-arg https_proxy="$HTTPS_PROXY" \
    -t localhost/caddy:latest "$SCRIPT_DIR"

echo ""
echo "Build complete! Image: localhost/caddy:latest"
echo ""
echo "Next steps:"
echo "  sudo cp $SCRIPT_DIR/Caddyfile /var/lib/workloads/caddy/Caddyfile"
echo "  sudo workloadctl enable caddy"
