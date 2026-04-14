#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HTTP_PROXY="${HTTP_PROXY:-}"
HTTPS_PROXY="${HTTPS_PROXY:-}"

echo "Building desktop-labwc-nested container image..."
http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" \
podman build \
    --build-arg http_proxy="$HTTP_PROXY" \
    --build-arg https_proxy="$HTTPS_PROXY" \
    -t localhost/desktop-labwc-nested:latest "$SCRIPT_DIR"

echo ""
echo "Build complete! Image: localhost/desktop-labwc-nested:latest"
echo ""
echo "Next steps:"
echo "  cosy create --audio --sudo --gpu --image localhost/desktop-labwc-nested:latest my-nested"
echo "  cosy start my-nested"
