#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HTTP_PROXY="${HTTP_PROXY:-}"
HTTPS_PROXY="${HTTPS_PROXY:-}"

echo "Building desktop-wayfire-kms container image..."
http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" \
podman build \
    --build-arg http_proxy="$HTTP_PROXY" \
    --build-arg https_proxy="$HTTPS_PROXY" \
    -t localhost/desktop-wayfire-kms:latest "$SCRIPT_DIR"

echo ""
echo "Build complete! Image: localhost/desktop-wayfire-kms:latest"
echo ""
echo "Next steps:"
echo "  cosy create --kms --audio --sudo --image localhost/desktop-wayfire-kms:latest my-desktop"
