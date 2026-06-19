#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HTTP_PROXY="${HTTP_PROXY:-}"
HTTPS_PROXY="${HTTPS_PROXY:-}"

echo "Building Avahi container image..."
http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" \
podman build \
    --build-arg http_proxy="$HTTP_PROXY" \
    --build-arg https_proxy="$HTTPS_PROXY" \
    -t localhost/avahi:latest "$SCRIPT_DIR"

echo ""
echo "Build complete! Image: localhost/avahi:latest"
echo ""
echo "Next steps:"
echo "  Edit /etc/workloads.d/avahi.toml and set ALIASES in [container.environment]"
echo "  sudo workloadctl enable avahi"
