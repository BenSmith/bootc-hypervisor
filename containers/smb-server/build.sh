#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HTTP_PROXY="${HTTP_PROXY:-}"
HTTPS_PROXY="${HTTPS_PROXY:-}"

echo "Building Samba container image..."
http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" \
podman build \
    --build-arg http_proxy="$HTTP_PROXY" \
    --build-arg https_proxy="$HTTPS_PROXY" \
    -t localhost/smb-server:latest "$SCRIPT_DIR"

echo ""
echo "Build complete! Image: localhost/smb-server:latest"
echo ""
echo "Next steps:"
echo "  sudo workload-ctl enable smb-server"
echo "  sudo cp $SCRIPT_DIR/smb.conf /var/lib/workloads/smb-server/smb.conf"
echo "  sudo workload-ctl enable smb-server"
echo "  sudo firewall-cmd --add-service=samba --permanent && sudo firewall-cmd --reload"
