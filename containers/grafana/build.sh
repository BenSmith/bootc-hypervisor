#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HTTP_PROXY="${HTTP_PROXY:-}"
HTTPS_PROXY="${HTTPS_PROXY:-}"

echo "Building Grafana container image..."
http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" \
podman build \
    --build-arg http_proxy="$HTTP_PROXY" \
    --build-arg https_proxy="$HTTPS_PROXY" \
    -t localhost/grafana:latest "$SCRIPT_DIR"

echo ""
echo "Build complete! Image: localhost/grafana:latest"
echo ""
echo "Next steps:"
echo "  sudo workload-ctl enable grafana"
echo "  sudo cp $SCRIPT_DIR/grafana.ini /var/lib/workloads/grafana/grafana.ini"
echo "  sudo workload-ctl enable grafana"
echo "  sudo firewall-cmd --add-port=3000/tcp --permanent && sudo firewall-cmd --reload"
