#!/bin/bash
set -e
cd "$(dirname "$0")"

GPU_TYPE="${GPU_TYPE:-amd}"

if podman build \
    --build-arg "GPU_TYPE=${GPU_TYPE}" \
    -t "localhost/wolf-game-streaming:${GPU_TYPE}" \
    -t "localhost/wolf-game-streaming:latest" \
    .; then
    echo "Build complete! Image: localhost/wolf-game-streaming:latest (GPU: ${GPU_TYPE})"
else
    echo ""
    echo "Build failed."
    exit 1
fi
