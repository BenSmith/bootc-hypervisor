#!/bin/bash
set -e
cd "$(dirname "$0")"

GPU_TYPE="${GPU_TYPE:-amd}"

podman build \
    --build-arg "GPU_TYPE=${GPU_TYPE}" \
    -t "localhost/wolf-game-streaming:${GPU_TYPE}" \
    -t "localhost/wolf-game-streaming:latest" \
    .

echo "Build complete! Image: localhost/wolf-game-streaming:latest (GPU: ${GPU_TYPE})"
