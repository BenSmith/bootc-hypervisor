#!/bin/bash
set -e
cd "$(dirname "$0")"

BUILD_ARGS=()

if [ -n "${SUNSHINE_RPM_URL:-}" ]; then
    # Local file: use podman build --volume to make it visible inside the build
    if [[ "$SUNSHINE_RPM_URL" == file://* ]]; then
        LOCAL_PATH="$(realpath "${SUNSHINE_RPM_URL#file://}")"
        BUILD_ARGS+=(--volume "${LOCAL_PATH}:/tmp/sunshine.rpm:ro")
        BUILD_ARGS+=(--build-arg "SUNSHINE_RPM_URL=/tmp/sunshine.rpm")
    elif [[ "$SUNSHINE_RPM_URL" == /* ]]; then
        LOCAL_PATH="$(realpath "$SUNSHINE_RPM_URL")"
        BUILD_ARGS+=(--volume "${LOCAL_PATH}:/tmp/sunshine.rpm:ro")
        BUILD_ARGS+=(--build-arg "SUNSHINE_RPM_URL=/tmp/sunshine.rpm")
    else
        BUILD_ARGS+=(--build-arg "SUNSHINE_RPM_URL=${SUNSHINE_RPM_URL}")
    fi
fi

if podman build "${BUILD_ARGS[@]}" -t localhost/wayfire-game-streaming:latest .; then
    echo "Build complete! Image: localhost/wayfire-game-streaming:latest"
else
    echo ""
    echo "Build failed. If the Sunshine RPM URL is outdated, override it with:"
    echo "  sudo SUNSHINE_RPM_URL=https://github.com/LizardByte/Sunshine/releases/download/v.../Sunshine-...-1.fc43.x86_64.rpm ./build.sh"
    echo "  Find the latest at https://github.com/LizardByte/Sunshine/releases/"
    echo ""
    echo "For a local RPM file:"
    echo "  sudo SUNSHINE_RPM_URL=/path/to/Sunshine.rpm ./build.sh"
    exit 1
fi
