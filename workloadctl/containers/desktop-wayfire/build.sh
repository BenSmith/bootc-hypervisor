#!/bin/bash
set -e
cd "$(dirname "$0")"

if podman build -t localhost/desktop-wayfire:latest .; then
    echo "Build complete! Image: localhost/desktop-wayfire:latest"
else
    echo "Build failed."
    exit 1
fi
