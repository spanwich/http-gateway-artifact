#!/bin/bash
# Build seL4 HTTP Gateway from source
#
# Usage:
#   docker run --rm -v $(pwd)/prebuilt:/output sel4-gw-builder /build.sh
#
set -euo pipefail

SRC_DIR="/src"
PROJECT_DIR="/workspace/projects/http_gateway_x86"

# Copy artifact source into ecosystem
echo "=== Setting up project ==="
mkdir -p "$PROJECT_DIR"
if [ -d "$SRC_DIR" ]; then
    cp -r "$SRC_DIR"/* "$PROJECT_DIR/"
else
    echo "ERROR: Mount source at /src (e.g., -v \$(pwd)/src:/src:ro)"
    exit 1
fi

# Set up mbedTLS
mkdir -p "$PROJECT_DIR/external"
ln -sf /workspace/mbedtls-3.6.5 "$PROJECT_DIR/external/mbedtls"

# Build
echo "=== Configuring (cmake) ==="
mkdir -p /workspace/build && cd /workspace/build
cmake -G Ninja -DPLATFORM=pc99 \
  -C "$PROJECT_DIR/settings.cmake" \
  "$PROJECT_DIR"

echo "=== Building (ninja) ==="
ninja

# Copy output
echo "=== Build complete ==="
ls -la images/kernel-x86_64-pc99 images/capdl-loader-image-x86_64-pc99

if [ -d "/output" ]; then
    cp images/kernel-x86_64-pc99 /output/
    cp images/capdl-loader-image-x86_64-pc99 /output/
    echo "Images copied to /output/"
else
    echo "Mount /output to extract images (e.g., -v \$(pwd)/prebuilt:/output)"
fi
