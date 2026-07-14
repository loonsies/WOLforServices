#!/bin/bash
# Shell script to run the build container and package the plugin
set -e

echo "=== Building WOL4Services Docker Image ==="
docker build -t wol4services-builder .

echo "=== Running build inside Docker ==="
docker run --rm -v "$(pwd):/workspace" wol4services-builder bash -c "chmod +x /workspace/build-package.sh && /workspace/build-package.sh"

echo "=== Build and package completed! ==="
