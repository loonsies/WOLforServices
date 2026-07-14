#!/bin/bash
# Script to build unraidwold and package WOL4Services inside the Docker container

set -e

echo "=== Building unraidwold daemon ==="
cd /workspace/unraidwold

export CGO_CFLAGS="-I/usr/local/include"
export CGO_LDFLAGS="-L/usr/local/lib -lpcap"
export LD_LIBRARY_PATH="/usr/local/lib"
export GOTOOLCHAIN=auto

go build -ldflags="-s -w" -o /workspace/src/WOL4Services/usr/local/bin/unraidwold unraidwold.go

echo "=== Verifying ELF linkage ==="
if command -v readelf >/dev/null 2>&1; then
    readelf -d /workspace/src/WOL4Services/usr/local/bin/unraidwold | grep NEEDED
fi

echo "=== Packaging WOL4Services ==="
cd /workspace
chmod +x src/mkpkg
./src/mkpkg WOL4Services

echo "=== Build and package completed successfully! ==="
