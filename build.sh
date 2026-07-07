#!/usr/bin/env bash
# Build the wedge desktop binary, stamping the version from the VERSION file.
# Usage: ./build.sh [output-path]   (default: ./dist/wedge)
set -euo pipefail
cd "$(dirname "$0")"

VERSION="$(cat VERSION 2>/dev/null || echo dev)"
OUT="${1:-dist/wedge}"
mkdir -p "$(dirname "$OUT")"

echo "==> Building wedge $VERSION -> $OUT"
go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$OUT" ./cmd/wedge
echo "    Done."
