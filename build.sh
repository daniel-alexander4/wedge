#!/usr/bin/env bash
# Cross-compile wedge for all platforms and build Linux .deb packages.
# Usage: ./build.sh [-p|--publish] [version]   (version defaults to the VERSION file)
#
# Produces one cgo-free static `wedge` binary per OS/arch in dist/ (the web UI is
# embedded, so each binary is fully self-contained), plus a .deb for linux
# amd64/arm64 when nfpm is installed
# (go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest). The .deb installs
# the binary, a .desktop entry, an icon, and registers the wedge:// handler.
#
# -p / --publish: after building, push main and publish the dist/ artifacts as
# GitHub release v<version>. Requires gh (authenticated), nfpm, and a clean,
# committed tree.
set -euo pipefail
cd "$(dirname "$0")"

PUBLISH=0
ARGS=()
for a in "$@"; do
  case "$a" in
    -p|--publish) PUBLISH=1 ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown flag: $a (usage: ./build.sh [-p|--publish] [version])" >&2; exit 1 ;;
    *) ARGS+=("$a") ;;
  esac
done
VERSION="${ARGS[0]:-$(cat VERSION 2>/dev/null || echo dev)}"

if [ "$PUBLISH" = 1 ]; then
  # Fail the preconditions before spending minutes building.
  command -v gh >/dev/null 2>&1 || { echo "publish needs the gh CLI (authenticated)" >&2; exit 1; }
  command -v nfpm >/dev/null 2>&1 || { echo "publish needs nfpm — a release without the .debs would strand deb installs (go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest)" >&2; exit 1; }
  [ "$VERSION" != "dev" ] || { echo "publish needs a real version (VERSION file missing?)" >&2; exit 1; }
  git diff-index --quiet HEAD -- || { echo "publish needs a clean tree — commit first (the release tag must match the built code)" >&2; exit 1; }
  if gh release view "v$VERSION" >/dev/null 2>&1; then
    echo "release v$VERSION already exists — bump VERSION (./bump.sh patch) and commit first" >&2
    exit 1
  fi
fi

DIST="dist"
rm -rf "$DIST"
mkdir -p "$DIST"

LDFLAGS="-s -w -X main.version=$VERSION"

targets=(
  "linux/amd64" "linux/arm64"
  "darwin/amd64" "darwin/arm64"
  "windows/amd64" "windows/arm64"
)

for t in "${targets[@]}"; do
  os="${t%/*}"; arch="${t#*/}"
  ext=""; [ "$os" = "windows" ] && ext=".exe"
  out="$DIST/wedge-$VERSION-$os-$arch$ext"
  echo "building $out"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
    -ldflags "$LDFLAGS" -o "$out" ./cmd/wedge
done

if command -v nfpm >/dev/null 2>&1; then
  for arch in amd64 arm64; do
    echo "packaging wedge_${VERSION}_${arch}.deb"
    # nfpm.yaml references the literal staged path dist/wedge.
    cp "$DIST/wedge-$VERSION-linux-$arch" "$DIST/wedge"
    ARCH="$arch" VERSION="$VERSION" \
      nfpm package --config build/nfpm.yaml --packager deb --target "$DIST/wedge_${VERSION}_${arch}.deb"
  done
  rm -f "$DIST/wedge"
else
  echo "nfpm not found — skipping .deb. Install: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"
fi

# macOS .app bundles: macOS routes wedge:// to a bundle identifier, not a bare
# binary, so the URL-scheme handler (Info.plist CFBundleURLTypes) needs a
# wedge.app. Ship one per arch, zipped. NOTE: unsigned — Gatekeeper quarantines
# it until it is codesigned + notarized (an Apple Developer account); until then
# a user opens it once via right-click → Open. `wedge --register-handler`
# (run from inside the .app) forces Launch Services to pick up the scheme.
for arch in amd64 arm64; do
  app="$DIST/wedge.app"
  rm -rf "$app"
  mkdir -p "$app/Contents/MacOS"
  cp "$DIST/wedge-$VERSION-darwin-$arch" "$app/Contents/MacOS/wedge"
  cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>wedge</string>
  <key>CFBundleDisplayName</key><string>wedge</string>
  <key>CFBundleIdentifier</key><string>io.alexander4.wedge</string>
  <key>CFBundleExecutable</key><string>wedge</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLName</key><string>io.alexander4.wedge</string>
      <key>CFBundleURLSchemes</key><array><string>wedge</string></array>
    </dict>
  </array>
</dict>
</plist>
PLIST
  ( cd "$DIST" && zip -qr "wedge-$VERSION-darwin-$arch.app.zip" wedge.app )
  rm -rf "$app"
  echo "packaged wedge-$VERSION-darwin-$arch.app.zip"
done

echo "done — artifacts in $DIST/"

if [ "$PUBLISH" = 1 ]; then
  echo "pushing main and publishing release v$VERSION"
  git push origin main
  gh release create "v$VERSION" \
    --title "wedge $VERSION" \
    --generate-notes \
    "$DIST"/*
  echo "published — https://github.com/daniel-alexander4/wedge/releases/tag/v$VERSION"

  # Optional apt channel: push the .debs to a public GCP Artifact Registry apt
  # repo so strangers can `apt install wedge` instead of building from source.
  # Off unless WEDGE_APT_REPO is set — build.sh -p is unchanged for anyone who
  # hasn't opted in. AR signs the repo metadata itself (clients trust it via
  # AR's own key), so there is no signing key to manage here. One-time setup +
  # the client sources.list line are documented in README.
  if [ -n "${WEDGE_APT_REPO:-}" ]; then
    command -v gcloud >/dev/null 2>&1 || { echo "WEDGE_APT_REPO set but gcloud not found — skipping apt publish" >&2; exit 1; }
    loc="${WEDGE_APT_LOCATION:-us-west1}"
    for arch in amd64 arm64; do
      deb="$DIST/wedge_${VERSION}_${arch}.deb"
      [ -f "$deb" ] || { echo "no $deb to upload (nfpm ran?) — skipping" >&2; continue; }
      echo "uploading $deb to AR apt repo $WEDGE_APT_REPO ($loc)"
      gcloud artifacts apt upload "$WEDGE_APT_REPO" --location="$loc" --source="$deb"
    done
    echo "apt channel updated — clients: apt update && apt install wedge"
  fi
fi
