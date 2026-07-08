#!/usr/bin/env bash
# Build wedge's .deb for this machine and install it — giving a menu item plus
# the wedge:// protocol-handler registration (the .deb's postinstall runs
# update-desktop-database + xdg-mime).
#
# Usage: ./install.sh [version]   (version defaults to the VERSION file)
set -euo pipefail
cd "$(dirname "$0")"

VERSION="${1:-$(cat VERSION 2>/dev/null || echo 0.0.0)}"
ARCH="$(dpkg --print-architecture)" # amd64 or arm64
DEB="dist/wedge_${VERSION}_${ARCH}.deb"
mkdir -p dist

echo "building wedge $VERSION ($ARCH)…"
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o dist/wedge ./cmd/wedge

if ! command -v nfpm >/dev/null 2>&1; then
  echo "installing nfpm…"
  # Pinned, not @latest: an unpinned build tool fetched mid-install could drift
  # or be compromised between runs. Bump deliberately when upgrading nfpm.
  go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.46.3
  export PATH="$PATH:$(go env GOPATH)/bin"
fi

echo "packaging $DEB…"
ARCH="$ARCH" VERSION="$VERSION" \
  nfpm package --config build/nfpm.yaml --packager deb --target "$DEB"
rm -f dist/wedge

echo "installing $DEB (sudo)…"
# apt-get (not dpkg -i) so any deps resolve; -qq keeps it quiet;
# APT::Sandbox::User=root lets apt read the .deb from your home dir without the
# "_apt couldn't access" permission warning.
sudo apt-get install -y -qq -o APT::Sandbox::User=root "./$DEB"

# Stop any instance still running the OLD binary so the next launch (menu or a
# wedge:// link) starts $VERSION. SIGTERM is wedge's clean-shutdown path; the
# KILL backstop covers a hung one. Exact process name, run as you — only your
# own wedge processes are touched.
if pgrep -x wedge >/dev/null 2>&1; then
  echo "stopping the running wedge so the next launch starts $VERSION…"
  pkill -TERM -x wedge 2>/dev/null || true
  for _ in {1..20}; do pgrep -x wedge >/dev/null 2>&1 || break; sleep 0.25; done
  pkill -KILL -x wedge 2>/dev/null || true
fi

# Refresh the desktop + icon caches so the menu entry, icon, and wedge:// handler
# are live now (the .deb postinstall already runs these; harmless to repeat).
sudo update-desktop-database >/dev/null 2>&1 || true
sudo gtk-update-icon-cache /usr/share/icons/hicolor >/dev/null 2>&1 || true

echo "done — wedge $VERSION installed; find it in your applications menu."
