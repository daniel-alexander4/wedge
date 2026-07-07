#!/usr/bin/env bash
# Build wedge and register it as the wedge:// protocol handler for the current user.
set -euo pipefail
cd "$(dirname "$0")"

BIN="${WEDGE_BIN:-$HOME/.local/bin/wedge}"
mkdir -p "$(dirname "$BIN")"
./build.sh "$BIN"

case "$(uname)" in
  Linux)
    APPS="$HOME/.local/share/applications"
    mkdir -p "$APPS"
    cat > "$APPS/wedge.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=wedge
Comment=SSH-key web authentication
Exec=$BIN %u
Terminal=false
Categories=Utility;Security;
MimeType=x-scheme-handler/wedge;
StartupWMClass=Wedge
EOF
    update-desktop-database "$APPS" 2>/dev/null || true
    xdg-mime default wedge.desktop x-scheme-handler/wedge 2>/dev/null || true
    echo "==> Installed $BIN and registered the wedge:// handler (Linux)."
    echo "    Ensure $(dirname "$BIN") is on your PATH."
    ;;
  Darwin)
    echo "==> Installed $BIN."
    echo "    macOS: register wedge:// via the app bundle's Info.plist CFBundleURLTypes"
    echo "    (CFBundleURLSchemes = [wedge]). See docs/wedge-protocol.md §9."
    ;;
  *)
    echo "==> Installed $BIN."
    echo "    Windows: register HKCU\\Software\\Classes\\wedge (URL Protocol +"
    echo "    shell\\open\\command). See docs/wedge-protocol.md §9."
    ;;
esac
