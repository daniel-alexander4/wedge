#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "==> Installing npm dependencies..."
npm install

echo "==> Building extension..."
npm run build:all

DIST_CHROME="$SCRIPT_DIR/dist/chrome"
if [[ ! -d "$DIST_CHROME" ]]; then
  echo "Build failed: $DIST_CHROME not found" >&2
  exit 1
fi

# Compute deterministic Chrome extension ID from the absolute path of dist/chrome.
# Chrome derives the ID for unpacked extensions by hashing the path:
#   SHA-256(path) -> take first 32 hex chars -> map 0-9a-f to a-p
compute_chrome_id() {
  local path="$1"
  local hash
  hash="$(printf '%s' "$path" | sha256sum | cut -c1-32)"
  local id=""
  for (( i=0; i<${#hash}; i++ )); do
    local c="${hash:$i:1}"
    case "$c" in
      0) id+="a";; 1) id+="b";; 2) id+="c";; 3) id+="d";;
      4) id+="e";; 5) id+="f";; 6) id+="g";; 7) id+="h";;
      8) id+="i";; 9) id+="j";; a) id+="k";; b) id+="l";;
      c) id+="m";; d) id+="n";; e) id+="o";; f) id+="p";;
    esac
  done
  echo "$id"
}

CHROME_EXT_ID="$(compute_chrome_id "$DIST_CHROME")"
echo ""
echo "Computed Chrome extension ID: $CHROME_EXT_ID"
echo "  (based on path: $DIST_CHROME)"

echo ""
echo "==> Installing native messaging hosts..."
"$SCRIPT_DIR/native-host/install-linux.sh" \
  --extension-id "$CHROME_EXT_ID"

echo ""
echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Load the extension in your browser:"
echo "     Chrome:  chrome://extensions -> Enable Developer mode -> Load unpacked -> select dist/chrome"
echo "     Firefox: about:debugging#/runtime/this-firefox -> Load Temporary Add-on -> select dist/firefox/manifest.json"
echo ""
echo "  2. Open the extension popup/options and configure origin mappings."
echo ""
echo "  NOTE: The computed extension ID ($CHROME_EXT_ID) is only valid when"
echo "  loading from: $DIST_CHROME"
echo "  If you move the dist folder, re-run this script."
