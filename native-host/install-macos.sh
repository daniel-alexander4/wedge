#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST_SCRIPT="$SCRIPT_DIR/com.pubkey.auth.py"
CHROME_TMPL="$SCRIPT_DIR/hosts/com.pubkey.auth.chrome.json"
FIREFOX_TMPL="$SCRIPT_DIR/hosts/com.pubkey.auth.firefox.json"

if [[ ! -x "$HOST_SCRIPT" ]]; then
  echo "Host script not executable: $HOST_SCRIPT" >&2
  exit 1
fi

install_chrome=false
install_chromium=false
install_edge=false
install_brave=false
install_firefox=false
global_extension_id=""
chrome_extension_id=""
chromium_extension_id=""
edge_extension_id=""
brave_extension_id=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --chrome)
      install_chrome=true
      shift
      ;;
    --chromium)
      install_chromium=true
      shift
      ;;
    --edge)
      install_edge=true
      shift
      ;;
    --brave)
      install_brave=true
      shift
      ;;
    --firefox)
      install_firefox=true
      shift
      ;;
    --extension-id)
      global_extension_id="${2:-}"
      shift 2
      ;;
    --chrome-extension-id)
      chrome_extension_id="${2:-}"
      shift 2
      ;;
    --chromium-extension-id)
      chromium_extension_id="${2:-}"
      shift 2
      ;;
    --edge-extension-id)
      edge_extension_id="${2:-}"
      shift 2
      ;;
    --brave-extension-id)
      brave_extension_id="${2:-}"
      shift 2
      ;;
    *)
      echo "Unknown arg: $1" >&2
      exit 1
      ;;
  esac
done

if ! $install_chrome && ! $install_chromium && ! $install_edge && ! $install_brave && ! $install_firefox; then
  # Auto-detect installed browsers
  if [[ -d "/Applications/Google Chrome.app" ]] || [[ -d "$HOME/Applications/Google Chrome.app" ]]; then
    install_chrome=true
  fi
  if [[ -d "/Applications/Chromium.app" ]] || [[ -d "$HOME/Applications/Chromium.app" ]]; then
    install_chromium=true
  fi
  if [[ -d "/Applications/Microsoft Edge.app" ]] || [[ -d "$HOME/Applications/Microsoft Edge.app" ]]; then
    install_edge=true
  fi
  if [[ -d "/Applications/Brave Browser.app" ]] || [[ -d "$HOME/Applications/Brave Browser.app" ]]; then
    install_brave=true
  fi
  if [[ -d "/Applications/Firefox.app" ]] || [[ -d "$HOME/Applications/Firefox.app" ]]; then
    install_firefox=true
  fi
  # Fallback: if nothing detected, install for all
  if ! $install_chrome && ! $install_chromium && ! $install_edge && ! $install_brave && ! $install_firefox; then
    echo "No browsers detected; installing for all." >&2
    install_chrome=true
    install_chromium=true
    install_edge=true
    install_brave=true
    install_firefox=true
  fi
fi

any_chromium=false
if $install_chrome || $install_chromium || $install_edge || $install_brave; then
  any_chromium=true
fi

if $any_chromium && [[ -z "$global_extension_id" && -z "$chrome_extension_id" && -z "$chromium_extension_id" && -z "$edge_extension_id" && -z "$brave_extension_id" ]]; then
  echo "Extension ID is required for Chromium-based browsers." >&2
  echo "Provide --extension-id (all) or browser-specific IDs." >&2
  exit 1
fi

resolve_extension_id() {
  local browser="$1"
  case "$browser" in
    chrome) echo "${chrome_extension_id:-$global_extension_id}" ;;
    chromium) echo "${chromium_extension_id:-$global_extension_id}" ;;
    edge) echo "${edge_extension_id:-$global_extension_id}" ;;
    brave) echo "${brave_extension_id:-$global_extension_id}" ;;
    *)
      echo ""
      ;;
  esac
}

mk_manifest() {
  local template="$1"
  local out="$2"
  local ext_id="${3:-}"
  mkdir -p "$(dirname "$out")"
  sed \
    -e "s#__HOST_PATH__#$HOST_SCRIPT#g" \
    -e "s#__EXTENSION_ID__#$ext_id#g" \
    "$template" > "$out"
  echo "Installed: $out"
}

if $install_chrome; then
  ext_id="$(resolve_extension_id chrome)"
  if [[ -z "$ext_id" ]]; then
    echo "Missing extension ID for Chrome." >&2
    exit 1
  fi
  mk_manifest "$CHROME_TMPL" "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.pubkey.auth.json" "$ext_id"
fi

if $install_chromium; then
  ext_id="$(resolve_extension_id chromium)"
  if [[ -z "$ext_id" ]]; then
    echo "Missing extension ID for Chromium." >&2
    exit 1
  fi
  mk_manifest "$CHROME_TMPL" "$HOME/Library/Application Support/Chromium/NativeMessagingHosts/com.pubkey.auth.json" "$ext_id"
fi

if $install_edge; then
  ext_id="$(resolve_extension_id edge)"
  if [[ -z "$ext_id" ]]; then
    echo "Missing extension ID for Edge." >&2
    exit 1
  fi
  mk_manifest "$CHROME_TMPL" "$HOME/Library/Application Support/Microsoft Edge/NativeMessagingHosts/com.pubkey.auth.json" "$ext_id"
fi

if $install_brave; then
  ext_id="$(resolve_extension_id brave)"
  if [[ -z "$ext_id" ]]; then
    echo "Missing extension ID for Brave." >&2
    exit 1
  fi
  mk_manifest "$CHROME_TMPL" "$HOME/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/com.pubkey.auth.json" "$ext_id"
fi

if $install_firefox; then
  mk_manifest "$FIREFOX_TMPL" "$HOME/Library/Application Support/Mozilla/NativeMessagingHosts/com.pubkey.auth.json"
fi

echo "Done."
echo "Optional key override: export PUBKEY_AUTH_KEY_PATH=~/.ssh/id_ed25519"
