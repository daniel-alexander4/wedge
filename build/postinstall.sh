#!/bin/sh
# Runs as root after the wedge .deb is unpacked. Refreshes the desktop database
# (so the wedge:// x-scheme-handler association from wedge.desktop takes effect)
# and the icon cache. Best-effort — a missing tool must not fail the install.
set -e
update-desktop-database -q 2>/dev/null || true
gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
exit 0
