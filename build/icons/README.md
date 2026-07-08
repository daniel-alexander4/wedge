# wedge icon set

Brand source for wedge's iconography (2026-07, slate/emerald/indigo; the UI
palette in `web/style.css` is derived from these colors). Mirrors Dan's
`wedge-icons.zip` delivery.

Every icon carries its own `#0f172a` halo/outline behind the colored art, so
one set reads on any background — light docs, dark UI, OS themes. PNG renders
at 16–256px are for consumers that can't take SVG (tray, Windows, READMEs);
`favicon/favicon.ico` is the multi-size favicon build of the mark.

Wired into the app (copies — edit here, re-copy there):

- `svg/wedge-mark.svg` → `build/wedge.svg` (nfpm installs it to hicolor;
  `wedge.desktop` references it as `Icon=wedge`).
- `svg/wedge-mark-small.svg` → `web/favicon.svg` and
  `web/icons/wedge-mark-small.svg` (UI header mark).
- `svg/wedge-glyph-add.svg`, `svg/wedge-glyph-keys.svg` → `web/icons/`
  (Add-site buttons, SSH-keys label).

Staged, not yet wired:

- `wedge-connected/pending/error/inactive` — status tiles for the
  system-tray quick-launch item (pending.md); no tray exists yet. The PNG
  renders are tray-ready.
- `wedge-glyph-settings` — no matching UI surface yet.
- `wedge-mark-mono` (SVG, currentColor) and `wedge-mark-mono-white` (PNG) —
  for contexts that need a single-color mark.

Only files under `web/` ship in the binary; nfpm packages only its explicit
file list, so nothing here rides along uninvited.
