# wedge icon set — complete package

Brand source for wedge's iconography (2026-07, slate/emerald/indigo; the UI
palette in `web/style.css` is derived from these colors). Mirrors Dan's
`wedge-complete-package.zip` delivery.

Two variants of every icon:

- `svg/contrast/`, `png/contrast/` — a `#0f172a` halo/outline sits behind the
  art so the icon reads on **any** background. Use wherever the backdrop is
  unknown: OS/desktop icons, favicons, docs on white.
- `svg/transparent/`, `png/transparent/` — bare art, for known-dark
  backgrounds like the wedge UI itself.

PNG renders at 16–256px for consumers that can't take SVG (tray, Windows,
READMEs); `favicon/` holds multi-size `.ico` builds of the mark.

Wired into the app:

- `svg/contrast/wedge-mark.svg` — copy at `build/wedge.svg`, which nfpm
  installs to hicolor and `wedge.desktop` references as `Icon=wedge`.
  Edit here, re-copy there.
- `svg/contrast/wedge-mark-small.svg` — copy at `web/favicon.svg` (browser
  tab background varies with theme, so contrast).
- `svg/transparent/wedge-mark-small.svg`, `wedge-glyph-add.svg`,
  `wedge-glyph-keys.svg` — copies in `web/icons/` (UI header mark and the
  Add-site / SSH-keys glyphs; the UI is always dark, so transparent).

Staged, not yet wired:

- `wedge-connected/pending/error/inactive` — status tiles for the
  system-tray quick-launch item (pending.md); no tray exists yet. The PNG
  renders are tray-ready.
- `wedge-glyph-settings` — no matching UI surface yet.
- `wedge-mark-mono` (SVG, currentColor) and `wedge-mark-mono-white` (PNG) —
  for contexts that need a single-color mark.

Only files under `web/` ship in the binary; nfpm packages only its explicit
file list, so nothing here rides along uninvited.
