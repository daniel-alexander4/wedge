# wedge icon set

Brand source for wedge's iconography (2026-07, slate/emerald/indigo). The UI
palette in `web/style.css` is derived from these colors.

Wired into the app:

- `wedge-mark.svg` — the app icon; a copy lives at `build/wedge.svg`, which
  nfpm installs to hicolor and `wedge.desktop` references as `Icon=wedge`.
  Edit here, re-copy there.
- `wedge-mark-small.svg` — copied to `web/favicon.svg` and
  `web/icons/wedge-mark-small.svg` (UI header mark).
- `wedge-glyph-add.svg`, `wedge-glyph-keys.svg` — copied to `web/icons/`
  (Add-site buttons, SSH-keys label).

Staged, not yet wired:

- `wedge-connected.svg`, `wedge-pending.svg`, `wedge-error.svg`,
  `wedge-inactive.svg` — status tiles for the system-tray quick-launch item
  (pending.md); no tray exists yet.
- `wedge-glyph-settings.svg` — no matching UI surface yet.
- `wedge-mark-mono.svg` — currentColor variant for contexts that need a
  theme-inherited mark.

Only files under `web/` ship in the binary; nfpm packages only its explicit
file list, so nothing here rides along uninvited.
