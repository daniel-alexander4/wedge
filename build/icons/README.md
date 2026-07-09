# Wedge — Icon Set

One set, transparent background + `#0f172a` contrast border, legible on any
background (light, mid-tone, busy, dark). Layout: `svg/`, `png/<size>/`,
`favicon/`. Naming: `wedge-*`.

## Layout
- `svg/` — source vectors (scalable, recolorable). Prefer these.
- `png/<size>/` — square raster ladder (16–1024, class-dependent).
- `png/@1x`, `png/@2x` — non-square marketing assets (wordmark, buttons).
- `png/social/` — social/OG cards at exact spec.
- `favicon/` — `wedge.ico` (app-grade) and `favicon.ico` (web).

## §1 Platform app icons
- `wedge-mark`, `wedge-mark-small` — rendered up to **1024** for the macOS
  `.icns` ladder (assemble with `iconutil`/`png2icns` at build time).
- `wedge-mark-macos` — Big Sur squircle tile, mark inset to standard margins;
  the Dock-native look. PNG at 256/512/1024.
- `favicon/wedge.ico` — app icon for `wedge.exe` and the `wedge://` registry
  `DefaultIcon`. Layers **16/24/32/48/64/128/256**.
- All square classes now include **22** and **24 px** for Linux panels/trays.

## §2 Tray
- `wedge-tray-<state>Template` — macOS menu-bar **template** images
  (monochrome black+alpha), 22/44/88 px. Status is shape-coded so it survives
  the mono constraint: **connected = filled disc, pending = half disc,
  error = ✕, inactive = hollow ring**.
- `wedge-symbolic.svg` — single-color `currentColor` mark for GNOME/symbolic
  panel themes.
- Color composite tray = the existing `wedge-connected/pending/error/inactive`
  marks (mark + status badge), now rendered at tray sizes **22/24/32/44**.
- Menu type glyphs `wedge-glyph-web/terminal/sftp` include **16/24 px
  monochrome** renders (`*-mono.png`) for small single-color menus.

## §3 UI action glyphs (style-matched to add/keys/settings; slate + mint/indigo)
`open` (↗ sign-in/open), `terminal` (SSH), `sftp` (file transfer), `remove`
(trash), `import` (~/.ssh/config), `export`, `tunnel` (jump/tunnel),
`presence` (tap-to-approve), `biometric` (Touch ID / Windows Hello), `web`.

## §4 Ecosystem / adoption
- `wedge-signin-dark`, `wedge-signin-light` — "Sign in with wedge" button
  badges (SVG + PNG @1x/@2x), mark + label.
- `wedge-wordmark`, `wedge-wordmark-light` — horizontal mark + wordmark lockup
  for README headers and docs titles.
- `png/social/wedge-social-preview.png` — 1280×640 GitHub repo card.
- `png/social/wedge-og-image.png` — 1200×630 Open Graph image.

## Palette
Mint `#6ee7b7` / `#10b981` · Indigo `#6366f1` `#818cf8` `#3b82f6` `#8b5cf6`
· Slate `#334155` · Border `#0f172a`

## Notes
- `wedge-mark-mono.svg` uses `currentColor`. PNGs ship as slate (`#334155`)
  and `-white` (`#ffffff`); render the SVG for any other color.
- Wordmark/buttons are set in **DejaVu Sans Bold** for portable rendering;
  swap `font-family` for your brand typeface and re-render if desired.

## Favicon HTML
```html
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="icon" type="image/svg+xml" href="/wedge-mark-small.svg">
```

## Wired into the app (copies — edit here, re-copy there)

- `svg/wedge-mark.svg` → `build/wedge.svg` (nfpm installs it to hicolor;
  `wedge.desktop` references it as `Icon=wedge`).
- `svg/wedge-mark-small.svg` → `web/favicon.svg` and
  `web/icons/wedge-mark-small.svg` (UI header mark).
- `svg/wedge-glyph-{add,keys,open,terminal,sftp,remove,export,import,presence}.svg`
  → `web/icons/` (settings/onboarding buttons + site-row actions + the
  consent dialog's tap-to-approve mark).

Staged, not yet wired:

- `wedge-connected/pending/error/inactive`, the `wedge-tray-*Template` set,
  `wedge-symbolic`, and the `*-mono.png` menu glyphs — for the system-tray
  quick-launch item (pending.md); no tray exists yet.
- `wedge-mark-macos`, the 512/1024 renders, and `favicon/wedge.ico` — for the
  deferred macOS `.icns` / Windows handler work.
- `wedge-signin-*`, `wedge-wordmark*`, `png/social/` — adoption assets for
  the publish push (SDK READMEs / repo page).
- `wedge-glyph-{settings,tunnel,web,biometric}` — no matching UI surface yet.

Only files under `web/` ship in the binary; nfpm packages only its explicit
file list, so nothing here rides along uninvited.
