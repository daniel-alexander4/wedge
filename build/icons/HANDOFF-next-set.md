# Icon handoff — what's missing for a full wedge set

Request for the next `wedge-icons.zip` delivery. The current set (see
README.md) covers the Linux desktop, the web UI's mark + three glyphs, and
tray-ready state tiles at 16–256px. The gaps below are what the roadmap
(pending.md: macOS/Windows support, tray quick-launch, publish/adoption push)
will need. Keep the established conventions: the `#0f172a` halo on every
colored icon, the flat `svg/` + `png/<size>/` + `favicon/` layout, `wedge-*`
naming.

## 1. Platform app icons — blocks the macOS/Windows handler work

- **512×512 and 1024×1024 PNG renders of `wedge-mark`** (and ideally
  `wedge-mark-small` for comparison at a distance). macOS `.icns` needs the
  full @1x/@2x ladder up to 1024; current renders stop at 256. The `.icns`
  itself can be assembled at build time (`iconutil`/`png2icns`) once the
  renders exist.
- **Optional macOS tile variant** (`wedge-mark-macos`): the mark centered on
  a Big Sur-style rounded-rect tile with standard margins. The halo'd mark
  works, but a squircle tile is the platform-native look in the Dock.
- **App-grade `.ico`** (`wedge.ico`, distinct from the favicon): layers
  16/24/32/48/64/128/256. The existing `favicon/favicon.ico` only carries
  16/32/48/64 — no 24 (Windows small UI) and no 256 (Explorer large view).
  This is what gets embedded in `wedge.exe` and referenced by the
  `wedge://` registry `DefaultIcon`.
- **22×22 and 24×24 PNG renders** of the existing names (at minimum
  `wedge-mark` + the four state tiles). Linux panels/trays are 22/24px;
  the current ladder jumps 16 → 32.

## 2. Tray quick-launch (pending GTM-bundle item)

The color state tiles (`connected/pending/error/inactive`) exist and are
tray-ready on Linux/Windows. Still missing:

- **macOS template variants**: monochrome black-with-alpha versions of the
  four states, 22×22 and 44×44 (@2x), named `wedge-tray-<state>Template`.
  macOS menu bar icons must be template images; the color tiles will look
  wrong there.
- **Linux symbolic variant**: a single-color `wedge-symbolic.svg`
  (currentColor, like `wedge-mark-mono`) for symbolic-icon panel themes.
- **A decision asset, if we want it**: a composite tray icon — the wedge
  mark with a small status dot/badge per state — as an alternative to the
  bare state tiles, so the tray reads "wedge" at a glance rather than an
  anonymous colored square. One composite per state, 22/24/32/44px.
- **Menu-item glyphs**: the tray's sites-list menu should show a per-row
  type glyph (web / terminal / SFTP). The §3 action glyphs cover the
  shapes — deliver them with 16px monochrome renders too, since menus on
  some platforms want small single-color icons.

## 3. UI action glyphs — replace font-dependent text glyphs

The settings rows currently use text/emoji glyphs whose rendering varies by
font stack (the terminal glyph renders as a tower on some systems, and color
emoji leaks on others). Style-match the existing `wedge-glyph-add/keys/
settings` set (SVG, slate/mint):

- `wedge-glyph-open` — replaces `↗` (sign in + open site)
- `wedge-glyph-terminal` — replaces `🖥︎` (SSH terminal launch)
- `wedge-glyph-sftp` — replaces `🗂︎` (SFTP file-manager launch, v0.2.6)
- `wedge-glyph-remove` — replaces `🗑` (remove site row)
- Roadmap glyphs, same batch if cheap: `wedge-glyph-import`
  (~/.ssh/config import), `wedge-glyph-export` (the settings sites list
  already has text-only Export…/Import… buttons — export is the missing
  half of the pair), `wedge-glyph-tunnel` (per-site tunnels/jump).
- `wedge-glyph-presence` — a "tap to approve" glyph for the consent
  window, which is currently all text; plus a fingerprint/biometric
  variant (`wedge-glyph-biometric`) for the pending Touch ID /
  Windows Hello presence upgrade.

(The ✓/✗ marks in the keys list and status line can stay text — they render
consistently — unless a matching pair is trivial to add.)

## 4. Ecosystem / adoption assets — for the publish push

- **"Sign in with wedge" button badges**: official full-button assets RPs
  can drop in next to `wedge.js` — dark and light variants, SVG + PNG,
  mark + label, in the spirit of "Sign in with Google" buttons. These
  belong in the SDK READMEs/demos once they exist.
- **Repo social preview**: 1280×640 card (mark + wordmark + one-liner) for
  the GitHub repo page, plus a generic 1200×630 og-image if it differs.
- **Horizontal lockup** (`wedge-wordmark`): mark + "wedge" wordmark, SVG,
  for the README header and docs/spec title pages.

## Not needed (already covered)

- Scalable Linux desktop icon (`wedge-mark.svg` → hicolor) — wired.
- Web UI favicon (SVG) + header mark + add/keys glyphs — wired.
- Monochrome mark: `wedge-mark-mono.svg` is currentColor and covers
  single-color contexts; `wedge-mark-mono-white` PNGs exist for raster.
- PWA/maskable icons — wedge is a chromeless app window, not a PWA.

## Priority order

1. §1 platform icons — they gate the already-pending macOS/Windows items.
2. §3 UI glyphs — visible polish, removes real font-rendering variance.
3. §2 tray variants — needed the day the tray item starts, not before.
4. §4 adoption assets — timed with the publish/release push.
