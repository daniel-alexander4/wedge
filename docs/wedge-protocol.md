# wedge — implementation notes for the `wedge://` flows

**Status:** current · **Applies to:** the wedge desktop app in this repository.

> **The wire protocol is specified normatively in [`wedge-spec-v1.md`](wedge-spec-v1.md)** —
> message formats, discovery, the core (browser-initiated) flow, the
> app-initiated extension (`/wedge/app-start` + `/wedge/claim`), conformance
> requirements, and security considerations. This document covers only what is
> specific to the wedge app: consent UX, configuration, key handling, and OS
> integration. Where the two disagree, the spec and the code win.

Proven end-to-end against `~/repos/wedge-web` on 2026-07-07 (full flow plus
browser-binding, single-use, and unconfigured-origin rejection; try-next and
add-on-first-use proven the same day).

---

## 1. How wedge maps onto the spec

- **Authenticator** = wedge (`cmd/wedge`, `internal/{protocol,rp,policy,signer,keyutil,server}`).
- The spec's allowlist (§7) is wedge's **sites list** (§3 below); the spec's
  presence action is wedge's **consent tap** (§2); the multi-key rule (spec §7
  "MAY try multiple keys") is wedge's **try-next** over agent-loaded `~/.ssh`
  keys, in discovery order.
- Both flows are implemented: the core flow via the `wedge://` handler
  (`runSign`), the app-initiated extension via the settings UI's launch button
  (`runAppSign` → `POST /api/signin`).
- **Unregistered key (app flow):** when every agent-loaded key fails verify
  with the spec's `unknown_key` code (§5.2), `runAppSign` returns status
  `"unregistered"` plus the RP's `registration_url` from discovery (§4;
  same-origin-validated, falling back to the origin root). The UI shows a
  3-second notice ("key not registered yet", with an immediate **Open now**
  button), then opens that page via `POST /api/open` — which accepts any
  http(s) URL whose origin is a configured site, never other hosts.

## 2. Consent & automation

**Every sign requires a user-presence tap — non-disableable globally.** The
click in wedge's consent window IS the presence signal (spec §7, §10
"Phishing"); biometric (Touch ID / Windows Hello) is a deferred upgrade.

Per-site, the first request offers three outcomes:

- **[Allow once]** — sign this one time; full detail screen again next time.
- **[Always allow]** — persist `alwaysAllow`: skip the detail screen, **still
  require the presence tap**. Never silent.
- **[Deny]** — refuse; the RP flow expires.

**New sites (gated add-on-first-use).** A flow for an origin not in the sites
list parks an **origin-only** prompt — no network until the user picks
[Add & Allow once] / [Add & Always allow] / [Deny]. Only http(s) origins are
eligible from links (an `ssh://` or other scheme is refused), so a link can't
plant a launch target.

**Silent (advanced, per-site opt-in):** `silent: true` skips the presence tap
for that one origin — off by default, explicitly warned, reopens the phishing
vector for that origin by informed choice. No global variant exists.

**Sign log:** every signature is recorded locally (time, origin, key,
approval type: allow-once / always-allow / silent) and shown in settings.
Revocation of RP sessions is the RP's job; the log is for detection.

**Key handling:** wedge holds no private keys. It discovers `~/.ssh/*.pub`,
cross-references `ssh-add -l`, and signs through the agent
(`ssh-keygen -Y sign -f <pubkey>`). Try-next: each agent-loaded key is tried
until the RP accepts one — safe because signatures are origin-bound (spec §6.1).

**Window surfacing:** the OS foregrounds wedge on a `wedge://` link; a second
process forwards the link to the running instance via `/internal/handoff` and
exits. The consent prompt reaches the UI over a long-poll (`/api/pending`).

## 3. Config schema

A single `sites` list — origin is the whole identity (spec §6.1), and any
agent-loaded key may sign for any site:

```jsonc
"sites": [
  { "origin": "https://acme.example",   // or "ssh://user@host:port" (launcher)
    "alwaysAllow": false,   // skip the detail screen; presence tap still required
    "silent": false,        // advanced: skip the presence tap too (per-site, warned)
    // ssh:// sites only — applied by the terminal launcher, ignored by SFTP:
    "tunnels": ["8080:localhost:80", "1080"], // shape picks the flag:
                            // [bind:]port → -D (SOCKS), [bind:]lport:host:hport → -L
    "jump": "user@bastion:22" }  // ProxyJump hop list (comma-separated) → -J
]
```

Tunnel specs and jump hops are strictly validated at launch
(`terminal.TunnelFlag` / `terminal.ValidateJump`) with the same
charset-limited, argv-only discipline as the target itself — never free text.
v1 limitation: no IPv6 literals and no wildcard/empty bind addresses.

The legacy `keyPath` + `allowedOrigins` + `originScopes` schema migrates to
`sites` on load. Settings offers **Export…/Import…** of the sites list
(`wedge-sites.json`; import merges by origin — adds/ORs flags, never deletes).
Discovery URLs are cached in memory only, never persisted.

**From SSH config.** Settings and onboarding step 2 can also import the
**literal `Host` aliases** from `~/.ssh/config` (`GET /api/sshconfig`) as
`ssh://<alias>` sites, through the same merge — review, then Save. Wildcard
and negated patterns, `Match`, and `Include` are deliberately not parsed:
launching runs `ssh <alias>`, so OpenSSH resolves
HostName/User/Port/ProxyJump/IdentityFile — including the blocks wedge didn't
read — at connect time. Aliases that fail the launch validation
(`terminal.ValidateSSHTarget`) are dropped server-side and reported as skipped.

## 4. Protocol-handler registration (per-OS)

- **Linux:** `.desktop` file with `MimeType=x-scheme-handler/wedge;` registered
  via `xdg-mime default` (automated by `install.sh` / the `.deb` postinstall).
- **macOS:** `CFBundleURLTypes` with `CFBundleURLSchemes = [wedge]` in
  `Info.plist` (manual — pending).
- **Windows:** `HKCU\Software\Classes\wedge` with `URL Protocol` and a
  `shell\open\command` pointing at the binary (manual — pending).

`wedge --version` and headless runs (`WEDGE_NO_BROWSER=1`) never trigger the
handler path.

**System tray (quick-launch).** On Linux (D-Bus StatusNotifierItem) and
Windows (win32) — both pure Go, so the CGO_ENABLED=0 release matrix is
untouched — wedge shows a tray icon whose menu lists the sites (ssh:// →
terminal, http(s) → sign-in-then-open; both go through the server's own
loopback API, so a tray click and a settings-row click share one validated
code path), plus **Open wedge** and **Quit wedge** — the first user-visible
way to stop wedge. The menu rebuilds live when sites change. Disable with
`WEDGE_NO_TRAY=1`. macOS tray needs cgo and lands with the native mac build.
GNOME shows StatusNotifier icons only with the AppIndicator extension (or a
proxy like snixembed); without one, wedge logs it and runs normally — there's
just no icon. Sign-ins started from the tray surface their consent tap through
the existing auto-opened window (`awaitDecision`), so the presence-tap
invariant is untouched.

## 5. Decision history (kept for the record)

1. **Runtime-proven** against `~/repos/wedge-web` (2026-07-07): full core flow,
   browser-binding, single-use, unconfigured-origin rejection; later the same
   day: try-next, namespace==origin enforcement, add-on-first-use, and the
   app-initiated claim flow.
2. **Key handling: delegate to `ssh-agent`** — private keys never enter wedge.
3. **Always-allow phishing risk resolved** by the mandatory per-sign presence
   tap (spec §10); "Always allow" skips only the detail screen; fully-silent is
   a per-site, explicitly-warned opt-in; the sign log provides detection.
4. **namespace == canonical origin** (2026-07-07 redesign): the per-site
   namespace/company config was retired; signatures are origin-bound and any
   key works at any site (see spec §6.1). Requires wedge-web in local mode
   until its registry namespace decoupling lands.
