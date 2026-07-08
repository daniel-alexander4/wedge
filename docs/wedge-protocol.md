# The `wedge://` authentication protocol

**Status:** v1 · **Date:** 2026-07-07 · **Applies to:** wedge desktop app + any relying-party website that wants "Sign in with wedge". Proven end-to-end against `~/repos/wedge-web` on 2026-07-07 (see §11).

wedge proves possession of a user's SSH key to a website, without a browser extension and without the website ever touching the user's machine directly. It replaces the old extension + native-host + `fetch('127.0.0.1')` model, which browsers are closing off (Chrome 142 Local Network Access, Firefox 2026).

---

## 1. Roles & terms

| Term | Meaning |
|------|---------|
| **User** | Owns an SSH key (`ssh-keygen -Y`-signable, e.g. ed25519). Runs wedge. |
| **wedge** | The user's desktop app. Holds the key unlocked (ssh-agent style), is the registered `wedge://` protocol handler, and runs a loopback server **for its own UI only** (never reachable cross-origin). |
| **RP** (relying party) | The website the user logs into. Has a **frontend** (login page) and a **backend** (the verifier + flow endpoints). |
| **origin** | The RP's web origin, e.g. `https://acme.example`. wedge's primary config key. |
| **challenge** | Random one-time bytes the RP wants signed. Format: `^[A-Za-z0-9_-]{16,256}$`. |
| **namespace** | The SSH-signature namespace the RP expects — **equal to the RP's canonical origin** (`namespace == origin`). wedge signs with the value the RP reports and rejects any namespace not equivalent (localhost↔127.0.0.1) to the link origin. This binds every signature to one origin, so it can't be replayed against another. (There is no separate namespace or company to configure; the old 64-char tag regex is retired.) |
| **keys** | wedge auto-discovers the user's `~/.ssh/*.pub` keys and signs with the **agent-loaded** ones, trying each in turn until the RP accepts one (try-next). Any key may be used for any site. |
| **request_id** | Opaque, single-use handle for one login attempt. Ties the browser, the signature, and the poll together. |

**Design invariant:** the `wedge://` link is fully attacker-controllable. wedge treats `origin` **only as a lookup key into its own config** and `request_id` as opaque. wedge never learns *where to send anything* from the link — only from config/discovery. This is what makes the link safe to accept from any source.

---

## 2. The flow

```
 RP frontend (browser)        wedge (desktop)              RP backend
      │                                                        │
 1. click "Sign in with wedge" ────────────────────────────────▶
      │                            2. backend mints request_id + challenge,
      │                               binds request_id to THIS browser (cookie)
      │◀──────────── request_id (+ page starts polling) ───────│
      │                                                        │
 3. open wedge://sign?v=1&origin=…&request_id=…                │
      │                                                        │
      ▼                                                        │
 4. OS launches/foregrounds wedge                              │
      │        5. wedge: origin ∈ config?  → discover RP        │
      │           endpoints from config (§4)                    │
      │        6. wedge GETs the challenge for request_id ──────▶ (challenge_url)
      │◀───────────── challenge, namespace, company ───────────│
      │        7. policy check (origin/namespace/company/fmt)   │
      │        8. consent: always-allow? sign silently.         │
      │           else prompt [Allow once][Always allow][Deny]  │
      │        9. ssh-keygen -Y sign  (held, unlocked key)      │
      │       10. POST signature for request_id ────────────────▶ (verify_url)
      │                          11. backend: match request_id's stored
      │                              challenge, ssh-keygen -Y verify,
      │                              mark request_id AUTHENTICATED
      │◀── 12. poll sees "authenticated" (same-browser cookie) ─│
      ▼                          13. backend completes login for the
  logged in                          browser that owns request_id
```

The RP↔browser half (steps 1, 2, 12, 13) is ordinary same-origin web traffic the RP already knows how to do. wedge only participates in steps 4–10, and only ever talks to the RP over endpoints it discovered from the **configured** origin.

At step 2 the RP binds `request_id` to **both** the initiating browser (a short-lived cookie) **and** the user's identity — the principal/username it will verify the signature against, plus that user's registered key(s). That's why wedge never sends a username (§5): the RP already knows who `request_id` is for. In `~/repos/wedge-web` this is the existing per-username key lookup (local/registry); the only new state is carrying `request_id` + a browser nonce + a status alongside the challenge it already mints.

---

## 3. The `wedge://` URI

```
wedge://sign?v=1&origin=<url-encoded origin>&request_id=<url-encoded id>
```

- `v` — protocol version, integer. This spec is `v=1`. wedge rejects unknown versions.
- `origin` — the RP origin. wedge normalizes it (existing `policy.NormalizeOrigin`, incl. localhost↔127.0.0.1) and requires an exact match in its allowlist. **Not in config → reject, no network, no prompt.**
- `request_id` — opaque; passed back to the RP verbatim in steps 6 and 10.

Deliberately minimal. The challenge is **not** in the link — wedge fetches it from the RP's discovered `challenge_url` (§5) so the only thing it ever signs is a value that provably came from the RP's own endpoint, not from whoever built the link.

Only `action = sign` exists in v1. Future actions (e.g. `register`) reuse the scheme.

---

## 4. RP discovery (`.well-known`)

wedge learns an RP's endpoints from a discovery document, so the user configures only the **origin** (the site URL), never raw URLs or a namespace:

```
GET https://<configured-origin>/.well-known/wedge.json
→ {
    "version": 1,
    "namespace": "https://acme.example",     // == the RP's canonical origin
    "challenge_url": "https://acme.example/wedge/challenge",
    "verify_url":    "https://acme.example/wedge/verify"
  }
```

- wedge builds the discovery URL from the **configured origin**, never from the link — so a hostile link cannot redirect discovery (no SSRF).
- `challenge_url` / `verify_url` **must** be same-origin with the configured origin; wedge rejects any that aren't. (Second SSRF guard.)
- Cached with a short TTL; refetched on cache miss or signature-verify failure.
- **`namespace` must equal the configured origin** (equivalence-aware, localhost↔127.0.0.1), or wedge refuses. This makes every signature origin-bound; there is no separate namespace or company to configure.

---

## 5. Messages

**Challenge fetch** (wedge → RP, step 6):
```
GET <challenge_url>?request_id=<id>
→ 200 { "challenge": "<16-256 url-safe chars>",
        "namespace": "https://acme.example",   // == the RP's canonical origin
        "expires_at": "<RFC3339>" }            // optional; wedge doesn't enforce it (RP owns expiry)
→ 404 / 410 if request_id unknown or expired
```

**Verify** (wedge → RP, step 10):
```
POST <verify_url>   (JSON; carries no browser cookie — request_id is the correlator)
{ "request_id": "<id>",
  "challenge":  "<echoed challenge>",
  "namespace":  "acme-login",
  "signature":  "-----BEGIN SSH SIGNATURE-----\n…",
  "public_key": "ssh-ed25519 AAAA…"   // OPTIONAL — see note
}
→ 200 { "ok": true }
→ 4xx { "ok": false, "error": "<reason>" }
```

**wedge sends no username.** The RP resolves *which user* (the principal) and their expected public key(s) from `request_id`, which it bound to the user's identity when the browser initiated the flow (§2). wedge only proves possession of a key by signing the challenge. `public_key` is optional; if the RP uses it (e.g. key-first lookup), it **must** confirm the key is a registered key for that principal — never trust a client-supplied key blindly. Verification is `ssh-keygen -Y verify -f <allowed_signers> -I <principal> -n <namespace> -s <sig>` with the challenge on stdin — the exact inverse of wedge's sign, and precisely what `~/repos/wedge-web` already does (`verify_signature()`), so the RP's crypto kernel is reused unchanged.

**Status poll** (browser → RP, steps 2/12 — RP-internal, spec'd for completeness):
```
GET <origin>/wedge/status?request_id=<id>      (same-origin, sends the binding cookie)
→ { "status": "pending" | "authenticated" | "denied" | "expired" }
```

---

## 6. Signing & verification

wedge's `signer` package does the sign side, over the keys `keyutil` discovers:

- **wedge auto-discovers `~/.ssh/*.pub`** and signs with the **agent-loaded** ones, trying each in turn (**try-next**) until the RP accepts one — a failed verify doesn't consume the RP's single-use challenge, so the next key can be tried. Each sign is `ssh-keygen -Y sign -n <namespace> -f <public-key> <challengefile>`, where `-f` names the **public** key whose private half the agent holds — so ssh-keygen signs through the agent and **the private key never enters wedge**. Challenge written to a `0600` temp file; namespace passed as an argv value (no shell). Any discovered key may be used for any site.
- **RP verifies:** `ssh-keygen -Y verify -f <allowed_signers> -I <principal> -n <namespace> -s <sigfile>` with the challenge on stdin. The RP must (a) confirm the `challenge` in the POST equals the one it issued for `request_id`, (b) verify against the user's **registered** public key for that principal — never trust the `public_key` field alone.

Because `namespace == the RP's canonical origin` (§4), a signature is bound to one origin and cannot be replayed against another RP.

---

## 7. Consent & automation

**Every sign requires a user-presence check — this is not negotiable and cannot be globally disabled.** A promptless authenticator can't prove the user actually intends a given sign (see §8), so wedge always requires a per-sign *presence* signal: ideally biometric (**Touch ID / Windows Hello**), falling back to a single **hardware-key-style touch / one-click confirm**. Presence is not a passphrase and not a form — it's ~1 second proving a human is here. It is the one signal that defeats the phishing vector in §8: a sign you didn't initiate simply doesn't get your tap.

**New site (gated add-on-first-use).** A sign request for an origin **not** in the sites list shows an origin-only prompt *before any network call* — nothing is fetched until the user adds it: **[Add & Allow once] / [Add & Always allow] / [Deny]**. Only http(s) origins are eligible (an `ssh://` or other scheme from a link is refused), so a link can't plant a launch target. Deny contacts nothing.

Per-origin, once a site is known each request offers three outcomes:

- **[Allow once]** — sign this one time; show the full confirm screen again next time.
- **[Always allow]** — persist `alwaysAllow: true` for this origin: subsequent requests **skip the detail screen but still require the presence tap**. This is the automation — no passphrase, nothing to read, just Touch ID. It is *not* silent signing. Enabled inline from this dialog, with plain copy: *"Skip this screen for acme.example — you'll still confirm with Touch ID each time."*
- **[Deny]** — refuse; RP flow expires.

**No global auto-sign toggle exists.** Always-allow is granted one origin at a time, from that origin's own first confirm.

**Advanced per-site opt-in — fully silent (no tap):** off by default, settable per origin only, behind an explicit *"this site can sign without me"* warning (`silent: true`). This is the escape hatch for a locked-down personal machine; it reopens the §8 risk for that one origin by the user's deliberate, informed choice — never the default, never global.

**Key handling — delegate to `ssh-agent` (decided).** wedge does not hold private key material; it signs through the user's running `ssh-agent` (private keys loaded via `ssh-add`, passphrase handled by the agent). So signing never re-prompts for a passphrase; the presence tap above is the only per-sign interaction. wedge does not store a configured key — it **auto-discovers `~/.ssh/*.pub`** and signs with whichever are loaded in the agent (§6, try-next); the settings UI lists each discovered key with a loaded/not-loaded badge so an unusable key is one `ssh-add` away.

**Sign log (detection).** wedge keeps a local, viewable log of every sign — timestamp, origin, the key that signed, and approval type (allow-once / always-allow-tap / silent) — surfaced in settings. No OS notifications (the presence tap already keeps the user in the loop). wedge **cannot revoke** the resulting session — that is the RP's responsibility ("sign out everywhere"); the log is for detection/audit, not recovery.

Surfacing the prompt when wedge's window may be closed: the OS foregrounds wedge when it handles the `wedge://` link (step 4), and wedge opens its consent window via `internal/browser` — so the prompt always appears. (nib/hespera have no need to raise their own window; this is wedge-specific.)

---

## 8. Security model

- **Origin is a lookup key, not a trust source.** Everything wedge *does* (discovery, challenge fetch, verify POST) is aimed at URLs derived from the user's configured origin, never the link. A link naming an unconfigured origin does nothing.
- **SSRF-closed:** discovery/challenge/verify URLs are all constrained same-origin to the configured origin.
- **Origin-bound signatures:** because `namespace == the canonical origin` and wedge refuses any namespace that isn't the origin, a signature harvested by one (even allowlisted-but-hostile) RP can't be replayed against a different one — which is also what makes signing every agent key in turn (try-next) safe.
- **Replay/expiry:** `challenge` and `request_id` are single-use and short-lived at the RP; the RP marks them used on verify.
- **Browser-binding:** the RP binds `request_id` to the browser that started the flow (a cookie set in step 2) and completes the login only for that browser (step 13). This closes the *steal/race* variant — an observer who learns a `request_id` for someone else's in-flight login cannot claim the resulting session.

### The phishing variant and why the presence tap closes it

The attack browser-binding does **not** stop: an attacker starts their *own* login at an RP, obtains their own `request_id`, then lures the victim's browser into opening `wedge://sign?origin=<that RP>&request_id=<attacker's>`. Because the attacker legitimately runs the entire RP side of the flow, every RP-issued secret is already theirs and the victim's browser-binding is theirs too — so no protocol-only measure distinguishes this from a real login. The **only** distinguishing signal is one that originates from the victim: a per-sign user action.

That is exactly why §7 makes a **user-presence tap mandatory on every sign, non-disableable globally**. A sign the victim didn't initiate produces a presence request the victim didn't expect — and they don't tap. This is the same reason FIDO/WebAuthn mandates a user-presence check on every assertion. With the tap required, the phishing variant is **closed**, not merely documented.

Residual, by deliberate user choice only: the **per-site advanced `silent: true` opt-in** (§7) removes the tap for one origin, reopening this exact variant for that origin. It is off by default, per-origin, and gated behind an explicit warning — an informed trade for a locked-down personal machine, not a shipping default.

**Decision on record:** mandatory per-sign presence (biometric/touch) is the default and cannot be turned off globally; "Always allow" skips only the *detail screen*, never the presence check; fully-silent is a per-site, explicitly-warned advanced opt-in. A local sign log (§7) provides after-the-fact detection.

---

## 9. Protocol-handler registration (install-time, per-OS)

- **Linux:** a `.desktop` file with `MimeType=x-scheme-handler/wedge;` registered via `xdg-mime default`.
- **macOS:** `CFBundleURLTypes` with `CFBundleURLSchemes = [wedge]` in `Info.plist`.
- **Windows:** `HKCU\Software\Classes\wedge` with `URL Protocol` and a `shell\open\command` pointing at the binary.

`wedge --version` / headless subcommands must run without triggering the handler path.

---

## 10. Config schema

A single `sites` list — the origin is the whole identity (namespace == origin), and any agent-loaded `~/.ssh` key may sign any site, so there is no per-site namespace, company, or key:

```jsonc
"sites": [
  { "origin": "https://acme.example",
    "alwaysAllow": false,   // skip the detail screen; presence tap still required
    "silent": false }       // advanced: skip the presence tap too (per-site, explicitly warned)
]
```

`alwaysAllow` and `silent` are independent: `alwaysAllow` drops the detail screen, `silent` drops the presence tap. Default both `false`. The old `keyPath` + `allowedOrigins` + `originScopes` schema is migrated to `sites` on load. New origins are added by **gated add-on-first-use**: an unknown origin shows an origin-only "new site" prompt (no network) with Add & Allow / Add & Always allow / Deny; wedge only contacts the RP after the user adds it. Discovery-supplied `challenge_url`/`verify_url` are cached (memory/short-TTL), not persisted.

---

## 11. Open items to close before implementation

1. ~~Confirm end-to-end against the demos repo~~ **Proven at runtime** against `~/repos/wedge-web` (2026-07-07): a full scripted flow — `/wedge/start` → `wedge://sign` handoff → discovery → challenge fetch → policy → consent tap → ssh-agent sign → `/wedge/verify` (`ssh-keygen -Y verify`) → `/wedge/status` `authenticated` — succeeded, and the browser-binding (wrong/absent cookie stays `pending`), single-use (replay → `expired`), and unconfigured-origin (rejected pre-network) guards all held. Verification kernel (`ssh-keygen -Y verify` + generated `allowed_signers`, challenge on stdin), challenge format (`[A-Za-z0-9_-]{16,256}`, byte-identical), namespace config, and cookie-session minting are **already present and reused unchanged**. Net-new on the RP is only the *choreography* layer: `.well-known/wedge.json`, a `request_id`-minting `challenge_url`, a JSON `verify_url` (request_id-keyed, no browser CSRF cookie), a `/wedge/status` poll, the request_id↔browser binding cookie, and the "Sign in with wedge" button. The demo's `ChallengeEntry` gains `request_id` + browser-nonce + status.
2. ~~Key handling~~ **Decided: delegate to `ssh-agent`** (§7) — private key never enters wedge.
3. ~~Confirm the verify path~~ **Confirmed:** `~/repos/wedge-web` verifies with `ssh-keygen -Y verify -f <allowed_signers> -I <username> -n <namespace> -s <sig>` (challenge on stdin), principal = **username** looked up server-side (local/local-admin/registry). This is why wedge's verify POST carries no username and the RP resolves the principal from `request_id` (§5).
4. ~~Always-allow phishing risk~~ **Resolved** (§7/§8): mandatory per-sign user-presence tap (biometric/touch), non-disableable globally; "Always allow" skips only the detail screen; fully-silent is a per-site explicitly-warned advanced opt-in; local sign log for detection.
