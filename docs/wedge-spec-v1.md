# The wedge Protocol — Specification

**Protocol version:** 1 · **Spec:** draft 2026-07-07 · **Status:** Draft

This document specifies the `wedge://` authentication protocol: a way for a
website (the Relying Party) to authenticate a user by an SSH-key signature
produced on the user's machine, without a browser extension and without the
website connecting to the user's machine. It is written for implementers — a
reader should be able to build a conforming Relying Party from this document
alone. The reference implementations are the `wedge` desktop app (Go) and
`wedge-web` (Python).

The words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
**MAY** are to be interpreted as in RFC 2119.

---

## 1. Actors and terminology

| Term | Meaning |
|------|---------|
| **User** | Owns one or more SSH keys, held by an `ssh-agent`. |
| **Authenticator** | The user's desktop app (e.g. wedge). Registered OS handler for the `wedge://` URI scheme. Signs challenges via the agent. Runs no listener reachable by websites. |
| **RP** (Relying Party) | The website the user signs in to. Serves the discovery document and the flow endpoints, and verifies signatures. |
| **origin** | An RP's web origin, `scheme://host[:port]`, https or http. The authenticator's security boundary: it is only ever a lookup key into the authenticator's own allowlist. |
| **namespace** | The SSH-signature namespace (`ssh-keygen -Y … -n`). Under this protocol it **is the RP's canonical origin** (§6.1). |
| **challenge** | Random one-time bytes the RP wants signed. |
| **request_id** | Opaque, single-use handle correlating one login attempt across the browser, the authenticator, and the RP. |

## 2. Protocol overview

Two flows share the same signing and verification core:

**Core flow (browser-initiated)** — the user is on the RP's login page:

```
Browser                        Authenticator                    RP backend
  │ 1. user clicks "Sign in with wedge"                             │
  │ 2. POST /wedge/start ────────────────────────────────────────▶ │  mints request_id + challenge,
  │ ◀─── request_id (+ browser-binding cookie); page polls ─────── │  binds request_id to THIS browser
  │ 3. open wedge://sign?v=1&origin=…&request_id=…                 │
  ▼ (OS launches/foregrounds the authenticator)                    │
        4. GET /.well-known/wedge.json  (discovery) ─────────────▶ │
        5. GET <challenge_url>?request_id=… ─────────────────────▶ │
        6. policy check + user presence consent                    │
        7. sign challenge via ssh-agent                            │
        8. POST <verify_url> {request_id, signature, …} ─────────▶ │  verify; mark authenticated
  │ 9. poll sees "authenticated" (same-browser cookie) ◀────────── │
  ▼ logged in                                                      │
```

**App-initiated extension (optional)** — the user starts from the
authenticator (no browser page yet):

```
Authenticator                                                  RP backend
  1. POST /wedge/app-start ──────────────────────────────────▶ │  mints request_id + challenge
  ◀── {request_id, challenge, namespace, claim_url} ────────── │  + single-use claim token
  2. consent + sign + POST <verify_url>  (as core §5) ────────▶ │  verify; mark authenticated
  3. open the default browser at claim_url ──────────────────▶ │  claim valid+unused → mint session
                                                    browser is logged in
```

The browser and the authenticator never talk to each other; they rendezvous
at the RP through `request_id`.

**Design invariant.** A `wedge://` link is fully attacker-controllable. The
authenticator treats `origin` only as a lookup key into its own configuration
and `request_id` as opaque. Every URL the authenticator contacts is derived
from a *user-configured* origin (directly, or via same-origin-validated
discovery), never from the link.

## 3. The `wedge://` URI (core flow)

```
wedge://sign?v=1&origin=<url-encoded origin>&request_id=<url-encoded id>
```

- `v` — integer protocol version. This document is `v=1`. Authenticators
  MUST reject unknown versions.
- `origin` — the RP origin. The authenticator MUST normalize it to
  `scheme://host[:port]` and MUST refuse (with no network activity) unless it
  is http(s) and matches the user's allowlist (§7).
- `request_id` — opaque; MUST match `^[A-Za-z0-9._-]{1,128}$`; echoed back to
  the RP verbatim.

The challenge is deliberately **not** in the link: the only value ever signed
is one fetched from the configured RP's own endpoint.

## 4. Discovery

```
GET <origin>/.well-known/wedge.json
→ 200 {
    "version": 1,
    "namespace": "<the RP's canonical origin>",
    "challenge_url": "<origin>/wedge/challenge",
    "verify_url": "<origin>/wedge/verify"
  }
```

RP requirements:
- `version` MUST be `1`; `namespace`, `challenge_url`, `verify_url` are REQUIRED.
- `namespace` MUST equal the RP's canonical origin (§6.1).
- `challenge_url` and `verify_url` MUST be same-origin with the document's origin.

Authenticator requirements:
- MUST build the discovery URL from the *configured* origin, never from a link.
- MUST reject a document whose version ≠ 1, whose namespace is empty, or whose
  endpoint URLs are not same-origin with the configured origin (SSRF guard).
- MUST ignore unknown fields (forward compatibility).
- MAY cache with a short TTL; SHOULD refetch after a verification failure.

## 5. Wire messages (signing core, both flows)

### 5.1 Challenge fetch (core flow)

```
GET <challenge_url>?request_id=<id>
→ 200 { "challenge": "<see §6.2>", "namespace": "<canonical origin>" }
→ 404 or 410 if request_id is unknown, used, or expired
```

`expires_at` (RFC 3339) MAY be included; authenticators do not enforce it —
expiry is the RP's job. Unknown fields MUST be ignored.

### 5.2 Verify

```
POST <verify_url>          Content-Type: application/json   (no cookies)
{ "request_id": "<id>",
  "challenge":  "<echoed challenge>",
  "namespace":  "<the namespace that was signed>",
  "signature":  "-----BEGIN SSH SIGNATURE-----\n…",
  "public_key": "ssh-ed25519 AAAA… comment"        // see below
}
→ 200 { "ok": true }
→ 4xx/5xx { "ok": false, "error": "<reason>" }
```

The RP MUST:
1. Look up the pending request by `request_id`; reject unknown/completed (404).
2. Verify the signature against the challenge **it stored** for that
   request_id — never the echoed `challenge` field.
3. Check `namespace` is equivalent (§6.1) to its canonical origin (400 on
   mismatch). Signature verification MUST then use the posted `namespace`
   string — it is the bytes the client signed, and under the §6.1 alias it
   may legitimately differ from the RP's own spelling.
4. Verify only against **registered** public keys. If the pending request
   carries a user identity, resolve that user's registered key(s). If it does
   not (keyless app-initiated start, §8), the posted `public_key` is used
   **only as a selector** to locate the registered account — like sshd
   scanning `authorized_keys` — and the signature is then verified strictly
   against the **stored** key, never the posted one.
5. On success: mark the request authenticated, consume the challenge
   (single-use), and return `{ "ok": true }`.

Error statuses observed by the reference RP: 400 (malformed/namespace
mismatch), 401 (signature verification failed / no account matches the key),
404 (unknown request), 429 (rate limited), 503 (verifier busy). Authenticators
MUST treat any non-2xx or `{"ok": false}` as failure and MAY try a different
key against the same request_id (a failed verify MUST NOT consume the
challenge or the request).

### 5.3 Signature format

Signatures are OpenSSH `SSHSIG` armored blocks, produced over the exact
challenge bytes:

```
ssh-keygen -Y sign -f <public-or-private-key> -n <namespace> <challenge-file>
```

and verified (reference kernel) with the challenge on stdin:

```
ssh-keygen -Y verify -f <allowed_signers> -I <principal> -n <namespace> -s <sig-file>
```

The `principal` and the first field of `allowed_signers` are an RP-internal
pairing that never appears on the wire: the RP uses the identifier under
which the key was registered (reference implementations: the account
username; in a keyless flow, the username of the account the `public_key`
selector matched) as both the `-I` value and the `allowed_signers` first
field.

The namespace binds a signature to one origin: a signature made for
`https://a.example` cannot be replayed at any other origin (§6.1).

### 5.4 Completion (core flow)

The RP binds `request_id` to the initiating browser at `/wedge/start` (an
HttpOnly, SameSite cookie carrying a random nonce is the reference mechanism)
and MUST mint the session only for a bearer of that binding:

```
GET <origin>/wedge/status?request_id=<id>       (browser, same-origin, with cookie)
→ { "status": "pending" | "authenticated" | "denied" | "expired" }
```

On `authenticated` with a valid binding, the RP mints its session, MUST
invalidate the request (single-use), and MAY include a `redirect` field. The
start/status endpoints are RP↔browser traffic; their exact shape is the RP's
choice — the binding and single-use requirements are not.

## 6. Data requirements

### 6.1 namespace == canonical origin

The SSH namespace an RP publishes (discovery, challenge, app-start) MUST be
its own canonical origin. Authenticators MUST refuse to sign when the
reported namespace, parsed as an origin, is not equivalent to the configured
origin the flow started from. Equivalence is exact string match after
normalization, plus the `localhost` ↔ `127.0.0.1` alias (same scheme/port).
Normalization reduces a URL to `scheme://host[:port]` — userinfo, path,
query, and fragment are dropped; nothing else changes (no default-port
elision, no case folding). Spellings that differ in an explicit default port
are therefore **not** equivalent: implementations SHOULD write origins
lowercase, with the port exactly as browsers reach the site. This is the
anti-replay property of the whole protocol: every signature is origin-bound.

### 6.2 Formats

| Value | Requirement |
|-------|-------------|
| challenge | `^[A-Za-z0-9_-]{16,256}$`, ≥128 bits of CSPRNG entropy, single-use, short TTL (reference: 180 s) |
| request_id | `^[A-Za-z0-9._-]{1,128}$`, unguessable, single-use |
| namespace | a canonical origin (§6.1) |
| claim token (§8) | ≥128 bits CSPRNG entropy, single-use |
| origin | `scheme://host[:port]`, scheme ∈ {http, https} |

## 7. Authenticator requirements

A conforming authenticator:

- MUST maintain a user-controlled origin allowlist and refuse any flow for an
  unlisted origin **before any network request** to it. It MAY offer to add an
  unlisted http(s) origin via an explicit, origin-only user consent (still no
  network before the user accepts).
- MUST require a per-signature **user presence action** by default. A
  per-origin, explicitly-warned opt-out MAY exist; a global one MUST NOT.
- MUST enforce §6.1 (namespace == origin) and §6.2 formats before signing.
- MUST sign through an agent or equivalent such that private key material is
  not read by the authenticator itself.
- MAY try multiple keys against one request (first accepted wins); this is
  safe because signatures are origin-bound.
- SHOULD keep a local, user-visible log of every signature produced.

## 8. App-initiated extension (optional)

An RP MAY additionally support login started from the authenticator. RPs that
do not implement this section are still conforming (Core).

### 8.1 Start

```
POST <origin>/wedge/app-start        Content-Type: application/json, body {}
→ 200 { "ok": true,
        "request_id": "<id>",
        "challenge":  "<§6.2>",
        "namespace":  "<canonical origin>",
        "claim_url":  "<origin>/wedge/claim?request_id=<id>&claim=<token>" }
→ 4xx { "ok": false, "error": "<reason>" }
```

- There is no browser yet, so there is no browser binding; a single-use
  **claim token** takes its place.
- The pending request carries no user identity; the account is resolved at
  verify time by the `public_key` selector rule (§5.2 item 4). RPs whose
  account model requires a pre-asserted username (e.g. directory-backed
  deployments) MUST reject app-start with an explanatory error.
- Authenticators MUST validate `claim_url` is same-origin with the configured
  origin before ever opening it (a hostile RP must not be able to hand the
  user's browser an arbitrary URL).

### 8.2 Sign and verify

Identical to §5.2–5.3, except `public_key` is REQUIRED (it is the account
selector).

### 8.3 Claim

After a successful verify, the authenticator opens the user's default browser
at `claim_url`:

```
GET <origin>/wedge/claim?request_id=<id>&claim=<token>
```

The RP MUST mint a session only when **all** hold: the request exists and is
`authenticated`; a claim token was issued and the request is unclaimed; the
presented token matches by **constant-time comparison**; the request is
within TTL. It MUST mark the claim used before minting (single-use) and
SHOULD immediately redirect away so the token does not remain in the address
bar. On any failure it MUST NOT mint a session (redirect to a login/error
page).

The token appears in a URL and can land in browser history and, on a
misconfigured RP, in outbound Referers. Single-use + short TTL bound the
exposure; RPs MUST NOT embed the claim URL in served page content and SHOULD
send `Referrer-Policy: no-referrer` on the claim response.

## 9. Versioning and extensibility

- The protocol version rides in the `wedge://` link (`v`) and the discovery
  document (`version`); the two MUST agree. Receivers MUST reject versions
  they do not implement, and MUST ignore unknown JSON fields.
- The app-start path is fixed at `<origin>/wedge/app-start` in v1. A future
  revision is expected to advertise it in the discovery document
  (`app_start_url`) instead; RPs SHOULD anticipate this by treating discovery
  fields as the eventual home of all endpoint URLs.

## 10. Security considerations

- **Origin is a lookup key, not a trust source.** Everything the
  authenticator contacts derives from user configuration plus same-origin
  validation. A link naming an unconfigured origin does nothing — not even a
  DNS lookup.
- **SSRF containment:** discovery/challenge/verify/claim URLs are all
  constrained same-origin with the configured origin.
- **Replay:** challenges and request_ids are single-use and short-lived;
  namespace==origin (§6.1) makes even a leaked signature worthless elsewhere.
- **Session theft:** core flow — the browser-binding cookie means knowing a
  request_id is not enough to collect the session; app flow — the claim token
  (single-use, constant-time-compared, TTL) plays that role.
- **Phishing (attacker-initiated flows):** an attacker who controls a
  legitimate RP interaction can lure a victim's browser into firing a
  `wedge://` link for the attacker's own request_id. No protocol message
  distinguishes this from a real login — only a signal originating from the
  victim can. That is why per-signature **user presence** (§7) is mandatory
  for authenticators, exactly as in FIDO/WebAuthn.
- **Key selection (keyless app flow):** the posted `public_key` is untrusted
  input; RPs verify only against stored, registered keys (§5.2 item 4).
- **Rate limiting:** RPs SHOULD rate-limit verify per source and per account
  and bound concurrent verifications.

## Appendix A — worked example

```sh
# 1. A user key (ed25519), held by ssh-agent
ssh-keygen -t ed25519 -N "" -C demo@example -f demo_key && ssh-add demo_key

# 2. RP mints a challenge (here: fixed for the example)
printf '%s' "AbCdEfGhIjKlMnOpQrStUvWx" > challenge.txt

# 3. Authenticator signs it, namespace = the RP's canonical origin
ssh-keygen -Y sign -f demo_key.pub -n "https://rp.example" challenge.txt
#   → challenge.txt.sig   ("-----BEGIN SSH SIGNATURE-----…")

# 4. RP verifies: registered key + principal + namespace, challenge on stdin
printf 'demo %s\n' "$(cut -d' ' -f1,2 demo_key.pub)" > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I demo -n "https://rp.example" \
  -s challenge.txt.sig < challenge.txt
# → Good "https://rp.example" signature for demo with ED25519 key SHA256:…
```

A signature made in step 3 verifies **only** with `-n "https://rp.example"` —
substituting any other namespace fails, which is the origin-binding property
in one command.

## Appendix B — reference implementations

- Authenticator: `wedge` (Go) — this repository.
- RP: `wedge-web` (Python, stdlib-only) — discovery, challenge/verify/status,
  app-start/claim, and the verification kernel (`ssh-keygen -Y verify`).
- RP middleware: `wedge-rp` (Python, `sdk/python/`; Node, `sdk/node/` — both
  in this repository) — pip-/npm-installable engines implementing every RP
  requirement of this spec, with Flask and Express adapters and matching
  conformance test suites (kept test-for-test in lockstep); built against
  this document as its implementability test.
