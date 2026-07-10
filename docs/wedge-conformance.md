# wedge conformance harness

`wedge-conform` is a black-box conformance tester for **relying-party (RP)**
implementations of the wedge protocol. It plays the **authenticator** role —
fetching discovery, signing challenges with its own throwaway SSH key over
real HTTP, replaying, and sending malformed input — and asserts every
**wire-observable** RP requirement of [`wedge-spec-v1.md`](wedge-spec-v1.md).
It is the mechanical verifier for the four `wedge-rp` middleware ports and for
any third-party RP wedge never wrote.

It does **not** replace the per-language conformance suites under `sdk/*/`
(which test each engine from the inside); it is the cross-implementation,
over-the-wire check that a running RP actually behaves.

## Running

```
go run ./cmd/wedge-conform --target http://127.0.0.1:9413 --key ./conform_ed25519 --user conform
```

- `--target` (required) — the RP's canonical origin.
- `--key` — a private key file (its `.pub` beside it) **registered with the
  RP**. Omit it and the harness generates a throwaway keypair, prints the
  public key, and waits for you to register it.
- `--user` — the username the key is registered under; enables the
  username-carrying start flow. Omit for keyless-only RPs.
- `--start-cmd` — a shell command printing a `request_id` or a `wedge://` link,
  for RPs whose browser-facing start endpoint doesn't match the reference
  shape (see below). Binding checks (S2/S3) report SKIP without it.
- `--probe-limits` — also probe the rate-limit and concurrency SHOULDs (§10).
  Off by default because it deliberately floods the verify endpoint.
- `--json` — machine-readable report.

Exit status is `0` only when every wire-observable MUST passes.

## The bootstrap contract

The harness needs one account whose registered public key it holds. Every
`wedge-rp` demo seeds exactly this: **one public key per username at process
start**, via `--user NAME:PUBKEY_PATH` (Python/Node/Go) or
`WEDGE_DEMO_USERS=name:path` (PHP). A conforming target only needs to offer
some equivalent way to register the harness's key before the run.

## Reference start shape vs. custom RPs

The spec (§5.4) deliberately leaves the **browser-facing** `/wedge/start` and
`/wedge/status` endpoint shapes to the RP — only the browser *binding* and
single-use *effects* are normative. So the harness drives them in the
**reference shape** spoken by `wedge.js` and every `wedge-rp` SDK (a
`POST /wedge/start` returning `{request_id}` and setting a binding cookie,
polled at `GET /wedge/status`). Against an RP with a different start shape,
pass `--start-cmd`; the binding checks (S2/S3) then report SKIP rather than
false-fail, because their mechanism isn't observable without knowing the shape.

## What is *not* black-box-testable

Some RP MUSTs cannot be asserted by an external client. The harness prints
these with every report so they're reviewed by hand, never silently passed:

- **§6.2 entropy** — challenge/request_id/claim-token CSPRNG quality is
  internal; only gross defects (collisions, obvious patterns) are visible.
- **§8.3 constant-time claim-token comparison** — a timing side-channel;
  functionally invisible to a client.
- **§8.3 claim URL never embedded in served content** — needs exhaustive
  inspection of everything the RP serves.
- **§4 `registration_url` is a real registration page** — a semantic/UX
  property.
- **§5.4 the binding *mechanism*** (HttpOnly SameSite cookie) — only its
  gating effect is asserted (S2/S3).

## Note on rate limiting

A single default run makes well under the reference engine's 30-verifies-per-
minute-per-source limit, so it never false-fails on the limiter. But
`--probe-limits` deliberately exhausts that budget, and all loopback requests
share source `127.0.0.1`, so a normal run started within ~60s of a probe run
(or of another run) can hit spurious `429`s. Space runs out, or restart the
target between them.

## Session-minted heuristic

Both reference claim outcomes (success and failure) are HTTP redirects, so the
harness distinguishes them by whether the response sets a session cookie
(`Set-Cookie`). An RP that mints sessions by some other means than a cookie
would need its claim checks (A5a/A5b/A7) adapted.
