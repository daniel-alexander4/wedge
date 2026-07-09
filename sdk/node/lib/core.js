// Framework-neutral wedge relying-party engine.
//
// WedgeRP implements every RP-side requirement of the wedge protocol v1
// (docs/wedge-spec-v1.md) as plain-data handlers — objects in, objects out. An
// adapter (wedge-rp/express, or ~60 lines of your own routing; see
// examples/http-demo.mjs) translates HTTP to these calls; nothing in this
// module imports a web framework.
//
// The host application supplies what the spec deliberately leaves out of
// scope: how accounts and their registered public keys are stored (the
// findKeys / findUserByPublicKey callbacks) and how a session is minted
// (adapters take a login callback).
//
// Port of sdk/python/wedge_rp/core.py — keep semantics in lockstep, and keep
// origin normalization/equivalence consistent with wedge's internal/policy
// (a security boundary).

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import { PRINCIPAL_RE, SSHKeygenUnavailable, splitPublicKey, verifySignature } from './kernel.js';
import { MemoryStore } from './store.js';

// /.well-known/wedge.json and /wedge/app-start are fixed by the spec (§4, §9);
// the rest are this package's defaults — challenge/verify are published via
// discovery, start/status/claim are wired to the matching wedge.js.
export const DISCOVERY_PATH = '/.well-known/wedge.json';
export const START_PATH = '/wedge/start';
export const CHALLENGE_PATH = '/wedge/challenge';
export const VERIFY_PATH = '/wedge/verify';
export const STATUS_PATH = '/wedge/status';
export const APP_START_PATH = '/wedge/app-start';
export const CLAIM_PATH = '/wedge/claim';
export const SCRIPT_PATH = '/wedge/wedge.js';

export const BINDING_COOKIE = 'wedge_flow';

// Must stay byte-identical to the authenticator's validation (spec §6.2 and
// wedge's internal/policy) — these are a security boundary.
export const CHALLENGE_RE = /^[A-Za-z0-9_-]{16,256}$/;
export const REQUEST_ID_RE = /^[A-Za-z0-9._-]{1,128}$/;

export const DEFAULT_CHALLENGE_TTL = 180; // seconds

// secrets.token_urlsafe equivalent: n random bytes, base64url, no padding.
function token(bytes) {
  return randomBytes(bytes).toString('base64url');
}

// Constant-time string equality: hash both sides to fixed length first so
// timingSafeEqual never throws on length mismatch (and length isn't leaked).
function constantTimeEqual(a, b) {
  const ha = createHash('sha256').update(String(a)).digest();
  const hb = createHash('sha256').update(String(b)).digest();
  return timingSafeEqual(ha, hb);
}

// Normalize to `scheme://host[:port]` (mirrors wedge's policy.NormalizeOrigin
// and the Python port: no default-port elision, no path). Throws for anything
// that isn't a plain http(s) origin. `new URL()` elides scheme-default ports,
// so an explicit :80/:443 is recovered from the raw authority — the spec's
// normalization keeps ports exactly as written.
export function normalizeOrigin(value) {
  const raw = String(value ?? '').trim();
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`not an http(s) origin: ${raw}`);
  }
  if ((url.protocol !== 'http:' && url.protocol !== 'https:') || !url.hostname) {
    throw new Error(`not an http(s) origin: ${raw}`);
  }
  let host = url.hostname; // lowercased; IPv6 comes back without brackets
  if (host.includes(':')) host = `[${host}]`;
  let port = url.port;
  if (port === '') {
    const explicit = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*?:(\d+)(?=[/?#]|$)/i.exec(raw);
    if (explicit) port = explicit[1];
  }
  return `${url.protocol}//${host}${port ? `:${port}` : ''}`;
}

// The origin plus its localhost↔127.0.0.1 alias with the same scheme and port
// (spec §6.1; mirrors wedge's policy.EquivalentOrigins).
export function equivalentOrigins(origin) {
  const origins = [origin];
  const url = new URL(origin);
  const alias = { localhost: '127.0.0.1', '127.0.0.1': 'localhost' }[url.hostname];
  if (alias) {
    const port = origin.match(/:(\d+)$/)?.[1];
    origins.push(`${url.protocol}//${alias}${port ? `:${port}` : ''}`);
  }
  return origins;
}

// Per-key sliding-window rate limiter (best-effort, per-process).
class SlidingWindow {
  #events = new Map();

  constructor(limit, windowSeconds) {
    this.limit = limit;
    this.windowMs = windowSeconds * 1000;
  }

  allow(key) {
    const now = Date.now();
    let events = this.#events.get(key);
    if (!events) this.#events.set(key, (events = []));
    while (events.length && events[0] <= now - this.windowMs) events.shift();
    if (events.length >= this.limit) return false;
    events.push(now);
    return true;
  }
}

// One instance per site.
//
// Options:
//   origin        — REQUIRED. The site's canonical origin exactly as browsers
//                   reach it (https://example.com, http://127.0.0.1:8080).
//                   Under namespace==origin this string IS the signature
//                   namespace, so it must be configured explicitly — never
//                   derived from a Host header an attacker can influence.
//   findKeys      — username => key line | array of key lines | null. The
//                   registered public key(s) for an account. Enables
//                   username-carrying sign-in. May be async.
//   findUserByPublicKey — key line => [username, keys] | null. Locate the
//                   account that registered a key (compare with sameKey();
//                   type+data, comments ignored). Enables keyless sign-in and
//                   the app-initiated flow. The posted key is only ever a
//                   selector: verification runs strictly against the stored
//                   keys you return (spec §5.2). May be async.
//   store         — MemoryStore (default) or SqliteStore / your own. Multi-
//                   process servers need a shared store.
//   challengeTtl  — seconds, default 180.
//   verifyTimeout — ms per ssh-keygen run, default 10000.
//   maxConcurrentVerifies — default 4.
//   verifyRateLimit — [attempts, windowSeconds] per source, default [30, 60];
//                   null disables.
//   registrationUrl — the site's key-registration page, advertised in
//                   discovery (spec §4) so authenticators can send a user
//                   whose key isn't registered yet straight there. Must be
//                   same-origin with origin.
export class WedgeRP {
  #findKeys;
  #findUserByPublicKey;
  #store;
  #verifyTimeout;
  #verifySlots;
  #rate;

  constructor({
    origin,
    findKeys = null,
    findUserByPublicKey = null,
    store = null,
    challengeTtl = DEFAULT_CHALLENGE_TTL,
    verifyTimeout = 10000,
    maxConcurrentVerifies = 4,
    verifyRateLimit = [30, 60],
    registrationUrl = null,
  }) {
    if (!findKeys && !findUserByPublicKey) {
      throw new Error('supply findKeys and/or findUserByPublicKey');
    }
    this.origin = normalizeOrigin(origin);
    if (registrationUrl !== null
        && registrationUrl !== this.origin
        && !registrationUrl.startsWith(this.origin + '/')) {
      throw new Error('registrationUrl must be same-origin with origin');
    }
    this.registrationUrl = registrationUrl;
    this.challengeTtl = Number(challengeTtl);
    this.#findKeys = findKeys;
    this.#findUserByPublicKey = findUserByPublicKey;
    this.#store = store ?? new MemoryStore();
    this.#verifyTimeout = Number(verifyTimeout);
    this.#verifySlots = maxConcurrentVerifies;
    this.#rate = verifyRateLimit ? new SlidingWindow(...verifyRateLimit) : null;
  }

  // -- helpers ---------------------------------------------------------------

  // Whether the configured origin is https (adapters use this for the binding
  // cookie's Secure attribute).
  get usesHttps() {
    return this.origin.startsWith('https://');
  }

  // Whether an Origin/Referer header value matches this site (alias-aware).
  // Adapters should reject browser-facing POSTs that fail this.
  isSameOrigin(value) {
    if (!value) return false;
    let candidate;
    try {
      candidate = normalizeOrigin(value);
    } catch {
      return false;
    }
    return equivalentOrigins(this.origin).includes(candidate);
  }

  // The wedge:// link the browser opens for this request (spec §3).
  signLink(requestId) {
    return `wedge://sign?v=1&origin=${encodeURIComponent(this.origin)}&request_id=${encodeURIComponent(requestId)}`;
  }

  #mint({ username, browserNonce, claimToken }) {
    const record = {
      requestId: token(18),
      challenge: token(24),
      namespace: this.origin,
      username,
      browserNonce,
      claimToken,
      status: 'pending',
      authenticatedUsername: null,
      expiresAt: Date.now() + this.challengeTtl * 1000,
    };
    this.#store.put(record);
    return record;
  }

  #live(requestId) {
    if (typeof requestId !== 'string' || !REQUEST_ID_RE.test(requestId)) return null;
    return this.#store.get(requestId);
  }

  // -- endpoint handlers -------------------------------------------------------

  // GET /.well-known/wedge.json (spec §4).
  discovery() {
    const body = {
      version: 1,
      namespace: this.origin,
      challenge_url: this.origin + CHALLENGE_PATH,
      verify_url: this.origin + VERIFY_PATH,
    };
    if (this.registrationUrl !== null) body.registration_url = this.registrationUrl;
    return body;
  }

  // POST /wedge/start (browser-facing; shape is the RP's choice, spec §5.4).
  // Returns { status, body, browserNonce }; the adapter must set browserNonce
  // as an HttpOnly cookie — it is the browser binding that later gates
  // session minting.
  start(username = null) {
    if (username !== null && username !== undefined) {
      if (typeof username !== 'string' || !PRINCIPAL_RE.test(username)) {
        return { status: 400, body: { ok: false, error: 'invalid username' }, browserNonce: null };
      }
      if (!this.#findKeys) {
        return { status: 400, body: { ok: false, error: 'username sign-in is not supported' }, browserNonce: null };
      }
    } else if (!this.#findUserByPublicKey) {
      return { status: 400, body: { ok: false, error: 'username required' }, browserNonce: null };
    }
    const browserNonce = token(24);
    const record = this.#mint({ username: username ?? null, browserNonce, claimToken: null });
    return {
      status: 200,
      body: { ok: true, request_id: record.requestId, link: this.signLink(record.requestId) },
      browserNonce,
    };
  }

  // GET <challenge_url>?request_id=… (spec §5.1).
  challenge(requestId) {
    const record = this.#live(requestId);
    if (!record || record.status !== 'pending') {
      return { status: 404, body: { ok: false, error: 'unknown request' } };
    }
    return { status: 200, body: { challenge: record.challenge, namespace: record.namespace } };
  }

  // POST /wedge/app-start (spec §8.1; path fixed in v1). Rejected with an
  // explanatory error when the host has no keyless account lookup — the RP is
  // then a conforming Core-only implementation (spec §8).
  appStart() {
    if (!this.#findUserByPublicKey) {
      return { status: 404, body: { ok: false, error: 'app-initiated sign-in is not supported by this site' } };
    }
    const claimToken = token(24);
    const record = this.#mint({ username: null, browserNonce: null, claimToken });
    const claimUrl = `${this.origin}${CLAIM_PATH}?request_id=${encodeURIComponent(record.requestId)}&claim=${encodeURIComponent(claimToken)}`;
    return {
      status: 200,
      body: {
        ok: true,
        request_id: record.requestId,
        challenge: record.challenge,
        namespace: record.namespace,
        claim_url: claimUrl,
      },
    };
  }

  // POST <verify_url> (spec §5.2; cookieless JSON from the authenticator).
  //
  // Verifies against the *stored* challenge and the account's *registered*
  // keys — the echoed `challenge` field is ignored and a posted `public_key`
  // is only an account selector. A failed verify consumes nothing, so the
  // authenticator may retry with its next key.
  async verify(body, { source = null } = {}) {
    if (typeof body !== 'object' || body === null || Array.isArray(body)) {
      return { status: 400, body: { ok: false, error: 'malformed request body' } };
    }
    const record = this.#live(body.request_id ?? '');
    if (!record || record.status !== 'pending') {
      return { status: 404, body: { ok: false, error: 'unknown request' } };
    }

    const namespace = body.namespace;
    if (typeof namespace !== 'string' || !this.isSameOrigin(namespace)) {
      return { status: 400, body: { ok: false, error: 'namespace mismatch' } };
    }
    const signature = body.signature;
    if (typeof signature !== 'string' || !signature.trimStart().startsWith('-----BEGIN SSH SIGNATURE-----')) {
      return { status: 400, body: { ok: false, error: 'malformed signature' } };
    }

    if (this.#rate && source && !this.#rate.allow(source)) {
      return { status: 429, body: { ok: false, error: 'rate limited' } };
    }

    const candidates = await this.#resolveCandidates(record, body.public_key);
    if (!Array.isArray(candidates)) return candidates; // error short-circuit

    if (this.#verifySlots <= 0) {
      return { status: 503, body: { ok: false, error: 'verifier busy' } };
    }
    this.#verifySlots -= 1;
    try {
      for (const [username, storedKey] of candidates) {
        // -n gets the namespace string the authenticator actually signed (it
        // echoes what we minted; alias variants of our origin are equivalent
        // by §6.1 but the bytes must match).
        const { ok } = await verifySignature(record.challenge, signature, {
          principal: username,
          publicKey: storedKey,
          namespace,
          timeout: this.#verifyTimeout,
        });
        if (ok) {
          if (!this.#store.setAuthenticated(record.requestId, username)) {
            return { status: 404, body: { ok: false, error: 'unknown request' } };
          }
          return { status: 200, body: { ok: true } };
        }
      }
    } catch (err) {
      if (err instanceof SSHKeygenUnavailable) {
        return { status: 503, body: { ok: false, error: err.message } };
      }
      throw err;
    } finally {
      this.#verifySlots += 1;
    }
    return { status: 401, body: { ok: false, error: 'signature verification failed' } };
  }

  // The [username, registeredKey] pairs to verify against, or an
  // { status, body } error.
  async #resolveCandidates(record, postedKey) {
    if (record.username !== null && record.username !== undefined) {
      let keys = await this.#findKeys(record.username);
      if (typeof keys === 'string') keys = [keys];
      if (!keys || keys.length === 0) {
        return { status: 401, body: { ok: false, error: 'no account matches', code: 'unknown_key' } };
      }
      return keys.map((key) => [record.username, key]);
    }
    // Keyless: the posted public key is REQUIRED (spec §8.2) and is only a
    // selector — verification runs against the stored keys.
    if (typeof postedKey !== 'string' || splitPublicKey(postedKey) === null) {
      return { status: 400, body: { ok: false, error: 'public_key required' } };
    }
    const match = await this.#findUserByPublicKey(postedKey);
    if (!match) {
      // The spec's unknown_key code (§5.2): the authenticator uses it to
      // steer the user to registration_url once every key has been tried.
      return { status: 401, body: { ok: false, error: 'no account matches key', code: 'unknown_key' } };
    }
    const [username, stored] = match;
    if (!PRINCIPAL_RE.test(username ?? '')) {
      return { status: 401, body: { ok: false, error: 'no account matches key', code: 'unknown_key' } };
    }
    const storedKeys = typeof stored === 'string' ? [stored] : Array.from(stored);
    return storedKeys.map((key) => [username, key]);
  }

  // GET /wedge/status?request_id=… (browser-facing, spec §5.4). Returns
  // { body, username }. A non-null username means the browser binding checked
  // out and the request was atomically consumed — the adapter must mint the
  // host session NOW (this is the only moment it can).
  status(requestId, browserNonce) {
    const record = this.#live(requestId);
    if (!record) return { body: { status: 'expired' }, username: null };
    if (record.browserNonce === null) {
      // App-initiated requests complete via /wedge/claim, never polling.
      return { body: { status: 'pending' }, username: null };
    }
    if (!browserNonce || !constantTimeEqual(browserNonce, record.browserNonce)) {
      return { body: { status: 'pending' }, username: null };
    }
    if (record.status !== 'authenticated') {
      return { body: { status: record.status }, username: null };
    }
    const taken = this.#store.takeAuthenticated(record.requestId);
    if (!taken || !taken.authenticatedUsername) {
      return { body: { status: 'pending' }, username: null };
    }
    return { body: { status: 'authenticated' }, username: taken.authenticatedUsername };
  }

  // GET /wedge/claim?request_id=…&claim=… (spec §8.3). Returns the username to
  // mint a session for, or null (adapter redirects to a login or error page —
  // never minting). The record is removed (= the claim is marked used)
  // *before* the username is returned.
  claim(requestId, claimToken) {
    const record = this.#live(requestId);
    if (
      !record
      || record.claimToken === null
      || record.status !== 'authenticated'
      || typeof claimToken !== 'string'
      || claimToken === ''
      || !constantTimeEqual(claimToken, record.claimToken)
    ) {
      return null;
    }
    const taken = this.#store.takeAuthenticated(record.requestId);
    return taken ? taken.authenticatedUsername : null;
  }
}
