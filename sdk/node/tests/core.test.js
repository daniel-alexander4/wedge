// Spec-conformance tests for the WedgeRP engine.
//
// Test-for-test port of sdk/python/tests/test_core.py — each test names the
// wedge-spec-v1.md requirement it pins down. Signatures are real SSHSIG made
// by ssh-keygen, so these tests double as an executable reading of the spec's
// RP MUSTs. Keep the two suites in lockstep.

import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';
import { after, before, test } from 'node:test';

import { WedgeRP, normalizeOrigin } from '../lib/core.js';
import { sameKey } from '../lib/kernel.js';
import { HAVE_SSH_KEYGEN, KeyPair } from './helpers.js';

const ORIGIN = 'http://127.0.0.1:9412';
const skip = !HAVE_SSH_KEYGEN;

let alice;
let mallory;

before(() => {
  if (skip) return;
  alice = new KeyPair('alice@test');
  mallory = new KeyPair('mallory@test');
});
after(() => {
  alice?.close();
  mallory?.close();
});

function makeRP(overrides = {}) {
  const users = { alice: alice.publicKey };
  return new WedgeRP({
    origin: ORIGIN,
    findKeys: (username) => users[username] ?? null,
    findUserByPublicKey: (posted) => {
      const hit = Object.entries(users).find(([, key]) => sameKey(key, posted));
      return hit ?? null;
    },
    ...overrides,
  });
}

// Run start + challenge fetch; returns { rid, challenge, nonce }.
function startAndFetch(rp, username = null) {
  const started = rp.start(username);
  assert.equal(started.status, 200);
  const rid = started.body.request_id;
  const ch = rp.challenge(rid);
  assert.equal(ch.status, 200);
  return { rid, challenge: ch.body.challenge, nonce: started.browserNonce };
}

function verifyBody(rid, challenge, { key = null, namespace = ORIGIN, ...overrides } = {}) {
  const signer = key ?? alice;
  return {
    request_id: rid,
    challenge,
    namespace,
    signature: signer.sign(challenge, namespace),
    public_key: signer.publicKey,
    ...overrides,
  };
}

// -- discovery (§4) ----------------------------------------------------------

test('discovery document', { skip }, () => {
  const doc = makeRP().discovery();
  assert.equal(doc.version, 1);
  assert.equal(doc.namespace, ORIGIN); // namespace == canonical origin (§6.1)
  assert.equal(doc.challenge_url, `${ORIGIN}/wedge/challenge`);
  assert.equal(doc.verify_url, `${ORIGIN}/wedge/verify`);
});

// -- link (§3) ---------------------------------------------------------------

test('sign link format', { skip }, () => {
  const { body } = makeRP().start();
  assert.equal(
    body.link,
    `wedge://sign?v=1&origin=http%3A%2F%2F127.0.0.1%3A9412&request_id=${body.request_id}`,
  );
});

// -- start -------------------------------------------------------------------

test('keyless start needs selector callback', { skip }, () => {
  const rp = makeRP({ findUserByPublicKey: null });
  const { status, body, browserNonce } = rp.start();
  assert.equal(status, 400);
  assert.equal(browserNonce, null);
  assert.equal(body.ok, false);
});

test('username start needs findKeys', { skip }, () => {
  const rp = makeRP({ findKeys: null });
  assert.equal(rp.start('alice').status, 400);
});

// -- challenge (§5.1, §6.2) ----------------------------------------------------

test('challenge unknown request', { skip }, () => {
  assert.equal(makeRP().challenge('nope').status, 404);
});

test('challenge format and namespace', { skip }, () => {
  const rp = makeRP();
  const { challenge } = startAndFetch(rp);
  assert.match(challenge, /^[A-Za-z0-9_-]{16,256}$/);
  const again = rp.challenge(rp.start().body.request_id);
  assert.equal(again.body.namespace, ORIGIN);
});

test('challenge gone after authentication', { skip }, async () => {
  const rp = makeRP();
  const { rid, challenge } = startAndFetch(rp, 'alice');
  assert.equal((await rp.verify(verifyBody(rid, challenge))).status, 200);
  assert.equal(rp.challenge(rid).status, 404); // used → 404 (§5.1)
});

// -- verify (§5.2) --------------------------------------------------------------

test('verify happy path, username flow', { skip }, async () => {
  const rp = makeRP();
  const { rid, challenge } = startAndFetch(rp, 'alice');
  const res = await rp.verify(verifyBody(rid, challenge));
  assert.deepEqual(res, { status: 200, body: { ok: true } });
});

test('verify unknown request', { skip }, async () => {
  const rp = makeRP();
  const { challenge } = startAndFetch(rp);
  const res = await rp.verify(verifyBody('unknown-id', challenge));
  assert.equal(res.status, 404);
  assert.equal(res.body.ok, false);
});

test('verify checks stored challenge, not the echo', { skip }, async () => {
  // RP MUST verify against the challenge it stored, never the echoed field
  // (§5.2 item 2) — a wrong echo with a good signature still passes.
  const rp = makeRP();
  const { rid, challenge } = startAndFetch(rp, 'alice');
  const body = verifyBody(rid, challenge);
  body.challenge = 'Definitely_Not_The_Challenge';
  assert.equal((await rp.verify(body)).status, 200);
});

test('verify rejects signature over wrong challenge', { skip }, async () => {
  const rp = makeRP();
  const { rid } = startAndFetch(rp, 'alice');
  const body = verifyBody(rid, 'NotTheMintedChallenge123'); // signature over wrong bytes
  assert.equal((await rp.verify(body)).status, 401);
});

test('verify namespace mismatch', { skip }, async () => {
  const rp = makeRP();
  const { rid, challenge } = startAndFetch(rp, 'alice');
  const res = await rp.verify(verifyBody(rid, challenge, { namespace: 'http://evil.example' }));
  assert.equal(res.status, 400);
  assert.deepEqual(res.body, { ok: false, error: 'namespace mismatch' });
});

test('verify accepts localhost alias namespace', { skip }, async () => {
  // localhost ↔ 127.0.0.1 with same scheme/port are equivalent (§6.1);
  // -n must get the alias string the authenticator actually signed.
  const rp = makeRP();
  const { rid, challenge } = startAndFetch(rp, 'alice');
  const body = verifyBody(rid, challenge, { namespace: 'http://localhost:9412' });
  assert.equal((await rp.verify(body)).status, 200);
});

test('failed verify consumes nothing', { skip }, async () => {
  // A failed verify MUST NOT consume the challenge or request (§5.2) — the
  // authenticator's try-next-key depends on it.
  const rp = makeRP();
  const { rid, challenge } = startAndFetch(rp, 'alice');
  assert.equal((await rp.verify(verifyBody(rid, challenge, { key: mallory }))).status, 401);
  assert.equal((await rp.verify(verifyBody(rid, challenge))).status, 200);
});

test('request single-use at verify', { skip }, async () => {
  const rp = makeRP();
  const { rid, challenge } = startAndFetch(rp, 'alice');
  const good = verifyBody(rid, challenge);
  assert.equal((await rp.verify(good)).status, 200);
  assert.equal((await rp.verify(good)).status, 404); // replay of the same verify
});

test('keyless verify requires public_key', { skip }, async () => {
  // public_key is REQUIRED when the pending request carries no username
  // (§8.2) — it is the account selector.
  const rp = makeRP();
  const { rid, challenge } = startAndFetch(rp);
  const body = verifyBody(rid, challenge);
  delete body.public_key;
  const res = await rp.verify(body);
  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'public_key required');
});

test('posted key is selector only', { skip }, async () => {
  // Posting alice's public key with mallory's signature MUST fail:
  // verification runs against the stored key, never the posted one (§5.2).
  const rp = makeRP();
  const { rid, challenge } = startAndFetch(rp);
  const body = verifyBody(rid, challenge, { key: mallory, public_key: alice.publicKey });
  assert.equal((await rp.verify(body)).status, 401);
});

test('unregistered key: no account', { skip }, async () => {
  const rp = makeRP();
  const { rid, challenge } = startAndFetch(rp);
  const res = await rp.verify(verifyBody(rid, challenge, { key: mallory }));
  assert.equal(res.status, 401);
  assert.equal(res.body.error, 'no account matches key');
});

test('verify rate limited per source', { skip }, async () => {
  const rp = makeRP({ verifyRateLimit: [2, 60] });
  const { rid, challenge } = startAndFetch(rp, 'alice');
  const bad = verifyBody(rid, challenge, { key: mallory });
  assert.equal((await rp.verify(bad, { source: '10.0.0.1' })).status, 401);
  assert.equal((await rp.verify(bad, { source: '10.0.0.1' })).status, 401);
  assert.equal((await rp.verify(bad, { source: '10.0.0.1' })).status, 429);
  // a different source is not affected
  assert.equal((await rp.verify(bad, { source: '10.0.0.2' })).status, 401);
});

// -- status + browser binding (§5.4) --------------------------------------------

test('status requires browser binding', { skip }, async () => {
  // Only the initiating browser (nonce bearer) can convert an authenticated
  // request into a session; everyone else sees pending.
  const rp = makeRP();
  const { rid, challenge, nonce } = startAndFetch(rp, 'alice');
  await rp.verify(verifyBody(rid, challenge));
  assert.deepEqual(rp.status(rid, null), { body: { status: 'pending' }, username: null });
  assert.deepEqual(rp.status(rid, 'wrong-nonce'), { body: { status: 'pending' }, username: null });
  assert.deepEqual(rp.status(rid, nonce), { body: { status: 'authenticated' }, username: 'alice' });
});

test('status is single-use', { skip }, async () => {
  const rp = makeRP();
  const { rid, challenge, nonce } = startAndFetch(rp, 'alice');
  await rp.verify(verifyBody(rid, challenge));
  assert.equal(rp.status(rid, nonce).username, 'alice');
  assert.deepEqual(rp.status(rid, nonce), { body: { status: 'expired' }, username: null });
});

test('status pending before verify, expired when unknown', { skip }, () => {
  const rp = makeRP();
  const { rid, nonce } = startAndFetch(rp, 'alice');
  assert.deepEqual(rp.status(rid, nonce), { body: { status: 'pending' }, username: null });
  assert.deepEqual(rp.status('unknown', nonce), { body: { status: 'expired' }, username: null });
});

test('ttl expiry', { skip }, async () => {
  const rp = makeRP({ challengeTtl: 0.05 });
  const { rid, challenge, nonce } = startAndFetch(rp, 'alice');
  await sleep(100);
  assert.equal(rp.challenge(rid).status, 404);
  assert.equal((await rp.verify(verifyBody(rid, challenge))).status, 404);
  assert.deepEqual(rp.status(rid, nonce), { body: { status: 'expired' }, username: null });
});

// -- app-initiated flow (§8) -------------------------------------------------------

async function appStartAndVerify(rp) {
  const started = rp.appStart();
  assert.equal(started.status, 200);
  const body = verifyBody(started.body.request_id, started.body.challenge);
  assert.equal((await rp.verify(body)).status, 200);
  return started.body;
}

test('app-start response shape', { skip }, () => {
  const { status, body } = makeRP().appStart();
  assert.equal(status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.namespace, ORIGIN);
  assert.ok(body.claim_url.startsWith(`${ORIGIN}/wedge/claim?`));
  assert.ok(body.claim_url.includes(body.request_id));
});

test('app-start rejected without selector', { skip }, () => {
  // RPs that need a pre-asserted username MUST reject app-start with an
  // explanatory error (§8.1); Core-only remains conforming (§8).
  const rp = makeRP({ findUserByPublicKey: null });
  const { status, body } = rp.appStart();
  assert.equal(status, 404);
  assert.equal(body.ok, false);
  assert.ok(body.error.includes('not supported'));
});

test('claim happy path, single-use', { skip }, async () => {
  const rp = makeRP();
  const body = await appStartAndVerify(rp);
  const token = body.claim_url.split('claim=')[1];
  assert.equal(rp.claim(body.request_id, token), 'alice');
  assert.equal(rp.claim(body.request_id, token), null); // single-use (§8.3)
});

test('claim rejects wrong token and unauthenticated', { skip }, async () => {
  const rp = makeRP();
  const started = rp.appStart().body;
  const token = started.claim_url.split('claim=')[1];
  assert.equal(rp.claim(started.request_id, token), null); // not yet authenticated
  const done = await appStartAndVerify(rp);
  assert.equal(rp.claim(done.request_id, 'wrong-token'), null);
  const real = done.claim_url.split('claim=')[1];
  assert.equal(rp.claim(done.request_id, real), 'alice');
});

test('app request not pollable via status', { skip }, async () => {
  // App-initiated requests have no browser binding; polling must never mint
  // (§8: the claim token is the substitute for the binding).
  const rp = makeRP();
  const body = await appStartAndVerify(rp);
  assert.deepEqual(rp.status(body.request_id, 'anything'), {
    body: { status: 'pending' },
    username: null,
  });
});

// -- construction -------------------------------------------------------------------

test('requires a lookup callback', () => {
  assert.throws(() => new WedgeRP({ origin: ORIGIN }));
});

test('rejects non-origin', () => {
  assert.throws(() => new WedgeRP({ origin: 'ftp://x', findKeys: () => null }));
  assert.throws(() => new WedgeRP({ origin: 'not a url', findKeys: () => null }));
});

// -- Node-specific additions ----------------------------------------------------

test('normalizeOrigin preserves explicit default ports (spec §6.1: no elision)', () => {
  assert.equal(normalizeOrigin('http://example.com:80'), 'http://example.com:80');
  assert.equal(normalizeOrigin('https://example.com:443/'), 'https://example.com:443');
  assert.equal(normalizeOrigin('http://Example.com:8080/path'), 'http://example.com:8080');
  assert.equal(normalizeOrigin('http://example.com'), 'http://example.com');
});

test('async account callbacks are awaited', { skip }, async () => {
  const rp = makeRP({
    findKeys: async (username) => (username === 'alice' ? alice.publicKey : null),
  });
  const { rid, challenge } = startAndFetch(rp, 'alice');
  assert.equal((await rp.verify(verifyBody(rid, challenge))).status, 200);
});
