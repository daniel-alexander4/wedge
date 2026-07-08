import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { SSHKeygenUnavailable, sameKey, splitPublicKey, verifySignature } from '../lib/kernel.js';
import { HAVE_SSH_KEYGEN, KeyPair } from './helpers.js';

const NAMESPACE = 'http://127.0.0.1:9412';
const CHALLENGE = 'AbCdEfGhIjKlMnOpQrStUvWx';

let key;
let other;
let sig;

before(() => {
  if (!HAVE_SSH_KEYGEN) return;
  key = new KeyPair();
  other = new KeyPair();
  sig = key.sign(CHALLENGE, NAMESPACE);
});
after(() => {
  key?.close();
  other?.close();
});

function verify(overrides = {}) {
  const params = {
    challenge: CHALLENGE,
    signature: sig,
    principal: 'alice',
    publicKey: key.publicKey,
    namespace: NAMESPACE,
    ...overrides,
  };
  const { challenge, signature, ...rest } = params;
  return verifySignature(challenge, signature, rest);
}

test('good signature verifies', { skip: !HAVE_SSH_KEYGEN }, async () => {
  const { ok, detail } = await verify();
  assert.equal(ok, true, detail);
});

test('wrong namespace rejected', { skip: !HAVE_SSH_KEYGEN }, async () => {
  assert.equal((await verify({ namespace: 'http://evil.example' })).ok, false);
});

test('wrong challenge rejected', { skip: !HAVE_SSH_KEYGEN }, async () => {
  assert.equal((await verify({ challenge: 'NotWhatWasSigned123' })).ok, false);
});

test('wrong key rejected', { skip: !HAVE_SSH_KEYGEN }, async () => {
  assert.equal((await verify({ publicKey: other.publicKey })).ok, false);
});

test('garbage signature rejected', { skip: !HAVE_SSH_KEYGEN }, async () => {
  const garbage = '-----BEGIN SSH SIGNATURE-----\ngarbage\n-----END SSH SIGNATURE-----';
  assert.equal((await verify({ signature: garbage })).ok, false);
});

test('unarmored signature rejected without spawning', { skip: !HAVE_SSH_KEYGEN }, async () => {
  const res = await verify({ signature: 'AAAA-not-armored' });
  assert.deepEqual(res, { ok: false, detail: 'malformed signature' });
});

test('key comment ignored', { skip: !HAVE_SSH_KEYGEN }, async () => {
  const [keytype, keydata] = key.publicKey.split(/\s+/);
  assert.equal((await verify({ publicKey: `${keytype} ${keydata} another@host` })).ok, true);
});

test('invalid principal rejected', { skip: !HAVE_SSH_KEYGEN }, async () => {
  const res = await verify({ principal: 'has space' });
  assert.deepEqual(res, { ok: false, detail: 'invalid principal' });
});

test('missing ssh-keygen raises SSHKeygenUnavailable', { skip: !HAVE_SSH_KEYGEN }, async () => {
  const savedPath = process.env.PATH;
  process.env.PATH = '/nonexistent';
  try {
    await assert.rejects(verify(), SSHKeygenUnavailable);
  } finally {
    process.env.PATH = savedPath;
  }
});

test('splitPublicKey parses and rejects', () => {
  assert.deepEqual(splitPublicKey('ssh-ed25519 AAAAC3Nza comment here'), ['ssh-ed25519', 'AAAAC3Nza']);
  assert.equal(splitPublicKey('just-one-field'), null);
  assert.equal(splitPublicKey(''), null);
});

test('sameKey ignores comment', () => {
  assert.equal(sameKey('ssh-ed25519 AAAAC3Nza a@b', 'ssh-ed25519 AAAAC3Nza c@d'), true);
  assert.equal(sameKey('ssh-ed25519 AAAAC3Nza', 'ssh-ed25519 AAAAC3Nzb'), false);
});
