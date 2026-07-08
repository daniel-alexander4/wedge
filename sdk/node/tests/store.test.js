import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { MemoryStore, SqliteStore } from '../lib/store.js';

function record(overrides = {}) {
  return {
    requestId: 'req1',
    challenge: 'AbCdEfGhIjKlMnOpQrStUvWx',
    namespace: 'http://127.0.0.1:9412',
    username: null,
    browserNonce: 'nonce',
    claimToken: null,
    status: 'pending',
    authenticatedUsername: null,
    expiresAt: Date.now() + 60_000,
    ...overrides,
  };
}

// Behavior every store must satisfy, run against both implementations.
function storeContract(name, makeStore) {
  test(`${name}: put/get roundtrip`, () => {
    const store = makeStore();
    store.put(record());
    const rec = store.get('req1');
    assert.equal(rec.challenge, 'AbCdEfGhIjKlMnOpQrStUvWx');
    assert.equal(rec.status, 'pending');
  });

  test(`${name}: unknown is null`, () => {
    assert.equal(makeStore().get('nope'), null);
  });

  test(`${name}: expired is null`, () => {
    const store = makeStore();
    store.put(record({ expiresAt: Date.now() - 1000 }));
    assert.equal(store.get('req1'), null);
  });

  test(`${name}: setAuthenticated only from pending`, () => {
    const store = makeStore();
    store.put(record());
    assert.equal(store.setAuthenticated('req1', 'alice'), true);
    assert.equal(store.setAuthenticated('req1', 'mallory'), false);
    const rec = store.get('req1');
    assert.equal(rec.status, 'authenticated');
    assert.equal(rec.authenticatedUsername, 'alice');
  });

  test(`${name}: setAuthenticated on unknown or expired`, () => {
    const store = makeStore();
    assert.equal(store.setAuthenticated('nope', 'alice'), false);
    store.put(record({ expiresAt: Date.now() - 1000 }));
    assert.equal(store.setAuthenticated('req1', 'alice'), false);
  });

  test(`${name}: take requires authenticated`, () => {
    const store = makeStore();
    store.put(record());
    assert.equal(store.takeAuthenticated('req1'), null);
    store.setAuthenticated('req1', 'alice');
    assert.equal(store.takeAuthenticated('req1').authenticatedUsername, 'alice');
  });

  test(`${name}: take is single-use`, () => {
    const store = makeStore();
    store.put(record());
    store.setAuthenticated('req1', 'alice');
    assert.notEqual(store.takeAuthenticated('req1'), null);
    assert.equal(store.takeAuthenticated('req1'), null);
    assert.equal(store.get('req1'), null);
  });
}

storeContract('MemoryStore', () => new MemoryStore());

const sqliteDir = mkdtempSync(join(tmpdir(), 'wedge-rp-test-'));
let sqliteN = 0;
storeContract('SqliteStore', () => new SqliteStore(join(sqliteDir, `store-${sqliteN++}.db`)));

test('SqliteStore: state shared across instances (models two workers)', () => {
  const path = join(sqliteDir, 'shared.db');
  const workerA = new SqliteStore(path);
  const workerB = new SqliteStore(path);
  workerA.put(record());
  assert.notEqual(workerB.get('req1'), null);
  assert.equal(workerB.setAuthenticated('req1', 'alice'), true);
  assert.equal(workerA.takeAuthenticated('req1').authenticatedUsername, 'alice');
  assert.equal(workerB.takeAuthenticated('req1'), null); // exactly one winner
});

after(() => rmSync(sqliteDir, { recursive: true, force: true }));
