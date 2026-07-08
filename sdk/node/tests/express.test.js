// Express adapter integration tests over a real HTTP server (skipped when
// express isn't installed — it's a devDependency).

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { WedgeRP } from '../lib/core.js';
import { sameKey } from '../lib/kernel.js';
import { HAVE_SSH_KEYGEN, KeyPair } from './helpers.js';

let express = null;
let wedgeRouter = null;
try {
  express = (await import('express')).default;
  ({ wedgeRouter } = await import('../lib/express.js'));
} catch {
  // express not installed — suite skips below
}

const ORIGIN = 'http://127.0.0.1:9412';
const skip = !HAVE_SSH_KEYGEN || express === null;

let alice;
let server;
let base;
let logins;

// Minimal cookie jar: name=value pairs captured from Set-Cookie headers.
class Jar {
  #cookies = new Map();

  absorb(res) {
    for (const line of res.headers.getSetCookie?.() ?? []) {
      const [pair] = line.split(';');
      const eq = pair.indexOf('=');
      const value = pair.slice(eq + 1);
      if (value === '') this.#cookies.delete(pair.slice(0, eq));
      else this.#cookies.set(pair.slice(0, eq), value);
    }
  }

  header() {
    return [...this.#cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  }
}

async function request(path, { jar = null, method = 'GET', body = null, headers = {} } = {}) {
  const res = await fetch(base + path, {
    method,
    redirect: 'manual',
    headers: {
      ...(body !== null ? { 'Content-Type': 'application/json' } : {}),
      ...(jar ? { Cookie: jar.header() } : {}),
      ...headers,
    },
    body: body !== null ? JSON.stringify(body) : null,
  });
  jar?.absorb(res);
  return res;
}

before(async () => {
  if (skip) return;
  alice = new KeyPair('alice@test');
  const users = { alice: alice.publicKey };
  const rp = new WedgeRP({
    origin: ORIGIN,
    findKeys: (username) => users[username] ?? null,
    findUserByPublicKey: (posted) =>
      Object.entries(users).find(([, key]) => sameKey(key, posted)) ?? null,
  });
  logins = [];
  const app = express();
  app.use(wedgeRouter(rp, {
    login: (username, req, res) => {
      logins.push(username);
      res.cookie('demo_session', username, { httpOnly: true });
    },
    redirectTo: '/home',
    failureRedirect: '/login',
  }));
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve);
  });
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => {
  server?.close();
  alice?.close();
});

// Browser start + authenticator verify, up to (but not including) status.
async function signInCore(jar) {
  const start = await request('/wedge/start', { jar, method: 'POST', body: { username: 'alice' } });
  assert.equal(start.status, 200);
  const { request_id: rid } = await start.json();
  const ch = await (await request(`/wedge/challenge?request_id=${rid}`)).json();
  const verify = await request('/wedge/verify', {
    method: 'POST',
    body: {
      request_id: rid,
      challenge: ch.challenge,
      namespace: ORIGIN,
      signature: alice.sign(ch.challenge, ORIGIN),
    },
  });
  assert.equal(verify.status, 200);
  return rid;
}

test('discovery served', { skip }, async () => {
  const doc = await (await request('/.well-known/wedge.json')).json();
  assert.equal(doc.version, 1);
  assert.equal(doc.namespace, ORIGIN);
});

test('core flow mints session for the bound browser', { skip }, async () => {
  const jar = new Jar();
  const rid = await signInCore(jar);
  const body = await (await request(`/wedge/status?request_id=${rid}`, { jar })).json();
  assert.equal(body.status, 'authenticated');
  assert.equal(body.redirect, '/home');
  assert.deepEqual(logins, ['alice']);
  assert.ok(jar.header().includes('demo_session=alice'));
  logins.length = 0;
});

test('unbound browser stays pending', { skip }, async () => {
  const jar = new Jar();
  const rid = await signInCore(jar);
  const stranger = await (await request(`/wedge/status?request_id=${rid}`)).json(); // no cookie
  assert.equal(stranger.status, 'pending');
  assert.deepEqual(logins, []);
});

test('cross-origin start rejected', { skip }, async () => {
  const res = await request('/wedge/start', {
    method: 'POST',
    body: {},
    headers: { Origin: 'http://evil.example' },
  });
  assert.equal(res.status, 403);
});

test('app-initiated claim flow, single-use', { skip }, async () => {
  const started = await (await request('/wedge/app-start', { method: 'POST', body: {} })).json();
  assert.equal(started.ok, true);
  const verify = await request('/wedge/verify', {
    method: 'POST',
    body: {
      request_id: started.request_id,
      challenge: started.challenge,
      namespace: started.namespace,
      signature: alice.sign(started.challenge, started.namespace),
      public_key: alice.publicKey,
    },
  });
  assert.equal(verify.status, 200);
  const claimPath = started.claim_url.slice(ORIGIN.length);
  const jar = new Jar(); // a fresh browser, as the app opens one
  const res = await request(claimPath, { jar });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/home');
  assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
  assert.deepEqual(logins, ['alice']);
  // single-use: the same claim URL never mints twice
  const replay = await request(claimPath);
  assert.equal(replay.headers.get('location'), '/login');
  assert.deepEqual(logins, ['alice']);
  logins.length = 0;
});

test('wedge.js served', { skip }, async () => {
  const res = await request('/wedge/wedge.js');
  assert.equal(res.status, 200);
  assert.ok((await res.text()).includes('window.Wedge'));
});
