#!/usr/bin/env node
// Minimal wedge relying party — raw node:http, no Express.
//
// Shows the "any framework" integration pattern: ~60 lines of routing
// translate HTTP to the framework-neutral WedgeRP handlers. Also the e2e
// harness for the wedge-rp test drive.
//
//     node http-demo.mjs --port 9412 --user dan:~/.ssh/id_ed25519.pub
//
// Then point the wedge app at http://127.0.0.1:9412 and open /login.
//
// Multi-process (needs the shared SQLite store and a fixed cookie secret):
//
//     node http-demo.mjs --port 9412 --user dan:~/.ssh/id_ed25519.pub \
//       --db /tmp/wedge-demo.db --secret change-me &   # repeat per process/port

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { homedir } from 'node:os';
import { parseArgs } from 'node:util';

import { BINDING_COOKIE, SCRIPT_PATH, WedgeRP, sameKey, SqliteStore } from 'wedge-rp';

const PAGE = (body) => `<!doctype html><meta charset="utf-8"><title>wedge-rp demo</title>
<body style="font-family: system-ui; max-width: 40rem; margin: 4rem auto">${body}</body>`;

const LOGIN = `<h1>wedge-rp demo</h1>
<p>Sign in with the SSH key registered for your account.</p>
<p><input id="u" placeholder="username (optional)"></p>
<p><button id="b">Sign in with wedge</button></p>
<p id="msg"></p>
<script src="/wedge/wedge.js"></script>
<script>
Wedge.attach(document.getElementById("b"), {
  usernameInput: "#u",
  onStatus: function (s) { document.getElementById("msg").textContent = s; },
  onError: function (e) { document.getElementById("msg").textContent = e.message; },
});
</script>`;

const { values: args } = parseArgs({
  options: {
    host: { type: 'string', default: '127.0.0.1' },
    port: { type: 'string', default: '9412' },
    origin: { type: 'string' },
    user: { type: 'string', multiple: true, default: [] },
    db: { type: 'string' },
    secret: { type: 'string' },
  },
});
if (args.user.length === 0) {
  console.error('register at least one --user NAME:PUBKEY_PATH');
  process.exit(2);
}

const origin = args.origin ?? `http://${args.host}:${args.port}`;
const users = Object.fromEntries(args.user.map((spec) => {
  const idx = spec.indexOf(':');
  const name = spec.slice(0, idx);
  const keyPath = spec.slice(idx + 1).replace(/^~/, homedir());
  return [name, readFileSync(keyPath, 'utf8').trim()];
}));
const secret = args.secret ?? randomBytes(32).toString('base64url');

const rp = new WedgeRP({
  origin,
  findKeys: (username) => users[username] ?? null,
  findUserByPublicKey: (posted) =>
    Object.entries(users).find(([, key]) => sameKey(key, posted)) ?? null,
  store: args.db ? new SqliteStore(args.db) : null,
});

const signSession = (username) =>
  `${username}.${createHmac('sha256', secret).update(username).digest('hex')}`;
const readSession = (value) => {
  if (!value || !value.includes('.')) return null;
  const username = value.slice(0, value.lastIndexOf('.'));
  const expected = Buffer.from(signSession(username));
  const got = Buffer.from(value);
  return expected.length === got.length && timingSafeEqual(expected, got) ? username : null;
};
const cookie = (req, name) => {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const eq = part.indexOf('=');
    if (eq !== -1 && part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
};
const readJson = (req) => new Promise((resolve) => {
  let data = '';
  req.setEncoding('utf8');
  req.on('data', (chunk) => { if ((data += chunk).length > 65536) req.destroy(); });
  req.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve(null); } });
});

const server = createServer(async (req, res) => {
  const url = new URL(req.url, origin);
  const route = `${req.method} ${url.pathname}`;
  const json = (status, body, extra = {}) => {
    res.writeHead(status, { 'Content-Type': 'application/json', ...extra });
    res.end(JSON.stringify(body));
  };
  const html = (body) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(PAGE(body));
  };
  const sessionCookie = (username) =>
    `demo_session=${signSession(username)}; Path=/; HttpOnly; SameSite=Strict`;

  // -- wedge endpoints --------------------------------------------------------
  if (route === 'GET /.well-known/wedge.json') return json(200, rp.discovery());
  if (route === 'POST /wedge/start') {
    const body = await readJson(req) ?? {};
    const { status, body: payload, browserNonce } = rp.start(body.username ?? null);
    const extra = browserNonce === null ? {} : {
      'Set-Cookie': `${BINDING_COOKIE}=${browserNonce}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${rp.challengeTtl}`,
    };
    return json(status, payload, extra);
  }
  if (route === 'GET /wedge/challenge') {
    const { status, body } = rp.challenge(url.searchParams.get('request_id') ?? '');
    return json(status, body);
  }
  if (route === 'POST /wedge/verify') {
    const { status, body } = await rp.verify(await readJson(req), { source: req.socket.remoteAddress });
    return json(status, body);
  }
  if (route === 'GET /wedge/status') {
    const { body, username } = rp.status(
      url.searchParams.get('request_id') ?? '',
      cookie(req, BINDING_COOKIE),
    );
    if (username !== null) {
      return json(200, { ...body, redirect: '/' }, { 'Set-Cookie': sessionCookie(username) });
    }
    return json(200, body);
  }
  if (route === 'POST /wedge/app-start') {
    const { status, body } = rp.appStart();
    return json(status, body);
  }
  if (route === 'GET /wedge/claim') {
    const username = rp.claim(
      url.searchParams.get('request_id') ?? '',
      url.searchParams.get('claim') ?? '',
    );
    res.writeHead(303, {
      Location: '/',
      'Referrer-Policy': 'no-referrer',
      ...(username !== null ? { 'Set-Cookie': sessionCookie(username) } : {}),
    });
    return res.end();
  }
  if (route === `GET ${SCRIPT_PATH}`) {
    res.writeHead(200, { 'Content-Type': 'text/javascript' });
    return res.end(readFileSync(new URL('../static/wedge.js', import.meta.url), 'utf8'));
  }

  // -- demo pages ---------------------------------------------------------------
  if (route === 'GET /login') return html(LOGIN);
  if (route === 'GET /logout') {
    res.writeHead(303, { Location: '/', 'Set-Cookie': 'demo_session=; Path=/; Max-Age=0' });
    return res.end();
  }
  if (route === 'GET /') {
    const who = readSession(cookie(req, 'demo_session'));
    return html(who
      ? `<h1>Signed in as ${who}</h1><p><a href="/logout">Log out</a></p>`
      : '<h1>Signed out</h1><p><a href="/login">Sign in with wedge</a></p>');
  }
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('not found');
});

server.listen(Number(args.port), args.host, () => {
  console.error(`wedge-rp demo on ${origin} (login at ${origin}/login)`);
});
