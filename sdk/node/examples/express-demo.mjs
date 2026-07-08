#!/usr/bin/env node
// The guide's Express integration, runnable: an Express app with "Sign in
// with wedge" mounted in one wedgeRouter() call. Requires express installed
// (it's this package's devDependency, so `npm install` here is enough).
//
//     node express-demo.mjs --port 9412 --user dan:~/.ssh/id_ed25519.pub

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { parseArgs } from 'node:util';

import express from 'express';

import { WedgeRP, sameKey, SqliteStore } from 'wedge-rp';
import { wedgeRouter } from 'wedge-rp/express';

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
  return [
    spec.slice(0, idx),
    readFileSync(spec.slice(idx + 1).replace(/^~/, homedir()), 'utf8').trim(),
  ];
}));

// Demo session: an HMAC-signed cookie (a real app would use express-session).
const secret = args.secret ?? randomBytes(32).toString('base64url');
const sign = (username) => `${username}.${createHmac('sha256', secret).update(username).digest('hex')}`;
const read = (value) => {
  if (!value || !value.includes('.')) return null;
  const username = value.slice(0, value.lastIndexOf('.'));
  const expected = Buffer.from(sign(username));
  const got = Buffer.from(value);
  return expected.length === got.length && timingSafeEqual(expected, got) ? username : null;
};

const rp = new WedgeRP({
  origin,
  findKeys: (username) => users[username] ?? null,
  findUserByPublicKey: (posted) =>
    Object.entries(users).find(([, key]) => sameKey(key, posted)) ?? null,
  store: args.db ? new SqliteStore(args.db) : null,
});

const app = express();
app.use(wedgeRouter(rp, {
  login: (username, req, res) => {
    res.cookie('demo_session', sign(username), { httpOnly: true, sameSite: 'strict' });
  },
  redirectTo: '/',
  failureRedirect: '/login',
}));

const page = (body) => `<!doctype html><meta charset="utf-8"><title>wedge-rp demo</title>
<body style="font-family: system-ui; max-width: 40rem; margin: 4rem auto">${body}</body>`;

app.get('/login', (req, res) => {
  res.send(page(`<h1>wedge-rp demo (Express)</h1>
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
</script>`));
});

app.get('/logout', (req, res) => {
  res.clearCookie('demo_session');
  res.redirect('/');
});

app.get('/', (req, res) => {
  const raw = (req.headers.cookie ?? '').split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith('demo_session='));
  const who = read(raw?.slice('demo_session='.length));
  res.send(page(who
    ? `<h1>Signed in as ${who}</h1><p><a href="/logout">Log out</a></p>`
    : '<h1>Signed out</h1><p><a href="/login">Sign in with wedge</a></p>'));
});

app.listen(Number(args.port), args.host, () => {
  console.error(`wedge-rp Express demo on ${origin} (login at ${origin}/login)`);
});
