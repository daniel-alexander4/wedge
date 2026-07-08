// Express adapter — the ~10-minute integration path.
//
// Exposes every wedge endpoint on an express.Router whose session-minting
// handlers run inside the normal request cycle, so the `login` callback can
// use whatever the host app already uses (express-session, your own cookie).
//
//     import express from 'express';
//     import { WedgeRP, SqliteStore } from 'wedge-rp';
//     import { wedgeRouter } from 'wedge-rp/express';
//
//     const rp = new WedgeRP({
//       origin: 'https://example.com',
//       findKeys: lookupKeys,
//       findUserByPublicKey: lookupAccount,
//       store: new SqliteStore('/var/lib/myapp/wedge.db'),
//     });
//     app.use(wedgeRouter(rp, { login: (username, req) => { req.session.user = username; } }));
//
// Express itself is an optional peer dependency — this module is only loaded
// via the 'wedge-rp/express' subpath. Plain string paths only, so the router
// behaves identically on Express 4 and 5. Cookies are parsed in-package
// (Express core never parses them; no cookie-parser dependency).

import { readFileSync } from 'node:fs';

import express from 'express';

import {
  APP_START_PATH,
  BINDING_COOKIE,
  CHALLENGE_PATH,
  CLAIM_PATH,
  DISCOVERY_PATH,
  SCRIPT_PATH,
  START_PATH,
  STATUS_PATH,
  VERIFY_PATH,
} from './core.js';

const wedgeJs = readFileSync(new URL('../static/wedge.js', import.meta.url), 'utf8');

function cookieValue(req, name) {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const eq = part.indexOf('=');
    if (eq !== -1 && part.slice(0, eq).trim() === name) {
      return decodeURIComponent(part.slice(eq + 1).trim());
    }
  }
  return null;
}

// Build an express.Router serving all wedge endpoints for `rp`.
//
// Options:
//   login           — REQUIRED. Called as login(username, req, res) inside the
//                     request cycle at the one moment a session may be minted.
//                     Establish your app's session here and nothing else.
//   redirectTo      — where the browser lands after sign-in: a path or a
//                     (username) => path function. Default '/'.
//   failureRedirect — where /wedge/claim sends the browser when a claim is
//                     invalid (it never mints a session on failure). Default '/'.
export function wedgeRouter(rp, { login, redirectTo = '/', failureRedirect = '/' }) {
  if (typeof login !== 'function') throw new Error('wedgeRouter needs a login callback');
  const router = express.Router();
  const json = express.json({ limit: '64kb' });
  const landing = (username) => (typeof redirectTo === 'function' ? redirectTo(username) : redirectTo);

  router.get(DISCOVERY_PATH, (req, res) => {
    res.json(rp.discovery());
  });

  router.post(START_PATH, json, (req, res) => {
    // Browser-facing POST: reject cross-site initiations outright.
    if (req.headers.origin && !rp.isSameOrigin(req.headers.origin)) {
      res.status(403).json({ ok: false, error: 'cross-origin request' });
      return;
    }
    const { status, body, browserNonce } = rp.start(req.body?.username ?? null);
    if (browserNonce !== null) {
      res.cookie(BINDING_COOKIE, browserNonce, {
        maxAge: rp.challengeTtl * 1000,
        httpOnly: true,
        sameSite: 'strict',
        secure: rp.usesHttps,
        path: '/',
      });
    }
    res.status(status).json(body);
  });

  router.get(CHALLENGE_PATH, (req, res) => {
    const { status, body } = rp.challenge(String(req.query.request_id ?? ''));
    res.status(status).json(body);
  });

  router.post(VERIFY_PATH, json, async (req, res, next) => {
    // Authenticator-facing: cookieless JSON (spec §5.2).
    try {
      const { status, body } = await rp.verify(req.body, { source: req.ip });
      res.status(status).json(body);
    } catch (err) {
      next(err);
    }
  });

  router.get(STATUS_PATH, async (req, res, next) => {
    try {
      const { body, username } = rp.status(
        String(req.query.request_id ?? ''),
        cookieValue(req, BINDING_COOKIE),
      );
      if (username !== null) {
        await login(username, req, res);
        res.json({ ...body, redirect: landing(username) });
        return;
      }
      res.json(body);
    } catch (err) {
      next(err);
    }
  });

  router.post(APP_START_PATH, (req, res) => {
    const { status, body } = rp.appStart();
    res.status(status).json(body);
  });

  router.get(CLAIM_PATH, async (req, res, next) => {
    try {
      const username = rp.claim(
        String(req.query.request_id ?? ''),
        String(req.query.claim ?? ''),
      );
      // The claim URL is a bearer secret: never let it leak via Referer, and
      // never render it into page content (spec §8.3) — hence redirect-only.
      res.set('Referrer-Policy', 'no-referrer');
      if (username === null) {
        res.redirect(failureRedirect);
        return;
      }
      await login(username, req, res);
      res.redirect(landing(username));
    } catch (err) {
      next(err);
    }
  });

  router.get(SCRIPT_PATH, (req, res) => {
    res.type('text/javascript').send(wedgeJs);
  });

  return router;
}
