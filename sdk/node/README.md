# wedge-rp — add "Sign in with wedge" to your Node site

[wedge](https://github.com/daniel-alexander4/wedge) is SSH-key web
authentication: your users sign a per-login challenge with the SSH key already
in their ssh-agent, and your site verifies it the same way `sshd` would — no
passwords, no WebAuthn ceremony, no cloud. This package is the relying-party
(server) side of the [wedge protocol v1](../../docs/wedge-spec-v1.md): it
serves the wedge endpoints, runs the challenge state machine, and verifies
signatures via `ssh-keygen -Y verify`.

- **Zero runtime dependencies.** Node built-ins only; the one external
  requirement is the `ssh-keygen` binary (OpenSSH 8.1+, present on
  effectively every server). wedge-rp implements no cryptography of its own.
- **Node ≥22.13** (both current LTS lines). ESM package; CommonJS apps can
  `require('wedge-rp')` as usual (stable `require(esm)`).
- **Express adapter included** (Express 4 and 5); the core is
  framework-neutral. TypeScript types ship in the box.
- **MIT.**

## Add it to an Express app (~10 minutes)

```
npm install wedge-rp
```

You supply two things the protocol deliberately leaves to your app: how to
look up a user's registered public key(s), and what "log this user in" means.

```js
import express from 'express';
import { WedgeRP, SqliteStore, sameKey } from 'wedge-rp';
import { wedgeRouter } from 'wedge-rp/express';

const app = express();

// 1. Account lookups against YOUR user store (shown here: an object).
const USERS = { alice: 'ssh-ed25519 AAAAC3... alice@laptop' };

const findKeys = (username) => USERS[username] ?? null;   // username -> key(s)

const findUserByPublicKey = (posted) =>                    // key -> [username, keys]
  Object.entries(USERS).find(([, key]) => sameKey(key, posted)) ?? null;

// 2. The RP engine. origin is your canonical origin exactly as browsers
//    reach it — it becomes the signature namespace, so configure it
//    explicitly; never derive it from a Host header.
const rp = new WedgeRP({
  origin: 'https://example.com',
  findKeys,
  findUserByPublicKey,
  store: new SqliteStore('/var/lib/myapp/wedge.db'), // shared across processes
  // Optional: advertised in discovery — wedge sends users whose key isn't
  // registered yet straight here (must be same-origin with origin).
  registrationUrl: 'https://example.com/register',
});

// 3. Mount it. `login` runs inside the request cycle at the one moment a
//    session may be minted — with express-session: req.session.user = username.
app.use(wedgeRouter(rp, {
  login: (username, req, res) => { req.session.user = username; },
  redirectTo: '/',
}));
```

And on your login page:

```html
<script src="/wedge/wedge.js"></script>
<button id="wedge-btn">Sign in with wedge</button>
<script>Wedge.attach(document.getElementById("wedge-btn"));</script>
```

That's the whole integration. A visitor clicks the button, their wedge app
opens and asks for a tap, and the page reloads signed in. Users who have the
[wedge app](https://github.com/daniel-alexander4/wedge) can also start from
the app itself (app-initiated flow) — that works automatically because you
supplied `findUserByPublicKey`.

### Deployment notes

- **Multiple processes?** The quickstart's `SqliteStore` is required under
  `cluster`/`pm2 -i N`: sign-in state must be shared, or the browser's status
  poll and the app's verify land on different processes and the login never
  completes. The zero-config default (`MemoryStore`) is for development and
  single-process servers. For multi-*host* deployments implement the
  four-method store interface over storage you already share. (`SqliteStore`
  uses the built-in `node:sqlite`, release-candidate stability as of Node 24 —
  the store contract keeps it swappable.)
- **`ssh-keygen` must be on PATH** (package `openssh-client` on Debian/Ubuntu).
  If it's missing or pre-8.1, verifies fail with a clear 503 and
  `SSHKeygenUnavailable` is thrown from the kernel.
- Serve over **HTTPS** in production; the binding cookie is set `Secure`
  automatically when your origin is https.

## Any other framework

The Express router is ~130 lines over a framework-neutral engine — objects
in, objects out. To integrate with anything else, route eight paths to the
matching `WedgeRP` methods and handle two cookies; `examples/http-demo.mjs`
does it with raw `node:http`. The contract per endpoint:

| Path (default) | Method | Engine call | Adapter's job |
|---|---|---|---|
| `/.well-known/wedge.json` | GET | `discovery()` | serve JSON (path fixed by spec) |
| `/wedge/start` | POST | `start(username?)` | set `browserNonce` as HttpOnly cookie |
| `/wedge/challenge` | GET | `challenge(requestId)` | serve JSON |
| `/wedge/verify` | POST | `await verify(body, {source})` | serve JSON (cookieless, authenticator-facing) |
| `/wedge/status` | GET | `status(requestId, cookie)` | on username: mint session, add `redirect` |
| `/wedge/app-start` | POST | `appStart()` | serve JSON (path fixed by spec) |
| `/wedge/claim` | GET | `claim(requestId, claim)` | on username: mint session; always redirect, `Referrer-Policy: no-referrer` |
| `/wedge/wedge.js` | GET | — | serve `static/wedge.js` |

Everything security-critical — single-use challenges and claim tokens,
constant-time comparisons, verify-against-stored-not-posted values, browser
binding, TTLs — lives in the engine, not the adapters.

## Registering keys

How users enroll public keys is your application's concern (the protocol
scopes it out, like WebAuthn does). Typical shape: an "SSH keys" box on the
account page, validated with `splitPublicKey()`, stored one key per account.
The posted key in a keyless sign-in is only ever a *selector*; wedge-rp
verifies strictly against the keys your callback returns.

## Tests

```
npm test
```

The suite signs with a real throwaway ed25519 key via `ssh-keygen -Y sign`,
so a passing run proves interop with the OpenSSH on your machine. The
conformance tests in `tests/core.test.js` are a test-for-test port of the
Python package's (`sdk/python/tests/test_core.py`) — one test per spec MUST;
keep the two suites in lockstep.
