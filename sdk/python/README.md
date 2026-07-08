# wedge-rp — add "Sign in with wedge" to your Python site

[wedge](https://github.com/daniel-alexander4/wedge) is SSH-key web
authentication: your users sign a per-login challenge with the SSH key already
in their ssh-agent, and your site verifies it the same way `sshd` would — no
passwords, no WebAuthn ceremony, no cloud. This package is the relying-party
(server) side of the [wedge protocol v1](../../docs/wedge-spec-v1.md): it
serves the wedge endpoints, runs the challenge state machine, and verifies
signatures via `ssh-keygen -Y verify`.

- **Zero runtime dependencies.** Pure standard library; the only external
  requirement is the `ssh-keygen` binary (OpenSSH 8.1+, present on
  effectively every server). wedge-rp implements no cryptography of its own.
- **Python 3.10+.** Framework-agnostic core; Flask adapter included.
- **MIT.**

## Add it to a Flask app (~10 minutes)

```
pip install wedge-rp[flask]
```

You supply two things the protocol deliberately leaves to your app: how to
look up a user's registered public key(s), and what "log this user in" means.

```python
from flask import Flask, session
from wedge_rp import WedgeRP, SQLiteStore, same_key
from wedge_rp.flask import wedge_blueprint

app = Flask(__name__)
app.secret_key = "..."

# 1. Account lookups against YOUR user store (shown here: a dict).
USERS = {"alice": "ssh-ed25519 AAAAC3... alice@laptop"}

def find_keys(username):                # username -> registered key(s)
    return USERS.get(username)

def find_user_by_public_key(posted):    # key -> (username, registered keys)
    for name, key in USERS.items():
        if same_key(key, posted):       # compares type+data, ignores comment
            return name, key
    return None

# 2. The RP engine. origin is your canonical origin exactly as browsers
#    reach it — it becomes the signature namespace, so configure it
#    explicitly; never derive it from a Host header.
rp = WedgeRP(
    origin="https://example.com",
    find_keys=find_keys,
    find_user_by_public_key=find_user_by_public_key,
    store=SQLiteStore("/var/lib/myapp/wedge.db"),  # shared across workers
)

# 3. Mount it. `login` runs inside a request context at the one moment a
#    session may be minted — use flask-login's login_user() if you have it.
app.register_blueprint(wedge_blueprint(
    rp,
    login=lambda username: session.__setitem__("user", username),
    redirect_to="/",
))
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
supplied `find_user_by_public_key`.

### Deployment notes

- **Multiple workers?** The quickstart's `SQLiteStore` is required under
  `gunicorn -w N` (any N > 1): sign-in state must be shared, or the browser's
  status poll and the app's verify land on different workers and the login
  never completes. The zero-config default (`MemoryStore`) is for development
  and single-process servers. For multi-*host* deployments implement the
  four-method `RequestStore` interface over storage you already share.
- **`ssh-keygen` must be on PATH** (package `openssh-client` on Debian/Ubuntu).
  If it's missing or pre-8.1, verifies fail with a clear 503 and
  `SSHKeygenUnavailable` is raised from the kernel.
- Serve over **HTTPS** in production; the binding cookie is set `Secure`
  automatically when your origin is https.

## Any other framework

The Flask blueprint is ~100 lines over a framework-neutral engine — dicts in,
dicts out. To integrate with anything else, route eight paths to the matching
`WedgeRP` methods and handle two cookies; `examples/wsgiref_demo.py` does it
with the raw standard library. The contract per endpoint:

| Path (default) | Method | Engine call | Adapter's job |
|---|---|---|---|
| `/.well-known/wedge.json` | GET | `discovery()` | serve JSON (path fixed by spec) |
| `/wedge/start` | POST | `start(username?)` | set `browser_nonce` as HttpOnly cookie |
| `/wedge/challenge` | GET | `challenge(request_id)` | serve JSON |
| `/wedge/verify` | POST | `verify(body, source=ip)` | serve JSON (cookieless, authenticator-facing) |
| `/wedge/status` | GET | `status(request_id, cookie)` | on username: mint session, add `redirect` |
| `/wedge/app-start` | POST | `app_start()` | serve JSON (path fixed by spec) |
| `/wedge/claim` | GET | `claim(request_id, claim)` | on username: mint session; always redirect, `Referrer-Policy: no-referrer` |
| `/wedge/wedge.js` | GET | — | serve `wedge_rp/static/wedge.js` |

Everything security-critical — single-use challenges and claim tokens,
constant-time comparisons, verify-against-stored-not-posted values, browser
binding, TTLs — lives in the engine, not the adapters.

## Registering keys

How users enroll public keys is your application's concern (the protocol
scopes it out, like WebAuthn does). Typical shape: an "SSH keys" box on the
account page, validated with `wedge_rp.split_public_key`, stored one key per
account. The posted key in a keyless sign-in is only ever a *selector*;
wedge-rp verifies strictly against the keys your callback returns.

## Tests

```
python -m unittest discover -s tests
```

The suite signs with a real throwaway ed25519 key via `ssh-keygen -Y sign`,
so a passing run proves interop with the OpenSSH on your machine. Tests in
`tests/test_core.py` are named for the spec requirement they pin down.
