# wedgerp — add "Sign in with wedge" to your Go site

[wedge](https://github.com/daniel-alexander4/wedge) is SSH-key web
authentication: your users sign a per-login challenge with the SSH key already
in their ssh-agent, and your site verifies it the same way `sshd` would — no
passwords, no WebAuthn ceremony, no cloud. This package is the relying-party
(server) side of the [wedge protocol v1](../../docs/wedge-spec-v1.md).

It lives inside the wedge module deliberately: the origin-equivalence rules
come from the authenticator's own `internal/policy` and the wire types from
`internal/rp`, so the two sides of the protocol cannot drift apart.

- **Zero dependencies.** The wedge module requires nothing; the one external
  requirement is the `ssh-keygen` binary (OpenSSH 8.1+). wedgerp implements
  no cryptography of its own.
- **net/http is the adapter.** `wedgerp.Handler` returns an `http.Handler`;
  chi, echo, gin, and the stdlib all mount it as-is.
- **MIT.**

## Add it to your app (~10 minutes)

```
go get github.com/daniel-alexander4/wedge/sdk/go/wedgerp
```

You supply two things the protocol deliberately leaves to your app: how to
look up a user's registered public key(s), and what "log this user in" means.

```go
import "github.com/daniel-alexander4/wedge/sdk/go/wedgerp"

// 1. Account lookups against YOUR user store (shown here: a map).
users := map[string]string{"alice": "ssh-ed25519 AAAAC3... alice@laptop"}

rp, err := wedgerp.New(wedgerp.Config{
    // 2. Your canonical origin exactly as browsers reach it — it becomes
    //    the signature namespace; never derive it from a Host header.
    Origin: "https://example.com",
    FindKeys: func(username string) ([]string, error) {
        if k, ok := users[username]; ok {
            return []string{k}, nil
        }
        return nil, nil
    },
    FindUserByPublicKey: func(posted string) (string, []string, error) {
        for name, k := range users {
            if wedgerp.SameKey(k, posted) { // type+data, comments ignored
                return name, []string{k}, nil
            }
        }
        return "", nil, nil
    },
    // Optional: advertised in discovery — wedge sends users whose key isn't
    // registered yet straight here (must be same-origin with Origin).
    RegistrationURL: "https://example.com/register",
})

// 3. Mount it. Login runs inside the request at the one moment a session
//    may be minted — establish your app's session there.
h := wedgerp.Handler(rp, wedgerp.HandlerOptions{
    Login: func(username string, w http.ResponseWriter, r *http.Request) {
        yourSessions.Create(w, username)
    },
    RedirectTo: "/",
})
mux.Handle("/.well-known/wedge.json", h)
mux.Handle("/wedge/", h)
```

And on your login page:

```html
<script src="/wedge/wedge.js"></script>
<button id="wedge-btn">Sign in with wedge</button>
<script>Wedge.attach(document.getElementById("wedge-btn"));</script>
```

That's the whole integration. A visitor clicks the button, their wedge app
opens and asks for a tap, and the page reloads signed in. Users who have the
wedge app can also start from the app itself (app-initiated flow) — that
works automatically because you supplied `FindUserByPublicKey`.

Runnable version: `examples/demo` —

```
go run ./sdk/go/examples/demo --port 9413 --user you:$HOME/.ssh/id_ed25519.pub
```

**Real-world integration: `examples/forgejo`** — "Sign in with wedge" for a
stock Forgejo or Gitea, no fork required. A gateway uses this middleware for
the wedge login, then reverse-proxies to Forgejo injecting the verified
username as the trusted `X-WEBAUTH-USER` header. `docker compose up` gives you
Forgejo-with-wedge-login; see [`examples/forgejo/README.md`](examples/forgejo/README.md).

## Deployment notes

- **One process (the Go norm): nothing to configure** — the default
  `MemoryStore` is correct. Running several processes or hosts behind one
  origin? Implement the four-method `RequestStore` interface over storage
  you already share (SQL, Redis); its two mutating methods are the
  single-use guarantees and must stay atomic there.
- **`ssh-keygen` must be on PATH** (package `openssh-client` on
  Debian/Ubuntu); overridable via `SSH_KEYGEN_PATH`. Missing or pre-8.1
  surfaces as a 503 with `ErrSSHKeygenUnavailable`.
- Serve over **HTTPS** in production; the binding cookie is `Secure`
  automatically when your origin is https.

## Custom routing

`Handler` is ~120 lines over the exported engine methods (`Discovery`,
`Start`, `Challenge`, `Verify`, `Status`, `Claim`, `AppStart`) — if you need
different paths or transports, wire those directly; everything
security-critical (single-use challenges and claim tokens, constant-time
comparisons, verify-against-stored-not-posted values, browser binding, TTLs)
lives in the engine, not the adapter. The challenge/verify paths are free as
long as discovery publishes them; `/.well-known/wedge.json` and
`/wedge/app-start` are fixed by the spec.

## Registering keys

How users enroll public keys is your application's concern (the protocol
scopes it out, like WebAuthn does). Validate submissions with
`wedgerp.SplitPublicKey`; the posted key in a keyless sign-in is only ever a
*selector* — wedgerp verifies strictly against the keys your callback
returns.

## Tests

```
go test ./sdk/go/...
```

The suite signs with a real throwaway ed25519 key via `ssh-keygen -Y sign`.
The conformance tests in `wedgerp_test.go` are a test-for-test port of the
Python and Node packages' (`sdk/python/tests/test_core.py`,
`sdk/node/tests/core.test.js`) — keep the three suites in lockstep.
