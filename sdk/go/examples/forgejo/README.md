# "Sign in with wedge" for Forgejo (and Gitea)

Add SSH-key web authentication to a stock Forgejo or Gitea instance — no fork,
no plugin, no code changes to Forgejo.

## How it works

Forgejo has no wedge auth source, and no arbitrary auth-source plugin surface
(its external auth is a fixed set: LDAP, SMTP, PAM, OAuth2/OIDC, reverse
proxy, SPNEGO). So this demo uses the one that fits: **reverse-proxy header
authentication**, which Forgejo supports out of the box.

```
browser ──► wedge gateway ──► Forgejo
             │  (this program)   ▲
             │                   │  X-WEBAUTH-USER: <verified username>
             └── wedge login ────┘
```

1. The **gateway** serves the wedge protocol (via the `wedgerp` middleware) on
   its own origin and reverse-proxies everything else to Forgejo.
2. When you sign in with wedge, the gateway verifies your SSH signature and
   opens a session.
3. For each proxied request from an authenticated session, the gateway sets
   the trusted `X-WEBAUTH-USER` header. Forgejo, configured with
   `ENABLE_REVERSE_PROXY_AUTHENTICATION` and auto-registration, signs the user
   in (creating the account on first sight).

## Security — read this

`X-WEBAUTH-USER` **is** the identity. Anyone who can set it on a request
Forgejo trusts becomes that user. Two rules keep that safe, both enforced by
the compose file:

- **Forgejo is never reachable except through the gateway** (no host port on
  the Forgejo service).
- **Forgejo trusts the header only from the gateway** (`REVERSE_PROXY_TRUSTED_PROXIES`
  = the gateway service, not a wildcard). A permissive value here is exactly
  the Gitea advisory [GHSA-f75j-4cw6-rmx4](https://github.com/go-gitea/gitea/security/advisories/GHSA-f75j-4cw6-rmx4).

The gateway itself **strips any client-supplied** `X-WEBAUTH-USER` (and the
email/full-name headers) on every inbound request before deciding whether to
add its own — so a browser can't forge one. That stripping is covered by
`main_test.go` (`TestUnauthenticatedStripsForgedHeader`).

## Run it

```bash
mkdir -p keys && cp ~/.ssh/id_ed25519.pub keys/dan.pub
docker compose up --build
```

Then, in the wedge app, add `http://127.0.0.1:3000` as a site (or let
add-on-first-use prompt you) and open <http://127.0.0.1:3000/wedge-login>.
Sign in; you land in Forgejo as `dan`.

Map more keys to usernames with additional `--user NAME:/keys/NAME.pub`
arguments in the compose `command:` list. The username you map becomes the
Forgejo account name (auto-created on first login).

## Run the gateway alone (against an existing Forgejo)

```bash
go run ./sdk/go/examples/forgejo \
  --origin http://127.0.0.1:3000 \
  --upstream http://your-forgejo:3000 \
  --user dan:$HOME/.ssh/id_ed25519.pub
```

Point Forgejo's `app.ini` at the gateway per the [reverse-proxy auth
docs](https://forgejo.org/docs/latest/admin/config-cheat-sheet/) — enable
reverse-proxy authentication and set `REVERSE_PROXY_TRUSTED_PROXIES` to the
gateway's address only.

## Gitea

Gitea uses the identical mechanism and config keys; point `--upstream` at a
Gitea instance and set the same `app.ini` values.
