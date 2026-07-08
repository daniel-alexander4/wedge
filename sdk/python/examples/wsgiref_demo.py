#!/usr/bin/env python3
"""Minimal wedge relying party — pure stdlib, no Flask.

Shows the "any framework" integration pattern: ~60 lines of routing translate
HTTP to the framework-neutral WedgeRP handlers. Also the e2e harness for the
wedge-rp test drive.

    python3 wsgiref_demo.py --port 9411 --user dan:~/.ssh/id_ed25519.pub

Then point the wedge app at http://127.0.0.1:9411 and open /login.

Multi-worker (needs the shared SQLite store and a fixed cookie secret):

    WEDGE_DEMO_ORIGIN=http://127.0.0.1:9411 \
    WEDGE_DEMO_USERS=dan:~/.ssh/id_ed25519.pub \
    WEDGE_DEMO_DB=/tmp/wedge-demo.db \
    WEDGE_DEMO_SECRET=change-me \
    gunicorn -w 4 -b 127.0.0.1:9411 'wsgiref_demo:app_from_env()'
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
from http import cookies as http_cookies
from pathlib import Path
from urllib.parse import parse_qs

from wedge_rp import core
from wedge_rp.core import WedgeRP
from wedge_rp.kernel import same_key
from wedge_rp.store import SQLiteStore

PAGE = """<!doctype html><meta charset="utf-8"><title>wedge-rp demo</title>
<body style="font-family: system-ui; max-width: 40rem; margin: 4rem auto">
{body}</body>"""

LOGIN = """<h1>wedge-rp demo</h1>
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
</script>"""


def _sign(secret: bytes, username: str) -> str:
    mac = hmac.new(secret, username.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{username}.{mac}"


def _unsign(secret: bytes, value: str | None) -> str | None:
    if not value or "." not in value:
        return None
    username, _, mac = value.rpartition(".")
    if hmac.compare_digest(_sign(secret, username), f"{username}.{mac}"):
        return username
    return None


def create_app(origin: str, users: dict[str, str], db: str | None = None, secret: str | None = None):
    """users maps username -> public key line (one key per user, demo-simple)."""
    cookie_secret = (secret or secrets.token_urlsafe(32)).encode("utf-8")
    rp = WedgeRP(
        origin=origin,
        find_keys=lambda username: users.get(username),
        find_user_by_public_key=lambda posted: next(
            ((name, key) for name, key in users.items() if same_key(key, posted)), None
        ),
        store=SQLiteStore(db) if db else None,
    )

    def app(environ, start_response):
        method = environ["REQUEST_METHOD"]
        path = environ["PATH_INFO"]
        query = {k: v[0] for k, v in parse_qs(environ.get("QUERY_STRING", "")).items()}
        jar = http_cookies.SimpleCookie(environ.get("HTTP_COOKIE", ""))
        cookie = {k: v.value for k, v in jar.items()}

        def read_json():
            try:
                length = min(int(environ.get("CONTENT_LENGTH") or 0), 64 * 1024)
                return json.loads(environ["wsgi.input"].read(length) or b"{}")
            except (ValueError, KeyError):
                return None

        def respond(status_code, body, content_type="application/json", extra=()):
            payload = json.dumps(body).encode() if isinstance(body, dict) else body.encode()
            headers = [("Content-Type", content_type), ("Content-Length", str(len(payload)))]
            headers.extend(extra)
            start_response(f"{status_code} {'OK' if status_code == 200 else 'X'}", headers)
            return [payload]

        def set_session(username):
            value = _sign(cookie_secret, username)
            return ("Set-Cookie", f"demo_session={value}; Path=/; HttpOnly; SameSite=Strict")

        # -- wedge endpoints ------------------------------------------------
        if method == "GET" and path == core.DISCOVERY_PATH:
            return respond(200, rp.discovery())
        if method == "POST" and path == core.START_PATH:
            body = read_json() or {}
            status_code, payload, nonce = rp.start(username=body.get("username"))
            extra = []
            if nonce is not None:
                extra.append(("Set-Cookie",
                              f"{core.BINDING_COOKIE}={nonce}; Path=/; HttpOnly; "
                              f"SameSite=Strict; Max-Age={int(rp.challenge_ttl)}"))
            return respond(status_code, payload, extra=extra)
        if method == "GET" and path == core.CHALLENGE_PATH:
            return respond(*rp.challenge(query.get("request_id", "")))
        if method == "POST" and path == core.VERIFY_PATH:
            return respond(*rp.verify(read_json(), source=environ.get("REMOTE_ADDR")))
        if method == "GET" and path == core.STATUS_PATH:
            payload, username = rp.status(query.get("request_id", ""), cookie.get(core.BINDING_COOKIE))
            if username is not None:
                return respond(200, dict(payload, redirect="/"), extra=[set_session(username)])
            return respond(200, payload)
        if method == "POST" and path == core.APP_START_PATH:
            return respond(*rp.app_start())
        if method == "GET" and path == core.CLAIM_PATH:
            username = rp.claim(query.get("request_id", ""), query.get("claim", ""))
            extra = [("Location", "/"), ("Referrer-Policy", "no-referrer")]
            if username is not None:
                extra.append(set_session(username))
            return respond(303, "", "text/plain", extra)
        if method == "GET" and path == core.SCRIPT_PATH:
            import importlib.resources
            js = importlib.resources.files("wedge_rp").joinpath("static/wedge.js").read_text("utf-8")
            return respond(200, js, "text/javascript")

        # -- demo pages -----------------------------------------------------
        if method == "GET" and path == "/login":
            return respond(200, PAGE.format(body=LOGIN), "text/html")
        if method == "GET" and path == "/logout":
            return respond(303, "", "text/plain",
                           [("Location", "/"), ("Set-Cookie", "demo_session=; Path=/; Max-Age=0")])
        if method == "GET" and path == "/":
            who = _unsign(cookie_secret, cookie.get("demo_session"))
            body = (f"<h1>Signed in as {who}</h1><p><a href='/logout'>Log out</a></p>" if who
                    else "<h1>Signed out</h1><p><a href='/login'>Sign in with wedge</a></p>")
            return respond(200, PAGE.format(body=body), "text/html")
        return respond(404, "not found", "text/plain")

    return app


def _parse_users(specs) -> dict[str, str]:
    users = {}
    for spec in specs:
        name, _, keypath = spec.partition(":")
        if not name or not keypath:
            raise SystemExit(f"bad --user spec {spec!r}; expected NAME:PUBKEY_PATH")
        users[name] = Path(keypath).expanduser().read_text("utf-8").strip()
    return users


def app_from_env():
    """WSGI factory for gunicorn: configuration via WEDGE_DEMO_* env vars."""
    return create_app(
        origin=os.environ["WEDGE_DEMO_ORIGIN"],
        users=_parse_users(os.environ["WEDGE_DEMO_USERS"].split(",")),
        db=os.environ.get("WEDGE_DEMO_DB"),
        secret=os.environ.get("WEDGE_DEMO_SECRET"),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9411)
    parser.add_argument("--origin", help="canonical origin (default http://HOST:PORT)")
    parser.add_argument("--user", action="append", default=[], metavar="NAME:PUBKEY_PATH",
                        help="register an account (repeatable)")
    parser.add_argument("--db", help="SQLite path for the request store (default in-memory)")
    args = parser.parse_args()
    if not args.user:
        parser.error("register at least one --user NAME:PUBKEY_PATH")

    origin = args.origin or f"http://{args.host}:{args.port}"
    app = create_app(origin, _parse_users(args.user), db=args.db)

    from wsgiref.simple_server import make_server

    print(f"wedge-rp demo on {origin} (login at {origin}/login)", file=sys.stderr)
    make_server(args.host, args.port, app).serve_forever()


if __name__ == "__main__":
    main()
