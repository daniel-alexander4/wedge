"""Flask adapter — the ~10-minute integration path.

Registers every wedge endpoint as a blueprint whose session-minting views run
inside Flask's request context, so the ``login`` callback can use whatever the
host app already uses (``flask_login.login_user``, ``session[...] = ...``).

    from wedge_rp import WedgeRP, SQLiteStore
    from wedge_rp.flask import wedge_blueprint

    rp = WedgeRP(origin="https://example.com",
                 find_keys=lookup_keys,
                 find_user_by_public_key=lookup_account,
                 store=SQLiteStore("/var/lib/myapp/wedge.db"))
    app.register_blueprint(wedge_blueprint(rp, login=my_login, redirect_to="/"))

Flask itself is not a dependency of wedge-rp — this module imports it lazily,
from the host app's own environment.
"""

from __future__ import annotations

import importlib.resources
from typing import Callable

from . import core

__all__ = ["wedge_blueprint"]


def wedge_blueprint(
    rp: core.WedgeRP,
    *,
    login: Callable[[str], None],
    redirect_to: str | Callable[[str], str] = "/",
    failure_redirect: str = "/",
    name: str = "wedge",
):
    """Build a Flask blueprint serving all wedge endpoints for ``rp``.

    :param login: called with the verified username, inside a request context,
        at the one moment a session may be minted. Establish your app's
        session here and nothing else.
    :param redirect_to: where the browser lands after sign-in — a path or a
        ``username -> path`` callable.
    :param failure_redirect: where /wedge/claim sends the browser when a claim
        is invalid (it never mints a session on failure).
    """
    from flask import Blueprint, Response, jsonify, redirect, request

    bp = Blueprint(name, __name__)

    def _landing(username: str) -> str:
        return redirect_to(username) if callable(redirect_to) else redirect_to

    @bp.get(core.DISCOVERY_PATH)
    def discovery():
        return jsonify(rp.discovery())

    @bp.post(core.START_PATH)
    def start():
        # Browser-facing POST: reject cross-site initiations outright.
        if request.headers.get("Origin") and not rp.is_same_origin(request.headers["Origin"]):
            return jsonify({"ok": False, "error": "cross-origin request"}), 403
        body = request.get_json(silent=True) or {}
        status, payload, nonce = rp.start(username=body.get("username"))
        resp = jsonify(payload)
        resp.status_code = status
        if nonce is not None:
            resp.set_cookie(
                core.BINDING_COOKIE,
                nonce,
                max_age=int(rp.challenge_ttl),
                httponly=True,
                samesite="Strict",
                secure=rp.uses_https,
                path="/",
            )
        return resp

    @bp.get(core.CHALLENGE_PATH)
    def challenge():
        status, payload = rp.challenge(request.args.get("request_id", ""))
        return jsonify(payload), status

    @bp.post(core.VERIFY_PATH)
    def verify():
        # Authenticator-facing: cookieless JSON (spec §5.2).
        status, payload = rp.verify(request.get_json(silent=True), source=request.remote_addr)
        return jsonify(payload), status

    @bp.get(core.STATUS_PATH)
    def status():
        payload, username = rp.status(
            request.args.get("request_id", ""),
            request.cookies.get(core.BINDING_COOKIE),
        )
        if username is not None:
            login(username)
            payload = dict(payload, redirect=_landing(username))
        return jsonify(payload)

    @bp.post(core.APP_START_PATH)
    def app_start():
        status_code, payload = rp.app_start()
        return jsonify(payload), status_code

    @bp.get(core.CLAIM_PATH)
    def claim():
        username = rp.claim(
            request.args.get("request_id", ""),
            request.args.get("claim", ""),
        )
        if username is None:
            resp = redirect(failure_redirect)
        else:
            login(username)
            resp = redirect(_landing(username))
        # The claim URL is a bearer secret: never let it leak via Referer, and
        # never render it into page content (spec §8.3) — hence redirect-only.
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @bp.get(core.SCRIPT_PATH)
    def script():
        js = importlib.resources.files("wedge_rp").joinpath("static/wedge.js").read_text("utf-8")
        return Response(js, mimetype="text/javascript")

    return bp
