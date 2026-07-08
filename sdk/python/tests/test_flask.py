"""Flask adapter integration tests (skipped when Flask isn't installed)."""

import unittest

try:
    import flask
except ImportError:  # pragma: no cover
    flask = None

from wedge_rp.core import WedgeRP
from wedge_rp.kernel import same_key

from helpers import HAVE_SSH_KEYGEN, KeyPair

ORIGIN = "http://127.0.0.1:9411"


@unittest.skipUnless(HAVE_SSH_KEYGEN, "ssh-keygen not installed")
@unittest.skipUnless(flask is not None, "flask not installed")
class FlaskAdapterTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = KeyPair("alice@test")

    @classmethod
    def tearDownClass(cls):
        cls.alice.close()

    def setUp(self):
        from wedge_rp.flask import wedge_blueprint

        users = {"alice": self.alice.public_key}
        self.rp = WedgeRP(
            origin=ORIGIN,
            find_keys=users.get,
            find_user_by_public_key=lambda posted: next(
                ((n, k) for n, k in users.items() if same_key(k, posted)), None
            ),
        )
        app = flask.Flask(__name__)
        app.secret_key = "test"
        self.logins = []

        def login(username):
            self.logins.append(username)
            flask.session["user"] = username

        app.register_blueprint(
            wedge_blueprint(self.rp, login=login, redirect_to="/home", failure_redirect="/login")
        )
        self.app = app
        self.client = app.test_client()

    def sign_in_core(self, client):
        """Browser start + app-side verify, up to (but not including) status."""
        start = client.post("/wedge/start", json={"username": "alice"})
        self.assertEqual(start.status_code, 200)
        rid = start.get_json()["request_id"]
        challenge = client.get(f"/wedge/challenge?request_id={rid}").get_json()["challenge"]
        verify = self.client.post(  # authenticator posts cookieless JSON
            "/wedge/verify",
            json={
                "request_id": rid,
                "challenge": challenge,
                "namespace": ORIGIN,
                "signature": self.alice.sign(challenge, ORIGIN),
            },
        )
        self.assertEqual(verify.status_code, 200)
        return rid

    def test_discovery_served(self):
        doc = self.client.get("/.well-known/wedge.json").get_json()
        self.assertEqual(doc["version"], 1)
        self.assertEqual(doc["namespace"], ORIGIN)

    def test_core_flow_mints_session_for_bound_browser(self):
        rid = self.sign_in_core(self.client)
        body = self.client.get(f"/wedge/status?request_id={rid}").get_json()
        self.assertEqual(body["status"], "authenticated")
        self.assertEqual(body["redirect"], "/home")
        self.assertEqual(self.logins, ["alice"])
        with self.client.session_transaction() as session:
            self.assertEqual(session["user"], "alice")

    def test_unbound_browser_stays_pending(self):
        rid = self.sign_in_core(self.client)
        stranger = self.app.test_client()  # no wedge_flow cookie
        self.assertEqual(
            stranger.get(f"/wedge/status?request_id={rid}").get_json()["status"],
            "pending",
        )
        self.assertEqual(self.logins, [])

    def test_cross_origin_start_rejected(self):
        resp = self.client.post(
            "/wedge/start", json={}, headers={"Origin": "http://evil.example"}
        )
        self.assertEqual(resp.status_code, 403)

    def test_app_initiated_claim_flow(self):
        started = self.client.post("/wedge/app-start").get_json()
        self.assertTrue(started["ok"])
        verify = self.client.post(
            "/wedge/verify",
            json={
                "request_id": started["request_id"],
                "challenge": started["challenge"],
                "namespace": started["namespace"],
                "signature": self.alice.sign(started["challenge"], started["namespace"]),
                "public_key": self.alice.public_key,
            },
        )
        self.assertEqual(verify.status_code, 200)
        claim_path = started["claim_url"].removeprefix(ORIGIN)
        browser = self.app.test_client()  # a fresh browser, as the app opens one
        resp = browser.get(claim_path)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.headers["Location"], "/home")
        self.assertEqual(resp.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(self.logins, ["alice"])
        # single-use: the same claim URL never mints twice
        resp2 = browser.get(claim_path)
        self.assertEqual(resp2.headers["Location"], "/login")
        self.assertEqual(self.logins, ["alice"])

    def test_wedge_js_served(self):
        resp = self.client.get("/wedge/wedge.js")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("window.Wedge", resp.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
