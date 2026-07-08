"""Spec-conformance tests for the WedgeRP engine.

Each test names the wedge-spec-v1.md requirement it pins down. Signatures are
real SSHSIG made by ssh-keygen, so these tests double as an executable
reading of the spec's RP MUSTs.
"""

import time
import unittest

from wedge_rp.core import WedgeRP
from wedge_rp.kernel import same_key

from helpers import HAVE_SSH_KEYGEN, KeyPair

ORIGIN = "http://127.0.0.1:9411"


@unittest.skipUnless(HAVE_SSH_KEYGEN, "ssh-keygen not installed")
class CoreConformanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = KeyPair("alice@test")
        cls.mallory = KeyPair("mallory@test")

    @classmethod
    def tearDownClass(cls):
        cls.alice.close()
        cls.mallory.close()

    def make_rp(self, **overrides):
        users = {"alice": self.alice.public_key}
        params = dict(
            origin=ORIGIN,
            find_keys=lambda u: users.get(u),
            find_user_by_public_key=lambda posted: next(
                ((name, key) for name, key in users.items() if same_key(key, posted)), None
            ),
        )
        params.update(overrides)
        return WedgeRP(**params)

    def start_and_fetch(self, rp, username=None):
        """Run start + challenge fetch; returns (request_id, challenge, nonce)."""
        status, body, nonce = rp.start(username=username)
        self.assertEqual(status, 200)
        cstatus, cbody = rp.challenge(body["request_id"])
        self.assertEqual(cstatus, 200)
        return body["request_id"], cbody["challenge"], nonce

    def verify_body(self, request_id, challenge, key=None, namespace=ORIGIN, **overrides):
        key = key or self.alice
        body = {
            "request_id": request_id,
            "challenge": challenge,
            "namespace": namespace,
            "signature": key.sign(challenge, namespace),
            "public_key": key.public_key,
        }
        body.update(overrides)
        return body

    # -- discovery (§4) -------------------------------------------------------

    def test_discovery_document(self):
        doc = self.make_rp().discovery()
        self.assertEqual(doc["version"], 1)
        self.assertEqual(doc["namespace"], ORIGIN)  # namespace == canonical origin (§6.1)
        self.assertEqual(doc["challenge_url"], ORIGIN + "/wedge/challenge")
        self.assertEqual(doc["verify_url"], ORIGIN + "/wedge/verify")

    # -- link (§3) ------------------------------------------------------------

    def test_sign_link_format(self):
        rp = self.make_rp()
        _, body, _ = rp.start()
        self.assertEqual(
            body["link"],
            f"wedge://sign?v=1&origin=http%3A%2F%2F127.0.0.1%3A9411&request_id={body['request_id']}",
        )

    # -- start ----------------------------------------------------------------

    def test_keyless_start_needs_selector_callback(self):
        rp = self.make_rp(find_user_by_public_key=None)
        status, body, nonce = rp.start()
        self.assertEqual((status, nonce), (400, None))
        self.assertFalse(body["ok"])

    def test_username_start_needs_find_keys(self):
        rp = self.make_rp(find_keys=None)
        status, _, _ = rp.start(username="alice")
        self.assertEqual(status, 400)

    # -- challenge (§5.1, §6.2) ------------------------------------------------

    def test_challenge_unknown_request(self):
        self.assertEqual(self.make_rp().challenge("nope")[0], 404)

    def test_challenge_format_and_namespace(self):
        rp = self.make_rp()
        _, challenge, _ = self.start_and_fetch(rp)
        self.assertRegex(challenge, r"^[A-Za-z0-9_-]{16,256}$")
        _, cbody = rp.challenge(rp.start()[1]["request_id"])
        self.assertEqual(cbody["namespace"], ORIGIN)

    def test_challenge_gone_after_authentication(self):
        rp = self.make_rp()
        rid, challenge, _ = self.start_and_fetch(rp, username="alice")
        self.assertEqual(rp.verify(self.verify_body(rid, challenge))[0], 200)
        self.assertEqual(rp.challenge(rid)[0], 404)  # used → 404 (§5.1)

    # -- verify (§5.2) ----------------------------------------------------------

    def test_verify_happy_path_username_flow(self):
        rp = self.make_rp()
        rid, challenge, _ = self.start_and_fetch(rp, username="alice")
        status, body = rp.verify(self.verify_body(rid, challenge))
        self.assertEqual((status, body), (200, {"ok": True}))

    def test_verify_unknown_request(self):
        rp = self.make_rp()
        _, challenge, _ = self.start_and_fetch(rp)
        status, body = rp.verify(self.verify_body("unknown-id", challenge))
        self.assertEqual(status, 404)
        self.assertFalse(body["ok"])

    def test_verify_checks_stored_challenge_not_echo(self):
        # RP MUST verify against the challenge it stored, never the echoed
        # field (§5.2 item 2) — a wrong echo with a good signature still passes.
        rp = self.make_rp()
        rid, challenge, _ = self.start_and_fetch(rp, username="alice")
        body = self.verify_body(rid, challenge)
        body["challenge"] = "Definitely_Not_The_Challenge"
        self.assertEqual(rp.verify(body)[0], 200)

    def test_verify_rejects_signature_over_wrong_challenge(self):
        rp = self.make_rp()
        rid, _, _ = self.start_and_fetch(rp, username="alice")
        wrong = "NotTheMintedChallenge123"
        body = self.verify_body(rid, wrong)  # signature over the wrong bytes
        self.assertEqual(rp.verify(body)[0], 401)

    def test_verify_namespace_mismatch(self):
        rp = self.make_rp()
        rid, challenge, _ = self.start_and_fetch(rp, username="alice")
        status, body = rp.verify(self.verify_body(rid, challenge, namespace="http://evil.example"))
        self.assertEqual(status, 400)
        self.assertEqual(body, {"ok": False, "error": "namespace mismatch"})

    def test_verify_accepts_localhost_alias_namespace(self):
        # localhost ↔ 127.0.0.1 with same scheme/port are equivalent (§6.1);
        # -n must get the alias string the authenticator actually signed.
        rp = self.make_rp()
        rid, challenge, _ = self.start_and_fetch(rp, username="alice")
        body = self.verify_body(rid, challenge, namespace="http://localhost:9411")
        self.assertEqual(rp.verify(body)[0], 200)

    def test_failed_verify_consumes_nothing(self):
        # A failed verify MUST NOT consume the challenge or request (§5.2) —
        # the authenticator's try-next-key depends on it.
        rp = self.make_rp()
        rid, challenge, _ = self.start_and_fetch(rp, username="alice")
        bad = self.verify_body(rid, challenge, key=self.mallory)
        self.assertEqual(rp.verify(bad)[0], 401)
        self.assertEqual(rp.verify(self.verify_body(rid, challenge))[0], 200)

    def test_request_single_use_at_verify(self):
        rp = self.make_rp()
        rid, challenge, _ = self.start_and_fetch(rp, username="alice")
        good = self.verify_body(rid, challenge)
        self.assertEqual(rp.verify(good)[0], 200)
        self.assertEqual(rp.verify(good)[0], 404)  # replay of the same verify

    def test_keyless_verify_requires_public_key(self):
        # public_key is REQUIRED when the pending request carries no username
        # (§8.2) — it is the account selector.
        rp = self.make_rp()
        rid, challenge, _ = self.start_and_fetch(rp)
        body = self.verify_body(rid, challenge)
        del body["public_key"]
        status, err = rp.verify(body)
        self.assertEqual(status, 400)
        self.assertEqual(err["error"], "public_key required")

    def test_posted_key_is_selector_only(self):
        # Posting alice's public key with mallory's signature MUST fail:
        # verification runs against the stored key, never the posted one (§5.2).
        rp = self.make_rp()
        rid, challenge, _ = self.start_and_fetch(rp)
        body = self.verify_body(rid, challenge, key=self.mallory,
                                public_key=self.alice.public_key)
        self.assertEqual(rp.verify(body)[0], 401)

    def test_unregistered_key_no_account(self):
        rp = self.make_rp()
        rid, challenge, _ = self.start_and_fetch(rp)
        status, body = rp.verify(self.verify_body(rid, challenge, key=self.mallory))
        self.assertEqual(status, 401)
        self.assertEqual(body["error"], "no account matches key")

    def test_verify_rate_limited(self):
        rp = self.make_rp(verify_rate_limit=(2, 60.0))
        rid, challenge, _ = self.start_and_fetch(rp, username="alice")
        bad = self.verify_body(rid, challenge, key=self.mallory)
        self.assertEqual(rp.verify(bad, source="10.0.0.1")[0], 401)
        self.assertEqual(rp.verify(bad, source="10.0.0.1")[0], 401)
        self.assertEqual(rp.verify(bad, source="10.0.0.1")[0], 429)
        # a different source is not affected
        self.assertEqual(rp.verify(bad, source="10.0.0.2")[0], 401)

    # -- status + browser binding (§5.4) -----------------------------------------

    def test_status_requires_browser_binding(self):
        # Only the initiating browser (nonce bearer) can convert an
        # authenticated request into a session; everyone else sees pending.
        rp = self.make_rp()
        rid, challenge, nonce = self.start_and_fetch(rp, username="alice")
        rp.verify(self.verify_body(rid, challenge))
        self.assertEqual(rp.status(rid, None), ({"status": "pending"}, None))
        self.assertEqual(rp.status(rid, "wrong-nonce"), ({"status": "pending"}, None))
        body, username = rp.status(rid, nonce)
        self.assertEqual((body, username), ({"status": "authenticated"}, "alice"))

    def test_status_single_use(self):
        rp = self.make_rp()
        rid, challenge, nonce = self.start_and_fetch(rp, username="alice")
        rp.verify(self.verify_body(rid, challenge))
        self.assertEqual(rp.status(rid, nonce)[1], "alice")
        self.assertEqual(rp.status(rid, nonce), ({"status": "expired"}, None))

    def test_status_pending_before_verify_and_expired_when_unknown(self):
        rp = self.make_rp()
        rid, _, nonce = self.start_and_fetch(rp, username="alice")
        self.assertEqual(rp.status(rid, nonce), ({"status": "pending"}, None))
        self.assertEqual(rp.status("unknown", nonce), ({"status": "expired"}, None))

    def test_ttl_expiry(self):
        rp = self.make_rp(challenge_ttl=0.05)
        rid, challenge, nonce = self.start_and_fetch(rp, username="alice")
        time.sleep(0.1)
        self.assertEqual(rp.challenge(rid)[0], 404)
        self.assertEqual(rp.verify(self.verify_body(rid, challenge))[0], 404)
        self.assertEqual(rp.status(rid, nonce), ({"status": "expired"}, None))

    # -- app-initiated flow (§8) ---------------------------------------------------

    def app_start_and_verify(self, rp):
        status, body = rp.app_start()
        self.assertEqual(status, 200)
        verify_body = self.verify_body(body["request_id"], body["challenge"])
        self.assertEqual(rp.verify(verify_body)[0], 200)
        return body

    def test_app_start_response_shape(self):
        status, body = self.make_rp().app_start()
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["namespace"], ORIGIN)
        self.assertTrue(body["claim_url"].startswith(ORIGIN + "/wedge/claim?"))
        self.assertIn(body["request_id"], body["claim_url"])

    def test_app_start_rejected_without_selector(self):
        # RPs that need a pre-asserted username MUST reject app-start with an
        # explanatory error (§8.1); Core-only remains conforming (§8).
        rp = self.make_rp(find_user_by_public_key=None)
        status, body = rp.app_start()
        self.assertEqual(status, 404)
        self.assertFalse(body["ok"])
        self.assertIn("not supported", body["error"])

    def test_claim_happy_path_single_use(self):
        rp = self.make_rp()
        body = self.app_start_and_verify(rp)
        token = body["claim_url"].split("claim=")[1]
        self.assertEqual(rp.claim(body["request_id"], token), "alice")
        self.assertIsNone(rp.claim(body["request_id"], token))  # single-use (§8.3)

    def test_claim_rejects_wrong_token_and_unauthenticated(self):
        rp = self.make_rp()
        status, body = rp.app_start()
        token = body["claim_url"].split("claim=")[1]
        self.assertIsNone(rp.claim(body["request_id"], token))  # not yet authenticated
        done = self.app_start_and_verify(rp)
        self.assertIsNone(rp.claim(done["request_id"], "wrong-token"))
        real = done["claim_url"].split("claim=")[1]
        self.assertEqual(rp.claim(done["request_id"], real), "alice")

    def test_app_request_not_pollable_via_status(self):
        # App-initiated requests have no browser binding; polling must never
        # mint (§8: the claim token is the substitute for the binding).
        rp = self.make_rp()
        body = self.app_start_and_verify(rp)
        self.assertEqual(rp.status(body["request_id"], "anything"), ({"status": "pending"}, None))

    # -- construction ---------------------------------------------------------------

    def test_requires_a_lookup_callback(self):
        with self.assertRaises(ValueError):
            WedgeRP(origin=ORIGIN)

    def test_rejects_non_origin(self):
        with self.assertRaises(ValueError):
            WedgeRP(origin="ftp://x", find_keys=lambda u: None)
        with self.assertRaises(ValueError):
            WedgeRP(origin="not a url", find_keys=lambda u: None)


if __name__ == "__main__":
    unittest.main()
