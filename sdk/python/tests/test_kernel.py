import os
import unittest
from unittest import mock

from wedge_rp.kernel import SSHKeygenUnavailable, same_key, split_public_key, verify_signature

from helpers import HAVE_SSH_KEYGEN, KeyPair

NAMESPACE = "http://127.0.0.1:9411"
CHALLENGE = "AbCdEfGhIjKlMnOpQrStUvWx"


@unittest.skipUnless(HAVE_SSH_KEYGEN, "ssh-keygen not installed")
class KernelTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = KeyPair()
        cls.other = KeyPair()
        cls.sig = cls.key.sign(CHALLENGE, NAMESPACE)

    @classmethod
    def tearDownClass(cls):
        cls.key.close()
        cls.other.close()

    def verify(self, **overrides):
        params = dict(
            challenge=CHALLENGE,
            signature=self.sig,
            principal="alice",
            public_key=self.key.public_key,
            namespace=NAMESPACE,
        )
        params.update(overrides)
        return verify_signature(params.pop("challenge"), params.pop("signature"), **params)

    def test_good_signature(self):
        ok, detail = self.verify()
        self.assertTrue(ok, detail)

    def test_wrong_namespace_rejected(self):
        ok, _ = self.verify(namespace="http://evil.example")
        self.assertFalse(ok)

    def test_wrong_challenge_rejected(self):
        ok, _ = self.verify(challenge="NotWhatWasSigned123")
        self.assertFalse(ok)

    def test_wrong_key_rejected(self):
        ok, _ = self.verify(public_key=self.other.public_key)
        self.assertFalse(ok)

    def test_garbage_signature_rejected(self):
        ok, detail = self.verify(signature="-----BEGIN SSH SIGNATURE-----\ngarbage\n-----END SSH SIGNATURE-----")
        self.assertFalse(ok, detail)

    def test_unarmored_signature_rejected_without_subprocess(self):
        ok, detail = self.verify(signature="AAAA-not-armored")
        self.assertFalse(ok)
        self.assertEqual(detail, "malformed signature")

    def test_key_comment_ignored(self):
        ok, detail = self.verify(public_key=self.key.public_key + " renamed-comment")
        # the original line already has a comment; replacing it must not matter
        fields = self.key.public_key.split()
        ok2, _ = self.verify(public_key=f"{fields[0]} {fields[1]} another@host")
        self.assertTrue(ok, detail)
        self.assertTrue(ok2)

    def test_invalid_principal_rejected(self):
        ok, detail = self.verify(principal="has space")
        self.assertFalse(ok)
        self.assertEqual(detail, "invalid principal")

    def test_missing_ssh_keygen_raises(self):
        with mock.patch.dict(os.environ, {"PATH": "/nonexistent"}):
            with self.assertRaises(SSHKeygenUnavailable):
                self.verify()


class KeyParsingTest(unittest.TestCase):
    def test_split_public_key(self):
        self.assertEqual(
            split_public_key("ssh-ed25519 AAAAC3Nza comment here"),
            ("ssh-ed25519", "AAAAC3Nza"),
        )
        self.assertIsNone(split_public_key("just-one-field"))
        self.assertIsNone(split_public_key(""))

    def test_same_key_ignores_comment(self):
        self.assertTrue(same_key("ssh-ed25519 AAAAC3Nza a@b", "ssh-ed25519 AAAAC3Nza c@d"))
        self.assertFalse(same_key("ssh-ed25519 AAAAC3Nza", "ssh-ed25519 AAAAC3Nzb"))


if __name__ == "__main__":
    unittest.main()
