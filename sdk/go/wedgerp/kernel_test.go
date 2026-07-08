package wedgerp

import (
	"errors"
	"strings"
	"testing"
)

const (
	testNamespace = "http://127.0.0.1:9413"
	testChallenge = "AbCdEfGhIjKlMnOpQrStUvWx"
)

func TestVerifyAcceptsGoodSignature(t *testing.T) {
	key := newKeyPair(t, "alice@test")
	sig := key.sign(t, testChallenge, testNamespace)
	ok, detail, err := VerifySignature(testChallenge, sig, "alice", key.publicKey, testNamespace, DefaultVerifyTimeout)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("verify failed: %s", detail)
	}
}

func TestVerifyRejectsTamperedInputs(t *testing.T) {
	key := newKeyPair(t, "alice@test")
	other := newKeyPair(t, "mallory@test")
	sig := key.sign(t, testChallenge, testNamespace)
	cases := []struct {
		name                                               string
		challenge, signature, principal, pubkey, namespace string
	}{
		{"wrong namespace", testChallenge, sig, "alice", key.publicKey, "http://evil.example"},
		{"wrong challenge", "NotWhatWasSigned123", sig, "alice", key.publicKey, testNamespace},
		{"wrong key", testChallenge, sig, "alice", other.publicKey, testNamespace},
		{"garbage signature", testChallenge, "-----BEGIN SSH SIGNATURE-----\ngarbage\n-----END SSH SIGNATURE-----", "alice", key.publicKey, testNamespace},
		{"unarmored signature", testChallenge, "AAAA-not-armored", "alice", key.publicKey, testNamespace},
		{"invalid principal", testChallenge, sig, "has space", key.publicKey, testNamespace},
		{"malformed public key", testChallenge, sig, "alice", "one-field", testNamespace},
	}
	for _, c := range cases {
		ok, _, err := VerifySignature(c.challenge, c.signature, c.principal, c.pubkey, c.namespace, DefaultVerifyTimeout)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", c.name, err)
		}
		if ok {
			t.Errorf("%s: verification succeeded, want failure", c.name)
		}
	}
}

func TestVerifyIgnoresPublicKeyComment(t *testing.T) {
	key := newKeyPair(t, "alice@test")
	sig := key.sign(t, testChallenge, testNamespace)
	fields := strings.Fields(key.publicKey)
	renamed := fields[0] + " " + fields[1] + " another@host"
	ok, detail, err := VerifySignature(testChallenge, sig, "alice", renamed, testNamespace, DefaultVerifyTimeout)
	if err != nil || !ok {
		t.Fatalf("verify with renamed comment: ok=%v err=%v detail=%s", ok, err, detail)
	}
}

func TestVerifyReportsMissingKeygen(t *testing.T) {
	key := newKeyPair(t, "alice@test")
	sig := key.sign(t, testChallenge, testNamespace)
	t.Setenv("SSH_KEYGEN_PATH", "/nonexistent/ssh-keygen")
	_, _, err := VerifySignature(testChallenge, sig, "alice", key.publicKey, testNamespace, DefaultVerifyTimeout)
	if !errors.Is(err, ErrSSHKeygenUnavailable) {
		t.Fatalf("want ErrSSHKeygenUnavailable, got %v", err)
	}
}

func TestVerifyReportsAncientKeygen(t *testing.T) {
	key := newKeyPair(t, "alice@test")
	sig := key.sign(t, testChallenge, testNamespace)
	fakeKeygen(t, `echo "ssh-keygen: unknown option -- Y" >&2; exit 1`)
	_, _, err := VerifySignature(testChallenge, sig, "alice", key.publicKey, testNamespace, DefaultVerifyTimeout)
	if !errors.Is(err, ErrSSHKeygenUnavailable) {
		t.Fatalf("want ErrSSHKeygenUnavailable, got %v", err)
	}
}

func TestSplitPublicKeyAndSameKey(t *testing.T) {
	kt, kd, ok := SplitPublicKey("ssh-ed25519 AAAAC3Nza comment here")
	if !ok || kt != "ssh-ed25519" || kd != "AAAAC3Nza" {
		t.Fatalf("SplitPublicKey = %q %q %v", kt, kd, ok)
	}
	if _, _, ok := SplitPublicKey("just-one-field"); ok {
		t.Error("one-field line parsed as key")
	}
	if !SameKey("ssh-ed25519 AAAAC3Nza a@b", "ssh-ed25519 AAAAC3Nza c@d") {
		t.Error("SameKey should ignore comments")
	}
	if SameKey("ssh-ed25519 AAAAC3Nza", "ssh-ed25519 AAAAC3Nzb") {
		t.Error("SameKey matched different key data")
	}
}
