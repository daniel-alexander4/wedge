package wedgerp

// Spec-conformance tests for the RP engine — a test-for-test port of
// sdk/python/tests/test_core.py and sdk/node/tests/core.test.js (keep the
// three suites in lockstep). Each test names the wedge-spec-v1.md requirement
// it pins down; signatures are real SSHSIG made by ssh-keygen.

import (
	"regexp"
	"strings"
	"testing"
	"time"

	wire "github.com/daniel-alexander4/wedge/internal/rp"
)

const testOrigin = "http://127.0.0.1:9413"

type fixture struct {
	rp      *RP
	alice   keyPair
	mallory keyPair
}

func newFixture(t *testing.T, mutate ...func(*Config)) *fixture {
	t.Helper()
	alice := newKeyPair(t, "alice@test")
	mallory := newKeyPair(t, "mallory@test")
	users := map[string]string{"alice": alice.publicKey}
	cfg := Config{
		Origin: testOrigin,
		FindKeys: func(username string) ([]string, error) {
			if key, ok := users[username]; ok {
				return []string{key}, nil
			}
			return nil, nil
		},
		FindUserByPublicKey: func(posted string) (string, []string, error) {
			for name, key := range users {
				if SameKey(key, posted) {
					return name, []string{key}, nil
				}
			}
			return "", nil, nil
		},
	}
	for _, m := range mutate {
		m(&cfg)
	}
	rp, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{rp: rp, alice: alice, mallory: mallory}
}

// startAndFetch runs start + challenge fetch: (requestID, challenge, nonce).
func (f *fixture) startAndFetch(t *testing.T, username string) (string, string, string) {
	t.Helper()
	status, body, nonce := f.rp.Start(username)
	if status != 200 {
		t.Fatalf("start: %d %+v", status, body)
	}
	rid := body.(StartBody).RequestID
	cstatus, cbody := f.rp.Challenge(rid)
	if cstatus != 200 {
		t.Fatalf("challenge: %d %+v", cstatus, cbody)
	}
	return rid, cbody.(wire.Challenge).Challenge, nonce
}

func (f *fixture) verifyReq(t *testing.T, rid, challenge string, signer keyPair, namespace string) wire.VerifyRequest {
	t.Helper()
	return wire.VerifyRequest{
		RequestID: rid,
		Challenge: challenge,
		Namespace: namespace,
		Signature: signer.sign(t, challenge, namespace),
		PublicKey: signer.publicKey,
	}
}

// -- discovery (§4) + link (§3) --------------------------------------------------

func TestDiscoveryDocument(t *testing.T) {
	f := newFixture(t)
	doc := f.rp.Discovery()
	if doc.Version != 1 || doc.Namespace != testOrigin ||
		doc.ChallengeURL != testOrigin+"/wedge/challenge" ||
		doc.VerifyURL != testOrigin+"/wedge/verify" {
		t.Fatalf("discovery = %+v", doc) // namespace == canonical origin (§6.1)
	}
}

func TestSignLinkFormat(t *testing.T) {
	f := newFixture(t)
	_, body, _ := f.rp.Start("")
	sb := body.(StartBody)
	want := "wedge://sign?v=1&origin=http%3A%2F%2F127.0.0.1%3A9413&request_id=" + sb.RequestID
	if sb.Link != want {
		t.Fatalf("link = %s, want %s", sb.Link, want)
	}
}

// -- start ------------------------------------------------------------------------

func TestKeylessStartNeedsSelectorCallback(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.FindUserByPublicKey = nil })
	status, _, nonce := f.rp.Start("")
	if status != 400 || nonce != "" {
		t.Fatalf("status=%d nonce=%q", status, nonce)
	}
}

func TestUsernameStartNeedsFindKeys(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.FindKeys = nil })
	if status, _, _ := f.rp.Start("alice"); status != 400 {
		t.Fatalf("status = %d", status)
	}
}

// -- challenge (§5.1, §6.2) ---------------------------------------------------------

func TestChallengeUnknownRequest(t *testing.T) {
	f := newFixture(t)
	if status, _ := f.rp.Challenge("nope"); status != 404 {
		t.Fatalf("status = %d", status)
	}
}

func TestChallengeFormat(t *testing.T) {
	f := newFixture(t)
	_, challenge, _ := f.startAndFetch(t, "alice")
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}$`).MatchString(challenge) {
		t.Fatalf("challenge %q fails §6.2 format", challenge)
	}
}

func TestChallengeGoneAfterAuthentication(t *testing.T) {
	f := newFixture(t)
	rid, challenge, _ := f.startAndFetch(t, "alice")
	if status, _ := f.rp.Verify(f.verifyReq(t, rid, challenge, f.alice, testOrigin), ""); status != 200 {
		t.Fatal("verify failed")
	}
	if status, _ := f.rp.Challenge(rid); status != 404 {
		t.Fatal("used request still serves its challenge (§5.1)")
	}
}

// -- verify (§5.2) --------------------------------------------------------------------

func TestVerifyHappyPathUsernameFlow(t *testing.T) {
	f := newFixture(t)
	rid, challenge, _ := f.startAndFetch(t, "alice")
	status, body := f.rp.Verify(f.verifyReq(t, rid, challenge, f.alice, testOrigin), "")
	if status != 200 {
		t.Fatalf("verify: %d %+v", status, body)
	}
}

func TestVerifyUnknownRequest(t *testing.T) {
	f := newFixture(t)
	_, challenge, _ := f.startAndFetch(t, "alice")
	req := f.verifyReq(t, "unknown-id", challenge, f.alice, testOrigin)
	if status, _ := f.rp.Verify(req, ""); status != 404 {
		t.Fatal("unknown request not 404")
	}
}

func TestVerifyChecksStoredChallengeNotEcho(t *testing.T) {
	// RP MUST verify against the challenge it stored, never the echoed field
	// (§5.2 item 2) — a wrong echo with a good signature still passes.
	f := newFixture(t)
	rid, challenge, _ := f.startAndFetch(t, "alice")
	req := f.verifyReq(t, rid, challenge, f.alice, testOrigin)
	req.Challenge = "Definitely_Not_The_Challenge"
	if status, _ := f.rp.Verify(req, ""); status != 200 {
		t.Fatal("echoed challenge was trusted")
	}
}

func TestVerifyRejectsSignatureOverWrongChallenge(t *testing.T) {
	f := newFixture(t)
	rid, _, _ := f.startAndFetch(t, "alice")
	req := f.verifyReq(t, rid, "NotTheMintedChallenge123", f.alice, testOrigin)
	if status, _ := f.rp.Verify(req, ""); status != 401 {
		t.Fatal("signature over wrong bytes accepted")
	}
}

func TestVerifyNamespaceMismatch(t *testing.T) {
	f := newFixture(t)
	rid, challenge, _ := f.startAndFetch(t, "alice")
	req := f.verifyReq(t, rid, challenge, f.alice, "http://evil.example")
	if status, _ := f.rp.Verify(req, ""); status != 400 {
		t.Fatal("foreign namespace accepted")
	}
}

func TestVerifyAcceptsLocalhostAliasNamespace(t *testing.T) {
	// localhost ↔ 127.0.0.1 with same scheme/port are equivalent (§6.1);
	// -n must get the alias string the authenticator actually signed.
	f := newFixture(t)
	rid, challenge, _ := f.startAndFetch(t, "alice")
	req := f.verifyReq(t, rid, challenge, f.alice, "http://localhost:9413")
	if status, body := f.rp.Verify(req, ""); status != 200 {
		t.Fatalf("alias namespace rejected: %d %+v", status, body)
	}
}

func TestFailedVerifyConsumesNothing(t *testing.T) {
	// A failed verify MUST NOT consume the challenge or request (§5.2) — the
	// authenticator's try-next-key depends on it.
	f := newFixture(t)
	rid, challenge, _ := f.startAndFetch(t, "alice")
	bad := f.verifyReq(t, rid, challenge, f.mallory, testOrigin)
	bad.PublicKey = "" // username-carrying flow: key resolved from the account
	if status, _ := f.rp.Verify(bad, ""); status != 401 {
		t.Fatal("mallory's signature accepted")
	}
	if status, _ := f.rp.Verify(f.verifyReq(t, rid, challenge, f.alice, testOrigin), ""); status != 200 {
		t.Fatal("failed verify consumed the request")
	}
}

func TestRequestSingleUseAtVerify(t *testing.T) {
	f := newFixture(t)
	rid, challenge, _ := f.startAndFetch(t, "alice")
	req := f.verifyReq(t, rid, challenge, f.alice, testOrigin)
	if status, _ := f.rp.Verify(req, ""); status != 200 {
		t.Fatal("first verify failed")
	}
	if status, _ := f.rp.Verify(req, ""); status != 404 {
		t.Fatal("verify replay accepted")
	}
}

func TestKeylessVerifyRequiresPublicKey(t *testing.T) {
	// public_key is REQUIRED when the pending request carries no username
	// (§8.2) — it is the account selector.
	f := newFixture(t)
	rid, challenge, _ := f.startAndFetch(t, "")
	req := f.verifyReq(t, rid, challenge, f.alice, testOrigin)
	req.PublicKey = ""
	status, body := f.rp.Verify(req, "")
	if status != 400 || !strings.Contains(body.(errorBody).Error, "public_key") {
		t.Fatalf("status=%d body=%+v", status, body)
	}
}

func TestPostedKeyIsSelectorOnly(t *testing.T) {
	// Posting alice's public key with mallory's signature MUST fail:
	// verification runs against the stored key, never the posted one (§5.2).
	f := newFixture(t)
	rid, challenge, _ := f.startAndFetch(t, "")
	req := f.verifyReq(t, rid, challenge, f.mallory, testOrigin)
	req.PublicKey = f.alice.publicKey
	if status, _ := f.rp.Verify(req, ""); status != 401 {
		t.Fatal("posted key was trusted for verification")
	}
}

func TestUnregisteredKeyNoAccount(t *testing.T) {
	f := newFixture(t)
	rid, challenge, _ := f.startAndFetch(t, "")
	req := f.verifyReq(t, rid, challenge, f.mallory, testOrigin)
	status, body := f.rp.Verify(req, "")
	if status != 401 || !strings.Contains(body.(errorBody).Error, "no account") {
		t.Fatalf("status=%d body=%+v", status, body)
	}
}

func TestVerifyRateLimitedPerSource(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RateLimitAttempts = 2; c.RateLimitWindow = time.Minute })
	rid, challenge, _ := f.startAndFetch(t, "alice")
	bad := f.verifyReq(t, rid, challenge, f.mallory, testOrigin)
	bad.PublicKey = ""
	for i, want := range []int{401, 401, 429} {
		if status, _ := f.rp.Verify(bad, "10.0.0.1"); status != want {
			t.Fatalf("attempt %d: status=%d want %d", i+1, status, want)
		}
	}
	if status, _ := f.rp.Verify(bad, "10.0.0.2"); status != 401 {
		t.Fatal("different source rate-limited")
	}
}

// -- status + browser binding (§5.4) ---------------------------------------------------

func TestStatusRequiresBrowserBinding(t *testing.T) {
	// Only the initiating browser (nonce bearer) can convert an authenticated
	// request into a session; everyone else sees pending.
	f := newFixture(t)
	rid, challenge, nonce := f.startAndFetch(t, "alice")
	_, _ = f.rp.Verify(f.verifyReq(t, rid, challenge, f.alice, testOrigin), "")
	if body, u := f.rp.Status(rid, ""); body.Status != "pending" || u != "" {
		t.Fatal("no-cookie poll leaked authentication")
	}
	if body, u := f.rp.Status(rid, "wrong-nonce"); body.Status != "pending" || u != "" {
		t.Fatal("wrong-nonce poll leaked authentication")
	}
	if body, u := f.rp.Status(rid, nonce); body.Status != "authenticated" || u != "alice" {
		t.Fatalf("bound poll: %+v %q", body, u)
	}
}

func TestStatusSingleUse(t *testing.T) {
	f := newFixture(t)
	rid, challenge, nonce := f.startAndFetch(t, "alice")
	_, _ = f.rp.Verify(f.verifyReq(t, rid, challenge, f.alice, testOrigin), "")
	if _, u := f.rp.Status(rid, nonce); u != "alice" {
		t.Fatal("first bound poll did not mint")
	}
	if body, u := f.rp.Status(rid, nonce); body.Status != "expired" || u != "" {
		t.Fatal("request survived session minting (§5.4 single-use)")
	}
}

func TestStatusPendingAndExpired(t *testing.T) {
	f := newFixture(t)
	rid, _, nonce := f.startAndFetch(t, "alice")
	if body, _ := f.rp.Status(rid, nonce); body.Status != "pending" {
		t.Fatal("fresh request not pending")
	}
	if body, _ := f.rp.Status("unknown", nonce); body.Status != "expired" {
		t.Fatal("unknown request not expired")
	}
}

func TestTTLExpiry(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.ChallengeTTL = 50 * time.Millisecond })
	rid, challenge, nonce := f.startAndFetch(t, "alice")
	time.Sleep(100 * time.Millisecond)
	if status, _ := f.rp.Challenge(rid); status != 404 {
		t.Fatal("expired challenge served")
	}
	if status, _ := f.rp.Verify(f.verifyReq(t, rid, challenge, f.alice, testOrigin), ""); status != 404 {
		t.Fatal("expired request verified")
	}
	if body, _ := f.rp.Status(rid, nonce); body.Status != "expired" {
		t.Fatal("expired request not reported expired")
	}
}

// -- app-initiated flow (§8) ---------------------------------------------------------------

func (f *fixture) appStartAndVerify(t *testing.T) AppStartBody {
	t.Helper()
	status, body := f.rp.AppStart()
	if status != 200 {
		t.Fatalf("app-start: %d %+v", status, body)
	}
	started := body.(AppStartBody)
	req := f.verifyReq(t, started.RequestID, started.Challenge, f.alice, started.Namespace)
	if vstatus, vbody := f.rp.Verify(req, ""); vstatus != 200 {
		t.Fatalf("app verify: %d %+v", vstatus, vbody)
	}
	return started
}

func claimTokenOf(t *testing.T, claimURL string) string {
	t.Helper()
	_, token, ok := strings.Cut(claimURL, "claim=")
	if !ok {
		t.Fatalf("no claim token in %s", claimURL)
	}
	return token
}

func TestAppStartResponseShape(t *testing.T) {
	f := newFixture(t)
	status, body := f.rp.AppStart()
	started := body.(AppStartBody)
	if status != 200 || !started.OK || started.Namespace != testOrigin ||
		!strings.HasPrefix(started.ClaimURL, testOrigin+"/wedge/claim?") ||
		!strings.Contains(started.ClaimURL, started.RequestID) {
		t.Fatalf("app-start = %d %+v", status, started)
	}
}

func TestAppStartRejectedWithoutSelector(t *testing.T) {
	// RPs that need a pre-asserted username MUST reject app-start with an
	// explanatory error (§8.1); Core-only remains conforming (§8).
	f := newFixture(t, func(c *Config) { c.FindUserByPublicKey = nil })
	status, body := f.rp.AppStart()
	if status != 404 || !strings.Contains(body.(errorBody).Error, "not supported") {
		t.Fatalf("app-start = %d %+v", status, body)
	}
}

func TestClaimHappyPathSingleUse(t *testing.T) {
	f := newFixture(t)
	started := f.appStartAndVerify(t)
	token := claimTokenOf(t, started.ClaimURL)
	if u, ok := f.rp.Claim(started.RequestID, token); !ok || u != "alice" {
		t.Fatalf("claim: %q %v", u, ok)
	}
	if _, ok := f.rp.Claim(started.RequestID, token); ok {
		t.Fatal("claim replay minted (§8.3 single-use)")
	}
}

func TestClaimRejectsWrongTokenAndUnauthenticated(t *testing.T) {
	f := newFixture(t)
	_, body := f.rp.AppStart()
	fresh := body.(AppStartBody)
	if _, ok := f.rp.Claim(fresh.RequestID, claimTokenOf(t, fresh.ClaimURL)); ok {
		t.Fatal("unauthenticated claim minted")
	}
	done := f.appStartAndVerify(t)
	if _, ok := f.rp.Claim(done.RequestID, "wrong-token"); ok {
		t.Fatal("wrong token claimed")
	}
	if u, ok := f.rp.Claim(done.RequestID, claimTokenOf(t, done.ClaimURL)); !ok || u != "alice" {
		t.Fatal("valid claim rejected after wrong-token attempt")
	}
}

func TestAppRequestNotPollableViaStatus(t *testing.T) {
	// App-initiated requests have no browser binding; polling must never mint
	// (§8: the claim token is the substitute for the binding).
	f := newFixture(t)
	started := f.appStartAndVerify(t)
	if body, u := f.rp.Status(started.RequestID, "anything"); body.Status != "pending" || u != "" {
		t.Fatal("app request minted via status poll")
	}
}

// -- construction ------------------------------------------------------------------------

func TestNewRequiresALookupCallback(t *testing.T) {
	if _, err := New(Config{Origin: testOrigin}); err == nil {
		t.Fatal("no-callback config accepted")
	}
}

func TestNewRejectsNonOrigin(t *testing.T) {
	for _, origin := range []string{"ftp://x", "not a url", ""} {
		if _, err := New(Config{Origin: origin, FindKeys: func(string) ([]string, error) { return nil, nil }}); err == nil {
			t.Errorf("origin %q accepted", origin)
		}
	}
}
