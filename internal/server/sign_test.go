package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"wedge/internal/config"
	"wedge/internal/rp"
)

// genKey creates a throwaway ed25519 keypair and returns the private-key path.
func genKey(t *testing.T) (priv, pub string) {
	t.Helper()
	dir := t.TempDir()
	priv = filepath.Join(dir, "id_ed25519")
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-C", "wedge-test", "-f", priv, "-q")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen unavailable: %v (%s)", err, out)
	}
	return priv, priv + ".pub"
}

// sshVerify mimics the RP's ssh-keygen -Y verify, matching wedge-web.
func sshVerify(t *testing.T, challenge, signature, namespace, pubKey string) bool {
	t.Helper()
	dir := t.TempDir()
	allowed := filepath.Join(dir, "allowed_signers")
	sig := filepath.Join(dir, "sig")
	os.WriteFile(allowed, []byte("tester "+pubKey+"\n"), 0644)
	os.WriteFile(sig, []byte(signature+"\n"), 0644)
	cmd := exec.Command("ssh-keygen", "-Y", "verify", "-f", allowed, "-I", "tester", "-n", namespace, "-s", sig)
	cmd.Stdin = strForReader(challenge)
	return cmd.Run() == nil
}

func strForReader(s string) *os.File {
	// small helper: write to a pipe so ssh-keygen reads challenge on stdin
	r, w, _ := os.Pipe()
	go func() { w.WriteString(s); w.Close() }()
	return r
}

// stubRP stands in for a relying party: discovery + challenge + real verify.
func stubRP(t *testing.T, namespace, pubKey string, hit *bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/wedge.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(rp.Discovery{
			Version: 1, Namespace: namespace,
			ChallengeURL: srv.URL + "/ch", VerifyURL: srv.URL + "/verify",
		})
	})
	mux.HandleFunc("/ch", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(rp.Challenge{Challenge: "AbCdEfGhIjKlMnOp_1234", Namespace: namespace})
	})
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		var b rp.VerifyRequest
		json.NewDecoder(r.Body).Decode(&b)
		if sshVerify(t, b.Challenge, b.Signature, b.Namespace, pubKey) {
			*hit = true
			json.NewEncoder(w).Encode(map[string]any{"ok": true})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "verify failed"})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func signTestServer(t *testing.T, origin, priv string) *Server {
	t.Helper()
	dir := t.TempDir()
	m, err := config.NewManagerWithPath(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	m.Update(func(c *config.Config) {
		c.KeyPath = priv
		c.AllowedOrigins = []string{origin}
		c.OriginScopes = map[string][]config.OriginScope{origin: {{Namespace: "ns"}}}
	})
	web := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("ok")}}
	return New(m, web)
}

// autoRespond waits for a parked consent and answers it.
func autoRespond(s *Server, decision string) {
	go func() {
		for i := 0; i < 500; i++ {
			if p := s.consent.head(); p != nil {
				s.consent.respond(p.ID, decision)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
}

func TestSignFlowEndToEnd(t *testing.T) {
	t.Setenv("WEDGE_NO_BROWSER", "1")
	priv, pub := genKey(t)
	pubKey, _ := os.ReadFile(pub)

	var verifyHit bool
	rpSrv := stubRP(t, "ns", string(pubKey), &verifyHit)
	s := signTestServer(t, rpSrv.URL, priv)

	autoRespond(s, "allow")
	s.runSign("wedge://sign?v=1&origin=" + urlEnc(rpSrv.URL) + "&request_id=req1")

	if !verifyHit {
		t.Fatal("RP verify endpoint was never hit with a valid signature")
	}
	if got := len(s.log.snapshot()); got != 1 {
		t.Fatalf("expected 1 sign-log entry, got %d", got)
	}
	if ent := s.log.snapshot()[0]; ent.Namespace != "ns" || ent.Approval != "allow-once" {
		t.Errorf("unexpected log entry: %+v", ent)
	}
}

func TestSignFlowDenied(t *testing.T) {
	t.Setenv("WEDGE_NO_BROWSER", "1")
	priv, pub := genKey(t)
	pubKey, _ := os.ReadFile(pub)

	var verifyHit bool
	rpSrv := stubRP(t, "ns", string(pubKey), &verifyHit)
	s := signTestServer(t, rpSrv.URL, priv)

	autoRespond(s, "deny")
	s.runSign("wedge://sign?v=1&origin=" + urlEnc(rpSrv.URL) + "&request_id=req1")

	if verifyHit {
		t.Error("deny must not deliver a signature")
	}
	if got := len(s.log.snapshot()); got != 0 {
		t.Errorf("deny must not log a sign, got %d", got)
	}
}

func TestSignFlowUnconfiguredOriginNoNetwork(t *testing.T) {
	t.Setenv("WEDGE_NO_BROWSER", "1")
	priv, _ := genKey(t)
	// Origin not in the allowlist -> must return immediately, never parking consent.
	s := signTestServer(t, "https://acme.example", priv)
	autoRespond(s, "allow") // should never fire
	s.runSign("wedge://sign?v=1&origin=" + urlEnc("https://evil.example") + "&request_id=req1")
	if p := s.consent.head(); p != nil {
		t.Error("unconfigured origin must not park a consent request")
	}
}

func TestSignFlowSilentSkipsConsent(t *testing.T) {
	t.Setenv("WEDGE_NO_BROWSER", "1")
	priv, pub := genKey(t)
	pubKey, _ := os.ReadFile(pub)

	var verifyHit bool
	rpSrv := stubRP(t, "ns", string(pubKey), &verifyHit)

	dir := t.TempDir()
	m, err := config.NewManagerWithPath(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	m.Update(func(c *config.Config) {
		c.KeyPath = priv
		c.AllowedOrigins = []string{rpSrv.URL}
		// silent = the advanced per-site opt-in: sign without a presence tap.
		c.OriginScopes = map[string][]config.OriginScope{rpSrv.URL: {{Namespace: "ns", Silent: true}}}
	})
	s := New(m, fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("ok")}})

	// No autoRespond: a silent scope must NOT park a consent request.
	s.runSign("wedge://sign?v=1&origin=" + urlEnc(rpSrv.URL) + "&request_id=req1")

	if !verifyHit {
		t.Fatal("silent scope should have signed and delivered")
	}
	if s.consent.head() != nil {
		t.Error("silent scope must not park a consent request")
	}
	if ents := s.log.snapshot(); len(ents) != 1 || ents[0].Approval != "silent" {
		t.Errorf("expected one 'silent' log entry, got %+v", ents)
	}
}

func TestConsentBrokerRespond(t *testing.T) {
	b := newConsentBroker()
	p := &pendingSign{ID: "x", decision: make(chan string, 1)}
	b.park(p)
	if b.head() == nil {
		t.Fatal("expected head after park")
	}
	if !b.respond("x", "allow") {
		t.Fatal("respond should succeed")
	}
	if got := <-p.decision; got != "allow" {
		t.Errorf("decision = %q", got)
	}
	if b.head() != nil {
		t.Error("queue should be empty after respond")
	}
	if b.respond("missing", "deny") {
		t.Error("respond on unknown id should be false")
	}
}

func urlEnc(s string) string {
	// minimal query-escape for the origin
	out := ""
	for _, r := range s {
		switch r {
		case ':':
			out += "%3A"
		case '/':
			out += "%2F"
		default:
			out += string(r)
		}
	}
	return out
}
