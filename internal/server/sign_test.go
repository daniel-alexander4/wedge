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

	"github.com/daniel-alexander4/wedge/internal/config"
	"github.com/daniel-alexander4/wedge/internal/keyutil"
	"github.com/daniel-alexander4/wedge/internal/rp"
)

// genKey creates a throwaway ed25519 keypair and returns (private, public) paths.
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
	r, w, _ := os.Pipe()
	go func() { w.WriteString(s); w.Close() }()
	return r
}

// stubRP stands in for a relying party: discovery + challenge + real verify.
// If nsOverride is "" it reports namespace == its own origin (the namespace==origin
// contract); a non-empty override lets a test simulate a misbehaving RP.
func stubRP(t *testing.T, nsOverride, pubKey string, verifyHit, contacted *bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	ns := func() string {
		if nsOverride != "" {
			return nsOverride
		}
		return srv.URL
	}
	mux.HandleFunc("/.well-known/wedge.json", func(w http.ResponseWriter, r *http.Request) {
		if contacted != nil {
			*contacted = true
		}
		json.NewEncoder(w).Encode(rp.Discovery{
			Version: 1, Namespace: ns(),
			ChallengeURL: srv.URL + "/ch", VerifyURL: srv.URL + "/verify",
		})
	})
	mux.HandleFunc("/ch", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(rp.Challenge{Challenge: "AbCdEfGhIjKlMnOp_1234", Namespace: ns()})
	})
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		var b rp.VerifyRequest
		json.NewDecoder(r.Body).Decode(&b)
		if sshVerify(t, b.Challenge, b.Signature, b.Namespace, pubKey) {
			*verifyHit = true
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

// newSignServer builds a server with the given sites and a fixed set of
// agent-loaded keys (paths of throwaway private keys), bypassing real discovery.
func newSignServer(t *testing.T, sites []config.Site, keyPaths ...string) *Server {
	t.Helper()
	dir := t.TempDir()
	m, err := config.NewManagerWithPath(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	m.Update(func(c *config.Config) { c.Sites = sites })
	s := New(m, fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("ok")}})
	keys := make([]keyutil.DiscoveredKey, len(keyPaths))
	for i, p := range keyPaths {
		keys[i] = keyutil.DiscoveredKey{Path: p, Comment: filepath.Base(filepath.Dir(p)), Fingerprint: "SHA256:test", AgentLoaded: true}
	}
	s.signableKeys = func() ([]keyutil.DiscoveredKey, error) { return keys, nil }
	return s
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
	rpSrv := stubRP(t, "", string(pubKey), &verifyHit, nil)
	s := newSignServer(t, []config.Site{{Origin: rpSrv.URL}}, priv)

	autoRespond(s, "allow")
	s.runSign("wedge://sign?v=1&origin=" + urlEnc(rpSrv.URL) + "&request_id=req1")

	if !verifyHit {
		t.Fatal("RP verify endpoint was never hit with a valid signature")
	}
	ents := s.log.snapshot()
	if len(ents) != 1 {
		t.Fatalf("expected 1 sign-log entry, got %d", len(ents))
	}
	if ents[0].Namespace != rpSrv.URL || ents[0].Approval != "allow-once" || ents[0].Key == "" {
		t.Errorf("unexpected log entry: %+v", ents[0])
	}
}

func TestSignFlowDenied(t *testing.T) {
	t.Setenv("WEDGE_NO_BROWSER", "1")
	priv, pub := genKey(t)
	pubKey, _ := os.ReadFile(pub)

	var verifyHit bool
	rpSrv := stubRP(t, "", string(pubKey), &verifyHit, nil)
	s := newSignServer(t, []config.Site{{Origin: rpSrv.URL}}, priv)

	autoRespond(s, "deny")
	s.runSign("wedge://sign?v=1&origin=" + urlEnc(rpSrv.URL) + "&request_id=req1")

	if verifyHit {
		t.Error("deny must not deliver a signature")
	}
	if got := len(s.log.snapshot()); got != 0 {
		t.Errorf("deny must not log a sign, got %d", got)
	}
}

func TestSignFlowNewSiteAdded(t *testing.T) {
	t.Setenv("WEDGE_NO_BROWSER", "1")
	priv, pub := genKey(t)
	pubKey, _ := os.ReadFile(pub)

	var verifyHit bool
	rpSrv := stubRP(t, "", string(pubKey), &verifyHit, nil)
	s := newSignServer(t, nil, priv) // origin NOT configured

	autoRespond(s, "add-allow")
	s.runSign("wedge://sign?v=1&origin=" + urlEnc(rpSrv.URL) + "&request_id=req1")

	if !verifyHit {
		t.Fatal("add-allow should have added the site and signed")
	}
	sites := s.configMgr.Get().Sites
	if len(sites) != 1 || sites[0].Origin != rpSrv.URL {
		t.Errorf("new site not persisted: %+v", sites)
	}
}

func TestSignFlowNewSiteDeniedNoNetwork(t *testing.T) {
	t.Setenv("WEDGE_NO_BROWSER", "1")
	priv, pub := genKey(t)
	pubKey, _ := os.ReadFile(pub)

	var verifyHit, contacted bool
	rpSrv := stubRP(t, "", string(pubKey), &verifyHit, &contacted)
	s := newSignServer(t, nil, priv) // origin NOT configured

	autoRespond(s, "deny")
	s.runSign("wedge://sign?v=1&origin=" + urlEnc(rpSrv.URL) + "&request_id=req1")

	if contacted {
		t.Error("declined new site must not contact the RP (no network before Add)")
	}
	if verifyHit {
		t.Error("declined new site must not sign")
	}
	if got := len(s.configMgr.Get().Sites); got != 0 {
		t.Errorf("declined new site must not be added, got %d sites", got)
	}
}

func TestSignFlowRejectsForeignNamespace(t *testing.T) {
	t.Setenv("WEDGE_NO_BROWSER", "1")
	priv, pub := genKey(t)
	pubKey, _ := os.ReadFile(pub)

	var verifyHit bool
	// RP reports a namespace bound to a DIFFERENT origin — must be rejected.
	rpSrv := stubRP(t, "http://evil.example", string(pubKey), &verifyHit, nil)
	s := newSignServer(t, []config.Site{{Origin: rpSrv.URL}}, priv)

	autoRespond(s, "allow")
	s.runSign("wedge://sign?v=1&origin=" + urlEnc(rpSrv.URL) + "&request_id=req1")

	if verifyHit {
		t.Error("a namespace that isn't the origin must be rejected before signing")
	}
}

func TestSignFlowTriesNextKey(t *testing.T) {
	t.Setenv("WEDGE_NO_BROWSER", "1")
	wrongPriv, _ := genKey(t)
	rightPriv, rightPub := genKey(t)
	rightPubKey, _ := os.ReadFile(rightPub)

	var verifyHit bool
	// Only the RIGHT key's public key is registered at the RP.
	rpSrv := stubRP(t, "", string(rightPubKey), &verifyHit, nil)
	// Wrong key first — the RP rejects it, try-next should fall through to the right one.
	s := newSignServer(t, []config.Site{{Origin: rpSrv.URL}}, wrongPriv, rightPriv)

	autoRespond(s, "allow")
	s.runSign("wedge://sign?v=1&origin=" + urlEnc(rpSrv.URL) + "&request_id=req1")

	if !verifyHit {
		t.Fatal("try-next should have fallen through to the accepted key")
	}
	if got := len(s.log.snapshot()); got != 1 {
		t.Fatalf("expected 1 successful sign, got %d", got)
	}
}

func TestSignFlowSilentSkipsConsent(t *testing.T) {
	t.Setenv("WEDGE_NO_BROWSER", "1")
	priv, pub := genKey(t)
	pubKey, _ := os.ReadFile(pub)

	var verifyHit bool
	rpSrv := stubRP(t, "", string(pubKey), &verifyHit, nil)
	s := newSignServer(t, []config.Site{{Origin: rpSrv.URL, Silent: true}}, priv)

	// No autoRespond: a silent site must NOT park a consent request.
	s.runSign("wedge://sign?v=1&origin=" + urlEnc(rpSrv.URL) + "&request_id=req1")

	if !verifyHit {
		t.Fatal("silent site should have signed and delivered")
	}
	if s.consent.head() != nil {
		t.Error("silent site must not park a consent request")
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
