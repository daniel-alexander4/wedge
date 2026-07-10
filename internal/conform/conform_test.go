package conform

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/daniel-alexander4/wedge/sdk/go/wedgerp"
)

func requireSSHKeygen(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available")
	}
}

// listenLocal binds a loopback listener first so the RP can be configured
// with its final origin before serving.
func listenLocal(t *testing.T) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln, "http://" + ln.Addr().String()
}

func serveHTTP(t *testing.T, ln net.Listener, h http.Handler) {
	t.Helper()
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
}

// TestHarnessPassesReferenceRP mounts the real wedgerp engine and requires a
// clean sheet: every check runs (no skips) and every MUST passes.
func TestHarnessPassesReferenceRP(t *testing.T) {
	requireSSHKeygen(t)
	key, err := GenerateKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	ln, origin := listenLocal(t)
	users := map[string]string{"conform": key.PublicKey}
	rp, err := wedgerp.New(wedgerp.Config{
		Origin:          origin,
		RegistrationURL: origin + "/register",
		FindKeys: func(username string) ([]string, error) {
			if k, ok := users[username]; ok {
				return []string{k}, nil
			}
			return nil, nil
		},
		FindUserByPublicKey: func(publicKey string) (string, []string, error) {
			for name, k := range users {
				if wedgerp.SameKey(publicKey, k) {
					return name, []string{k}, nil
				}
			}
			return "", nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	serveHTTP(t, ln, wedgerp.Handler(rp, wedgerp.HandlerOptions{
		Login: func(username string, w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: username, Path: "/"})
		},
		RedirectTo:      "/",
		FailureRedirect: "/login",
	}))

	s, err := NewSession(origin, "conform", key, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	rep := Run(s, "test", false)
	for _, c := range rep.Checks {
		if c.Status == Fail {
			t.Errorf("%s %s FAILED: %s", c.ID, c.Name, c.Detail)
		}
		if c.Status == Skip {
			t.Errorf("%s unexpectedly skipped: %s", c.ID, c.Detail)
		}
	}
	if !rep.Passed() {
		t.Error("reference RP reported non-conformant")
	}
	if rep.MustPassed != rep.MustTotal || rep.MustTotal == 0 {
		t.Errorf("MUSTs %d/%d", rep.MustPassed, rep.MustTotal)
	}
}

// TestHarnessFailsBrokenRP mounts a deliberately non-conforming RP (static
// replayable challenge, trusts the echoed challenge field, accepts any
// namespace) and requires the harness to catch each violation — the guard
// against a harness that passes everything.
func TestHarnessFailsBrokenRP(t *testing.T) {
	requireSSHKeygen(t)
	key, err := GenerateKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	ln, origin := listenLocal(t)
	serveHTTP(t, ln, brokenRP(origin, key.PublicKey))

	s, err := NewSession(origin, "", key, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	rep := Run(s, "test", false)
	if rep.Passed() {
		t.Fatal("broken RP passed the harness")
	}
	want := map[string]bool{"V2": false, "V3": false, "V7": false}
	for _, c := range rep.Checks {
		if _, ok := want[c.ID]; ok && c.Status == Fail {
			want[c.ID] = true
		}
	}
	for id, caught := range want {
		if !caught {
			t.Errorf("%s violation not caught", id)
		}
	}
}

// brokenRP is a minimal reference-shape RP with planted conformance bugs.
func brokenRP(origin, registeredKey string) http.Handler {
	var mu sync.Mutex
	requests := map[string]string{} // request_id → challenge (never consumed — V7 bug)

	token := func() string {
		b := make([]byte, 18)
		rand.Read(b)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	writeJSON := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/wedge.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"version": 1, "namespace": origin,
			"challenge_url": origin + "/wedge/challenge",
			"verify_url":    origin + "/wedge/verify",
		})
	})
	mux.HandleFunc("POST /wedge/start", func(w http.ResponseWriter, r *http.Request) {
		id := token()
		mu.Lock()
		requests[id] = token()
		mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "wedge_flow", Value: token(), HttpOnly: true})
		writeJSON(w, 200, map[string]any{"ok": true, "request_id": id})
	})
	mux.HandleFunc("GET /wedge/challenge", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ch, ok := requests[r.URL.Query().Get("request_id")]
		mu.Unlock()
		if !ok {
			writeJSON(w, 404, map[string]any{"ok": false, "error": "unknown request"})
			return
		}
		writeJSON(w, 200, map[string]any{"challenge": ch, "namespace": origin})
	})
	mux.HandleFunc("POST /wedge/verify", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RequestID string `json:"request_id"`
			Challenge string `json:"challenge"`
			Namespace string `json:"namespace"`
			Signature string `json:"signature"`
			PublicKey string `json:"public_key"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		_, ok := requests[body.RequestID]
		mu.Unlock()
		if !ok {
			writeJSON(w, 404, map[string]any{"ok": false, "error": "unknown request"})
			return
		}
		// Planted bugs: verifies the POSTED challenge under the POSTED
		// namespace (V2 + V3), against the posted key if it matches the
		// registered one; never consumes the request (V7).
		if !wedgerp.SameKey(body.PublicKey, registeredKey) {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "no account matches key", "code": "unknown_key"})
			return
		}
		ok, _, err := wedgerp.VerifySignature(body.Challenge, body.Signature, "victim", registeredKey, body.Namespace, 10*time.Second)
		if err != nil || !ok {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "signature verification failed"})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /wedge/app-start", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 404, map[string]any{"ok": false, "error": "not supported"})
	})
	mux.HandleFunc("GET /wedge/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"status": "pending"})
	})
	return mux
}
