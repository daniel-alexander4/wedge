package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"wedge/internal/config"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	m, err := config.NewManagerWithPath(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	m.Update(func(c *config.Config) {
		c.Sites = []config.Site{{Origin: "https://acme.example"}}
	})
	web := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>ok</html>")}}
	return New(m, web)
}

// loopbackReq builds a request that passes the loopback guard (loopback peer +
// loopback Host). Callers tweak method/headers to exercise the guards.
func loopbackReq(method, target string, body string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	r.RemoteAddr = "127.0.0.1:54321"
	r.Host = "127.0.0.1:7890"
	if method != http.MethodGet {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://127.0.0.1:7890") // same-origin
	}
	return r
}

func serve(s *Server, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, r)
	return w
}

func TestGetConfig(t *testing.T) {
	s := testServer(t)
	w := serve(s, loopbackReq(http.MethodGet, "/api/config", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var cfg config.Config
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(cfg.Sites) != 1 || cfg.Sites[0].Origin != "https://acme.example" {
		t.Errorf("unexpected sites: %v", cfg.Sites)
	}
}

func TestPostConfigRoundTrip(t *testing.T) {
	s := testServer(t)
	body := `{"enabled":true,"sites":[{"origin":"https://beta.example","alwaysAllow":true}],"serverPort":7890}`
	w := serve(s, loopbackReq(http.MethodPost, "/api/config", body))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	got := s.configMgr.Get()
	if len(got.Sites) != 1 || got.Sites[0].Origin != "https://beta.example" || !got.Sites[0].AlwaysAllow {
		t.Errorf("sites not round-tripped: %+v", got.Sites)
	}
}

func TestLoopbackGuardRejectsNonLoopbackPeer(t *testing.T) {
	s := testServer(t)
	r := loopbackReq(http.MethodGet, "/api/config", "")
	r.RemoteAddr = "203.0.113.7:40000" // public peer
	if w := serve(s, r); w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-loopback peer, got %d", w.Code)
	}
}

func TestLoopbackGuardRejectsRebindHost(t *testing.T) {
	s := testServer(t)
	r := loopbackReq(http.MethodGet, "/api/config", "")
	r.Host = "attacker.example" // loopback socket, attacker Host (DNS rebinding)
	if w := serve(s, r); w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-loopback Host, got %d", w.Code)
	}
}

func TestCSRFRejectsCrossOrigin(t *testing.T) {
	s := testServer(t)
	r := loopbackReq(http.MethodPost, "/api/config", `{"enabled":true}`)
	r.Header.Set("Origin", "https://evil.example") // cross-site
	if w := serve(s, r); w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for cross-origin POST, got %d", w.Code)
	}
}

func TestKeysEndpoint(t *testing.T) {
	s := testServer(t)
	w := serve(s, loopbackReq(http.MethodGet, "/api/keys", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	// The list content depends on the host's ~/.ssh, but the shape must be a
	// (possibly empty) array — never null or an error.
	if resp.Keys == nil {
		t.Error("expected a keys array (possibly empty), got null")
	}
}

func TestSignLogEmpty(t *testing.T) {
	s := testServer(t)
	w := serve(s, loopbackReq(http.MethodGet, "/api/signlog", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Entries []SignLogEntry `json:"entries"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Entries) != 0 {
		t.Errorf("expected empty sign log, got %d entries", len(resp.Entries))
	}
}

func TestSignLogAppendBounded(t *testing.T) {
	l := &signLog{}
	for i := 0; i < signLogCap+50; i++ {
		l.Append(SignLogEntry{Origin: "https://acme.example"})
	}
	if got := len(l.snapshot()); got != signLogCap {
		t.Errorf("expected sign log bounded at %d, got %d", signLogCap, got)
	}
}
