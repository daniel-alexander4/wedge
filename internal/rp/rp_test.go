package rp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func stubRP(t *testing.T, discovery func(origin string) Discovery) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/wedge.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(discovery(srv.URL))
	})
	mux.HandleFunc("/ch", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Challenge{Challenge: "AbCdEfGhIjKlMnOp_1234", Namespace: "ns"})
	})
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestDiscoverAndChallenge(t *testing.T) {
	srv := stubRP(t, func(origin string) Discovery {
		return Discovery{Version: 1, Namespace: "ns", ChallengeURL: origin + "/ch", VerifyURL: origin + "/verify"}
	})
	d, err := Discover(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if d.Namespace != "ns" {
		t.Errorf("namespace = %q", d.Namespace)
	}
	ch, err := FetchChallenge(context.Background(), d.ChallengeURL, "req1")
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	if ch.Challenge == "" {
		t.Error("empty challenge")
	}
}

func TestDiscoverRejectsCrossOriginURLs(t *testing.T) {
	srv := stubRP(t, func(origin string) Discovery {
		// verify_url points at a different origin — must be rejected (SSRF guard).
		return Discovery{Version: 1, Namespace: "ns", ChallengeURL: origin + "/ch", VerifyURL: "https://evil.example/verify"}
	})
	if _, err := Discover(context.Background(), srv.URL); err == nil {
		t.Error("expected cross-origin verify_url to be rejected")
	}
}

func TestVerifyRejectsNon2xx(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "nope"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if err := Verify(context.Background(), srv.URL+"/verify", VerifyRequest{RequestID: "r"}); err == nil {
		t.Error("expected error on 400")
	}
}
