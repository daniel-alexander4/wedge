package rp

import (
	"context"
	"encoding/json"
	"errors"
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

func TestDiscoverRegistrationURL(t *testing.T) {
	// Same-origin registration_url is kept.
	srv := stubRP(t, func(origin string) Discovery {
		return Discovery{Version: 1, Namespace: "ns", ChallengeURL: origin + "/ch", VerifyURL: origin + "/verify", RegistrationURL: origin + "/register"}
	})
	d, err := Discover(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if d.RegistrationURL != srv.URL+"/register" {
		t.Errorf("registration_url = %q", d.RegistrationURL)
	}

	// A foreign-origin registration_url is advisory: dropped, not fatal (spec §4).
	srv2 := stubRP(t, func(origin string) Discovery {
		return Discovery{Version: 1, Namespace: "ns", ChallengeURL: origin + "/ch", VerifyURL: origin + "/verify", RegistrationURL: "https://evil.example/register"}
	})
	d2, err := Discover(context.Background(), srv2.URL)
	if err != nil {
		t.Fatalf("discover with bad registration_url must not fail: %v", err)
	}
	if d2.RegistrationURL != "" {
		t.Errorf("foreign registration_url survived: %q", d2.RegistrationURL)
	}
}

func TestVerifyUnknownKeyCode(t *testing.T) {
	mux := http.NewServeMux()
	code := "unknown_key"
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "no account matches key", "code": code})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// The spec's unknown_key code surfaces as ErrUnknownKey.
	err := Verify(context.Background(), srv.URL+"/verify", VerifyRequest{RequestID: "r"})
	if !errors.Is(err, ErrUnknownKey) {
		t.Errorf("expected ErrUnknownKey, got %v", err)
	}

	// An unrecognized code is still a plain failure, not ErrUnknownKey.
	code = "something_else"
	err = Verify(context.Background(), srv.URL+"/verify", VerifyRequest{RequestID: "r"})
	if err == nil || errors.Is(err, ErrUnknownKey) {
		t.Errorf("unrecognized code must fail without ErrUnknownKey, got %v", err)
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

func TestStartApp(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server
	// claimHost controls whether the returned claim_url is same-origin.
	claimHost := ""
	mux.HandleFunc("/wedge/app-start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		host := srv.URL
		if claimHost != "" {
			host = claimHost
		}
		json.NewEncoder(w).Encode(map[string]any{
			"ok":         true,
			"request_id": "rid1",
			"challenge":  "AbCdEfGhIjKlMnOp_1234",
			"namespace":  "ns",
			"claim_url":  host + "/wedge/claim?request_id=rid1&claim=tok",
		})
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	// Same-origin claim_url is accepted.
	got, err := StartApp(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("StartApp: %v", err)
	}
	if got.RequestID != "rid1" || got.Challenge == "" {
		t.Errorf("unexpected AppStart: %+v", got)
	}

	// A claim_url on a foreign host must be rejected (anti-gadget / SSRF guard).
	claimHost = "https://evil.example.com"
	if _, err := StartApp(context.Background(), srv.URL); err == nil {
		t.Error("expected StartApp to reject a foreign-origin claim_url")
	}
}
