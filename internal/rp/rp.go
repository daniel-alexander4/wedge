// Package rp is wedge's client to a relying-party website: discovery, challenge
// fetch, and signature delivery. Every URL it dials is derived from — and
// constrained same-origin to — the origin wedge already has in its config, so a
// hostile wedge:// link can never redirect wedge's network traffic (no SSRF).
// See docs/wedge-protocol.md §4–§5.
package rp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxBody caps a response body so a hostile/broken RP can't exhaust memory.
const maxBody = 64 << 10

var client = &http.Client{Timeout: 10 * time.Second}

type Discovery struct {
	Version      int    `json:"version"`
	Namespace    string `json:"namespace"`
	Company      string `json:"company,omitempty"`
	ChallengeURL string `json:"challenge_url"`
	VerifyURL    string `json:"verify_url"`
}

type Challenge struct {
	Challenge string `json:"challenge"`
	Namespace string `json:"namespace"`
	Company   string `json:"company,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// VerifyRequest is the body wedge POSTs to the RP's verify_url. It carries no
// username — the RP resolves the principal from request_id (§5).
type VerifyRequest struct {
	RequestID string `json:"request_id"`
	Challenge string `json:"challenge"`
	Namespace string `json:"namespace"`
	Signature string `json:"signature"`
	PublicKey string `json:"public_key,omitempty"`
}

// Discover fetches and validates <origin>/.well-known/wedge.json. origin must be
// a normalized "scheme://host" string. challenge_url and verify_url are required
// to be same-origin with it.
func Discover(ctx context.Context, origin string) (Discovery, error) {
	var d Discovery
	if err := getJSON(ctx, strings.TrimRight(origin, "/")+"/.well-known/wedge.json", &d); err != nil {
		return Discovery{}, err
	}
	if d.Version != 1 {
		return Discovery{}, fmt.Errorf("unsupported discovery version %d", d.Version)
	}
	if !sameOrigin(origin, d.ChallengeURL) {
		return Discovery{}, fmt.Errorf("challenge_url is not same-origin with %s", origin)
	}
	if !sameOrigin(origin, d.VerifyURL) {
		return Discovery{}, fmt.Errorf("verify_url is not same-origin with %s", origin)
	}
	if strings.TrimSpace(d.Namespace) == "" {
		return Discovery{}, fmt.Errorf("discovery is missing namespace")
	}
	return d, nil
}

// FetchChallenge GETs the challenge the RP minted for request_id.
func FetchChallenge(ctx context.Context, challengeURL, requestID string) (Challenge, error) {
	u, err := url.Parse(challengeURL)
	if err != nil {
		return Challenge{}, fmt.Errorf("bad challenge_url: %w", err)
	}
	q := u.Query()
	q.Set("request_id", requestID)
	u.RawQuery = q.Encode()

	var c Challenge
	if err := getJSON(ctx, u.String(), &c); err != nil {
		return Challenge{}, err
	}
	if strings.TrimSpace(c.Challenge) == "" {
		return Challenge{}, fmt.Errorf("challenge response missing challenge")
	}
	return c, nil
}

// Verify POSTs the signature to the RP. A non-2xx or {"ok":false} is an error.
func Verify(ctx context.Context, verifyURL string, req VerifyRequest) error {
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("verify failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var out struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(data, &out); err == nil && !out.OK && out.Error != "" {
		return fmt.Errorf("verify rejected: %s", out.Error)
	}
	return nil
}

func getJSON(ctx context.Context, rawURL string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s: status %d", rawURL, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// sameOrigin reports whether target's scheme://host equals origin's.
func sameOrigin(origin, target string) bool {
	o, err1 := url.Parse(origin)
	t, err2 := url.Parse(target)
	if err1 != nil || err2 != nil || t.Host == "" {
		return false
	}
	return strings.EqualFold(o.Scheme, t.Scheme) && strings.EqualFold(o.Host, t.Host)
}
