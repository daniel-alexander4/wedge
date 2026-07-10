// Package conform is the wedge protocol conformance harness: a black-box
// client that drives any RP implementation over HTTP in the authenticator
// role and asserts every wire-observable RP requirement of
// docs/wedge-spec-v1.md. MUST failures are conformance failures; SHOULDs
// report as warnings. Requirements that are not black-box-observable
// (CSPRNG entropy bounds, constant-time comparison, "never embed the claim
// URL in content") are listed explicitly rather than silently dropped.
//
// The browser-facing start/status endpoints are deliberately non-normative
// (spec §5.4: "shape is the RP's choice"), so the harness drives them in the
// reference shape spoken by wedge.js and all wedge-rp SDKs; against an RP
// with a custom start shape, supply a StartCmd and the binding checks are
// reported SKIP.
package conform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/daniel-alexander4/wedge/internal/policy"
)

// Reference endpoint paths (spec §4 fixes discovery and app-start; the rest
// are the reference shape shared by wedge.js and the wedge-rp SDKs).
const (
	discoveryPath = "/.well-known/wedge.json"
	startPath     = "/wedge/start"
	appStartPath  = "/wedge/app-start"
)

// Session is one conformance run against one target RP.
type Session struct {
	Target   string // canonical origin under test
	User     string // username the harness key is registered under ("" = keyless only)
	Key      *KeyPair
	StartCmd string // optional: command printing a request_id or wedge:// link (custom start shapes)
	Client   *http.Client

	disc     map[string]any // raw discovery document
	discErr  error
	challURL string
	verURL   string

	// memoized flow state shared between related checks
	unregResp   *wireResp
	appProbe    *appProbeState
	claimResp   *wireResp
	bindingDone *pending
	tmp         string
}

// NewSession validates the target and prepares the HTTP client.
func NewSession(target, user string, key *KeyPair, startCmd string) (*Session, error) {
	origin := policy.NormalizeOrigin(strings.TrimSpace(target))
	if origin == "" || (!strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://")) {
		return nil, fmt.Errorf("target is not an http(s) origin: %q", target)
	}
	return &Session{
		Target:   origin,
		User:     user,
		Key:      key,
		StartCmd: startCmd,
		Client: &http.Client{
			Timeout: 15 * time.Second,
			// Claim redirects are asserted, not followed.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// -- wire helpers ---------------------------------------------------------------

type wireResp struct {
	Status  int
	Body    map[string]any
	Raw     []byte
	Cookies []*http.Cookie
	Header  http.Header
}

func (s *Session) get(rawURL string, cookies ...*http.Cookie) (wireResp, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return wireResp{}, err
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return s.do(req)
}

func (s *Session) postJSON(rawURL string, payload any) (wireResp, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return wireResp{}, err
	}
	req, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return wireResp{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	return s.do(req)
}

func (s *Session) do(req *http.Request) (wireResp, error) {
	resp, err := s.Client.Do(req)
	if err != nil {
		return wireResp{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out := wireResp{Status: resp.StatusCode, Raw: raw, Cookies: resp.Cookies(), Header: resp.Header}
	_ = json.Unmarshal(raw, &out.Body) // non-JSON bodies leave Body nil; checks assert as needed
	return out, nil
}

func str(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

// sameOrigin reports whether rawURL is same-origin with the target
// (equivalence-aware per spec §6.1).
func (s *Session) sameOrigin(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	candidate := policy.NormalizeOrigin(u.Scheme + "://" + u.Host)
	for _, equiv := range policy.EquivalentOrigins(s.Target) {
		if candidate == equiv {
			return true
		}
	}
	return false
}

// discovery fetches and caches the discovery document.
func (s *Session) discovery() (map[string]any, error) {
	if s.disc != nil || s.discErr != nil {
		return s.disc, s.discErr
	}
	resp, err := s.get(s.Target + discoveryPath)
	if err != nil {
		s.discErr = err
		return nil, err
	}
	if resp.Status != 200 || resp.Body == nil {
		s.discErr = fmt.Errorf("discovery: HTTP %d", resp.Status)
		return nil, s.discErr
	}
	s.disc = resp.Body
	s.challURL = str(resp.Body, "challenge_url")
	s.verURL = str(resp.Body, "verify_url")
	return s.disc, nil
}

// pending is one live sign request the harness minted on the target.
type pending struct {
	RequestID string
	Challenge string
	Namespace string
	Binding   *http.Cookie // nil when the start shape doesn't expose one
}

// newRequest mints a fresh pending request: reference /wedge/start by
// default, or StartCmd for custom shapes, then fetches the challenge.
func (s *Session) newRequest() (pending, error) {
	if _, err := s.discovery(); err != nil {
		return pending{}, err
	}
	var p pending
	if s.StartCmd != "" {
		out, err := exec.Command("sh", "-c", s.StartCmd).Output()
		if err != nil {
			return pending{}, fmt.Errorf("start-cmd: %w", err)
		}
		p.RequestID = requestIDFrom(strings.TrimSpace(string(out)))
		if p.RequestID == "" {
			return pending{}, fmt.Errorf("start-cmd output is neither a request_id nor a wedge:// link")
		}
	} else {
		body := map[string]string{}
		if s.User != "" {
			body["username"] = s.User
		}
		resp, err := s.postJSON(s.Target+startPath, body)
		if err != nil {
			return pending{}, err
		}
		if resp.Status != 200 {
			return pending{}, fmt.Errorf("reference /wedge/start: HTTP %d (custom shape? use --start-cmd)", resp.Status)
		}
		p.RequestID = str(resp.Body, "request_id")
		if p.RequestID == "" {
			if link := str(resp.Body, "link"); link != "" {
				p.RequestID = requestIDFrom(link)
			}
		}
		if p.RequestID == "" {
			return pending{}, fmt.Errorf("reference /wedge/start returned no request_id")
		}
		for _, c := range resp.Cookies {
			if c.Name != "" {
				p.Binding = c
				break
			}
		}
	}
	resp, err := s.get(s.challURL + "?request_id=" + url.QueryEscape(p.RequestID))
	if err != nil {
		return pending{}, err
	}
	if resp.Status != 200 {
		return pending{}, fmt.Errorf("challenge fetch: HTTP %d", resp.Status)
	}
	p.Challenge = str(resp.Body, "challenge")
	p.Namespace = str(resp.Body, "namespace")
	return p, nil
}

// requestIDFrom accepts a bare request_id or a wedge://sign link.
func requestIDFrom(out string) string {
	if strings.HasPrefix(out, "wedge://") {
		u, err := url.Parse(out)
		if err != nil {
			return ""
		}
		return u.Query().Get("request_id")
	}
	if requestIDRe.MatchString(out) {
		return out
	}
	return ""
}

// verify posts a §5.2 verify body; extra fields are merged in (junk-field
// tolerance tests) and empty-string fields removed (missing-field tests).
func (s *Session) verify(p pending, signature, publicKey, namespace, echoChallenge string, extra map[string]any) (wireResp, error) {
	body := map[string]any{
		"request_id": p.RequestID,
		"challenge":  echoChallenge,
		"namespace":  namespace,
		"signature":  signature,
		"public_key": publicKey,
	}
	for k, v := range extra {
		body[k] = v
	}
	for k, v := range body {
		if sv, ok := v.(string); ok && sv == "" {
			delete(body, k)
		}
	}
	resp, err := s.postJSON(s.verURL, body)
	if err != nil {
		return resp, err
	}
	// The reference engine rate-limits verify per source (30/min); a paced
	// run stays under it, but one polite retry keeps a slow target honest.
	if resp.Status == 429 {
		time.Sleep(2 * time.Second)
		return s.postJSON(s.verURL, body)
	}
	return resp, err
}

// signedVerify signs the stored challenge under the target namespace and
// posts the canonical happy-path body.
func (s *Session) signedVerify(p pending) (wireResp, error) {
	sig, err := s.Key.Sign(p.Challenge, p.Namespace)
	if err != nil {
		return wireResp{}, err
	}
	return s.verify(p, sig, s.Key.PublicKey, p.Namespace, p.Challenge, nil)
}
