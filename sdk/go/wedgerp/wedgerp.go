// Package wedgerp is the relying-party middleware for wedge — SSH-key web
// authentication (docs/wedge-spec-v1.md). It implements every RP-side
// requirement of the protocol as framework-neutral handlers; Handler wraps
// them as a net/http mux any router can mount.
//
// The host application supplies what the spec deliberately leaves out of
// scope: how accounts and their registered public keys are stored (the
// FindKeys / FindUserByPublicKey callbacks) and how a session is minted
// (HandlerOptions.Login).
//
// Living in the wedge module on purpose: the origin normalization/equivalence
// comes from internal/policy and the wire types from internal/rp, so the
// authenticator and this RP can't drift apart — a mismatch is a compile error.
// Semantics are kept in lockstep with sdk/python/wedge_rp/core.py and
// sdk/node/lib/core.js.
package wedgerp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/daniel-alexander4/wedge/internal/policy"
	wire "github.com/daniel-alexander4/wedge/internal/rp"
)

// Endpoint paths. Discovery and app-start are fixed by the spec (§4, §9); the
// rest are this package's defaults — challenge/verify are published via
// discovery, start/status/claim are wired to the matching wedge.js.
const (
	DiscoveryPath = "/.well-known/wedge.json"
	StartPath     = "/wedge/start"
	ChallengePath = "/wedge/challenge"
	VerifyPath    = "/wedge/verify"
	StatusPath    = "/wedge/status"
	AppStartPath  = "/wedge/app-start"
	ClaimPath     = "/wedge/claim"
	ScriptPath    = "/wedge/wedge.js"
)

// BindingCookie is the browser-binding cookie name (spec §5.4).
const BindingCookie = "wedge_flow"

// Security boundary: byte-identical to internal/policy's challengeRegex and
// internal/protocol's requestIDRe (spec §6.2) — keep all copies consistent.
var (
	challengeRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}$`)
	requestIDRegex = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

// DefaultChallengeTTL is the reference request lifetime (spec §6.2).
const DefaultChallengeTTL = 180 * time.Second

// Config configures one RP site.
type Config struct {
	// Origin is REQUIRED: the site's canonical origin exactly as browsers
	// reach it (https://example.com, http://127.0.0.1:8080). Under the
	// protocol's namespace==origin rule this string IS the signature
	// namespace, so it must be configured explicitly — never derived from a
	// Host header an attacker can influence.
	Origin string

	// FindKeys returns the registered public-key line(s) for an account
	// (nil/empty = no account). Enables username-carrying sign-in.
	FindKeys func(username string) ([]string, error)

	// FindUserByPublicKey locates the account that registered a key (compare
	// with SameKey; type+data, comments ignored). username=="" means no
	// match. Enables keyless sign-in and the app-initiated flow. The posted
	// key is only ever a selector: verification runs strictly against the
	// keys returned here (spec §5.2).
	FindUserByPublicKey func(publicKey string) (username string, keys []string, err error)

	// Store defaults to NewMemoryStore(). Multi-process deployments need a
	// shared RequestStore implementation.
	Store RequestStore

	ChallengeTTL  time.Duration // default DefaultChallengeTTL
	VerifyTimeout time.Duration // default DefaultVerifyTimeout

	// MaxConcurrentVerifies bounds simultaneous ssh-keygen runs (default 4).
	MaxConcurrentVerifies int

	// Verify rate limit per source (default 30 attempts / 1 minute);
	// DisableVerifyRateLimit turns it off.
	RateLimitAttempts      int
	RateLimitWindow        time.Duration
	DisableVerifyRateLimit bool

	// RegistrationURL is the site's key-registration page, advertised in
	// discovery (spec §4) so authenticators can send a user whose key isn't
	// registered yet straight there. Must be same-origin with Origin.
	RegistrationURL string
}

// RP is one site's engine. All methods are safe for concurrent use.
type RP struct {
	origin              string
	registrationURL     string
	findKeys            func(string) ([]string, error)
	findUserByPublicKey func(string) (string, []string, error)
	store               RequestStore
	challengeTTL        time.Duration
	verifyTimeout       time.Duration
	verifySlots         chan struct{}
	rate                *slidingWindow
}

// New validates cfg and builds the engine.
func New(cfg Config) (*RP, error) {
	if cfg.FindKeys == nil && cfg.FindUserByPublicKey == nil {
		return nil, fmt.Errorf("wedgerp: supply FindKeys and/or FindUserByPublicKey")
	}
	origin := policy.NormalizeOrigin(strings.TrimSpace(cfg.Origin))
	if origin == "" || (!strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://")) {
		return nil, fmt.Errorf("wedgerp: Origin is not an http(s) origin: %q", cfg.Origin)
	}
	if cfg.RegistrationURL != "" && cfg.RegistrationURL != origin && !strings.HasPrefix(cfg.RegistrationURL, origin+"/") {
		return nil, fmt.Errorf("wedgerp: RegistrationURL must be same-origin with Origin")
	}
	rp := &RP{
		origin:              origin,
		registrationURL:     cfg.RegistrationURL,
		findKeys:            cfg.FindKeys,
		findUserByPublicKey: cfg.FindUserByPublicKey,
		store:               cfg.Store,
		challengeTTL:        cfg.ChallengeTTL,
		verifyTimeout:       cfg.VerifyTimeout,
	}
	if rp.store == nil {
		rp.store = NewMemoryStore()
	}
	if rp.challengeTTL <= 0 {
		rp.challengeTTL = DefaultChallengeTTL
	}
	if rp.verifyTimeout <= 0 {
		rp.verifyTimeout = DefaultVerifyTimeout
	}
	slots := cfg.MaxConcurrentVerifies
	if slots <= 0 {
		slots = 4
	}
	rp.verifySlots = make(chan struct{}, slots)
	if !cfg.DisableVerifyRateLimit {
		attempts, window := cfg.RateLimitAttempts, cfg.RateLimitWindow
		if attempts <= 0 {
			attempts = 30
		}
		if window <= 0 {
			window = time.Minute
		}
		rp.rate = &slidingWindow{limit: attempts, window: window, events: map[string][]time.Time{}}
	}
	return rp, nil
}

// Origin is the canonical (normalized) origin this RP serves.
func (rp *RP) Origin() string { return rp.origin }

// UsesHTTPS tells adapters whether the binding cookie should be Secure.
func (rp *RP) UsesHTTPS() bool { return strings.HasPrefix(rp.origin, "https://") }

// IsSameOrigin reports whether an Origin/Referer header value matches this
// site (localhost↔127.0.0.1 alias-aware, per spec §6.1). Adapters should
// reject browser-facing POSTs that fail this.
func (rp *RP) IsSameOrigin(value string) bool {
	candidate := policy.NormalizeOrigin(strings.TrimSpace(value))
	if candidate == "" {
		return false
	}
	for _, equiv := range policy.EquivalentOrigins(rp.origin) {
		if candidate == equiv {
			return true
		}
	}
	return false
}

// SignLink is the wedge:// link the browser opens for a request (spec §3).
func (rp *RP) SignLink(requestID string) string {
	return "wedge://sign?v=1&origin=" + url.QueryEscape(rp.origin) +
		"&request_id=" + url.QueryEscape(requestID)
}

// ChallengeTTL is the configured request lifetime (adapters use it for the
// binding cookie Max-Age).
func (rp *RP) ChallengeTTL() time.Duration { return rp.challengeTTL }

// -- response bodies -----------------------------------------------------------

type errorBody struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
	Code  string `json:"code,omitempty"` // machine-readable token (spec §5.2), e.g. "unknown_key"
}

func errBody(msg string) errorBody { return errorBody{OK: false, Error: msg} }

// errUnknownKey is the spec's unknown_key verify outcome (§5.2): no registered
// account matches the offered key. The authenticator uses the code to steer
// the user to registration_url once every key has been tried.
func errUnknownKey(msg string) errorBody { return errorBody{OK: false, Error: msg, Code: "unknown_key"} }

// StartBody is the /wedge/start success response.
type StartBody struct {
	OK        bool   `json:"ok"`
	RequestID string `json:"request_id"`
	Link      string `json:"link"`
}

// AppStartBody is the /wedge/app-start success response (spec §8.1).
type AppStartBody struct {
	OK bool `json:"ok"`
	wire.AppStart
}

// StatusBody is the /wedge/status response (spec §5.4).
type StatusBody struct {
	Status   string `json:"status"`
	Redirect string `json:"redirect,omitempty"`
}

type okBody struct {
	OK bool `json:"ok"`
}

// -- helpers -------------------------------------------------------------------

// token mints n CSPRNG bytes as unpadded base64url (same shape as Python's
// secrets.token_urlsafe and Node's base64url).
func token(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("wedgerp: crypto/rand: " + err.Error()) // unreachable on sane systems
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// constantTimeEqual compares strings in constant time; hashing first makes
// the comparison length-proof.
func constantTimeEqual(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// slidingWindow is a per-key best-effort rate limiter (per-process).
type slidingWindow struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	events map[string][]time.Time
}

func (w *slidingWindow) allow(key string) bool {
	now := time.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	events := w.events[key]
	cutoff := now.Add(-w.window)
	for len(events) > 0 && !events[0].After(cutoff) {
		events = events[1:]
	}
	if len(events) >= w.limit {
		w.events[key] = events
		return false
	}
	w.events[key] = append(events, now)
	return true
}

func (rp *RP) mint(username, browserNonce, claimToken string) (RequestRecord, error) {
	rec := RequestRecord{
		RequestID:    token(18),
		Challenge:    token(24),
		Namespace:    rp.origin,
		Username:     username,
		BrowserNonce: browserNonce,
		ClaimToken:   claimToken,
		Status:       "pending",
		ExpiresAt:    time.Now().Add(rp.challengeTTL),
	}
	return rec, rp.store.Put(rec)
}

func (rp *RP) live(requestID string) (RequestRecord, bool) {
	if !requestIDRegex.MatchString(requestID) {
		return RequestRecord{}, false
	}
	rec, ok, err := rp.store.Get(requestID)
	if err != nil {
		return RequestRecord{}, false
	}
	return rec, ok
}

// -- endpoint handlers ------------------------------------------------------------

// Discovery is GET /.well-known/wedge.json (spec §4).
func (rp *RP) Discovery() wire.Discovery {
	return wire.Discovery{
		Version:         1,
		Namespace:       rp.origin,
		ChallengeURL:    rp.origin + ChallengePath,
		VerifyURL:       rp.origin + VerifyPath,
		RegistrationURL: rp.registrationURL,
	}
}

// Start is POST /wedge/start (browser-facing; shape is the RP's choice, spec
// §5.4). username=="" starts a keyless flow. The returned browserNonce must
// be set as an HttpOnly cookie — it is the browser binding that later gates
// session minting.
func (rp *RP) Start(username string) (status int, body any, browserNonce string) {
	if username != "" {
		if !principalRegex.MatchString(username) {
			return 400, errBody("invalid username"), ""
		}
		if rp.findKeys == nil {
			return 400, errBody("username sign-in is not supported"), ""
		}
	} else if rp.findUserByPublicKey == nil {
		return 400, errBody("username required"), ""
	}
	nonce := token(24)
	rec, err := rp.mint(username, nonce, "")
	if err != nil {
		return 500, errBody("internal error"), ""
	}
	return 200, StartBody{OK: true, RequestID: rec.RequestID, Link: rp.SignLink(rec.RequestID)}, nonce
}

// Challenge is GET <challenge_url>?request_id=… (spec §5.1).
func (rp *RP) Challenge(requestID string) (int, any) {
	rec, ok := rp.live(requestID)
	if !ok || rec.Status != "pending" {
		return 404, errBody("unknown request")
	}
	return 200, wire.Challenge{Challenge: rec.Challenge, Namespace: rec.Namespace}
}

// AppStart is POST /wedge/app-start (spec §8.1; path fixed in v1). Rejected
// with an explanatory error when the host has no keyless account lookup — the
// RP is then a conforming Core-only implementation (spec §8).
func (rp *RP) AppStart() (int, any) {
	if rp.findUserByPublicKey == nil {
		return 404, errBody("app-initiated sign-in is not supported by this site")
	}
	claimToken := token(24)
	rec, err := rp.mint("", "", claimToken)
	if err != nil {
		return 500, errBody("internal error")
	}
	claimURL := rp.origin + ClaimPath +
		"?request_id=" + url.QueryEscape(rec.RequestID) +
		"&claim=" + url.QueryEscape(claimToken)
	return 200, AppStartBody{OK: true, AppStart: wire.AppStart{
		RequestID: rec.RequestID,
		Challenge: rec.Challenge,
		Namespace: rec.Namespace,
		ClaimURL:  claimURL,
	}}
}

// Verify is POST <verify_url> (spec §5.2; cookieless JSON from the
// authenticator). It verifies against the *stored* challenge and the
// account's *registered* keys — the echoed Challenge field is ignored and a
// posted PublicKey is only an account selector. A failed verify consumes
// nothing, so the authenticator may retry with its next key. source (e.g.
// the peer IP) feeds the rate limiter; "" disables it for the call.
func (rp *RP) Verify(req wire.VerifyRequest, source string) (int, any) {
	rec, ok := rp.live(req.RequestID)
	if !ok || rec.Status != "pending" {
		return 404, errBody("unknown request")
	}
	if !rp.IsSameOrigin(req.Namespace) {
		return 400, errBody("namespace mismatch")
	}
	if !strings.HasPrefix(strings.TrimLeft(req.Signature, " \t\r\n"), sigHeader) {
		return 400, errBody("malformed signature")
	}
	if rp.rate != nil && source != "" && !rp.rate.allow(source) {
		return 429, errBody("rate limited")
	}

	username, keys, status, errResp := rp.resolveCandidates(rec, req.PublicKey)
	if status != 0 {
		return status, errResp
	}

	select {
	case rp.verifySlots <- struct{}{}:
		defer func() { <-rp.verifySlots }()
	default:
		return 503, errBody("verifier busy")
	}

	for _, key := range keys {
		// -n gets the namespace string the authenticator actually signed (it
		// echoes what we minted; alias variants of our origin are equivalent
		// by §6.1 but the bytes must match).
		ok, _, err := VerifySignature(rec.Challenge, req.Signature, username, key, req.Namespace, rp.verifyTimeout)
		if err != nil {
			return 503, errBody(err.Error())
		}
		if ok {
			authed, err := rp.store.SetAuthenticated(rec.RequestID, username)
			if err != nil || !authed {
				return 404, errBody("unknown request")
			}
			return 200, okBody{OK: true}
		}
	}
	return 401, errBody("signature verification failed")
}

// resolveCandidates returns the account and registered keys to verify
// against, or (0,0,status,body) on error. status==0 means success.
func (rp *RP) resolveCandidates(rec RequestRecord, postedKey string) (string, []string, int, any) {
	if rec.Username != "" {
		keys, err := rp.findKeys(rec.Username)
		if err != nil {
			return "", nil, 500, errBody("internal error")
		}
		if len(keys) == 0 {
			return "", nil, 401, errUnknownKey("no account matches")
		}
		return rec.Username, keys, 0, nil
	}
	// Keyless: the posted public key is REQUIRED (spec §8.2) and is only a
	// selector — verification runs against the stored keys.
	if _, _, ok := SplitPublicKey(postedKey); !ok {
		return "", nil, 400, errBody("public_key required")
	}
	username, keys, err := rp.findUserByPublicKey(postedKey)
	if err != nil {
		return "", nil, 500, errBody("internal error")
	}
	if username == "" || len(keys) == 0 || !principalRegex.MatchString(username) {
		return "", nil, 401, errUnknownKey("no account matches key")
	}
	return username, keys, 0, nil
}

// Status is GET /wedge/status?request_id=… (browser-facing, spec §5.4). A
// non-empty username means the browser binding checked out and the request
// was atomically consumed — the adapter must mint the host session NOW (this
// is the only moment it can).
func (rp *RP) Status(requestID, browserNonce string) (body StatusBody, username string) {
	rec, ok := rp.live(requestID)
	if !ok {
		return StatusBody{Status: "expired"}, ""
	}
	if rec.BrowserNonce == "" {
		// App-initiated requests complete via /wedge/claim, never polling.
		return StatusBody{Status: "pending"}, ""
	}
	if browserNonce == "" || !constantTimeEqual(browserNonce, rec.BrowserNonce) {
		return StatusBody{Status: "pending"}, ""
	}
	if rec.Status != "authenticated" {
		return StatusBody{Status: rec.Status}, ""
	}
	taken, ok, err := rp.store.TakeAuthenticated(rec.RequestID)
	if err != nil || !ok || taken.AuthenticatedUsername == "" {
		return StatusBody{Status: "pending"}, ""
	}
	return StatusBody{Status: "authenticated"}, taken.AuthenticatedUsername
}

// Claim is GET /wedge/claim?request_id=…&claim=… (spec §8.3). It returns the
// username to mint a session for, or ok=false (the adapter redirects to a
// login or error page — never minting). The record is removed (= the claim is
// marked used) *before* the username is returned.
func (rp *RP) Claim(requestID, claimToken string) (username string, ok bool) {
	rec, live := rp.live(requestID)
	if !live ||
		rec.ClaimToken == "" ||
		rec.Status != "authenticated" ||
		claimToken == "" ||
		!constantTimeEqual(claimToken, rec.ClaimToken) {
		return "", false
	}
	taken, took, err := rp.store.TakeAuthenticated(rec.RequestID)
	if err != nil || !took || taken.AuthenticatedUsername == "" {
		return "", false
	}
	return taken.AuthenticatedUsername, true
}
