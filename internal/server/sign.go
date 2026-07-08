package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wedge/internal/browser"
	"wedge/internal/config"
	"wedge/internal/keyutil"
	"wedge/internal/policy"
	"wedge/internal/protocol"
	"wedge/internal/rp"
	"wedge/internal/signer"
)

// consentTimeout is how long a parked sign waits for the user's presence tap
// before it is abandoned.
const consentTimeout = 45 * time.Second

var signSeq atomic.Uint64

// pendingSign is a sign request awaiting the user's decision in wedge's window.
// The decision channel is buffered so respond() never blocks even if the
// orchestration already timed out.
type pendingSign struct {
	ID          string `json:"id"`
	Origin      string `json:"origin"`
	Namespace   string `json:"namespace"`
	Company     string `json:"company"`
	Challenge   string `json:"challenge"`
	AlwaysAllow bool   `json:"alwaysAllow"`

	decision chan string `json:"-"`
}

// consentBroker parks pending signs and hands them to the UI (long-poll) and
// back (respond). One-at-a-time from the UI's view; a small queue tolerates
// concurrent requests.
type consentBroker struct {
	mu     sync.Mutex
	queue  []*pendingSign
	notify chan struct{}
}

func newConsentBroker() *consentBroker {
	return &consentBroker{notify: make(chan struct{}, 1)}
}

func (b *consentBroker) wake() {
	select {
	case b.notify <- struct{}{}:
	default:
	}
}

func (b *consentBroker) park(p *pendingSign) {
	b.mu.Lock()
	b.queue = append(b.queue, p)
	b.mu.Unlock()
	b.wake()
}

func (b *consentBroker) head() *pendingSign {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.queue) > 0 {
		return b.queue[0]
	}
	return nil
}

func (b *consentBroker) remove(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, p := range b.queue {
		if p.ID == id {
			b.queue = append(b.queue[:i], b.queue[i+1:]...)
			return
		}
	}
}

// respond resolves a parked sign. Returns false if id is unknown.
func (b *consentBroker) respond(id, decision string) bool {
	b.mu.Lock()
	for i, p := range b.queue {
		if p.ID == id {
			b.queue = append(b.queue[:i], b.queue[i+1:]...)
			ch := p.decision
			b.mu.Unlock()
			ch <- decision
			return true
		}
	}
	b.mu.Unlock()
	return false
}

// waitForPending blocks until a pending sign is available or ctx is done.
func (b *consentBroker) waitForPending(ctx context.Context) *pendingSign {
	for {
		if p := b.head(); p != nil {
			return p
		}
		select {
		case <-b.notify:
		case <-ctx.Done():
			return nil
		}
	}
}

// ---- HTTP handlers (registered in New) ----

func (s *Server) handlePending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	p := s.consent.waitForPending(ctx)
	if p == nil {
		writeJSON(w, http.StatusOK, map[string]any{"pending": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pending": true, "request": p})
}

func (s *Server) handleRespond(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID       string `json:"id"`
		Decision string `json:"decision"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid request body"})
		return
	}
	// Decision is the UI verb (allow / allow-always / deny). runSign maps it to a
	// sign-log approval label (allow-once / always-allow / silent) — distinct
	// vocabularies for two layers; note "allow-always" (verb) vs "always-allow" (label).
	switch body.Decision {
	case "allow", "allow-always", "deny":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid decision"})
		return
	}
	s.consent.respond(body.ID, body.Decision)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleHandoff receives a wedge:// URL forwarded from a second wedge process
// (the one the OS launched to handle the protocol link). Loopback-guarded; a
// forwarded URL only triggers the consent flow, never a silent sign.
func (s *Server) handleHandoff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid request body"})
		return
	}
	s.HandleSignURL(body.URL)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- orchestration ----

// HandleSignURL processes a wedge:// link asynchronously.
func (s *Server) HandleSignURL(raw string) { go s.runSign(raw) }

func (s *Server) runSign(raw string) {
	req, err := protocol.ParseSignURL(raw)
	if err != nil {
		log.Printf("sign: bad link: %v", err)
		return
	}
	cfg := s.configMgr.Get()
	if !cfg.Enabled {
		log.Printf("sign: signing disabled")
		return
	}
	origin := policy.NormalizeOrigin(req.Origin)
	if origin == "" || !originAllowed(origin, cfg) {
		log.Printf("sign: origin not allowed: %s", req.Origin)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	disc, err := rp.Discover(ctx, origin)
	if err != nil {
		log.Printf("sign: discovery failed for %s: %v", origin, err)
		return
	}
	ch, err := rp.FetchChallenge(ctx, disc.ChallengeURL, req.RequestID)
	if err != nil {
		log.Printf("sign: challenge fetch failed: %v", err)
		return
	}

	res := policy.EvaluateSignPolicy(policy.SignPolicyInput{
		Enabled:        cfg.Enabled,
		Challenge:      ch.Challenge,
		Namespace:      ch.Namespace,
		Company:        ch.Company,
		Origin:         origin,
		AllowedOrigins: cfg.AllowedOrigins,
		OriginScopes:   cfg.OriginScopes,
	})
	if !res.OK {
		log.Printf("sign: policy rejected: %s", strings.ReplaceAll(res.Error, "\n", " "))
		return
	}

	scope := findScope(cfg, origin, res.ExpectedNamespace)
	approval := "allow-once"

	if scope != nil && scope.Silent {
		approval = "silent" // per-site advanced opt-in: no presence tap
	} else {
		alwaysAllow := scope != nil && scope.AlwaysAllow
		p := &pendingSign{
			ID:          fmt.Sprintf("sign-%d", signSeq.Add(1)),
			Origin:      origin,
			Namespace:   res.ExpectedNamespace,
			Company:     res.ExpectedCompany,
			Challenge:   ch.Challenge,
			AlwaysAllow: alwaysAllow,
			decision:    make(chan string, 1),
		}
		switch s.awaitDecision(ctx, p) {
		case "deny", "":
			log.Printf("sign: denied or timed out for %s", origin)
			return
		case "allow-always":
			if err := s.configMgr.Update(func(c *config.Config) {
				setAlwaysAllow(c, origin, res.ExpectedNamespace)
			}); err != nil {
				log.Printf("sign: could not persist always-allow: %v", err)
			}
			approval = "always-allow"
		default: // "allow"
			if alwaysAllow {
				approval = "always-allow"
			}
		}
	}

	sig, err := signer.Sign(ch.Challenge, res.ExpectedNamespace, cfg.KeyPath, signer.DefaultTimeout)
	if err != nil {
		log.Printf("sign: signing failed: %v", err)
		return
	}
	if err := rp.Verify(ctx, disc.VerifyURL, rp.VerifyRequest{
		RequestID: req.RequestID,
		Challenge: ch.Challenge,
		Namespace: res.ExpectedNamespace,
		Signature: sig,
		PublicKey: publicKeyForConfig(cfg.KeyPath),
	}); err != nil {
		log.Printf("sign: verify delivery failed: %v", err)
		return
	}
	s.log.Append(SignLogEntry{
		Time:      time.Now().UTC().Format(time.RFC3339),
		Origin:    origin,
		Namespace: res.ExpectedNamespace,
		Approval:  approval,
	})
	log.Printf("sign: completed for %s (%s)", origin, approval)
}

// awaitDecision parks p, surfaces wedge's window, and waits for the user's tap.
func (s *Server) awaitDecision(ctx context.Context, p *pendingSign) string {
	s.consent.park(p)
	// Best-effort: bring a wedge window forward so the prompt is seen. A window
	// already open is long-polling /api/pending and will show it regardless.
	if os.Getenv("WEDGE_NO_BROWSER") == "" && s.Addr() != "" {
		browser.Open("http://" + s.Addr() + "/")
	}
	select {
	case d := <-p.decision:
		return d
	case <-time.After(consentTimeout):
		s.consent.remove(p.ID)
		return ""
	case <-ctx.Done():
		s.consent.remove(p.ID)
		return ""
	}
}

// ---- config helpers ----

func originAllowed(origin string, cfg config.Config) bool {
	for _, cand := range policy.EquivalentOrigins(origin) {
		for _, a := range cfg.AllowedOrigins {
			if cand == a {
				return true
			}
		}
	}
	return false
}

func findScope(cfg config.Config, origin, namespace string) *config.OriginScope {
	for _, cand := range policy.EquivalentOrigins(origin) {
		scopes := cfg.OriginScopes[cand]
		for i := range scopes {
			if strings.TrimSpace(scopes[i].Namespace) == namespace {
				return &scopes[i]
			}
		}
	}
	return nil
}

func setAlwaysAllow(c *config.Config, origin, namespace string) {
	for _, cand := range policy.EquivalentOrigins(origin) {
		scopes := c.OriginScopes[cand]
		for i := range scopes {
			if strings.TrimSpace(scopes[i].Namespace) == namespace {
				scopes[i].AlwaysAllow = true
				return
			}
		}
	}
}

func publicKeyForConfig(keyPath string) string {
	p := keyutil.ResolveKeyPath(keyPath)
	if !strings.HasSuffix(p, ".pub") {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
