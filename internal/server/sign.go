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
	Challenge   string `json:"challenge"`
	AlwaysAllow bool   `json:"alwaysAllow"`
	// NewSite marks the gated add-on-first-use prompt: the origin isn't in the
	// sites list yet, so this is shown origin-only (no namespace/challenge —
	// nothing has been fetched over the network) with Add & Allow / Add & Always.
	NewSite bool `json:"newSite"`

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
	// Decision is the UI verb. Known-site prompts send allow / allow-always /
	// deny; the new-site prompt sends add-allow / add-always / deny. runSign maps
	// these to a sign-log approval label (allow-once / always-allow / silent) —
	// distinct vocabularies for two layers.
	switch body.Decision {
	case "allow", "allow-always", "add-allow", "add-always", "deny":
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
	if origin == "" {
		log.Printf("sign: bad origin: %s", req.Origin)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	approval := "allow-once"
	consented := false // set once a presence tap has authorized this sign

	// Gated add-on-first-use: an origin not in the sites list gets an
	// origin-only consent BEFORE any network. Nothing is fetched until the user
	// explicitly adds it — preserving the no-network-for-unconfigured-origins
	// invariant. Deny contacts nothing. The Add tap is itself the presence tap,
	// so the normal consent below is skipped for a just-added site.
	if findSite(cfg, origin) == nil {
		p := &pendingSign{
			ID:       fmt.Sprintf("sign-%d", signSeq.Add(1)),
			Origin:   origin,
			NewSite:  true,
			decision: make(chan string, 1),
		}
		alwaysAllow := false
		switch s.awaitDecision(ctx, p) {
		case "add-always":
			alwaysAllow = true
			approval = "always-allow"
		case "add-allow":
		default: // "deny" or timeout
			log.Printf("sign: new site declined: %s", origin)
			return
		}
		if err := s.configMgr.Update(func(c *config.Config) {
			addSite(c, origin, alwaysAllow)
		}); err != nil {
			log.Printf("sign: could not add site: %v", err)
			return
		}
		cfg = s.configMgr.Get()
		consented = true
	}

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
		Enabled:   cfg.Enabled,
		Challenge: ch.Challenge,
		Namespace: ch.Namespace,
		Origin:    origin,
		Origins:   siteOrigins(cfg),
	})
	if !res.OK {
		log.Printf("sign: policy rejected: %s", strings.ReplaceAll(res.Error, "\n", " "))
		return
	}

	// Consent for an already-known site. (A site just added above already got its
	// presence tap in the new-site prompt, so it skips this.)
	site := findSite(cfg, origin)
	if !consented {
		switch {
		case site != nil && site.Silent:
			approval = "silent" // per-site advanced opt-in: no presence tap
		default:
			alwaysAllow := site != nil && site.AlwaysAllow
			p := &pendingSign{
				ID:          fmt.Sprintf("sign-%d", signSeq.Add(1)),
				Origin:      origin,
				Namespace:   res.Namespace,
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
					setSiteAlwaysAllow(c, origin)
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
	}

	// Try each agent-loaded key in turn; the first the RP accepts wins. A failed
	// verify doesn't consume the RP's challenge, so the next key can be tried.
	signable, err := s.signableKeys()
	if err != nil {
		log.Printf("sign: key discovery failed: %v", err)
		return
	}
	if len(signable) == 0 {
		log.Printf("sign: no agent-loaded keys to sign with (ssh-add a key)")
		return
	}
	var usedKey string
	delivered := false
	for _, k := range signable {
		sig, signErr := signer.Sign(ch.Challenge, res.Namespace, k.Path, signer.DefaultTimeout)
		if signErr != nil {
			log.Printf("sign: key %s could not sign: %v", k.Fingerprint, signErr)
			continue
		}
		verifyErr := rp.Verify(ctx, disc.VerifyURL, rp.VerifyRequest{
			RequestID: req.RequestID,
			Challenge: ch.Challenge,
			Namespace: res.Namespace,
			Signature: sig,
			PublicKey: readPublicKey(k.Path),
		})
		if verifyErr == nil {
			usedKey = keyLabel(k)
			delivered = true
			break
		}
		log.Printf("sign: key %s rejected by RP, trying next: %v", k.Fingerprint, verifyErr)
	}
	if !delivered {
		log.Printf("sign: no agent key was accepted for %s", origin)
		return
	}
	s.log.Append(SignLogEntry{
		Time:      time.Now().UTC().Format(time.RFC3339),
		Origin:    origin,
		Namespace: res.Namespace,
		Approval:  approval,
		Key:       usedKey,
	})
	log.Printf("sign: completed for %s (%s) with %s", origin, approval, usedKey)
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

// siteOrigins is the configured allowlist passed to the policy engine.
func siteOrigins(cfg config.Config) []string {
	origins := make([]string, 0, len(cfg.Sites))
	for _, site := range cfg.Sites {
		origins = append(origins, site.Origin)
	}
	return origins
}

// findSite returns the site for origin (up to the localhost↔127.0.0.1 alias).
func findSite(cfg config.Config, origin string) *config.Site {
	for _, cand := range policy.EquivalentOrigins(origin) {
		for i := range cfg.Sites {
			if cfg.Sites[i].Origin == cand {
				return &cfg.Sites[i]
			}
		}
	}
	return nil
}

// addSite appends origin to the sites list if not already present (gated
// add-on-first-use). No-op if an equivalent origin is already configured.
func addSite(c *config.Config, origin string, alwaysAllow bool) {
	for _, cand := range policy.EquivalentOrigins(origin) {
		for i := range c.Sites {
			if c.Sites[i].Origin == cand {
				c.Sites[i].AlwaysAllow = c.Sites[i].AlwaysAllow || alwaysAllow
				return
			}
		}
	}
	c.Sites = append(c.Sites, config.Site{Origin: origin, AlwaysAllow: alwaysAllow})
}

func setSiteAlwaysAllow(c *config.Config, origin string) {
	for _, cand := range policy.EquivalentOrigins(origin) {
		for i := range c.Sites {
			if c.Sites[i].Origin == cand {
				c.Sites[i].AlwaysAllow = true
				return
			}
		}
	}
}

func readPublicKey(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// keyLabel is a human-readable identifier for the sign log: the key's comment
// if it has one, else its fingerprint.
func keyLabel(k keyutil.DiscoveredKey) string {
	if c := strings.TrimSpace(k.Comment); c != "" {
		return c
	}
	return k.Fingerprint
}
