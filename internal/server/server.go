// Package server hosts wedge's own settings/onboarding UI on a loopback-only
// HTTP listener. It has NO cross-origin surface — the old /sign endpoint that a
// website called cross-origin is gone; signing arrives via the wedge://
// protocol handler. Every route here is for wedge's own app-mode
// window and is guarded by both a loopback check (peer IP + Host header) and a
// same-origin CSRF check, mirroring the nib/hespera pattern.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"wedge/internal/browser"
	"wedge/internal/config"
	"wedge/internal/keyutil"
	"wedge/internal/terminal"
)

const Version = "0.1.3"

// signLogCap bounds the in-memory sign log so it can't grow without limit.
const signLogCap = 500

type Server struct {
	configMgr  *config.Manager
	web        fs.FS
	httpServer *http.Server
	listener   net.Listener
	log        *signLog
	consent    *consentBroker
	// signableKeys is the source of agent-loaded keys the sign path tries, in
	// order. Defaults to keyutil.SignableKeys; overridable in tests.
	signableKeys func() ([]keyutil.DiscoveredKey, error)
	// openURL opens a configured site in the default browser. Defaults to
	// browser.OpenTab; overridable in tests so they don't spawn a browser.
	openURL func(string) error
	// openSSH opens a terminal running ssh against a configured ssh:// site.
	// Defaults to terminal.OpenSSH; overridable in tests.
	openSSH func(user, host, port string) error
}

func New(configMgr *config.Manager, web fs.FS) *Server {
	s := &Server{
		configMgr:    configMgr,
		web:          web,
		log:          &signLog{},
		consent:      newConsentBroker(),
		signableKeys: keyutil.SignableKeys,
		openURL:      browser.OpenTab,
		openSSH:      terminal.OpenSSH,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/enabled", s.handleEnabled)
	mux.HandleFunc("/api/keys", s.handleKeys)
	mux.HandleFunc("/api/open", s.handleOpen)
	mux.HandleFunc("/api/ssh", s.handleSSH)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/signlog", s.handleSignLog)
	mux.HandleFunc("/api/pending", s.handlePending)
	mux.HandleFunc("/api/respond", s.handleRespond)
	mux.HandleFunc("/internal/handoff", s.handleHandoff)
	mux.Handle("/", http.FileServerFS(s.web))
	s.httpServer = &http.Server{Handler: csrfGuard(loopbackOnly(mux))}
	return s
}

// Start binds a loopback listener on the configured port and serves. It refuses
// any non-loopback bind — wedge's UI is never network-exposed.
func (s *Server) Start() error {
	cfg := s.configMgr.Get()
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.ServerPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	if tcp, ok := ln.Addr().(*net.TCPAddr); !ok || !tcp.IP.IsLoopback() {
		ln.Close()
		return fmt.Errorf("refusing to serve on non-loopback address %s", ln.Addr())
	}
	s.listener = ln
	go s.httpServer.Serve(ln)
	return nil
}

func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}

// ---- handlers ----

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.configMgr.Get())
	case http.MethodPost:
		var cfg config.Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid request body"})
			return
		}
		err := s.configMgr.Update(func(c *config.Config) {
			c.Enabled = cfg.Enabled
			c.Sites = cfg.Sites
			if cfg.ServerPort > 0 {
				c.ServerPort = cfg.ServerPort
			}
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleEnabled(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid request body"})
		return
	}
	if err := s.configMgr.Update(func(c *config.Config) { c.Enabled = body.Enabled }); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "config": s.configMgr.Get()})
}

// handleKeys returns the SSH keys discovered in ~/.ssh, each with whether its
// private half is loaded in the ssh-agent (only those can sign). This is public
// key metadata only — path, type, comment, fingerprint — never private material.
func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	keys, err := keyutil.DiscoverKeys()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"keys": []any{}, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	available, keyLoaded := agentStatus()
	writeJSON(w, http.StatusOK, map[string]any{
		"running": s.Addr() != "",
		"address": s.Addr(),
		"version": Version,
		"agent":   map[string]any{"available": available, "keyLoaded": keyLoaded},
	})
}

func (s *Server) handleSignLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": s.log.snapshot()})
}

// ---- sign log ----

type SignLogEntry struct {
	Time      string `json:"time"`
	Origin    string `json:"origin"`
	Namespace string `json:"namespace"`
	Approval  string `json:"approval"` // "allow-once" | "always-allow" | "silent"
	Key       string `json:"key"`      // which agent key signed (comment or fingerprint)
}

type signLog struct {
	mu      sync.Mutex
	entries []SignLogEntry
}

// Append records a sign event, bounded at signLogCap (oldest dropped). The sign
// path calls this on every completed sign.
func (l *signLog) Append(e SignLogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
	if len(l.entries) > signLogCap {
		l.entries = l.entries[len(l.entries)-signLogCap:]
	}
}

func (l *signLog) snapshot() []SignLogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]SignLogEntry, len(l.entries))
	copy(out, l.entries)
	return out
}

// ---- guards ----

// loopbackOnly admits a request only when both the connecting peer and the
// requested Host are loopback. The peer-IP check is an unspoofable socket fact
// that self-enforces the loopback bind; the Host allowlist defends against DNS
// rebinding, where the socket is loopback but the browser carries an attacker's
// hostname.
func loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !peerIsLoopback(r.RemoteAddr) || !hostIsLoopback(r.Host) {
			http.Error(w, "loopback only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func peerIsLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func hostIsLoopback(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}

// csrfGuard rejects cross-site unsafe requests: an unsafe method whose
// Origin/Referer host does not match the request Host. Same-origin requests
// (the wedge UI calling its own API) and requests that omit both headers pass.
func csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isSameOriginUnsafe(r) {
			http.Error(w, "cross-site request forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isSameOriginUnsafe(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return true // safe method
	}
	reqHost := strings.TrimSpace(r.Host)
	if reqHost == "" {
		return true
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || strings.TrimSpace(u.Host) == "" {
			return false
		}
		return sameHostPort(reqHost, u.Host)
	}
	if referer := strings.TrimSpace(r.Header.Get("Referer")); referer != "" {
		u, err := url.Parse(referer)
		if err != nil || strings.TrimSpace(u.Host) == "" {
			return false
		}
		return sameHostPort(reqHost, u.Host)
	}
	return true
}

func sameHostPort(a, b string) bool {
	ha, pa := splitHostPort(a)
	hb, pb := splitHostPort(b)
	if !strings.EqualFold(ha, hb) {
		return false
	}
	return pa == pb
}

func splitHostPort(v string) (host, port string) {
	u, err := url.Parse("//" + strings.TrimSpace(v))
	if err != nil {
		return "", ""
	}
	return strings.ToLower(strings.TrimSpace(u.Hostname())), strings.TrimSpace(u.Port())
}

// ---- helpers ----

// agentStatus reports whether an ssh-agent is reachable and holds at least one
// identity. Best-effort: keyLoaded is "the agent has some key", not a
// fingerprint match against the configured identity.
func agentStatus() (available, keyLoaded bool) {
	if os.Getenv("SSH_AUTH_SOCK") == "" {
		return false, false
	}
	available = true
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ssh-add", "-l").Output()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 &&
		!strings.Contains(string(out), "no identities") {
		keyLoaded = true
	}
	return available, keyLoaded
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
