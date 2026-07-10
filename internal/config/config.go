package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

const (
	DefaultServerPort = 7890
	configDirName     = "wedge"
	configFileName    = "config.json"
)

// Site is one place wedge is authorized to sign into. The origin is the security
// boundary (see docs/wedge-protocol.md §8) and, under the namespace==origin
// model, also fixes the SSH signature namespace — so there is no separate
// namespace to configure. Any discovered ssh-agent key may be used for any site.
type Site struct {
	Origin string `json:"origin"`
	// AlwaysAllow skips the sign detail screen for this site; the per-sign
	// user-presence tap is still required (see docs/wedge-protocol.md §7).
	AlwaysAllow bool `json:"alwaysAllow,omitempty"`
	// Silent (advanced, per-site opt-in) skips the presence tap too. Off by
	// default; reopens the §8 phishing risk for this origin by informed choice.
	Silent bool `json:"silent,omitempty"`
	// Tunnels are per-site port forwards applied when the terminal launcher
	// runs ssh (ssh:// sites only). Each spec's shape picks the flag —
	// [bind:]port → -D, [bind:]lport:host:hport → -L — and is strictly
	// validated at launch (terminal.TunnelFlag); never free text.
	Tunnels []string `json:"tunnels,omitempty"`
	// Jump is an OpenSSH ProxyJump hop list ([user@]host[:port], comma-
	// separated) passed as -J at launch. Validated by terminal.ValidateJump.
	Jump string `json:"jump,omitempty"`
}

type Config struct {
	Enabled    bool   `json:"enabled"`
	Sites      []Site `json:"sites"`
	ServerPort int    `json:"serverPort"`
}

func DefaultConfig() Config {
	return Config{
		Enabled:    true,
		Sites:      []Site{},
		ServerPort: DefaultServerPort,
	}
}

// legacyConfig mirrors the pre-sites schema (keyPath + allowedOrigins +
// originScopes) so Load can migrate an old config.json into the sites list.
type legacyConfig struct {
	Enabled        bool                     `json:"enabled"`
	Sites          []Site                   `json:"sites"`
	AllowedOrigins []string                 `json:"allowedOrigins"`
	OriginScopes   map[string][]legacyScope `json:"originScopes"`
	ServerPort     int                      `json:"serverPort"`
}

type legacyScope struct {
	AlwaysAllow bool `json:"alwaysAllow"`
	Silent      bool `json:"silent"`
}

// migrateSites folds the legacy allowedOrigins + originScopes into a single
// sites list: one Site per origin, OR-ing the alwaysAllow/silent flags across
// that origin's old scopes. Order is stable (allowedOrigins first, then any
// scope-only origins, sorted) so the rewritten config is deterministic.
func migrateSites(lc legacyConfig) []Site {
	seen := map[string]int{} // origin -> index in out
	out := []Site{}
	add := func(origin string, alwaysAllow, silent bool) {
		if origin == "" {
			return
		}
		if i, ok := seen[origin]; ok {
			out[i].AlwaysAllow = out[i].AlwaysAllow || alwaysAllow
			out[i].Silent = out[i].Silent || silent
			return
		}
		seen[origin] = len(out)
		out = append(out, Site{Origin: origin, AlwaysAllow: alwaysAllow, Silent: silent})
	}
	for _, o := range lc.AllowedOrigins {
		add(o, false, false)
	}
	scopeOrigins := make([]string, 0, len(lc.OriginScopes))
	for o := range lc.OriginScopes {
		scopeOrigins = append(scopeOrigins, o)
	}
	sort.Strings(scopeOrigins)
	for _, o := range scopeOrigins {
		for _, sc := range lc.OriginScopes[o] {
			add(o, sc.AlwaysAllow, sc.Silent)
		}
	}
	return out
}

type Manager struct {
	mu       sync.RWMutex
	path     string
	config   Config
	onChange func()
}

func NewManager() (*Manager, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(configDir, configDirName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	m := &Manager{
		path:   filepath.Join(dir, configFileName),
		config: DefaultConfig(),
	}
	if err := m.Load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return m, nil
}

func NewManagerWithPath(path string) (*Manager, error) {
	m := &Manager{
		path:   path,
		config: DefaultConfig(),
	}
	if err := m.Load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return m, nil
}

func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.path)
	if err != nil {
		return err
	}
	var lc legacyConfig
	if err := json.Unmarshal(data, &lc); err != nil {
		return err
	}
	cfg := Config{
		Enabled:    lc.Enabled,
		Sites:      lc.Sites,
		ServerPort: lc.ServerPort,
	}
	// Migrate a pre-sites config (no sites, but legacy origins present).
	if len(cfg.Sites) == 0 && (len(lc.AllowedOrigins) > 0 || len(lc.OriginScopes) > 0) {
		cfg.Sites = migrateSites(lc)
	}
	if cfg.Sites == nil {
		cfg.Sites = []Site{}
	}
	if cfg.ServerPort == 0 {
		cfg.ServerPort = DefaultServerPort
	}
	m.config = cfg
	return nil
}

func (m *Manager) Save() error {
	m.mu.RLock()
	cfg := m.config
	m.mu.RUnlock()

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(m.path)
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, m.path)
}

func (m *Manager) Get() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cfg := m.config
	sites := make([]Site, len(cfg.Sites))
	copy(sites, cfg.Sites)
	cfg.Sites = sites
	return cfg
}

func (m *Manager) Update(fn func(*Config)) error {
	m.mu.Lock()
	fn(&m.config)
	onChange := m.onChange
	m.mu.Unlock()
	err := m.Save()
	if err == nil && onChange != nil {
		onChange()
	}
	return err
}

// OnChange registers fn to run after every successful Update save (e.g. the
// tray rebuilding its sites menu). Single subscriber; called outside the lock.
func (m *Manager) OnChange(fn func()) {
	m.mu.Lock()
	m.onChange = fn
	m.mu.Unlock()
}
