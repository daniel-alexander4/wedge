package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

const (
	// DefaultKeyPath points at the PUBLIC key: wedge signs through ssh-agent
	// (ssh-keygen -Y sign -f <pubkey>), so the private half never enters wedge.
	DefaultKeyPath    = "~/.ssh/id_ed25519.pub"
	DefaultServerPort = 7890
	configDirName     = "wedge"
	configFileName    = "config.json"
)

type OriginScope struct {
	Namespace string `json:"namespace"`
	Company   string `json:"company,omitempty"`
	// AlwaysAllow skips the sign detail screen for this scope; the per-sign
	// user-presence tap is still required (see docs/wedge-protocol.md §7).
	AlwaysAllow bool `json:"alwaysAllow,omitempty"`
	// Silent (advanced, per-site opt-in) skips the presence tap too. Off by
	// default; reopens the §8 phishing risk for this origin by informed choice.
	Silent bool `json:"silent,omitempty"`
}

type Config struct {
	Enabled        bool                     `json:"enabled"`
	KeyPath        string                   `json:"keyPath"`
	AllowedOrigins []string                 `json:"allowedOrigins"`
	OriginScopes   map[string][]OriginScope `json:"originScopes"`
	ServerPort     int                      `json:"serverPort"`
}

func DefaultConfig() Config {
	return Config{
		Enabled:        true,
		KeyPath:        DefaultKeyPath,
		AllowedOrigins: []string{},
		OriginScopes:   map[string][]OriginScope{},
		ServerPort:     DefaultServerPort,
	}
}

type Manager struct {
	mu     sync.RWMutex
	path   string
	config Config
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
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	if cfg.OriginScopes == nil {
		cfg.OriginScopes = map[string][]OriginScope{}
	}
	if cfg.AllowedOrigins == nil {
		cfg.AllowedOrigins = []string{}
	}
	if cfg.KeyPath == "" {
		cfg.KeyPath = DefaultKeyPath
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
	origins := make([]string, len(cfg.AllowedOrigins))
	copy(origins, cfg.AllowedOrigins)
	cfg.AllowedOrigins = origins
	scopes := make(map[string][]OriginScope, len(cfg.OriginScopes))
	for k, v := range cfg.OriginScopes {
		s := make([]OriginScope, len(v))
		copy(s, v)
		scopes[k] = s
	}
	cfg.OriginScopes = scopes
	return cfg
}

func (m *Manager) Update(fn func(*Config)) error {
	m.mu.Lock()
	fn(&m.config)
	m.mu.Unlock()
	return m.Save()
}
