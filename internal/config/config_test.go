package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.Enabled {
		t.Error("expected enabled=true by default")
	}
	if cfg.KeyPath != DefaultKeyPath {
		t.Errorf("expected keyPath=%q, got %q", DefaultKeyPath, cfg.KeyPath)
	}
	if cfg.ServerPort != DefaultServerPort {
		t.Errorf("expected port=%d, got %d", DefaultServerPort, cfg.ServerPort)
	}
}

func TestCreateLoadSaveRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	m, err := NewManagerWithPath(path)
	if err != nil {
		t.Fatal(err)
	}

	m.Update(func(c *Config) {
		c.KeyPath = "~/.ssh/id_rsa"
		c.AllowedOrigins = []string{"http://localhost:3000"}
		c.OriginScopes = map[string][]OriginScope{
			"http://localhost:3000": {{Namespace: "dev"}},
		}
		c.ServerPort = 9999
	})

	m2, err := NewManagerWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := m2.Get()
	if cfg.KeyPath != "~/.ssh/id_rsa" {
		t.Errorf("keyPath mismatch: %q", cfg.KeyPath)
	}
	if len(cfg.AllowedOrigins) != 1 || cfg.AllowedOrigins[0] != "http://localhost:3000" {
		t.Errorf("allowedOrigins mismatch: %v", cfg.AllowedOrigins)
	}
	if cfg.ServerPort != 9999 {
		t.Errorf("port mismatch: %d", cfg.ServerPort)
	}
	scopes := cfg.OriginScopes["http://localhost:3000"]
	if len(scopes) != 1 || scopes[0].Namespace != "dev" {
		t.Errorf("originScopes mismatch: %v", cfg.OriginScopes)
	}
}

func TestUpdatePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	m, err := NewManagerWithPath(path)
	if err != nil {
		t.Fatal(err)
	}

	m.Update(func(c *Config) {
		c.Enabled = false
	})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("config file should not be empty after save")
	}

	m2, err := NewManagerWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if m2.Get().Enabled {
		t.Error("expected enabled=false after reload")
	}
}
