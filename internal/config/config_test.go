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
	if len(cfg.Sites) != 0 {
		t.Errorf("expected no sites by default, got %v", cfg.Sites)
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
		c.Sites = []Site{{Origin: "http://localhost:3000", AlwaysAllow: true}}
		c.ServerPort = 9999
	})

	m2, err := NewManagerWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := m2.Get()
	if cfg.ServerPort != 9999 {
		t.Errorf("port mismatch: %d", cfg.ServerPort)
	}
	if len(cfg.Sites) != 1 || cfg.Sites[0].Origin != "http://localhost:3000" || !cfg.Sites[0].AlwaysAllow {
		t.Errorf("sites mismatch: %v", cfg.Sites)
	}
}

func TestOnChangeFiresAfterUpdate(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManagerWithPath(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	fired := 0
	m.OnChange(func() { fired++ })
	if err := m.Update(func(c *Config) { c.Enabled = false }); err != nil {
		t.Fatal(err)
	}
	if fired != 1 {
		t.Errorf("onChange fired %d times, want 1", fired)
	}
	// The callback may itself read the config (the tray rebuilds its menu) —
	// must not deadlock and must see the new value.
	m.OnChange(func() {
		fired++
		if m.Get().Enabled {
			t.Error("onChange read stale config")
		}
	})
	if err := m.Update(func(c *Config) { c.Enabled = false }); err != nil {
		t.Fatal(err)
	}
	if fired != 2 {
		t.Errorf("onChange fired %d times total, want 2", fired)
	}
}

func TestTunnelsJumpRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	m, err := NewManagerWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	m.Update(func(c *Config) {
		c.Sites = []Site{{Origin: "ssh://web1", Tunnels: []string{"8080:localhost:80", "1080"}, Jump: "dan@bastion:22"}}
	})

	m2, err := NewManagerWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	s := m2.Get().Sites[0]
	if len(s.Tunnels) != 2 || s.Tunnels[0] != "8080:localhost:80" || s.Tunnels[1] != "1080" || s.Jump != "dan@bastion:22" {
		t.Errorf("tunnels/jump did not round-trip: %+v", s)
	}
}

func TestMigratesLegacyConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	legacy := `{
	  "enabled": true,
	  "keyPath": "~/.ssh/id_ed25519.pub",
	  "allowedOrigins": ["http://a.example", "http://b.example"],
	  "originScopes": {
	    "http://a.example": [{"namespace": "a", "alwaysAllow": true}],
	    "http://b.example": [{"namespace": "b", "silent": true}]
	  },
	  "serverPort": 7890
	}`
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := NewManagerWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := m.Get()
	if len(cfg.Sites) != 2 {
		t.Fatalf("expected 2 migrated sites, got %v", cfg.Sites)
	}
	// allowedOrigins order is preserved.
	if cfg.Sites[0].Origin != "http://a.example" || !cfg.Sites[0].AlwaysAllow {
		t.Errorf("site 0 mismatch: %+v", cfg.Sites[0])
	}
	if cfg.Sites[1].Origin != "http://b.example" || !cfg.Sites[1].Silent {
		t.Errorf("site 1 mismatch: %+v", cfg.Sites[1])
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
