package keyutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResolveKeyPathDefault(t *testing.T) {
	p := ResolveKeyPath("")
	if !strings.HasSuffix(p, ".ssh/id_ed25519") {
		t.Errorf("expected default key path ending in .ssh/id_ed25519, got %q", p)
	}
}

func TestResolveKeyPathTilde(t *testing.T) {
	p := ResolveKeyPath("~/.ssh/id_rsa")
	if strings.HasPrefix(p, "~") {
		t.Errorf("tilde should be expanded, got %q", p)
	}
	if !strings.HasSuffix(p, ".ssh/id_rsa") {
		t.Errorf("expected path ending in .ssh/id_rsa, got %q", p)
	}
}

func TestValidateKeyFileMissing(t *testing.T) {
	err := ValidateKeyFile("/nonexistent/path/id_ed25519")
	if err == nil {
		t.Error("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %s", err)
	}
}

func TestValidateKeyFilePermsTooOpen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission checks skipped on Windows")
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "id_test")
	os.WriteFile(keyFile, []byte("dummy"), 0644)

	err := ValidateKeyFile(keyFile)
	if err == nil {
		t.Error("expected error for open permissions")
	}
	if !strings.Contains(err.Error(), "too open") {
		t.Errorf("expected 'too open' in error, got: %s", err)
	}
}

func TestValidateKeyFileValid(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission checks skipped on Windows")
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "id_test")
	os.WriteFile(keyFile, []byte("dummy"), 0600)

	err := ValidateKeyFile(keyFile)
	if err != nil {
		t.Errorf("expected no error, got: %s", err)
	}
}

func TestValidateSigningIdentityPublicKey(t *testing.T) {
	dir := t.TempDir()
	pub := filepath.Join(dir, "id_ed25519.pub")
	// Public keys are world-readable (0644) by design; ValidateSigningIdentity
	// must accept that for a .pub path (agent-backed signing), unlike a private key.
	os.WriteFile(pub, []byte("ssh-ed25519 AAAA test@host\n"), 0644)

	if err := ValidateSigningIdentity(pub); err != nil {
		t.Errorf("expected .pub with 0644 perms to validate, got: %s", err)
	}
}

func TestValidateSigningIdentityMissingPublicKey(t *testing.T) {
	err := ValidateSigningIdentity("/nonexistent/id_ed25519.pub")
	if err == nil {
		t.Error("expected error for missing public key")
	}
}
