//go:build linux

package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRegisterWritesSchemeDesktopEntry drives the real register/unregister
// round-trip against a temp XDG_DATA_HOME and asserts the .desktop entry
// declares the wedge:// scheme and points Exec at this binary.
func TestRegisterWritesSchemeDesktopEntry(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_DATA_HOME", tmp)

	if err := Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	path := filepath.Join(tmp, "applications", desktopFileName)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading desktop entry: %v", err)
	}
	s := string(body)
	// The scheme declaration is what makes update-desktop-database build the
	// x-scheme-handler/wedge association.
	if !strings.Contains(s, "MimeType=x-scheme-handler/wedge;") {
		t.Errorf("desktop entry missing scheme MimeType:\n%s", s)
	}
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	if !strings.Contains(s, "Exec="+exe+" %u") {
		t.Errorf("Exec line does not point at this binary (%s):\n%s", exe, s)
	}

	if err := Unregister(); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("desktop entry still present after Unregister")
	}
}
