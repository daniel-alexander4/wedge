//go:build linux

package handler

import (
	"os"
	"os/exec"
	"path/filepath"
)

// desktopFileName is the per-user .desktop entry. The .deb installs a
// system-wide wedge.desktop instead; this one (a distinct name) is for
// raw-binary installs and never collides with the packaged one.
const desktopFileName = "wedge-handler.desktop"

// register writes a per-user .desktop entry declaring the wedge:// scheme and
// refreshes the desktop database so the association takes effect. Mirrors the
// mechanism build/wedge.desktop + the .deb postinstall use system-wide.
func register() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	dir := applicationsDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, desktopFileName)
	content := "[Desktop Entry]\n" +
		"Type=Application\n" +
		"Name=wedge\n" +
		"Comment=SSH-key web authentication; launches your sites and SSH hosts\n" +
		"Exec=" + exe + " %u\n" +
		"Icon=wedge\n" +
		"Terminal=false\n" +
		"Categories=X-Other;\n" +
		"MimeType=x-scheme-handler/wedge;\n" +
		"StartupNotify=true\n" +
		"StartupWMClass=Wedge\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return err
	}
	refreshDesktopDatabase(dir)
	return nil
}

func unregister() error {
	path := filepath.Join(applicationsDir(), desktopFileName)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	refreshDesktopDatabase(applicationsDir())
	return nil
}

// applicationsDir is $XDG_DATA_HOME/applications, defaulting to
// ~/.local/share/applications.
func applicationsDir() string {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "applications")
}

// refreshDesktopDatabase rebuilds the scheme→desktop association cache. Best
// effort: absence of update-desktop-database is not fatal (some minimal
// desktops resolve the association without the cache).
func refreshDesktopDatabase(dir string) {
	if _, err := exec.LookPath("update-desktop-database"); err != nil {
		return
	}
	_ = exec.Command("update-desktop-database", dir).Run()
}
