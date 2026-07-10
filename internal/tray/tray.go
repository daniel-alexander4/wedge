// Package tray puts wedge in the system tray: the sites list as a menu (the
// GTM quick-launch — open a shell or sign into a site without the settings
// window), plus Open wedge and Quit. The real implementation exists on Linux
// (D-Bus StatusNotifierItem) and Windows (win32), both pure Go, so the
// CGO_ENABLED=0 release matrix is untouched; macOS needs cgo and gets the
// no-op stub until the mac support push builds natively.
package tray

import "strings"

// Site is one launchable menu entry.
type Site struct {
	Origin string
	SSH    bool // ssh:// → terminal launch; otherwise sign-in-then-open
}

// NewSite classifies an origin for the menu.
func NewSite(origin string) Site {
	return Site{Origin: origin, SSH: strings.HasPrefix(origin, "ssh://")}
}

// Deps carries everything the tray needs from the app. The action funcs run on
// their own goroutines (a sign-in can block on the consent tap for 45s).
type Deps struct {
	Version  string
	Icon     []byte // platform tray icon (PNG, or ICO on Windows)
	GlyphSSH []byte // 16px mono menu glyph for ssh sites
	GlyphWeb []byte // 16px mono menu glyph for web sites
	Sites    func() []Site
	OpenUI   func()
	Launch   func(Site)
}
