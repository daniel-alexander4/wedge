// Package wedge is the module root. Its only job is to embed the web UI assets
// and the tray icons so the whole app ships as one self-contained binary — no
// loose asset directories to deploy alongside it.
package wedge

import (
	"embed"
	"io/fs"
	"runtime"
)

//go:embed all:web
var webFS embed.FS

// Tray assets, wired per build/icons/README.md §2: the color composite state
// tile at panel size for Linux, the layered .ico for the Windows notification
// area, and the 16px monochrome type glyphs for menu items.
var (
	//go:embed build/icons/png/22x22/wedge-connected.png
	trayIconPNG []byte
	//go:embed build/icons/favicon/wedge.ico
	trayIconICO []byte
	//go:embed build/icons/png/16x16/wedge-glyph-terminal-mono.png
	trayGlyphTerminal []byte
	//go:embed build/icons/png/16x16/wedge-glyph-web-mono.png
	trayGlyphWeb []byte
)

// TrayIcon returns the platform-appropriate tray icon bytes (Windows wants a
// layered .ico; everywhere else takes PNG).
func TrayIcon() []byte {
	if runtime.GOOS == "windows" {
		return trayIconICO
	}
	return trayIconPNG
}

// TrayGlyphTerminal is the 16px mono menu glyph for ssh:// sites.
func TrayGlyphTerminal() []byte { return trayGlyphTerminal }

// TrayGlyphWeb is the 16px mono menu glyph for http(s) sites.
func TrayGlyphWeb() []byte { return trayGlyphWeb }

// WebFS returns the UI asset tree rooted at web/, so "/" maps to index.html.
func WebFS() fs.FS {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err) // embed guarantees web/ exists; a failure here is a build bug
	}
	return sub
}
