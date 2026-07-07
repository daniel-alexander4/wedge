// Package wedge is the module root. Its only job is to embed the web UI assets
// so the whole app ships as one self-contained binary — no loose web/ directory
// to deploy alongside it.
package wedge

import (
	"embed"
	"io/fs"
)

//go:embed all:web
var webFS embed.FS

// WebFS returns the UI asset tree rooted at web/, so "/" maps to index.html.
func WebFS() fs.FS {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err) // embed guarantees web/ exists; a failure here is a build bug
	}
	return sub
}
