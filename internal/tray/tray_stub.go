//go:build !linux && !windows

package tray

// The tray backends (fyne.io/systray) need cgo on macOS, which the
// CGO_ENABLED=0 cross-compile matrix in build.sh can't provide — so darwin
// (and anything else) gets this no-op stub. macOS tray support lands with the
// native mac build (see pending.md, mac gaps).

// Supported reports whether this build carries a real tray.
func Supported() bool { return false }

// Run is a no-op; main gates on Supported() and never calls it here.
func Run(Deps) {}

// Quit is a no-op.
func Quit() {}

// Refresh is a no-op.
func Refresh() {}
