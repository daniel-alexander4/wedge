//go:build !linux

// Package singleton — non-Linux fallback. macOS/Windows single-instance
// take-over is handled at the OS launcher level; this is a no-op so the rest of
// the app compiles and runs everywhere. (Phase 2 adds URL-forwarding to a
// running instance for the wedge:// handler.)
package singleton

// ReplaceOthers is a no-op on non-Linux platforms and reports zero replaced.
func ReplaceOthers() int { return 0 }
