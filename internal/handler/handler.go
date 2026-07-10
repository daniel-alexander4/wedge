// Package handler registers (and unregisters) this binary as the OS handler
// for the wedge:// URL scheme, so a website's wedge://sign link launches wedge.
//
// This is the self-service path for installs that don't run the .deb (whose
// postinstall already registers the handler on Linux): `wedge
// --register-handler`. Each OS has its own mechanism — Linux a per-user
// .desktop entry, Windows an HKCU registry key, macOS Launch Services against
// the .app bundle — behind the shared Register/Unregister API.
package handler

// Register installs this binary as the wedge:// scheme handler for the current
// user. It is idempotent: re-registering just refreshes the entry.
func Register() error { return register() }

// Unregister removes the wedge:// handler registration for the current user.
func Unregister() error { return unregister() }
