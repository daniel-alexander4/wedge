package keyutil

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

func ResolveKeyPath(override string) string {
	p := strings.TrimSpace(override)
	if p == "" {
		p = "~/.ssh/id_ed25519"
	}
	if strings.HasPrefix(p, "~/") {
		if u, err := user.Current(); err == nil {
			p = filepath.Join(u.HomeDir, p[2:])
		}
	}
	return p
}

// ValidateSigningIdentity checks a configured signing identity. A ".pub" path
// is a public key (wedge signs via ssh-agent, so the private half isn't here) —
// it only needs to be a readable regular file, since public keys are 0644 by
// design. Any other path is treated as a private key and held to the strict
// permission checks in ValidateKeyFile.
func ValidateSigningIdentity(path string) error {
	resolved := ResolveKeyPath(path)
	if strings.HasSuffix(resolved, ".pub") {
		return validatePublicKeyFile(resolved)
	}
	return ValidateKeyFile(resolved)
}

func validatePublicKeyFile(resolved string) error {
	info, err := os.Lstat(resolved)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("public key file not found: %s", resolved)
		}
		return fmt.Errorf("cannot stat public key file: %s: %w", resolved, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("key path must not be a symlink: %s", resolved)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("key path is not a regular file: %s", resolved)
	}
	return nil
}

func ValidateKeyFile(path string) error {
	resolved := ResolveKeyPath(path)

	info, err := os.Lstat(resolved)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("key file not found: %s", resolved)
		}
		return fmt.Errorf("cannot stat key file: %s: %w", resolved, err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("key path is not a regular file: %s", resolved)
	}

	// Check symlink
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("key path must not be a symlink: %s", resolved)
	}

	if runtime.GOOS != "windows" {
		// Check ownership
		uid := os.Getuid()
		if uid >= 0 {
			stat := info.Sys()
			if stat != nil {
				if sysUID := fileUID(stat); sysUID >= 0 && sysUID != uid {
					return fmt.Errorf("key file is not owned by current user: %s", resolved)
				}
			}
		}

		// Check permissions
		mode := info.Mode().Perm()
		if mode&0o077 != 0 {
			return fmt.Errorf("key file permissions are too open (%#o), expected 0o600 or stricter", mode)
		}
	}

	return nil
}
