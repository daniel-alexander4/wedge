package keyutil

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DiscoveredKey is one public key found in the user's ~/.ssh directory, with
// whether its private half is currently loaded in the ssh-agent. Only
// agent-loaded keys can actually sign (wedge never touches private key files),
// so AgentLoaded is the gate on which keys the sign path will try.
type DiscoveredKey struct {
	Path        string `json:"path"`
	Type        string `json:"type"`
	Comment     string `json:"comment"`
	Fingerprint string `json:"fingerprint"`
	AgentLoaded bool   `json:"agentLoaded"`
}

// sshDir returns <home>/.ssh. os.UserHomeDir is correct on all three OSes —
// Linux/macOS use $HOME/.ssh, Windows uses %USERPROFILE%\.ssh (same subdir).
func sshDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh"), nil
}

// DiscoverKeys enumerates ~/.ssh/*.pub, parses each via `ssh-keygen -lf`, and
// marks the ones whose fingerprint appears in `ssh-add -l` as agent-loaded.
// Files that don't parse as public keys are skipped. A missing/empty agent just
// leaves every key AgentLoaded=false — never an error.
func DiscoverKeys() ([]DiscoveredKey, error) {
	dir, err := sshDir()
	if err != nil {
		return nil, err
	}
	matches, err := filepath.Glob(filepath.Join(dir, "*.pub"))
	if err != nil {
		return nil, err
	}
	loaded := agentFingerprints()

	keygen := keygenBinary()
	out := make([]DiscoveredKey, 0, len(matches))
	for _, path := range matches {
		k, ok := describeKey(keygen, path)
		if !ok {
			continue
		}
		k.AgentLoaded = loaded[k.Fingerprint]
		out = append(out, k)
	}
	return out, nil
}

// SignableKeys returns the discovered keys that are loaded in the agent — the
// exact set the sign path iterates (try-next), in discovery order.
func SignableKeys() ([]DiscoveredKey, error) {
	keys, err := DiscoverKeys()
	if err != nil {
		return nil, err
	}
	signable := make([]DiscoveredKey, 0, len(keys))
	for _, k := range keys {
		if k.AgentLoaded {
			signable = append(signable, k)
		}
	}
	return signable, nil
}

func keygenBinary() string {
	if p := os.Getenv("SSH_KEYGEN_PATH"); p != "" {
		return p
	}
	return "ssh-keygen"
}

// describeKey runs `ssh-keygen -lf <path>` and parses its
// "<bits> <fingerprint> <comment...> (<TYPE>)" line.
func describeKey(keygen, path string) (DiscoveredKey, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, keygen, "-l", "-f", path).Output()
	if err != nil {
		return DiscoveredKey{}, false
	}
	fp, comment, typ, ok := parseKeygenLine(string(out))
	if !ok {
		return DiscoveredKey{}, false
	}
	return DiscoveredKey{Path: path, Type: typ, Comment: comment, Fingerprint: fp}, true
}

// agentFingerprints returns the set of SHA256 fingerprints the ssh-agent holds.
// Any failure (no agent, no identities) yields an empty set, not an error.
func agentFingerprints() map[string]bool {
	set := map[string]bool{}
	if os.Getenv("SSH_AUTH_SOCK") == "" {
		return set
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ssh-add", "-l").Output()
	if err != nil {
		return set
	}
	for _, line := range strings.Split(string(out), "\n") {
		if fp, _, _, ok := parseKeygenLine(line); ok {
			set[fp] = true
		}
	}
	return set
}

// parseKeygenLine parses one "<bits> SHA256:<fp> <comment...> (<TYPE>)" line as
// emitted by both `ssh-keygen -lf` and `ssh-add -l`.
func parseKeygenLine(line string) (fingerprint, comment, keyType string, ok bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 3 {
		return "", "", "", false
	}
	fingerprint = fields[1]
	if !strings.HasPrefix(fingerprint, "SHA256:") && !strings.HasPrefix(fingerprint, "MD5:") {
		return "", "", "", false
	}
	last := fields[len(fields)-1]
	keyType = strings.TrimSuffix(strings.TrimPrefix(last, "("), ")")
	comment = strings.Join(fields[2:len(fields)-1], " ")
	return fingerprint, comment, keyType, true
}
