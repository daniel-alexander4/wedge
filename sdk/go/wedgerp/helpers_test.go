package wedgerp

// Shared fixtures: a real throwaway SSH key and real SSHSIG signatures, so a
// passing suite proves interop with the OpenSSH on the machine (same
// discipline as the Python and Node suites). Error-path tests use a fake
// ssh-keygen via SSH_KEYGEN_PATH, like internal/signer's tests.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func requireSSHKeygen(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not installed")
	}
}

type keyPair struct {
	keyPath   string
	publicKey string
}

func newKeyPair(t *testing.T, comment string) keyPair {
	t.Helper()
	requireSSHKeygen(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-C", comment, "-q", "-f", keyPath).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -t ed25519: %v: %s", err, out)
	}
	pub, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatalf("read pubkey: %v", err)
	}
	return keyPair{keyPath: keyPath, publicKey: strings.TrimSpace(string(pub))}
}

// sign makes an armored SSHSIG over challenge, like the wedge app does.
func (k keyPair) sign(t *testing.T, challenge, namespace string) string {
	t.Helper()
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-f", k.keyPath, "-n", namespace)
	cmd.Stdin = strings.NewReader(challenge)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ssh-keygen -Y sign: %v", err)
	}
	return string(out)
}

// fakeKeygen installs a script as ssh-keygen via SSH_KEYGEN_PATH (the
// internal/signer test trick) for error-path tests.
func fakeKeygen(t *testing.T, script string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-keygen")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatalf("write fake keygen: %v", err)
	}
	t.Setenv("SSH_KEYGEN_PATH", path)
}
