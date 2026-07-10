package conform

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// KeyPair is the harness's throwaway signing identity — a passphrase-less
// ed25519 file key, signed with directly via ssh-keygen (never an agent),
// mirroring the SDK conformance suites' helpers.
type KeyPair struct {
	Path      string // private key file
	PublicKey string // the "ssh-ed25519 AAAA… comment" line
}

func keygenBinary() string {
	if p := os.Getenv("SSH_KEYGEN_PATH"); p != "" {
		return p
	}
	return "ssh-keygen"
}

// GenerateKey mints a throwaway ed25519 keypair under dir.
func GenerateKey(dir string) (*KeyPair, error) {
	path := filepath.Join(dir, "wedge-conform_ed25519")
	cmd := exec.Command(keygenBinary(), "-t", "ed25519", "-N", "", "-C", "wedge-conform", "-q", "-f", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ssh-keygen -t ed25519: %v: %s", err, out)
	}
	return LoadKey(path)
}

// LoadKey wraps an existing private key file (its .pub must sit beside it).
func LoadKey(path string) (*KeyPair, error) {
	pub, err := os.ReadFile(path + ".pub")
	if err != nil {
		return nil, fmt.Errorf("reading public key: %w", err)
	}
	return &KeyPair{Path: path, PublicKey: strings.TrimSpace(string(pub))}, nil
}

// Sign produces the armored SSHSIG over the exact challenge bytes under the
// given namespace (spec §5.3): ssh-keygen -Y sign, challenge on stdin.
func (k *KeyPair) Sign(challenge, namespace string) (string, error) {
	cmd := exec.Command(keygenBinary(), "-Y", "sign", "-f", k.Path, "-n", namespace)
	cmd.Stdin = strings.NewReader(challenge)
	out, err := run(cmd, 10*time.Second)
	if err != nil {
		return "", fmt.Errorf("ssh-keygen -Y sign: %w", err)
	}
	return out, nil
}

func run(cmd *exec.Cmd, timeout time.Duration) (string, error) {
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(errb.String()))
		}
		return out.String(), nil
	case <-time.After(timeout):
		cmd.Process.Kill()
		return "", fmt.Errorf("timed out after %s", timeout)
	}
}
