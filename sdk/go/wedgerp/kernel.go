// Signature-verification kernel: shells out to `ssh-keygen -Y verify`
// (OpenSSH 8.1+), so wedgerp implements no cryptography of its own —
// verification behaves exactly like sshd's allowed_signers handling. Only
// public keys and signatures pass through here; private keys never leave the
// user's ssh-agent.
//
// Mirrors internal/signer's shell-out conventions (env-overridable binary,
// context timeout, argv-only, 0600 temp files) and the Python/Node kernels'
// semantics — keep the validation rules in lockstep with
// sdk/python/wedge_rp/kernel.py and sdk/node/lib/kernel.js.

package wedgerp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// The principal is the first token of an allowed_signers line, so it must be
// a single inert token: no whitespace, and none of the characters ssh-keygen
// treats as comments, quoting, or patterns ("#", '"', "*", "?", ",").
var principalRegex = regexp.MustCompile(`^[A-Za-z0-9._@+=-]{1,256}$`)

var (
	keytypeRegex = regexp.MustCompile(`^[A-Za-z0-9@.-]{1,64}$`)
	// Go's regexp caps {m,n} at 1000, so the 16384-byte bound the other SDK
	// kernels encode in-pattern is a separate length check here.
	keydataRegex = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)
)

const maxKeyDataBytes = 16384

const (
	sigHeader         = "-----BEGIN SSH SIGNATURE-----"
	maxSignatureBytes = 64 * 1024

	// DefaultVerifyTimeout bounds one ssh-keygen -Y verify run.
	DefaultVerifyTimeout = 10 * time.Second
)

// ErrSSHKeygenUnavailable reports that ssh-keygen is missing or too old for
// `-Y verify` (needs OpenSSH 8.1+) — a server misconfiguration, not a bad
// login.
var ErrSSHKeygenUnavailable = errors.New("ssh-keygen unavailable")

// keygenBinary returns the ssh-keygen to exec, overridable for tests via
// SSH_KEYGEN_PATH (same convention as internal/signer and internal/keyutil).
func keygenBinary() string {
	if p := os.Getenv("SSH_KEYGEN_PATH"); p != "" {
		return p
	}
	return "ssh-keygen"
}

// SplitPublicKey returns the (keytype, base64data) of an OpenSSH public-key
// line, dropping any trailing comment; ok=false if the line doesn't look like
// a public key.
func SplitPublicKey(publicKey string) (keytype, keydata string, ok bool) {
	fields := strings.Fields(strings.TrimSpace(publicKey))
	if len(fields) < 2 {
		return "", "", false
	}
	if !keytypeRegex.MatchString(fields[0]) ||
		len(fields[1]) > maxKeyDataBytes || !keydataRegex.MatchString(fields[1]) {
		return "", "", false
	}
	return fields[0], fields[1], true
}

// SameKey reports whether two public-key lines denote the same key (type +
// data; comments and surrounding whitespace ignored). Use it to implement
// Config.FindUserByPublicKey.
func SameKey(a, b string) bool {
	at, ad, aok := SplitPublicKey(a)
	bt, bd, bok := SplitPublicKey(b)
	return aok && bok && at == bt && ad == bd
}

// VerifySignature verifies an armored SSHSIG signature over the exact bytes
// of challenge, made with namespace, against publicKey.
//
// A failed verification is a normal outcome: (false, reason, nil). A non-nil
// error means the environment is broken (ErrSSHKeygenUnavailable).
func VerifySignature(challenge, signature, principal, publicKey, namespace string, timeout time.Duration) (bool, string, error) {
	if !principalRegex.MatchString(principal) {
		return false, "invalid principal", nil
	}
	keytype, keydata, ok := SplitPublicKey(publicKey)
	if !ok {
		return false, "malformed public key", nil
	}
	if !strings.HasPrefix(strings.TrimLeft(signature, " \t\r\n"), sigHeader) || len(signature) > maxSignatureBytes {
		return false, "malformed signature", nil
	}
	if namespace == "" || strings.ContainsAny(namespace, "\n\x00") {
		return false, "invalid namespace", nil
	}

	dir, err := os.MkdirTemp("", "wedge-rp-")
	if err != nil {
		return false, "", fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(dir)
	allowed := filepath.Join(dir, "allowed_signers")
	sigfile := filepath.Join(dir, "challenge.sig")
	line := fmt.Sprintf("%s %s %s\n", principal, keytype, keydata)
	if err := os.WriteFile(allowed, []byte(line), 0o600); err != nil {
		return false, "", fmt.Errorf("write allowed_signers: %w", err)
	}
	if err := os.WriteFile(sigfile, []byte(strings.TrimSpace(signature)+"\n"), 0o600); err != nil {
		return false, "", fmt.Errorf("write signature: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, keygenBinary(),
		"-Y", "verify",
		"-f", allowed,
		"-I", principal,
		"-n", namespace,
		"-s", sigfile,
	)
	cmd.Stdin = strings.NewReader(challenge)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if runErr == nil {
		detail := strings.TrimSpace(stdout.String())
		if detail == "" {
			detail = "signature verified"
		}
		return true, detail, nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return false, "verification timed out", nil
	}
	// exec.ErrNotFound covers PATH lookups; os.ErrNotExist covers an explicit
	// SSH_KEYGEN_PATH pointing nowhere.
	if errors.Is(runErr, exec.ErrNotFound) || errors.Is(runErr, os.ErrNotExist) {
		return false, "", fmt.Errorf("%w: ssh-keygen not found — install openssh-client", ErrSSHKeygenUnavailable)
	}
	errText := strings.TrimSpace(stderr.String())
	if strings.Contains(errText, "unknown option") || strings.HasPrefix(strings.ToLower(errText), "usage:") {
		return false, "", fmt.Errorf("%w: ssh-keygen lacks -Y verify — OpenSSH 8.1+ required", ErrSSHKeygenUnavailable)
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		if errText == "" {
			errText = strings.TrimSpace(stdout.String())
		}
		if errText == "" {
			errText = "signature verification failed"
		}
		return false, errText, nil
	}
	return false, "", fmt.Errorf("ssh-keygen: %w", runErr)
}
