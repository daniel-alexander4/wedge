package signer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"wedge/internal/keyutil"
)

const DefaultTimeout = 10 * time.Second

var (
	challengeRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}$`)
	namespaceRegex = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
)

func Sign(challenge, namespace, keyPath string, timeout time.Duration) (string, error) {
	challenge = strings.TrimSpace(challenge)
	namespace = strings.TrimSpace(namespace)

	if challenge == "" {
		return "", fmt.Errorf("challenge is empty")
	}
	if namespace == "" {
		return "", fmt.Errorf("namespace is empty")
	}
	if !challengeRegex.MatchString(challenge) {
		return "", fmt.Errorf("invalid challenge format")
	}
	if !namespaceRegex.MatchString(namespace) {
		return "", fmt.Errorf("invalid namespace format")
	}

	resolvedKey := keyutil.ResolveKeyPath(keyPath)
	if err := keyutil.ValidateSigningIdentity(resolvedKey); err != nil {
		return "", err
	}

	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	keygen := os.Getenv("SSH_KEYGEN_PATH")
	if keygen == "" {
		keygen = "ssh-keygen"
	}

	tmpDir, err := os.MkdirTemp("", "pubkey-auth-")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	challengeFile := filepath.Join(tmpDir, "challenge")
	sigFile := filepath.Join(tmpDir, "challenge.sig")

	if err := os.WriteFile(challengeFile, []byte(challenge), 0600); err != nil {
		return "", fmt.Errorf("failed to write challenge file: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, keygen,
		"-Y", "sign",
		"-f", resolvedKey,
		"-n", namespace,
		challengeFile,
	)
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("ssh-keygen sign timed out after %s", timeout)
	}
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("ssh-keygen sign failed (code %d): %s", exitErr.ExitCode(), detail)
		}
		return "", fmt.Errorf("ssh-keygen sign failed: %s", detail)
	}

	sigData, err := os.ReadFile(sigFile)
	if err != nil {
		return "", fmt.Errorf("signature file was not created by ssh-keygen")
	}

	signature := strings.TrimSpace(string(sigData))
	if signature == "" {
		return "", fmt.Errorf("signature file is empty")
	}

	return signature, nil
}
