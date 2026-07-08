package policy

import (
	"strings"
	"testing"
)

// baseInput is the happy path under namespace==origin: the RP reports a
// namespace equal to the (allowlisted) link origin.
var baseInput = SignPolicyInput{
	Enabled:   true,
	Challenge: "AbCdEfGhIjKlMnOp_1234",
	Namespace: "http://localhost:8080",
	Origin:    "http://localhost:8080",
	Origins:   []string{"http://localhost:8080"},
}

func withOverrides(overrides func(*SignPolicyInput)) SignPolicyInput {
	input := baseInput
	input.Origins = append([]string(nil), baseInput.Origins...)
	overrides(&input)
	return input
}

func TestAcceptsNamespaceEqualsOrigin(t *testing.T) {
	result := EvaluateSignPolicy(baseInput)
	if !result.OK {
		t.Fatalf("expected ok=true, got error: %s", result.Error)
	}
	if result.Namespace != "http://localhost:8080" {
		t.Errorf("expected namespace to sign with = origin, got %q", result.Namespace)
	}
}

func TestAcceptsLocalhostEquivalence(t *testing.T) {
	// Link origin uses 127.0.0.1, the RP reports localhost — same port, so the
	// origin allowlist and the namespace==origin check both pass via the alias.
	input := withOverrides(func(i *SignPolicyInput) {
		i.Origin = "http://127.0.0.1:8080"
	})
	result := EvaluateSignPolicy(input)
	if !result.OK {
		t.Errorf("expected ok=true, got error: %s", result.Error)
	}
}

func TestRejectsOriginNotAllowed(t *testing.T) {
	input := withOverrides(func(i *SignPolicyInput) {
		i.Origin = "http://localhost:8081"
		i.Namespace = "http://localhost:8081"
	})
	result := EvaluateSignPolicy(input)
	if result.OK {
		t.Error("expected ok=false")
	}
	if !strings.Contains(result.Error, "Origin not allowed") {
		t.Errorf("expected 'Origin not allowed', got: %s", result.Error)
	}
}

func TestRejectsForeignNamespace(t *testing.T) {
	// Origin is allowlisted, but the RP claims a namespace bound to a *different*
	// origin — the core security check that keeps signatures origin-bound.
	input := withOverrides(func(i *SignPolicyInput) {
		i.Namespace = "http://evil.example"
	})
	result := EvaluateSignPolicy(input)
	if result.OK {
		t.Error("expected ok=false for a namespace that isn't the origin")
	}
	if !strings.Contains(result.Error, "Expected Namespace") {
		t.Errorf("expected 'Expected Namespace', got: %s", result.Error)
	}
}

func TestRejectsNonOriginNamespace(t *testing.T) {
	// A bare tag namespace (not a URL) no longer validates — it isn't an origin.
	input := withOverrides(func(i *SignPolicyInput) {
		i.Namespace = "mediasurfer"
	})
	result := EvaluateSignPolicy(input)
	if result.OK {
		t.Error("expected ok=false for a non-origin namespace")
	}
	if !strings.Contains(result.Error, "Expected Namespace") {
		t.Errorf("expected 'Expected Namespace', got: %s", result.Error)
	}
}

func TestRejectsInvalidChallengeFormat(t *testing.T) {
	input := withOverrides(func(i *SignPolicyInput) {
		i.Challenge = "bad!!"
	})
	result := EvaluateSignPolicy(input)
	if result.OK {
		t.Error("expected ok=false")
	}
	if result.Error != "Invalid challenge format" {
		t.Errorf("expected 'Invalid challenge format', got: %s", result.Error)
	}
}

func TestRejectsDisabled(t *testing.T) {
	input := withOverrides(func(i *SignPolicyInput) {
		i.Enabled = false
	})
	result := EvaluateSignPolicy(input)
	if result.OK {
		t.Error("expected ok=false when disabled")
	}
}
