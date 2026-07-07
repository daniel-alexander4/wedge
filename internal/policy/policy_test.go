package policy

import (
	"strings"
	"testing"

	"wedge/internal/config"
)

var baseConfig = SignPolicyInput{
	Enabled:        true,
	Challenge:      "AbCdEfGhIjKlMnOp_1234",
	Namespace:      "myapp",
	Origin:         "http://localhost:8080",
	AllowedOrigins: []string{"http://localhost:8080"},
	OriginScopes: map[string][]config.OriginScope{
		"http://localhost:8080": {{Namespace: "myapp"}},
	},
}

func withOverrides(overrides func(*SignPolicyInput)) SignPolicyInput {
	input := baseConfig
	// Deep copy maps
	input.AllowedOrigins = make([]string, len(baseConfig.AllowedOrigins))
	copy(input.AllowedOrigins, baseConfig.AllowedOrigins)
	input.OriginScopes = make(map[string][]config.OriginScope, len(baseConfig.OriginScopes))
	for k, v := range baseConfig.OriginScopes {
		s := make([]config.OriginScope, len(v))
		copy(s, v)
		input.OriginScopes[k] = s
	}
	overrides(&input)
	return input
}

func TestAcceptsLocalhostEquivalence(t *testing.T) {
	input := withOverrides(func(i *SignPolicyInput) {
		i.Origin = "http://127.0.0.1:8080"
	})
	result := EvaluateSignPolicy(input)
	if !result.OK {
		t.Errorf("expected ok=true, got error: %s", result.Error)
	}
}

func TestRejectsOriginMismatch(t *testing.T) {
	input := withOverrides(func(i *SignPolicyInput) {
		i.Origin = "http://localhost:8081"
	})
	result := EvaluateSignPolicy(input)
	if result.OK {
		t.Error("expected ok=false")
	}
	if !strings.Contains(result.Error, "Origin not allowed") {
		t.Errorf("expected 'Origin not allowed' in error, got: %s", result.Error)
	}
}

func TestRejectsNamespaceMismatch(t *testing.T) {
	input := withOverrides(func(i *SignPolicyInput) {
		i.Namespace = "wrong-namespace"
	})
	result := EvaluateSignPolicy(input)
	if result.OK {
		t.Error("expected ok=false")
	}
	if !strings.Contains(result.Error, "Expected Namespace") {
		t.Errorf("expected 'Expected Namespace' in error, got: %s", result.Error)
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

func TestRejectsNoNamespaceMapping(t *testing.T) {
	input := withOverrides(func(i *SignPolicyInput) {
		i.OriginScopes = map[string][]config.OriginScope{}
	})
	result := EvaluateSignPolicy(input)
	if result.OK {
		t.Error("expected ok=false")
	}
	if !strings.Contains(result.Error, "No namespace configured for origin") {
		t.Errorf("expected 'No namespace configured for origin' in error, got: %s", result.Error)
	}
}

func TestRejectsCompanyMismatch(t *testing.T) {
	input := withOverrides(func(i *SignPolicyInput) {
		i.Company = "wrong-company"
		i.OriginScopes = map[string][]config.OriginScope{
			"http://localhost:8080": {{Namespace: "myapp", Company: "mycompany"}},
		}
	})
	result := EvaluateSignPolicy(input)
	if result.OK {
		t.Error("expected ok=false")
	}
	if !strings.Contains(result.Error, "Expected Company") {
		t.Errorf("expected 'Expected Company' in error, got: %s", result.Error)
	}
}

func TestAcceptsMultipleNamespaces(t *testing.T) {
	input := withOverrides(func(i *SignPolicyInput) {
		i.Namespace = "registry-namespace-admin"
		i.OriginScopes = map[string][]config.OriginScope{
			"http://localhost:8080": {
				{Namespace: "registry-admin"},
				{Namespace: "registry-namespace-admin"},
			},
		}
	})
	result := EvaluateSignPolicy(input)
	if !result.OK {
		t.Errorf("expected ok=true, got error: %s", result.Error)
	}
}
