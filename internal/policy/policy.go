package policy

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"wedge/internal/config"
)

var (
	challengeRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}$`)
	namespaceRegex = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
	companyRegex   = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
)

type SignPolicyInput struct {
	Enabled        bool
	Challenge      string
	Namespace      string
	Company        string
	Origin         string
	AllowedOrigins []string
	OriginScopes   map[string][]config.OriginScope
}

type SignPolicyResult struct {
	OK                bool
	Error             string
	Origin            string
	ExpectedNamespace string
	ExpectedCompany   string
	Challenge         string
}

func NormalizeOrigin(value string) string {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	// Reconstruct origin as scheme://host (includes port if present)
	return u.Scheme + "://" + u.Host
}

func NormalizeNamespace(value string) string {
	v := strings.TrimSpace(value)
	if namespaceRegex.MatchString(v) {
		return v
	}
	return ""
}

func NormalizeCompany(value string) string {
	v := strings.TrimSpace(value)
	if companyRegex.MatchString(v) {
		return v
	}
	return ""
}

func EquivalentOrigins(origin string) []string {
	origins := []string{origin}
	u, err := url.Parse(origin)
	if err != nil {
		return origins
	}
	hostname := u.Hostname()
	port := u.Port()
	if hostname == "localhost" {
		alt := u.Scheme + "://127.0.0.1"
		if port != "" {
			alt += ":" + port
		}
		origins = append(origins, alt)
	} else if hostname == "127.0.0.1" {
		alt := u.Scheme + "://localhost"
		if port != "" {
			alt += ":" + port
		}
		origins = append(origins, alt)
	}
	return origins
}

func EvaluateSignPolicy(input SignPolicyInput) SignPolicyResult {
	if !input.Enabled {
		return SignPolicyResult{OK: false, Error: "Signing is disabled"}
	}

	challenge := strings.TrimSpace(input.Challenge)
	namespace := strings.TrimSpace(input.Namespace)
	company := strings.TrimSpace(input.Company)
	origin := NormalizeOrigin(strings.TrimSpace(input.Origin))

	if challenge == "" || namespace == "" || origin == "" {
		return SignPolicyResult{OK: false, Error: "Missing challenge, namespace, or origin"}
	}

	if !challengeRegex.MatchString(challenge) {
		return SignPolicyResult{OK: false, Error: "Invalid challenge format"}
	}

	if NormalizeNamespace(namespace) == "" {
		return SignPolicyResult{OK: false, Error: "Invalid namespace format"}
	}
	if company != "" && NormalizeCompany(company) == "" {
		return SignPolicyResult{OK: false, Error: "Invalid company format"}
	}

	// Check origin against allowlist
	matchedOrigin := ""
	for _, candidate := range EquivalentOrigins(origin) {
		for _, allowed := range input.AllowedOrigins {
			if candidate == allowed {
				matchedOrigin = candidate
				break
			}
		}
		if matchedOrigin != "" {
			break
		}
	}
	if matchedOrigin == "" {
		return SignPolicyResult{OK: false, Error: fmt.Sprintf("Origin not allowed: %s", origin)}
	}

	// Find scopes for origin
	var expectedScopes []config.OriginScope
	for _, candidate := range EquivalentOrigins(origin) {
		if scopes, ok := input.OriginScopes[candidate]; ok {
			expectedScopes = scopes
			break
		}
	}
	if len(expectedScopes) == 0 {
		return SignPolicyResult{OK: false, Error: fmt.Sprintf("No namespace configured for origin: %s", origin)}
	}

	// Check namespace match
	var namespaceMatches []config.OriginScope
	for _, scope := range expectedScopes {
		if strings.TrimSpace(scope.Namespace) == namespace {
			namespaceMatches = append(namespaceMatches, scope)
		}
	}
	if len(namespaceMatches) == 0 {
		configuredNamespaces := []string{}
		seen := map[string]bool{}
		for _, scope := range expectedScopes {
			ns := strings.TrimSpace(scope.Namespace)
			if ns != "" && !seen[ns] {
				configuredNamespaces = append(configuredNamespaces, ns)
				seen[ns] = true
			}
		}
		expectedNS := "<none>"
		if len(configuredNamespaces) > 0 {
			expectedNS = configuredNamespaces[0]
		}
		receivedNS := namespace
		if receivedNS == "" {
			receivedNS = "<empty>"
		}
		return SignPolicyResult{
			OK:    false,
			Error: fmt.Sprintf("ERROR\nExpected Namespace: %s\nReceived Namespace: %s", expectedNS, receivedNS),
		}
	}

	// Check company match
	var matchingScope *config.OriginScope
	for i, scope := range namespaceMatches {
		expectedCompany := strings.TrimSpace(scope.Company)
		if expectedCompany == "" {
			matchingScope = &namespaceMatches[i]
			break
		}
		if company == expectedCompany {
			matchingScope = &namespaceMatches[i]
			break
		}
	}
	if matchingScope == nil {
		expectedCompany := strings.TrimSpace(namespaceMatches[0].Company)
		receivedCompany := company
		if receivedCompany == "" {
			receivedCompany = "<empty>"
		}
		return SignPolicyResult{
			OK:    false,
			Error: fmt.Sprintf("ERROR\nExpected Company: %s\nReceived Company: %s", expectedCompany, receivedCompany),
		}
	}

	resultNS := strings.TrimSpace(matchingScope.Namespace)
	resultCompany := strings.TrimSpace(matchingScope.Company)

	return SignPolicyResult{
		OK:                true,
		Origin:            origin,
		ExpectedNamespace: resultNS,
		ExpectedCompany:   resultCompany,
		Challenge:         challenge,
	}
}
