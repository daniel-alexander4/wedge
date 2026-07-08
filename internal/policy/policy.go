package policy

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// challengeRegex bounds the one-time challenge to a URL-safe token. This is a
// security boundary and must stay byte-identical to the RP's challenge format.
var challengeRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}$`)

// SignPolicyInput is the decision input for a single wedge:// sign. Under the
// namespace==origin model the namespace is not a free-form tag: it is the RP's
// canonical origin, so it is validated as an origin equivalent to the link's
// origin — not against a character-class regex (which forbade the "/" a URL
// needs). See docs/wedge-protocol.md.
type SignPolicyInput struct {
	Enabled   bool
	Challenge string
	Namespace string   // reported by the RP's challenge response
	Origin    string   // from the wedge:// link (attacker-controllable lookup key)
	Origins   []string // configured site allowlist
}

type SignPolicyResult struct {
	OK        bool
	Error     string
	Origin    string // normalized link origin
	Namespace string // the value to sign with (the RP's reported namespace)
	Challenge string
}

func NormalizeOrigin(value string) string {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	// Reconstruct origin as scheme://host (includes port if present)
	return u.Scheme + "://" + u.Host
}

// EquivalentOrigins returns origin plus its localhost↔127.0.0.1 alias, preserving
// scheme and port. This is the equivalence used for both allowlist matching and
// the namespace==origin check, so a link using localhost and an RP reporting
// 127.0.0.1 (or vice versa) still line up.
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

// originsEquivalent reports whether a and b are the same origin up to the
// localhost↔127.0.0.1 alias. Both must already be normalized origins.
func originsEquivalent(a, b string) bool {
	for _, cand := range EquivalentOrigins(a) {
		if cand == b {
			return true
		}
	}
	return false
}

func EvaluateSignPolicy(input SignPolicyInput) SignPolicyResult {
	if !input.Enabled {
		return SignPolicyResult{OK: false, Error: "Signing is disabled"}
	}

	challenge := strings.TrimSpace(input.Challenge)
	namespace := strings.TrimSpace(input.Namespace)
	origin := NormalizeOrigin(strings.TrimSpace(input.Origin))

	if challenge == "" || namespace == "" || origin == "" {
		return SignPolicyResult{OK: false, Error: "Missing challenge, namespace, or origin"}
	}

	if !challengeRegex.MatchString(challenge) {
		return SignPolicyResult{OK: false, Error: "Invalid challenge format"}
	}

	// Origin must be in the configured allowlist (the security boundary).
	matchedOrigin := ""
	for _, candidate := range EquivalentOrigins(origin) {
		for _, allowed := range input.Origins {
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

	// namespace==origin: the RP's reported namespace, parsed as an origin, must be
	// equivalent to the link origin. This keeps every signature origin-bound
	// (non-replayable across sites) and rejects an RP that claims a foreign or
	// shared namespace.
	nsOrigin := NormalizeOrigin(namespace)
	if nsOrigin == "" || !originsEquivalent(origin, nsOrigin) {
		return SignPolicyResult{
			OK:    false,
			Error: fmt.Sprintf("ERROR\nExpected Namespace: %s\nReceived Namespace: %s", origin, namespace),
		}
	}

	return SignPolicyResult{
		OK:        true,
		Origin:    origin,
		Namespace: namespace, // sign with exactly what the RP reported
		Challenge: challenge,
	}
}
