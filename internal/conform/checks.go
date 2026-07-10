package conform

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/daniel-alexander4/wedge/internal/policy"
)

// Security boundary: byte-identical to internal/policy's challengeRegex and
// internal/protocol's requestIDRe (spec §6.2) — keep all copies consistent.
var (
	challengeRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}$`)
	requestIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

type Status string

const (
	Pass Status = "PASS"
	Fail Status = "FAIL"
	Warn Status = "WARN"
	Skip Status = "SKIP"
)

type Result struct {
	Status Status
	Detail string
}

func pass() Result                            { return Result{Status: Pass} }
func fail(f string, a ...any) Result          { return Result{Status: Fail, Detail: fmt.Sprintf(f, a...)} }
func warn(f string, a ...any) Result          { return Result{Status: Warn, Detail: fmt.Sprintf(f, a...)} }
func skip(f string, a ...any) Result          { return Result{Status: Skip, Detail: fmt.Sprintf(f, a...)} }
func failIf(bad bool, f string, a ...any) Result {
	if bad {
		return fail(f, a...)
	}
	return pass()
}

// Check is one wire-observable requirement.
type Check struct {
	ID      string
	Section string
	Level   string // MUST or SHOULD
	Name    string
	Run     func(*Session) Result
}

// Untestable lists the RP requirements a black-box client cannot assert —
// printed with every report so they're reviewed, never silently dropped.
var Untestable = []string{
	"§6.2 challenge/request_id/claim-token entropy (≥128-bit CSPRNG, unguessable) — RNG quality is internal; only gross defects are externally visible",
	"§8.3 claim-token constant-time comparison — a timing side-channel property, functionally invisible to a client",
	"§8.3 claim URL never embedded in served page content — requires exhaustive inspection of all RP content",
	"§4 registration_url points at a usable key-registration page — a semantic/UX property",
	"§5.4 the binding *mechanism* (HttpOnly SameSite cookie is the reference) — only its gating effect is asserted (S2/S3)",
}

// Checks is the conformance matrix, in run order. probes enables the opt-in
// rate-limit/concurrency probes (they deliberately trip the target).
func Checks(probes bool) []Check {
	list := []Check{
		{"D1", "§4", "MUST", "discovery version is 1", func(s *Session) Result {
			d, err := s.discovery()
			if err != nil {
				return fail("%v", err)
			}
			v, _ := d["version"].(float64)
			return failIf(v != 1, "version = %v", d["version"])
		}},
		{"D2", "§4", "MUST", "discovery carries namespace, challenge_url, verify_url", func(s *Session) Result {
			d, err := s.discovery()
			if err != nil {
				return fail("%v", err)
			}
			for _, k := range []string{"namespace", "challenge_url", "verify_url"} {
				if str(d, k) == "" {
					return fail("missing %s", k)
				}
			}
			return pass()
		}},
		{"D3", "§4/§6.1", "MUST", "discovery namespace equals the canonical origin", func(s *Session) Result {
			d, err := s.discovery()
			if err != nil {
				return fail("%v", err)
			}
			ns := policy.NormalizeOrigin(str(d, "namespace"))
			for _, equiv := range policy.EquivalentOrigins(s.Target) {
				if ns == equiv {
					return pass()
				}
			}
			return fail("namespace %q != origin %q", str(d, "namespace"), s.Target)
		}},
		{"D4", "§4", "MUST", "challenge_url is same-origin", func(s *Session) Result {
			d, err := s.discovery()
			if err != nil {
				return fail("%v", err)
			}
			return failIf(!s.sameOrigin(str(d, "challenge_url")), "challenge_url %q", str(d, "challenge_url"))
		}},
		{"D5", "§4", "MUST", "verify_url is same-origin", func(s *Session) Result {
			d, err := s.discovery()
			if err != nil {
				return fail("%v", err)
			}
			return failIf(!s.sameOrigin(str(d, "verify_url")), "verify_url %q", str(d, "verify_url"))
		}},
		{"D7", "§4", "MUST", "registration_url (when present) is same-origin", func(s *Session) Result {
			d, err := s.discovery()
			if err != nil {
				return fail("%v", err)
			}
			ru := str(d, "registration_url")
			if ru == "" {
				return skip("registration_url not advertised (optional)")
			}
			return failIf(!s.sameOrigin(ru), "registration_url %q", ru)
		}},

		{"F5", "§6.2", "MUST", "request_id matches its format", func(s *Session) Result {
			p, err := s.newRequest()
			if err != nil {
				return fail("%v", err)
			}
			return failIf(!requestIDRe.MatchString(p.RequestID), "request_id %q", p.RequestID)
		}},
		{"C1", "§5.1/§6.2/§6.1", "MUST", "challenge fetch returns a well-formed challenge and the canonical namespace", func(s *Session) Result {
			p, err := s.newRequest()
			if err != nil {
				return fail("%v", err)
			}
			if !challengeRe.MatchString(p.Challenge) {
				return fail("challenge %q fails §6.2", p.Challenge)
			}
			d, _ := s.discovery()
			if p.Namespace != str(d, "namespace") {
				return fail("challenge namespace %q != discovery namespace %q", p.Namespace, str(d, "namespace"))
			}
			return pass()
		}},
		{"C2", "§5.1", "MUST", "unknown request_id yields 404/410 on challenge fetch", func(s *Session) Result {
			if _, err := s.discovery(); err != nil {
				return fail("%v", err)
			}
			resp, err := s.get(s.challURL + "?request_id=wedge-conform-no-such-request")
			if err != nil {
				return fail("%v", err)
			}
			return failIf(resp.Status != 404 && resp.Status != 410, "HTTP %d", resp.Status)
		}},
		{"V1", "§5.2(1)", "MUST", "verify of an unknown request_id is rejected 404", func(s *Session) Result {
			if _, err := s.discovery(); err != nil {
				return fail("%v", err)
			}
			sig, err := s.Key.Sign("wedge-conform-standalone", s.Target)
			if err != nil {
				return fail("%v", err)
			}
			resp, err := s.verify(pending{RequestID: "wedge-conform-no-such-request"}, sig, s.Key.PublicKey, s.Target, "wedge-conform-standalone", nil)
			if err != nil {
				return fail("%v", err)
			}
			return failIf(resp.Status != 404, "HTTP %d", resp.Status)
		}},
		{"V7", "§5.2(5)/§6.2", "MUST", "happy-path verify succeeds once and the request is single-use", func(s *Session) Result {
			p, err := s.newRequest()
			if err != nil {
				return fail("%v", err)
			}
			resp, err := s.signedVerify(p)
			if err != nil {
				return fail("%v", err)
			}
			if resp.Status != 200 || resp.Body["ok"] != true {
				return fail("first verify: HTTP %d %s", resp.Status, resp.Raw)
			}
			replay, err := s.signedVerify(p)
			if err != nil {
				return fail("%v", err)
			}
			if replay.Status == 200 {
				return fail("replayed verify succeeded — request/challenge is not single-use")
			}
			// C2b: the consumed challenge must be gone.
			gone, err := s.get(s.challURL + "?request_id=" + url.QueryEscape(p.RequestID))
			if err != nil {
				return fail("%v", err)
			}
			return failIf(gone.Status != 404 && gone.Status != 410, "challenge still served after auth: HTTP %d", gone.Status)
		}},
		{"V2", "§5.2(2)", "MUST", "verification runs against the stored challenge, never the echoed field", func(s *Session) Result {
			p, err := s.newRequest()
			if err != nil {
				return fail("%v", err)
			}
			sig, err := s.Key.Sign(p.Challenge, p.Namespace)
			if err != nil {
				return fail("%v", err)
			}
			resp, err := s.verify(p, sig, s.Key.PublicKey, p.Namespace, "attacker-chosen-echo-value", nil)
			if err != nil {
				return fail("%v", err)
			}
			if resp.Status != 200 {
				return fail("good signature with a junk echoed challenge was rejected (HTTP %d) — RP appears to trust the echoed field", resp.Status)
			}
			p2, err := s.newRequest()
			if err != nil {
				return fail("%v", err)
			}
			evilSig, err := s.Key.Sign("attacker-chosen-echo-value", p2.Namespace)
			if err != nil {
				return fail("%v", err)
			}
			resp2, err := s.verify(p2, evilSig, s.Key.PublicKey, p2.Namespace, "attacker-chosen-echo-value", nil)
			if err != nil {
				return fail("%v", err)
			}
			return failIf(resp2.Status == 200, "signature over the echoed (attacker) value was accepted")
		}},
		{"V3", "§5.2(3)", "MUST", "namespace mismatch is rejected 400", func(s *Session) Result {
			p, err := s.newRequest()
			if err != nil {
				return fail("%v", err)
			}
			evil := "http://evil.example"
			sig, err := s.Key.Sign(p.Challenge, evil)
			if err != nil {
				return fail("%v", err)
			}
			resp, err := s.verify(p, sig, s.Key.PublicKey, evil, p.Challenge, nil)
			if err != nil {
				return fail("%v", err)
			}
			return failIf(resp.Status != 400, "HTTP %d", resp.Status)
		}},
		{"V4", "§5.2(3)/§6.1", "MUST", "the localhost↔127.0.0.1 alias namespace is accepted at verify", func(s *Session) Result {
			alias := aliasOrigin(s.Target)
			if alias == "" {
				return skip("target is not loopback; the §6.1 alias only covers localhost↔127.0.0.1")
			}
			p, err := s.newRequest()
			if err != nil {
				return fail("%v", err)
			}
			sig, err := s.Key.Sign(p.Challenge, alias)
			if err != nil {
				return fail("%v", err)
			}
			resp, err := s.verify(p, sig, s.Key.PublicKey, alias, p.Challenge, nil)
			if err != nil {
				return fail("%v", err)
			}
			return failIf(resp.Status != 200, "alias namespace %q rejected: HTTP %d %s", alias, resp.Status, resp.Raw)
		}},
		{"V5", "§5.2(4)", "MUST", "a valid signature by an unregistered key is rejected 401", func(s *Session) Result {
			resp, err := s.unregisteredVerify()
			if err != nil {
				return fail("%v", err)
			}
			return failIf(resp.Status != 401, "HTTP %d %s", resp.Status, resp.Raw)
		}},
		{"V9", "§5.2/§4", "SHOULD", "the no-account outcome carries code \"unknown_key\"", func(s *Session) Result {
			resp, err := s.unregisteredVerify()
			if err != nil {
				return fail("%v", err)
			}
			if str(resp.Body, "code") != "unknown_key" {
				return warn("code %q (SHOULD be \"unknown_key\", especially with registration_url advertised)", str(resp.Body, "code"))
			}
			return pass()
		}},
		{"V10", "§5.2", "MUST", "a failed signature against a registered key carries no unknown_key code", func(s *Session) Result {
			p, err := s.newRequest()
			if err != nil {
				return fail("%v", err)
			}
			sig, err := s.Key.Sign("not-the-real-challenge-bytes", p.Namespace)
			if err != nil {
				return fail("%v", err)
			}
			resp, err := s.verify(p, sig, s.Key.PublicKey, p.Namespace, p.Challenge, nil)
			if err != nil {
				return fail("%v", err)
			}
			if resp.Status != 401 {
				return fail("bad signature: HTTP %d", resp.Status)
			}
			return failIf(str(resp.Body, "code") == "unknown_key", "unknown_key sent for a registered key's failed signature")
		}},
		{"V8", "§5.2", "MUST", "a failed verify consumes nothing (retry with a good signature succeeds)", func(s *Session) Result {
			p, err := s.newRequest()
			if err != nil {
				return fail("%v", err)
			}
			badSig, err := s.Key.Sign("wrong-bytes-entirely", p.Namespace)
			if err != nil {
				return fail("%v", err)
			}
			if resp, err := s.verify(p, badSig, s.Key.PublicKey, p.Namespace, p.Challenge, nil); err != nil || resp.Status == 200 {
				return fail("bad signature verify: err=%v HTTP %d", err, resp.Status)
			}
			resp, err := s.signedVerify(p)
			if err != nil {
				return fail("%v", err)
			}
			return failIf(resp.Status != 200, "good verify after a failed one: HTTP %d %s — the failure consumed the request", resp.Status, resp.Raw)
		}},
		{"G3", "§9", "MUST", "unknown JSON fields are ignored", func(s *Session) Result {
			p, err := s.newRequest()
			if err != nil {
				return fail("%v", err)
			}
			sig, err := s.Key.Sign(p.Challenge, p.Namespace)
			if err != nil {
				return fail("%v", err)
			}
			resp, err := s.verify(p, sig, s.Key.PublicKey, p.Namespace, p.Challenge,
				map[string]any{"x_wedge_conform_future_field": "ignore me", "nested": map[string]any{"a": 1}})
			if err != nil {
				return fail("%v", err)
			}
			return failIf(resp.Status != 200, "verify with unknown fields: HTTP %d %s", resp.Status, resp.Raw)
		}},

		{"S2", "§5.4", "MUST", "the session is minted only for the binding bearer", (*Session).checkBinding},
		{"S3", "§5.4", "MUST", "the authenticated request is single-use at completion", (*Session).checkBindingSingleUse},

		{"A1", "§8.1", "MUST", "app-start returns request_id, challenge, namespace, and a same-origin claim_url", func(s *Session) Result {
			ap, res := s.appStart()
			if res != nil {
				return *res
			}
			if !requestIDRe.MatchString(ap.RequestID) || !challengeRe.MatchString(ap.Challenge) {
				return fail("malformed request_id/challenge")
			}
			if !s.sameOrigin(ap.ClaimURL) || !strings.Contains(ap.ClaimURL, ap.RequestID) {
				return fail("claim_url %q", ap.ClaimURL)
			}
			return pass()
		}},
		{"A4", "§8.2", "MUST", "app-flow verify without public_key is rejected 400", func(s *Session) Result {
			ap, res := s.appStart()
			if res != nil {
				return *res
			}
			sig, err := s.Key.Sign(ap.Challenge, ap.Namespace)
			if err != nil {
				return fail("%v", err)
			}
			resp, err := s.verify(pending{RequestID: ap.RequestID}, sig, "", ap.Namespace, ap.Challenge, nil)
			if err != nil {
				return fail("%v", err)
			}
			return failIf(resp.Status != 400, "HTTP %d", resp.Status)
		}},
		{"A5a", "§8.3", "MUST", "claim before authentication mints no session", func(s *Session) Result {
			ap, res := s.appStart()
			if res != nil {
				return *res
			}
			resp, err := s.get(ap.ClaimURL)
			if err != nil {
				return fail("%v", err)
			}
			return failIf(mintedSession(resp), "claim before verify set a session cookie")
		}},
		{"A5b", "§8.3", "MUST", "claim with a wrong token mints no session", func(s *Session) Result {
			ap, res := s.appStart()
			if res != nil {
				return *res
			}
			if resp, err := s.appVerify(ap); err != nil || resp.Status != 200 {
				return fail("app verify: err=%v HTTP %d", err, resp.Status)
			}
			wrong := replaceQuery(ap.ClaimURL, "claim", "wedge-conform-wrong-token")
			resp, err := s.get(wrong)
			if err != nil {
				return fail("%v", err)
			}
			return failIf(mintedSession(resp), "claim with a wrong token set a session cookie")
		}},
		{"A7", "§8.3", "MUST", "a correct claim mints once; the replay mints nothing", func(s *Session) Result {
			ap, res := s.appStart()
			if res != nil {
				return *res
			}
			if resp, err := s.appVerify(ap); err != nil || resp.Status != 200 {
				return fail("app verify: err=%v HTTP %d", err, resp.Status)
			}
			first, err := s.get(ap.ClaimURL)
			if err != nil {
				return fail("%v", err)
			}
			if !mintedSession(first) {
				return fail("correct claim minted no session (HTTP %d, no cookie — heuristic: a session Set-Cookie marks success)", first.Status)
			}
			replay, err := s.get(ap.ClaimURL)
			if err != nil {
				return fail("%v", err)
			}
			return failIf(mintedSession(replay), "replayed claim minted a session — claim is not single-use")
		}},
		{"A8", "§8.3", "SHOULD", "the claim response redirects away", func(s *Session) Result {
			resp, res := s.claimResponse()
			if res != nil {
				return *res
			}
			if resp.Status < 300 || resp.Status > 399 {
				return warn("claim response is HTTP %d, not a redirect", resp.Status)
			}
			return pass()
		}},
		{"A11", "§8.3", "SHOULD", "the claim response sends Referrer-Policy: no-referrer", func(s *Session) Result {
			resp, res := s.claimResponse()
			if res != nil {
				return *res
			}
			if !strings.EqualFold(resp.Header.Get("Referrer-Policy"), "no-referrer") {
				return warn("Referrer-Policy %q", resp.Header.Get("Referrer-Policy"))
			}
			return pass()
		}},
	}
	if probes {
		list = append(list,
			Check{"SEC1", "§10", "SHOULD", "verify is rate-limited per source", (*Session).probeRateLimit},
			Check{"SEC2", "§10", "SHOULD", "concurrent verifications are bounded", (*Session).probeConcurrency},
		)
	}
	return list
}

// aliasOrigin returns the §6.1 loopback alias spelling of origin, or "".
func aliasOrigin(origin string) string {
	if strings.Contains(origin, "://127.0.0.1") {
		return strings.Replace(origin, "://127.0.0.1", "://localhost", 1)
	}
	if strings.Contains(origin, "://localhost") {
		return strings.Replace(origin, "://localhost", "://127.0.0.1", 1)
	}
	return ""
}

// mintedSession is the session-minted heuristic: the RP's Login set a cookie
// on the response. Both reference claim outcomes are redirects, so the
// Set-Cookie is the observable difference.
func mintedSession(resp wireResp) bool {
	return len(resp.Cookies) > 0
}

func replaceQuery(rawURL, key, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// unregisteredVerify signs correctly with a fresh, never-registered key.
// Memoized: V5 and V9 share one wire exchange.
func (s *Session) unregisteredVerify() (wireResp, error) {
	if s.unregResp != nil {
		return *s.unregResp, nil
	}
	p, err := s.newRequest()
	if err != nil {
		return wireResp{}, err
	}
	stranger, err := GenerateKey(s.tmpDir())
	if err != nil {
		return wireResp{}, err
	}
	sig, err := stranger.Sign(p.Challenge, p.Namespace)
	if err != nil {
		return wireResp{}, err
	}
	resp, err := s.verify(p, sig, stranger.PublicKey, p.Namespace, p.Challenge, nil)
	if err == nil {
		s.unregResp = &resp
	}
	return resp, err
}
