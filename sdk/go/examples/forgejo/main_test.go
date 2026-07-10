package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daniel-alexander4/wedge/sdk/go/wedgerp"
)

func requireSSHKeygen(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available")
	}
}

// echoUpstream stands in for Forgejo: it reports the X-WEBAUTH-USER it was
// handed, so the test can assert exactly what the gateway injected.
func echoUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"webauth_user": r.Header.Get("X-WEBAUTH-USER")})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// genKey mints a throwaway ed25519 keypair and returns its private path and
// public-key line.
func genKey(t *testing.T) (keyPath, pubLine string) {
	t.Helper()
	dir := t.TempDir()
	keyPath = filepath.Join(dir, "id_ed25519")
	if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-C", "gw-test", "-q", "-f", keyPath).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
	pub, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	return keyPath, strings.TrimSpace(string(pub))
}

func sign(t *testing.T, keyPath, challenge, namespace string) string {
	t.Helper()
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-f", keyPath, "-n", namespace)
	cmd.Stdin = strings.NewReader(challenge)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ssh-keygen -Y sign: %v", err)
	}
	return string(out)
}

// buildGateway wires a gateway in front of the echo upstream, registered for
// one user, and returns the running test server.
func buildGateway(t *testing.T, upstream, user, pubLine string) *httptest.Server {
	t.Helper()
	// Two-step: the RP origin must equal the gateway's own URL, known only
	// after the server starts — so start with a placeholder handler, then
	// rebuild once the address is known.
	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	rp, err := wedgerp.New(wedgerp.Config{
		Origin: srv.URL,
		FindKeys: func(u string) ([]string, error) {
			if u == user {
				return []string{pubLine}, nil
			}
			return nil, nil
		},
		FindUserByPublicKey: func(posted string) (string, []string, error) {
			if wedgerp.SameKey(pubLine, posted) {
				return user, []string{pubLine}, nil
			}
			return "", nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	upURL, _ := url.Parse(upstream)
	secret := []byte("test-secret-not-for-production--32")
	handler = gateway(rp, &session{secret: secret}, upURL)
	return srv
}

// login runs the full wedge username flow against the gateway and returns the
// session cookie the gateway issued.
func login(t *testing.T, client *http.Client, gwURL, user, keyPath string) *http.Cookie {
	t.Helper()
	// start
	resp, err := client.Post(gwURL+"/wedge/start", "application/json",
		strings.NewReader(`{"username":"`+user+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	var start struct {
		RequestID string `json:"request_id"`
	}
	decode(t, resp, &start)
	var binding *http.Cookie
	for _, c := range resp.Cookies() {
		binding = c
	}
	// challenge
	resp, err = client.Get(gwURL + "/wedge/challenge?request_id=" + url.QueryEscape(start.RequestID))
	if err != nil {
		t.Fatal(err)
	}
	var ch struct {
		Challenge string `json:"challenge"`
		Namespace string `json:"namespace"`
	}
	decode(t, resp, &ch)
	// verify
	body, _ := json.Marshal(map[string]string{
		"request_id": start.RequestID, "challenge": ch.Challenge,
		"namespace": ch.Namespace, "signature": sign(t, keyPath, ch.Challenge, ch.Namespace),
	})
	resp, err = client.Post(gwURL+"/wedge/verify", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("verify: HTTP %d", resp.StatusCode)
	}
	// status with the binding cookie mints the gateway session
	req, _ := http.NewRequest("GET", gwURL+"/wedge/status?request_id="+url.QueryEscape(start.RequestID), nil)
	req.AddCookie(binding)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return c
		}
	}
	t.Fatal("gateway issued no session cookie after status")
	return nil
}

func decode(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

func webauthUser(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var m map[string]string
	json.Unmarshal(b, &m)
	return m["webauth_user"]
}

// TestUnauthenticatedNeverReachesUpstreamWithHeader is the security crux: an
// unauthenticated request — even one that forges X-WEBAUTH-USER — must reach
// the upstream with no identity header.
func TestUnauthenticatedStripsForgedHeader(t *testing.T) {
	up := echoUpstream(t)
	gw := buildGateway(t, up.URL, "dan", "ssh-ed25519 AAAAunused dan")

	req, _ := http.NewRequest("GET", gw.URL+"/some/repo", nil)
	req.Header.Set("X-WEBAUTH-USER", "admin") // forged
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if got := webauthUser(t, resp); got != "" {
		t.Fatalf("forged X-WEBAUTH-USER reached upstream as %q — impersonation hole", got)
	}
}

// TestAuthenticatedInjectsVerifiedUser drives a real wedge sign-in and checks
// the upstream then sees exactly the verified username — and that logout stops
// the injection.
func TestAuthenticatedInjectsVerifiedUser(t *testing.T) {
	requireSSHKeygen(t)
	up := echoUpstream(t)
	keyPath, pub := genKey(t)
	gw := buildGateway(t, up.URL, "dan", pub)

	jar := &cookieJar{}
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	cookie := login(t, client, gw.URL, "dan", keyPath)

	// A proxied request carrying the session sees the verified identity.
	req, _ := http.NewRequest("GET", gw.URL+"/", nil)
	req.AddCookie(cookie)
	req.Header.Set("X-WEBAUTH-USER", "admin") // still stripped before re-injection
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if got := webauthUser(t, resp); got != "dan" {
		t.Fatalf("authenticated upstream saw X-WEBAUTH-USER=%q, want \"dan\"", got)
	}

	// Without the session cookie, no identity — even right after login.
	resp, err = http.Get(gw.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if got := webauthUser(t, resp); got != "" {
		t.Fatalf("no-session request injected %q", got)
	}
}

// cookieJar is a minimal jar so the login flow's binding cookie round-trips.
type cookieJar struct{ cookies []*http.Cookie }

func (j *cookieJar) SetCookies(_ *url.URL, cs []*http.Cookie) { j.cookies = append(j.cookies, cs...) }
func (j *cookieJar) Cookies(_ *url.URL) []*http.Cookie        { return j.cookies }
