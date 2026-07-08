package wedgerp

// Adapter tests over a real HTTP server (httptest), including cookie flow.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	wire "github.com/daniel-alexander4/wedge/internal/rp"
)

type handlerFixture struct {
	*fixture
	server *httptest.Server
	logins []string
}

func newHandlerFixture(t *testing.T) *handlerFixture {
	t.Helper()
	hf := &handlerFixture{fixture: newFixture(t)}
	h := Handler(hf.rp, HandlerOptions{
		Login: func(username string, w http.ResponseWriter, r *http.Request) {
			hf.logins = append(hf.logins, username)
			http.SetCookie(w, &http.Cookie{Name: "demo_session", Value: username, HttpOnly: true})
		},
		RedirectTo:      "/home",
		FailureRedirect: "/login",
	})
	hf.server = httptest.NewServer(h)
	t.Cleanup(hf.server.Close)
	return hf
}

func (hf *handlerFixture) postJSON(t *testing.T, path string, body any, headers map[string]string) *http.Response {
	t.Helper()
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", hf.server.URL+path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func (hf *handlerFixture) get(t *testing.T, path string, cookies []*http.Cookie) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", hf.server.URL+path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func decode[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// signInCore drives browser start + authenticator verify over HTTP; returns
// the request id and the binding cookie.
func (hf *handlerFixture) signInCore(t *testing.T) (string, *http.Cookie) {
	t.Helper()
	start := hf.postJSON(t, StartPath, map[string]string{"username": "alice"}, nil)
	if start.StatusCode != 200 {
		t.Fatalf("start: %d", start.StatusCode)
	}
	var binding *http.Cookie
	for _, c := range start.Cookies() {
		if c.Name == BindingCookie {
			binding = c
		}
	}
	if binding == nil {
		t.Fatal("no binding cookie set")
	}
	started := decode[StartBody](t, start)
	ch := decode[wire.Challenge](t, hf.get(t, ChallengePath+"?request_id="+started.RequestID, nil))
	verify := hf.postJSON(t, VerifyPath, wire.VerifyRequest{
		RequestID: started.RequestID,
		Challenge: ch.Challenge,
		Namespace: testOrigin,
		Signature: hf.alice.sign(t, ch.Challenge, testOrigin),
	}, nil)
	if verify.StatusCode != 200 {
		t.Fatalf("verify: %d", verify.StatusCode)
	}
	verify.Body.Close()
	return started.RequestID, binding
}

func TestHandlerServesDiscovery(t *testing.T) {
	hf := newHandlerFixture(t)
	doc := decode[wire.Discovery](t, hf.get(t, DiscoveryPath, nil))
	if doc.Version != 1 || doc.Namespace != testOrigin {
		t.Fatalf("discovery = %+v", doc)
	}
}

func TestHandlerCoreFlowMintsSessionForBoundBrowser(t *testing.T) {
	hf := newHandlerFixture(t)
	rid, binding := hf.signInCore(t)
	resp := hf.get(t, StatusPath+"?request_id="+rid, []*http.Cookie{binding})
	body := decode[StatusBody](t, resp)
	if body.Status != "authenticated" || body.Redirect != "/home" {
		t.Fatalf("status body = %+v", body)
	}
	if len(hf.logins) != 1 || hf.logins[0] != "alice" {
		t.Fatalf("logins = %v", hf.logins)
	}
}

func TestHandlerUnboundBrowserStaysPending(t *testing.T) {
	hf := newHandlerFixture(t)
	rid, _ := hf.signInCore(t)
	body := decode[StatusBody](t, hf.get(t, StatusPath+"?request_id="+rid, nil))
	if body.Status != "pending" || len(hf.logins) != 0 {
		t.Fatalf("unbound poll: %+v logins=%v", body, hf.logins)
	}
}

func TestHandlerRejectsCrossOriginStart(t *testing.T) {
	hf := newHandlerFixture(t)
	resp := hf.postJSON(t, StartPath, map[string]string{}, map[string]string{"Origin": "http://evil.example"})
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestHandlerAppInitiatedClaimFlowSingleUse(t *testing.T) {
	hf := newHandlerFixture(t)
	started := decode[AppStartBody](t, hf.postJSON(t, AppStartPath, map[string]string{}, nil))
	verify := hf.postJSON(t, VerifyPath, wire.VerifyRequest{
		RequestID: started.RequestID,
		Challenge: started.Challenge,
		Namespace: started.Namespace,
		Signature: hf.alice.sign(t, started.Challenge, started.Namespace),
		PublicKey: hf.alice.publicKey,
	}, nil)
	if verify.StatusCode != 200 {
		t.Fatalf("verify: %d", verify.StatusCode)
	}
	verify.Body.Close()

	claimPath := strings.TrimPrefix(started.ClaimURL, testOrigin)
	resp := hf.get(t, claimPath, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/home" ||
		resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("claim: %d %s %s", resp.StatusCode, resp.Header.Get("Location"), resp.Header.Get("Referrer-Policy"))
	}
	if len(hf.logins) != 1 || hf.logins[0] != "alice" {
		t.Fatalf("logins = %v", hf.logins)
	}
	replay := hf.get(t, claimPath, nil)
	defer replay.Body.Close()
	if replay.Header.Get("Location") != "/login" || len(hf.logins) != 1 {
		t.Fatal("claim replay minted a session")
	}
}

func TestHandlerServesWedgeJS(t *testing.T) {
	hf := newHandlerFixture(t)
	resp := hf.get(t, ScriptPath, nil)
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(buf.String(), "window.Wedge") {
		t.Fatalf("wedge.js: %d", resp.StatusCode)
	}
}
