// Command forgejo-wedge is a "Sign in with wedge" gateway for Forgejo (and
// Gitea — identical mechanism). Forgejo has no wedge auth source and no
// arbitrary auth-source plugin surface, so instead of forking it we use its
// documented reverse-proxy header authentication: the gateway authenticates
// the browser with wedge (the wedgerp middleware), then reverse-proxies every
// other request to Forgejo, injecting the verified username as the trusted
// X-WEBAUTH-USER header. Forgejo, configured with
// ENABLE_REVERSE_PROXY_AUTHENTICATION and auto-registration, signs the user in.
//
//	go run ./sdk/go/examples/forgejo \
//	  --origin http://127.0.0.1:3000 --upstream http://127.0.0.1:3001 \
//	  --user dan:$HOME/.ssh/id_ed25519.pub
//
// SECURITY: the gateway MUST be the only path to Forgejo, and Forgejo MUST
// trust only the gateway (REVERSE_PROXY_TRUSTED_PROXIES). The header is a
// bearer of identity — anyone who can set it on a request Forgejo trusts is
// that user (see GHSA-f75j-4cw6-rmx4). The gateway strips any client-supplied
// auth headers on every inbound request before deciding whether to add its own.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/daniel-alexander4/wedge/sdk/go/wedgerp"
)

// authHeaders are the reverse-proxy identity headers Forgejo reads (defaults
// from its config cheat-sheet). The gateway owns these: it strips any inbound
// copy and sets X-WEBAUTH-USER itself only for an authenticated session.
var authHeaders = []string{"X-WEBAUTH-USER", "X-WEBAUTH-EMAIL", "X-WEBAUTH-FULLNAME"}

const loginPage = `<!doctype html><meta charset="utf-8"><title>Sign in with wedge</title>
<body style="font-family: system-ui; max-width: 40rem; margin: 4rem auto">
<h1>Sign in to Forgejo with wedge</h1>
<p>Authenticate with the SSH key registered for your account.</p>
<p><input id="u" placeholder="username (optional)"></p>
<p><button id="b">Sign in with wedge</button></p>
<p id="msg"></p>
<script src="/wedge/wedge.js"></script>
<script>
Wedge.attach(document.getElementById("b"), {
  usernameInput: "#u",
  onStatus: function (s) { document.getElementById("msg").textContent = s; },
  onError: function (e) { document.getElementById("msg").textContent = e.message; },
});
</script></body>`

func main() {
	users := userFlags{}
	addr := flag.String("addr", "127.0.0.1:3000", "gateway listen address")
	origin := flag.String("origin", "", "gateway canonical origin (default http://ADDR)")
	upstream := flag.String("upstream", "http://127.0.0.1:3001", "Forgejo base URL (must NOT be otherwise reachable)")
	flag.Var(users, "user", "map a wedge key to a Forgejo username, NAME:PUBKEY_PATH (repeatable)")
	flag.Parse()
	if len(users) == 0 {
		log.Fatal("register at least one --user NAME:PUBKEY_PATH")
	}
	if *origin == "" {
		*origin = "http://" + *addr
	}
	upURL, err := url.Parse(*upstream)
	if err != nil {
		log.Fatalf("--upstream: %v", err)
	}

	rp, err := wedgerp.New(wedgerp.Config{
		Origin: *origin,
		FindKeys: func(username string) ([]string, error) {
			if key, ok := users[username]; ok {
				return []string{key}, nil
			}
			return nil, nil
		},
		FindUserByPublicKey: func(posted string) (string, []string, error) {
			for name, key := range users {
				if wedgerp.SameKey(key, posted) {
					return name, []string{key}, nil
				}
			}
			return "", nil, nil
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Fatal(err)
	}
	sess := &session{secret: secret}

	log.Printf("forgejo-wedge gateway on %s → %s (login at %s/wedge-login)", *origin, *upstream, *origin)
	log.Fatal(http.ListenAndServe(*addr, gateway(rp, sess, upURL)))
}

// gateway builds the full handler: wedge auth endpoints + login page, and a
// reverse proxy for everything else that injects the authenticated identity.
func gateway(rp *wedgerp.RP, sess *session, upstream *url.URL) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(upstream)

	wedge := wedgerp.Handler(rp, wedgerp.HandlerOptions{
		Login: func(username string, w http.ResponseWriter, r *http.Request) {
			sess.set(w, username)
		},
		RedirectTo:      "/",
		FailureRedirect: "/wedge-login",
	})

	mux := http.NewServeMux()
	mux.Handle("/.well-known/wedge.json", wedge)
	mux.Handle("/wedge/", wedge)
	mux.HandleFunc("GET /wedge-login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, loginPage)
	})
	mux.HandleFunc("GET /wedge-logout", func(w http.ResponseWriter, r *http.Request) {
		sess.clear(w)
		http.Redirect(w, r, "/wedge-login", http.StatusSeeOther)
	})
	// Everything else is Forgejo, behind the identity injection.
	mux.Handle("/", inject(proxy, sess))
	return mux
}

// inject is the security core. On EVERY inbound request it first strips any
// client-supplied auth headers (a client must never be able to assert its own
// identity to Forgejo), then, only for a valid gateway session, sets
// X-WEBAUTH-USER to the verified username. Forgejo trusts the header because
// it trusts only this gateway (REVERSE_PROXY_TRUSTED_PROXIES).
func inject(proxy http.Handler, sess *session) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range authHeaders {
			r.Header.Del(h)
		}
		if user := sess.user(r); user != "" {
			r.Header.Set("X-WEBAUTH-USER", user)
		}
		proxy.ServeHTTP(w, r)
	})
}

// -- session (HMAC-signed cookie; a real deployment brings its own) -----------

type session struct{ secret []byte }

const sessionCookie = "forgejo_wedge_session"

func (s *session) sign(username string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(username))
	return username + "." + hex.EncodeToString(mac.Sum(nil))
}

func (s *session) set(w http.ResponseWriter, username string) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: s.sign(username),
		Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func (s *session) clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1})
}

// user returns the verified username for the request, or "" if the session
// cookie is absent or its HMAC doesn't check out.
func (s *session) user(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	username, _, ok := strings.Cut(c.Value, ".")
	if !ok || !hmac.Equal([]byte(s.sign(username)), []byte(c.Value)) {
		return ""
	}
	return username
}

// -- --user NAME:PUBKEY_PATH flag ---------------------------------------------

type userFlags map[string]string

func (u userFlags) String() string { return fmt.Sprint(map[string]string(u)) }
func (u userFlags) Set(spec string) error {
	name, keyPath, ok := strings.Cut(spec, ":")
	if !ok {
		return fmt.Errorf("expected NAME:PUBKEY_PATH, got %q", spec)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	u[name] = strings.TrimSpace(string(key))
	return nil
}
