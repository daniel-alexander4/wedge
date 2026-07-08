// Minimal wedge relying party in Go — the wedgerp integration pattern and the
// e2e harness for the SDK test drive.
//
//	go run ./sdk/go/examples/demo --port 9413 --user dan:$HOME/.ssh/id_ed25519.pub
//
// Then point the wedge app at http://127.0.0.1:9413 and open /login.
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
	"os"
	"strings"

	"github.com/daniel-alexander4/wedge/sdk/go/wedgerp"
)

const page = `<!doctype html><meta charset="utf-8"><title>wedge-rp demo</title>
<body style="font-family: system-ui; max-width: 40rem; margin: 4rem auto">%s</body>`

const login = `<h1>wedge-rp demo (Go)</h1>
<p>Sign in with the SSH key registered for your account.</p>
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
</script>`

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

func main() {
	users := userFlags{}
	host := flag.String("host", "127.0.0.1", "bind address")
	port := flag.Int("port", 9413, "port")
	origin := flag.String("origin", "", "canonical origin (default http://HOST:PORT)")
	flag.Var(users, "user", "register an account, NAME:PUBKEY_PATH (repeatable)")
	flag.Parse()
	if len(users) == 0 {
		log.Fatal("register at least one --user NAME:PUBKEY_PATH")
	}
	if *origin == "" {
		*origin = fmt.Sprintf("http://%s:%d", *host, *port)
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

	// Demo session: an HMAC-signed cookie (a real app brings its own).
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Fatal(err)
	}
	sign := func(username string) string {
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(username))
		return username + "." + hex.EncodeToString(mac.Sum(nil))
	}
	whoAmI := func(r *http.Request) string {
		c, err := r.Cookie("demo_session")
		if err != nil {
			return ""
		}
		username, _, ok := strings.Cut(c.Value, ".")
		if !ok || !hmac.Equal([]byte(sign(username)), []byte(c.Value)) {
			return ""
		}
		return username
	}

	mux := http.NewServeMux()
	mux.Handle("/.well-known/wedge.json", wedgeHandler(rp, sign))
	mux.Handle("/wedge/", wedgeHandler(rp, sign))
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, page, login)
	})
	mux.HandleFunc("GET /logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "demo_session", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if who := whoAmI(r); who != "" {
			fmt.Fprintf(w, page, "<h1>Signed in as "+who+`</h1><p><a href="/logout">Log out</a></p>`)
			return
		}
		fmt.Fprintf(w, page, `<h1>Signed out</h1><p><a href="/login">Sign in with wedge</a></p>`)
	})

	addr := fmt.Sprintf("%s:%d", *host, *port)
	log.Printf("wedge-rp demo on %s (login at %s/login)", *origin, *origin)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func wedgeHandler(rp *wedgerp.RP, sign func(string) string) http.Handler {
	return wedgerp.Handler(rp, wedgerp.HandlerOptions{
		Login: func(username string, w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{
				Name: "demo_session", Value: sign(username),
				Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
			})
		},
		RedirectTo:      "/",
		FailureRedirect: "/login",
	})
}
