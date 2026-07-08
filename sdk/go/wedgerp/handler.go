// net/http adapter — in Go this IS the framework adapter: chi, echo, gin, and
// the stdlib all mount an http.Handler.

package wedgerp

import (
	_ "embed"
	"encoding/json"
	"net"
	"net/http"
	"time"

	wire "github.com/daniel-alexander4/wedge/internal/rp"
)

//go:embed wedge.js
var wedgeJS []byte

// HandlerOptions wires the host application into the wedge endpoints.
type HandlerOptions struct {
	// Login is REQUIRED: called with the verified username, inside the
	// request, at the one moment a session may be minted. Establish your
	// app's session here (set your session cookie on w) and nothing else.
	Login func(username string, w http.ResponseWriter, r *http.Request)

	// RedirectTo is where the browser lands after sign-in (default "/").
	// RedirectToFunc overrides it per user when set.
	RedirectTo     string
	RedirectToFunc func(username string) string

	// FailureRedirect is where /wedge/claim sends the browser when a claim
	// is invalid — it never mints a session on failure (default "/").
	FailureRedirect string
}

// Handler serves every wedge endpoint for rp. Mount it at the root of the
// same origin rp is configured with:
//
//	mux.Handle("/.well-known/wedge.json", h)
//	mux.Handle("/wedge/", h)
//
// or simply pass it requests for those paths from any router.
func Handler(rp *RP, opts HandlerOptions) http.Handler {
	if opts.Login == nil {
		panic("wedgerp: HandlerOptions.Login is required")
	}
	if opts.RedirectTo == "" {
		opts.RedirectTo = "/"
	}
	if opts.FailureRedirect == "" {
		opts.FailureRedirect = "/"
	}
	landing := func(username string) string {
		if opts.RedirectToFunc != nil {
			return opts.RedirectToFunc(username)
		}
		return opts.RedirectTo
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET "+DiscoveryPath, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, rp.Discovery())
	})

	mux.HandleFunc("POST "+StartPath, func(w http.ResponseWriter, r *http.Request) {
		// Browser-facing POST: reject cross-site initiations outright.
		if origin := r.Header.Get("Origin"); origin != "" && !rp.IsSameOrigin(origin) {
			writeJSON(w, 403, errBody("cross-origin request"))
			return
		}
		var body struct {
			Username string `json:"username"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body)
		status, resp, nonce := rp.Start(body.Username)
		if nonce != "" {
			http.SetCookie(w, &http.Cookie{
				Name:     BindingCookie,
				Value:    nonce,
				Path:     "/",
				MaxAge:   int(rp.ChallengeTTL() / time.Second),
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				Secure:   rp.UsesHTTPS(),
			})
		}
		writeJSON(w, status, resp)
	})

	mux.HandleFunc("GET "+ChallengePath, func(w http.ResponseWriter, r *http.Request) {
		status, resp := rp.Challenge(r.URL.Query().Get("request_id"))
		writeJSON(w, status, resp)
	})

	mux.HandleFunc("POST "+VerifyPath, func(w http.ResponseWriter, r *http.Request) {
		// Authenticator-facing: cookieless JSON (spec §5.2).
		var req wire.VerifyRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&req); err != nil {
			writeJSON(w, 400, errBody("malformed request body"))
			return
		}
		source, _, _ := net.SplitHostPort(r.RemoteAddr)
		status, resp := rp.Verify(req, source)
		writeJSON(w, status, resp)
	})

	mux.HandleFunc("GET "+StatusPath, func(w http.ResponseWriter, r *http.Request) {
		nonce := ""
		if c, err := r.Cookie(BindingCookie); err == nil {
			nonce = c.Value
		}
		body, username := rp.Status(r.URL.Query().Get("request_id"), nonce)
		if username != "" {
			opts.Login(username, w, r)
			body.Redirect = landing(username)
		}
		writeJSON(w, 200, body)
	})

	mux.HandleFunc("POST "+AppStartPath, func(w http.ResponseWriter, r *http.Request) {
		status, resp := rp.AppStart()
		writeJSON(w, status, resp)
	})

	mux.HandleFunc("GET "+ClaimPath, func(w http.ResponseWriter, r *http.Request) {
		// The claim URL is a bearer secret: never let it leak via Referer,
		// and never render it into page content (spec §8.3) — redirect-only.
		w.Header().Set("Referrer-Policy", "no-referrer")
		q := r.URL.Query()
		username, ok := rp.Claim(q.Get("request_id"), q.Get("claim"))
		if !ok {
			http.Redirect(w, r, opts.FailureRedirect, http.StatusSeeOther)
			return
		}
		opts.Login(username, w, r)
		http.Redirect(w, r, landing(username), http.StatusSeeOther)
	})

	mux.HandleFunc("GET "+ScriptPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write(wedgeJS)
	})

	return mux
}

// writeJSON mirrors internal/server's helper (unexported there; trivial).
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
