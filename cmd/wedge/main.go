// Command wedge runs the wedge desktop app: it starts a loopback-only web
// server for its own settings/onboarding UI and opens that UI in a chromeless
// app-mode window.
//
// It is also the wedge:// protocol handler. When the OS launches `wedge
// wedge://sign?…`, a single-instance guard forwards the link to an
// already-running wedge (which surfaces the consent prompt in its own window);
// if none is running, this process becomes primary and handles it.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/daniel-alexander4/wedge"
	"github.com/daniel-alexander4/wedge/internal/browser"
	"github.com/daniel-alexander4/wedge/internal/config"
	"github.com/daniel-alexander4/wedge/internal/server"
	"github.com/daniel-alexander4/wedge/internal/singleton"
	"github.com/daniel-alexander4/wedge/internal/tray"
)

// version is set at build time via -ldflags "-X main.version=…" (see build.sh).
var version = "dev"

func main() {
	log.SetFlags(0)
	log.SetPrefix("wedge: ")

	if hasFlag("--version") || hasFlag("-version") {
		log.Printf("wedge %s", version)
		return
	}

	signURL := firstWedgeArg()

	if hasFlag("--replace") {
		if n := singleton.ReplaceOthers(); n > 0 {
			log.Printf("replaced %d running instance(s)", n)
		}
	}

	mgr, err := config.NewManager()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	server.Version = version // single source of truth: VERSION → ldflags → here → /api/status
	srv := server.New(mgr, wedge.WebFS())
	if err := srv.Start(); err != nil {
		// The UI port is taken — assume a wedge is already running and attach to
		// it instead of starting a second server.
		port := mgr.Get().ServerPort
		if signURL != "" {
			if forwardHandoff(port, signURL) {
				return
			}
			log.Fatalf("could not reach running wedge to hand off the link: %v", err)
		}
		// No link — just focus the running instance's window.
		if os.Getenv("WEDGE_NO_BROWSER") == "" {
			browser.Open(fmt.Sprintf("http://127.0.0.1:%d/", port))
		}
		return
	}

	uiURL := "http://" + srv.Addr() + "/"
	log.Printf("wedge %s — UI at %s", version, uiURL)

	if os.Getenv("WEDGE_NO_BROWSER") == "" {
		if _, err := browser.Open(uiURL); err != nil {
			log.Printf("could not open a browser window: %v", err)
		}
	}

	// If we were launched to handle a link, process it now (the window we just
	// opened will show the consent prompt via long-poll).
	if signURL != "" {
		srv.HandleSignURL(signURL)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Where a real tray backend exists (linux/windows, pure Go), the tray owns
	// the main goroutine until its Quit item or a signal ends it — the first
	// user-visible way to stop wedge. Elsewhere (or under WEDGE_NO_TRAY=1)
	// main blocks on the signal exactly as before.
	if tray.Supported() && os.Getenv("WEDGE_NO_TRAY") == "" {
		mgr.OnChange(tray.Refresh) // sites edited in settings → menu rebuilds
		go func() {
			<-ctx.Done()
			tray.Quit()
		}()
		tray.Run(trayDeps(mgr, uiURL))
	} else {
		<-ctx.Done()
	}
	if err := srv.Stop(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("shutdown: %v", err)
	}
}

// trayDeps wires the tray menu to the running app. Site launches go over the
// server's own loopback API (the forwardHandoff pattern), so a tray click and
// a settings-row click share the exact same validated code path.
func trayDeps(mgr *config.Manager, uiURL string) tray.Deps {
	port := mgr.Get().ServerPort
	return tray.Deps{
		Version:  version,
		Icon:     wedge.TrayIcon(),
		GlyphSSH: wedge.TrayGlyphTerminal(),
		GlyphWeb: wedge.TrayGlyphWeb(),
		Sites: func() []tray.Site {
			cfg := mgr.Get()
			sites := make([]tray.Site, 0, len(cfg.Sites))
			for _, s := range cfg.Sites {
				sites = append(sites, tray.NewSite(s.Origin))
			}
			return sites
		},
		OpenUI: func() { browser.Open(uiURL) },
		Launch: func(s tray.Site) {
			path := "/api/signin"
			timeout := 90 * time.Second // sign-in can wait 45s on the consent tap
			if s.SSH {
				path, timeout = "/api/ssh", 10*time.Second
			}
			if err := postLoopback(port, path, map[string]string{"origin": s.Origin}, timeout); err != nil {
				log.Printf("tray launch %s: %v", s.Origin, err)
			}
		},
	}
}

// forwardHandoff hands a wedge:// link to the running instance's loopback
// server. Returns true on success.
func forwardHandoff(port int, signURL string) bool {
	return postLoopback(port, "/internal/handoff", map[string]string{"url": signURL}, 3*time.Second) == nil
}

// postLoopback POSTs JSON to this (or the running) wedge's loopback server.
func postLoopback(port int, path string, payload any, timeout time.Duration) error {
	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("http://127.0.0.1:%d%s", port, path)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&e)
		if e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func firstWedgeArg() string {
	for _, a := range os.Args[1:] {
		if strings.HasPrefix(a, "wedge://") {
			return a
		}
	}
	return ""
}

func hasFlag(name string) bool {
	for _, a := range os.Args[1:] {
		if a == name {
			return true
		}
	}
	return false
}
