//go:build linux || windows

package tray

import (
	"sync"

	"fyne.io/systray"
)

var (
	mu     sync.Mutex
	deps   Deps
	ready  bool
	cancel chan struct{} // closes on every menu rebuild so old click loops exit
)

// Supported reports whether this build carries a real tray.
func Supported() bool { return true }

// Run shows the tray and blocks until Quit (menu item or the Quit function).
// It must own the main goroutine. If no tray host is available (e.g. GNOME
// without the AppIndicator extension), systray logs and keeps running — wedge
// itself is unaffected, there's just no visible icon.
func Run(d Deps) {
	mu.Lock()
	deps = d
	mu.Unlock()
	systray.Run(onReady, nil)
}

// Quit ends Run. Safe to call from any goroutine (e.g. the signal bridge).
func Quit() { systray.Quit() }

// Refresh rebuilds the sites menu from Deps.Sites. No-op before Run is ready.
func Refresh() {
	mu.Lock()
	r := ready
	mu.Unlock()
	if r {
		buildMenu()
	}
}

func onReady() {
	mu.Lock()
	d := deps
	ready = true
	mu.Unlock()
	systray.SetIcon(d.Icon)
	systray.SetTooltip("wedge " + d.Version)
	buildMenu()
}

func buildMenu() {
	mu.Lock()
	if cancel != nil {
		close(cancel)
	}
	cancel = make(chan struct{})
	c := cancel
	d := deps
	mu.Unlock()

	systray.ResetMenu()

	open := systray.AddMenuItem("Open wedge", "Open the wedge window")
	go clickLoop(c, open, d.OpenUI)
	systray.AddSeparator()

	sites := d.Sites()
	if len(sites) == 0 {
		none := systray.AddMenuItem("No sites configured", "Add sites in the wedge window")
		none.Disable()
	}
	for _, s := range sites {
		var tip string
		if s.SSH {
			tip = "Open an SSH terminal to this host"
		} else {
			tip = "Sign in with wedge and open this site"
		}
		item := systray.AddMenuItem(s.Origin, tip)
		if s.SSH {
			item.SetIcon(d.GlyphSSH)
		} else {
			item.SetIcon(d.GlyphWeb)
		}
		site := s
		go clickLoop(c, item, func() { d.Launch(site) })
	}

	systray.AddSeparator()
	quit := systray.AddMenuItem("Quit wedge", "Stop wedge")
	go clickLoop(c, quit, systray.Quit)
}

// clickLoop dispatches an item's clicks until the menu is rebuilt (cancel
// closes). Actions run on their own goroutine so a slow launch (sign-in
// waiting on the consent tap) never blocks the menu.
func clickLoop(cancel chan struct{}, mi *systray.MenuItem, fn func()) {
	for {
		select {
		case <-cancel:
			return
		case _, ok := <-mi.ClickedCh:
			if !ok {
				return
			}
			go fn()
		}
	}
}
