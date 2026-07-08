// Package browser opens wedge's UI in a chromeless app-mode window.
//
// We prefer a Chromium-family browser's --app mode, which gives a dedicated,
// address-bar-free window that looks like a native desktop app while reusing an
// engine that's already installed. If none is found we fall back to opening the
// URL as an ordinary tab in the default browser. (Safari has no app mode, so a
// Safari-only Mac takes the tab fallback — by design.)
//
// Adapted from the same pattern in nib/hespera.
package browser

import (
	"os"
	"os/exec"
	"runtime"
)

// fileExists reports whether a path is a regular, runnable file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// Open launches url as an app-mode window, or a default-browser tab if no
// app-mode-capable browser is found. It returns the started command (already
// running) so the caller can wait on it, or an error if nothing could launch.
func Open(url string) (*exec.Cmd, error) {
	if path, ok := findChromium(); ok {
		appArgs := []string{"--app=" + url, "--new-window"}
		if runtime.GOOS == "linux" {
			// Stable WM_CLASS so the panel can match the window to wedge's
			// .desktop entry and show the themed icon.
			appArgs = append(appArgs, "--class=Wedge")
		}
		cmd := exec.Command(path, appArgs...)
		if err := cmd.Start(); err == nil {
			return cmd, nil
		}
		// fall through to the tab fallback if the app-mode launch failed
	}

	name, args := tabOpener(url)
	cmd := exec.Command(name, args...)
	return cmd, cmd.Start()
}

// OpenTab opens url as an ordinary tab in the user's default browser, reusing a
// running instance or launching one. Unlike Open it never uses chromeless
// app-mode — this is for launching real sites, not wedge's own UI.
func OpenTab(url string) error {
	name, args := tabOpener(url)
	return exec.Command(name, args...).Start()
}

// findChromium returns the first Chromium-family browser found for the OS.
func findChromium() (string, bool) {
	for _, c := range chromiumCandidates() {
		if path, err := exec.LookPath(c); err == nil {
			return path, true
		}
		if fileExists(c) { // absolute paths (macOS .app bundles)
			return c, true
		}
	}
	return "", false
}

// chromiumCandidates lists browser binaries to try, per OS.
func chromiumCandidates() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
	case "windows":
		return []string{
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
			"chrome.exe", "msedge.exe",
		}
	default: // linux and friends
		return []string{
			"google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
			"microsoft-edge", "brave-browser",
		}
	}
}

// tabOpener returns the OS command that opens a URL in the default browser.
func tabOpener(url string) (string, []string) {
	switch runtime.GOOS {
	case "darwin":
		return "open", []string{url}
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		return "xdg-open", []string{url}
	}
}
