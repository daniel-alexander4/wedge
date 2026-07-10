//go:build darwin

package handler

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// register asks Launch Services to (re)scan the .app bundle that contains this
// binary, so the CFBundleURLTypes declaration in its Info.plist takes effect.
// macOS routes wedge:// to a bundle identifier, never a bare binary, so wedge
// must be run from inside the wedge.app that build.sh assembles.
func register() error {
	app, err := containingApp()
	if err != nil {
		return err
	}
	return lsregister(app, false)
}

func unregister() error {
	app, err := containingApp()
	if err != nil {
		return err
	}
	return lsregister(app, true)
}

// containingApp returns the .app bundle directory this binary lives in
// (…/wedge.app/Contents/MacOS/wedge → …/wedge.app), or an error naming the fix.
func containingApp() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	// Walk up to the first ancestor ending in .app.
	for dir := filepath.Dir(exe); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		if strings.HasSuffix(dir, ".app") {
			return dir, nil
		}
	}
	return "", fmt.Errorf("wedge must be run from inside wedge.app to register the wedge:// handler (run the .app that build.sh produces, not the bare binary)")
}

func lsregister(app string, remove bool) error {
	const bin = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
	args := []string{"-f"}
	if remove {
		args = []string{"-u"}
	}
	return exec.Command(bin, append(args, app)...).Run()
}
