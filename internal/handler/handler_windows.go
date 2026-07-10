//go:build windows

package handler

import (
	"os"

	"golang.org/x/sys/windows/registry"
)

// register writes the per-user URL-protocol keys under HKCU\Software\Classes\
// wedge (no admin/elevation needed), pointing the scheme at this exe. Per the
// Windows shell contract: an empty "URL Protocol" value marks the key as a
// scheme handler, and shell\open\command is invoked with the URL as %1.
func register() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	root, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Classes\wedge`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.SetStringValue("", "URL:wedge protocol"); err != nil {
		return err
	}
	if err := root.SetStringValue("URL Protocol", ""); err != nil {
		return err
	}

	cmd, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Classes\wedge\shell\open\command`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer cmd.Close()
	return cmd.SetStringValue("", `"`+exe+`" "%1"`)
}

func unregister() error {
	// Delete leaf-up: DeleteKey removes only keys without subkeys.
	for _, k := range []string{
		`Software\Classes\wedge\shell\open\command`,
		`Software\Classes\wedge\shell\open`,
		`Software\Classes\wedge\shell`,
		`Software\Classes\wedge`,
	} {
		err := registry.DeleteKey(registry.CURRENT_USER, k)
		if err != nil && err != registry.ErrNotExist {
			return err
		}
	}
	return nil
}
