// Package terminal opens a terminal window running the system ssh client, so
// wedge can launch a real SSH session (not just web auth). It never runs a
// shell on untrusted input: the user/host/port are strictly validated (see
// ValidateSSHTarget) so the components can't carry shell metacharacters or an
// ssh option-injection like `-oProxyCommand=...`, and they are passed as
// separate argv. That validation is what makes the macOS (osascript) and
// Windows (start) launchers safe despite their shell-ish nature.
package terminal

import (
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

var (
	// hostnames and IPv4 literals: must start and end alphanumeric, so a leading
	// '-' (ssh option injection) and shell metacharacters are both excluded.
	sshHostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?$`)
	sshUserRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// ValidateSSHTarget rejects anything that could turn `ssh <target>` into
// arbitrary command execution: empty/leading-'-' host, non-hostname characters,
// a bad user, or an out-of-range port.
func ValidateSSHTarget(user, host, port string) error {
	if host == "" {
		return fmt.Errorf("ssh: empty host")
	}
	if strings.HasPrefix(host, "-") || !sshHostRe.MatchString(host) {
		return fmt.Errorf("ssh: invalid host %q", host)
	}
	if user != "" {
		if strings.HasPrefix(user, "-") || !sshUserRe.MatchString(user) {
			return fmt.Errorf("ssh: invalid user %q", user)
		}
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("ssh: invalid port %q", port)
		}
	}
	return nil
}

// sshFlagArgs builds the ssh argument vector (after "ssh") from validated
// components: -p <port>, -l <user> as separate flags, host last.
func sshFlagArgs(user, host, port string) []string {
	args := []string{}
	if port != "" {
		args = append(args, "-p", port)
	}
	if user != "" {
		args = append(args, "-l", user)
	}
	return append(args, host)
}

// OpenSSH opens a terminal window running `ssh` against the validated target.
func OpenSSH(user, host, port string) error {
	if err := ValidateSSHTarget(user, host, port); err != nil {
		return err
	}
	sargs := sshFlagArgs(user, host, port)

	switch runtime.GOOS {
	case "darwin":
		// do script runs the string in a shell; sargs are validated (no spaces,
		// quotes, or metacharacters) so the joined command is shell-safe.
		cmd := "ssh " + strings.Join(sargs, " ")
		script := `tell application "Terminal" to do script "` + cmd + `"`
		return exec.Command("osascript", "-e", script, "-e", `tell application "Terminal" to activate`).Start()
	case "windows":
		if p, err := exec.LookPath("wt"); err == nil { // Windows Terminal
			return exec.Command(p, append([]string{"ssh"}, sargs...)...).Start()
		}
		// cmd /c start "" ssh ... — validated args, escaped as argv by Go.
		return exec.Command("cmd", append([]string{"/c", "start", "", "ssh"}, sargs...)...).Start()
	default: // linux and other unix
		term, flag, ok := findTerminal()
		if !ok {
			return fmt.Errorf("no terminal emulator found (install e.g. gnome-terminal, konsole, or xterm)")
		}
		var targs []string
		if flag != "" {
			targs = append(targs, flag)
		}
		targs = append(targs, "ssh")
		targs = append(targs, sargs...)
		return exec.Command(term, targs...).Start()
	}
}

// linuxTerminals lists terminal emulators and the flag that runs the rest of the
// args as a command. Order = preference; x-terminal-emulator (the Debian
// alternatives symlink) first. An empty flag means the command follows directly.
func linuxTerminals() []struct{ bin, flag string } {
	return []struct{ bin, flag string }{
		{"x-terminal-emulator", "-e"},
		{"gnome-terminal", "--"},
		{"konsole", "-e"},
		{"xfce4-terminal", "-x"},
		{"alacritty", "-e"},
		{"kitty", ""},
		{"xterm", "-e"},
	}
}

func findTerminal() (bin, flag string, ok bool) {
	for _, t := range linuxTerminals() {
		if path, err := exec.LookPath(t.bin); err == nil {
			return path, t.flag, true
		}
	}
	return "", "", false
}
