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
	// hostnames, IPv4 literals, and ssh_config Host aliases: must start
	// alphanumeric, so a leading '-' (ssh option injection) and shell
	// metacharacters are both excluded. Underscore is allowed after the first
	// character — aliases aren't DNS names (`Host my_server` is common) and `_`
	// carries no shell or option-injection risk.
	sshHostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._\-]*[A-Za-z0-9_])?$`)
	sshUserRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

func validHostPart(h string) bool {
	return h != "" && !strings.HasPrefix(h, "-") && sshHostRe.MatchString(h)
}

// validPort accepts digits-only 1–65535 (no signs — Atoi's "+22" would leak
// a non-numeric character into argv).
func validPort(p string) bool {
	for _, c := range p {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(p)
	return err == nil && n >= 1 && n <= 65535
}

// ValidateSSHTarget rejects anything that could turn `ssh <target>` into
// arbitrary command execution: empty/leading-'-' host, non-hostname characters,
// a bad user, or an out-of-range port.
func ValidateSSHTarget(user, host, port string) error {
	if host == "" {
		return fmt.Errorf("ssh: empty host")
	}
	if !validHostPart(host) {
		return fmt.Errorf("ssh: invalid host %q", host)
	}
	if user != "" {
		if strings.HasPrefix(user, "-") || !sshUserRe.MatchString(user) {
			return fmt.Errorf("ssh: invalid user %q", user)
		}
	}
	if port != "" && !validPort(port) {
		return fmt.Errorf("ssh: invalid port %q", port)
	}
	return nil
}

// TunnelFlag validates a per-site tunnel spec and returns the ssh flag it
// drives. The spec's shape picks the flag by colon count, mirroring ssh's own
// argument grammar: [bind:]port (0–1 colons) is a dynamic SOCKS forward (-D),
// [bind:]lport:host:hport (2–3) is a local forward (-L). Every segment is
// strictly validated — no empty segments, no wildcard binds, no IPv6 literals
// (v1 limitation) — so a spec can't smuggle ssh options or shell metacharacters.
func TunnelFlag(spec string) (string, error) {
	bad := func() (string, error) { return "", fmt.Errorf("ssh: invalid tunnel %q", spec) }
	parts := strings.Split(spec, ":")
	switch len(parts) {
	case 1: // port
		if !validPort(parts[0]) {
			return bad()
		}
		return "-D", nil
	case 2: // bind:port
		if !validHostPart(parts[0]) || !validPort(parts[1]) {
			return bad()
		}
		return "-D", nil
	case 3: // lport:host:hport
		if !validPort(parts[0]) || !validHostPart(parts[1]) || !validPort(parts[2]) {
			return bad()
		}
		return "-L", nil
	case 4: // bind:lport:host:hport
		if !validHostPart(parts[0]) || !validPort(parts[1]) || !validHostPart(parts[2]) || !validPort(parts[3]) {
			return bad()
		}
		return "-L", nil
	default:
		return bad()
	}
}

// ValidateJump validates a ProxyJump hop list: comma-separated
// [user@]host[:port] entries, each held to the same user/host/port rules as
// the target itself (leading '-' and shell metacharacters excluded).
func ValidateJump(jump string) error {
	for _, hop := range strings.Split(jump, ",") {
		user, rest := "", hop
		if i := strings.Index(hop, "@"); i >= 0 {
			user, rest = hop[:i], hop[i+1:]
			if user == "" {
				return fmt.Errorf("ssh: invalid jump hop %q", hop)
			}
		}
		host, port := rest, ""
		if i := strings.Index(rest, ":"); i >= 0 {
			host, port = rest[:i], rest[i+1:]
			if port == "" {
				return fmt.Errorf("ssh: invalid jump hop %q", hop)
			}
		}
		if err := ValidateSSHTarget(user, host, port); err != nil {
			return fmt.Errorf("ssh: invalid jump hop %q: %w", hop, err)
		}
	}
	return nil
}

// sshFlagArgs builds the ssh argument vector (after "ssh") from validated
// components: -L/-D per tunnel spec, -J <jump>, -p <port>, -l <user> as
// separate flags, host last.
func sshFlagArgs(user, host, port string, tunnels []string, jump string) []string {
	args := []string{}
	for _, t := range tunnels {
		flag, err := TunnelFlag(t)
		if err != nil {
			continue // callers validate first; never emit an unvalidated spec
		}
		args = append(args, flag, t)
	}
	if jump != "" {
		args = append(args, "-J", jump)
	}
	if port != "" {
		args = append(args, "-p", port)
	}
	if user != "" {
		args = append(args, "-l", user)
	}
	return append(args, host)
}

// OpenSSH opens a terminal window running `ssh` against the validated target,
// with the site's optional tunnels (-L/-D) and jump hops (-J) applied.
func OpenSSH(user, host, port string, tunnels []string, jump string) error {
	if err := ValidateSSHTarget(user, host, port); err != nil {
		return err
	}
	for _, t := range tunnels {
		if _, err := TunnelFlag(t); err != nil {
			return err
		}
	}
	if jump != "" {
		if err := ValidateJump(jump); err != nil {
			return err
		}
	}
	sargs := sshFlagArgs(user, host, port, tunnels, jump)

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
