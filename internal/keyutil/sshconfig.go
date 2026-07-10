package keyutil

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// SSHConfigHosts parses an ssh_config stream and returns its literal Host
// aliases, deduplicated, in order of first appearance. Only `Host` lines are
// read: wildcard/negated patterns (*, ?, !…) are skipped and Match/Include
// blocks are ignored entirely — an imported site launches `ssh <alias>`, so
// OpenSSH itself resolves HostName/User/Port/ProxyJump and any wildcard or
// Match settings from the config at connect time.
func SSHConfigHosts(r io.Reader) []string {
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		key, rest := splitConfigLine(sc.Text())
		if key != "host" {
			continue
		}
		for _, pat := range splitPatterns(rest) {
			if strings.HasPrefix(pat, "#") {
				break // trailing comment — ignore the rest of the line
			}
			if pat == "" || strings.ContainsAny(pat, "*?") || strings.HasPrefix(pat, "!") {
				continue // not a literal alias
			}
			if !seen[pat] {
				seen[pat] = true
				out = append(out, pat)
			}
		}
	}
	return out
}

// DiscoverSSHConfigHosts reads ~/.ssh/config and returns its literal Host
// aliases. A missing config file yields an empty list, never an error.
func DiscoverSSHConfigHosts() ([]string, error) {
	dir, err := sshDir()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(dir, "config"))
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	defer f.Close()
	return SSHConfigHosts(f), nil
}

// splitConfigLine splits one ssh_config line into its lowercased keyword and
// the remaining arguments. ssh_config separates them with whitespace or `=`
// ("Host web1", "Host=web1", "Host = web1"), and keywords are case-insensitive.
// Comment and blank lines yield an empty keyword.
func splitConfigLine(line string) (key, rest string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", ""
	}
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return strings.ToLower(line), ""
	}
	key = strings.ToLower(line[:i])
	rest = strings.TrimSpace(line[i:])
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "="))
	return key, rest
}

// splitPatterns splits a Host argument list into patterns. Double quotes group
// a pattern containing spaces (per ssh_config quoting) and are stripped.
func splitPatterns(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, c := range s {
		switch {
		case c == '"':
			inQuote = !inQuote
		case (c == ' ' || c == '\t') && !inQuote:
			flush()
		default:
			cur.WriteRune(c)
		}
	}
	flush()
	return out
}
