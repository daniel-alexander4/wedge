package keyutil

import (
	"reflect"
	"strings"
	"testing"
)

func TestSSHConfigHosts(t *testing.T) {
	cases := []struct {
		name   string
		config string
		want   []string
	}{
		{"basic literal", "Host web1\n  HostName web1.example.com\n", []string{"web1"}},
		{"multi-pattern keeps literals only", "Host web1 web2 *.internal\n", []string{"web1", "web2"}},
		{"wildcard-only stanza skipped", "Host *\n  ForwardAgent no\n", nil},
		{"question-mark wildcard skipped", "Host web?\n", nil},
		{"negation skipped", "Host !bad good\n", []string{"good"}},
		{"match block ignored", "Match host *.example.com\n  User dan\nHost db1\n", []string{"db1"}},
		{"include ignored", "Include ~/.ssh/extra\nHost db2\n", []string{"db2"}},
		{"equals separator", "Host=web3\nHost = web4\n", []string{"web3", "web4"}},
		{"keyword case-insensitive", "HOST web5\nhOsT web6\n", []string{"web5", "web6"}},
		{"quoted alias", "Host \"web7\"\n", []string{"web7"}},
		{"quoted alias with space passes through", "Host \"my host\"\n", []string{"my host"}},
		{"dedupe keeps first order", "Host web1\nHost web2\nHost web1\n", []string{"web1", "web2"}},
		{"comment lines ignored", "# Host nope\n  # Host nope2\nHost web8\n", []string{"web8"}},
		{"trailing comment cut", "Host web9 # prod box\n", []string{"web9"}},
		{"directives are not hosts", "Host web1\n  HostName real.example.com\n  User dan\n  Port 2222\n", []string{"web1"}},
		{"underscore alias kept", "Host my_server\n", []string{"my_server"}},
		{"indented host line", "  Host web10\n", []string{"web10"}},
		{"empty input", "", nil},
	}
	for _, c := range cases {
		got := SSHConfigHosts(strings.NewReader(c.config))
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: SSHConfigHosts = %v, want %v", c.name, got, c.want)
		}
	}
}
