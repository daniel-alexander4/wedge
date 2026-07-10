package terminal

import (
	"reflect"
	"testing"
)

func TestValidateSSHTargetAccepts(t *testing.T) {
	cases := []struct{ user, host, port string }{
		{"", "example.com", ""},
		{"dan", "example.com", ""},
		{"dan", "10.0.0.5", "2222"},
		{"git", "host-1.sub.example.com", "22"},
		{"", "localhost", "65535"},
		{"", "my_server", ""},
		{"dan", "host_1.example", "22"},
	}
	for _, c := range cases {
		if err := ValidateSSHTarget(c.user, c.host, c.port); err != nil {
			t.Errorf("ValidateSSHTarget(%q,%q,%q) = %v, want nil", c.user, c.host, c.port, err)
		}
	}
}

func TestValidateSSHTargetRejectsInjection(t *testing.T) {
	// Each of these must be rejected — they are the ssh argument-injection and
	// shell-metacharacter vectors.
	cases := []struct{ name, user, host, port string }{
		{"option-injection host", "", "-oProxyCommand=calc", ""},
		{"leading-dash user", "-oProxyCommand=x", "host", ""},
		{"command substitution", "", "host$(reboot)", ""},
		{"semicolon", "", "host;reboot", ""},
		{"space", "", "host reboot", ""},
		{"backtick", "", "ho`st`", ""},
		{"pipe", "", "a|b", ""},
		{"empty host", "", "", ""},
		{"bad port", "", "host", "99999"},
		{"non-numeric port", "", "host", "22x"},
		{"quote in user", "u\"x", "host", ""},
		{"leading underscore host", "", "_host", ""},
	}
	for _, c := range cases {
		if err := ValidateSSHTarget(c.user, c.host, c.port); err == nil {
			t.Errorf("%s: ValidateSSHTarget(%q,%q,%q) = nil, want rejection", c.name, c.user, c.host, c.port)
		}
	}
}

func TestSSHFlagArgs(t *testing.T) {
	got := sshFlagArgs("dan", "example.com", "2222")
	want := []string{"-p", "2222", "-l", "dan", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sshFlagArgs = %v, want %v", got, want)
	}
	// no user, no port → just the host
	if got := sshFlagArgs("", "example.com", ""); !reflect.DeepEqual(got, []string{"example.com"}) {
		t.Errorf("sshFlagArgs(bare) = %v, want [example.com]", got)
	}
}
