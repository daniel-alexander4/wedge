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

func TestTunnelFlag(t *testing.T) {
	accepts := []struct{ spec, flag string }{
		{"1080", "-D"},
		{"127.0.0.1:1080", "-D"},
		{"8080:localhost:80", "-L"},
		{"127.0.0.1:8080:internal-box:443", "-L"},
		{"8080:my_server:80", "-L"},
	}
	for _, c := range accepts {
		flag, err := TunnelFlag(c.spec)
		if err != nil || flag != c.flag {
			t.Errorf("TunnelFlag(%q) = %q, %v; want %q, nil", c.spec, flag, err, c.flag)
		}
	}
	rejects := []struct{ name, spec string }{
		{"empty", ""},
		{"empty segment", ":8080:host:80"},
		{"trailing colon", "8080:host:"},
		{"too many segments", "a:8080:host:80:9"},
		{"wildcard bind", "*:1080"},
		{"option injection", "-oProxyCommand=calc"},
		{"space", "8080:host reboot:80"},
		{"metacharacter", "8080:host$(reboot):80"},
		{"bad port", "99999"},
		{"non-numeric port", "80x:host:80"},
		{"signed port", "+8080:host:80"},
		{"ipv6 bracket", "[::1]:8080:host:80"},
	}
	for _, c := range rejects {
		if _, err := TunnelFlag(c.spec); err == nil {
			t.Errorf("%s: TunnelFlag(%q) = nil, want rejection", c.name, c.spec)
		}
	}
}

func TestValidateJump(t *testing.T) {
	accepts := []string{
		"bastion",
		"dan@bastion",
		"bastion:2222",
		"dan@bastion:2222",
		"hop1,dan@hop2:22,hop3.example.com",
	}
	for _, j := range accepts {
		if err := ValidateJump(j); err != nil {
			t.Errorf("ValidateJump(%q) = %v, want nil", j, err)
		}
	}
	rejects := []struct{ name, jump string }{
		{"empty hop", "bastion,,other"},
		{"option injection", "-oProxyCommand=calc"},
		{"leading-dash user", "-x@bastion"},
		{"empty user", "@bastion"},
		{"trailing colon", "bastion:"},
		{"double colon", "bastion:22:9"},
		{"metacharacter", "bas;tion"},
		{"space", "bastion two"},
	}
	for _, c := range rejects {
		if err := ValidateJump(c.jump); err == nil {
			t.Errorf("%s: ValidateJump(%q) = nil, want rejection", c.name, c.jump)
		}
	}
}

func TestSSHFlagArgs(t *testing.T) {
	got := sshFlagArgs("dan", "example.com", "2222", nil, "")
	want := []string{"-p", "2222", "-l", "dan", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sshFlagArgs = %v, want %v", got, want)
	}
	// no user, no port → just the host
	if got := sshFlagArgs("", "example.com", "", nil, ""); !reflect.DeepEqual(got, []string{"example.com"}) {
		t.Errorf("sshFlagArgs(bare) = %v, want [example.com]", got)
	}
	// tunnels and jump precede -p/-l, host stays last
	got = sshFlagArgs("dan", "web1", "2222", []string{"8080:localhost:80", "1080"}, "dan@bastion:22")
	want = []string{"-L", "8080:localhost:80", "-D", "1080", "-J", "dan@bastion:22", "-p", "2222", "-l", "dan", "web1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sshFlagArgs(full) = %v, want %v", got, want)
	}
}
