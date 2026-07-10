package tray

import "testing"

func TestNewSite(t *testing.T) {
	cases := []struct {
		origin string
		ssh    bool
	}{
		{"ssh://web1", true},
		{"ssh://dan@example.com:2222", true},
		{"https://acme.example", false},
		{"http://localhost:3000", false},
	}
	for _, c := range cases {
		s := NewSite(c.origin)
		if s.Origin != c.origin || s.SSH != c.ssh {
			t.Errorf("NewSite(%q) = %+v, want SSH=%v", c.origin, s, c.ssh)
		}
	}
}
