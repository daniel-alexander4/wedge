package protocol

import "testing"

func TestParseSignURLValid(t *testing.T) {
	r, err := ParseSignURL("wedge://sign?v=1&origin=https%3A%2F%2Facme.example&request_id=req_ABC-123.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Version != 1 {
		t.Errorf("version = %d", r.Version)
	}
	if r.Origin != "https://acme.example" {
		t.Errorf("origin = %q", r.Origin)
	}
	if r.RequestID != "req_ABC-123.4" {
		t.Errorf("request_id = %q", r.RequestID)
	}
}

func TestParseSignURLRejects(t *testing.T) {
	bad := []string{
		"http://sign?v=1&origin=https://a&request_id=x",   // wrong scheme
		"wedge://other?v=1&origin=https://a&request_id=x", // wrong action
		"wedge://sign?v=2&origin=https://a&request_id=x",  // wrong version
		"wedge://sign?v=1&request_id=x",                   // missing origin
		"wedge://sign?v=1&origin=https://a",               // missing request_id
		"wedge://sign?v=1&origin=https://a&request_id=has spaces",
		"wedge://sign?v=1&origin=https://a&request_id=" + longString(200),
	}
	for _, u := range bad {
		if _, err := ParseSignURL(u); err == nil {
			t.Errorf("expected error for %q", u)
		}
	}
}

func longString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}
