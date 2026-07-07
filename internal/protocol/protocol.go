// Package protocol parses wedge:// deep links. The link is fully
// attacker-controllable, so parsing is strict and carries no trust: origin is
// only ever used as a lookup key into wedge's own config, and request_id is
// opaque. See docs/wedge-protocol.md §3.
package protocol

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// requestIDRe bounds the opaque request_id to a safe charset/length. It is
// echoed to the RP verbatim, so keep it URL/JSON-safe.
var requestIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// SignRequest is a parsed wedge://sign link.
type SignRequest struct {
	Version   int
	Origin    string // raw origin string from the link (not yet normalized)
	RequestID string
}

// ParseSignURL parses a wedge://sign?v=1&origin=…&request_id=… link.
func ParseSignURL(raw string) (SignRequest, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return SignRequest{}, fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "wedge" {
		return SignRequest{}, fmt.Errorf("not a wedge:// url")
	}
	if u.Host != "sign" {
		return SignRequest{}, fmt.Errorf("unsupported action %q", u.Host)
	}
	q := u.Query()
	if q.Get("v") != "1" {
		return SignRequest{}, fmt.Errorf("unsupported protocol version %q", q.Get("v"))
	}
	origin := strings.TrimSpace(q.Get("origin"))
	if origin == "" {
		return SignRequest{}, fmt.Errorf("missing origin")
	}
	requestID := strings.TrimSpace(q.Get("request_id"))
	if !requestIDRe.MatchString(requestID) {
		return SignRequest{}, fmt.Errorf("invalid request_id")
	}
	return SignRequest{Version: 1, Origin: origin, RequestID: requestID}, nil
}
