package conform

import (
	"net/http"
	"net/url"
	"os"
	"sync"
)

// Reference browser-completion path (spec §5.4 leaves the shape to the RP;
// this is the wedge.js/wedge-rp shape).
const statusPath = "/wedge/status"

// appStart is the parsed §8.1 response.
type appStart struct {
	RequestID string
	Challenge string
	Namespace string
	ClaimURL  string
}

// tmpDir lazily creates a scratch dir for extra throwaway keys.
func (s *Session) tmpDir() string {
	if s.tmp == "" {
		s.tmp, _ = os.MkdirTemp("", "wedge-conform-")
	}
	return s.tmp
}

// Close removes the session's scratch dir.
func (s *Session) Close() {
	if s.tmp != "" {
		os.RemoveAll(s.tmp)
	}
}

// appStart probes and memoizes §8 support. A non-200 means a conforming
// Core-only RP (§8.1 explanatory rejection) — the app section SKIPs.
func (s *Session) appStart() (appStart, *Result) {
	if s.appProbe != nil {
		if s.appProbe.reject != nil {
			return appStart{}, s.appProbe.reject
		}
	} else {
		s.appProbe = &appProbeState{}
		if _, err := s.discovery(); err != nil {
			r := fail("%v", err)
			s.appProbe.reject = &r
			return appStart{}, s.appProbe.reject
		}
		resp, err := s.postJSON(s.Target+appStartPath, map[string]any{})
		if err != nil {
			r := fail("%v", err)
			s.appProbe.reject = &r
			return appStart{}, s.appProbe.reject
		}
		if resp.Status != 200 {
			r := skip("app-initiated flow not supported (HTTP %d: %s) — a conforming Core-only RP", resp.Status, str(resp.Body, "error"))
			s.appProbe.reject = &r
			return appStart{}, s.appProbe.reject
		}
	}
	// Supported: every call mints a fresh request (claims are single-use).
	resp, err := s.postJSON(s.Target+appStartPath, map[string]any{})
	if err != nil {
		r := fail("%v", err)
		return appStart{}, &r
	}
	if resp.Status != 200 {
		r := fail("app-start: HTTP %d", resp.Status)
		return appStart{}, &r
	}
	return appStart{
		RequestID: str(resp.Body, "request_id"),
		Challenge: str(resp.Body, "challenge"),
		Namespace: str(resp.Body, "namespace"),
		ClaimURL:  str(resp.Body, "claim_url"),
	}, nil
}

type appProbeState struct {
	reject *Result // nil = supported
}

// appVerify signs and verifies an app-start request (public_key REQUIRED).
func (s *Session) appVerify(ap appStart) (wireResp, error) {
	sig, err := s.Key.Sign(ap.Challenge, ap.Namespace)
	if err != nil {
		return wireResp{}, err
	}
	return s.verify(pending{RequestID: ap.RequestID}, sig, s.Key.PublicKey, ap.Namespace, ap.Challenge, nil)
}

// claimResponse memoizes one full app flow's successful claim response for
// the header/redirect SHOULD checks (A8/A11).
func (s *Session) claimResponse() (wireResp, *Result) {
	if s.claimResp != nil {
		return *s.claimResp, nil
	}
	ap, res := s.appStart()
	if res != nil {
		return wireResp{}, res
	}
	if resp, err := s.appVerify(ap); err != nil || resp.Status != 200 {
		r := fail("app verify: err=%v HTTP %d", err, resp.Status)
		return wireResp{}, &r
	}
	resp, err := s.get(ap.ClaimURL)
	if err != nil {
		r := fail("%v", err)
		return wireResp{}, &r
	}
	s.claimResp = &resp
	return resp, nil
}

// checkBinding (S2): after a successful verify, only the binding bearer sees
// "authenticated"; no cookie or a wrong nonce stays pending. Reference
// start/status shapes only — SKIP under a custom start command.
func (s *Session) checkBinding() Result {
	p, resp, res := s.boundAuthenticated()
	if res != nil {
		return *res
	}
	_ = resp
	statusURL := s.Target + statusPath + "?request_id=" + url.QueryEscape(p.RequestID)

	bare, err := s.get(statusURL)
	if err != nil {
		return fail("%v", err)
	}
	if str(bare.Body, "status") == "authenticated" {
		return fail("status with NO binding cookie reported authenticated")
	}
	wrong, err := s.get(statusURL, &http.Cookie{Name: p.Binding.Name, Value: "wedge-conform-wrong-nonce"})
	if err != nil {
		return fail("%v", err)
	}
	if str(wrong.Body, "status") == "authenticated" {
		return fail("status with a WRONG binding nonce reported authenticated")
	}
	right, err := s.get(statusURL, p.Binding)
	if err != nil {
		return fail("%v", err)
	}
	if str(right.Body, "status") != "authenticated" {
		return fail("binding bearer did not get authenticated (status %q)", str(right.Body, "status"))
	}
	s.bindingDone = &p // S3 continues from here
	return pass()
}

// checkBindingSingleUse (S3): the request cannot be collected twice.
func (s *Session) checkBindingSingleUse() Result {
	if s.StartCmd != "" {
		return skip("custom start shape — binding not observable (spec §5.4 leaves the shape to the RP)")
	}
	p := s.bindingDone
	if p == nil {
		// S2 failed or skipped; run an independent flow.
		fresh, _, res := s.boundAuthenticated()
		if res != nil {
			return *res
		}
		statusURL := s.Target + statusPath + "?request_id=" + url.QueryEscape(fresh.RequestID)
		if resp, err := s.get(statusURL, fresh.Binding); err != nil || str(resp.Body, "status") != "authenticated" {
			return fail("first collection failed (err=%v)", err)
		}
		p = &fresh
	}
	statusURL := s.Target + statusPath + "?request_id=" + url.QueryEscape(p.RequestID)
	again, err := s.get(statusURL, p.Binding)
	if err != nil {
		return fail("%v", err)
	}
	return failIf(str(again.Body, "status") == "authenticated", "the request was collected twice")
}

// boundAuthenticated runs start → sign → verify and returns the pending
// request with its binding cookie, ready for status collection.
func (s *Session) boundAuthenticated() (pending, wireResp, *Result) {
	if s.StartCmd != "" {
		r := skip("custom start shape — binding not observable (spec §5.4 leaves the shape to the RP)")
		return pending{}, wireResp{}, &r
	}
	p, err := s.newRequest()
	if err != nil {
		r := fail("%v", err)
		return pending{}, wireResp{}, &r
	}
	if p.Binding == nil {
		r := skip("reference start set no binding cookie — binding not observable")
		return pending{}, wireResp{}, &r
	}
	resp, err := s.signedVerify(p)
	if err != nil || resp.Status != 200 {
		r := fail("verify: err=%v HTTP %d %s", err, resp.Status, resp.Raw)
		return pending{}, wireResp{}, &r
	}
	return p, resp, nil
}

// probeRateLimit (SEC1, opt-in): hammers verify with bad signatures from one
// source until a 429 appears (cap 40 attempts).
func (s *Session) probeRateLimit() Result {
	p, err := s.newRequest()
	if err != nil {
		return fail("%v", err)
	}
	badSig, err := s.Key.Sign("rate-limit-probe-bytes", p.Namespace)
	if err != nil {
		return fail("%v", err)
	}
	for i := 0; i < 40; i++ {
		resp, err := s.postJSON(s.verURL, map[string]any{
			"request_id": p.RequestID, "challenge": p.Challenge,
			"namespace": p.Namespace, "signature": badSig, "public_key": s.Key.PublicKey,
		})
		if err != nil {
			return fail("%v", err)
		}
		if resp.Status == 429 {
			return pass()
		}
	}
	return warn("no 429 after 40 failed verifies from one source (spec §10 SHOULD rate-limit)")
}

// probeConcurrency (SEC2, opt-in): bursts parallel verifies looking for 503.
func (s *Session) probeConcurrency() Result {
	p, err := s.newRequest()
	if err != nil {
		return fail("%v", err)
	}
	sig, err := s.Key.Sign("concurrency-probe-bytes", p.Namespace)
	if err != nil {
		return fail("%v", err)
	}
	var wg sync.WaitGroup
	saw503 := false
	var mu sync.Mutex
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := s.postJSON(s.verURL, map[string]any{
				"request_id": p.RequestID, "challenge": p.Challenge,
				"namespace": p.Namespace, "signature": sig, "public_key": s.Key.PublicKey,
			})
			if err == nil && resp.Status == 503 {
				mu.Lock()
				saw503 = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if !saw503 {
		return warn("no 503 under a 12-wide verify burst (spec §10 SHOULD bound concurrency)")
	}
	return pass()
}
