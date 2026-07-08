package wedgerp

import (
	"sync"
	"testing"
	"time"
)

func testRecord(mutate ...func(*RequestRecord)) RequestRecord {
	rec := RequestRecord{
		RequestID:    "req1",
		Challenge:    "AbCdEfGhIjKlMnOpQrStUvWx",
		Namespace:    testNamespace,
		BrowserNonce: "nonce",
		Status:       "pending",
		ExpiresAt:    time.Now().Add(time.Minute),
	}
	for _, m := range mutate {
		m(&rec)
	}
	return rec
}

func TestMemoryStoreRoundtrip(t *testing.T) {
	s := NewMemoryStore()
	if err := s.Put(testRecord()); err != nil {
		t.Fatal(err)
	}
	rec, ok, _ := s.Get("req1")
	if !ok || rec.Challenge != "AbCdEfGhIjKlMnOpQrStUvWx" || rec.Status != "pending" {
		t.Fatalf("roundtrip: ok=%v rec=%+v", ok, rec)
	}
	if _, ok, _ := s.Get("nope"); ok {
		t.Error("unknown id returned a record")
	}
}

func TestMemoryStoreExpiry(t *testing.T) {
	s := NewMemoryStore()
	_ = s.Put(testRecord(func(r *RequestRecord) { r.ExpiresAt = time.Now().Add(-time.Second) }))
	if _, ok, _ := s.Get("req1"); ok {
		t.Error("expired record returned")
	}
	if ok, _ := s.SetAuthenticated("req1", "alice"); ok {
		t.Error("expired record authenticated")
	}
}

func TestMemoryStoreSetAuthenticatedOnlyFromPending(t *testing.T) {
	s := NewMemoryStore()
	_ = s.Put(testRecord())
	if ok, _ := s.SetAuthenticated("req1", "alice"); !ok {
		t.Fatal("pending record refused authentication")
	}
	if ok, _ := s.SetAuthenticated("req1", "mallory"); ok {
		t.Fatal("authenticated record re-authenticated")
	}
	rec, _, _ := s.Get("req1")
	if rec.Status != "authenticated" || rec.AuthenticatedUsername != "alice" {
		t.Fatalf("record = %+v", rec)
	}
}

func TestMemoryStoreTakeIsSingleUse(t *testing.T) {
	s := NewMemoryStore()
	_ = s.Put(testRecord())
	if _, ok, _ := s.TakeAuthenticated("req1"); ok {
		t.Fatal("pending record taken")
	}
	_, _ = s.SetAuthenticated("req1", "alice")
	rec, ok, _ := s.TakeAuthenticated("req1")
	if !ok || rec.AuthenticatedUsername != "alice" {
		t.Fatalf("take: ok=%v rec=%+v", ok, rec)
	}
	if _, ok, _ := s.TakeAuthenticated("req1"); ok {
		t.Fatal("record taken twice")
	}
	if _, ok, _ := s.Get("req1"); ok {
		t.Fatal("taken record still present")
	}
}

func TestMemoryStoreTakeRaceHasExactlyOneWinner(t *testing.T) {
	s := NewMemoryStore()
	_ = s.Put(testRecord())
	_, _ = s.SetAuthenticated("req1", "alice")
	var wg sync.WaitGroup
	wins := make(chan struct{}, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok, _ := s.TakeAuthenticated("req1"); ok {
				wins <- struct{}{}
			}
		}()
	}
	wg.Wait()
	close(wins)
	if n := len(wins); n != 1 {
		t.Fatalf("winners = %d, want exactly 1", n)
	}
}
