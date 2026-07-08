// Pending sign-in state.
//
// Every wedge sign-in is one RequestRecord keyed by request_id, carrying the
// challenge and the single-use tokens that gate session minting. Single-use
// is enforced structurally: TakeAuthenticated removes the record atomically,
// so no second session can ever be minted from the same sign-in (spec §5.4,
// §8.3), and a challenge dies with its record.
//
// MemoryStore covers one process — the normal shape of a Go server. A
// multi-process or multi-host deployment implements RequestStore over storage
// it already shares (SQL, Redis); the two mutating methods are the single-use
// guarantees and must stay atomic there.

package wedgerp

import (
	"sync"
	"time"
)

// RequestRecord is one pending sign-in. Empty string means "not set".
type RequestRecord struct {
	RequestID string
	Challenge string
	Namespace string
	Username  string // asserted at start (username-carrying core flow)
	// BrowserNonce is the browser-binding cookie value (core flow); empty for
	// app-initiated requests, which complete via the claim token instead.
	BrowserNonce string
	ClaimToken   string // single-use claim token (app-initiated flow)
	Status       string // "pending" | "authenticated"
	// AuthenticatedUsername is the account that verified, set with
	// Status == "authenticated".
	AuthenticatedUsername string
	ExpiresAt             time.Time
}

// RequestStore is the pending-request storage contract. Implementations must
// make SetAuthenticated and TakeAuthenticated atomic across every process
// sharing the store.
type RequestStore interface {
	// Put inserts a new record.
	Put(rec RequestRecord) error
	// Get returns the live record; ok=false if unknown or expired.
	Get(requestID string) (rec RequestRecord, ok bool, err error)
	// SetAuthenticated atomically moves a live record from "pending" to
	// "authenticated", recording the verified account. ok=false if it was
	// not pending.
	SetAuthenticated(requestID, username string) (ok bool, err error)
	// TakeAuthenticated atomically removes and returns a live
	// "authenticated" record. At most one caller ever receives a record.
	TakeAuthenticated(requestID string) (rec RequestRecord, ok bool, err error)
}

// MemoryStore is the in-process default. Thread-safe; not shared across
// processes.
type MemoryStore struct {
	mu      sync.Mutex
	records map[string]RequestRecord
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]RequestRecord)}
}

func (s *MemoryStore) prune(now time.Time) {
	for id, rec := range s.records {
		if !rec.ExpiresAt.After(now) {
			delete(s.records, id)
		}
	}
}

func (s *MemoryStore) Put(rec RequestRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(time.Now())
	s.records[rec.RequestID] = rec
	return nil
}

func (s *MemoryStore) Get(requestID string) (RequestRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(time.Now())
	rec, ok := s.records[requestID]
	return rec, ok, nil
}

func (s *MemoryStore) SetAuthenticated(requestID, username string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(time.Now())
	rec, ok := s.records[requestID]
	if !ok || rec.Status != "pending" {
		return false, nil
	}
	rec.Status = "authenticated"
	rec.AuthenticatedUsername = username
	s.records[requestID] = rec
	return true, nil
}

func (s *MemoryStore) TakeAuthenticated(requestID string) (RequestRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(time.Now())
	rec, ok := s.records[requestID]
	if !ok || rec.Status != "authenticated" {
		return RequestRecord{}, false, nil
	}
	delete(s.records, requestID)
	return rec, true, nil
}
