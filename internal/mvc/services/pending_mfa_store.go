package services

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

const (
	mfaTicketTTL   = 5 * time.Minute
	mfaMaxAttempts = 5
)

// pendingMFAStore holds tickets issued after a password check succeeds
// but a confirmed second factor still needs to be verified. It is
// intentionally process-local — a real deployment behind a load balancer
// needs a shared store (Redis) for this once multiple instances run;
// documented as a known limitation until internal/support/cache exists
// (see STRUCT_FRAMEWORK.md's Pass 7 follow-up).
//
// An attacker can never reach this state without first proving the
// password — Issue is only ever called after Login's password check
// succeeds — so a ticket alone, without the account's own TOTP secret or
// a valid backup code, is not enough to authenticate.
type pendingMFAStore struct {
	mu      sync.Mutex
	tickets map[string]*mfaTicket
}

type mfaTicket struct {
	userID   string
	expires  time.Time
	attempts int
}

func newPendingMFAStore() *pendingMFAStore {
	return &pendingMFAStore{tickets: make(map[string]*mfaTicket)}
}

// Issue creates a new single-use ticket for userID.
func (s *pendingMFAStore) Issue(userID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()

	ticket, err := randomTicket()
	if err != nil {
		return "", err
	}
	s.tickets[ticket] = &mfaTicket{userID: userID, expires: time.Now().Add(mfaTicketTTL)}
	return ticket, nil
}

// Redeem validates ticket and, if it's still live, counts one attempt
// against it — a wrong code can be retried up to mfaMaxAttempts times
// before the ticket itself is discarded, so a caller must still call
// Consume once a code actually verifies; Redeem alone doesn't delete it.
func (s *pendingMFAStore) Redeem(ticket string) (userID string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()

	t, exists := s.tickets[ticket]
	if !exists || time.Now().After(t.expires) {
		delete(s.tickets, ticket)
		return "", false
	}
	t.attempts++
	if t.attempts > mfaMaxAttempts {
		delete(s.tickets, ticket)
		return "", false
	}
	return t.userID, true
}

// Consume deletes ticket — called once its code has been verified
// successfully, so the same ticket can never be redeemed a second time.
func (s *pendingMFAStore) Consume(ticket string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tickets, ticket)
}

func (s *pendingMFAStore) sweepLocked() {
	now := time.Now()
	for k, t := range s.tickets {
		if now.After(t.expires) {
			delete(s.tickets, k)
		}
	}
}

func randomTicket() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("services: generating mfa ticket: %w", err)
	}
	return fmt.Sprintf("%x", b), nil
}
