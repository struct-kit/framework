package services

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

const webauthnCeremonyTTL = 5 * time.Minute

// webauthnCeremonyStore holds the random challenge issued by a
// begin-registration or begin-assertion call until the matching finish
// call redeems it. Process-local by design, same caveat as
// pendingMFAStore. Unlike pendingMFAStore, a ceremony is single-use with
// no retry budget — redeeming it always deletes it, whether or not the
// signature that follows actually verifies, since a WebAuthn assertion
// can't be "guessed and retried" the way a 6-digit TOTP code can.
type webauthnCeremonyStore struct {
	mu         sync.Mutex
	ceremonies map[string]*webauthnCeremony
}

type webauthnCeremony struct {
	userID    string
	challenge []byte
	expires   time.Time
}

func newWebAuthnCeremonyStore() *webauthnCeremonyStore {
	return &webauthnCeremonyStore{ceremonies: make(map[string]*webauthnCeremony)}
}

// Issue starts a new ceremony for userID (the account being enrolled, or
// — for an assertion used as a second factor — the account a pending
// MFA ticket already identified) and returns its ID and challenge.
func (s *webauthnCeremonyStore) Issue(userID string) (ceremonyID string, challenge []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()

	ceremonyID, err = randomID()
	if err != nil {
		return "", nil, err
	}
	challenge = make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return "", nil, fmt.Errorf("services: generating webauthn challenge: %w", err)
	}

	s.ceremonies[ceremonyID] = &webauthnCeremony{
		userID:    userID,
		challenge: challenge,
		expires:   time.Now().Add(webauthnCeremonyTTL),
	}
	return ceremonyID, challenge, nil
}

// Redeem consumes ceremonyID unconditionally — success or failure of the
// signature check that follows, the ceremony can't be reused either way.
func (s *webauthnCeremonyStore) Redeem(ceremonyID string) (userID string, challenge []byte, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()

	c, exists := s.ceremonies[ceremonyID]
	delete(s.ceremonies, ceremonyID)
	if !exists || time.Now().After(c.expires) {
		return "", nil, false
	}
	return c.userID, c.challenge, true
}

func (s *webauthnCeremonyStore) sweepLocked() {
	now := time.Now()
	for k, c := range s.ceremonies {
		if now.After(c.expires) {
			delete(s.ceremonies, k)
		}
	}
}

func randomID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("services: generating id: %w", err)
	}
	return fmt.Sprintf("%x", b), nil
}
