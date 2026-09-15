package rpc

import (
	"errors"
	"sync"
	"time"
)

var ErrCircuitOpen = errors.New("rpc: circuit breaker is open")

// CircuitBreaker trips after a run of consecutive failures crosses
// failureThreshold, refusing further calls until cooldown has elapsed —
// then allows exactly one trial call through (half-open) before either
// closing again (on success) or re-opening (on failure).
type CircuitBreaker struct {
	mu               sync.Mutex
	failureThreshold int
	cooldown         time.Duration
	consecutiveFails int
	openUntil        time.Time
	halfOpen         bool
}

func NewCircuitBreaker(failureThreshold int, cooldown time.Duration) *CircuitBreaker {
	if failureThreshold <= 0 {
		failureThreshold = 5
	}
	return &CircuitBreaker{failureThreshold: failureThreshold, cooldown: cooldown}
}

// Allow reports whether a call should proceed right now.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.openUntil.IsZero() {
		return true
	}
	if time.Now().After(cb.openUntil) {
		// Half-open: let exactly one trial call through until RecordSuccess or
		// RecordFailure resolves the outcome.
		if !cb.halfOpen {
			cb.halfOpen = true
			return true
		}
		return false
	}
	return false
}

func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.consecutiveFails = 0
	cb.openUntil = time.Time{}
	cb.halfOpen = false
}

func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.consecutiveFails++
	if cb.halfOpen || cb.consecutiveFails >= cb.failureThreshold {
		cb.openUntil = time.Now().Add(cb.cooldown)
		cb.halfOpen = false
	}
}
