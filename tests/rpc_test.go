package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"struct-framework/internal/platform/rpc"
)

func TestRPC_CircuitBreaker_TripsAndHalfOpens(t *testing.T) {
	cooldown := 50 * time.Millisecond
	cb := rpc.NewCircuitBreaker(3, cooldown)

	if !cb.Allow() {
		t.Fatal("expected newly initialized circuit breaker to allow calls")
	}

	cb.RecordFailure()
	cb.RecordFailure()
	if !cb.Allow() {
		t.Fatal("expected circuit breaker to still allow calls after 2 failures")
	}

	cb.RecordFailure()
	if cb.Allow() {
		t.Fatal("expected circuit breaker to trip open after 3 failures")
	}

	time.Sleep(cooldown + 10*time.Millisecond)

	if !cb.Allow() {
		t.Fatal("expected circuit breaker to allow one trial call after cooldown")
	}
	if cb.Allow() {
		t.Fatal("expected trial call in-flight to prevent other calls")
	}

	cb.RecordSuccess()
	if !cb.Allow() {
		t.Fatal("expected circuit breaker to close and allow calls after trial success")
	}
}

func TestRPC_Bulkhead_LimitsConcurrency(t *testing.T) {
	bh := rpc.NewBulkhead(2)

	ctx := context.Background()
	rel1, err := bh.Acquire(ctx)
	if err != nil {
		t.Fatalf("unexpected error acquiring slot 1: %v", err)
	}
	defer rel1()

	rel2, err := bh.Acquire(ctx)
	if err != nil {
		t.Fatalf("unexpected error acquiring slot 2: %v", err)
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()

	_, err = bh.Acquire(timeoutCtx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected DeadlineExceeded when bulkhead is saturated, got %v", err)
	}

	rel2()

	rel3, err := bh.Acquire(ctx)
	if err != nil {
		t.Fatalf("unexpected error acquiring after release: %v", err)
	}
	rel3()
}

func TestRPC_RetryPolicy(t *testing.T) {
	policy := rpc.RetryPolicy{
		MaxAttempts: 4,
		BaseDelay:   5 * time.Millisecond,
		MaxDelay:    20 * time.Millisecond,
	}

	attempts := 0
	err := policy.Do(context.Background(), func(ctx context.Context) (bool, error) {
		attempts++
		if attempts < 3 {
			return true, errors.New("transient error")
		}
		return false, nil
	})

	if err != nil {
		t.Fatalf("unexpected error from RetryPolicy: %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts until success, got %d", attempts)
	}
}

func TestRPC_StaticResolver(t *testing.T) {
	res := rpc.NewStaticResolver("http://srv1:8080", "http://srv2:8080")
	eps, err := res.Resolve(context.Background())
	if err != nil {
		t.Fatalf("unexpected resolve error: %v", err)
	}
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(eps))
	}
}
