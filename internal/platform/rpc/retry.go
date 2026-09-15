// Package rpc implements the framework guide's §6.4 resilience pattern
// for internal service-to-service calls: deadline propagation, bounded
// retries, a circuit breaker, a bulkhead, and client-side load
// balancing.
//
// Deviation from the framework guide: §6.4 specifies gRPC over
// protobuf. Building an actual gRPC-compatible client (HTTP/2 framing
// plus protobuf wire encoding) from scratch — with no `protoc` and no
// `grpc-go` available in this build environment — would be a second
// wire-protocol-scale undertaking on the order of the PostgreSQL/MySQL
// clients, attempted blind and unverified like they were. Rather than
// do that, this package implements the same resilience architecture
// over plain net/http and JSON, which is already proven in this
// codebase. Swapping the transport for real gRPC later touches only
// this package's Client.Call — callers depend on its typed signature,
// not the wire format underneath it.
package rpc

import (
	"context"
	"math/rand"
	"time"
)

// RetryPolicy configures bounded retries with exponential backoff and
// full jitter (a uniform random delay between 0 and the current backoff
// ceiling, not a fixed exponential value) — retried only for calls the
// caller marks idempotent (framework guide §6.4).
type RetryPolicy struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
}

func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{MaxAttempts: 3, BaseDelay: 100 * time.Millisecond, MaxDelay: 2 * time.Second}
}

func (p RetryPolicy) backoff(attempt int) time.Duration {
	ceiling := p.BaseDelay << uint(attempt)
	if ceiling <= 0 || ceiling > p.MaxDelay {
		ceiling = p.MaxDelay
	}
	if ceiling <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(ceiling) + 1))
}

// Do runs fn up to MaxAttempts times. fn reports whether a failure is
// worth retrying at all (a 4xx from the server, for instance, never is,
// regardless of how many attempts remain) — Do stops immediately on
// success or on a non-retryable error.
func (p RetryPolicy) Do(ctx context.Context, fn func(ctx context.Context) (retryable bool, err error)) error {
	var lastErr error
	attempts := p.MaxAttempts
	if attempts <= 0 {
		attempts = 1
	}
	for attempt := 0; attempt < attempts; attempt++ {
		retryable, err := fn(ctx)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retryable || attempt == attempts-1 {
			return lastErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(p.backoff(attempt)):
		}
	}
	return lastErr
}
