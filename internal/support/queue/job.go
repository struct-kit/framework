// Package queue defines the background job contract used by
// `struct make job NAME` (framework guide §11). A real Redis Streams/SQS
// adapter is later work; this package's Job interface and RetryPolicy are
// stable enough to write real jobs against today, run in-process via
// InProcessRunner until a durable queue backend lands.
package queue

import (
	"context"
	"fmt"
	"time"
)

// Job is the contract every generated job (`struct make job NAME`)
// implements.
type Job interface {
	Name() string
	Run(ctx context.Context) error
}

// RetryPolicy configures exponential backoff with a capped attempt count —
// generated jobs get a sane default; tune per job as needed.
type RetryPolicy struct {
	MaxAttempts int
	BackoffBase time.Duration
}

func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{MaxAttempts: 5, BackoffBase: 500 * time.Millisecond}
}

// InProcessRunner executes a Job with retries, in the current process. It
// is a development/single-instance stand-in for a durable queue worker —
// a job that fails after MaxAttempts is returned as an error, not
// persisted anywhere for later inspection.
func InProcessRunner(ctx context.Context, job Job, policy RetryPolicy) error {
	var lastErr error
	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		if err := job.Run(ctx); err != nil {
			lastErr = err
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(policy.BackoffBase * time.Duration(attempt)):
			}
			continue
		}
		return nil
	}
	return fmt.Errorf("queue: job %q failed after %d attempts: %w", job.Name(), policy.MaxAttempts, lastErr)
}
