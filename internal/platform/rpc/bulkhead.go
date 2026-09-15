package rpc

import "context"

// Bulkhead limits how many concurrent calls one dependency can have in
// flight, so one slow downstream can't exhaust the caller's own
// goroutine/connection budget (framework guide §6.4).
type Bulkhead struct {
	sem chan struct{}
}

func NewBulkhead(maxConcurrent int) *Bulkhead {
	if maxConcurrent <= 0 {
		maxConcurrent = 50
	}
	return &Bulkhead{sem: make(chan struct{}, maxConcurrent)}
}

// Acquire blocks until a slot is free or ctx is done, returning a
// release function the caller must call exactly once when the call
// completes.
func (b *Bulkhead) Acquire(ctx context.Context) (release func(), err error) {
	select {
	case b.sem <- struct{}{}:
		return func() { <-b.sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
