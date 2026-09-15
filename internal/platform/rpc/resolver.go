package rpc

import (
	"context"
	"fmt"
	"sync/atomic"
)

// Resolver returns the currently-known base URLs for one logical
// service. StaticResolver is the only implementation this pass ships —
// a DNS-SRV-based resolver (framework guide §6.4) is a documented follow-
// up: testing one meaningfully needs a real DNS environment this sandbox
// doesn't have, and a resolver that's never been exercised against real
// DNS is exactly the kind of unverified code this project tries not to
// ship silently.
type Resolver interface {
	Resolve(ctx context.Context) ([]string, error)
}

// StaticResolver returns a fixed list of base URLs (e.g.
// "http://orders-service:8080") every time.
type StaticResolver struct {
	endpoints []string
}

func NewStaticResolver(endpoints ...string) *StaticResolver {
	return &StaticResolver{endpoints: endpoints}
}

func (r *StaticResolver) Resolve(ctx context.Context) ([]string, error) {
	if len(r.endpoints) == 0 {
		return nil, fmt.Errorf("rpc: static resolver has no endpoints configured")
	}
	return r.endpoints, nil
}

// roundRobin picks the next endpoint from a resolved list, in rotation —
// the client-side load-balancing piece of §6.4. It carries no health
// information of its own; a call to an endpoint that's actually down
// still counts against the circuit breaker and retry budget like any
// other failure.
type roundRobin struct {
	counter atomic.Uint64
}

func (rr *roundRobin) pick(endpoints []string) string {
	n := rr.counter.Add(1)
	return endpoints[(n-1)%uint64(len(endpoints))]
}
