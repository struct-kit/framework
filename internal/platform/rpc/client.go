package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"struct-framework/internal/platform/http/middleware"
	"struct-framework/internal/platform/tracing"
)

// deadlineSafetyMargin is shaved off the caller's remaining context
// deadline before it's forwarded downstream (framework guide §6.4:
// "shrunk by a safety margin") — a callee should never still be working
// after the caller itself would have already given up and moved on.
const deadlineSafetyMargin = 50 * time.Millisecond

// Client is a resilient JSON-over-HTTP client for internal
// service-to-service calls — see this package's doc comment for why
// it's JSON-over-HTTP rather than real gRPC.
type Client struct {
	httpClient *http.Client
	resolver   Resolver
	breaker    *CircuitBreaker
	bulkhead   *Bulkhead
	retry      RetryPolicy
	rr         roundRobin
}

type ClientOption func(*Client)

func WithRetryPolicy(p RetryPolicy) ClientOption         { return func(c *Client) { c.retry = p } }
func WithCircuitBreaker(cb *CircuitBreaker) ClientOption { return func(c *Client) { c.breaker = cb } }
func WithBulkhead(b *Bulkhead) ClientOption              { return func(c *Client) { c.bulkhead = b } }
func WithHTTPClient(h *http.Client) ClientOption         { return func(c *Client) { c.httpClient = h } }

// defaultTransport tunes connection reuse for the common case this
// client is built for: repeated calls to a small, fixed set of internal
// services, not one-off calls to arbitrary hosts. Go's zero-value
// http.Transport (what a bare &http.Client{} gets) already reuses
// connections, but its defaults (100 total idle connections, 2 idle
// connections per host) are sized for a client fanning out to many
// different hosts — the opposite of this package's actual workload.
// Raising MaxIdleConnsPerHost so it can actually hold onto a connection
// per concurrent in-flight call to the same service (bounded by this
// package's own Bulkhead, so it can't grow unbounded) avoids paying a
// fresh TCP (and, if TLS is added later, handshake) cost on every retry
// or burst of concurrent calls to the same endpoint.
func defaultTransport() *http.Transport {
	return &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
	}
}

// NewClient builds a Client with sane defaults — a 5-consecutive-failure/
// 30s-cooldown circuit breaker, a 50-concurrent-call bulkhead, and
// DefaultRetryPolicy — all overridable via options.
func NewClient(resolver Resolver, opts ...ClientOption) *Client {
	c := &Client{
		httpClient: &http.Client{Transport: defaultTransport()},
		resolver:   resolver,
		breaker:    NewCircuitBreaker(5, 30*time.Second),
		bulkhead:   NewBulkhead(50),
		retry:      DefaultRetryPolicy(),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Call performs one JSON-over-HTTP request/response round trip against
// path on a resolved endpoint of this Client's service, decoding the
// response into resp (pass nil for either req or resp if the call has no
// body in that direction).
//
// idempotent controls whether a transient failure (a network error, or
// any 5xx status) is retried per this Client's RetryPolicy — a 4xx is
// never retried regardless, since retrying a client error just repeats
// the same mistake. Only mark a call idempotent once you've confirmed
// it's genuinely safe to run more than once (framework guide §6.4:
// "retried only for methods marked idempotent").
func (c *Client) Call(ctx context.Context, method, path string, req, resp any, idempotent bool) error {
	ctx, cancel := withSafetyMargin(ctx, deadlineSafetyMargin)
	defer cancel()

	release, err := c.bulkhead.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("rpc: bulkhead: %w", err)
	}
	defer release()

	if !c.breaker.Allow() {
		return ErrCircuitOpen
	}

	var bodyBytes []byte
	if req != nil {
		bodyBytes, err = json.Marshal(req)
		if err != nil {
			return fmt.Errorf("rpc: encoding request: %w", err)
		}
	}

	err = c.retry.Do(ctx, func(ctx context.Context) (bool, error) {
		return c.doOnce(ctx, method, path, bodyBytes, resp, idempotent)
	})
	if err != nil {
		c.breaker.RecordFailure()
		return err
	}
	c.breaker.RecordSuccess()
	return nil
}

func (c *Client) doOnce(ctx context.Context, method, path string, bodyBytes []byte, resp any, idempotent bool) (retryable bool, err error) {
	endpoints, err := c.resolver.Resolve(ctx)
	if err != nil {
		return false, fmt.Errorf("rpc: resolving endpoints: %w", err)
	}
	base := c.rr.pick(endpoints)

	httpReq, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return false, fmt.Errorf("rpc: building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json; charset=utf-8")
	if reqID := middleware.RequestIDFrom(ctx); reqID != "" {
		httpReq.Header.Set(middleware.RequestIDHeader, reqID)
	}
	if span, ok := tracing.SpanFromContext(ctx); ok {
		tc := tracing.TraceContext{TraceID: span.TraceID, SpanID: span.SpanID, Sampled: true}
		httpReq.Header.Set("traceparent", tc.String())
	}

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		// A network-level failure (connection refused, timeout, DNS
		// failure) is always worth retrying if the caller marked the
		// call idempotent — it says nothing about whether the request
		// was even received, let alone acted on.
		return idempotent, fmt.Errorf("rpc: request to %s failed: %w", base, err)
	}
	defer httpResp.Body.Close()

	switch {
	case httpResp.StatusCode >= 500:
		return idempotent, fmt.Errorf("rpc: %s returned status %d", base, httpResp.StatusCode)
	case httpResp.StatusCode >= 400:
		return false, fmt.Errorf("rpc: %s returned status %d", base, httpResp.StatusCode)
	}

	if resp != nil {
		if err := json.NewDecoder(httpResp.Body).Decode(resp); err != nil {
			return false, fmt.Errorf("rpc: decoding response from %s: %w", base, err)
		}
	}
	return false, nil
}

func withSafetyMargin(ctx context.Context, margin time.Duration) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, deadline.Add(-margin))
}
