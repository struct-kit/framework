// Package events defines the domain event contract used by
// `struct make event NAME` (framework guide §6.5).
//
// This is the foundational type only — the transactional outbox (writing
// the event in the same DB transaction as the business change it
// describes) and the broker relay are Pass 6 work, once the store layer
// (Pass 3) exists to host the outbox table. Generated event files compile
// and are usable standalone today; Publish here is an in-memory stand-in
// that Pass 6 replaces without changing the Event type or generated
// call sites.
package events

import (
	"context"
	"time"
)

// Event is the envelope every domain event is wrapped in. Name should be
// versioned (e.g. "OrderPlacedV1") per §6.5 — payloads may only ever gain
// optional fields within a version.
type Event struct {
	ID          string
	Name        string
	AggregateID string
	OccurredAt  time.Time
	Payload     any
}

// Publisher is the contract generated event files publish through. The
// in-memory implementation below exists so generated code has something
// real to call before Pass 6's outbox-backed implementation lands.
type Publisher interface {
	Publish(ctx context.Context, e Event) error
}

// InMemoryPublisher is a placeholder Publisher: it logs nothing and drops
// nothing — it simply invokes a registered handler synchronously, useful
// for unit tests and for local development before a broker exists. It is
// NOT the transactional outbox described in §6.5 and must not be used in
// production once Pass 6 lands.
type InMemoryPublisher struct {
	handlers map[string][]func(context.Context, Event) error
}

func NewInMemoryPublisher() *InMemoryPublisher {
	return &InMemoryPublisher{handlers: make(map[string][]func(context.Context, Event) error)}
}

func (p *InMemoryPublisher) Subscribe(eventName string, handler func(context.Context, Event) error) {
	p.handlers[eventName] = append(p.handlers[eventName], handler)
}

func (p *InMemoryPublisher) Publish(ctx context.Context, e Event) error {
	for _, h := range p.handlers[e.Name] {
		if err := h(ctx, e); err != nil {
			return err
		}
	}
	return nil
}
