// Package analytics implements the framework guide's §8.4 event
// publisher: typed domain events sent to an async pipeline via a
// buffered, non-blocking publisher, so analytics never slows down the
// request path.
//
// Deviation from the framework guide: §8.4 imagines a Kafka or Redis
// Streams pipeline behind this. No broker client exists in this build
// environment (same gap as internal/platform/events' outbox relay and
// internal/platform/rpc's transport) — Sink is the seam a real one
// would plug into; LogSink is the only Sink shipped.
package analytics

import (
	"context"
	"log/slog"
	"time"
)

// Event is a typed analytics event — "UserRegistered", "OrderPlaced",
// and similar domain events fit this shape.
type Event struct {
	Name      string
	UserID    string
	Timestamp time.Time
	Props     map[string]any
}

// Sink is where a Publisher hands off events it accepted.
type Sink interface {
	Send(ctx context.Context, e Event) error
}

// LogSink logs each event and always succeeds — enough to prove the
// publish/drain loop works, not a production destination.
type LogSink struct {
	Logger *slog.Logger
}

func (s LogSink) Send(ctx context.Context, e Event) error {
	s.Logger.Info("analytics_event", "name", e.Name, "user_id", e.UserID, "props", e.Props)
	return nil
}

// DroppedEventsCounter is the one method Publisher needs to record a
// dropped event under backpressure — declared here, not imported from
// internal/platform/metrics, matching this codebase's "declare a local
// interface" pattern for cross-cutting dependencies.
type DroppedEventsCounter interface {
	Inc()
}

// Publisher buffers events in a fixed-size channel and forwards them to
// a Sink from a background goroutine. Track never blocks the caller —
// a full buffer drops the event rather than queuing indefinitely, with
// DroppedCounter (if set) incremented for visibility into how often
// that's happening.
type Publisher struct {
	events  chan Event
	sink    Sink
	logger  *slog.Logger
	dropped DroppedEventsCounter
}

type PublisherOption func(*Publisher)

func WithDroppedEventsCounter(c DroppedEventsCounter) PublisherOption {
	return func(p *Publisher) { p.dropped = c }
}

func NewPublisher(sink Sink, logger *slog.Logger, bufferSize int, opts ...PublisherOption) *Publisher {
	if bufferSize <= 0 {
		bufferSize = 1000
	}
	p := &Publisher{events: make(chan Event, bufferSize), sink: sink, logger: logger}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Track enqueues e without blocking.
func (p *Publisher) Track(e Event) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	select {
	case p.events <- e:
	default:
		if p.dropped != nil {
			p.dropped.Inc()
		}
		p.logger.Warn("analytics: event dropped (buffer full)", "name", e.Name)
	}
}

// Run drains the event buffer, forwarding each to Sink, until ctx is
// done. Call this once from a long-lived goroutine at startup.
func (p *Publisher) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-p.events:
			if err := p.sink.Send(ctx, e); err != nil {
				p.logger.Error("analytics: sink failed", "name", e.Name, "error", err)
			}
		}
	}
}
