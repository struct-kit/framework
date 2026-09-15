package events

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"
)

// OutboxRow is the dialect-neutral shape a store-backed Publisher's
// FetchUndispatched returns. Unlike, say, postgres.UserRow (which must
// be a separate type per dialect because internal/mvc/models is
// off-limits to internal/platform), this package IS the shared type both
// dialects can return directly — internal/platform/store/postgres and
// .../mysql importing internal/platform/events is platform-to-platform,
// which the framework guide's layering rule (§2) never restricts.
type OutboxRow struct {
	ID          string
	EventName   string
	AggregateID string
	Payload     string // JSON-encoded
	CreatedAt   time.Time
}

// OutboxSource is what the relay polls. Both dialects' OutboxPublisher
// implement this alongside Publisher — the same table backs both
// reading (for the relay) and writing (for business code publishing an
// event inside its own transaction).
type OutboxSource interface {
	FetchUndispatched(ctx context.Context, limit int) ([]OutboxRow, error)
	MarkDispatched(ctx context.Context, id string) error
}

// Sink is where the relay hands off an undispatched event — the
// boundary a real broker client (Kafka, Redis Streams) would plug into.
// This package has no broker client of its own; wiring one in is its
// own wire-protocol-scale undertaking, out of scope for this pass (see
// PLAN.md's Pass 6 scope note). LogSink is the only Sink shipped —
// enough to prove the relay loop itself works, not a production
// destination.
type Sink interface {
	Send(ctx context.Context, e Event) error
}

// LogSink logs each event it receives and always succeeds — a
// placeholder that makes the relay loop observable without a real
// broker behind it.
type LogSink struct {
	Logger *slog.Logger
}

func (s LogSink) Send(ctx context.Context, e Event) error {
	s.Logger.Info("outbox_event_dispatched", "event_id", e.ID, "name", e.Name, "aggregate_id", e.AggregateID)
	return nil
}

// Relay polls an OutboxSource on an interval and hands each undispatched
// row to a Sink, marking it dispatched only once the Sink accepts it. A
// failed Send leaves the row undispatched for the next poll — at-least-
// once delivery, which is exactly why framework guide §6.5 requires
// downstream consumers to be idempotent (they may see the same event
// more than once).
type Relay struct {
	source OutboxSource
	sink   Sink
	logger *slog.Logger
}

func NewRelay(source OutboxSource, sink Sink, logger *slog.Logger) *Relay {
	return &Relay{source: source, sink: sink, logger: logger}
}

// Run polls source every interval until ctx is done.
func (r *Relay) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.pollOnce(ctx)
		}
	}
}

// PollOnce runs a single poll-and-dispatch pass — exported so `struct
// relay --once` and tests can trigger exactly one pass without waiting
// on a ticker.
func (r *Relay) PollOnce(ctx context.Context) {
	r.pollOnce(ctx)
}

func (r *Relay) pollOnce(ctx context.Context) {
	rows, err := r.source.FetchUndispatched(ctx, 100)
	if err != nil {
		r.logger.Error("outbox relay: fetch failed", "error", err)
		return
	}

	for _, row := range rows {
		e := Event{ID: row.ID, Name: row.EventName, AggregateID: row.AggregateID, OccurredAt: row.CreatedAt}
		if row.Payload != "" {
			if err := json.Unmarshal([]byte(row.Payload), &e.Payload); err != nil {
				r.logger.Error("outbox relay: decoding payload failed", "event_id", row.ID, "error", err)
				continue
			}
		}

		if err := r.sink.Send(ctx, e); err != nil {
			r.logger.Error("outbox relay: sink failed", "event_id", row.ID, "error", err)
			continue
		}
		if err := r.source.MarkDispatched(ctx, row.ID); err != nil {
			r.logger.Error("outbox relay: marking dispatched failed", "event_id", row.ID, "error", err)
		}
	}
}
