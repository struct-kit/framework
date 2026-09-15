package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"struct-framework/internal/platform/events"
	"struct-framework/internal/platform/store"
)

// OutboxPublisher implements events.Publisher by writing to the outbox
// table through whatever store.Driver it's given — pass it a store.Tx
// mid-transaction to get the actual transactional-outbox guarantee
// (framework guide §6.5): the event row commits or rolls back together
// with the business change it describes, in the same statement batch,
// so the two can never diverge. Pass the top-level Pool instead for a
// non-transactional publish (still durable, just not atomic with
// anything else).
//
// It also implements events.OutboxSource (FetchUndispatched/
// MarkDispatched) — the same table backs both roles: business code
// writes rows here, and internal/platform/events.Relay reads them back
// out for dispatch to a real Sink.
type OutboxPublisher struct {
	db store.Driver
}

func NewOutboxPublisher(db store.Driver) *OutboxPublisher {
	return &OutboxPublisher{db: db}
}

func (p *OutboxPublisher) Publish(ctx context.Context, e events.Event) error {
	payloadJSON, err := json.Marshal(e.Payload)
	if err != nil {
		return fmt.Errorf("postgres: encoding event payload: %w", err)
	}
	occurredAt := e.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	_, err = p.db.Exec(ctx,
		`INSERT INTO outbox_events (id, event_name, aggregate_id, payload, created_at, dispatched)
		 VALUES ($1, $2, $3, $4, $5, false)`,
		e.ID, e.Name, e.AggregateID, string(payloadJSON), occurredAt,
	)
	return err
}

func (p *OutboxPublisher) FetchUndispatched(ctx context.Context, limit int) ([]events.OutboxRow, error) {
	rows, err := p.db.Query(ctx,
		`SELECT id, event_name, aggregate_id, payload, created_at
		 FROM outbox_events WHERE dispatched = false ORDER BY created_at LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []events.OutboxRow
	for rows.Next() {
		var r events.OutboxRow
		if err := rows.Scan(&r.ID, &r.EventName, &r.AggregateID, &r.Payload, &r.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

func (p *OutboxPublisher) MarkDispatched(ctx context.Context, id string) error {
	_, err := p.db.Exec(ctx,
		`UPDATE outbox_events SET dispatched = true, dispatched_at = $1 WHERE id = $2`,
		time.Now().UTC(), id,
	)
	return err
}

// Compile-time checks that OutboxPublisher actually satisfies both
// roles it's documented to play — catches an interface-signature
// mismatch here, at build time, rather than as a runtime surprise when
// something tries to use it as one or the other.
var (
	_ events.Publisher    = (*OutboxPublisher)(nil)
	_ events.OutboxSource = (*OutboxPublisher)(nil)
)
