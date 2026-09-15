package mysql

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"struct-framework/internal/platform/events"
	"struct-framework/internal/platform/store"
)

// OutboxPublisher mirrors postgres.OutboxPublisher exactly — see that
// type's doc comment for the transactional-outbox design.
type OutboxPublisher struct {
	db store.Driver
}

func NewOutboxPublisher(db store.Driver) *OutboxPublisher {
	return &OutboxPublisher{db: db}
}

func (p *OutboxPublisher) Publish(ctx context.Context, e events.Event) error {
	payloadJSON, err := json.Marshal(e.Payload)
	if err != nil {
		return fmt.Errorf("mysql: encoding event payload: %w", err)
	}
	occurredAt := e.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	_, err = p.db.Exec(ctx,
		`INSERT INTO outbox_events (id, event_name, aggregate_id, payload, created_at, dispatched)
		 VALUES (?, ?, ?, ?, ?, 0)`,
		e.ID, e.Name, e.AggregateID, string(payloadJSON), occurredAt,
	)
	return err
}

func (p *OutboxPublisher) FetchUndispatched(ctx context.Context, limit int) ([]events.OutboxRow, error) {
	rows, err := p.db.Query(ctx,
		`SELECT id, event_name, aggregate_id, payload, created_at
		 FROM outbox_events WHERE dispatched = 0 ORDER BY created_at LIMIT ?`, limit)
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
		`UPDATE outbox_events SET dispatched = 1, dispatched_at = ? WHERE id = ?`,
		time.Now().UTC(), id,
	)
	return err
}

var (
	_ events.Publisher    = (*OutboxPublisher)(nil)
	_ events.OutboxSource = (*OutboxPublisher)(nil)
)
