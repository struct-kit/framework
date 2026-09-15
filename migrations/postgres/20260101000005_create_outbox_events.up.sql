CREATE TABLE outbox_events (
    id            TEXT PRIMARY KEY,
    event_name    TEXT NOT NULL,
    aggregate_id  TEXT NOT NULL,
    payload       TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    dispatched    BOOLEAN NOT NULL DEFAULT FALSE,
    dispatched_at TIMESTAMPTZ
);

CREATE INDEX outbox_events_undispatched_idx ON outbox_events (created_at) WHERE dispatched = false;
