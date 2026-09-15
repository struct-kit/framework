CREATE TABLE outbox_events (
    id            VARCHAR(255) PRIMARY KEY,
    event_name    VARCHAR(255) NOT NULL,
    aggregate_id  VARCHAR(255) NOT NULL,
    payload       TEXT NOT NULL,
    created_at    DATETIME(6) NOT NULL,
    dispatched    TINYINT(1) NOT NULL DEFAULT 0,
    dispatched_at DATETIME(6) NULL
);

CREATE INDEX outbox_events_dispatched_idx ON outbox_events (dispatched, created_at);
