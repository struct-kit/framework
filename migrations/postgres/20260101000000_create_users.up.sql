CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    locale        TEXT NOT NULL DEFAULT 'en',
    created_at    TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX users_email_key ON users (email);
