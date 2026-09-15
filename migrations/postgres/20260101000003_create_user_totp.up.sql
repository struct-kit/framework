CREATE TABLE user_totp (
    user_id          TEXT PRIMARY KEY REFERENCES users(id),
    secret_encrypted TEXT NOT NULL,
    confirmed        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMPTZ NOT NULL
);

CREATE TABLE user_backup_codes (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id),
    code_hash  TEXT NOT NULL,
    used       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX user_backup_codes_user_id_idx ON user_backup_codes (user_id);
