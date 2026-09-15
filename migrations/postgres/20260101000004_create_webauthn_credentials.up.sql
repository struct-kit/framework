CREATE TABLE webauthn_credentials (
    credential_id TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id),
    public_key_x  TEXT NOT NULL,
    public_key_y  TEXT NOT NULL,
    sign_count    BIGINT NOT NULL DEFAULT 0,
    name          TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX webauthn_credentials_user_id_idx ON webauthn_credentials (user_id);
