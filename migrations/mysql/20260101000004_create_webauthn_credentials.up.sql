CREATE TABLE webauthn_credentials (
    credential_id VARCHAR(512) PRIMARY KEY,
    user_id       VARCHAR(255) NOT NULL,
    public_key_x  VARCHAR(255) NOT NULL,
    public_key_y  VARCHAR(255) NOT NULL,
    sign_count    BIGINT NOT NULL DEFAULT 0,
    name          VARCHAR(255) NOT NULL DEFAULT '',
    created_at    DATETIME(6) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX webauthn_credentials_user_id_idx ON webauthn_credentials (user_id);
