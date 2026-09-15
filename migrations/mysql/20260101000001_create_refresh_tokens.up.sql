CREATE TABLE refresh_tokens (
    id         VARCHAR(255) PRIMARY KEY,
    user_id    VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    family_id  VARCHAR(255) NOT NULL,
    revoked    TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE UNIQUE INDEX refresh_tokens_token_hash_key ON refresh_tokens (token_hash);
CREATE INDEX refresh_tokens_family_id_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_user_id_idx ON refresh_tokens (user_id);
