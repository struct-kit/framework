CREATE TABLE user_totp (
    user_id          VARCHAR(255) PRIMARY KEY,
    secret_encrypted VARCHAR(512) NOT NULL,
    confirmed        TINYINT(1) NOT NULL DEFAULT 0,
    created_at       DATETIME(6) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE user_backup_codes (
    id         VARCHAR(255) PRIMARY KEY,
    user_id    VARCHAR(255) NOT NULL,
    code_hash  VARCHAR(255) NOT NULL,
    used       TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME(6) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX user_backup_codes_user_id_idx ON user_backup_codes (user_id);
