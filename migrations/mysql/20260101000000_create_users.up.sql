CREATE TABLE users (
    id            VARCHAR(255) PRIMARY KEY,
    email         VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    locale        VARCHAR(16) NOT NULL DEFAULT 'en',
    created_at    DATETIME(6) NOT NULL,
    updated_at    DATETIME(6) NOT NULL
);

CREATE UNIQUE INDEX users_email_key ON users (email);
