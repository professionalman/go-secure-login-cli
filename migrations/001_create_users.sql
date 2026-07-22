CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password_hash VARCHAR(60) NOT NULL,
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    totp_secret_encrypted VARCHAR(512),
    registered_at TIMESTAMPTZ NOT NULL,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (
        (totp_enabled = FALSE AND totp_secret_encrypted IS NULL)
        OR
        (totp_enabled = TRUE AND totp_secret_encrypted IS NOT NULL)
    )
);

CREATE UNIQUE INDEX idx_users_username ON users(username);
