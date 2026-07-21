CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    totp_enabled INTEGER NOT NULL DEFAULT 0 CHECK (totp_enabled IN (0, 1)),
    totp_secret_encrypted TEXT,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_login_attempts >= 0),
    locked_until TEXT,
    registered_at TEXT NOT NULL,
    last_login_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (
        (totp_enabled = 0 AND totp_secret_encrypted IS NULL)
        OR
        (totp_enabled = 1 AND totp_secret_encrypted IS NOT NULL)
    )
);

CREATE UNIQUE INDEX idx_users_username ON users(username);
