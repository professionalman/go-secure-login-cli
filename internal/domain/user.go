package domain

import "time"

// User is the persisted authentication identity. PasswordHash and encrypted
// TOTP material must never be exposed through presentation DTOs.
type User struct {
	ID                  string
	Username            string
	PasswordHash        string
	TOTPEnabled         bool
	TOTPSecretEncrypted *string
	FailedLoginAttempts int
	LockedUntil         *time.Time
	RegisteredAt        time.Time
	LastLoginAt         *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}
