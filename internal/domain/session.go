package domain

import "time"

// Session is the persisted representation. TokenHash is stored instead of the
// raw bearer token held by the running CLI.
type Session struct {
	ID        string
	UserID    string
	TokenHash string
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}
