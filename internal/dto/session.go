package dto

import "time"

type SessionResult struct {
	RawToken          string
	ExpiresAt         time.Time
	User              User
	PreviousLastLogin *time.Time
}

type AuthenticatedUser struct {
	User      User
	ExpiresAt time.Time
}
