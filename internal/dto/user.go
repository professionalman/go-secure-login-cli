package dto

import "time"

// User is the non-sensitive user representation returned by services.
type User struct {
	ID           string
	Username     string
	TOTPEnabled  bool
	RegisteredAt time.Time
}
