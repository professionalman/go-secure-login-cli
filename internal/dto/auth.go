package dto

import "time"

// RegisterInput contains transient registration values. Callers must not log
// or persist Password or PasswordConfirmation.
type RegisterInput struct {
	Username             string
	Password             string
	PasswordConfirmation string
}

type LoginInput struct {
	Username string
	Password string
}

type LoginStatus string

const (
	LoginStatusAuthenticated LoginStatus = "authenticated"
	LoginStatusTOTPRequired  LoginStatus = "totp_required"
)

type LoginResult struct {
	Status            LoginStatus
	User              User
	RawSessionToken   string
	SessionExpiresAt  time.Time
	PreviousLastLogin *time.Time
}
