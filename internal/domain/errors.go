package domain

import "errors"

var (
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidUsername    = errors.New("invalid username")
	ErrInvalidPassword    = errors.New("invalid password")
	ErrPasswordMismatch   = errors.New("password confirmation does not match")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked      = errors.New("account locked")
	ErrInvalidTOTP        = errors.New("invalid TOTP")
	ErrTOTPAlreadyEnabled = errors.New("TOTP already enabled")
	ErrTOTPNotEnabled     = errors.New("TOTP not enabled")
	ErrTOTPSetupNotFound  = errors.New("TOTP setup not found")
	ErrTOTPSetupExpired   = errors.New("TOTP setup expired")
	ErrSessionExpired     = errors.New("session expired")
	ErrSessionRevoked     = errors.New("session revoked")
	ErrUnauthorized       = errors.New("authentication required")
)
