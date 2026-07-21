package dto

// RegisterInput contains transient registration values. Callers must not log
// or persist Password or PasswordConfirmation.
type RegisterInput struct {
	Username             string
	Password             string
	PasswordConfirmation string
}
