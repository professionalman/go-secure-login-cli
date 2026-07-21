package security

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string, cost int) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

func VerifyPassword(passwordHash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
}

// BcryptPasswordHasher adapts the password utility to service boundaries.
type BcryptPasswordHasher struct {
	Cost int
}

func (h BcryptPasswordHasher) Hash(password string) (string, error) {
	return HashPassword(password, h.Cost)
}

func (h BcryptPasswordHasher) Verify(passwordHash, password string) error {
	return VerifyPassword(passwordHash, password)
}
