package security

//go:generate go tool mockgen -source=password.go -destination=mocks/mock_password.go -package=mocks

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

type IPasswordManager interface {
	Hash(password string) (string, error)
	Verify(passwordHash, password string) error
}

// BcryptPasswordManager provides hashing and verification through one contract.
type BcryptPasswordManager struct {
	Cost int
}

func (h BcryptPasswordManager) Hash(password string) (string, error) {
	return HashPassword(password, h.Cost)
}

func (h BcryptPasswordManager) Verify(passwordHash, password string) error {
	return VerifyPassword(passwordHash, password)
}
