package repository

import (
	"context"

	"auth-cli/internal/domain"
)

// UserRepository is the persistence boundary used by authentication services.
// Login-security and TOTP update operations will be added with their vertical
// slices.
type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	FindByUsername(ctx context.Context, username string) (*domain.User, error)
	FindByID(ctx context.Context, userID string) (*domain.User, error)
}
