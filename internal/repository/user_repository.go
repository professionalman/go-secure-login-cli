package repository

import (
	"context"
	"time"

	"auth-cli/internal/domain"
)

// UserRepository is the persistence boundary used by authentication services.
type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	FindByUsername(ctx context.Context, username string) (*domain.User, error)
	FindByID(ctx context.Context, userID string) (*domain.User, error)
	UpdateLoginFailureState(ctx context.Context, userID string, failedAttempts int, lockedUntil *time.Time, updatedAt time.Time) error
	ResetLoginSecurity(ctx context.Context, userID string, lastLoginAt time.Time) error
}
