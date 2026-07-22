package user

//go:generate go tool mockgen -source=interface.go -destination=mocks/mock_user.go -package=mocks

import (
	"context"
	"time"

	"auth-cli/internal/domain"
)

type IUserRepository interface {
	Create(ctx context.Context, value *domain.User) error
	FindByUsername(ctx context.Context, username string) (*domain.User, error)
	FindByID(ctx context.Context, userID string) (*domain.User, error)
	UpdateLastLogin(ctx context.Context, userID string, at time.Time) error
	EnableTOTP(ctx context.Context, userID, encryptedSecret string, updatedAt time.Time) error
	DisableTOTP(ctx context.Context, userID string, updatedAt time.Time) error
}
