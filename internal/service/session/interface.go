package session

//go:generate go tool mockgen -source=interface.go -destination=mocks/mock_session.go -package=mocks

import (
	"context"

	"auth-cli/internal/dto"
)

type ISessionService interface {
	FinalizeLogin(ctx context.Context, userID string) (*dto.SessionResult, error)
	ValidateSession(ctx context.Context, rawToken string) (*dto.AuthenticatedUser, error)
	Logout(ctx context.Context, rawToken string) error
}
