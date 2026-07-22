package session

import (
	"context"

	"auth-cli/internal/dto"
)

type ISessionService interface {
	FinalizeLogin(ctx context.Context, userID string) (*dto.SessionResult, error)
	ValidateSession(ctx context.Context, rawToken string) (*dto.AuthenticatedUser, error)
	Logout(ctx context.Context, rawToken string) error
}
