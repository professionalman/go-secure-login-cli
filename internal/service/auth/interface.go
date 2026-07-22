package auth

//go:generate go tool mockgen -source=interface.go -destination=mocks/mock_auth.go -package=mocks

import (
	"context"

	"auth-cli/internal/dto"
)

type IAuthService interface {
	Register(ctx context.Context, input dto.RegisterInput) (*dto.User, error)
	LoginWithPassword(ctx context.Context, input dto.LoginInput) (*dto.LoginResult, error)
	CompleteTOTPLogin(ctx context.Context, challengeID, code string) (*dto.LoginResult, error)
	CancelTOTPLogin(challengeID string)
	ClearTOTPLoginChallenges()
}
