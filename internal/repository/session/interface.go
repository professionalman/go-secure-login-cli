package session

import (
	"context"
	"time"

	"auth-cli/internal/domain"
)

type ISessionRepository interface {
	Create(ctx context.Context, value *domain.Session) error
	FindByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error)
	Revoke(ctx context.Context, sessionID string, revokedAt time.Time) error
	DeleteExpired(ctx context.Context, before time.Time) error
}
