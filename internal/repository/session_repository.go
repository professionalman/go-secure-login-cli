package repository

import (
	"context"
	"time"

	"auth-cli/internal/domain"
)

type SessionRepository interface {
	Create(ctx context.Context, session *domain.Session) error
	FindByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error)
	Revoke(ctx context.Context, sessionID string, revokedAt time.Time) error
	DeleteExpired(ctx context.Context, before time.Time) error
}
