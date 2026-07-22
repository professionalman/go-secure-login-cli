package loginsecurity

import (
	"context"
	"time"
)

type ILoginSecurityRepository interface {
	IsBlocked(ctx context.Context, userID string) (bool, error)
	RecordFailure(
		ctx context.Context,
		userID string,
		maximumAttempts int,
		blockDuration time.Duration,
	) (bool, error)
	Reset(ctx context.Context, userID string) error
}
