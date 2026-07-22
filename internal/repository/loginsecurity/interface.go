package loginsecurity

//go:generate go tool mockgen -source=interface.go -destination=mocks/mock_loginsecurity.go -package=mocks
//go:generate go tool mockgen -source=redis.go -destination=mocks/mock_redis_client.go -package=mocks

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
