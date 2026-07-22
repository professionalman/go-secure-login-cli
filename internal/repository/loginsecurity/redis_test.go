package loginsecurity_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"auth-cli/internal/repository/loginsecurity"
	loginsecuritymocks "auth-cli/internal/repository/loginsecurity/mocks"

	"github.com/redis/go-redis/v9"
	"go.uber.org/mock/gomock"
)

func TestRedisRepositoryIsBlocked(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := loginsecuritymocks.NewMockIRedisClient(ctrl)
	repo := loginsecurity.NewRedisRepository(client)
	ctx := context.Background()

	client.EXPECT().
		Exists(ctx, "auth-cli:login:user-id:blocked").
		Return(redis.NewIntResult(1, nil))

	blocked, err := repo.IsBlocked(ctx, "user-id")
	if err != nil {
		t.Fatalf("IsBlocked() error = %v", err)
	}
	if !blocked {
		t.Fatal("IsBlocked() = false, want true")
	}
}

func TestRedisRepositoryRecordFailure(t *testing.T) {
	tests := []struct {
		name       string
		scriptFlag int64
		wantLocked bool
	}{
		{name: "below threshold", scriptFlag: 0, wantLocked: false},
		{name: "threshold reached", scriptFlag: 1, wantLocked: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			client := loginsecuritymocks.NewMockIRedisClient(ctrl)
			repo := loginsecurity.NewRedisRepository(client)
			ctx := context.Background()
			duration := 15 * time.Minute

			client.EXPECT().
				Eval(
					ctx,
					gomock.Any(),
					[]string{
						"auth-cli:login:user-id:failures",
						"auth-cli:login:user-id:blocked",
					},
					5,
					duration.Milliseconds(),
				).
				Return(redis.NewCmdResult(test.scriptFlag, nil))

			blocked, err := repo.RecordFailure(ctx, "user-id", 5, duration)
			if err != nil {
				t.Fatalf("RecordFailure() error = %v", err)
			}
			if blocked != test.wantLocked {
				t.Fatalf("RecordFailure() blocked = %v, want %v", blocked, test.wantLocked)
			}
		})
	}
}

func TestRedisRepositoryResetDeletesBothKeys(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := loginsecuritymocks.NewMockIRedisClient(ctrl)
	repo := loginsecurity.NewRedisRepository(client)
	ctx := context.Background()

	client.EXPECT().
		Del(
			ctx,
			"auth-cli:login:user-id:failures",
			"auth-cli:login:user-id:blocked",
		).
		Return(redis.NewIntResult(2, nil))

	if err := repo.Reset(ctx, "user-id"); err != nil {
		t.Fatalf("Reset() error = %v", err)
	}
}

func TestRedisRepositoryFailsClosedOnClientError(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := loginsecuritymocks.NewMockIRedisClient(ctrl)
	repo := loginsecurity.NewRedisRepository(client)
	ctx := context.Background()
	clientError := errors.New("redis unavailable")

	client.EXPECT().
		Exists(ctx, "auth-cli:login:user-id:blocked").
		Return(redis.NewIntResult(0, clientError))

	blocked, err := repo.IsBlocked(ctx, "user-id")
	if err == nil || blocked {
		t.Fatalf("IsBlocked() = (%v, %v), want (false, error)", blocked, err)
	}
}
