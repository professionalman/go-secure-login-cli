package loginsecurity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const keyPrefix = "auth-cli:login:"

const recordFailureScript = `
if redis.call("EXISTS", KEYS[2]) == 1 then
	return 1
end
local attempts = redis.call("INCR", KEYS[1])
if attempts >= tonumber(ARGV[1]) then
	redis.call("DEL", KEYS[1])
	redis.call("PSETEX", KEYS[2], ARGV[2], "1")
	return 1
end
return 0
`

type IRedisClient interface {
	Exists(ctx context.Context, keys ...string) *redis.IntCmd
	Eval(ctx context.Context, script string, keys []string, args ...any) *redis.Cmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
	Ping(ctx context.Context) *redis.StatusCmd
	Close() error
}

type RedisRepository struct {
	client IRedisClient
}

func Open(ctx context.Context, redisURL string) (*redis.Client, error) {
	if strings.TrimSpace(redisURL) == "" {
		return nil, fmt.Errorf("Redis URL is required")
	}
	options, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse Redis URL: %w", err)
	}
	client := redis.NewClient(options)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("connect to Redis: %w", err)
	}
	return client, nil
}

func NewRedisRepository(client IRedisClient) *RedisRepository {
	return &RedisRepository{client: client}
}

func (r *RedisRepository) IsBlocked(ctx context.Context, userID string) (bool, error) {
	count, err := r.client.Exists(ctx, blockedKey(userID)).Result()
	if err != nil {
		return false, fmt.Errorf("check login block: %w", err)
	}
	return count > 0, nil
}

func (r *RedisRepository) RecordFailure(
	ctx context.Context,
	userID string,
	maximumAttempts int,
	blockDuration time.Duration,
) (bool, error) {
	result, err := r.client.Eval(
		ctx,
		recordFailureScript,
		[]string{failuresKey(userID), blockedKey(userID)},
		maximumAttempts,
		blockDuration.Milliseconds(),
	).Int64()
	if err != nil {
		return false, fmt.Errorf("record login failure: %w", err)
	}
	return result == 1, nil
}

func (r *RedisRepository) Reset(ctx context.Context, userID string) error {
	if err := r.client.Del(ctx, failuresKey(userID), blockedKey(userID)).Err(); err != nil {
		return fmt.Errorf("reset login security: %w", err)
	}
	return nil
}

func failuresKey(userID string) string {
	return keyPrefix + userID + ":failures"
}

func blockedKey(userID string) string {
	return keyPrefix + userID + ":blocked"
}
