package session

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"auth-cli/internal/domain"
	"auth-cli/internal/repository"

	"github.com/jackc/pgx/v5/pgconn"
)

type IDBExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type PostgresRepository struct {
	db IDBExecutor
}

func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

func NewPostgresRepositoryWithExecutor(db IDBExecutor) *PostgresRepository {
	return &PostgresRepository{db: db}
}

func (r *PostgresRepository) Create(ctx context.Context, value *domain.Session) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		value.ID, value.UserID, value.TokenHash, value.CreatedAt.UTC(),
		value.ExpiresAt.UTC(), value.RevokedAt,
	)
	if isUniqueViolation(err) {
		return repository.ErrConflict
	}
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (r *PostgresRepository) FindByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	var value domain.Session
	var revokedAt sql.NullTime
	err := r.db.QueryRowContext(ctx, `
		SELECT id, user_id, token_hash, created_at, expires_at, revoked_at
		FROM sessions
		WHERE token_hash = $1`, tokenHash).Scan(
		&value.ID, &value.UserID, &value.TokenHash, &value.CreatedAt,
		&value.ExpiresAt, &revokedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan session: %w", err)
	}
	value.CreatedAt = value.CreatedAt.UTC()
	value.ExpiresAt = value.ExpiresAt.UTC()
	if revokedAt.Valid {
		at := revokedAt.Time.UTC()
		value.RevokedAt = &at
	}
	return &value, nil
}

func (r *PostgresRepository) Revoke(ctx context.Context, sessionID string, revokedAt time.Time) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE sessions SET revoked_at = $1
		WHERE id = $2 AND revoked_at IS NULL`, revokedAt.UTC(), sessionID)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read revoked session count: %w", err)
	}
	if rows == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *PostgresRepository) DeleteExpired(ctx context.Context, before time.Time) error {
	if _, err := r.db.ExecContext(ctx,
		"DELETE FROM sessions WHERE expires_at <= $1", before.UTC(),
	); err != nil {
		return fmt.Errorf("delete expired sessions: %w", err)
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
