package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"auth-cli/internal/domain"
	"auth-cli/internal/repository"
)

type SQLiteSessionRepository struct {
	db dbExecutor
}

func NewSessionRepository(db *sql.DB) *SQLiteSessionRepository {
	return newSessionRepository(db)
}

func newSessionRepository(db dbExecutor) *SQLiteSessionRepository {
	return &SQLiteSessionRepository{db: db}
}

func (r *SQLiteSessionRepository) Create(ctx context.Context, session *domain.Session) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO sessions (
			id, user_id, token_hash, created_at, expires_at, revoked_at
		) VALUES (?, ?, ?, ?, ?, ?)`,
		session.ID,
		session.UserID,
		session.TokenHash,
		formatTime(session.CreatedAt),
		formatTime(session.ExpiresAt),
		nullableTime(session.RevokedAt),
	)
	if err == nil {
		return nil
	}
	if isUniqueConstraint(err) {
		return repository.ErrConflict
	}
	return fmt.Errorf("insert session: %w", err)
}

func (r *SQLiteSessionRepository) FindByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	var session domain.Session
	var createdAt string
	var expiresAt string
	var revokedAt sql.NullString
	err := r.db.QueryRowContext(ctx, `
		SELECT id, user_id, token_hash, created_at, expires_at, revoked_at
		FROM sessions
		WHERE token_hash = ?`, tokenHash).Scan(
		&session.ID,
		&session.UserID,
		&session.TokenHash,
		&createdAt,
		&expiresAt,
		&revokedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan session: %w", err)
	}
	if session.CreatedAt, err = parseTime("session created_at", createdAt); err != nil {
		return nil, err
	}
	if session.ExpiresAt, err = parseTime("session expires_at", expiresAt); err != nil {
		return nil, err
	}
	if session.RevokedAt, err = parseNullableTime("session revoked_at", revokedAt); err != nil {
		return nil, err
	}
	return &session, nil
}

func (r *SQLiteSessionRepository) Revoke(ctx context.Context, sessionID string, revokedAt time.Time) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE sessions
		SET revoked_at = ?
		WHERE id = ? AND revoked_at IS NULL`, formatTime(revokedAt), sessionID)
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

func (r *SQLiteSessionRepository) DeleteExpired(ctx context.Context, before time.Time) error {
	// RFC3339Nano omits trailing fractional zeros, so timestamps must be parsed
	// before comparison rather than compared as SQLite TEXT values.
	rows, err := r.db.QueryContext(ctx, "SELECT id, expires_at FROM sessions")
	if err != nil {
		return fmt.Errorf("list sessions for expiry cleanup: %w", err)
	}

	var expiredIDs []string
	for rows.Next() {
		var sessionID string
		var rawExpiry string
		if err := rows.Scan(&sessionID, &rawExpiry); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan session for expiry cleanup: %w", err)
		}
		expiresAt, err := parseTime("session expires_at", rawExpiry)
		if err != nil {
			_ = rows.Close()
			return err
		}
		if !expiresAt.After(before.UTC()) {
			expiredIDs = append(expiredIDs, sessionID)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate sessions for expiry cleanup: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close session expiry rows: %w", err)
	}

	for _, sessionID := range expiredIDs {
		if _, err := r.db.ExecContext(ctx, "DELETE FROM sessions WHERE id = ?", sessionID); err != nil {
			return fmt.Errorf("delete expired session: %w", err)
		}
	}
	return nil
}
