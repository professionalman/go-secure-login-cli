package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"auth-cli/internal/domain"
	"auth-cli/internal/repository"

	sqlitedriver "modernc.org/sqlite"
)

const (
	sqliteConstraintPrimaryKey = 1555
	sqliteConstraintUnique     = 2067
)

type rowScanner interface {
	Scan(dest ...any) error
}

// SQLiteUserRepository persists users with database/sql and SQLite.
type SQLiteUserRepository struct {
	db dbExecutor
}

func NewUserRepository(db *sql.DB) *SQLiteUserRepository {
	return newUserRepository(db)
}

func newUserRepository(db dbExecutor) *SQLiteUserRepository {
	return &SQLiteUserRepository{db: db}
}

func (r *SQLiteUserRepository) Create(ctx context.Context, user *domain.User) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO users (
			id, username, password_hash, totp_enabled, totp_secret_encrypted,
			failed_login_attempts, locked_until, registered_at, last_login_at,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		user.ID,
		user.Username,
		user.PasswordHash,
		boolAsInteger(user.TOTPEnabled),
		nullableString(user.TOTPSecretEncrypted),
		user.FailedLoginAttempts,
		nullableTime(user.LockedUntil),
		formatTime(user.RegisteredAt),
		nullableTime(user.LastLoginAt),
		formatTime(user.CreatedAt),
		formatTime(user.UpdatedAt),
	)
	if err == nil {
		return nil
	}
	if isUniqueConstraint(err) {
		return repository.ErrConflict
	}
	return fmt.Errorf("insert user: %w", err)
}

func (r *SQLiteUserRepository) FindByUsername(ctx context.Context, username string) (*domain.User, error) {
	return scanUser(r.db.QueryRowContext(ctx, userSelect+" WHERE username = ?", username))
}

func (r *SQLiteUserRepository) FindByID(ctx context.Context, userID string) (*domain.User, error) {
	return scanUser(r.db.QueryRowContext(ctx, userSelect+" WHERE id = ?", userID))
}

func (r *SQLiteUserRepository) ResetLoginSecurity(ctx context.Context, userID string, lastLoginAt time.Time) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE users
		SET failed_login_attempts = 0,
		    locked_until = NULL,
		    last_login_at = ?,
		    updated_at = ?
		WHERE id = ?`, formatTime(lastLoginAt), formatTime(lastLoginAt), userID)
	if err != nil {
		return fmt.Errorf("reset user login security: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read reset user count: %w", err)
	}
	if rows == 0 {
		return repository.ErrNotFound
	}
	return nil
}

const userSelect = `
	SELECT id, username, password_hash, totp_enabled, totp_secret_encrypted,
	       failed_login_attempts, locked_until, registered_at, last_login_at,
	       created_at, updated_at
	FROM users`

func scanUser(row rowScanner) (*domain.User, error) {
	var user domain.User
	var totpEnabled int
	var totpSecret sql.NullString
	var lockedUntil sql.NullString
	var registeredAt string
	var lastLoginAt sql.NullString
	var createdAt string
	var updatedAt string

	err := row.Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&totpEnabled,
		&totpSecret,
		&user.FailedLoginAttempts,
		&lockedUntil,
		&registeredAt,
		&lastLoginAt,
		&createdAt,
		&updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}

	user.TOTPEnabled = totpEnabled == 1
	if totpSecret.Valid {
		user.TOTPSecretEncrypted = &totpSecret.String
	}
	var parseErr error
	if user.RegisteredAt, parseErr = parseTime("registered_at", registeredAt); parseErr != nil {
		return nil, parseErr
	}
	if user.CreatedAt, parseErr = parseTime("created_at", createdAt); parseErr != nil {
		return nil, parseErr
	}
	if user.UpdatedAt, parseErr = parseTime("updated_at", updatedAt); parseErr != nil {
		return nil, parseErr
	}
	if user.LockedUntil, parseErr = parseNullableTime("locked_until", lockedUntil); parseErr != nil {
		return nil, parseErr
	}
	if user.LastLoginAt, parseErr = parseNullableTime("last_login_at", lastLoginAt); parseErr != nil {
		return nil, parseErr
	}
	return &user, nil
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return formatTime(*value)
}

func nullableString(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func parseTime(column, value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse %s: %w", column, err)
	}
	return parsed.UTC(), nil
}

func parseNullableTime(column string, value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	parsed, err := parseTime(column, value.String)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func boolAsInteger(value bool) int {
	if value {
		return 1
	}
	return 0
}

func isUniqueConstraint(err error) bool {
	var sqliteErr *sqlitedriver.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	code := sqliteErr.Code()
	return code == sqliteConstraintPrimaryKey || code == sqliteConstraintUnique
}
