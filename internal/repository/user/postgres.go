package user

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

type IRowScanner interface {
	Scan(dest ...any) error
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

func (r *PostgresRepository) Create(ctx context.Context, value *domain.User) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO users (
			id, username, password_hash, totp_enabled, totp_secret_encrypted,
			registered_at, last_login_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		value.ID, value.Username, value.PasswordHash, value.TOTPEnabled,
		value.TOTPSecretEncrypted, value.RegisteredAt.UTC(), value.LastLoginAt,
		value.CreatedAt.UTC(), value.UpdatedAt.UTC(),
	)
	if isUniqueViolation(err) {
		return repository.ErrConflict
	}
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

func (r *PostgresRepository) FindByUsername(ctx context.Context, username string) (*domain.User, error) {
	return scanUser(r.db.QueryRowContext(ctx, userSelect+" WHERE username = $1", username))
}

func (r *PostgresRepository) FindByID(ctx context.Context, userID string) (*domain.User, error) {
	return scanUser(r.db.QueryRowContext(ctx, userSelect+" WHERE id = $1", userID))
}

func (r *PostgresRepository) UpdateLastLogin(ctx context.Context, userID string, at time.Time) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE users
		SET last_login_at = $1, updated_at = $1
		WHERE id = $2`, at.UTC(), userID)
	if err != nil {
		return fmt.Errorf("update last login: %w", err)
	}
	return requireAffected(result)
}

func (r *PostgresRepository) EnableTOTP(ctx context.Context, userID, encryptedSecret string, updatedAt time.Time) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE users
		SET totp_enabled = TRUE, totp_secret_encrypted = $1, updated_at = $2
		WHERE id = $3 AND totp_enabled = FALSE`, encryptedSecret, updatedAt.UTC(), userID)
	if err != nil {
		return fmt.Errorf("enable user TOTP: %w", err)
	}
	if err := requireAffected(result); errors.Is(err, repository.ErrNotFound) {
		return repository.ErrConflict
	} else {
		return err
	}
}

func (r *PostgresRepository) DisableTOTP(ctx context.Context, userID string, updatedAt time.Time) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE users
		SET totp_enabled = FALSE, totp_secret_encrypted = NULL, updated_at = $1
		WHERE id = $2 AND totp_enabled = TRUE`, updatedAt.UTC(), userID)
	if err != nil {
		return fmt.Errorf("disable user TOTP: %w", err)
	}
	if err := requireAffected(result); errors.Is(err, repository.ErrNotFound) {
		return repository.ErrConflict
	} else {
		return err
	}
}

const userSelect = `
	SELECT id, username, password_hash, totp_enabled, totp_secret_encrypted,
	       registered_at, last_login_at, created_at, updated_at
	FROM users`

func scanUser(row IRowScanner) (*domain.User, error) {
	var value domain.User
	var secret sql.NullString
	var lastLogin sql.NullTime
	err := row.Scan(
		&value.ID, &value.Username, &value.PasswordHash, &value.TOTPEnabled,
		&secret, &value.RegisteredAt, &lastLogin, &value.CreatedAt, &value.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}
	if secret.Valid {
		value.TOTPSecretEncrypted = &secret.String
	}
	if lastLogin.Valid {
		at := lastLogin.Time.UTC()
		value.LastLoginAt = &at
	}
	value.RegisteredAt = value.RegisteredAt.UTC()
	value.CreatedAt = value.CreatedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
	return &value, nil
}

func requireAffected(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read affected rows: %w", err)
	}
	if rows == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
