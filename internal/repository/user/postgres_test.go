package user_test

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"
	"time"

	"auth-cli/internal/domain"
	"auth-cli/internal/repository"
	userrepository "auth-cli/internal/repository/user"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestPostgresRepositoryCreate(t *testing.T) {
	_, mock, repo := newUserRepository(t)
	now := time.Date(2026, 7, 22, 8, 30, 0, 123, time.FixedZone("IST", 5*60*60+30*60))
	value := &domain.User{
		ID: "user-id", Username: "kavya", PasswordHash: "$2a$12$hash",
		RegisteredAt: now, CreatedAt: now, UpdatedAt: now,
	}

	mock.ExpectExec("INSERT INTO users").
		WithArgs(
			value.ID, value.Username, value.PasswordHash, false, nil,
			now.UTC(), nil, now.UTC(), now.UTC(),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := repo.Create(context.Background(), value); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	assertUserExpectations(t, mock)
}

func TestPostgresRepositoryCreateMapsUniqueViolation(t *testing.T) {
	_, mock, repo := newUserRepository(t)
	now := time.Now().UTC()
	value := &domain.User{
		ID: "user-id", Username: "kavya", PasswordHash: "$2a$12$hash",
		RegisteredAt: now, CreatedAt: now, UpdatedAt: now,
	}

	mock.ExpectExec("INSERT INTO users").
		WillReturnError(&pgconn.PgError{Code: "23505"})

	err := repo.Create(context.Background(), value)
	if !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("Create() error = %v, want ErrConflict", err)
	}
	assertUserExpectations(t, mock)
}

func TestPostgresRepositoryFindByUsername(t *testing.T) {
	_, mock, repo := newUserRepository(t)
	now := time.Date(2026, 7, 22, 3, 0, 0, 0, time.UTC)
	query := regexp.QuoteMeta(`
		SELECT id, username, password_hash, totp_enabled, totp_secret_encrypted,
		       registered_at, last_login_at, created_at, updated_at
		FROM users WHERE username = $1`)
	mock.ExpectQuery(query).
		WithArgs("kavya").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "username", "password_hash", "totp_enabled",
			"totp_secret_encrypted", "registered_at", "last_login_at",
			"created_at", "updated_at",
		}).AddRow("user-id", "kavya", "$2a$12$hash", false, nil, now, nil, now, now))

	value, err := repo.FindByUsername(context.Background(), "kavya")
	if err != nil {
		t.Fatalf("FindByUsername() error = %v", err)
	}
	if value.ID != "user-id" || value.Username != "kavya" {
		t.Fatalf("FindByUsername() = %#v", value)
	}
	if value.TOTPSecretEncrypted != nil || value.LastLoginAt != nil {
		t.Fatalf("nullable fields were not preserved: %#v", value)
	}
	assertUserExpectations(t, mock)
}

func TestPostgresRepositoryFindByIDMapsNoRows(t *testing.T) {
	_, mock, repo := newUserRepository(t)
	mock.ExpectQuery("FROM users WHERE id = \\$1").
		WithArgs("missing").
		WillReturnError(sql.ErrNoRows)

	_, err := repo.FindByID(context.Background(), "missing")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindByID() error = %v, want ErrNotFound", err)
	}
	assertUserExpectations(t, mock)
}

func TestPostgresRepositoryUpdateLastLoginRequiresAffectedRow(t *testing.T) {
	_, mock, repo := newUserRepository(t)
	at := time.Date(2026, 7, 22, 9, 0, 0, 0, time.FixedZone("IST", 5*60*60+30*60))
	mock.ExpectExec("UPDATE users SET last_login_at = \\$1, updated_at = \\$1 WHERE id = \\$2").
		WithArgs(at.UTC(), "missing").
		WillReturnResult(sqlmock.NewResult(0, 0))

	err := repo.UpdateLastLogin(context.Background(), "missing", at)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("UpdateLastLogin() error = %v, want ErrNotFound", err)
	}
	assertUserExpectations(t, mock)
}

func TestPostgresRepositoryEnableTOTPMapsUnchangedUserToConflict(t *testing.T) {
	_, mock, repo := newUserRepository(t)
	at := time.Now()
	mock.ExpectExec("UPDATE users SET totp_enabled = TRUE").
		WithArgs("encrypted-secret", at.UTC(), "user-id").
		WillReturnResult(sqlmock.NewResult(0, 0))

	err := repo.EnableTOTP(context.Background(), "user-id", "encrypted-secret", at)
	if !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("EnableTOTP() error = %v, want ErrConflict", err)
	}
	assertUserExpectations(t, mock)
}

func newUserRepository(t *testing.T) (*sql.DB, sqlmock.Sqlmock, *userrepository.PostgresRepository) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, mock, userrepository.NewPostgresRepository(db)
}

func assertUserExpectations(t *testing.T, mock sqlmock.Sqlmock) {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}
