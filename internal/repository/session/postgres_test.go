package session_test

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"
	"time"

	"auth-cli/internal/domain"
	"auth-cli/internal/repository"
	sessionrepository "auth-cli/internal/repository/session"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestPostgresRepositoryCreateStoresTokenHash(t *testing.T) {
	db, mock, repo := newSessionRepository(t)
	now := time.Date(2026, 7, 22, 3, 0, 0, 0, time.UTC)
	value := &domain.Session{
		ID: "session-id", UserID: "user-id",
		TokenHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		CreatedAt: now, ExpiresAt: now.Add(30 * time.Minute),
	}

	mock.ExpectExec("INSERT INTO sessions").
		WithArgs(value.ID, value.UserID, value.TokenHash, value.CreatedAt, value.ExpiresAt, nil).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := repo.Create(context.Background(), value); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	assertSessionExpectations(t, mock)
	_ = db
}

func TestPostgresRepositoryCreateMapsUniqueViolation(t *testing.T) {
	_, mock, repo := newSessionRepository(t)
	now := time.Now().UTC()
	value := &domain.Session{
		ID: "session-id", UserID: "user-id", TokenHash: "hash",
		CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	mock.ExpectExec("INSERT INTO sessions").
		WillReturnError(&pgconn.PgError{Code: "23505"})

	err := repo.Create(context.Background(), value)
	if !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("Create() error = %v, want ErrConflict", err)
	}
	assertSessionExpectations(t, mock)
}

func TestPostgresRepositoryFindByTokenHash(t *testing.T) {
	_, mock, repo := newSessionRepository(t)
	now := time.Date(2026, 7, 22, 3, 0, 0, 0, time.UTC)
	hash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	query := regexp.QuoteMeta(`
		SELECT id, user_id, token_hash, created_at, expires_at, revoked_at
		FROM sessions
		WHERE token_hash = $1`)
	mock.ExpectQuery(query).
		WithArgs(hash).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "token_hash", "created_at", "expires_at", "revoked_at",
		}).AddRow("session-id", "user-id", hash, now, now.Add(30*time.Minute), nil))

	value, err := repo.FindByTokenHash(context.Background(), hash)
	if err != nil {
		t.Fatalf("FindByTokenHash() error = %v", err)
	}
	if value.TokenHash != hash || value.RevokedAt != nil {
		t.Fatalf("FindByTokenHash() = %#v", value)
	}
	assertSessionExpectations(t, mock)
}

func TestPostgresRepositoryFindByTokenHashMapsNoRows(t *testing.T) {
	_, mock, repo := newSessionRepository(t)
	mock.ExpectQuery("FROM sessions WHERE token_hash = \\$1").
		WithArgs("missing").
		WillReturnError(sql.ErrNoRows)

	_, err := repo.FindByTokenHash(context.Background(), "missing")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindByTokenHash() error = %v, want ErrNotFound", err)
	}
	assertSessionExpectations(t, mock)
}

func TestPostgresRepositoryRevokeRequiresAffectedRow(t *testing.T) {
	_, mock, repo := newSessionRepository(t)
	at := time.Now()
	mock.ExpectExec("UPDATE sessions SET revoked_at = \\$1 WHERE id = \\$2 AND revoked_at IS NULL").
		WithArgs(at.UTC(), "session-id").
		WillReturnResult(sqlmock.NewResult(0, 0))

	err := repo.Revoke(context.Background(), "session-id", at)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("Revoke() error = %v, want ErrNotFound", err)
	}
	assertSessionExpectations(t, mock)
}

func TestPostgresRepositoryDeleteExpiredUsesUTCTimestamp(t *testing.T) {
	_, mock, repo := newSessionRepository(t)
	before := time.Date(2026, 7, 22, 9, 0, 0, 0, time.FixedZone("IST", 5*60*60+30*60))
	mock.ExpectExec("DELETE FROM sessions WHERE expires_at <= \\$1").
		WithArgs(before.UTC()).
		WillReturnResult(sqlmock.NewResult(0, 2))

	if err := repo.DeleteExpired(context.Background(), before); err != nil {
		t.Fatalf("DeleteExpired() error = %v", err)
	}
	assertSessionExpectations(t, mock)
}

func newSessionRepository(t *testing.T) (*sql.DB, sqlmock.Sqlmock, *sessionrepository.PostgresRepository) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, mock, sessionrepository.NewPostgresRepository(db)
}

func assertSessionExpectations(t *testing.T, mock sqlmock.Sqlmock) {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}
