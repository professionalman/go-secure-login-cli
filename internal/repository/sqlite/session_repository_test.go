package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"auth-cli/internal/domain"
	"auth-cli/internal/repository"

	"github.com/DATA-DOG/go-sqlmock"
)

const (
	insertSessionSQL = `
		INSERT INTO sessions (
			id, user_id, token_hash, created_at, expires_at, revoked_at
		) VALUES (?, ?, ?, ?, ?, ?)`
	findSessionSQL = `
		SELECT id, user_id, token_hash, created_at, expires_at, revoked_at
		FROM sessions
		WHERE token_hash = ?`
	revokeSessionSQL = `
		UPDATE sessions
		SET revoked_at = ?
		WHERE id = ? AND revoked_at IS NULL`
)

var sessionColumns = []string{"id", "user_id", "token_hash", "created_at", "expires_at", "revoked_at"}

func TestSessionRepositoryLifecycleWithSQLMock(t *testing.T) {
	ctx := context.Background()
	db, mock := newRepositoryMock(t)
	repo := NewSessionRepository(db)
	now := time.Date(2026, time.July, 21, 16, 0, 0, 0, time.UTC)
	session := &domain.Session{
		ID: "session-1", UserID: "user-1", TokenHash: "hash-1",
		CreatedAt: now, ExpiresAt: now.Add(30 * time.Minute),
	}

	mock.ExpectExec(insertSessionSQL).
		WithArgs(session.ID, session.UserID, session.TokenHash, formatTime(session.CreatedAt), formatTime(session.ExpiresAt), nil).
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := repo.Create(ctx, session); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	mock.ExpectQuery(findSessionSQL).WithArgs("hash-1").WillReturnRows(
		sqlmock.NewRows(sessionColumns).AddRow(
			"session-1", "user-1", "hash-1", formatTime(now), formatTime(session.ExpiresAt), nil,
		),
	)
	found, err := repo.FindByTokenHash(ctx, "hash-1")
	if err != nil || found.ID != session.ID || !found.ExpiresAt.Equal(session.ExpiresAt) {
		t.Fatalf("FindByTokenHash() = %#v, %v", found, err)
	}

	revokedAt := now.Add(time.Minute)
	mock.ExpectExec(revokeSessionSQL).WithArgs(formatTime(revokedAt), session.ID).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repo.Revoke(ctx, session.ID, revokedAt); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	mock.ExpectExec(revokeSessionSQL).WithArgs(formatTime(revokedAt), session.ID).WillReturnResult(sqlmock.NewResult(0, 0))
	if err := repo.Revoke(ctx, session.ID, revokedAt); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("second Revoke() error = %v", err)
	}
}

func TestSessionRepositoryMapsNotFoundAndConflictWithSQLMock(t *testing.T) {
	ctx := context.Background()
	db, mock := newRepositoryMock(t)
	repo := NewSessionRepository(db)
	mock.ExpectQuery(findSessionSQL).WithArgs("missing").WillReturnError(sql.ErrNoRows)
	if _, err := repo.FindByTokenHash(ctx, "missing"); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindByTokenHash() error = %v", err)
	}
	now := time.Now().UTC()
	session := &domain.Session{ID: "duplicate", UserID: "u", TokenHash: "hash", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	mock.ExpectExec(insertSessionSQL).
		WithArgs(session.ID, session.UserID, session.TokenHash, formatTime(now), formatTime(session.ExpiresAt), nil).
		WillReturnError(mockSQLiteError{code: sqliteConstraintPrimaryKey})
	if err := repo.Create(ctx, session); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("Create() conflict error = %v", err)
	}
}

func TestSessionRepositoryDeleteExpiredWithSQLMock(t *testing.T) {
	ctx := context.Background()
	db, mock := newRepositoryMock(t)
	repo := NewSessionRepository(db)
	now := time.Date(2026, time.July, 21, 20, 0, 0, 0, time.UTC)
	mock.ExpectQuery("SELECT id, expires_at FROM sessions").WillReturnRows(
		sqlmock.NewRows([]string{"id", "expires_at"}).
			AddRow("before", formatTime(now.Add(-time.Nanosecond))).
			AddRow("exact", formatTime(now)).
			AddRow("after", formatTime(now.Add(time.Nanosecond))),
	)
	mock.ExpectExec("DELETE FROM sessions WHERE id = ?").WithArgs("before").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM sessions WHERE id = ?").WithArgs("exact").WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repo.DeleteExpired(ctx, now); err != nil {
		t.Fatalf("DeleteExpired() error = %v", err)
	}
}
