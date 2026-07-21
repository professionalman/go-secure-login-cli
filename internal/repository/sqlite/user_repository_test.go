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

const insertUserSQL = `
		INSERT INTO users (
			id, username, password_hash, totp_enabled, totp_secret_encrypted,
			failed_login_attempts, locked_until, registered_at, last_login_at,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

var userColumns = []string{
	"id", "username", "password_hash", "totp_enabled", "totp_secret_encrypted",
	"failed_login_attempts", "locked_until", "registered_at", "last_login_at", "created_at", "updated_at",
}

func TestUserRepositoryCreateAndFindWithSQLMock(t *testing.T) {
	ctx := context.Background()
	db, mock := newRepositoryMock(t)
	repo := NewUserRepository(db)
	now := time.Date(2026, time.July, 21, 10, 11, 12, 123, time.UTC)
	user := &domain.User{
		ID: "user-1", Username: "alice", PasswordHash: "bcrypt-hash",
		RegisteredAt: now, CreatedAt: now, UpdatedAt: now,
	}

	mock.ExpectExec(insertUserSQL).
		WithArgs("user-1", "alice", "bcrypt-hash", 0, nil, 0, nil, formatTime(now), nil, formatTime(now), formatTime(now)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	mock.ExpectQuery(userSelect + " WHERE username = ?").WithArgs("alice").
		WillReturnRows(sqlmock.NewRows(userColumns).AddRow(
			"user-1", "alice", "bcrypt-hash", 0, nil, 0, nil,
			formatTime(now), nil, formatTime(now), formatTime(now),
		))
	byUsername, err := repo.FindByUsername(ctx, "alice")
	if err != nil {
		t.Fatalf("FindByUsername() error = %v", err)
	}
	if byUsername.ID != user.ID || byUsername.Username != user.Username || !byUsername.RegisteredAt.Equal(now) {
		t.Fatalf("FindByUsername() = %#v", byUsername)
	}

	mock.ExpectQuery(userSelect + " WHERE id = ?").WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows(userColumns).AddRow(
			"user-1", "alice", "bcrypt-hash", 0, nil, 0, nil,
			formatTime(now), nil, formatTime(now), formatTime(now),
		))
	byID, err := repo.FindByID(ctx, "user-1")
	if err != nil || byID.Username != "alice" {
		t.Fatalf("FindByID() = %#v, %v", byID, err)
	}
}

func TestUserRepositoryMapsNotFoundConflictAndDatabaseErrors(t *testing.T) {
	ctx := context.Background()
	db, mock := newRepositoryMock(t)
	repo := NewUserRepository(db)

	mock.ExpectQuery(userSelect + " WHERE username = ?").WithArgs("missing").WillReturnError(sql.ErrNoRows)
	if _, err := repo.FindByUsername(ctx, "missing"); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindByUsername() error = %v, want ErrNotFound", err)
	}

	now := time.Now().UTC()
	user := &domain.User{ID: "2", Username: "alice", PasswordHash: "hash", RegisteredAt: now, CreatedAt: now, UpdatedAt: now}
	mock.ExpectExec(insertUserSQL).
		WithArgs("2", "alice", "hash", 0, nil, 0, nil, formatTime(now), nil, formatTime(now), formatTime(now)).
		WillReturnError(mockSQLiteError{code: sqliteConstraintUnique})
	if err := repo.Create(ctx, user); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("Create() conflict error = %v", err)
	}

	mock.ExpectQuery(userSelect + " WHERE id = ?").WithArgs("broken").WillReturnError(errors.New("database unavailable"))
	if _, err := repo.FindByID(ctx, "broken"); err == nil || errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindByID() database error = %v", err)
	}
}
