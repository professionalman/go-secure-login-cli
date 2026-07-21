package sqlite

import (
	"context"
	"testing"
	"time"

	"auth-cli/internal/repository"

	"github.com/DATA-DOG/go-sqlmock"
)

const updateLoginFailureSQL = `
		UPDATE users
		SET failed_login_attempts = ?,
		    locked_until = ?,
		    updated_at = ?
		WHERE id = ?`

func TestUserRepositoryUpdatesLoginFailureStateWithSQLMock(t *testing.T) {
	ctx := context.Background()
	db, mock := newRepositoryMock(t)
	repo := NewUserRepository(db)
	now := time.Date(2026, time.July, 21, 22, 0, 0, 123, time.UTC)
	lockedUntil := now.Add(15 * time.Minute)

	mock.ExpectExec(updateLoginFailureSQL).
		WithArgs(5, formatTime(lockedUntil), formatTime(now), "u").
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repo.UpdateLoginFailureState(ctx, "u", 5, &lockedUntil, now); err != nil {
		t.Fatal(err)
	}

	afterExpiry := lockedUntil.Add(time.Nanosecond)
	mock.ExpectExec(updateLoginFailureSQL).
		WithArgs(1, nil, formatTime(afterExpiry), "u").
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repo.UpdateLoginFailureState(ctx, "u", 1, nil, afterExpiry); err != nil {
		t.Fatal(err)
	}

	mock.ExpectExec(updateLoginFailureSQL).
		WithArgs(1, nil, formatTime(afterExpiry), "missing").
		WillReturnResult(sqlmock.NewResult(0, 0))
	if err := repo.UpdateLoginFailureState(ctx, "missing", 1, nil, afterExpiry); err != repository.ErrNotFound {
		t.Fatalf("missing user error = %v", err)
	}
}
