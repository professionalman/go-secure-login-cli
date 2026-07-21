package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"auth-cli/internal/repository"

	"github.com/DATA-DOG/go-sqlmock"
)

const enableTOTPSQL = `
		UPDATE users
		SET totp_enabled = 1,
		    totp_secret_encrypted = ?,
		    updated_at = ?
		WHERE id = ? AND totp_enabled = 0`

func TestUserRepositoryEnablesTOTPAtomicallyWithSQLMock(t *testing.T) {
	ctx := context.Background()
	db, mock := newRepositoryMock(t)
	repo := NewUserRepository(db)
	now := time.Date(2026, time.July, 22, 4, 0, 0, 0, time.UTC)

	mock.ExpectExec(enableTOTPSQL).WithArgs("encrypted-secret", formatTime(now), "u").
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repo.EnableTOTP(ctx, "u", "encrypted-secret", now); err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(enableTOTPSQL).WithArgs("replacement", formatTime(now.Add(time.Second)), "u").
		WillReturnResult(sqlmock.NewResult(0, 0))
	if err := repo.EnableTOTP(ctx, "u", "replacement", now.Add(time.Second)); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("second EnableTOTP() error = %v, want ErrConflict", err)
	}
}
