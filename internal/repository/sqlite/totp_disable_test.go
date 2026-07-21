package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"auth-cli/internal/repository"

	"github.com/DATA-DOG/go-sqlmock"
)

const disableTOTPSQL = `
		UPDATE users
		SET totp_enabled = 0,
		    totp_secret_encrypted = NULL,
		    updated_at = ?
		WHERE id = ? AND totp_enabled = 1`

func TestUserRepositoryDisablesTOTPAndClearsSecretAtomicallyWithSQLMock(t *testing.T) {
	ctx := context.Background()
	db, mock := newRepositoryMock(t)
	repo := NewUserRepository(db)
	now := time.Date(2026, time.July, 22, 14, 0, 0, 0, time.UTC)

	mock.ExpectExec(disableTOTPSQL).WithArgs(formatTime(now), "u").
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repo.DisableTOTP(ctx, "u", now); err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(disableTOTPSQL).WithArgs(formatTime(now.Add(time.Second)), "u").
		WillReturnResult(sqlmock.NewResult(0, 0))
	if err := repo.DisableTOTP(ctx, "u", now.Add(time.Second)); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("second DisableTOTP() error = %v, want ErrConflict", err)
	}
}
