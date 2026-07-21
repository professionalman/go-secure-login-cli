package sqlite

import (
	"context"
	"fmt"
	"time"

	"auth-cli/internal/repository"
)

func (r *SQLiteUserRepository) DisableTOTP(ctx context.Context, userID string, updatedAt time.Time) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE users
		SET totp_enabled = 0,
		    totp_secret_encrypted = NULL,
		    updated_at = ?
		WHERE id = ? AND totp_enabled = 1`, formatTime(updatedAt), userID)
	if err != nil {
		return fmt.Errorf("disable user TOTP: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read disabled TOTP user count: %w", err)
	}
	if rows == 0 {
		return repository.ErrConflict
	}
	return nil
}
