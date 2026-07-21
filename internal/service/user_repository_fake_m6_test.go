package service

import (
	"context"
	"time"

	"auth-cli/internal/repository"
)

func (f *fakeUserRepository) DisableTOTP(_ context.Context, userID string, updatedAt time.Time) error {
	for _, user := range f.users {
		if user.ID != userID {
			continue
		}
		if !user.TOTPEnabled {
			return repository.ErrConflict
		}
		user.TOTPEnabled = false
		user.TOTPSecretEncrypted = nil
		user.UpdatedAt = updatedAt
		return nil
	}
	return repository.ErrNotFound
}
