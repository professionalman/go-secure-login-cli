package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"auth-cli/internal/database"
	"auth-cli/internal/domain"
	"auth-cli/internal/repository"
)

func TestUserRepositoryEnablesTOTPAtomically(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, time.July, 22, 4, 0, 0, 0, time.UTC)
	repo := NewUserRepository(db)
	if err := repo.Create(ctx, &domain.User{
		ID: "u", Username: "alice", PasswordHash: "hash",
		RegisteredAt: now.Add(-time.Hour), CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	if err := repo.EnableTOTP(ctx, "u", "encrypted-secret", now); err != nil {
		t.Fatal(err)
	}
	user, err := repo.FindByID(ctx, "u")
	if err != nil {
		t.Fatal(err)
	}
	if !user.TOTPEnabled || user.TOTPSecretEncrypted == nil || *user.TOTPSecretEncrypted != "encrypted-secret" || !user.UpdatedAt.Equal(now) {
		t.Fatalf("persisted TOTP state = %#v", user)
	}
	if err := repo.EnableTOTP(ctx, "u", "replacement", now.Add(time.Second)); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("second EnableTOTP() error = %v, want ErrConflict", err)
	}
}
