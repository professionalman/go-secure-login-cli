package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"auth-cli/internal/database"
	"auth-cli/internal/domain"
)

func TestUserRepositoryUpdatesLoginFailureState(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, time.July, 21, 22, 0, 0, 123, time.UTC)
	repo := NewUserRepository(db)
	if err := repo.Create(ctx, &domain.User{
		ID: "u", Username: "alice", PasswordHash: "hash",
		RegisteredAt: now.Add(-time.Hour), CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	lockedUntil := now.Add(15 * time.Minute)
	if err := repo.UpdateLoginFailureState(ctx, "u", 5, &lockedUntil, now); err != nil {
		t.Fatal(err)
	}
	user, err := repo.FindByID(ctx, "u")
	if err != nil {
		t.Fatal(err)
	}
	if user.FailedLoginAttempts != 5 || user.LockedUntil == nil || !user.LockedUntil.Equal(lockedUntil) || !user.UpdatedAt.Equal(now) {
		t.Fatalf("persisted lockout state = %#v", user)
	}

	afterExpiry := lockedUntil.Add(time.Nanosecond)
	if err := repo.UpdateLoginFailureState(ctx, "u", 1, nil, afterExpiry); err != nil {
		t.Fatal(err)
	}
	user, err = repo.FindByID(ctx, "u")
	if err != nil {
		t.Fatal(err)
	}
	if user.FailedLoginAttempts != 1 || user.LockedUntil != nil || !user.UpdatedAt.Equal(afterExpiry) {
		t.Fatalf("persisted post-expiry state = %#v", user)
	}
}
