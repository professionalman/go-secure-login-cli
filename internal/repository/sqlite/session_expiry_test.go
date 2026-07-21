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

func TestDeleteExpiredHandlesNanosecondBoundary(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	exactSecond := time.Date(2026, time.July, 21, 20, 0, 0, 0, time.UTC)
	users := NewUserRepository(db)
	if err := users.Create(ctx, &domain.User{
		ID: "u", Username: "alice", PasswordHash: "hash",
		RegisteredAt: exactSecond, CreatedAt: exactSecond, UpdatedAt: exactSecond,
	}); err != nil {
		t.Fatal(err)
	}
	sessions := NewSessionRepository(db)
	if err := sessions.Create(ctx, &domain.Session{
		ID: "s", UserID: "u", TokenHash: "hash",
		CreatedAt: exactSecond.Add(-time.Minute), ExpiresAt: exactSecond,
	}); err != nil {
		t.Fatal(err)
	}

	if err := sessions.DeleteExpired(ctx, exactSecond.Add(-time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.FindByTokenHash(ctx, "hash"); err != nil {
		t.Fatalf("session deleted before its exact expiry: %v", err)
	}

	if err := sessions.DeleteExpired(ctx, exactSecond.Add(time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.FindByTokenHash(ctx, "hash"); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindByTokenHash() error = %v, want ErrNotFound", err)
	}
}
