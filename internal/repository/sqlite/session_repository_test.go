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

func TestSessionRepositoryLifecycle(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	users := NewUserRepository(db)
	now := time.Date(2026, time.July, 21, 16, 0, 0, 0, time.UTC)
	if err := users.Create(ctx, &domain.User{
		ID: "user-1", Username: "alice", PasswordHash: "hash",
		RegisteredAt: now, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	sessions := NewSessionRepository(db)
	session := &domain.Session{
		ID: "session-1", UserID: "user-1", TokenHash: "hash-1",
		CreatedAt: now, ExpiresAt: now.Add(30 * time.Minute),
	}
	if err := sessions.Create(ctx, session); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	found, err := sessions.FindByTokenHash(ctx, "hash-1")
	if err != nil {
		t.Fatalf("FindByTokenHash() error = %v", err)
	}
	if found.ID != session.ID || !found.ExpiresAt.Equal(session.ExpiresAt) {
		t.Errorf("found session = %#v, want %#v", found, session)
	}

	revokedAt := now.Add(time.Minute)
	if err := sessions.Revoke(ctx, session.ID, revokedAt); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	found, err = sessions.FindByTokenHash(ctx, "hash-1")
	if err != nil {
		t.Fatal(err)
	}
	if found.RevokedAt == nil || !found.RevokedAt.Equal(revokedAt) {
		t.Errorf("RevokedAt = %v, want %v", found.RevokedAt, revokedAt)
	}
	if err := sessions.Revoke(ctx, session.ID, revokedAt); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("second Revoke() error = %v, want ErrNotFound", err)
	}
}

func TestSessionRepositoryDeleteExpired(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	users := NewUserRepository(db)
	if err := users.Create(ctx, &domain.User{ID: "u", Username: "alice", PasswordHash: "h", RegisteredAt: now, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	sessions := NewSessionRepository(db)
	if err := sessions.Create(ctx, &domain.Session{ID: "expired", UserID: "u", TokenHash: "expired", CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := sessions.DeleteExpired(ctx, now); err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.FindByTokenHash(ctx, "expired"); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("FindByTokenHash() error = %v, want ErrNotFound", err)
	}
}
