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

func TestUserRepositoryCreateAndFind(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	repo := NewUserRepository(db)
	now := time.Date(2026, time.July, 21, 10, 11, 12, 123, time.UTC)
	user := &domain.User{
		ID:           "user-1",
		Username:     "alice",
		PasswordHash: "$2a$04$not-a-plaintext-password-hash",
		RegisteredAt: now,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	byUsername, err := repo.FindByUsername(ctx, "alice")
	if err != nil {
		t.Fatalf("FindByUsername() error = %v", err)
	}
	if byUsername.ID != user.ID || byUsername.Username != user.Username || byUsername.PasswordHash != user.PasswordHash {
		t.Errorf("FindByUsername() = %#v, want core fields from %#v", byUsername, user)
	}
	if !byUsername.RegisteredAt.Equal(now) {
		t.Errorf("RegisteredAt = %v, want %v", byUsername.RegisteredAt, now)
	}

	byID, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if byID.Username != "alice" {
		t.Errorf("FindByID().Username = %q, want alice", byID.Username)
	}
}

func TestUserRepositoryErrors(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	repo := NewUserRepository(db)
	if _, err := repo.FindByUsername(ctx, "missing"); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindByUsername() error = %v, want ErrNotFound", err)
	}

	now := time.Now().UTC()
	first := &domain.User{ID: "1", Username: "alice", PasswordHash: "hash", RegisteredAt: now, CreatedAt: now, UpdatedAt: now}
	second := &domain.User{ID: "2", Username: "alice", PasswordHash: "other-hash", RegisteredAt: now, CreatedAt: now, UpdatedAt: now}
	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("first Create() error = %v", err)
	}
	if err := repo.Create(ctx, second); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("duplicate Create() error = %v, want ErrConflict", err)
	}
}
