package service

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"auth-cli/internal/database"
	"auth-cli/internal/domain"
	sqliterepository "auth-cli/internal/repository/sqlite"
	"auth-cli/internal/security"
)

func TestFinalizeLoginRollsBackUserResetWhenSessionInsertFails(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, time.July, 21, 21, 0, 0, 0, time.UTC)
	users := sqliterepository.NewUserRepository(db)
	sessions := sqliterepository.NewSessionRepository(db)
	if err := users.Create(ctx, &domain.User{
		ID: "u", Username: "alice", PasswordHash: "hash", FailedLoginAttempts: 2,
		RegisteredAt: now.Add(-time.Hour), CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := sessions.Create(ctx, &domain.Session{
		ID: "duplicate-session", UserID: "u", TokenHash: "existing-hash",
		CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	service := NewSessionService(
		users,
		sessions,
		sqliterepository.NewUnitOfWork(db),
		&mutableClock{now: now},
		func() string { return "duplicate-session" },
		func() (string, string, error) { return "raw", security.HashSessionToken("raw"), nil },
		30*time.Minute,
	)
	if _, err := service.FinalizeLogin(ctx, "u"); err == nil {
		t.Fatal("FinalizeLogin() error = nil, want duplicate-session failure")
	}

	user, err := users.FindByID(ctx, "u")
	if err != nil {
		t.Fatal(err)
	}
	if user.FailedLoginAttempts != 2 || user.LastLoginAt != nil {
		t.Fatalf("user security state changed after rollback: %#v", user)
	}
}
