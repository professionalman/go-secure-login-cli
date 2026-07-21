package service

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"auth-cli/internal/database"
	"auth-cli/internal/domain"
	"auth-cli/internal/dto"
	sqliterepository "auth-cli/internal/repository/sqlite"
	"auth-cli/internal/security"
)

func TestCompletePasswordLoginResetsExpiredLockState(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, time.July, 22, 0, 0, 0, 0, time.UTC)
	expiredAtBoundary := now
	users := sqliterepository.NewUserRepository(db)
	sessions := sqliterepository.NewSessionRepository(db)
	if err := users.Create(ctx, &domain.User{
		ID: "user-1", Username: "alice", PasswordHash: "hashed:correct",
		FailedLoginAttempts: 5, LockedUntil: &expiredAtBoundary,
		RegisteredAt: now.Add(-time.Hour), CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	sessionService := NewSessionService(
		users,
		sessions,
		sqliterepository.NewUnitOfWork(db),
		fakeClock{now: now},
		func() string { return "session-1" },
		func() (string, string, error) { return "raw", security.HashSessionToken("raw"), nil },
		30*time.Minute,
	)
	auth := NewAuthService(
		users,
		fakeHasher{},
		fakeClock{now: now},
		func() string { return "unused" },
		RegistrationPolicy{},
		WithSessionService(sessionService),
		WithLoginSecurityPolicy(LoginSecurityPolicy{MaximumAttempts: 5, LockoutDuration: 15 * time.Minute}),
	)

	result, err := auth.LoginWithPassword(ctx, dto.LoginInput{Username: "alice", Password: "correct"})
	if err != nil {
		t.Fatalf("LoginWithPassword() error = %v", err)
	}
	if result.Status != dto.LoginStatusAuthenticated {
		t.Fatalf("status = %q, want %q", result.Status, dto.LoginStatusAuthenticated)
	}
	user, err := users.FindByID(ctx, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if user.FailedLoginAttempts != 0 || user.LockedUntil != nil || user.LastLoginAt == nil || !user.LastLoginAt.Equal(now) {
		t.Fatalf("complete login did not reset security state: %#v", user)
	}
}
