package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"auth-cli/internal/database"
	"auth-cli/internal/domain"
	"auth-cli/internal/repository"
	sqliterepository "auth-cli/internal/repository/sqlite"
	"auth-cli/internal/security"
)

type mutableClock struct{ now time.Time }

func (m *mutableClock) Now() time.Time { return m.now }

func TestSessionServiceFinalizeValidateAndLogout(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	users := sqliterepository.NewUserRepository(db)
	sessions := sqliterepository.NewSessionRepository(db)
	uow := sqliterepository.NewUnitOfWork(db)
	now := time.Date(2026, time.July, 21, 17, 0, 0, 0, time.UTC)
	previous := now.Add(-24 * time.Hour)
	if err := users.Create(ctx, &domain.User{
		ID: "user-1", Username: "alice", PasswordHash: "hash",
		FailedLoginAttempts: 3, LockedUntil: pointerTo(now.Add(time.Hour)),
		LastLoginAt: &previous, RegisteredAt: previous.Add(-time.Hour), CreatedAt: previous, UpdatedAt: previous,
	}); err != nil {
		t.Fatal(err)
	}

	serviceClock := &mutableClock{now: now}
	service := NewSessionService(
		users, sessions, uow, serviceClock,
		func() string { return "session-1" },
		func() (string, string, error) { return "raw-token", security.HashSessionToken("raw-token"), nil },
		30*time.Minute,
	)
	result, err := service.FinalizeLogin(ctx, "user-1")
	if err != nil {
		t.Fatalf("FinalizeLogin() error = %v", err)
	}
	if result.RawToken != "raw-token" || !result.ExpiresAt.Equal(now.Add(30*time.Minute)) {
		t.Errorf("session result = %#v", result)
	}
	if result.PreviousLastLogin == nil || !result.PreviousLastLogin.Equal(previous) {
		t.Errorf("PreviousLastLogin = %v, want %v", result.PreviousLastLogin, previous)
	}
	var storedHash string
	if err := db.QueryRowContext(ctx, "SELECT token_hash FROM sessions WHERE id = ?", "session-1").Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if storedHash == result.RawToken || storedHash != security.HashSessionToken(result.RawToken) {
		t.Errorf("stored token value = %q, raw = %q", storedHash, result.RawToken)
	}
	updated, err := users.FindByID(ctx, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if updated.FailedLoginAttempts != 0 || updated.LockedUntil != nil || updated.LastLoginAt == nil || !updated.LastLoginAt.Equal(now) {
		t.Errorf("login security was not reset atomically: %#v", updated)
	}

	authenticated, err := service.ValidateSession(ctx, "raw-token")
	if err != nil || authenticated.User.Username != "alice" {
		t.Fatalf("ValidateSession() = %#v, %v", authenticated, err)
	}
	if err := service.Logout(ctx, "raw-token"); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if _, err := service.ValidateSession(ctx, "raw-token"); !errors.Is(err, domain.ErrSessionRevoked) {
		t.Fatalf("ValidateSession() after logout error = %v, want ErrSessionRevoked", err)
	}
}

func TestSessionServiceExpirationAndUnknownToken(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	users := sqliterepository.NewUserRepository(db)
	sessions := sqliterepository.NewSessionRepository(db)
	uow := sqliterepository.NewUnitOfWork(db)
	now := time.Now().UTC()
	if err := users.Create(ctx, &domain.User{ID: "u", Username: "alice", PasswordHash: "h", RegisteredAt: now, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	serviceClock := &mutableClock{now: now}
	service := NewSessionService(users, sessions, uow, serviceClock, func() string { return "s" }, func() (string, string, error) {
		return "raw", security.HashSessionToken("raw"), nil
	}, time.Minute)
	if _, err := service.FinalizeLogin(ctx, "u"); err != nil {
		t.Fatal(err)
	}
	serviceClock.now = now.Add(time.Minute)
	if _, err := service.ValidateSession(ctx, "raw"); !errors.Is(err, domain.ErrSessionExpired) {
		t.Errorf("expired ValidateSession() error = %v", err)
	}
	if _, err := service.ValidateSession(ctx, "missing"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("unknown ValidateSession() error = %v", err)
	}
}

func TestUnitOfWorkRollsBackLoginWrites(t *testing.T) {
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
	users := sqliterepository.NewUserRepository(db)
	if err := users.Create(ctx, &domain.User{ID: "u", Username: "alice", PasswordHash: "h", FailedLoginAttempts: 2, RegisteredAt: now, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	uow := sqliterepository.NewUnitOfWork(db)
	sentinel := errors.New("session insert failed")
	err = uow.WithinTransaction(ctx, func(txUsers repository.UserRepository, _ repository.SessionRepository) error {
		if err := txUsers.ResetLoginSecurity(ctx, "u", now.Add(time.Minute)); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("WithinTransaction() error = %v", err)
	}
	user, err := users.FindByID(ctx, "u")
	if err != nil {
		t.Fatal(err)
	}
	if user.FailedLoginAttempts != 2 || user.LastLoginAt != nil {
		t.Errorf("transaction changes were not rolled back: %#v", user)
	}
}

func pointerTo(value time.Time) *time.Time { return &value }
