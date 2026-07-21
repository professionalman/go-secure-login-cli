package service

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"auth-cli/internal/database"
	"auth-cli/internal/dto"
	sqliterepository "auth-cli/internal/repository/sqlite"
	"auth-cli/internal/security"
)

func TestRegisterPersistsOnlyBcryptHash(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	const password = "Secret123!"
	auth := NewAuthService(
		sqliterepository.NewUserRepository(db),
		security.BcryptPasswordHasher{Cost: 4},
		fakeClock{now: time.Date(2026, time.July, 21, 15, 0, 0, 0, time.UTC)},
		func() string { return "integration-user" },
		RegistrationPolicy{
			MinimumUsernameLength: 3,
			MaximumUsernameLength: 50,
			MinimumPasswordLength: 8,
			MaximumPasswordLength: 72,
		},
	)
	if _, err := auth.Register(ctx, dto.RegisterInput{
		Username:             "Alice",
		Password:             password,
		PasswordConfirmation: password,
	}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	var stored string
	if err := db.QueryRowContext(ctx, "SELECT password_hash FROM users WHERE username = ?", "alice").Scan(&stored); err != nil {
		t.Fatalf("query password_hash: %v", err)
	}
	if stored == password {
		t.Fatal("database contains the plaintext password")
	}
	if err := security.VerifyPassword(stored, password); err != nil {
		t.Fatalf("stored value is not a valid bcrypt hash for the password: %v", err)
	}
}
