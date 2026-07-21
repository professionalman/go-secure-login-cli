package service

import (
	"bytes"
	"context"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"auth-cli/internal/database"
	"auth-cli/internal/domain"
	sqliterepository "auth-cli/internal/repository/sqlite"
	"auth-cli/internal/security"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func TestTOTPEnrollmentPersistsOnlyEncryptedSecretAndKeepsSessionValid(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, time.July, 22, 8, 0, 0, 0, time.UTC)
	users := sqliterepository.NewUserRepository(db)
	sessions := sqliterepository.NewSessionRepository(db)
	if err := users.Create(ctx, &domain.User{
		ID: "user-1", Username: "alice", PasswordHash: "hash",
		RegisteredAt: now.Add(-time.Hour), CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	sessionService := NewSessionService(
		users,
		sessions,
		sqliterepository.NewUnitOfWork(db),
		fakeClock{now: now},
		func() string { return "session-1" },
		func() (string, string, error) { return "raw-session", security.HashSessionToken("raw-session"), nil },
		30*time.Minute,
	)
	if _, err := sessionService.FinalizeLogin(ctx, "user-1"); err != nil {
		t.Fatal(err)
	}

	cipher, err := security.NewAESGCMCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	totpService := NewTOTPService(
		fakeClock{now: now},
		TOTPPolicy{Issuer: "InternshipAuthCLI", Period: 30, Skew: 1, Digits: 6},
		WithTOTPRandomReader(bytes.NewReader(bytes.Repeat([]byte{0x24}, 20))),
	)
	auth := NewAuthService(
		users,
		fakeHasher{},
		fakeClock{now: now},
		func() string { return "unused" },
		RegistrationPolicy{},
		WithSessionService(sessionService),
		WithTOTPEnrollment(totpService, cipher, 10*time.Minute),
	)

	setup, err := auth.BeginTOTPSetup(ctx, "raw-session")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(setup.ProvisioningURI)
	if err != nil {
		t.Fatal(err)
	}
	secret := parsed.Query().Get("secret")
	if secret == "" {
		t.Fatal("provisioning URI omitted TOTP secret")
	}
	code, err := totp.GenerateCodeCustom(secret, now, totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ConfirmTOTPSetup(ctx, "raw-session", code); err != nil {
		t.Fatal(err)
	}

	var enabled int
	var storedSecret string
	if err := db.QueryRowContext(ctx, "SELECT totp_enabled, totp_secret_encrypted FROM users WHERE id = ?", "user-1").Scan(&enabled, &storedSecret); err != nil {
		t.Fatal(err)
	}
	if enabled != 1 || storedSecret == secret || storedSecret == "" {
		t.Fatalf("stored TOTP state = %d/%q", enabled, storedSecret)
	}
	decrypted, err := cipher.Decrypt(storedSecret)
	if err != nil || decrypted != secret {
		t.Fatalf("Decrypt(stored secret) = %q, %v", decrypted, err)
	}
	authenticated, err := sessionService.ValidateSession(ctx, "raw-session")
	if err != nil || !authenticated.User.TOTPEnabled {
		t.Fatalf("existing session after enrollment = %#v, %v", authenticated, err)
	}
}
