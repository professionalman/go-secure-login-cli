package service

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"auth-cli/internal/database"
	"auth-cli/internal/domain"
	"auth-cli/internal/dto"
	sqliterepository "auth-cli/internal/repository/sqlite"
	"auth-cli/internal/security"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func TestTOTPLoginAndDisableIntegration(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, time.July, 22, 15, 0, 0, 0, time.UTC)
	const password = "Secret123!"
	const secret = "JBSWY3DPEHPK3PXP"
	passwords := security.BcryptPasswordHasher{Cost: 4}
	passwordHash, err := passwords.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := security.NewAESGCMCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	encryptedSecret, err := cipher.Encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}

	users := sqliterepository.NewUserRepository(db)
	sessions := sqliterepository.NewSessionRepository(db)
	if err := users.Create(ctx, &domain.User{
		ID: "user-1", Username: "alice", PasswordHash: passwordHash,
		TOTPEnabled: true, TOTPSecretEncrypted: &encryptedSecret, FailedLoginAttempts: 3,
		RegisteredAt: now.Add(-time.Hour), CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	sessionService := NewSessionService(
		users, sessions, sqliterepository.NewUnitOfWork(db), fakeClock{now: now},
		func() string { return "session-id" },
		func() (string, string, error) { return "raw-session", security.HashSessionToken("raw-session"), nil },
		30*time.Minute,
	)
	totpService := NewTOTPService(fakeClock{now: now}, TOTPPolicy{Issuer: "issuer", Period: 30, Skew: 1, Digits: 6})
	auth := NewAuthService(
		users, passwords, fakeClock{now: now}, func() string { return "unused" }, RegistrationPolicy{},
		WithSessionService(sessionService),
		WithLoginSecurityPolicy(LoginSecurityPolicy{MaximumAttempts: 5, LockoutDuration: 15 * time.Minute}),
		WithTOTPEnrollment(totpService, cipher, 10*time.Minute),
		WithTOTPLogin(totpService, cipher, 5*time.Minute, fixedChallengeToken("opaque-challenge")),
	)

	challenge, err := auth.LoginWithPassword(ctx, dto.LoginInput{Username: "alice", Password: password})
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Status != dto.LoginStatusTOTPRequired || challenge.RawSessionToken != "" {
		t.Fatalf("password result = %#v", challenge)
	}
	var challengeSessionCount int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sessions WHERE token_hash = ?", security.HashSessionToken(challenge.ChallengeID)).Scan(&challengeSessionCount); err != nil {
		t.Fatal(err)
	}
	if challengeSessionCount != 0 {
		t.Fatal("password-only TOTP step created a database session")
	}
	if _, err := auth.CompleteTOTPLogin(ctx, challenge.ChallengeID, "000000"); !errors.Is(err, domain.ErrInvalidTOTP) {
		t.Fatalf("wrong TOTP error = %v", err)
	}
	user, err := users.FindByID(ctx, "user-1")
	if err != nil || user.FailedLoginAttempts != 4 {
		t.Fatalf("wrong TOTP login state = %#v/%v", user, err)
	}

	code, err := totp.GenerateCodeCustom(secret, now, totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatal(err)
	}
	login, err := auth.CompleteTOTPLogin(ctx, challenge.ChallengeID, code)
	if err != nil {
		t.Fatal(err)
	}
	if login.RawSessionToken != "raw-session" || login.Status != dto.LoginStatusAuthenticated {
		t.Fatalf("completed login = %#v", login)
	}
	user, err = users.FindByID(ctx, "user-1")
	if err != nil || user.FailedLoginAttempts != 0 || user.LockedUntil != nil || user.LastLoginAt == nil {
		t.Fatalf("completed login security state = %#v/%v", user, err)
	}

	if err := auth.DisableTOTP(ctx, login.RawSessionToken, "wrong", code); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("disable wrong password error = %v", err)
	}
	user, _ = users.FindByID(ctx, "user-1")
	if !user.TOTPEnabled || user.FailedLoginAttempts != 0 {
		t.Fatalf("disable reauthentication changed login counters/state: %#v", user)
	}
	if err := auth.DisableTOTP(ctx, login.RawSessionToken, password, code); err != nil {
		t.Fatal(err)
	}
	var enabled int
	var storedSecret sql.NullString
	if err := db.QueryRowContext(ctx, "SELECT totp_enabled, totp_secret_encrypted FROM users WHERE id = ?", "user-1").Scan(&enabled, &storedSecret); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 || storedSecret.Valid {
		t.Fatalf("disabled persistent state = %d/%#v", enabled, storedSecret)
	}
	authenticated, err := sessionService.ValidateSession(ctx, login.RawSessionToken)
	if err != nil || authenticated.User.TOTPEnabled {
		t.Fatalf("existing session after disable = %#v/%v", authenticated, err)
	}
}
