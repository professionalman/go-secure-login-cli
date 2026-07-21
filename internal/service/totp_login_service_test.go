package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"auth-cli/internal/domain"
	"auth-cli/internal/dto"
)

type fakeM6Sessions struct {
	finalizedUserID string
	result          *dto.SessionResult
	validated       *dto.AuthenticatedUser
	validateErr     error
}

func (f *fakeM6Sessions) FinalizeLogin(_ context.Context, userID string) (*dto.SessionResult, error) {
	f.finalizedUserID = userID
	return f.result, nil
}

func (f *fakeM6Sessions) ValidateSession(context.Context, string) (*dto.AuthenticatedUser, error) {
	if f.validateErr != nil {
		return nil, f.validateErr
	}
	return f.validated, nil
}

func (*fakeM6Sessions) Logout(context.Context, string) error { return nil }

type fakeM6Cipher struct {
	secret string
	err    error
}

func (f *fakeM6Cipher) Encrypt(plaintext string) (string, error) {
	return "encrypted:" + plaintext, nil
}

func (f *fakeM6Cipher) Decrypt(string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.secret, nil
}

func TestTOTPLoginChallengeLifecycleAndSingleUse(t *testing.T) {
	now := time.Date(2026, time.July, 22, 9, 0, 0, 0, time.UTC)
	encrypted := "encrypted-secret"
	user := &domain.User{
		ID: "user-1", Username: "alice", PasswordHash: "hashed:password",
		TOTPEnabled: true, TOTPSecretEncrypted: &encrypted, FailedLoginAttempts: 2,
		RegisteredAt: now.Add(-time.Hour),
	}
	repo := &fakeUserRepository{users: map[string]*domain.User{"alice": user}}
	sessions := &fakeM6Sessions{result: &dto.SessionResult{
		RawToken: "raw-session", ExpiresAt: now.Add(30 * time.Minute),
		User: dto.User{ID: user.ID, Username: user.Username, TOTPEnabled: true, RegisteredAt: user.RegisteredAt},
	}}
	totpService := &fakeTOTPService{validCode: "123456"}
	auth := NewAuthService(
		repo, fakeHasher{}, fakeClock{now: now}, func() string { return "unused" }, RegistrationPolicy{},
		WithSessionService(sessions),
		WithLoginSecurityPolicy(LoginSecurityPolicy{MaximumAttempts: 5, LockoutDuration: 15 * time.Minute}),
		WithTOTPLogin(totpService, &fakeM6Cipher{secret: "plaintext-secret"}, 5*time.Minute, fixedChallengeToken("opaque-challenge")),
	)

	challenge, err := auth.LoginWithPassword(context.Background(), dto.LoginInput{Username: "alice", Password: "password"})
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Status != dto.LoginStatusTOTPRequired || challenge.ChallengeID != "opaque-challenge" {
		t.Fatalf("challenge = %#v", challenge)
	}
	if challenge.User.ID != "" || challenge.RawSessionToken != "" || challenge.PreviousLastLogin != nil {
		t.Fatalf("challenge leaked authenticated data: %#v", challenge)
	}
	if !challenge.ChallengeExpiresAt.Equal(now.Add(5 * time.Minute)) {
		t.Fatalf("challenge expiry = %v", challenge.ChallengeExpiresAt)
	}
	stored := auth.totpLogin.store.byID[challenge.ChallengeID]
	if stored.userID != user.ID || stored.expiresAt != challenge.ChallengeExpiresAt {
		t.Fatalf("stored challenge = %#v", stored)
	}

	if _, err := auth.CompleteTOTPLogin(context.Background(), challenge.ChallengeID, "000000"); !errors.Is(err, domain.ErrInvalidTOTP) {
		t.Fatalf("invalid code error = %v", err)
	}
	if user.FailedLoginAttempts != 3 || pendingLoginCount(auth) != 1 {
		t.Fatalf("invalid code state = attempts %d, challenges %d", user.FailedLoginAttempts, pendingLoginCount(auth))
	}
	result, err := auth.CompleteTOTPLogin(context.Background(), challenge.ChallengeID, "123456")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != dto.LoginStatusAuthenticated || result.RawSessionToken != "raw-session" || sessions.finalizedUserID != user.ID {
		t.Fatalf("authenticated result/session = %#v/%q", result, sessions.finalizedUserID)
	}
	if pendingLoginCount(auth) != 0 {
		t.Fatal("successful challenge was retained")
	}
	if _, err := auth.CompleteTOTPLogin(context.Background(), challenge.ChallengeID, "123456"); !errors.Is(err, domain.ErrTOTPChallengeNotFound) {
		t.Fatalf("reused challenge error = %v", err)
	}
}

func TestTOTPLoginChallengeExpiryCancellationAndShutdownClear(t *testing.T) {
	now := time.Date(2026, time.July, 22, 10, 0, 0, 0, time.UTC)
	serviceClock := &mutableClock{now: now}
	encrypted := "encrypted"
	user := &domain.User{ID: "u", Username: "alice", PasswordHash: "hashed:password", TOTPEnabled: true, TOTPSecretEncrypted: &encrypted}
	repo := &fakeUserRepository{users: map[string]*domain.User{"alice": user}}
	auth := NewAuthService(
		repo, fakeHasher{}, serviceClock, func() string { return "unused" }, RegistrationPolicy{},
		WithSessionService(&fakeM6Sessions{}),
		WithTOTPLogin(&fakeTOTPService{}, &fakeM6Cipher{}, 5*time.Minute, fixedChallengeToken("challenge")),
	)

	challenge, err := auth.LoginWithPassword(context.Background(), dto.LoginInput{Username: "alice", Password: "password"})
	if err != nil {
		t.Fatal(err)
	}
	serviceClock.now = challenge.ChallengeExpiresAt
	if _, err := auth.CompleteTOTPLogin(context.Background(), challenge.ChallengeID, "123456"); !errors.Is(err, domain.ErrTOTPChallengeExpired) {
		t.Fatalf("completion at expiry error = %v", err)
	}
	if pendingLoginCount(auth) != 0 {
		t.Fatal("expired challenge was retained")
	}

	serviceClock.now = now
	challenge, err = auth.LoginWithPassword(context.Background(), dto.LoginInput{Username: "alice", Password: "password"})
	if err != nil {
		t.Fatal(err)
	}
	auth.CancelTOTPLogin(challenge.ChallengeID)
	if pendingLoginCount(auth) != 0 {
		t.Fatal("cancelled challenge was retained")
	}
	challenge, err = auth.LoginWithPassword(context.Background(), dto.LoginInput{Username: "alice", Password: "password"})
	if err != nil {
		t.Fatal(err)
	}
	auth.ClearTOTPLoginChallenges()
	if pendingLoginCount(auth) != 0 {
		t.Fatal("shutdown clear retained challenge")
	}
}

func TestWrongTOTPUsesSharedLockoutThresholdAndRemovesLockedChallenge(t *testing.T) {
	now := time.Date(2026, time.July, 22, 11, 0, 0, 0, time.UTC)
	encrypted := "encrypted"
	user := &domain.User{
		ID: "u", Username: "alice", PasswordHash: "hashed:password", TOTPEnabled: true,
		TOTPSecretEncrypted: &encrypted, FailedLoginAttempts: 3,
	}
	repo := &fakeUserRepository{users: map[string]*domain.User{"alice": user}}
	auth := NewAuthService(
		repo, fakeHasher{}, fakeClock{now: now}, func() string { return "unused" }, RegistrationPolicy{},
		WithSessionService(&fakeM6Sessions{}),
		WithLoginSecurityPolicy(LoginSecurityPolicy{MaximumAttempts: 5, LockoutDuration: 15 * time.Minute}),
		WithTOTPLogin(&fakeTOTPService{validCode: "123456"}, &fakeM6Cipher{secret: "secret"}, 5*time.Minute, fixedChallengeToken("challenge")),
	)

	challenge, err := auth.LoginWithPassword(context.Background(), dto.LoginInput{Username: "alice", Password: "password"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.CompleteTOTPLogin(context.Background(), challenge.ChallengeID, "000000"); !errors.Is(err, domain.ErrInvalidTOTP) {
		t.Fatalf("attempt 4 error = %v", err)
	}
	if user.FailedLoginAttempts != 4 || pendingLoginCount(auth) != 1 {
		t.Fatalf("attempt 4 state = %d/%d", user.FailedLoginAttempts, pendingLoginCount(auth))
	}
	if _, err := auth.CompleteTOTPLogin(context.Background(), challenge.ChallengeID, "000000"); !errors.Is(err, domain.ErrAccountLocked) {
		t.Fatalf("attempt 5 error = %v", err)
	}
	if user.FailedLoginAttempts != 5 || user.LockedUntil == nil || pendingLoginCount(auth) != 0 {
		t.Fatalf("attempt 5 state = %d/%v/%d", user.FailedLoginAttempts, user.LockedUntil, pendingLoginCount(auth))
	}
}

func fixedChallengeToken(value string) SessionTokenGenerator {
	return func() (string, string, error) { return value, "unused-hash", nil }
}

func pendingLoginCount(service *DefaultAuthService) int {
	store := service.totpLogin.store
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.byID)
}
