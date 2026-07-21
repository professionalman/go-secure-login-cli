package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"auth-cli/internal/domain"
	"auth-cli/internal/dto"
)

func TestDisableTOTPRequiresSessionPasswordAndCodeWithoutChangingLockout(t *testing.T) {
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	encrypted := "encrypted"
	user := &domain.User{
		ID: "u", Username: "alice", PasswordHash: "hashed:password", TOTPEnabled: true,
		TOTPSecretEncrypted: &encrypted, FailedLoginAttempts: 3,
	}
	repo := &fakeUserRepository{users: map[string]*domain.User{"alice": user}}
	sessions := &fakeM6Sessions{validated: &dto.AuthenticatedUser{User: dto.User{ID: user.ID, Username: user.Username, TOTPEnabled: true}}}
	totpService := &fakeTOTPService{validCode: "123456"}
	auth := NewAuthService(
		repo, fakeHasher{}, fakeClock{now: now}, func() string { return "unused" }, RegistrationPolicy{},
		WithSessionService(sessions), WithTOTPEnrollment(totpService, &fakeM6Cipher{secret: "secret"}, 10*time.Minute),
	)

	if err := auth.DisableTOTP(context.Background(), "raw-session", "wrong", "123456"); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("wrong password error = %v", err)
	}
	if user.FailedLoginAttempts != 3 || !user.TOTPEnabled {
		t.Fatalf("wrong password changed security state: %#v", user)
	}
	if err := auth.DisableTOTP(context.Background(), "raw-session", "password", "000000"); !errors.Is(err, domain.ErrInvalidTOTP) {
		t.Fatalf("wrong code error = %v", err)
	}
	if user.FailedLoginAttempts != 3 || !user.TOTPEnabled {
		t.Fatalf("wrong code changed security state: %#v", user)
	}
	if err := auth.DisableTOTP(context.Background(), "raw-session", "password", "123456"); err != nil {
		t.Fatal(err)
	}
	if user.TOTPEnabled || user.TOTPSecretEncrypted != nil || user.FailedLoginAttempts != 3 {
		t.Fatalf("disabled state = %#v", user)
	}
	if err := auth.DisableTOTP(context.Background(), "raw-session", "password", "123456"); !errors.Is(err, domain.ErrTOTPNotEnabled) {
		t.Fatalf("second disable error = %v", err)
	}
}

func TestDisableTOTPRejectsInvalidSessionBeforeReauthentication(t *testing.T) {
	repo := &fakeUserRepository{users: make(map[string]*domain.User)}
	sessions := &fakeM6Sessions{validateErr: domain.ErrSessionExpired}
	auth := NewAuthService(
		repo, fakeHasher{}, fakeClock{now: time.Now()}, func() string { return "unused" }, RegistrationPolicy{},
		WithSessionService(sessions), WithTOTPEnrollment(&fakeTOTPService{}, &fakeM6Cipher{}, 10*time.Minute),
	)
	if err := auth.DisableTOTP(context.Background(), "expired", "password", "123456"); !errors.Is(err, domain.ErrSessionExpired) {
		t.Fatalf("invalid session error = %v", err)
	}
}
