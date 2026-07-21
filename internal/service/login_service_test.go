package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"auth-cli/internal/domain"
	"auth-cli/internal/dto"
	"auth-cli/internal/repository"
)

func (f *fakeUserRepository) ResetLoginSecurity(context.Context, string, time.Time) error {
	return nil
}

func (f fakeHasher) Verify(passwordHash, password string) error {
	if f.err != nil {
		return f.err
	}
	if passwordHash == "hashed:"+password {
		return nil
	}
	return errors.New("password mismatch")
}

type fakeLoginSessions struct {
	result *dto.SessionResult
	err    error
	userID string
}

func (f *fakeLoginSessions) FinalizeLogin(_ context.Context, userID string) (*dto.SessionResult, error) {
	f.userID = userID
	return f.result, f.err
}

func (*fakeLoginSessions) ValidateSession(context.Context, string) (*dto.AuthenticatedUser, error) {
	return nil, errors.New("not used")
}

func (*fakeLoginSessions) Logout(context.Context, string) error {
	return errors.New("not used")
}

type recordingPasswordManager struct {
	verifyCalls int
}

func (r *recordingPasswordManager) Hash(password string) (string, error) {
	return "hashed:" + password, nil
}

func (r *recordingPasswordManager) Verify(passwordHash, password string) error {
	r.verifyCalls++
	if passwordHash == "hashed:"+password {
		return nil
	}
	return errors.New("password mismatch")
}

func TestLoginWithPasswordCreatesSession(t *testing.T) {
	now := time.Now().UTC()
	repo := &fakeUserRepository{users: map[string]*domain.User{
		"alice": {ID: "user-1", Username: "alice", PasswordHash: "hashed:password", RegisteredAt: now},
	}}
	sessions := &fakeLoginSessions{result: &dto.SessionResult{
		RawToken: "raw", ExpiresAt: now.Add(time.Hour), User: dto.User{ID: "user-1", Username: "alice"},
	}}
	auth := NewAuthService(repo, fakeHasher{}, fakeClock{now: now}, func() string { return "id" }, RegistrationPolicy{}, WithSessionService(sessions))
	result, err := auth.LoginWithPassword(context.Background(), dto.LoginInput{Username: " ALICE ", Password: "password"})
	if err != nil {
		t.Fatalf("LoginWithPassword() error = %v", err)
	}
	if result.Status != dto.LoginStatusAuthenticated || result.RawSessionToken != "raw" || sessions.userID != "user-1" {
		t.Errorf("login result/sessions = %#v/%q", result, sessions.userID)
	}
}

func TestLoginWithPasswordUsesGenericCredentialError(t *testing.T) {
	now := time.Now().UTC()
	manager := &recordingPasswordManager{}
	repo := &fakeUserRepository{users: map[string]*domain.User{
		"alice": {ID: "user-1", Username: "alice", PasswordHash: "hashed:correct", RegisteredAt: now},
	}}
	auth := NewAuthService(repo, manager, fakeClock{now: now}, func() string { return "id" }, RegistrationPolicy{})

	_, wrongPassword := auth.LoginWithPassword(context.Background(), dto.LoginInput{Username: "alice", Password: "wrong"})
	_, unknownUser := auth.LoginWithPassword(context.Background(), dto.LoginInput{Username: "unknown", Password: "wrong"})
	if !errors.Is(wrongPassword, domain.ErrInvalidCredentials) || !errors.Is(unknownUser, domain.ErrInvalidCredentials) {
		t.Errorf("wrong/unknown errors = %v/%v", wrongPassword, unknownUser)
	}
	if manager.verifyCalls != 2 {
		t.Errorf("Verify calls = %d, want one for known and one dummy comparison", manager.verifyCalls)
	}
}

func TestLoginWithPasswordDoesNotCreateSessionForTOTPUser(t *testing.T) {
	now := time.Now().UTC()
	repo := &fakeUserRepository{users: map[string]*domain.User{
		"alice": {ID: "user-1", Username: "alice", PasswordHash: "hashed:password", TOTPEnabled: true, RegisteredAt: now},
	}}
	sessions := &fakeLoginSessions{result: &dto.SessionResult{RawToken: "must-not-be-used"}}
	auth := NewAuthService(repo, fakeHasher{}, fakeClock{now: now}, func() string { return "id" }, RegistrationPolicy{}, WithSessionService(sessions))
	result, err := auth.LoginWithPassword(context.Background(), dto.LoginInput{Username: "alice", Password: "password"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != dto.LoginStatusTOTPRequired || sessions.userID != "" {
		t.Errorf("result/session user = %#v/%q", result, sessions.userID)
	}
}

var _ repository.UserRepository = (*fakeUserRepository)(nil)
