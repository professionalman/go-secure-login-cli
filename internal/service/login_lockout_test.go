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

func (f *fakeUserRepository) UpdateLoginFailureState(
	_ context.Context,
	userID string,
	failedAttempts int,
	lockedUntil *time.Time,
	updatedAt time.Time,
) error {
	for _, user := range f.users {
		if user.ID != userID {
			continue
		}
		user.FailedLoginAttempts = failedAttempts
		if lockedUntil == nil {
			user.LockedUntil = nil
		} else {
			deadline := *lockedUntil
			user.LockedUntil = &deadline
		}
		user.UpdatedAt = updatedAt
		return nil
	}
	return repository.ErrNotFound
}

func TestPasswordLoginLockoutAtConfiguredThreshold(t *testing.T) {
	now := time.Date(2026, time.July, 21, 22, 0, 0, 0, time.UTC)
	user := &domain.User{
		ID: "user-1", Username: "alice", PasswordHash: "hashed:correct",
		FailedLoginAttempts: 3, RegisteredAt: now.Add(-time.Hour),
	}
	repo := &fakeUserRepository{users: map[string]*domain.User{"alice": user}}
	passwords := &recordingPasswordManager{}
	auth := newLockoutTestAuth(repo, passwords, fakeClock{now: now})

	_, err := auth.LoginWithPassword(context.Background(), dto.LoginInput{Username: "alice", Password: "wrong"})
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("attempt 4 error = %v, want ErrInvalidCredentials", err)
	}
	if user.FailedLoginAttempts != 4 || user.LockedUntil != nil {
		t.Fatalf("attempt 4 state = %d/%v, want 4/unlocked", user.FailedLoginAttempts, user.LockedUntil)
	}

	_, err = auth.LoginWithPassword(context.Background(), dto.LoginInput{Username: "alice", Password: "wrong"})
	if !errors.Is(err, domain.ErrAccountLocked) {
		t.Fatalf("attempt 5 error = %v, want ErrAccountLocked", err)
	}
	wantDeadline := now.Add(15 * time.Minute)
	if user.FailedLoginAttempts != 5 || user.LockedUntil == nil || !user.LockedUntil.Equal(wantDeadline) {
		t.Fatalf("attempt 5 state = %d/%v, want 5/%v", user.FailedLoginAttempts, user.LockedUntil, wantDeadline)
	}

	_, err = auth.LoginWithPassword(context.Background(), dto.LoginInput{Username: "alice", Password: "correct"})
	if !errors.Is(err, domain.ErrAccountLocked) {
		t.Fatalf("attempt 6 error = %v, want ErrAccountLocked", err)
	}
	if user.FailedLoginAttempts != 5 || passwords.verifyCalls != 2 {
		t.Fatalf("active lock changed state or verified password: attempts=%d verifyCalls=%d", user.FailedLoginAttempts, passwords.verifyCalls)
	}
}

func TestPasswordLoginLockExpiryBoundary(t *testing.T) {
	deadline := time.Date(2026, time.July, 21, 23, 0, 0, 0, time.UTC)
	tests := []struct {
		name             string
		now              time.Time
		wantError        error
		wantAttempts     int
		wantPasswordWork int
	}{
		{name: "immediately before expiry", now: deadline.Add(-time.Nanosecond), wantError: domain.ErrAccountLocked, wantAttempts: 5, wantPasswordWork: 0},
		{name: "exactly at expiry", now: deadline, wantError: domain.ErrInvalidCredentials, wantAttempts: 1, wantPasswordWork: 1},
		{name: "immediately after expiry", now: deadline.Add(time.Nanosecond), wantError: domain.ErrInvalidCredentials, wantAttempts: 1, wantPasswordWork: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lockedUntil := deadline
			user := &domain.User{
				ID: "user-1", Username: "alice", PasswordHash: "hashed:correct",
				FailedLoginAttempts: 5, LockedUntil: &lockedUntil, RegisteredAt: deadline.Add(-time.Hour),
			}
			repo := &fakeUserRepository{users: map[string]*domain.User{"alice": user}}
			passwords := &recordingPasswordManager{}
			auth := newLockoutTestAuth(repo, passwords, fakeClock{now: tt.now})

			_, err := auth.LoginWithPassword(context.Background(), dto.LoginInput{Username: "alice", Password: "wrong"})
			if !errors.Is(err, tt.wantError) {
				t.Fatalf("LoginWithPassword() error = %v, want %v", err, tt.wantError)
			}
			if user.FailedLoginAttempts != tt.wantAttempts || passwords.verifyCalls != tt.wantPasswordWork {
				t.Fatalf("state/work = %d/%d, want %d/%d", user.FailedLoginAttempts, passwords.verifyCalls, tt.wantAttempts, tt.wantPasswordWork)
			}
			if tt.wantAttempts == 1 && user.LockedUntil != nil {
				t.Fatalf("expired lock was not cleared: %v", user.LockedUntil)
			}
		})
	}
}

func TestPasswordSuccessRetainsFailuresUntilTOTPCompletes(t *testing.T) {
	now := time.Date(2026, time.July, 21, 22, 30, 0, 0, time.UTC)
	user := &domain.User{
		ID: "user-1", Username: "alice", PasswordHash: "hashed:correct",
		TOTPEnabled: true, FailedLoginAttempts: 4, RegisteredAt: now.Add(-time.Hour),
	}
	repo := &fakeUserRepository{users: map[string]*domain.User{"alice": user}}
	auth := newLockoutTestAuth(repo, &recordingPasswordManager{}, fakeClock{now: now})

	result, err := auth.LoginWithPassword(context.Background(), dto.LoginInput{Username: "alice", Password: "correct"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != dto.LoginStatusTOTPRequired {
		t.Fatalf("status = %q, want %q", result.Status, dto.LoginStatusTOTPRequired)
	}
	if user.FailedLoginAttempts != 4 || user.LockedUntil != nil {
		t.Fatalf("password step reset login security: %d/%v", user.FailedLoginAttempts, user.LockedUntil)
	}
}

func newLockoutTestAuth(users repository.UserRepository, passwords PasswordHasher, serviceClock fakeClock) *DefaultAuthService {
	return NewAuthService(
		users,
		passwords,
		serviceClock,
		func() string { return "id" },
		RegistrationPolicy{},
		WithLoginSecurityPolicy(LoginSecurityPolicy{MaximumAttempts: 5, LockoutDuration: 15 * time.Minute}),
	)
}
