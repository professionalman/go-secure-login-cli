package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"auth-cli/internal/domain"
	"auth-cli/internal/dto"
	"auth-cli/internal/repository"
)

type fakeClock struct{ now time.Time }

func (f fakeClock) Now() time.Time { return f.now }

type fakeHasher struct{ err error }

func (f fakeHasher) Hash(password string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return "hashed:" + password, nil
}

type fakeUserRepository struct {
	users     map[string]*domain.User
	createErr error
	findErr   error
	created   *domain.User
}

func (f *fakeUserRepository) Create(_ context.Context, user *domain.User) error {
	if f.createErr != nil {
		return f.createErr
	}
	copy := *user
	f.created = &copy
	if f.users == nil {
		f.users = make(map[string]*domain.User)
	}
	f.users[user.Username] = &copy
	return nil
}

func (f *fakeUserRepository) FindByUsername(_ context.Context, username string) (*domain.User, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	if user, found := f.users[username]; found {
		copy := *user
		return &copy, nil
	}
	return nil, repository.ErrNotFound
}

func (f *fakeUserRepository) FindByID(_ context.Context, userID string) (*domain.User, error) {
	for _, user := range f.users {
		if user.ID == userID {
			copy := *user
			return &copy, nil
		}
	}
	return nil, repository.ErrNotFound
}

func TestRegisterCreatesNormalizedUserWithHash(t *testing.T) {
	repo := &fakeUserRepository{users: make(map[string]*domain.User)}
	now := time.Date(2026, time.July, 21, 12, 30, 0, 0, time.FixedZone("test", 19800))
	auth := newTestAuthService(repo, fakeHasher{}, fakeClock{now: now})

	result, err := auth.Register(context.Background(), dto.RegisterInput{
		Username:             "  Alice.Smith  ",
		Password:             "password123",
		PasswordConfirmation: "password123",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if result.Username != "alice.smith" {
		t.Errorf("Username = %q, want alice.smith", result.Username)
	}
	if repo.created == nil {
		t.Fatal("repository did not receive a user")
	}
	if repo.created.PasswordHash != "hashed:password123" || repo.created.PasswordHash == "password123" {
		t.Errorf("PasswordHash = %q, want non-plaintext fake hash", repo.created.PasswordHash)
	}
	if !repo.created.RegisteredAt.Equal(now.UTC()) || !repo.created.CreatedAt.Equal(now.UTC()) {
		t.Errorf("timestamps = %v/%v, want %v", repo.created.RegisteredAt, repo.created.CreatedAt, now.UTC())
	}
	if repo.created.ID != "fixed-user-id" {
		t.Errorf("ID = %q, want fixed-user-id", repo.created.ID)
	}
}

func TestRegisterValidation(t *testing.T) {
	tests := []struct {
		name      string
		input     dto.RegisterInput
		wantError error
	}{
		{name: "empty username", input: dto.RegisterInput{Username: "", Password: "password", PasswordConfirmation: "password"}, wantError: domain.ErrInvalidUsername},
		{name: "short username", input: dto.RegisterInput{Username: "ab", Password: "password", PasswordConfirmation: "password"}, wantError: domain.ErrInvalidUsername},
		{name: "invalid first character", input: dto.RegisterInput{Username: ".alice", Password: "password", PasswordConfirmation: "password"}, wantError: domain.ErrInvalidUsername},
		{name: "unsafe characters", input: dto.RegisterInput{Username: "alice smith", Password: "password", PasswordConfirmation: "password"}, wantError: domain.ErrInvalidUsername},
		{name: "long username", input: dto.RegisterInput{Username: strings.Repeat("a", 51), Password: "password", PasswordConfirmation: "password"}, wantError: domain.ErrInvalidUsername},
		{name: "short password", input: dto.RegisterInput{Username: "alice", Password: "short", PasswordConfirmation: "short"}, wantError: domain.ErrInvalidPassword},
		{name: "long password", input: dto.RegisterInput{Username: "alice", Password: strings.Repeat("a", 73), PasswordConfirmation: strings.Repeat("a", 73)}, wantError: domain.ErrInvalidPassword},
		{name: "password mismatch", input: dto.RegisterInput{Username: "alice", Password: "password", PasswordConfirmation: "different"}, wantError: domain.ErrPasswordMismatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeUserRepository{users: make(map[string]*domain.User)}
			auth := newTestAuthService(repo, fakeHasher{}, fakeClock{now: time.Now()})
			_, err := auth.Register(context.Background(), tt.input)
			if !errors.Is(err, tt.wantError) {
				t.Fatalf("Register() error = %v, want %v", err, tt.wantError)
			}
			if repo.created != nil {
				t.Fatal("invalid registration reached repository Create()")
			}
		})
	}
}

func TestRegisterDuplicateUsername(t *testing.T) {
	repo := &fakeUserRepository{users: map[string]*domain.User{
		"alice": {ID: "existing", Username: "alice"},
	}}
	auth := newTestAuthService(repo, fakeHasher{}, fakeClock{now: time.Now()})

	_, err := auth.Register(context.Background(), dto.RegisterInput{
		Username:             " ALICE ",
		Password:             "password",
		PasswordConfirmation: "password",
	})
	if !errors.Is(err, domain.ErrUserAlreadyExists) {
		t.Fatalf("Register() error = %v, want ErrUserAlreadyExists", err)
	}
}

func TestRegisterMapsCreateConflict(t *testing.T) {
	repo := &fakeUserRepository{users: make(map[string]*domain.User), createErr: repository.ErrConflict}
	auth := newTestAuthService(repo, fakeHasher{}, fakeClock{now: time.Now()})

	_, err := auth.Register(context.Background(), dto.RegisterInput{
		Username:             "alice",
		Password:             "password",
		PasswordConfirmation: "password",
	})
	if !errors.Is(err, domain.ErrUserAlreadyExists) {
		t.Fatalf("Register() error = %v, want ErrUserAlreadyExists", err)
	}
}

func newTestAuthService(users repository.UserRepository, hasher PasswordHasher, serviceClock fakeClock) *DefaultAuthService {
	return NewAuthService(users, hasher, serviceClock, func() string { return "fixed-user-id" }, RegistrationPolicy{
		MinimumUsernameLength: 3,
		MaximumUsernameLength: 50,
		MinimumPasswordLength: 8,
		MaximumPasswordLength: 72,
	})
}
